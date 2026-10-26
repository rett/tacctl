package cli

// Shell completion. 'tacctl completion bash|zsh|fish' prints cobra's
// generated script; the script asks the binary itself ('tacctl __complete
// <words>', cobra's protocol) what can come next. The binary answers from
// the command tree (sub-commands) and from the verbs' Specs (flags and
// positionals, args.go), and it never reads tacctl's state: the live names
// (users, groups, scopes, backends, listeners, backups) come from the
// bridge 'sudo -n tacctl _completion-names <kind>', which works as root or
// with the NOPASSWD sudoers rule ('tacctl config sudoers install') and is
// empty otherwise, which is harmless: the operator types the name.

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
)

// configPaths are the keys 'config get' completes, as a word list: every
// exact key of the schema and the prefix of every key family (so 'tier.' is
// offered and the group is typed by hand), with the shipped built-in
// instances. Generated from the schema, so a new key is completed without a
// second list; TestConfigPathsCoverSchema holds it to that.
var configPaths = configKeyWords(conf.NewSchema(nil))

// shippedInstances are the family keys a fresh install already has.
var shippedInstances = []string{"privileges.operator", "commands.superuser", "commands.operator", "commands.readonly"}

// configKeyWords is the sorted, de-duplicated 'a|b|c' list of a schema's
// exact keys, family prefixes and shippedInstances.
func configKeyWords(s *conf.Schema) string {
	words := slices.Concat(s.Keys(), s.Wildcards(), shippedInstances)
	slices.Sort(words)
	return strings.Join(slices.Compact(words), "|")
}

// topSpecs are the verbs outside the families.
var topSpecs = map[string]Spec{
	"install":   {Flags: []Flag{{Names: []string{"--branch"}, Value: true}, {Names: []string{"-y", "--yes"}}}},
	"upgrade":   {Flags: []Flag{{Names: []string{"--branch"}, Value: true}}},
	"uninstall": {Flags: []Flag{{Names: []string{"-y", "--yes"}}}},
	"rollback":  rollbackSpec,
	"version":   {Flags: []Flag{{Names: []string{"--long"}}}},
}

// completionShells are the shells 'tacctl completion' writes a script for.
var completionShells = []string{"bash", "zsh", "fish"}

// completionUsage is what 'tacctl completion' prints for a missing or an
// unknown shell.
const completionUsage = "Usage: tacctl completion bash|zsh|fish"

// completionCmd is 'tacctl completion <shell>': the generated script on
// stdout. It runs as the invoking user (reexec.go), reads no state and has
// no tier gate: the script is the same for everyone.
func completionCmd(inv *invocation) *cobra.Command {
	c := verb("completion bash", "Print the shell completion script")
	c.Hidden = true
	c.RunE = func(_ *cobra.Command, args []string) error {
		shell := arg(args, 0)
		if !slices.Contains(completionShells, shell) {
			inv.app.Out.Error(completionUsage)
			return exit(1)
		}
		return GenCompletion(inv.app.Out.Stdout, shell)
	}
	return c
}

// GenCompletion writes the completion script of shell to w.
func GenCompletion(w io.Writer, shell string) error {
	root := newRoot(&invocation{})
	switch shell {
	case "zsh":
		return root.GenZshCompletion(w)
	case "fish":
		return root.GenFishCompletion(w, true)
	}
	return root.GenBashCompletionV2(w, true)
}

// BashCompletion is the bash script that install and upgrade place in
// /etc/bash_completion.d.
func BashCompletion() ([]byte, error) {
	var b bytes.Buffer
	if err := GenCompletion(&b, "bash"); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// specLookups are the argument specs of the families, by first word: the
// function gets the whole path (the words after 'tacctl', the family's own
// first) and answers the Spec of that leaf. A family file registers its own
// in init(): registerSpecs for the usual 'family <verb>' table, registerSpecFunc
// for any other shape. The words that are leaves of their own are topSpecs.
var specLookups = map[string]func(path []string) (Spec, bool){}

// registerSpecFunc registers the lookup of the family word.
func registerSpecFunc(word string, f func(path []string) (Spec, bool)) {
	if _, dup := specLookups[word]; dup {
		panic("cli: specs of '" + word + "' registered twice")
	}
	specLookups[word] = f
}

// registerSpecs registers the specs of 'word <verb>', keyed by the verb.
func registerSpecs(word string, specs map[string]Spec) {
	registerSpecFunc(word, func(path []string) (Spec, bool) {
		if len(path) < 2 {
			return Spec{}, false
		}
		s, ok := specs[path[1]]
		return s, ok
	})
}

func init() {
	registerSpecs("user", userSpecs)
	registerSpecs("scope", scopeSpecs)
	registerSpecs("host", hostSpecs)
	registerSpecs("backend", backendSpecs)
	registerSpecs("store", storeSpecs)
	registerSpecs("log", logSpecs)
	registerSpecs("backup", backupSpecs)
	registerSpecFunc("group", func(path []string) (Spec, bool) {
		s, ok := groupSpecs[strings.Join(path[1:], " ")]
		return s, ok
	})
	registerSpecFunc("config", func(path []string) (Spec, bool) {
		var s Spec
		var ok bool
		switch {
		case len(path) < 2:
		case len(path) == 2:
			s, ok = configSpecs[path[1]]
		case path[1] == "linux":
			s, ok = configLinuxSpecs[path[2]]
		case path[1] == "snmp":
			s, ok = configSNMPSpecs[path[2]]
		case path[1] == "devices":
			s, ok = configDevicesSpecs[path[2]]
		case path[1] == "allow" || path[1] == "deny" || path[1] == "mgmt-acl":
			s, ok = configPolicySpecs[path[2]]
		}
		return s, ok
	})
}

// specFor is the Spec of the command at path (the words after 'tacctl').
func specFor(path []string) (Spec, bool) {
	if f, ok := specLookups[path[0]]; ok {
		return f(path)
	}
	if len(path) == 1 {
		s, ok := topSpecs[path[0]]
		return s, ok
	}
	return Spec{}, false
}

// attachCompletion gives every leaf command that has a Spec its
// ValidArgsFunction. A command with sub-commands completes their names
// (cobra's own).
func attachCompletion(inv *invocation, root *cobra.Command) {
	var walk func(c *cobra.Command, path []string)
	walk = func(c *cobra.Command, path []string) {
		if len(c.Commands()) == 0 {
			if spec, ok := specFor(path); ok {
				c.ValidArgsFunction = func(cmd *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
					comps, dir := inv.completeSpec(spec, args, toComplete)
					return inv.describeFlags(cmd, path, spec, comps), dir
				}
			}
			return
		}
		for _, sub := range c.Commands() {
			walk(sub, append(slices.Clone(path), sub.Name()))
		}
	}
	for _, sub := range root.Commands() {
		walk(sub, []string{sub.Name()})
	}
}

// describeFlags gives each flag among comps the description the shell's
// '?' shows for it, after the value it takes ('--idle' → '<min>: End the
// session after ...'): bash, zsh and fish list it beside the flag when
// there is more than one candidate. The other words are left as they are.
func (inv *invocation) describeFlags(cmd *cobra.Command, path []string, spec Spec, comps []cobra.Completion) []cobra.Completion {
	helps := inv.flagHelps(cmd, path, spec, comps)
	out := make([]cobra.Completion, 0, len(comps))
	for _, c := range comps {
		h, ok := helps[c]
		if !ok || h[1] == "" || strings.Contains(c, "\t") {
			out = append(out, c)
			continue
		}
		desc := h[1]
		if h[0] != "" {
			desc = h[0] + ": " + desc
		}
		out = append(out, cobra.CompletionWithDesc(c, desc))
	}
	return out
}

// completeSpec answers cobra's __complete for a leaf: args are the words
// typed after the command and before the one being completed. It offers, in
// this order, the value of a value flag that is waiting for one; else the
// words of the next positional and, where a flag can come, the flags not
// yet on the line.
func (inv *invocation) completeSpec(spec Spec, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	byName := map[string]*Flag{}
	for i := range spec.Flags {
		for _, n := range spec.Flags[i].Names {
			byName[n] = &spec.Flags[i]
		}
	}
	seen := map[string]bool{}
	values := map[string]string{}
	var pending *Flag
	var words []string // the positionals typed so far
	alone := false
	pos := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			words = append(words, args[i+1:]...)
			pos += len(args) - i - 1
			break
		}
		name, val, hasVal := strings.Cut(a, "=")
		f, isFlag := byName[name]
		if len(a) < 2 || a[0] != '-' || !isFlag {
			if len(a) >= 2 && a[0] == '-' {
				continue // a flag the verb does not know: no positional
			}
			words = append(words, a)
			pos++
			continue
		}
		alone = alone || f.Alone
		if !f.Repeat {
			seen[f.Names[0]] = true
		}
		switch {
		case !f.Value:
		case hasVal:
			values[f.Names[0]] = val
		case f.Optional:
			// a bare flag: the next word is not its value
		case i+1 < len(args):
			i++
			values[f.Names[0]] = args[i]
		default:
			pending = f
		}
	}
	if pending != nil {
		return inv.completeKind(pending.Kind, toComplete, values)
	}
	// '--name=<partial>' of a flag whose value is optional (a bare '--name' is
	// offered below): the values of its kind. The generated scripts strip the
	// flag and the '=' themselves and expect the value alone; the shell
	// replaces the whole word, so it gets the flag in front.
	if name, cur, ok := strings.Cut(toComplete, "="); ok && strings.HasPrefix(name, "-") {
		if f := byName[name]; f != nil && f.Optional {
			var out []cobra.Completion
			for _, w := range inv.kindWords(f.Kind, values) {
				if !strings.HasPrefix(w, cur) {
					continue
				}
				if inv.shellMode {
					w = name + "=" + w
				}
				out = append(out, w)
			}
			return out, cobra.ShellCompDirectiveNoFileComp
		}
	}
	kind := ""
	if pos < len(spec.Args) {
		kind = spec.Args[pos]
	} else if spec.MaxArgs < 0 && len(spec.Args) == 1 {
		kind = spec.Args[0] // a list of one kind goes on past the end
	}
	if rest, ok := strings.CutPrefix(kind, "@"); ok {
		word, k, _ := strings.Cut(rest, ":")
		kind = ""
		if slices.Contains(words, word) {
			kind = k
		}
	}
	if rest, ok := strings.CutPrefix(kind, "?"); ok {
		parts := strings.SplitN(rest, ":", 3)
		kind = ""
		if len(parts) == 3 {
			kind = parts[2]
			if slices.Contains(words, parts[0]) {
				kind = parts[1]
			}
		}
	}
	if kind == KindBreakGlass && len(words) > 0 {
		values["@scope"] = words[0]
	}
	var out []cobra.Completion
	dir := cobra.ShellCompDirectiveNoFileComp
	if !alone {
		out, dir = inv.completeKind(kind, toComplete, values)
	}
	if strings.HasPrefix(toComplete, "-") || (!inv.shellMode && kind != KindFile && pos >= spec.MinArgs) {
		for i := range spec.Flags {
			f := &spec.Flags[i]
			if seen[f.Names[0]] || !f.offeredAfter(words) {
				continue
			}
			for _, n := range f.Names {
				if strings.HasPrefix(n, toComplete) {
					out = append(out, n)
				}
			}
		}
	}
	if len(out) > 0 && dir == cobra.ShellCompDirectiveDefault {
		dir = cobra.ShellCompDirectiveNoFileComp
	}
	return out, dir
}

// completeKind is the words of one kind that start with toComplete, and the
// directive that goes with them. values are the flags already on the line
// (the listeners of --backend).
func (inv *invocation) completeKind(kind, toComplete string, values map[string]string) ([]cobra.Completion, cobra.ShellCompDirective) {
	switch kind {
	case "":
		return nil, cobra.ShellCompDirectiveNoFileComp
	case KindFile:
		return nil, cobra.ShellCompDirectiveDefault
	}
	if base, ok := strings.CutSuffix(kind, KindList); ok {
		prefix := ""
		if i := strings.LastIndex(toComplete, ","); i >= 0 {
			prefix = toComplete[:i+1]
		}
		have := strings.Split(strings.TrimSuffix(prefix, ","), ",")
		for i, h := range have {
			// 'name=reason' elements (breakglass hold) name the device
			have[i], _, _ = strings.Cut(h, "=")
		}
		cur := strings.TrimPrefix(toComplete, prefix)
		var out []cobra.Completion
		for _, w := range inv.kindWords(base, values) {
			// A name keeps its description (the shell's '?' lists it).
			name, desc, _ := strings.Cut(w, "\t")
			if strings.HasPrefix(name, cur) && !slices.Contains(have, name) {
				c := prefix + name
				if desc != "" {
					c = cobra.CompletionWithDesc(c, desc)
				}
				out = append(out, c)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
	var out []cobra.Completion
	for _, w := range inv.kindWords(kind, values) {
		if strings.HasPrefix(w, toComplete) {
			out = append(out, w)
		}
	}
	dir := cobra.ShellCompDirectiveNoFileComp
	if kind == configPaths {
		// A family prefix is not a whole key: no space after it, and once
		// it is typed the names it takes come from the store.
		for _, w := range inv.configFamilyWords(toComplete) {
			if !slices.Contains(out, w) {
				out = append(out, w)
			}
		}
		if slices.ContainsFunc(out, func(w cobra.Completion) bool { return strings.HasSuffix(w, ".") }) {
			dir |= cobra.ShellCompDirectiveNoSpace
		}
	}
	return out, dir
}

// configFamilies says what names the keys of each wildcard family of the
// schema take after their prefix: the groups or the scopes of the store, or
// "" when the name is typed by hand (a listener, a device, a hold). The
// last word of a family with a key after the name ends in a dot.
// TestConfigFamiliesCoverSchema holds it to the schema's prefixes.
var configFamilies = map[string]string{
	"privileges.": KindGroups, "commands.": KindGroups, "tier.": KindGroups, "wti_level.": KindGroups,
	"junos.":     KindGroups,
	"aaa.order.": KindScopes, "exec_timeout.": KindScopes, "tacacs_group.": KindScopes, "radius_group.": KindScopes,
	"cisco.source_interface.": KindScopes, "scope_auth_method.": KindScopes,
	"scope_mgmt_acl.names.cisco.": KindScopes, "scope_mgmt_acl.names.juniper.": KindScopes,
	"scope_mgmt_acl.permits.": KindScopes, "breakglass_scope.": KindScopes, "blocks.": KindScopes,
	"snmp_scope.": KindScopes, "netconf_scope.": KindScopes,
	"listeners.": "", "blocks_device.": "", "breakglass_hold.": "", "emergency.lockdown.": "",
}

// configFamilyWords are the keys of the families whose prefix toComplete
// already starts with, one per group or scope the store has ('tier.ops',
// and 'junos.ops.' where a key follows the name).
func (inv *invocation) configFamilyWords(toComplete string) []string {
	var out []string
	for fam, kind := range configFamilies {
		if kind == "" || !strings.HasPrefix(toComplete, fam) {
			continue
		}
		more := ""
		if r, ok := conf.NewSchema(nil).RuleFor(fam + "x"); !ok || r.Depth > 1 || r.Tail != "" {
			more = "."
		}
		for _, n := range inv.liveNames(inv.ctx, kind) {
			if w := fam + n + more; strings.HasPrefix(w, toComplete) {
				out = append(out, w)
			}
		}
	}
	slices.Sort(out)
	return out
}

// kindWords are all the words of a kind: a fixed list written 'a|b|c', or
// the live names of a _completion-names kind.
func (inv *invocation) kindWords(kind string, values map[string]string) []string {
	if parts := strings.Split(kind, "+"); len(parts) > 1 {
		var out []string
		for _, k := range parts {
			out = append(out, inv.kindWords(k, values)...)
		}
		return out
	}
	if strings.Contains(kind, "|") {
		return strings.Split(kind, "|")
	}
	if _, ok := completionDescKinds[kind]; ok && inv.shellMode {
		return inv.liveLines(inv.ctx, kind, "--desc")
	}
	switch kind {
	case KindLine:
		var out []string
		for _, r := range topRows() {
			if r.Name != "shell" && !slices.ContainsFunc(out, func(w string) bool { return strings.HasPrefix(w, r.Name+"\t") }) {
				out = append(out, r.Name+"\t"+r.Desc)
			}
		}
		return out
	case KindUsers, KindGroups, KindScopes, KindHosts, KindDevices, KindCiscoDevices, KindJuniperDevices, KindBackups, KindBackends, KindEnabledBackends, KindHeld, KindShapes:
		return inv.liveNames(inv.ctx, kind)
	case KindBreakGlass:
		return inv.liveNames(inv.ctx, kind, values["@scope"])
	case KindListeners:
		if b := values["--backend"]; b != "" {
			return inv.liveNames(inv.ctx, kind, b)
		}
		return inv.liveNames(inv.ctx, kind)
	}
	// A single fixed word ('1|2' lists have the bar; one word has none).
	return []string{kind}
}

// liveLines is liveNames with one entry per line ('name<TAB>description').
func (inv *invocation) liveLines(ctx context.Context, kind string, extra ...string) []string {
	if inv.app == nil || inv.app.Runner == nil {
		return nil
	}
	res, err := inv.app.Runner.Run(ctx, execx.Cmd{
		Name: "sudo", Args: append([]string{"-n", "tacctl", "_completion-names", kind}, extra...)})
	if err != nil || res.Code != 0 {
		return nil
	}
	var lines []string
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return alignDescs(lines)
}

// alignDescs pads the words of the descriptions of 'name<TAB>a b c' lines
// to columns (the last word stays as it is).
func alignDescs(lines []string) []string {
	var width []int
	for _, l := range lines {
		_, d, _ := strings.Cut(l, "\t")
		for i, w := range strings.Fields(d) {
			if i == len(width) {
				width = append(width, 0)
			}
			width[i] = max(width[i], len(w))
		}
	}
	out := make([]string, len(lines))
	for i, l := range lines {
		name, d, ok := strings.Cut(l, "\t")
		if !ok {
			out[i] = l
			continue
		}
		ws := strings.Fields(d)
		for j := 0; j < len(ws)-1; j++ {
			ws[j] += strings.Repeat(" ", width[j]-len(ws[j]))
		}
		out[i] = name + "\t" + strings.Join(ws, " ")
	}
	return out
}

// liveNames asks 'sudo -n tacctl _completion-names <kind> [arg]' for the
// names; no answer (no rule, no password) is no names.
func (inv *invocation) liveNames(ctx context.Context, kind string, extra ...string) []string {
	if inv.app == nil || inv.app.Runner == nil {
		return nil
	}
	res, err := inv.app.Runner.Run(ctx, execx.Cmd{
		Name: "sudo", Args: append([]string{"-n", "tacctl", "_completion-names", kind}, extra...)})
	if err != nil || res.Code != 0 {
		return nil
	}
	return strings.Fields(string(res.Stdout))
}
