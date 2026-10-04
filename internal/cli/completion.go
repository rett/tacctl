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

	"github.com/rett/tacctl/internal/execx"
)

// configPaths are the shipped top-level keys 'config get' completes, as a
// word list; nested paths are typed by hand.
const configPaths = "bcrypt.cost|password.max_age_days|password.min_length|secret.min_length|scope.default|" +
	"mgmt_acl.names.cisco|mgmt_acl.names.juniper|mgmt_acl.permits|privileges.operator|" +
	"commands.superuser|commands.operator|commands.readonly"

// topSpecs are the verbs outside the families.
var topSpecs = map[string]Spec{
	"install":   {Flags: []Flag{{Names: []string{"--branch"}, Value: true}, {Names: []string{"-y", "--yes"}}}},
	"upgrade":   {Flags: []Flag{{Names: []string{"--branch"}, Value: true}}},
	"uninstall": {Flags: []Flag{{Names: []string{"-y", "--yes"}}}},
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
		case len(path) == 2:
			s, ok = configSpecs[path[1]]
		case path[1] == "linux":
			s, ok = configLinuxSpecs[path[2]]
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
				c.ValidArgsFunction = func(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
					return inv.completeSpec(spec, args, toComplete)
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
	kind := ""
	if pos < len(spec.Args) {
		kind = spec.Args[pos]
	}
	if rest, ok := strings.CutPrefix(kind, "@"); ok {
		word, k, _ := strings.Cut(rest, ":")
		kind = ""
		if slices.Contains(words, word) {
			kind = k
		}
	}
	var out []cobra.Completion
	dir := cobra.ShellCompDirectiveNoFileComp
	if !alone {
		out, dir = inv.completeKind(kind, toComplete, values)
	}
	if strings.HasPrefix(toComplete, "-") || (kind != KindFile && pos >= spec.MinArgs) {
		for i := range spec.Flags {
			f := &spec.Flags[i]
			if seen[f.Names[0]] || (f.Only != "" && !slices.Contains(words, f.Only)) {
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
		cur := strings.TrimPrefix(toComplete, prefix)
		var out []cobra.Completion
		for _, w := range inv.kindWords(base, values) {
			if strings.HasPrefix(w, cur) && !slices.Contains(have, w) {
				out = append(out, prefix+w)
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
	return out, cobra.ShellCompDirectiveNoFileComp
}

// kindWords are all the words of a kind: a fixed list written 'a|b|c', or
// the live names of a _completion-names kind.
func (inv *invocation) kindWords(kind string, values map[string]string) []string {
	if strings.Contains(kind, "|") {
		return strings.Split(kind, "|")
	}
	switch kind {
	case KindUsers, KindGroups, KindScopes, KindHosts, KindDevices, KindBackups, KindBackends, KindEnabledBackends:
		return inv.liveNames(inv.ctx, kind)
	case KindListeners:
		if b := values["--backend"]; b != "" {
			return inv.liveNames(inv.ctx, kind, b)
		}
		return inv.liveNames(inv.ctx, kind)
	}
	// A single fixed word ('1|2' lists have the bar; one word has none).
	return []string{kind}
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
