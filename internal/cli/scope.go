package cli

// The 'scope' family (lib/scopes.sh cmd_scope at 0.1.16), native since
// WP2.4b. The sub-families take the scope name before their verb (scope
// prefixes <scope> add ...), so their verbs are arguments, not
// sub-commands. Every message, prompt, exit status and the order of the
// checks are the bash's: a check that comes before another in cmd_scope_<verb>
// comes before it here, so the same wrong command line gets the same first
// complaint.

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// scopeSpecs are the arguments of each verb, for completion (args.go).
var scopeSpecs = map[string]Spec{
	"list":    {},
	"routing": {},
	"show":    {MinArgs: 1, MaxArgs: 1, Args: []string{KindScopes}},
	"add": {MinArgs: 1, MaxArgs: 1, Args: []string{""}, Flags: []Flag{
		{Names: []string{"--prefixes"}, Value: true}, {Names: []string{"--secret"}, Value: true},
		{Names: []string{"--protocols"}, Value: true, Kind: "tacacs|radius" + KindList},
		{Names: []string{"--vendor-attrs"}, Value: true, Kind: "cisco|juniper|wti" + KindList},
		{Names: []string{"--default"}}}},
	"remove":       {MinArgs: 1, MaxArgs: 1, Args: []string{KindScopes}, Flags: []Flag{{Names: []string{"--force"}}}},
	"rename":       {MinArgs: 2, MaxArgs: 2, Args: []string{KindScopes, ""}},
	"default":      {MaxArgs: 1, Args: []string{KindScopes}},
	"lookup":       {MinArgs: 1, MaxArgs: 1, Args: []string{""}},
	"prefixes":     {MinArgs: 1, MaxArgs: 4, Args: []string{KindScopes, "list|add|remove|move", "", KindScopes}, Flags: []Flag{{Names: []string{"--all"}, Only: "remove", Alone: true}, {Names: []string{"--force"}, Only: "remove"}}},
	"staging":      {MaxArgs: 2, Args: []string{"list|remove", ""}},
	"secret":       {MinArgs: 1, MaxArgs: 3, Args: []string{KindScopes, "show|set|generate", ""}},
	"protocols":    {MinArgs: 1, MaxArgs: 3, Args: []string{KindScopes, "list|set|clear", "tacacs|radius" + KindList}},
	"vendor-attrs": {MinArgs: 1, MaxArgs: 3, Args: []string{KindScopes, "show|enable|disable", "cisco|juniper|wti" + KindList}},
	"devices":      {MinArgs: 1, MaxArgs: 4, Args: []string{KindScopes, "list|set|unset", "", After("set", "cisco|juniper|wti")}},
	"aaa-order":    {MinArgs: 1, MaxArgs: 2, Args: []string{KindScopes, "tacacs-first|local-first"}},
	"exec-timeout": {MinArgs: 1, MaxArgs: 2, Args: []string{KindScopes, ""}},
	"tacacs-group": {MinArgs: 1, MaxArgs: 2, Args: []string{KindScopes, ""}},
	"radius-group": {MinArgs: 1, MaxArgs: 2, Args: []string{KindScopes, ""}},
	"auth-method":  {MinArgs: 1, MaxArgs: 2, Args: []string{KindScopes, "tacacs|radius|clear"}},
	"mgmt-acl":     {MinArgs: 1, MaxArgs: 3, Args: []string{KindScopes, "list|add|remove|clear|cisco-name|juniper-name", ""}},
}

func scopeCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(withPreflight, run)
	}
	c := verb("scope <subcommand>", "Scope management (named CIDR + shared-secret bundles)",
		withRun(verb("list", "One row per scope (aggregated prefix list)"), n(inv.scopeListView)),
		withRun(verb("routing", "One row per (scope, prefix) — first-match order"), n(inv.scopeRouting)),
		withRun(verb("show <name>", "Detailed view"), n(inv.scopeShow)),
		withRun(verb("add <name> --prefixes <cidrs> [--secret <value>|generate] [--protocols <p>[,<p>...]] [--vendor-attrs <v>[,<v>...]] [--default]",
			"Create a new scope"), n(inv.scopeAdd)),
		withRun(verb("remove <name> [--force]", "Delete a scope (confirms)"), n(inv.scopeRemove)),
		withRun(verb("rename <old> <new>", "Rename (updates user references)"), n(inv.scopeRename)),
		withRun(verb("default [<name>]", "Show or set the default scope"), n(inv.scopeDefault)),
		withRun(verb("lookup <ip|cidr>", "Show which scope owns an address"), n(inv.scopeLookup)),
		withRun(verb("prefixes <scope> {list|add|remove} [<cidr>[,<cidr>...]] | remove --all [--force] | move <cidrs> <scope>", "Manage a scope's CIDR list"), n(inv.scopePrefixes)),
		withRun(verb("staging [list | remove <address>]", "Bench addresses of devices provisioned off-site for a scope"), n(inv.scopeStaging)),
		withRun(verb("secret <scope> {show|set <value>|generate}", "Manage a scope's shared secret"), n(inv.scopeSecret)),
		withRun(verb("protocols <scope> [list|set <protocol>[,<protocol>...]|clear]",
			"Limit a scope to some protocols (tacacs, radius); default: all"), n(inv.scopeProtocols)),
		withRun(verb("vendor-attrs <scope> [enable|disable <vendor>[,<vendor>...]]",
			"RADIUS: vendor privilege attributes sent to the scope's devices"), n(inv.scopeVendorAttrs)),
		withRun(verb("devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]",
			"RADIUS: tag an address of the scope with its vendor"), n(inv.scopeDevices)),
		withRun(verb("aaa-order <scope> [tacacs-first|local-first]",
			"AAA method-list order in this scope's rendered device configs"), n(inv.scopeAAAOrder)),
		withRun(verb("exec-timeout <scope> [minutes]",
			"Per-scope idle-session timeout in rendered device configs"), n(inv.scopeExecTimeout)),
		withRun(verb("tacacs-group <scope> [name]", "Per-scope Cisco aaa-group-server label"), n(inv.scopeTacacsGroup)),
		withRun(verb("radius-group <scope> [name]", "Per-scope Cisco aaa-group-server label for RADIUS"), n(inv.scopeRadiusGroup)),
		withRun(verb("auth-method <scope> [tacacs|radius|clear]",
			"Protocol this scope's device configs and host enrollments use"), n(inv.scopeAuthMethodCmd)),
		withRun(verb("mgmt-acl <scope> {list|add|remove|clear|cisco-name|juniper-name} [args]",
			"Per-scope permit list and ACL / filter names"), n(inv.scopeMgmtACL)),
	)
	// No sub-command, help, -h, --help: the usage, exit 0; anything else:
	// an error, the usage, exit 1.
	c.RunE = n(func(args []string) error {
		sub := arg(args, 0)
		switch sub {
		case "", "-h", "--help", "help":
			return inv.scopeUsage()
		}
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		if err := inv.scopeUsage(); err != nil {
			return err
		}
		return exit(1)
	})
	return c
}

// The protocols and vendors a scope may name (SCOPE_PROTOCOLS,
// SCOPE_VENDORS).
var (
	scopeProtocols = names.KnownProtocols
	scopeVendors   = names.KnownVendors
)

// scopeConfKeys are SCOPE_CONF_KEYS: every tacctl.yaml key stored under a
// scope's name (<key>.<scope>). 'scope rename' moves them and 'scope
// remove' drops them (scopeConfKeysMove).
var scopeConfKeys = []string{"aaa.order", "exec_timeout", "tacacs_group", "radius_group", "scope_auth_method",
	"scope_mgmt_acl.names.cisco", "scope_mgmt_acl.names.juniper", "scope_mgmt_acl.permits"}

// The ACL / filter names the device configs use when none is set
// (CISCO_ACL_NAME_DEFAULT, JUNIPER_ACL_NAME_DEFAULT).
const (
	ciscoACLNameDefault   = "VTY-ACL"
	juniperACLNameDefault = "MGMT-ACL"
)

// --- shared helpers ---------------------------------------------------------

// applyWith is 'store_apply <writer>' for a writer that does more than one
// store.Mutate (tacctl.yaml edits, several steps): fn runs under the
// snapshot StoreApply takes, every enabled backend renders and restarts as
// it needs, and the model is read again afterwards (store_apply's
// _model_invalidate).
func (inv *invocation) applyWith(fn func() error) error {
	_, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, fn)
	inv.loaded = false
	return err
}

// applyStore is 'store_apply store_<op> ...': one store.Mutate.
func (inv *invocation) applyStore(fn func(*store.Store) error) error {
	err := inv.storeApply(fn)
	inv.loaded = false
	return err
}

// mutate is one store write inside a writer (store_<op>).
func (inv *invocation) mutate(fn func(*store.Store) error) error {
	_, err := store.Mutate(inv.app.Paths.StoreFile, inv.app.MutateOptions(), fn)
	return err
}

// joinNonEmpty is "printf '%s\n' ... | awk 'NF' | paste -sd<sep>": the
// entries that are not blank, joined.
func joinNonEmpty(list []string, sep string) string {
	var out []string
	for _, s := range list {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return strings.Join(out, sep)
}

// countNonEmpty is "printf '%s\n' ... | awk 'NF' | wc -l".
func countNonEmpty(list []string) int {
	n := 0
	for _, s := range list {
		if strings.TrimSpace(s) != "" {
			n++
		}
	}
	return n
}

// captured is what '$(...)' holds for the lines of list: joined, trailing
// newlines stripped (an empty or all-blank-lines list is "").
func captured(list []string) string { return strings.TrimRight(strings.Join(list, "\n"), "\n") }

// runes is bash's ${#s} in a UTF-8 locale: the length in characters.
func runes(s string) int { return utf8.RuneCountInString(s) }

// plural is the 'entr$( [[ $n -eq 1 ]] && echo y || echo ies )' idiom.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// parseCIDRList is parse_cidr_list as its callers see it ('requested=$(
// parse_cidr_list "$arg")'): the comma-separated entries of the first line,
// each trimmed by 'echo | xargs' (an unbalanced quote: xargs's complaint,
// and the entry is skipped, as the command substitution runs without
// errexit), validated (the first invalid one: '[ERROR] Invalid CIDR', exit
// 1), canonicalised and deduplicated, in input order.
func (inv *invocation) parseCIDRList(input string) ([]string, error) {
	if i := strings.IndexByte(input, '\n'); i >= 0 {
		input = input[:i]
	}
	var out []string
	for _, raw := range strings.Split(input, ",") {
		entry, err := shellquote.XargsEcho(raw)
		if err != nil {
			inv.stderrLine("xargs: " + err.Error())
			continue
		}
		if entry == "" {
			continue
		}
		n, err := cidr.Parse(entry)
		if err != nil {
			return nil, inv.usageErr("Invalid CIDR: '" + entry + "'")
		}
		if c := n.String(); !contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// xargsWords is 'IFS=, read -ra list <<< "$arg"' with each entry through
// 'x=$(echo "$x" | xargs)' in the command's own shell: an unbalanced quote
// is xargs's complaint and exit 1 (set -e).
func (inv *invocation) xargsWords(csv string) ([]string, error) {
	if i := strings.IndexByte(csv, '\n'); i >= 0 {
		csv = csv[:i]
	}
	var out []string
	for _, raw := range strings.Split(csv, ",") {
		w, err := shellquote.XargsEcho(raw)
		if err != nil {
			inv.stderrLine("xargs: " + err.Error())
			return nil, exit(1)
		}
		out = append(out, w)
	}
	return out, nil
}

// shellWords is the unquoted '${list//,/ }' of a for loop: commas become
// blanks and the result is split on blanks (pathname expansion, which
// would apply too, is not reproduced).
func shellWords(csv string) []string {
	return strings.Fields(strings.ReplaceAll(csv, ",", " "))
}

// validated reports a validator's refusal as the bash's error() calls do:
// one [ERROR] line per message, through 'echo -e' (the messages quote the
// value as given), exit 1.
func (inv *invocation) validated(err error) error {
	var ne *names.Error
	if errors.As(err, &ne) {
		return inv.usageErr(ne.Lines()...)
	}
	return err
}

// scopeRequire is _scope_require: the scope exists, or the error naming
// the scopes there are.
func (inv *invocation) scopeRequire(name string) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	if m.Exists("scopes", name) {
		return nil
	}
	return inv.usageErr("Scope '" + name + "' does not exist. Available: " + strings.Join(m.ScopesByRouting(), " "))
}

// scopeExists is model_scope_exists, a model read error returned.
func (inv *invocation) scopeExists(name string) (bool, error) {
	m, err := inv.model()
	if err != nil {
		return false, err
	}
	return m.Exists("scopes", name), nil
}

// scopeOf is the model's scope, or nil (with the model error).
func (inv *invocation) scopeOf(name string) (*model.Scope, error) {
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	if !m.Exists("scopes", name) {
		return nil, nil
	}
	return m.Scope(name), nil
}

// confGet is conf_get <path> [fallback].
func (inv *invocation) confGet(path, fallback string) string {
	v, _ := inv.app.Conf().Get(path, fallback)
	return v
}

// scopeAuthMethod is scope_auth_method: tacacs or radius as set with
// 'scope auth-method', "" otherwise (a value the schema does not know reads
// as none).
func (inv *invocation) scopeAuthMethod(scope string) string {
	switch v := inv.confGet("scope_auth_method."+scope, ""); v {
	case "tacacs", "radius":
		return v
	}
	return ""
}

// scopeProtocolChoice is scope_protocol_choice: the protocol the scope
// decides (its auth-method, else the one protocol its filter names) and
// where it comes from ("auth-method", "protocols" or "").
func (inv *invocation) scopeProtocolChoice(scope string) (choice, source string) {
	if v := inv.scopeAuthMethod(scope); v != "" {
		return v, "auth-method"
	}
	var protocols []string
	if s, err := inv.scopeOf(scope); err == nil && s != nil {
		for _, p := range s.Protocols {
			if strings.TrimSpace(p) != "" {
				protocols = append(protocols, p)
			}
		}
	}
	if len(protocols) == 1 && !strings.Contains(protocols[0], "\n") {
		return protocols[0], "protocols"
	}
	return "", ""
}

// linuxDefaultMethodBackend is 'linux_method_backend "$(linux_default_method)"':
// the protocol of 'host default-method' (tacplus is tacacs).
func (inv *invocation) linuxDefaultMethodBackend() string {
	if inv.confGet("host.default_method", "tacplus") == "radius" {
		return "radius"
	}
	return "tacacs"
}

// scopeProtocolInEffect is _scope_protocol_in_effect.
func (inv *invocation) scopeProtocolInEffect(scope string) string {
	if choice, source := inv.scopeProtocolChoice(scope); source == "protocols" {
		return choice + ": the scope's only protocol"
	}
	return "devices: tacacs; hosts: " + inv.linuxDefaultMethodBackend()
}

// readMgmtACLName is read_mgmt_acl_name <vendor> [scope]: the per-scope
// name, else the global one, else the shipped default.
func (inv *invocation) readMgmtACLName(vendor, scope string) string {
	def := ciscoACLNameDefault
	if vendor == "juniper" {
		def = juniperACLNameDefault
	}
	global := inv.confGet("mgmt_acl.names."+vendor, def)
	if scope == "" {
		return global
	}
	return inv.confGet("scope_mgmt_acl.names."+vendor+"."+scope, global)
}

// readMgmtACLCIDRs is read_mgmt_acl_cidrs [scope]: the per-scope permits
// when there are any, else the global ones, each canonicalised (an entry
// that is no CIDR as it is).
func (inv *invocation) readMgmtACLCIDRs(scope string) []string {
	c := inv.app.Conf()
	var list []string
	if scope != "" {
		list = c.GetList("scope_mgmt_acl.permits." + scope)
	}
	if captured(list) == "" {
		list = c.GetList("mgmt_acl.permits")
	}
	var out []string
	for _, l := range strings.Split(strings.Join(list, "\n"), "\n") {
		s := strings.TrimSpace(l)
		if s == "" {
			continue
		}
		if n, err := cidr.Parse(s); err == nil {
			s = n.String()
		}
		out = append(out, s)
	}
	return out
}

// writeMgmtACLCIDRs is write_mgmt_acl_cidrs <list> [scope]: the list
// canonicalised, deduplicated and sorted by specificity (entries that are
// no CIDR dropped) replaces mgmt_acl.permits or the scope's permits; an
// empty list removes the key.
func (inv *invocation) writeMgmtACLCIDRs(list []string, scope string) error {
	path := "mgmt_acl.permits"
	if scope != "" {
		path = "scope_mgmt_acl.permits." + scope
	}
	var canon []string
	for _, l := range list {
		s := strings.TrimSpace(l)
		if s == "" {
			continue
		}
		if n, err := cidr.Parse(s); err == nil && !contains(canon, n.String()) {
			canon = append(canon, n.String())
		}
	}
	return inv.app.Conf().SetList(path, cidr.SortBySpecificity(canon))
}

// scopeConfKeysMove is _scope_conf_keys_move <old> [<new>]: every per-scope
// key of tacctl.yaml stored under old goes to new; without new it is
// dropped. tacctl.yaml is left alone when it does not mention old at all.
func (inv *invocation) scopeConfKeysMove(old, newName string) error {
	data, err := os.ReadFile(inv.app.Paths.Overrides)
	if err != nil || !bytes.Contains(data, []byte(old)) {
		return nil
	}
	c := inv.app.Conf()
	for _, key := range scopeConfKeys {
		from := key + "." + old
		if !c.HasOverride(from) {
			continue
		}
		value, _ := c.Value(from)
		if err := c.Unset(from); err != nil {
			return err
		}
		if newName != "" {
			if err := c.SetValue(key+"."+newName, value); err != nil {
				ui.Output{Stdout: inv.app.Out.Stderr}.Warn(from + " holds a value tacctl.yaml does not take; it was not carried over to '" + newName + "'.")
			}
		}
	}
	return nil
}

// --- usage, list, routing ---------------------------------------------------

// scopeUsageText is cmd_scope_usage's text: the block, then how many
// scopes there are and the default ("<unset>" when there is none).
func scopeUsageText(count int, def string) string {
	return Usage("scope", UsageVars{"current": fmt.Sprintf("Current scopes: %d\nDefault scope:  %s", count, def)})
}

// scopePrefixesUsage, scopeSecretUsage and scopeMgmtACLUsage are the help
// of the sub-families, with the numbers they end with.
func scopePrefixesUsage(scope string, entries int) string {
	return Usage("scope-prefixes", UsageVars{"scope": scope, "current": fmt.Sprintf("Current entries: %d", entries)})
}

func scopeSecretUsage(scope string, length, minLen int) string {
	return Usage("scope-secret", UsageVars{"scope": scope, "current": fmt.Sprintf("Current length: %d chars (min %d)", length, minLen)})
}

func scopeMgmtACLUsage(scope string, perScope, global int) string {
	return Usage("scope-mgmt-acl", UsageVars{"scope": scope,
		"current": fmt.Sprintf("Current entries: %d (per-scope) / %d (global fallback)", perScope, global)})
}

// scopeUsage is cmd_scope_usage.
func (inv *invocation) scopeUsage() error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	def, err := inv.defaultScope()
	if err != nil {
		return err
	}
	if def == "" {
		def = "<unset>"
	}
	inv.write(scopeUsageText(len(m.ScopeNames()), def))
	return nil
}

func (inv *invocation) scopeListView([]string) error {
	b, nc, cy := ui.Bold, ui.NC, ui.Cyan
	title := "Scopes"
	hint := cy + "(each scope's prefixes are listed under its name; 'tacctl scope routing' shows the order addresses are matched in)" + nc
	inv.echo("")
	def, err := inv.defaultScope()
	if err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	rows := m.ScopeRows(def)
	if len(rows) == 0 {
		inv.echoE(b + title + nc + " " + hint)
		inv.echo(ui.Rule(title + " " + hint))
		inv.echo("  (no scopes configured)")
		inv.echo("")
		return nil
	}
	split := func(row string) []string {
		f := strings.SplitN(row, "|", 5)
		for len(f) < 5 {
			f = append(f, "")
		}
		return f
	}
	withVendor := false
	for _, r := range rows {
		if f := strings.SplitN(r, "|", 5); len(f) == 5 && strings.TrimSpace(f[4]) != "" {
			withVendor = true
		}
	}
	cols := []ui.Col{ui.Left("NAME"), ui.Left("PREFIXES"), ui.Right("USERS"), ui.Left("DEFAULT")}
	if withVendor {
		cols = append(cols, ui.Left("VENDOR ATTRIBUTES (RADIUS)"))
	}
	t := ui.NewTable(title, cols...)
	t.Hint = hint
	for _, r := range rows {
		f := split(r)
		name, c, users, isDefault, vendor := f[0], f[1], f[2], f[3], f[4]
		if name == "" {
			if c == "" {
				continue
			}
			t.Add("", c)
			continue
		}
		if withVendor {
			if vendor == "" {
				vendor = "not sent"
			}
			t.Add(ui.Styled(ui.Bold, name), c, users, isDefault, vendor)
		} else {
			dfl := ui.Cell{}
			if isDefault == "yes" {
				dfl = ui.Styled(cy, "yes")
			}
			t.Add(ui.Styled(ui.Bold, name), c, users, dfl)
		}
	}
	inv.write(t.String())
	inv.echo("")
	return nil
}

func (inv *invocation) scopeRouting([]string) error {
	b, nc, cy := ui.Bold, ui.NC, ui.Cyan
	title := "Scope routing"
	hint := cy + "(first-match order — narrower prefixes win)" + nc
	inv.echo("")
	def, err := inv.defaultScope()
	if err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	rows := m.ScopeRouting(def)
	if len(rows) == 0 {
		inv.echoE(b + title + nc + " " + hint)
		inv.echo(ui.Rule(title + " " + hint))
		inv.echo("  (no scopes configured)")
		inv.echo("")
		return nil
	}
	t := ui.NewTable(title, ui.Right("#"), ui.Left("NAME"), ui.Left("PREFIX"), ui.Right("USERS"), ui.Left("DEFAULT"))
	t.Hint = hint
	i := 0
	for _, r := range rows {
		f := strings.SplitN(r, "|", 4)
		for len(f) < 4 {
			f = append(f, "")
		}
		if f[0] == "" {
			continue
		}
		i++
		dfl := ui.Cell{}
		if f[3] == "yes" {
			dfl = ui.Styled(cy, "yes")
		}
		t.Add(fmt.Sprint(i), ui.Styled(ui.Bold, f[0]), f[1], f[2], dfl)
	}
	inv.write(t.String())
	inv.echo("")
	return nil
}

// --- show -------------------------------------------------------------------

func (inv *invocation) scopeShow(args []string) error {
	name := arg(args, 0)
	if name == "" {
		return inv.usageErr("Usage: tacctl scope show <name>")
	}
	s, err := inv.scopeOf(name)
	if err != nil {
		return err
	}
	if s == nil {
		return inv.usageErr("Scope '" + name + "' does not exist.")
	}
	// The value itself is never printed here: 'scope secret <name> show'
	// is the one command that reveals it.
	secret := s.Secret
	n := runes(secret)
	minLen := inv.app.Tunables().SecretMinLength
	reveal := "show with 'tacctl scope secret " + name + " show'"
	var secretLine string
	switch {
	case secret == "":
		secretLine = ui.Red + "(unset)" + ui.NC
	case strings.Contains(secret, "REPLACE"):
		secretLine = fmt.Sprintf("%s(PLACEHOLDER, %d chars — run 'tacctl scope secret %s generate')%s", ui.Red, n, name, ui.NC)
	case n < minLen:
		secretLine = fmt.Sprintf("%s(set, %d chars, below min %d)%s — %s", ui.Red, n, minLen, ui.NC, reveal)
	default:
		secretLine = fmt.Sprintf("%s(set, %d chars)%s — %s", ui.Green, n, ui.NC, reveal)
	}
	def, err := inv.defaultScope()
	if err != nil {
		return err
	}
	isDefault := "no"
	if name == def {
		isDefault = "yes"
	}
	protocols := strings.Join(s.Protocols, ",")
	vendorAttrs := strings.Join(s.VendorAttrs, ",")
	authMethod := inv.scopeAuthMethod(name)
	aaaOrder := inv.confGet("aaa.order."+name, "tacacs-first")
	execTimeout := inv.confGet("exec_timeout."+name, "60")
	tacacsGroup := inv.confGet("tacacs_group."+name, "TACACS-GROUP")
	radiusGroup := inv.confGet("radius_group."+name, "RADIUS-GROUP")
	ciscoACL := inv.readMgmtACLName("cisco", name)
	juniperACL := inv.readMgmtACLName("juniper", name)
	execDisplay := execTimeout + " min"
	if execTimeout == "0" {
		execDisplay = "0 min (never expire)"
	}
	if protocols == "" {
		protocols = "all (no filter)"
	}
	if authMethod == "" {
		authMethod = "not set (" + inv.scopeProtocolInEffect(name) + ")"
	}
	if vendorAttrs == "" {
		vendorAttrs = "not sent"
	}

	b, nc := ui.Bold, ui.NC
	inv.echo("")
	inv.echoE(b + "Scope:" + nc + " " + name)
	inv.echo("--------------------------------------------")
	inv.echoE("  " + b + "Default:" + nc + "       " + isDefault)
	inv.echoE("  " + b + "Secret:" + nc + "        " + secretLine)
	inv.echoE("  " + b + "Protocols:" + nc + "     " + protocols)
	inv.echoE("  " + b + "Auth method:" + nc + "   " + authMethod)
	inv.echoE("  " + b + "Vendor attributes:" + nc + " " + vendorAttrs + "   (RADIUS; tacctl scope vendor-attrs " + name + ")")
	inv.echoE("  " + b + "AAA order:" + nc + "     " + aaaOrder)
	inv.echoE("  " + b + "Exec timeout:" + nc + "  " + execDisplay)
	inv.echoE("  " + b + "TACACS group:" + nc + "  " + tacacsGroup)
	inv.echoE("  " + b + "RADIUS group:" + nc + "  " + radiusGroup)
	inv.echoE("  " + b + "Cisco ACL:" + nc + "     " + ciscoACL)
	inv.echoE("  " + b + "Juniper ACL:" + nc + "   " + juniperACL)
	inv.echoE("  " + b + "Prefixes:" + nc)
	m, _ := inv.model()
	if pfx := m.ScopePrefixes(name); len(pfx) == 0 {
		inv.echo("    (none — no clients can match this scope)")
	} else {
		for _, c := range pfx {
			if c != "" {
				inv.echo("    - " + c)
			}
		}
	}
	if devices := m.ScopeDevices(name); len(devices) > 0 {
		inv.echoE("  " + b + "Tagged addresses:" + nc + " (RADIUS: each gets its own vendor's attribute only)")
		for _, d := range devices {
			dc, dv, _ := strings.Cut(d, "|")
			if dc != "" {
				inv.echo("    - " + dc + "  " + dv)
			}
		}
	}
	inv.echoE("  " + b + "Users:" + nc)
	if users := m.Members(name); len(users) == 0 {
		inv.echo("    (none)")
	} else {
		for _, u := range users {
			inv.echo("    - " + u)
		}
	}
	inv.echo("")
	return nil
}

// --- add --------------------------------------------------------------------

// scopePrefixCollisions is _scope_prefix_collisions: the "already claimed"
// line of every CIDR another scope than owner holds.
func (inv *invocation) scopePrefixCollisions(cidrs []string, owner string) ([]string, error) {
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, c := range cidrs {
		if o := m.PrefixOwner(c); o != "" && o != owner {
			out = append(out, "    - "+c+"  (already in scope '"+o+"')")
		}
	}
	return out, nil
}

// scopeVendorList is _scope_vendor_list: the vendors of a comma list in
// the fixed order, each once, as a csv; the error is printed.
func (inv *invocation) scopeVendorList(csv string) (string, error) {
	words := shellWords(csv)
	for _, v := range words {
		if !contains(scopeVendors, v) {
			return "", inv.usageErr("Unknown vendor '" + v + "'. Known vendors: " + strings.Join(scopeVendors, ", "))
		}
	}
	var out []string
	for _, known := range scopeVendors {
		if contains(words, known) {
			out = append(out, known)
		}
	}
	if len(out) == 0 {
		return "", inv.usageErr("No vendor given. Known vendors: " + strings.Join(scopeVendors, ", "))
	}
	return strings.Join(out, ","), nil
}

// scopeDeviceProblems prints _scope_device_problems' lines for the
// device-problems view of (scope, prefixCSV): one error per tagged address
// that would be left where it cannot be.
func (inv *invocation) scopeDeviceProblems(lines []string) {
	for _, l := range lines {
		f := strings.SplitN(l, "|", 3)
		if len(f) < 3 || f[0] == "" {
			continue
		}
		lead := "scope '" + f[0] + "': devices: "
		inv.app.Out.ErrorE("    - " + strings.TrimPrefix(f[2], lead) + "  (tagged in scope '" + f[0] +
			"'; to remove the tag: tacctl scope devices " + f[0] + " unset " + f[1] + ")")
	}
}

const scopeAddUsage = "Usage: tacctl scope add <name> --prefixes <cidrs> [--secret <value>|generate] [--protocols <protocol>[,<protocol>...]] [--vendor-attrs <vendor>[,<vendor>...]] [--default]"

func (inv *invocation) scopeAdd(args []string) error {
	a := inv.app
	name := arg(args, 0)
	if name == "" {
		return inv.usageErr(scopeAddUsage)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateScopeName(name); err != nil {
		return inv.validated(err)
	}
	if exists, err := inv.scopeExists(name); err != nil {
		return err
	} else if exists {
		return inv.usageErr("Scope '" + name + "' already exists.")
	}

	var prefixes, secretArg, protocolsArg, vendorArg string
	makeDefault := false
	rest := args[1:]
	// 'x="${2:-}"; shift 2': a value flag that ends the line fails the
	// shift, which ends the command (set -e) with nothing said.
	take := func(v *string) error {
		*v = arg(rest, 1)
		if len(rest) < 2 {
			return exit(1)
		}
		rest = rest[2:]
		return nil
	}
	for len(rest) > 0 {
		var err error
		switch rest[0] {
		case "--prefixes":
			err = take(&prefixes)
		case "--secret":
			err = take(&secretArg)
		case "--protocols":
			err = take(&protocolsArg)
		case "--vendor-attrs":
			vendorArg = arg(rest, 1)
			if vendorArg == "" {
				return inv.usageErr("--vendor-attrs needs a list of vendors (" + strings.Join(scopeVendors, ", ") + ").")
			}
			rest = rest[2:]
		case "--default":
			makeDefault = true
			rest = rest[1:]
		default:
			return inv.usageErr("Unknown flag: '" + rest[0] + "'")
		}
		if err != nil {
			return err
		}
	}

	// --protocols: the filter 'scope protocols <name> set' would write.
	var protocols []string
	if protocolsArg != "" {
		for _, p := range shellWords(protocolsArg) {
			if !contains(scopeProtocols, p) {
				return inv.usageErr("Unknown protocol '" + p + "'. Known protocols: " + strings.Join(scopeProtocols, ", "))
			}
		}
		for _, known := range scopeProtocols {
			if strings.Contains(","+protocolsArg+",", ","+known+",") {
				protocols = append(protocols, known)
			}
		}
	}
	vendorAttrs := ""
	if vendorArg != "" {
		v, err := inv.scopeVendorList(vendorArg)
		if err != nil {
			return err
		}
		vendorAttrs = v
	}

	if prefixes == "" {
		return inv.usageErr("--prefixes <cidrs> is required (comma-separated list).")
	}
	canon, err := inv.parseCIDRList(prefixes)
	if err != nil {
		return err
	}
	if len(canon) == 0 {
		return inv.usageErr("No valid CIDRs in --prefixes.")
	}
	collisions, err := inv.scopePrefixCollisions(canon, "")
	if err != nil {
		return err
	}
	if len(collisions) > 0 {
		msgs := append([]string{"Cannot create scope '" + name + "': prefix(es) already claimed:"}, collisions...)
		return inv.usageErr(append(msgs, "Each CIDR belongs to exactly one scope. Remove it from the owning",
			"scope first with 'tacctl scope prefixes <owner> remove <cidr>'.")...)
	}
	csv := strings.Join(canon, ",")
	m, _ := inv.model()
	if problems, ok := m.DeviceProblems(name, csv, "", ""); !ok {
		a.Out.ErrorE("Cannot create scope '" + name + "': it would take over an address another scope has tagged with a vendor:")
		inv.scopeDeviceProblems(problems)
		return exit(1)
	}

	var secret string
	if secretArg == "" || secretArg == "generate" {
		s, err := ui.RandomBase64(a.Knobs.Rand(), 24)
		if err != nil {
			return err
		}
		secret = s
		a.Out.InfoE("Generated secret: " + ui.Bold + secret + ui.NC)
	} else {
		secret = secretArg
		if n, minLen := runes(secret), a.Tunables().SecretMinLength; n < minLen {
			return inv.usageErr(fmt.Sprintf("Secret is %d characters; minimum is %d.", n, minLen))
		}
	}

	if err := inv.applyWith(func() error {
		fields := []string{"prefixes=" + csv, "secret=" + secret}
		if len(protocols) > 0 {
			fields = append(fields, "protocols="+strings.Join(protocols, ","))
		}
		if vendorAttrs != "" {
			fields = append(fields, "vendor_attrs="+vendorAttrs)
		}
		if err := inv.mutate(func(s *store.Store) error { return s.ScopeSet(name, fields...) }); err != nil {
			return err
		}
		if makeDefault {
			return a.Conf().Set("scope.default", name)
		}
		return nil
	}); err != nil {
		return err
	}
	if makeDefault {
		a.Out.Info("Scope '" + name + "' added and set as default.")
	} else {
		a.Out.Info("Scope '" + name + "' added.")
	}
	inv.echo("")
	return nil
}

// --- remove / rename / default / lookup --------------------------------------

// scopeMembersRefusal prints the members of a scope as 'tacctl user scope
// <u> remove <scope>' lines (stdout), between the error lines before and
// after, and exits 1.
func (inv *invocation) scopeMembersRefusal(scope string, members, before []string, after string) error {
	for _, l := range before {
		inv.app.Out.ErrorE(l)
	}
	for _, u := range members {
		inv.echo("    tacctl user scope " + u + " remove " + scope)
	}
	inv.app.Out.ErrorE(after)
	return exit(1)
}

// scopeRemoveWrite is _scope_remove_write: the scope off every user that
// still has it, gone, and its tacctl.yaml keys with it.
func (inv *invocation) scopeRemoveWrite(name string) func() error {
	return func() error {
		if err := inv.mutate(func(s *store.Store) error { return s.ScopeDel(name, true) }); err != nil {
			return err
		}
		return inv.scopeConfKeysMove(name, "")
	}
}

func (inv *invocation) scopeRemove(args []string) error {
	a := inv.app
	name := arg(args, 0)
	if name == "" {
		return inv.usageErr("Usage: tacctl scope remove <name> [--force]")
	}
	force := arg(args, 1) == "--force"
	if err := inv.requireStore(); err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("scopes", name) {
		return inv.usageErr("Scope '" + name + "' does not exist.")
	}
	if err := inv.scopeHostsRefusal(name, "Cannot remove '"+name+"'"); err != nil {
		return err
	}
	members := m.Members(name)
	if len(members) > 0 && !force {
		return inv.scopeMembersRefusal(name, members, []string{
			fmt.Sprintf("Cannot remove '%s': %d user(s) still reference it.", name, len(members)),
			"Remove them first:",
		}, "Or pass --force to strip the scope from those users AND delete it.")
	}
	def, err := inv.defaultScope()
	if err != nil {
		return err
	}
	if name == def {
		return inv.usageErr("Cannot remove '"+name+"': it is the default scope.",
			"Point the default at another scope first: tacctl scope default <other>")
	}
	a.Out.Warn("About to remove scope '" + name + "'.")
	if len(members) > 0 {
		a.Out.Warn(fmt.Sprintf("This will also strip '%s' from %d user(s).", name, len(members)))
	}
	if !a.Prompter().ConfirmPrefix("  Confirm removal? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	if err := inv.applyWith(inv.scopeRemoveWrite(name)); err != nil {
		return err
	}
	a.Out.Info("Scope '" + name + "' removed.")
	inv.echo("")
	return nil
}

func (inv *invocation) scopeRename(args []string) error {
	a := inv.app
	old, newName := arg(args, 0), arg(args, 1)
	if old == "" || newName == "" {
		return inv.usageErr("Usage: tacctl scope rename <old> <new>")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("scopes", old) {
		return inv.usageErr("Scope '" + old + "' does not exist.")
	}
	if m.Exists("scopes", newName) {
		return inv.usageErr("Scope '" + newName + "' already exists.")
	}
	if !names.MatchScope(newName) {
		return inv.usageErr("Invalid new name '" + newName + "'.")
	}
	if err := inv.applyWith(func() error {
		if err := inv.mutate(func(s *store.Store) error { return s.ScopeRename(old, newName) }); err != nil {
			return err
		}
		if err := inv.scopeConfKeysMove(old, newName); err != nil {
			return err
		}
		if inv.confGet("scope.default", "") == old {
			if err := a.Conf().Set("scope.default", newName); err != nil {
				return err
			}
			a.Out.Info("Default-scope marker updated: " + old + " -> " + newName)
		}
		return nil
	}); err != nil {
		return err
	}
	// Enrolled hosts and staging addresses name the scope too: they follow
	// it (the hosts keep its secret, which the rename does not change).
	hostsMoved, err := inv.scopeRenameHosts(old, newName)
	if err != nil {
		return err
	}
	m, err = inv.model()
	if err != nil {
		return err
	}
	a.Out.Info(fmt.Sprintf("Scope renamed: %s -> %s (%d user(s) updated).", old, newName, len(m.Members(newName))))
	if hostsMoved > 0 {
		a.Out.Info(fmt.Sprintf("Enrolled hosts registered in '%s' now name '%s': %d.", old, newName, hostsMoved))
	}
	inv.echo("")
	return nil
}

func (inv *invocation) scopeDefault(args []string) error {
	name := arg(args, 0)
	if name == "" {
		current, err := inv.defaultScope()
		if err != nil {
			return err
		}
		inv.echo("")
		if current == "" {
			inv.echo("  No default scope set (no scopes configured yet?).")
		} else {
			inv.echo("  Default scope: " + current)
		}
		inv.echo("")
		inv.echo("  Usage: tacctl scope default <name>    # set default to <name>")
		inv.echo("  The default scope is used when:")
		inv.echo("    - 'tacctl user add <u> <g>' is run without --scopes")
		inv.echo("    - 'tacctl config cisco/juniper' is run without --scope")
		inv.echo("")
		return nil
	}
	if exists, err := inv.scopeExists(name); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("Scope '" + name + "' does not exist.")
	}
	if err := inv.app.Conf().Set("scope.default", name); err != nil {
		return err
	}
	inv.app.Out.Info("Default scope set to '" + name + "'.")
	inv.echo("")
	return nil
}

// scopeLookup's exit status is 0 found, 1 no scope owns it, 2 not an
// address (the scope-lookup view's code).
func (inv *invocation) scopeLookup(args []string) error {
	query := arg(args, 0)
	if query == "" {
		return inv.usageErr("Usage: tacctl scope lookup <ip|cidr>", "Examples:",
			"  tacctl scope lookup 10.5.1.2", "  tacctl scope lookup 10.5.0.0/16")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	lines, code := m.ScopeLookup(query)
	for _, l := range lines {
		inv.echo(l)
	}
	if code != model.LookupFound {
		return exit(code)
	}
	return nil
}

// --- prefixes ---------------------------------------------------------------

func (inv *invocation) scopePrefixes(args []string) error {
	a := inv.app
	scope, sub, argv := arg(args, 0), arg(args, 1), arg(args, 2)
	if scope == "" {
		return inv.usageErr("Usage: tacctl scope prefixes <scope> {list|add|remove} [<cidrs>]",
			"       tacctl scope prefixes <scope> move <cidrs> <other-scope>",
			"       tacctl scope prefixes <scope> remove --all [--force]")
	}
	// A membership list: emptying it is 'remove --all'; the old 'clear'
	// fails naming its replacement.
	if sub == "clear" {
		return inv.usageErr("'clear' was renamed: use 'tacctl scope prefixes " + scope + " remove --all [--force]'")
	}
	removeAll, force := false, false
	if sub == "remove" && len(args) > 2 {
		others := false
		for _, x := range args[2:] {
			switch x {
			case "--all":
				others = others || removeAll
				removeAll = true
			case "--force":
				others = others || force
				force = true
			default:
				others = true
			}
		}
		if removeAll && others {
			return inv.usageErr("Usage: tacctl scope prefixes " + scope + " remove --all [--force]   ('--all' takes no CIDRs)")
		}
		if force && !removeAll {
			return inv.usageErr("Usage: tacctl scope prefixes " + scope + " remove --all --force   ('--force' is only valid with --all)")
		}
	}
	if sub == "add" || sub == "remove" || sub == "move" {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("scopes", scope) {
		return inv.usageErr("Scope '" + scope + "' does not exist.")
	}
	current := m.ScopePrefixes(scope)

	switch sub {
	case "", "-h", "--help", "help":
		inv.write(scopePrefixesUsage(scope, countNonEmpty(current)))
		return nil
	case "list":
		inv.echo("")
		inv.echoE(ui.Bold + "Prefixes for scope '" + scope + "'" + ui.NC)
		inv.echo(ui.Rule("Prefixes for scope '" + scope + "'"))
		if len(current) == 0 {
			inv.echo("  (empty — no clients can match this scope)")
		} else {
			for _, c := range current {
				if c != "" {
					inv.echo("  - " + c)
				}
			}
		}
		inv.echo("")
		return nil
	case "add", "remove":
	case "move":
		return inv.scopePrefixesMove(m, scope, argv, arg(args, 3))
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", "Run 'tacctl scope prefixes "+scope+"' for usage.")
	}

	if removeAll {
		return inv.scopePrefixesRemoveAll(scope, current, force)
	}
	if argv == "" {
		msgs := []string{"Usage: tacctl scope prefixes " + scope + " " + sub + " <cidr>[,<cidr>...]"}
		if sub == "remove" {
			msgs = append(msgs, "       tacctl scope prefixes "+scope+" remove --all [--force]")
		}
		return inv.usageErr(msgs...)
	}
	requested, err := inv.parseCIDRList(argv)
	if err != nil {
		return err
	}
	if len(requested) == 0 {
		return inv.usageErr("No valid CIDRs provided.")
	}
	var changed, skipped []string
	if sub == "add" {
		// Cross-scope collision check before any mutation: a CIDR another
		// scope owns cannot be silently stolen.
		collisions, err := inv.scopePrefixCollisions(requested, scope)
		if err != nil {
			return err
		}
		if len(collisions) > 0 {
			msgs := append([]string{"Cannot add prefix(es) to scope '" + scope + "':"}, collisions...)
			return inv.usageErr(append(msgs, "Remove them from the owning scope first:",
				"  tacctl scope prefixes <owner> remove <cidr>")...)
		}
		for _, c := range requested {
			if contains(current, c) {
				skipped = append(skipped, c)
			} else {
				changed = append(changed, c)
				current = append(current, c)
			}
		}
		if len(changed) == 0 {
			a.Out.Info("No new CIDRs (already present in '" + scope + "': " + strings.Join(skipped, " ") + ").")
			inv.echo("")
			return nil
		}
	} else {
		for _, c := range requested {
			if contains(current, c) {
				changed = append(changed, c)
				current = without(current, c)
			} else {
				skipped = append(skipped, c)
			}
		}
		if len(changed) == 0 {
			a.Out.Warn("Nothing to remove (not present: " + strings.Join(skipped, " ") + ").")
			return nil
		}
		if joinNonEmpty(current, "") == "" {
			return inv.usageErr("Cannot remove every prefix of scope '"+scope+"': a scope needs at least one.",
				"To delete the scope: tacctl scope remove "+scope)
		}
	}
	// Tagged addresses must stay inside a prefix of their scope: refused,
	// not dropped.
	newCSV := joinNonEmpty(current, ",")
	if problems, ok := m.DeviceProblems(scope, newCSV, "", ""); !ok {
		if sub == "remove" {
			a.Out.ErrorE("Cannot remove the prefix(es) from scope '" + scope + "': a tagged address would be left outside the scope's prefixes:")
		} else {
			a.Out.ErrorE("Cannot add the prefix(es) to scope '" + scope + "': it would take over an address another scope has tagged with a vendor:")
		}
		inv.scopeDeviceProblems(problems)
		return inv.usageErr("Nothing was changed. Unset the tag first, or (when moving a range) add the new prefix before removing the old one.")
	}
	if err := inv.applyStore(func(s *store.Store) error { return s.ScopeSet(scope, "prefixes="+newCSV) }); err != nil {
		return err
	}
	v := "Added"
	if sub == "remove" {
		v = "Removed"
	}
	a.Out.Info(fmt.Sprintf("%s %d prefix(es) for scope '%s': %s", v, len(changed), scope, strings.Join(changed, " ")))
	if len(skipped) > 0 {
		a.Out.Info("(Skipped: " + strings.Join(skipped, " ") + ")")
	}
	inv.echo("")
	return nil
}

// scopePrefixesMove is 'scope prefixes <from> move <cidrs> <to>': the
// prefixes leave one scope and join another in one change, so the
// addresses they hold are never answered by neither. The enrolled hosts
// whose addresses another scope then answers are named, with the move
// that follows them; none is moved here.
func (inv *invocation) scopePrefixesMove(m *model.Model, from, list, to string) error {
	a := inv.app
	if list == "" || to == "" {
		return inv.usageErr("Usage: tacctl scope prefixes " + from + " move <cidr>[,<cidr>...] <other-scope>")
	}
	if !m.Exists("scopes", to) {
		return inv.usageErr("Scope '" + to + "' does not exist.")
	}
	if to == from {
		return inv.usageErr("The prefixes are already in scope '" + from + "'.")
	}
	requested, err := inv.parseCIDRList(list)
	if err != nil {
		return err
	}
	if len(requested) == 0 {
		return inv.usageErr("No valid CIDRs provided.")
	}
	src, dst := m.ScopePrefixes(from), m.ScopePrefixes(to)
	var missing []string
	for _, c := range requested {
		if !contains(src, c) {
			missing = append(missing, c)
		}
	}
	if len(missing) > 0 {
		return inv.usageErr("Not prefixes of scope '" + from + "': " + strings.Join(missing, " ") + ". Nothing was changed.")
	}
	for _, c := range requested {
		src = without(src, c)
		if !contains(dst, c) {
			dst = append(dst, c)
		}
	}
	if joinNonEmpty(src, "") == "" {
		return inv.usageErr("Cannot move every prefix of scope '"+from+"': a scope needs at least one. Nothing was changed.",
			"Add another prefix to it first, or move its users and hosts and remove it: tacctl scope remove "+from)
	}
	srcCSV, dstCSV := joinNonEmpty(src, ","), joinNonEmpty(dst, ",")
	if problems, ok := m.DeviceProblems(from, srcCSV, "", ""); !ok {
		a.Out.ErrorE("Cannot move the prefix(es) out of scope '" + from + "': a tagged address would be left outside the scope's prefixes:")
		inv.scopeDeviceProblems(problems)
		return inv.usageErr("Nothing was changed. Unset the tag first.")
	}
	if problems, ok := m.DeviceProblems(to, dstCSV, "", ""); !ok {
		a.Out.ErrorE("Cannot move the prefix(es) into scope '" + to + "': it would take over an address another scope has tagged with a vendor:")
		inv.scopeDeviceProblems(problems)
		return inv.usageErr("Nothing was changed. Unset the tag first.")
	}
	if err := inv.applyStore(func(s *store.Store) error {
		if err := s.ScopeSet(from, "prefixes="+srcCSV); err != nil {
			return err
		}
		return s.ScopeSet(to, "prefixes="+dstCSV)
	}); err != nil {
		return err
	}
	a.Out.Info(fmt.Sprintf("Moved %d prefix(es) from scope '%s' to '%s': %s", len(requested), from, to, strings.Join(requested, " ")))
	inv.hostDriftReport()
	inv.echo("")
	return nil
}

// scopeRenameHosts names the new scope in every registry line and staging
// entry that named the old one; the number of hosts changed.
func (inv *invocation) scopeRenameHosts(old, newName string) (int, error) {
	reg, err := inv.registry()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range reg.Entries() {
		if e.Scope != old {
			continue
		}
		e.Scope = newName
		if err := reg.Replace(e); err != nil {
			return n, err
		}
		n++
	}
	entries := inv.stagingLoad()
	changed := false
	for i := range entries {
		if entries[i].Scope == old {
			entries[i].Scope, changed = newName, true
		}
	}
	if changed {
		if err := inv.stagingSave(entries); err != nil {
			return n, err
		}
	}
	return n, nil
}

// scopeHostsRefusal refuses to remove a scope enrolled hosts use: they
// hold its secret, so their logins would fail. Moving them is the way.
func (inv *invocation) scopeHostsRefusal(scope, what string) error {
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	var used []string
	for _, e := range reg.Entries() {
		if e.Scope == scope {
			used = append(used, e.Name)
		}
	}
	if len(used) == 0 {
		return nil
	}
	return inv.usageErr(what+": enrolled hosts use it: "+strings.Join(used, ", ")+". Nothing was changed.",
		"Move each one to another scope first: tacctl host move <host> [<scope>]   (or: tacctl host unenroll <host>)")
}

// without is list minus every entry equal to s ('grep -vxF').
func without(list []string, s string) []string {
	var out []string
	for _, x := range list {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// scopePrefixesRemoveAll is _scope_prefixes_remove_all: a scope cannot
// exist without a prefix, so removing them all removes the scope, with the
// guard of 'scope remove' (users still referencing it need --force).
func (inv *invocation) scopePrefixesRemoveAll(scope string, current []string, force bool) error {
	a := inv.app
	if len(current) == 0 {
		a.Out.Info("Scope '" + scope + "' prefix list is already empty.")
		return nil
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if err := inv.scopeHostsRefusal(scope, "Cannot remove every prefix of '"+scope+"' (that removes the scope)"); err != nil {
		return err
	}
	members := m.Members(scope)
	if len(members) > 0 && !force {
		return inv.scopeMembersRefusal(scope, members, []string{
			fmt.Sprintf("Cannot remove every prefix of '%s': %d user(s) still reference it.", scope, len(members)),
			"Removing every prefix removes the scope, and with it those users' grant.",
			"Detach users first:",
		}, "Or pass --force to strip the scope from those users AND remove it.")
	}
	a.Out.Warn(fmt.Sprintf("Removing all %d prefix(es) from '%s' removes the scope.", len(current), scope))
	if len(members) > 0 {
		a.Out.Warn(fmt.Sprintf("%d user(s) will lose their grant of '%s'.", len(members), scope))
	}
	if !a.Prompter().ConfirmPrefix("  Confirm? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	if err := inv.applyWith(inv.scopeRemoveWrite(scope)); err != nil {
		return err
	}
	a.Out.Info("Removed all prefixes from scope '" + scope + "' (the scope is removed).")
	inv.echo("")
	return nil
}

// --- secret -----------------------------------------------------------------

var (
	reLowerOnly = regexp.MustCompile(`^[a-z]+$`)
	reUpperOnly = regexp.MustCompile(`^[A-Z]+$`)
	reDigitOnly = regexp.MustCompile(`^[0-9]+$`)
)

func (inv *invocation) scopeSecret(args []string) error {
	a := inv.app
	scope, sub, value := arg(args, 0), arg(args, 1), arg(args, 2)
	if scope == "" {
		return inv.usageErr("Usage: tacctl scope secret <scope> {show|set <value>|generate}")
	}
	if sub == "set" || sub == "generate" {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	s, err := inv.scopeOf(scope)
	if err != nil {
		return err
	}
	if s == nil {
		return inv.usageErr("Scope '" + scope + "' does not exist.")
	}
	cur := s.Secret
	n := runes(cur)
	minLen := a.Tunables().SecretMinLength
	b, nc := ui.Bold, ui.NC
	switch sub {
	case "", "-h", "--help", "help":
		inv.write(scopeSecretUsage(scope, n, minLen))
	case "show":
		inv.echo("")
		inv.echoE(b + "Scope '" + scope + "' — shared secret" + nc)
		inv.echo(ui.Rule("Scope '" + scope + "' — shared secret"))
		switch {
		case cur == "":
			inv.echoE("  " + ui.Red + "(unset)" + nc)
		case strings.Contains(cur, "REPLACE"):
			inv.echoE("  Value:  " + b + cur + nc)
			inv.echoE(fmt.Sprintf("  %sLength: %d chars — PLACEHOLDER (run 'tacctl scope secret %s generate')%s", ui.Red, n, scope, nc))
		case n < minLen:
			inv.echoE("  Value:  " + b + cur + nc)
			inv.echoE(fmt.Sprintf("  %sLength: %d chars (below min %d)%s", ui.Red, n, minLen, nc))
		default:
			inv.echoE("  Value:  " + b + cur + nc)
			inv.echoE(fmt.Sprintf("  %sLength: %d chars%s", ui.Green, n, nc))
		}
		inv.echo("")
	case "set":
		if value == "" {
			return inv.usageErr("Usage: tacctl scope secret " + scope + " set <value>")
		}
		if l := runes(value); l < minLen {
			return inv.usageErr(fmt.Sprintf("Secret is %d characters; minimum is %d.", l, minLen))
		}
		if reLowerOnly.MatchString(value) || reUpperOnly.MatchString(value) || reDigitOnly.MatchString(value) {
			return inv.usageErr("Secret is single-character-class (low entropy).")
		}
		if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "secret="+value) }); err != nil {
			return err
		}
		a.Out.Info("Scope '" + scope + "' secret updated.")
		a.Out.WarnE("Update ALL devices in scope '" + scope + "' with the new secret: " + value)
		inv.echo("")
	case "generate":
		v, err := ui.RandomBase64(a.Knobs.Rand(), 24)
		if err != nil {
			return err
		}
		inv.echoE("  Generated: " + b + v + nc)
		if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "secret="+v) }); err != nil {
			return err
		}
		a.Out.Info("Scope '" + scope + "' secret updated.")
		a.Out.Warn("Update ALL devices in scope '" + scope + "' with the new secret above.")
		inv.echo("")
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", "Run 'tacctl scope secret "+scope+"' for usage.")
	}
	return nil
}

// --- protocols --------------------------------------------------------------

func (inv *invocation) scopeProtocols(args []string) error {
	a := inv.app
	scope, sub, value := arg(args, 0), arg(args, 1), arg(args, 2)
	usage := "Usage: tacctl scope protocols " + scope + " [list|set <protocol>[,<protocol>...]|clear]"
	if scope == "" {
		return inv.usageErr("Usage: tacctl scope protocols <scope> [list|set <protocol>[,<protocol>...]|clear]")
	}
	if sub == "set" || sub == "clear" {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	s, err := inv.scopeOf(scope)
	if err != nil {
		return err
	}
	if s == nil {
		return inv.usageErr("Scope '" + scope + "' does not exist.")
	}
	current := joinNonEmpty(s.Protocols, ",")
	known := strings.Join(scopeProtocols, ", ")

	switch sub {
	case "", "list", "-h", "--help", "help":
		inv.echo("")
		if current == "" {
			inv.echo("  Scope '" + scope + "' protocols: all (no filter — every enabled backend serves it)")
		} else {
			inv.echo("  Scope '" + scope + "' protocols: " + current)
		}
		inv.echo("")
		inv.echo("  Usage: tacctl scope protocols " + scope + " set <protocol>[,<protocol>...]   (known: " + known + ")")
		inv.echo("         tacctl scope protocols " + scope + " clear                            (back to all)")
		inv.echo("")
	case "set":
		if value == "" {
			return inv.usageErr("Usage: tacctl scope protocols "+scope+" set <protocol>[,<protocol>...]", "Known protocols: "+known)
		}
		words, err := inv.xargsWords(value)
		if err != nil {
			return err
		}
		var wanted []string
		for _, p := range words {
			if p == "" {
				continue
			}
			if !contains(scopeProtocols, p) {
				return inv.usageErr("Unknown protocol '" + p + "'. Known protocols: " + known)
			}
			wanted = append(wanted, p)
		}
		var list []string
		for _, k := range scopeProtocols {
			if contains(wanted, k) {
				list = append(list, k)
			}
		}
		newList := strings.Join(list, ",")
		if newList == "" {
			return inv.usageErr("No protocols given. To remove the filter: tacctl scope protocols " + scope + " clear")
		}
		if newList == current {
			a.Out.Info("Scope '" + scope + "' protocols already " + newList + ".")
			inv.echo("")
			return nil
		}
		// A filter without the scope's auth-method would leave the
		// defaults it names pointing at a backend that ignores the scope.
		if am := inv.scopeAuthMethod(scope); am != "" && !contains(list, am) {
			return inv.usageErr("Scope '"+scope+"' has auth-method "+am+", which protocols '"+newList+"' would leave unserved. Nothing was changed.",
				"Change or clear the auth-method first: tacctl scope auth-method "+scope+" <tacacs|radius|clear>   (or keep "+am+" in the list)")
		}
		if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "protocols="+newList) }); err != nil {
			return err
		}
		a.Out.Info("Scope '" + scope + "' protocols set to " + newList + ".")
		if !contains(list, "tacacs") {
			a.Out.Warn("Scope '" + scope + "' is no longer served over TACACS+: its devices and its users' grant of it are left out of tacquito.yaml.")
		}
		inv.echo("")
	case "clear":
		if current == "" {
			a.Out.Info("Scope '" + scope + "' has no protocols filter.")
			inv.echo("")
			return nil
		}
		if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "protocols=null") }); err != nil {
			return err
		}
		a.Out.Info("Scope '" + scope + "' protocols filter cleared (every enabled backend serves it).")
		inv.echo("")
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", usage)
	}
	return nil
}

// --- vendor-attrs / devices -------------------------------------------------

// scopeVendorRadiusNotes is _scope_vendor_radius_notes: why a vendor
// attribute change has no effect yet, if it has none.
func (inv *invocation) scopeVendorRadiusNotes(scope string) {
	a := inv.app
	var protocols string
	if s, err := inv.scopeOf(scope); err == nil && s != nil {
		protocols = joinNonEmpty(s.Protocols, ",")
	}
	if protocols != "" && !strings.Contains(","+protocols+",", ",radius,") {
		a.Out.Warn("Scope '" + scope + "' is limited to " + protocols + " (tacctl scope protocols), so it is not served over RADIUS and this has no effect yet.")
	} else if ids, err := a.Backends().Enabled(); err == nil && !contains(ids, backend.RADIUS) {
		a.Out.Warn("The RADIUS backend is not enabled on this server, so this has no effect yet: tacctl backend enable radius")
	}
}

func (inv *invocation) scopeVendorAttrs(args []string) error {
	a := inv.app
	scope, sub, value := arg(args, 0), arg(args, 1), arg(args, 2)
	vendors := strings.Join(scopeVendors, ", ")
	usage := "Usage: tacctl scope vendor-attrs <scope> [enable <vendor>[,<vendor>...]|disable <vendor>[,<vendor>...]]"
	if scope == "" {
		return inv.usageErr(usage, "Vendors: "+vendors)
	}
	if sub == "enable" || sub == "disable" {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	s, err := inv.scopeOf(scope)
	if err != nil {
		return err
	}
	if s == nil {
		return inv.usageErr("Scope '" + scope + "' does not exist.")
	}
	current := joinNonEmpty(s.VendorAttrs, ",")
	m, _ := inv.model()

	switch sub {
	case "", "show", "list", "-h", "--help", "help":
		tagged := len(m.ScopeDevices(scope))
		shown := current
		if shown == "" {
			shown = "not sent"
		}
		inv.echo("")
		inv.echo("  Scope '" + scope + "' vendor attributes: " + shown)
		if tagged > 0 {
			inv.echo(fmt.Sprintf("  Tagged addresses: %d (each gets its own vendor's attribute only; tacctl scope devices %s)", tagged, scope))
		}
		inv.write(`
    Over RADIUS an Access-Accept always carries Service-Type. A vendor's privilege attribute
    is added only when that vendor is enabled here (for every device of the scope that is not
    tagged) or the device's address is tagged with it:
      cisco    Cisco-AVPair "shell:priv-lvl=<N>"   (the group's privilege level)
      juniper  Juniper-Local-User-Name            (the group's Juniper class)
      wti      WTI-Super                          (0 ViewOnly, 1 User, 2 SuperUser, 3 Administrator)
    TACACS+ is not affected.

`)
		inv.echo("  Usage: tacctl scope vendor-attrs " + scope + " enable <vendor>[,<vendor>...]    (vendors: " + vendors + ")")
		inv.echo("         tacctl scope vendor-attrs " + scope + " disable <vendor>[,<vendor>...]")
		inv.echo("")
		return nil
	case "enable", "disable":
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'. The verbs are enable and disable: nothing is sent until a vendor is enabled.", usage)
	}

	if value == "" {
		return inv.usageErr("Usage: tacctl scope vendor-attrs "+scope+" "+sub+" <vendor>[,<vendor>...]", "Vendors: "+vendors)
	}
	wanted, err := inv.scopeVendorList(value)
	if err != nil {
		return err
	}
	in := func(csv, v string) bool { return strings.Contains(","+csv+",", ","+v+",") }
	var newList, changed []string
	for _, v := range scopeVendors {
		switch {
		case in(wanted, v):
			if sub == "enable" {
				newList = append(newList, v)
				if !in(current, v) {
					changed = append(changed, v)
				}
			} else if in(current, v) {
				changed = append(changed, v)
			}
		case in(current, v):
			newList = append(newList, v)
		}
	}
	newCSV := strings.Join(newList, ",")
	if len(changed) == 0 {
		if sub == "enable" {
			a.Out.Info("Scope '" + scope + "': " + strings.ReplaceAll(wanted, ",", ", ") + " already enabled (vendor attributes: " +
				strings.ReplaceAll(current, ",", ", ") + ").")
		} else {
			shown := current
			if shown == "" {
				shown = "not sent"
			}
			a.Out.Info("Scope '" + scope + "': " + strings.ReplaceAll(wanted, ",", ", ") + " not enabled; no change (vendor attributes: " + shown + ").")
		}
		inv.echo("")
		return nil
	}
	stored := newCSV
	if stored == "" {
		stored = "null"
	}
	if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "vendor_attrs="+stored) }); err != nil {
		return err
	}
	ch := strings.Join(changed, ", ")
	if sub == "enable" {
		a.Out.Info("Scope '" + scope + "': vendor attributes enabled: " + ch + ". Now sent: " + strings.ReplaceAll(newCSV, ",", ", ") + ".")
	} else {
		now := newCSV
		if now == "" {
			now = "not sent"
		}
		a.Out.Info("Scope '" + scope + "': vendor attributes disabled: " + ch + ". Now: " + now + ".")
		var still []string
		for _, d := range m.ScopeDevices(scope) {
			dc, dv, _ := strings.Cut(d, "|")
			if dc != "" && strings.Contains(", "+ch+", ", ", "+dv+", ") {
				still = append(still, dc)
			}
		}
		if len(still) > 0 {
			a.Out.Info("Tagged addresses keep their vendor's attribute: " + strings.Join(still, ", ") + " (tacctl scope devices " + scope + ").")
		}
	}
	inv.scopeVendorRadiusNotes(scope)
	inv.echo("")
	return nil
}

func (inv *invocation) scopeDevices(args []string) error {
	a := inv.app
	scope, sub, addr, vendor := arg(args, 0), arg(args, 1), arg(args, 2), arg(args, 3)
	vendors := strings.Join(scopeVendors, ", ")
	usage := "Usage: tacctl scope devices <scope> [set <ip|cidr> <vendor>|unset <ip|cidr>]"
	if scope == "" {
		return inv.usageErr(usage)
	}
	if sub == "set" || sub == "unset" {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("scopes", scope) {
		return inv.usageErr("Scope '" + scope + "' does not exist.")
	}
	// An engineer tags the addresses of their own scopes only (D18).
	if err := inv.ownScope(inv.callerScopes(), scope); err != nil {
		return err
	}
	current := m.ScopeDevices(scope)

	switch sub {
	case "", "list", "-h", "--help", "help":
		attrs := joinNonEmpty(m.Scope(scope).VendorAttrs, ",")
		if attrs == "" {
			attrs = "not sent"
		}
		inv.echo("")
		title := "Tagged addresses of scope '" + scope + "'"
		if len(current) == 0 {
			inv.echoE(ui.Bold + title + ui.NC + " (RADIUS)")
			inv.echo(ui.Rule(title + " (RADIUS)"))
			inv.echo("  (none)")
		} else {
			t := ui.NewTable(title, ui.Left("ADDRESS"), ui.Left("VENDOR"))
			t.Hint = "(RADIUS)"
			for _, d := range current {
				dc, dv, _ := strings.Cut(d, "|")
				if dc != "" {
					t.Add(dc, dv)
				}
			}
			inv.write(t.String())
		}
		inv.echo("")
		inv.echo("  A tagged address gets its own vendor's attribute and no other vendor's.")
		inv.echo("  Every other device of the scope gets what the scope enables: " + attrs + " (tacctl scope vendor-attrs " + scope + ").")
		inv.echo("")
		inv.echo("  Usage: tacctl scope devices " + scope + " set <ip|cidr> <vendor>    (vendors: " + vendors + ")")
		inv.echo("         tacctl scope devices " + scope + " unset <ip|cidr>")
		inv.echo("")
		return nil
	case "set", "unset":
	default:
		return inv.usageErr("Unknown subcommand: '"+sub+"'", usage)
	}

	if addr == "" || (sub == "set" && vendor == "") || (sub == "unset" && vendor != "") {
		if sub == "set" {
			return inv.usageErr("Usage: tacctl scope devices " + scope + " set <ip|cidr> <vendor>   (vendors: " + vendors + ")")
		}
		return inv.usageErr("Usage: tacctl scope devices " + scope + " unset <ip|cidr>")
	}
	c := cidr.Canonical(addr)
	if c == "" {
		return inv.usageErr("Invalid address or CIDR: '" + addr + "'")
	}
	had := ""
	var newMap []string
	for _, d := range current {
		dc, dv, _ := strings.Cut(d, "|")
		if dc == "" {
			continue
		}
		if dc == c {
			had = dv
		} else {
			newMap = append(newMap, dc+"="+dv)
		}
	}

	if sub == "unset" {
		if had == "" {
			a.Out.Info(c + " is not tagged in scope '" + scope + "'; no change.")
			inv.echo("")
			return nil
		}
		stored := strings.Join(newMap, ",")
		if stored == "" {
			stored = "null"
		}
		if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "devices="+stored) }); err != nil {
			return err
		}
		a.Out.Info("Scope '" + scope + "': " + c + " is no longer tagged (it was " + had + "); it gets what the scope enables (tacctl scope vendor-attrs " + scope + ").")
		inv.echo("")
		return nil
	}

	if !contains(scopeVendors, vendor) {
		return inv.usageErr("Unknown vendor '" + vendor + "'. Known vendors: " + vendors)
	}
	if had == vendor {
		a.Out.Info(c + " is already tagged " + vendor + " in scope '" + scope + "'; no change.")
		inv.echo("")
		return nil
	}
	prefixCSV := joinNonEmpty(m.Scope(scope).Prefixes, ",")
	if problems, ok := m.DeviceProblems(scope, prefixCSV, c, vendor); !ok {
		a.Out.ErrorE("Cannot tag " + c + " in scope '" + scope + "': a tagged address must be one this scope answers for ('tacctl scope lookup " + addr + "').")
		for _, l := range problems {
			f := strings.SplitN(l, "|", 3)
			if len(f) < 3 || f[1] != c {
				continue
			}
			a.Out.ErrorE("    - " + strings.TrimPrefix(f[2], "scope '"+f[0]+"': devices: "))
		}
		return inv.usageErr("Nothing was changed.")
	}
	entries := append(newMap, c+"="+vendor)
	if err := inv.applyStore(func(st *store.Store) error { return st.ScopeSet(scope, "devices="+strings.Join(entries, ",")) }); err != nil {
		return err
	}
	if had != "" {
		a.Out.Info("Scope '" + scope + "': " + c + " is now tagged " + vendor + " (it was " + had + ").")
	} else {
		a.Out.Info("Scope '" + scope + "': " + c + " tagged " + vendor + ": over RADIUS it gets that vendor's attribute only.")
	}
	inv.scopeVendorRadiusNotes(scope)
	inv.echo("")
	return nil
}

// --- aaa-order, exec-timeout, tacacs-group, radius-group ---------------------

// scopeKnob is the common shape of the four per-scope device-render
// settings: show the value (or its default) and its source, or set it.
type scopeKnob struct {
	verb, usage, key, def string
	shown                 func(current string) string // the "Scope 's' ...: <v>" line's tail
	help                  []string                    // the explanation lines
	setUsage              string                      // "<...>" of the Usage line
	set                   func(inv *invocation, scope, value string)
}

func (inv *invocation) scopeKnob(k scopeKnob, args []string) error {
	scope, value := arg(args, 0), arg(args, 1)
	if scope == "" {
		return inv.usageErr(k.usage)
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	path := k.key + "." + scope
	current, source := inv.confGet(path, ""), "override (tacctl.yaml: "+path+")"
	if current == "" {
		current, source = k.def, "default"
	}
	if value == "" {
		inv.echo("")
		inv.echo("  Scope '" + scope + "'")
		inv.echo("  " + k.shown(current))
		inv.echo("  Source: " + source)
		inv.echo("")
		for _, l := range k.help {
			inv.echo(l)
		}
		inv.echo("")
		inv.echo("  Usage: tacctl scope " + k.verb + " " + scope + " " + k.setUsage)
		inv.echo("")
		return nil
	}
	if err := inv.app.Conf().Set(path, value); err != nil {
		return err
	}
	k.set(inv, scope, value)
	return nil
}

func (inv *invocation) scopeAAAOrder(args []string) error {
	return inv.scopeKnob(scopeKnob{
		verb: "aaa-order", usage: "Usage: tacctl scope aaa-order <scope> [tacacs-first|local-first]", key: "aaa.order", def: "tacacs-first",
		shown: func(v string) string { return "AAA method-list order: " + v },
		help: []string{
			"    tacacs-first  The server (TACACS+ or RADIUS) is authoritative; local used only on server outage.",
			"    local-first   Local DB checked first; the server used for names not found locally.",
		},
		setUsage: "<tacacs-first|local-first>",
		set: func(inv *invocation, scope, v string) {
			inv.app.Out.Info("Scope '" + scope + "' AAA method-list order set to " + v + ".")
			if v == "local-first" {
				inv.app.Out.Warn("Local usernames that collide with tacctl users will win locally on devices in this scope (TACACS+ and RADIUS).")
				inv.app.Out.Warn("Scope local accounts to break-glass / emergency use only.")
			}
			inv.echo("")
			inv.echo("  Re-run 'tacctl config cisco --scope " + scope + "' / 'tacctl config juniper --scope " + scope + "'")
			inv.echo("  and push the updated method-lists to each device in this scope — the change is not")
			inv.echo("  applied until the device receives the new AAA stanzas.")
			inv.echo("")
		},
	}, args)
}

func (inv *invocation) scopeExecTimeout(args []string) error {
	return inv.scopeKnob(scopeKnob{
		verb: "exec-timeout", usage: "Usage: tacctl scope exec-timeout <scope> [minutes]", key: "exec_timeout", def: "60",
		shown:    func(v string) string { return "exec-timeout: " + v + " minute(s)" },
		help:     []string{"    0..60 minutes. 0 = never expire (both Cisco and Junos)."},
		setUsage: "<minutes>",
		set: func(inv *invocation, scope, v string) {
			inv.app.Out.InfoE("Scope '" + scope + "' exec-timeout set to " + v + " minute(s).")
			if v == "0" {
				inv.app.Out.Warn("exec-timeout 0 disables idle-session expiry on devices in this scope.")
				inv.app.Out.Warn("Long-lived sessions on unattended terminals become a security risk.")
			}
			inv.echo("")
			inv.echo("  Re-run 'tacctl config cisco --scope " + scope + "' / 'tacctl config juniper --scope " + scope + "'")
			inv.echo("  and push the updated line-config / login stanzas to each device in this scope.")
			inv.echo("")
		},
	}, args)
}

func (inv *invocation) scopeTacacsGroup(args []string) error {
	return inv.scopeKnob(scopeKnob{
		verb: "tacacs-group", usage: "Usage: tacctl scope tacacs-group <scope> [name]", key: "tacacs_group", def: "TACACS-GROUP",
		shown: func(v string) string { return "Cisco aaa-group-server name: " + v },
		help: []string{
			"    Rendered into every 'aaa group server tacacs+ <NAME>' and the method-list",
			"    / accounting lines that reference the group (Cisco only; Junos has no",
			"    equivalent).",
		},
		setUsage: "<name>",
		set: func(inv *invocation, scope, v string) {
			inv.app.Out.InfoE("Scope '" + scope + "' aaa-group-server label set to " + v + ".")
			inv.echo("")
			inv.echo("  Re-run 'tacctl config cisco --scope " + scope + "' and push the updated AAA")
			inv.echo("  stanzas to each device in this scope — the change is not applied until")
			inv.echo("  the device receives the new group name. Leaving a stale local group")
			inv.echo("  reference on the device will break authentication.")
			inv.echo("")
		},
	}, args)
}

func (inv *invocation) scopeRadiusGroup(args []string) error {
	return inv.scopeKnob(scopeKnob{
		verb: "radius-group", usage: "Usage: tacctl scope radius-group <scope> [name]", key: "radius_group", def: "RADIUS-GROUP",
		shown: func(v string) string { return "Cisco RADIUS aaa-group-server name: " + v },
		help: []string{
			"    Rendered into every 'aaa group server radius <NAME>' and the method-list",
			"    / accounting lines that reference the group by",
			"    'tacctl config cisco --protocol radius' (Cisco only; Junos has no",
			"    equivalent).",
		},
		setUsage: "<name>",
		set: func(inv *invocation, scope, v string) {
			inv.app.Out.InfoE("Scope '" + scope + "' RADIUS aaa-group-server label set to " + v + ".")
			inv.echo("")
			inv.echo("  Re-run 'tacctl config cisco --scope " + scope + " --protocol radius' and push the")
			inv.echo("  updated AAA stanzas to each device in this scope — the change is not applied")
			inv.echo("  until the device receives the new group name. Leaving a stale local group")
			inv.echo("  reference on the device will break authentication.")
			inv.echo("")
		},
	}, args)
}

// --- auth-method ------------------------------------------------------------

func (inv *invocation) scopeAuthMethodCmd(args []string) error {
	a := inv.app
	scope, method := arg(args, 0), arg(args, 1)
	if scope == "" {
		return inv.usageErr("Usage: tacctl scope auth-method <scope> [tacacs|radius|clear]")
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	current := inv.scopeAuthMethod(scope)
	source := "override (tacctl.yaml: scope_auth_method." + scope + ")"
	if current == "" {
		source = "default (not set)"
	}
	if method == "" {
		shown := current
		if shown == "" {
			shown = "not set"
		}
		inv.echo("")
		inv.echo("  Scope '" + scope + "' auth-method: " + shown)
		inv.echo("  Source: " + source)
		if current == "" {
			inv.echo("  In effect: " + inv.scopeProtocolInEffect(scope))
		}
		inv.write(`
    Used when the command names no protocol: 'tacctl config cisco|juniper|wti' without
    --protocol, 'tacctl host enroll' (a host not yet registered) and
    'tacctl config linux script' without --method. Without it: the scope's only
    protocol when 'tacctl scope protocols' names exactly one, else tacacs for device
    configs and 'tacctl host default-method' for hosts.

`)
		inv.echo("  Usage: tacctl scope auth-method " + scope + " <tacacs|radius|clear>")
		inv.echo("")
		return nil
	}
	switch method {
	case "tacplus":
		method = "tacacs"
	case "tacacs", "radius":
	case "clear", "default":
		if inv.confGet("scope_auth_method."+scope, "") == "" {
			a.Out.Info("Scope '" + scope + "' has no auth-method set; no change.")
			inv.echo("")
			return nil
		}
		if err := a.Conf().Unset("scope_auth_method." + scope); err != nil {
			return err
		}
		a.Out.Info("Scope '" + scope + "' auth-method cleared (in effect: " + inv.scopeProtocolInEffect(scope) + ").")
		inv.echo("")
		return nil
	default:
		return inv.usageErr("Unknown auth-method '" + method + "'. Use tacacs, radius or clear.")
	}
	// A protocols filter that leaves the method out: every config made
	// from this default would not work.
	var protocols string
	if s, err := inv.scopeOf(scope); err == nil && s != nil {
		protocols = joinNonEmpty(s.Protocols, ",")
	}
	if protocols != "" && !strings.Contains(","+protocols+",", ","+method+",") {
		return inv.usageErr("Scope '"+scope+"' is limited to "+protocols+" (tacctl scope protocols), so it is not served over "+method+".",
			"Serve it over "+method+" first: tacctl scope protocols "+scope+" set "+protocols+","+method+"   (or 'clear' for every protocol)")
	}
	if method == current {
		a.Out.Info("Scope '" + scope + "' auth-method already " + method + "; no change.")
		inv.echo("")
		return nil
	}
	if err := a.Conf().Set("scope_auth_method."+scope, method); err != nil {
		return err
	}
	a.Out.Info("Scope '" + scope + "' auth-method set to " + method + ".")
	if ids, err := a.Backends().Enabled(); err == nil && !contains(ids, method) {
		a.Out.Warn("The " + method + " backend is not enabled on this server: tacctl backend enable " + method)
	}
	inv.echo("")
	inv.echo("  'tacctl config cisco|juniper|wti --scope " + scope + "' and new 'tacctl host enroll --scope " + scope + "'")
	inv.echo("  now use " + method + " unless told otherwise. Devices and hosts already configured are not")
	inv.echo("  changed: push the new device config, or re-enroll a host with --method, to switch them.")
	inv.echo("")
	return nil
}

// --- mgmt-acl ---------------------------------------------------------------

func (inv *invocation) scopeMgmtACL(args []string) error {
	a := inv.app
	scope, sub, value := arg(args, 0), arg(args, 1), arg(args, 2)
	if scope == "" {
		return inv.usageErr("Usage: tacctl scope mgmt-acl <scope> <list|add|remove|clear|cisco-name|juniper-name> [args]")
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	c := a.Conf()
	path := "scope_mgmt_acl.permits." + scope
	switch sub {
	case "", "-h", "--help", "help":
		inv.write(scopeMgmtACLUsage(scope, len(inv.readMgmtACLCIDRs(scope)), len(inv.readMgmtACLCIDRs(""))))
	case "list":
		scopeEntries, globalEntries := c.GetList(path), c.GetList("mgmt_acl.permits")
		inv.echo("")
		inv.echoE(ui.Bold + "Management ACL for scope '" + scope + "'" + ui.NC)
		inv.echo(ui.Rule("Management ACL for scope '" + scope + "'"))
		switch {
		case captured(scopeEntries) != "":
			inv.echo("  Source: per-scope override (scope_mgmt_acl.permits." + scope + ")")
			inv.listLines(scopeEntries)
		case captured(globalEntries) != "":
			inv.echo("  Source: global (mgmt_acl.permits) — per-scope list is empty")
			inv.listLines(globalEntries)
		default:
			inv.echo("  (empty — both per-scope and global lists are unset)")
			inv.echo("")
			inv.echo("  Add to this scope only:  tacctl scope mgmt-acl " + scope + " add <cidr>")
			inv.echo("  Add to the global list:  tacctl config mgmt-acl add <cidr>")
		}
		inv.echo("")
	case "add":
		if value == "" {
			return inv.usageErr("Usage: tacctl scope mgmt-acl " + scope + " add <cidr>[,<cidr>...]")
		}
		requested, err := inv.parseCIDRList(value)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return inv.usageErr("No valid CIDRs provided.")
		}
		current := c.GetList(path)
		var added, skipped []string
		for _, x := range requested {
			if contains(current, x) {
				skipped = append(skipped, x)
			} else {
				added = append(added, x)
				current = append(current, x)
			}
		}
		if len(added) == 0 {
			a.Out.Info("No new CIDRs to add to scope '" + scope + "' (already present: " + strings.Join(skipped, " ") + ").")
			inv.echo("")
			return nil
		}
		if err := inv.writeMgmtACLCIDRs(current, scope); err != nil {
			return err
		}
		a.Out.Info(fmt.Sprintf("Added %d to scope '%s' mgmt-acl: %s", len(added), scope, strings.Join(added, " ")))
		if len(skipped) > 0 {
			a.Out.Info("(Already present, unchanged: " + strings.Join(skipped, " ") + ")")
		}
		a.Out.Info("Re-run 'tacctl config cisco --scope " + scope + "' / 'tacctl config juniper --scope " + scope + "' to see the new output.")
		inv.echo("")
	case "remove":
		if value == "" {
			return inv.usageErr("Usage: tacctl scope mgmt-acl " + scope + " remove <cidr>[,<cidr>...]")
		}
		requested, err := inv.parseCIDRList(value)
		if err != nil {
			return err
		}
		if len(requested) == 0 {
			return inv.usageErr("No valid CIDRs provided.")
		}
		current := c.GetList(path)
		if captured(current) == "" {
			a.Out.Warn("Nothing to remove — scope '" + scope + "' has no per-scope permits (rendering from the global list).")
			return nil
		}
		var removed, missing []string
		for _, x := range requested {
			if contains(current, x) {
				removed = append(removed, x)
				current = without(current, x)
			} else {
				missing = append(missing, x)
			}
		}
		if len(removed) == 0 {
			a.Out.Warn("Nothing to remove (not present in per-scope list: " + strings.Join(missing, " ") + ").")
			return nil
		}
		if err := inv.writeMgmtACLCIDRs(current, scope); err != nil {
			return err
		}
		a.Out.Info(fmt.Sprintf("Removed %d from scope '%s' mgmt-acl: %s", len(removed), scope, strings.Join(removed, " ")))
		if len(missing) > 0 {
			a.Out.Info("(Not present, skipped: " + strings.Join(missing, " ") + ")")
		}
		inv.echo("")
	case "clear":
		if captured(c.GetList(path)) == "" {
			a.Out.Info("Per-scope list for '" + scope + "' is already empty (render falls back to global).")
			inv.echo("")
			return nil
		}
		if !a.Prompter().ConfirmPrefix("  Clear all per-scope mgmt-acl entries for '" + scope + "'? Render will fall back to global. [y/N]: ") {
			a.Out.Info("Aborted.")
			return nil
		}
		if err := c.Unset(path); err != nil {
			return err
		}
		a.Out.Info("Per-scope mgmt-acl cleared for '" + scope + "'.")
		inv.echo("")
	case "cisco-name", "juniper-name":
		vendor := strings.TrimSuffix(sub, "-name")
		key := "scope_mgmt_acl.names." + vendor + "." + scope
		current := inv.confGet(key, "")
		effective := inv.readMgmtACLName(vendor, scope)
		var source string
		if current == "" {
			shipped := ciscoACLNameDefault
			if vendor == "juniper" {
				shipped = juniperACLNameDefault
			}
			if inv.confGet("mgmt_acl.names."+vendor, shipped) == shipped {
				source = "default"
			} else {
				source = "global (tacctl config mgmt-acl " + vendor + "-name)"
			}
		} else {
			source = "override (tacctl.yaml: " + key + ")"
		}
		if value == "" {
			inv.echo("")
			inv.echo("  Scope '" + scope + "' " + vendor + " mgmt-acl name: " + effective)
			inv.echo("  Source: " + source)
			inv.echo("")
			inv.echo("    Rendered into " + vendor + " device configs for this scope only.")
			inv.echo("    Clear the per-scope override by setting it to the global value.")
			inv.echo("")
			inv.echo("  Usage: tacctl scope mgmt-acl " + scope + " " + sub + " <name>")
			inv.echo("")
			return nil
		}
		if err := c.Set(key, value); err != nil {
			return err
		}
		a.Out.InfoE("Scope '" + scope + "' " + vendor + " mgmt-acl name set to " + value + ".")
		inv.echo("")
		inv.echo("  Re-run 'tacctl config " + vendor + " --scope " + scope + "' and push the updated")
		inv.echo("  ACL / filter block to each device in this scope. A stale ACL name on")
		inv.echo("  the device will still reference the old filter until replaced.")
		inv.echo("")
	default:
		return inv.usageErr("Unknown subcommand '" + sub + "'. Use: list | add | remove | clear | cisco-name | juniper-name.")
	}
	return nil
}

// listLines is 'echo "$list" | while read -r e; do [[ -z $e ]] && continue;
// echo "  - $e"; done'.
func (inv *invocation) listLines(list []string) {
	for _, e := range strings.Split(strings.Join(list, "\n"), "\n") {
		if e != "" {
			inv.echo("  - " + e)
		}
	}
}
