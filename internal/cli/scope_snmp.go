package cli

// 'scope snmp' (D41 and D46 of docs/plans/0.2.3-plan.md): the SNMP settings
// of a scope, with 'config snmp' as the default beneath them. The scope's
// non-secret settings are tacctl.yaml's snmp_scope.<scope>.* (written only
// when set), its community and v3 passphrases are StateDir/snmp/<scope>.yaml
// (0600, internal/snmpcred; never printed but by 'show --reveal'). The
// device walkthroughs render the effective values with the scope's allowed
// clients and contact (internal/devices/snmp.go).
//
// The verbs that set or clear anything, and 'test', are the superuser's. The
// tier gate sees 'scope snmp' only, so the engineer's part is decided here
// (the shape of 'scope secret'): an engineer reads the scopes of their own
// ('show' with or without --reveal, and the plain reads of version, port,
// timeout, contact and clients list), and every reveal is logged.

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/snmpcred"
	"github.com/rett/tacctl/internal/ui"
)

const scopeSNMPUse = "snmp <scope> {show [--reveal]|version|community|v3-user|clients|contact|port|timeout|clear|test}"

const scopeSNMPShort = "SNMP settings, credentials, allowed clients and contact of a scope"

// scopeSNMPSpecs are the arguments of each verb after the scope.
var scopeSNMPSpecs = map[string]Spec{
	"show":      {MaxArgs: 0, Flags: []Flag{{Names: []string{"--reveal"}}}},
	"version":   {MaxArgs: 1, Args: []string{"v2c|v3"}},
	"community": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--stdin"}}}},
	"v3-user": {MinArgs: 1, MaxArgs: 1, Args: []string{""}, Flags: []Flag{
		{Names: []string{"--auth"}, Value: true, Kind: strings.Join(snmp.AuthProtocols, "|")},
		{Names: []string{"--priv"}, Value: true},
		{Names: []string{"--stdin"}}}},
	"clients": {MaxArgs: 2, Args: []string{"list|add|remove", ""}},
	"contact": {MaxArgs: -1, Flags: []Flag{{Names: []string{"--clear"}}}},
	"port":    {MaxArgs: 1, Args: []string{""}},
	"timeout": {MaxArgs: 1, Args: []string{""}},
	"clear":   {MaxArgs: 0},
	"test":    {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices}},
}

// scopeSNMPVerbs are the verbs ({Use, Short}), in usage order.
var scopeSNMPVerbs = [][2]string{
	{"show [--reveal]", "The scope's SNMP settings, where each value comes from, and the allowed clients; --reveal also prints the credentials"},
	{"version [v2c|v3]", "Show or set the SNMP version of the scope's devices"},
	{"community [--stdin]", "Set the scope's v2c community (asked twice, not echoed); the scope's version becomes v2c"},
	{"v3-user <user> [--auth sha|sha256] [--priv aes128] [--stdin]",
		"Set the scope's v3 user and passphrases (authPriv); the scope's version becomes v3"},
	{"clients list|add|remove [<cidr>[,<cidr>...]]", "The ranges allowed to query the devices (IPv4; the tacctl server is always first, 0.0.0.0/0 is always refused last)"},
	{"contact [<text>|--clear]", "Show, set or remove the scope's SNMP contact"},
	{"port [<n>]", "Show or set the agents' UDP port for the scope (default: the default's)"},
	{"timeout [<seconds>]", "Show or set the wait for an answer for the scope, 1-10"},
	{"clear", "Remove the scope's own SNMP settings and credentials: the default applies again"},
	{"test <address|device>", "Read the sysName of one device with the scope's settings"},
}

// scopeSNMPOptions are the option lines under a verb's row.
var scopeSNMPOptions = map[string][][2]string{
	"show": {
		{"--reveal", "Print the community or the v3 passphrases (an engineer: their own scopes; logged)"},
	},
	"v3-user": {
		{"--auth sha|sha256", "HMAC-SHA-96 or HMAC-SHA-256-192 (default: the default's, else sha)"},
		{"--priv aes128", "AES-128 (the only one)"},
		{"--stdin", "(community, v3-user) Read the secrets from stdin, one per line"},
	},
	"contact": {
		{"--clear", "Remove the contact"},
	},
}

// scopeSNMPUsage is the usage of 'scope snmp'.
func scopeSNMPUsage(scope string) string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "tacctl scope snmp " + scope + ui.NC + " — SNMP for the devices of scope '" + scope + "'\n\nUsage: tacctl scope snmp " + scope + " <subcommand>\n\n")
	for _, v := range scopeSNMPVerbs {
		use, short := v[0], v[1]
		if len(use) > 40 {
			b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 40) + "  " + short + "\n")
		} else {
			fmt.Fprintf(&b, "  %-40s  %s\n", use, short)
		}
		for _, o := range scopeSNMPOptions[strings.Fields(use)[0]] {
			fmt.Fprintf(&b, "      %-36s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
A setting the scope does not set comes from the default ('tacctl config snmp'),
then the built-in; 'show' says which. The device walkthroughs ('tacctl config
cisco|juniper|wti') render the effective values for the scope, and 'device add'
and 'device check' read a device's sysName with the credentials of its scope.
The allowed clients are the tacctl server's own address first (always), the
scope's ranges in the order given, then 0.0.0.0/0 refused (always, never
stored). The scope's settings are in tacctl.yaml (snmp_scope.<scope>.*), its
credentials in /etc/tacctl/snmp/<scope>.yaml (0600), which tacctl never prints
but for 'show --reveal'.

Examples:
  tacctl scope snmp ` + scope + ` community
  tacctl scope snmp ` + scope + ` clients add 192.0.2.0/24,198.51.100.7
  tacctl scope snmp ` + scope + ` contact 'NOC <noc@example.net>'
  tacctl scope snmp ` + scope + ` show --reveal

`)
	return b.String()
}

// scopeSNMP dispatches 'scope snmp <scope> <subcommand>'.
func (inv *invocation) scopeSNMP(args []string) error {
	scope, sub := arg(args, 0), arg(args, 1)
	if scope == "" {
		return inv.usageErr("Usage: tacctl scope snmp <scope> <show|version|community|v3-user|clients|contact|port|timeout|clear|test> [args]")
	}
	f := inv.callerScopes()
	if f.restricted {
		if err := inv.scopeNotFound(f, scope); err != nil {
			return err
		}
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	switch sub {
	case "", "-h", "--help", "help":
		inv.write(scopeSNMPUsage(scope))
		return nil
	}
	spec, ok := scopeSNMPSpecs[sub]
	if !ok {
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(scopeSNMPUsage(scope))
		return exit(1)
	}
	var rest []string
	if len(args) > 2 {
		rest = args[2:]
	}
	p, err := Parse(spec, rest)
	if err != nil {
		return inv.scopeSNMPUsageErr(scope, sub, err)
	}
	// An engineer reads and changes nothing (D45; the gate sees 'scope snmp'
	// only).
	if f.restricted && !scopeSNMPRead(sub, p) {
		return inv.usageErr("The engineer tier reads a scope's SNMP settings: tacctl scope snmp " + scope +
			" show [--reveal]. Changing them is the superuser's. Nothing was changed.")
	}
	switch sub {
	case "show":
		return inv.scopeSNMPShow(scope, p.Has("--reveal"), f.restricted)
	case "version":
		return inv.scopeSNMPVersion(scope, p)
	case "community":
		return inv.scopeSNMPCommunity(scope, p)
	case "v3-user":
		return inv.scopeSNMPV3User(scope, p)
	case "clients":
		return inv.scopeSNMPClients(scope, p)
	case "contact":
		return inv.scopeSNMPContact(scope, p)
	case "port":
		return inv.scopeSNMPNumber(scope, p, conf.SNMPKeyPort, "port", "UDP port", "1-65535", 1, 65535)
	case "timeout":
		return inv.scopeSNMPNumber(scope, p, conf.SNMPKeyTimeout, "timeout", "timeout", "1-10", snmp.MinTimeout, snmp.MaxTimeout)
	case "clear":
		return inv.scopeSNMPClear(scope)
	default:
		return inv.scopeSNMPTest(scope, p)
	}
}

// scopeSNMPRead reports whether the verb as given only reads: what an
// engineer may run.
func scopeSNMPRead(sub string, p Parsed) bool {
	switch sub {
	case "show":
		return true
	case "version", "port", "timeout":
		return len(p.Args) == 0
	case "contact":
		return len(p.Args) == 0 && !p.Has("--clear")
	case "clients":
		return len(p.Args) == 0 || p.Args[0] == "list"
	}
	return false
}

func (inv *invocation) scopeSNMPUsageErr(scope, verbName string, err error) error {
	var use string
	for _, v := range scopeSNMPVerbs {
		if strings.Fields(v[0])[0] == verbName {
			use = v[0]
		}
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	return inv.usageErr(msg, "Usage: tacctl scope snmp "+scope+" "+use)
}

// from is the label of where a value comes from.
func from(src string) string { return "(" + src + ")" }

// scopeSNMPShow is 'show': the effective settings with their sources, the
// allowed clients and, with --reveal, the credentials. An engineer's reveal
// is logged (never the value).
func (inv *invocation) scopeSNMPShow(scope string, reveal, restricted bool) error {
	e, err := inv.snmpEffective(scope)
	if err != nil {
		return err
	}
	own := policy.SNMPSettings(inv.app.Conf(), scope)
	if reveal && restricted {
		inv.secretRead("snmp", scope)
	}
	title := "SNMP for scope '" + scope + "'"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	switch e.Version {
	case "":
		inv.echo("  version:    not set (the scope's walkthroughs say SNMP is not configured)  " + from(snmpcred.NotSet))
	case snmp.V2c:
		inv.echo("  version:    v2c (the community)  " + from(e.VersionFrom))
	case snmp.V3:
		inv.echo("  version:    v3 (the user, authPriv)  " + from(e.VersionFrom))
	default:
		inv.echo("  version:    " + e.Version + "  " + from(e.VersionFrom))
	}
	inv.echo("  port:       " + strconv.Itoa(e.Port) + "  " + from(e.PortFrom))
	inv.echo("  timeout:    " + strconv.Itoa(e.Timeout) + " s, one retry  " + from(e.TimeoutFrom))
	secret := func(set bool, value string) string {
		switch {
		case !set:
			return "not set"
		case reveal:
			return value
		}
		return "set"
	}
	inv.echo("  community:  " + secret(e.Community != "", e.Community) + "  " + from(commFrom(e)))
	if e.Version == snmp.V3 || e.V3From != snmpcred.NotSet {
		user := "not set"
		if e.User != "" {
			user = e.User
		}
		inv.echo("  v3 user:    " + user + "  " + from(e.V3From))
		inv.echo("  v3 passphrases: auth " + secret(e.AuthPass != "", e.AuthPass) + ", priv " + secret(e.PrivPass != "", e.PrivPass) + "  " + from(e.V3From))
		inv.echo("  v3 auth:    " + e.Auth + "  " + from(e.AuthFrom) + "; priv: " + e.Priv + "  " + from(e.PrivFrom))
	}
	if own.Contact == "" {
		inv.echo("  contact:    not set (the walkthroughs leave a placeholder and list it as unfilled)")
	} else {
		inv.echo("  contact:    " + own.Contact + "  " + from(snmpcred.FromScope))
	}
	inv.echo("  clients:    the tacctl server first (its /32; always), then the scope's ranges, then 0.0.0.0/0 refused (always, never stored)")
	if len(own.Clients) == 0 {
		inv.echo("              the scope lists no ranges: only the tacctl server may query (scope snmp " + scope + " clients add <cidr>)")
	}
	for _, c := range own.Clients {
		inv.echo("              " + c)
	}
	for _, w := range cidr.OverlapWarnings(own.Clients) {
		inv.echo("  Note:       " + w + " (both stay)")
	}
	// A device's own settings come first (D72): which of the scope's
	// devices have some.
	inv.echo("  order:      a device's own setting first (tacctl device snmp <name>), then the scope's, then the default's, then the built-in")
	if devs := inv.scopeDevicesWithSNMP(scope); len(devs) > 0 {
		inv.echo("  devices with settings of their own: " + strings.Join(devs, ", ") + " (tacctl device snmp <name> show)")
	}
	switch {
	case reveal && restricted:
		inv.echo("  Reveal logged: the secrets above are the scope's own or the default's, as labelled.")
	case !reveal:
		inv.echo("  Credentials: " + inv.app.Paths.SNMPDir + "/" + scope + ".yaml (0600; 'show --reveal' prints them)")
	}
	inv.echo("")
	return nil
}

// commFrom is where the community comes from, or "not set".
func commFrom(e snmpcred.Effective) string { return e.CommunityFrom }

// scopeSNMPVersion shows or sets the scope's version.
func (inv *invocation) scopeSNMPVersion(scope string, p Parsed) error {
	c := inv.app.Conf()
	if len(p.Args) == 0 {
		e, err := inv.snmpEffective(scope)
		if err != nil {
			return err
		}
		if e.Version == "" {
			inv.echo("not set")
			return nil
		}
		inv.echo(e.Version + "  " + from(e.VersionFrom))
		return nil
	}
	v := p.Args[0]
	if v != snmp.V2c && v != snmp.V3 {
		return inv.usageErr("Unknown version '"+v+"': v2c or v3.", "Usage: tacctl scope snmp "+scope+" version [v2c|v3]")
	}
	if err := c.Set(conf.SNMPPath(scope, conf.SNMPKeyVersion), v); err != nil {
		return err
	}
	inv.app.Out.Info("SNMP version of scope '" + scope + "' set to " + v + ".")
	inv.scopeSNMPHint(scope)
	return nil
}

// scopeSNMPHint says what is missing for the scope's lookups after a
// change, so a half-configured scope is not a surprise.
func (inv *invocation) scopeSNMPHint(scope string) {
	if _, problem := inv.snmpConfigFor(scope); problem != "" {
		inv.app.Out.Warn("Not usable yet: " + problem + ".")
	}
}

func (inv *invocation) scopeSNMPCommunity(scope string, p Parsed) error {
	s, err := inv.readSecret(p.Has("--stdin"), "community")
	if err != nil {
		return err
	}
	if msg := secretProblem(s, "the community", 1, names.SNMPCommunityMax); msg != "" {
		return inv.usageErr(msg)
	}
	a := inv.app
	cr, err := snmpcred.LoadScope(a.Paths.SNMPDir, scope)
	if err != nil {
		return err
	}
	cr.Community = s
	if err := snmpcred.SaveScope(a.Paths.SNMPDir, scope, cr); err != nil {
		return err
	}
	if err := a.Conf().Set(conf.SNMPPath(scope, conf.SNMPKeyVersion), snmp.V2c); err != nil {
		return err
	}
	a.Out.InfoE("SNMP community of scope '" + scope + "' set (" + a.Paths.SNMPDir + "/" + scope + ".yaml); the scope's version is v2c. Try it: tacctl scope snmp " + scope + " test <address>")
	return nil
}

func (inv *invocation) scopeSNMPV3User(scope string, p Parsed) error {
	user := p.Args[0]
	if !reSNMPUser.MatchString(user) || names.SNMPTokenProblem(user, names.SNMPUserMax) != "" {
		return inv.usageErr("Invalid SNMPv3 user '" + user + "': 1-32 printable characters, no blanks, no '?' or '\"'.")
	}
	auth, priv := p.Value("--auth"), p.Value("--priv")
	if p.Has("--auth") && auth != snmp.AuthSHA && auth != snmp.AuthSHA256 {
		return inv.usageErr("Unknown --auth '" + auth + "': sha or sha256.")
	}
	if p.Has("--priv") && priv != snmp.PrivAES128 {
		return inv.usageErr("Unknown --priv '" + priv + "': aes128.")
	}
	stdin := p.Has("--stdin")
	ap, err := inv.readSecret(stdin, "authentication passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(ap, "the authentication passphrase", 8, names.SNMPPassphraseMax); msg != "" {
		return inv.usageErr(msg)
	}
	pp, err := inv.readSecret(stdin, "privacy passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(pp, "the privacy passphrase", 8, names.SNMPPassphraseMax); msg != "" {
		return inv.usageErr(msg)
	}
	a := inv.app
	cr, err := snmpcred.LoadScope(a.Paths.SNMPDir, scope)
	if err != nil {
		return err
	}
	cr.User, cr.AuthPass, cr.PrivPass = user, ap, pp
	if err := snmpcred.SaveScope(a.Paths.SNMPDir, scope, cr); err != nil {
		return err
	}
	c := a.Conf()
	if err := c.Set(conf.SNMPPath(scope, conf.SNMPKeyVersion), snmp.V3); err != nil {
		return err
	}
	if auth != "" {
		if err := c.Set(conf.SNMPPath(scope, conf.SNMPKeyAuth), auth); err != nil {
			return err
		}
	}
	if priv != "" {
		if err := c.Set(conf.SNMPPath(scope, conf.SNMPKeyPriv), priv); err != nil {
			return err
		}
	}
	e, err := inv.snmpEffective(scope)
	if err != nil {
		return err
	}
	a.Out.InfoE("SNMPv3 user and passphrases of scope '" + scope + "' set (" + a.Paths.SNMPDir + "/" + scope + ".yaml); the scope's version is v3, auth " +
		e.Auth + ", priv " + e.Priv + ". Try it: tacctl scope snmp " + scope + " test <address>")
	return nil
}

// scopeSNMPClients lists, adds and removes the scope's allowed ranges.
func (inv *invocation) scopeSNMPClients(scope string, p Parsed) error {
	a := inv.app
	c := a.Conf()
	action := "list"
	if len(p.Args) > 0 {
		action = p.Args[0]
	}
	cur := policy.SNMPClients(c, scope)
	switch action {
	case "list":
		inv.echo("")
		title := "Allowed SNMP clients of scope '" + scope + "'"
		inv.echoE(ui.Bold + title + ui.NC)
		inv.echo(ui.Rule(title))
		inv.echo("  1. the tacctl server's own /32 (always first; the address its route to the devices uses, or --source of the walkthrough)")
		for i, r := range cur {
			inv.echo(fmt.Sprintf("  %d. %s", i+2, r))
		}
		if len(cur) == 0 {
			inv.echo("  (the scope lists no ranges: only the tacctl server may query; add one with: tacctl scope snmp " + scope + " clients add <cidr>)")
		}
		inv.echo(fmt.Sprintf("  %d. 0.0.0.0/0 refused (always last, never stored)", len(cur)+2))
		for _, w := range cidr.OverlapWarnings(cur) {
			inv.echo("  Note: " + w + " (both stay)")
		}
		inv.echo("")
		return nil
	case "add", "remove":
	default:
		return inv.usageErr("Unknown action '"+action+"': list, add or remove.", "Usage: tacctl scope snmp "+scope+" clients list|add|remove [<cidr>[,<cidr>...]]")
	}
	if len(p.Args) < 2 || p.Args[1] == "" {
		return inv.usageErr("Usage: tacctl scope snmp " + scope + " clients " + action + " <cidr>[,<cidr>...]")
	}
	requested, err := inv.parseCIDRList(p.Args[1])
	if err != nil {
		return err
	}
	if len(requested) == 0 {
		return inv.usageErr("No valid CIDRs provided.")
	}
	if action == "add" {
		for _, r := range requested {
			if why := cidr.ClientProblem(r); why != "" {
				return inv.usageErr("'" + r + "' " + why + ". Nothing was changed.")
			}
		}
		added, skipped, err := policy.AddSNMPClients(c, scope, requested)
		if err != nil {
			var ve *conf.ValidationError
			if errors.As(err, &ve) {
				return inv.usageErr(fmt.Sprintf("A scope lists at most %d client ranges (it has %d). Nothing was changed.", cidr.MaxSNMPClients, len(cur)))
			}
			return err
		}
		if len(added) == 0 {
			a.Out.Info("No new ranges to add to scope '" + scope + "' (already present: " + strings.Join(skipped, " ") + ").")
			return nil
		}
		a.Out.Info(fmt.Sprintf("Added %d allowed SNMP client range(s) to scope '%s': %s", len(added), scope, strings.Join(added, " ")))
		if len(skipped) > 0 {
			a.Out.Info("(Already present, unchanged: " + strings.Join(skipped, " ") + ")")
		}
		for _, w := range cidr.OverlapWarnings(policy.SNMPClients(c, scope)) {
			for _, x := range added {
				if strings.Contains(w, x) {
					a.Out.Warn(w + " (both stay).")
					break
				}
			}
		}
		a.Out.Info("Re-run 'tacctl config cisco|juniper|wti --scope " + scope + "' to see the new output.")
		return nil
	}
	if len(cur) == 0 {
		a.Out.Warn("Nothing to remove: scope '" + scope + "' lists no SNMP client ranges.")
		return nil
	}
	removed, missing, err := policy.RemoveSNMPClients(c, scope, requested)
	if err != nil {
		return err
	}
	if len(removed) == 0 {
		a.Out.Warn("Nothing to remove (not in the list: " + strings.Join(missing, " ") + ").")
		return nil
	}
	a.Out.Info(fmt.Sprintf("Removed %d SNMP client range(s) from scope '%s': %s", len(removed), scope, strings.Join(removed, " ")))
	if len(missing) > 0 {
		a.Out.Info("(Not in the list, skipped: " + strings.Join(missing, " ") + ")")
	}
	return nil
}

// scopeSNMPContact shows, sets or removes the scope's contact.
func (inv *invocation) scopeSNMPContact(scope string, p Parsed) error {
	a := inv.app
	c := a.Conf()
	if p.Has("--clear") {
		if len(p.Args) > 0 {
			return inv.usageErr("--clear takes no text.", "Usage: tacctl scope snmp "+scope+" contact [<text>|--clear]")
		}
		if !c.HasOverride(conf.SNMPPath(scope, conf.SNMPKeyContact)) {
			a.Out.Info("Scope '" + scope + "' has no contact; nothing was changed.")
			return nil
		}
		if err := policy.ClearSNMPKey(c, scope, conf.SNMPKeyContact); err != nil {
			return err
		}
		a.Out.Info("Contact of scope '" + scope + "' removed.")
		return nil
	}
	if len(p.Args) == 0 {
		if cur := policy.SNMPContact(c, scope); cur != "" {
			inv.echo(cur)
		} else {
			inv.echo("not set")
		}
		return nil
	}
	text := strings.Join(p.Args, " ")
	if msg := conf.SNMPTextProblem(text); msg != "" {
		return inv.usageErr("The contact " + msg + ".")
	}
	if err := policy.SetSNMPContact(c, scope, text); err != nil {
		return err
	}
	a.Out.Info("Contact of scope '" + scope + "' set to '" + text + "'.")
	return nil
}

// scopeSNMPNumber shows or sets the scope's port or timeout.
func (inv *invocation) scopeSNMPNumber(scope string, p Parsed, key, verbName, what, rng string, lo, hi int) error {
	if len(p.Args) == 0 {
		e, err := inv.snmpEffective(scope)
		if err != nil {
			return err
		}
		n, src := e.Port, e.PortFrom
		if key == conf.SNMPKeyTimeout {
			n, src = e.Timeout, e.TimeoutFrom
		}
		inv.echo(strconv.Itoa(n) + "  " + from(src))
		return nil
	}
	v := p.Args[0]
	if n, err := strconv.Atoi(v); err != nil || n < lo || n > hi || strconv.Itoa(n) != v {
		return inv.usageErr("Invalid " + what + " '" + v + "': expected " + rng + ".")
	}
	if err := inv.app.Conf().Set(conf.SNMPPath(scope, key), v); err != nil {
		return err
	}
	inv.app.Out.Info("SNMP " + what + " of scope '" + scope + "' set to " + v + ".")
	return nil
}

// scopeSNMPClear removes the scope's own settings and credentials.
func (inv *invocation) scopeSNMPClear(scope string) error {
	a := inv.app
	cr, err := snmpcred.LoadScope(a.Paths.SNMPDir, scope)
	if err != nil {
		return err
	}
	had := !cr.Empty() || policy.SNMPSet(a.Conf(), scope)
	if err := inv.scopeSNMPDrop(scope); err != nil {
		return err
	}
	if !had {
		a.Out.Info("Scope '" + scope + "' has no SNMP settings of its own; nothing was changed.")
		return nil
	}
	a.Out.Info("SNMP settings, credentials, allowed clients and contact of scope '" + scope + "' removed: the default applies again.")
	return nil
}

// scopeSNMPDrop removes everything the scope has: its keys in tacctl.yaml
// and its credentials file.
func (inv *invocation) scopeSNMPDrop(scope string) error {
	if err := snmpcred.RemoveScope(inv.app.Paths.SNMPDir, scope); err != nil {
		return err
	}
	_, err := policy.MoveSNMPScope(inv.app.Conf(), scope, "")
	return err
}

// scopeSNMPMove follows a scope's rename (newName set) or removal (newName
// empty): its keys in tacctl.yaml and its credentials file. It reports what
// could not be carried over.
func (inv *invocation) scopeSNMPMove(old, newName string) error {
	a := inv.app
	if newName == "" {
		return inv.scopeSNMPDrop(old)
	}
	lost, err := policy.MoveSNMPScope(a.Conf(), old, newName)
	if err != nil {
		return err
	}
	for _, l := range lost {
		ui.Output{Stdout: a.Out.Stderr}.Warn(l + " holds a value tacctl.yaml does not take; it was not carried over to '" + newName + "'.")
	}
	return snmpcred.RenameScope(a.Paths.SNMPDir, old, newName)
}

// scopeSNMPTest reads the sysName of one device with the scope's settings.
func (inv *invocation) scopeSNMPTest(scope string, p Parsed) error {
	return inv.snmpTestWith(scope, p.Args[0], "tacctl scope snmp "+scope+" test <address|device>")
}

// snmpTestWith is 'test' for the default (scope "") and for a scope.
func (inv *invocation) snmpTestWith(scope, key, usage string) error {
	addr, aerr := devreg.NormalizeAddress(key)
	if aerr != nil {
		// A registered device's name.
		_, res, err := inv.deviceLoad()
		if err != nil {
			return err
		}
		e, ok := res.Lookup(key, devreg.ScopeFilter{})
		if !ok || e.Address == "" {
			return inv.usageErr("'"+key+"' is neither an address nor a registered device.", "Usage: "+usage)
		}
		addr = e.Address
	}
	g, problem := inv.snmpGetterFor(scope)
	if g == nil {
		return inv.usageErr("Cannot test: " + problem + ".")
	}
	name, err := g.SysName(inv.ctx, addr)
	var te *snmp.TimeoutError
	var re *snmp.ReportError
	switch {
	case errors.As(err, &te):
		alike := "a wrong community"
		if e, eerr := inv.snmpEffective(scope); eerr == nil && e.Version == snmp.V3 {
			alike = "a wrong privacy passphrase"
		}
		return inv.usageErr("No answer from " + addr + ": " + te.Error() + ". No agent there, a filter on the way, or " +
			alike + " (an agent drops such a request without a word).")
	case errors.As(err, &re):
		return inv.usageErr(addr + " refused the request: " + re.Error() + ".")
	case err != nil:
		return inv.usageErr("No sysName from " + addr + ": " + err.Error() + ".")
	}
	if strings.TrimSpace(name) == "" {
		inv.app.Out.Info(addr + " answered with an empty sysName.")
		return nil
	}
	inv.app.Out.Info(addr + " calls itself '" + name + "' (SNMP sysName).")
	return nil
}
