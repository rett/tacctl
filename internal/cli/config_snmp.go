package cli

// 'config snmp' (docs/plans/0.2.2-plan.md 5.10, WP9.17): the SNMP access
// 'device add' and 'device check' read a device's sysName with. The version,
// port, timeout and v3 protocols are tacctl.yaml's snmp.*; the community and
// the v3 user and passphrases are StateDir/snmp.yaml (internal/snmpcred,
// 0600), which nothing prints. The verbs are the superuser's (no tier row
// names them: the credentials reach every device).

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/snmpcred"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerConfigVerb("snmp", configSNMPFamilySpec, configSNMPCmd)
}

// configSNMPFamilySpec is the spec of 'config snmp' as registerConfigVerb
// takes it.
var configSNMPFamilySpec = Spec{MaxArgs: -1, Args: []string{"show|version|community|v3-user|port|timeout|clear|test", After("v3-user", snmpV3UserActions), ""}}

// configSNMPSpecs are the arguments of each verb.
var configSNMPSpecs = map[string]Spec{
	"show":      {MaxArgs: 1, Flags: []Flag{{Names: []string{"--reveal"}}}},
	"version":   {MaxArgs: 1, Args: []string{"v2c|v3"}},
	"community": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--stdin"}}}},
	"v3-user":   snmpV3UserSpec(true),
	"port":      {MaxArgs: 1, Args: []string{""}},
	"timeout":   {MaxArgs: 1, Args: []string{""}},
	"clear":     {MaxArgs: 0},
	"test":      {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices}},
}

// configSNMPVerbs are the verbs ({Use, Short}), in usage order.
var configSNMPVerbs = [][2]string{
	{"show [--reveal [<user>]]", "The SNMP settings, and whether the credentials are set; --reveal prints them (administrators)"},
	{"version [v2c|v3]", "Show or set the SNMP version"},
	{"community [--stdin]", "Set the v2c community (asked twice, not echoed); the version becomes v2c"},
	{"v3-user add|remove|default|list [<user>]",
		"The v3 user pool: add (passphrases asked), remove, default, list"},
	{"port [<n>]", "Show or set the agents' UDP port (default 161)"},
	{"timeout [<seconds>]", "Show or set the wait for an answer, 1-10 (default 2; one retry)"},
	{"clear", "Remove the credentials and the version: no lookups"},
	{"test <address|device>", "Read the sysName of one device and print it, or why there is none"},
}

// configSNMPOptions are the option lines under a verb's row.
var configSNMPOptions = map[string][][2]string{
	"show": {
		{"--reveal [<user>]", "Print the community and the default user's passphrases, or one user's"},
	},
	"v3-user": {
		{"add <user> [--default]", "Add a user to the pool (or replace its passphrases); --default makes it the default"},
		{"--auth sha|sha256", "HMAC-SHA-96 or HMAC-SHA-256-192 (default sha)"},
		{"--priv aes128", "AES-128 (the only one)"},
		{"--stdin", "(community, v3-user add) Read the secrets from stdin, one per line"},
		{"remove <user>", "Take a user out of the pool"},
		{"default [<user>|--none]", "Show, choose or clear the default user"},
		{"list", "The users of the pool, never a passphrase"},
	},
}

func configSNMPCmd(inv *invocation) *cobra.Command {
	c := verb("snmp <subcommand>", "SNMP for the name hint of 'device add' (sysName)")
	c.RunE = inv.native(withPreflight, inv.configSNMP)
	for _, v := range configSNMPVerbs {
		word := strings.Fields(v[0])[0]
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.configSNMP(append([]string{word}, args...))
		})))
	}
	return c
}

// configSNMPUsage is the usage of 'config snmp'.
func configSNMPUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "SNMP name hint" + ui.NC + "\n\nUsage: tacctl config snmp <subcommand>\n\n")
	for _, v := range configSNMPVerbs {
		use, short := v[0], v[1]
		if len(use) > 40 {
			b.WriteString("  " + use + "\n  " + strings.Repeat(" ", 40) + "  " + short + "\n")
		} else {
			fmt.Fprintf(&b, "  %-40s  %s\n", use, short)
		}
		for _, o := range configSNMPOptions[strings.Fields(use)[0]] {
			fmt.Fprintf(&b, "      %-36s  %s\n", o[0], o[1])
		}
	}
	b.WriteString(`
'tacctl device add' reads the device's sysName.0 with these settings and
compares it with the name given (a hint only: the add never waits on it
beyond the timeout, and never fails for it), and stores the sysLocation.0 it
reports as the device's location; 'device check' shows both.
v2c sends the community; v3 is authPriv only (SHA or SHA-256, AES-128). The
version, the port, the timeout and the two protocols are one setting; the v3
users are a pool of names with their passphrases and a default user. Adding a
user changes nothing but the pool: 'version v3' makes the lookups use v3, and
the default user is the one they read with. A name stands for one user across
the config's pool, the scopes' and the devices'.
The settings are in tacctl.yaml (snmp.*), the community and the v3 users
and passphrases in /etc/tacctl/snmp.yaml (0600), which tacctl prints only for
'show --reveal'.

These are the default for every scope. A scope sets its own with 'tacctl scope
snmp <scope> ...' (version, community, v3-user, clients, contact, port,
timeout); what it does not set comes from here.

Examples:
  tacctl config snmp community
  printf '%s\n' "$COMMUNITY" | tacctl config snmp community --stdin
  tacctl config snmp v3-user add alice --auth sha256 --default
  tacctl config snmp version v3
  tacctl config snmp test 192.0.2.10

`)
	return b.String()
}

// configSNMP dispatches: no sub-command, help, -h and --help are the usage
// (exit 0); an unknown one is an error, then the usage (exit 1).
func (inv *invocation) configSNMP(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	run := map[string]func([]string) error{
		"show": inv.snmpShow, "version": inv.snmpVersion, "community": inv.snmpCommunity, "v3-user": inv.snmpV3User,
		"port": inv.snmpPort, "timeout": inv.snmpTimeout, "clear": inv.snmpClear, "test": inv.snmpTest,
	}
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(configSNMPUsage())
		return nil
	default:
		if f, ok := run[sub]; ok {
			if _, err := Parse(configSNMPSpecs[sub], rest); err != nil {
				return inv.snmpUsageErr(sub, err)
			}
			return f(rest)
		}
		return inv.unknownSub(sub)
	}
}

// snmpUsageErr is a bad argument of a verb: the error and its usage line.
func (inv *invocation) snmpUsageErr(verbName string, err error) error {
	var use string
	for _, v := range configSNMPVerbs {
		if strings.Fields(v[0])[0] == verbName {
			use = v[0]
		}
	}
	msg := err.Error()
	var uf *UnknownFlagError
	if errors.As(err, &uf) {
		msg = "Unknown option: '" + uf.Flag + "'"
	}
	if verbName == "v3-user" {
		return inv.usageErr(append([]string{msg}, snmpV3UserUsage(snmpSetter(""), true)...)...)
	}
	return inv.usageErr(msg, "Usage: tacctl config snmp "+use)
}

func (inv *invocation) snmpParse(verbName string, args []string) Parsed {
	p, _ := Parse(configSNMPSpecs[verbName], args)
	return p
}

// snmpCreds reads snmp.yaml.
func (inv *invocation) snmpCreds() (snmpcred.Creds, error) {
	return snmpcred.Load(inv.app.Paths.SNMPFile)
}

// setOrNot is 'set' or 'not set'.
func setOrNot(b bool) string {
	if b {
		return "set"
	}
	return "not set"
}

func (inv *invocation) snmpShow(args []string) error {
	a := inv.app
	p := inv.snmpParse("show", args)
	reveal := p.Has("--reveal")
	revealUser := ""
	if len(p.Args) > 0 {
		if !reveal {
			return inv.usageErr("A user is for --reveal: tacctl config snmp show --reveal <user>")
		}
		revealUser = p.Args[0]
	}
	// The default reaches every device: a restricted caller never reveals it.
	// The gate does not open 'config snmp' to a restricted caller at all (its
	// tier rows are the superuser's), so this refusal is the same rule where
	// the gate does not run, not a reachable one: a restricted caller's
	// reads of SNMP are 'scope snmp' of its own scopes.
	if reveal && inv.callerScopes().restricted {
		return inv.deniedUsage(reasonSuperuser, "The default SNMP credentials are the superuser's to read. Nothing was printed.")
	}
	c, err := inv.snmpCreds()
	if err != nil {
		return err
	}
	// A reveal of one user prints only that user; without a name it prints
	// the community and the default user's passphrases. It is logged first,
	// with the user's name (never a passphrase).
	shown, _ := c.Find(c.Default)
	if revealUser != "" {
		u, ok := c.Find(revealUser)
		if !ok {
			return inv.usageErr(noPoolUser(revealUser, "the config", c)...)
		}
		shown = u
	}
	if reveal {
		inv.secretReadUser("snmp-default", "default", shown.Name)
	}
	src := func(path, def string) string {
		v := inv.confGet(path, "")
		if v == "" || !a.Conf().HasOverride(path) {
			return def + " (default)"
		}
		return v
	}
	version := inv.confGet("snmp.version", "")
	inv.echo("")
	inv.echoE(ui.Bold + "SNMP name hint" + ui.NC)
	switch version {
	case "":
		inv.echo("  version:    not set (no lookup; 'version', 'community' or 'v3-user' sets it)")
	case snmp.V2c:
		inv.echo("  version:    v2c (the community)")
	case snmp.V3:
		inv.echo("  version:    v3 (the default user, authPriv)")
	default:
		inv.echo("  version:    " + version)
	}
	inv.echo("  port:       " + src("snmp.port", strconv.Itoa(snmp.DefaultPort)))
	inv.echo("  timeout:    " + src("snmp.timeout", strconv.Itoa(snmp.DefaultTimeout)) + " s, one retry")
	if n, err := strconv.Atoi(inv.confGet("snmp.timeout", strconv.Itoa(snmp.DefaultTimeout))); err == nil {
		if note := snmpScaleNote(n, inv.timeoutScaleOf("", 0).N); note != "" {
			inv.echo(note)
		}
	}
	if revealUser == "" {
		inv.echo("  community:  " + secretOrSet(reveal, c.Community))
	}
	// The v3 lines only when v3 is chosen or set up: v2c is the usual way.
	if version == snmp.V3 || len(c.Users) > 0 {
		inv.echo("  v3 users:   " + poolText(c, false))
		switch {
		case reveal:
			inv.echo("  v3 user:    " + dash(shown.Name) + "; auth passphrase: " + dash(shown.AuthPass) + "; priv passphrase: " + dash(shown.PrivPass))
		case revealUser == "":
			inv.echo("  v3 user:    " + dash(shown.Name) + "; passphrases: " + setOrNot(shown.Complete()))
		}
		inv.echo("  v3 auth:    " + src("snmp.v3.auth", snmp.AuthSHA) + "; priv: " + src("snmp.v3.priv", snmp.PrivAES128))
	}
	if _, problem := inv.snmpConfig(); problem != "" && version != "" {
		inv.echo("  Not usable: " + problem + ".")
	}
	if reveal {
		inv.echo("  Credentials: " + a.Paths.SNMPFile + " (0600)")
	} else {
		inv.echo("  Credentials: " + a.Paths.SNMPFile + " (0600; 'show --reveal' prints them)")
	}
	inv.echo("")
	return nil
}

// poolText is the users of a pool on one line, the default marked; names are
// replaced by their count for a caller who may not see them.
func poolText(c snmpcred.Creds, hide bool) string {
	if len(c.Users) == 0 {
		if c.Default != "" && !hide {
			return "none of its own; the default is " + c.Default
		}
		return "none"
	}
	if hide {
		return strconv.Itoa(len(c.Users)) + " " + plural(len(c.Users), "user", "users")
	}
	out := make([]string, len(c.Users))
	for i, u := range c.Users {
		out[i] = u.Name
		if u.Name == c.Default {
			out[i] += " (default)"
		}
	}
	return strings.Join(out, ", ")
}

// noPoolUser is the refusal of a user the level does not have.
func noPoolUser(user, where string, c snmpcred.Creds) []string {
	have := "it has none"
	if len(c.Users) > 0 {
		have = "it has: " + strings.Join(c.Names(), ", ")
	}
	return []string{"No SNMPv3 user '" + user + "' in the pool of " + where + " (" + have + ")."}
}

// secretReadUser logs a secret read as secretRead does, naming the v3 user
// whose passphrases are printed (never a passphrase).
func (inv *invocation) secretReadUser(kind, name, user string) {
	if user == "" {
		inv.secretRead(kind, name)
		return
	}
	inv.app.Audit().Reveal(audit.Info, "secret-read", kvp("kind", kind), kvp("name", name), kvp("user", user), audit.Pair("by", inv.sudoUser()))
}

// secretOrSet is a credential as 'show' prints it: the value when revealed,
// else only whether it is set.
func secretOrSet(reveal bool, v string) string {
	switch {
	case v == "":
		return "not set"
	case reveal:
		return v
	}
	return "set"
}

// readSecret is one secret: from stdin (--stdin, one line), else typed
// twice at a terminal without echo. what names it in the prompts.
func (inv *invocation) readSecret(stdin bool, what string) (string, error) {
	pr := inv.app.Prompter()
	if stdin {
		s := pr.Ask("")
		if s == "" {
			return "", inv.usageErr("No " + what + " on stdin (one per line).")
		}
		return s, nil
	}
	if !pr.Interactive() {
		return "", inv.usageErr("No terminal to ask for the "+what+" on; pipe it in with --stdin.", "Nothing was changed.")
	}
	s, err := pr.Password("  " + upperFirst(what) + ": ")
	if err != nil {
		return "", err
	}
	if s == "" {
		return "", inv.usageErr("An empty " + what + "; nothing was changed.")
	}
	again, err := pr.Password("  Again: ")
	if err != nil {
		return "", err
	}
	if again != s {
		return "", inv.usageErr("The two did not match; nothing was changed.")
	}
	return s, nil
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// secretProblem is why s cannot be a secret (” when it can): too short or
// too long, or something a device CLI would misread (a blank, '?', '"', a
// control character: names.SNMPTokenProblem). The value ends up in a line
// the operator pastes into a device.
func secretProblem(s, what string, min, max int) string {
	if len(s) < min {
		return upperFirst(what) + " too short: at least " + strconv.Itoa(min) + " characters."
	}
	if strings.ContainsAny(s, "\n\r\x00") {
		return upperFirst(what) + " cannot hold a line break or a NUL."
	}
	if p := names.SNMPTokenProblem(s, max); p != "" {
		return upperFirst(what) + " " + p + "."
	}
	return ""
}

func (inv *invocation) snmpCommunity(args []string) error {
	p := inv.snmpParse("community", args)
	s, err := inv.readSecret(p.Has("--stdin"), "community")
	if err != nil {
		return err
	}
	if msg := secretProblem(s, "the community", 1, names.SNMPCommunityMax); msg != "" {
		return inv.usageErr(msg)
	}
	c, err := inv.snmpCreds()
	if err != nil {
		return err
	}
	c.Community = s
	inv.app.Audit().Touch()
	if err := snmpcred.Save(inv.app.Paths.SNMPFile, c); err != nil {
		return err
	}
	if err := inv.app.Conf().Set("snmp.version", snmp.V2c); err != nil {
		return err
	}
	inv.detail("snmp set", kvp("kind", "community"))
	inv.app.Out.InfoE("SNMP community set (" + inv.app.Paths.SNMPFile + "); version v2c. Try it: tacctl config snmp test <address>")
	return nil
}

// reSNMPUser is an SNMPv3 user name (SnmpAdminString, 1-32), printable
// without blanks.
var reSNMPUser = regexp.MustCompile(`^[!-~]{1,32}$`)

// snmpV3User is 'v3-user add|remove|default|list' of the config.
func (inv *invocation) snmpV3User(args []string) error {
	w := inv.app.Audit()
	before := w.Touched()
	err := inv.configPool().run(inv.snmpParse("v3-user", args))
	if err == nil && !before && w.Touched() {
		inv.detail("snmp set", kvp("kind", "v3-user"))
	}
	return err
}

// snmpVersion shows or sets the SNMP version of the name lookups.
func (inv *invocation) snmpVersion(args []string) error {
	p := inv.snmpParse("version", args)
	if len(p.Args) == 0 {
		if v := inv.confGet("snmp.version", ""); v != "" {
			inv.echo(v)
		} else {
			inv.echo("not set")
		}
		return nil
	}
	v := p.Args[0]
	if v != snmp.V2c && v != snmp.V3 {
		return inv.usageErr("Unknown version '"+v+"': v2c or v3.", "Usage: tacctl config snmp version [v2c|v3]")
	}
	if err := inv.app.Conf().Set("snmp.version", v); err != nil {
		return err
	}
	inv.detail("snmp set", kvp("kind", "version"))
	inv.app.Out.InfoE("SNMP version set to " + v + ".")
	if _, problem := inv.snmpConfig(); problem != "" {
		inv.app.Out.Warn("Not usable yet: " + problem + ".")
	}
	return nil
}

func (inv *invocation) snmpPort(args []string) error {
	return inv.configTunable("snmp set", []audit.KV{kvp("kind", "port")}, args, "snmp.port", inv.confGet("snmp.port", strconv.Itoa(snmp.DefaultPort)), []string{
		"  SNMP port: " + inv.confGet("snmp.port", strconv.Itoa(snmp.DefaultPort)),
		"",
		"  Usage: tacctl config snmp port <1-65535>",
	}, "SNMP port set to %v.")
}

func (inv *invocation) snmpTimeout(args []string) error {
	return inv.configTunable("snmp set", []audit.KV{kvp("kind", "timeout")}, args, "snmp.timeout", inv.confGet("snmp.timeout", strconv.Itoa(snmp.DefaultTimeout)), []string{
		"  SNMP timeout: " + inv.confGet("snmp.timeout", strconv.Itoa(snmp.DefaultTimeout)) + " s (one retry)",
		"",
		"  Usage: tacctl config snmp timeout <1-10>",
	}, "SNMP timeout set to %v s.")
}

func (inv *invocation) snmpClear([]string) error {
	a := inv.app
	c, err := inv.snmpCreds()
	if err != nil {
		return err
	}
	had := !c.Empty() || a.Conf().HasOverride("snmp.version")
	inv.configPool().warnReferrers()
	a.Audit().Touch()
	if err := snmpcred.Save(a.Paths.SNMPFile, snmpcred.Creds{}); err != nil {
		return err
	}
	if a.Conf().HasOverride("snmp.version") {
		if err := a.Conf().Unset("snmp.version"); err != nil {
			return err
		}
	}
	if !had {
		a.Out.Info("No SNMP credentials were set; nothing was changed.")
		return nil
	}
	inv.detail("snmp set", kvp("kind", "clear"))
	a.Out.Info("SNMP credentials removed and snmp.version unset: 'device add' reads no sysName.")
	return nil
}

func (inv *invocation) snmpTest(args []string) error {
	p := inv.snmpParse("test", args)
	return inv.snmpTestWith("", p.Args[0], "tacctl config snmp test <address|device>")
}
