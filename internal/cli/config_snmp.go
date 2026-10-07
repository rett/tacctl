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

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/snmpcred"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerConfigVerb("snmp", configSNMPFamilySpec, configSNMPCmd)
}

// configSNMPFamilySpec is the spec of 'config snmp' as registerConfigVerb
// takes it.
var configSNMPFamilySpec = Spec{MaxArgs: -1, Args: []string{"show|community|v3-user|port|timeout|clear|test", ""}}

// configSNMPSpecs are the arguments of each verb.
var configSNMPSpecs = map[string]Spec{
	"show":      {MaxArgs: 0},
	"community": {MaxArgs: 0, Flags: []Flag{{Names: []string{"--stdin"}}}},
	"v3-user": {MinArgs: 1, MaxArgs: 1, Args: []string{""}, Flags: []Flag{
		{Names: []string{"--auth"}, Value: true, Kind: strings.Join(snmp.AuthProtocols, "|")},
		{Names: []string{"--priv"}, Value: true},
		{Names: []string{"--stdin"}}}},
	"port":    {MaxArgs: 1, Args: []string{""}},
	"timeout": {MaxArgs: 1, Args: []string{""}},
	"clear":   {MaxArgs: 0},
	"test":    {MinArgs: 1, MaxArgs: 1, Args: []string{KindDevices}},
}

// configSNMPVerbs are the verbs ({Use, Short}), in usage order.
var configSNMPVerbs = [][2]string{
	{"show", "The SNMP settings, and whether the credentials are set (never what they are)"},
	{"community [--stdin]", "Set the v2c community (asked twice, not echoed); the version becomes v2c"},
	{"v3-user <user> [--auth sha|sha256] [--priv aes128] [--stdin]",
		"Set the v3 user and its passphrases (authPriv); the version becomes v3"},
	{"port [<n>]", "Show or set the agents' UDP port (default 161)"},
	{"timeout [<seconds>]", "Show or set the wait for an answer, 1-10 (default 2; one retry)"},
	{"clear", "Remove the credentials and the version: no lookups"},
	{"test <address|device>", "Read the sysName of one device and print it, or why there is none"},
}

// configSNMPOptions are the option lines under a verb's row.
var configSNMPOptions = map[string][][2]string{
	"v3-user": {
		{"--auth sha|sha256", "HMAC-SHA-96 or HMAC-SHA-256-192 (default sha)"},
		{"--priv aes128", "AES-128 (the only one)"},
		{"--stdin", "(community, v3-user) Read the secrets from stdin, one per line"},
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
beyond the timeout, and never fails for it); 'device check' shows it.
v2c sends the community; v3 is authPriv only (SHA or SHA-256, AES-128).
The settings are in tacctl.yaml (snmp.*), the community and the v3 user
and passphrases in /etc/tacctl/snmp.yaml (0600), which tacctl never prints.

Examples:
  tacctl config snmp community
  printf '%s\n' "$COMMUNITY" | tacctl config snmp community --stdin
  tacctl config snmp v3-user alice --auth sha256
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
		"show": inv.snmpShow, "community": inv.snmpCommunity, "v3-user": inv.snmpV3User,
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
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(configSNMPUsage())
		return exit(1)
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

func (inv *invocation) snmpShow([]string) error {
	a := inv.app
	c, err := inv.snmpCreds()
	if err != nil {
		return err
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
		inv.echo("  version:    not set (no lookup; 'community' or 'v3-user' sets it)")
	case snmp.V2c:
		inv.echo("  version:    v2c (the community)")
	case snmp.V3:
		inv.echo("  version:    v3 (the user, authPriv)")
	default:
		inv.echo("  version:    " + version)
	}
	inv.echo("  port:       " + src("snmp.port", strconv.Itoa(snmp.DefaultPort)))
	inv.echo("  timeout:    " + src("snmp.timeout", strconv.Itoa(snmp.DefaultTimeout)) + " s, one retry")
	inv.echo("  community:  " + setOrNot(c.Community != ""))
	// The v3 lines only when v3 is chosen or set up: v2c is the usual way.
	if version == snmp.V3 || c.User != "" || c.AuthPass != "" || c.PrivPass != "" {
		inv.echo("  v3 user:    " + setOrNot(c.User != "") + "; passphrases: " + setOrNot(c.AuthPass != "" && c.PrivPass != ""))
		inv.echo("  v3 auth:    " + src("snmp.v3.auth", snmp.AuthSHA) + "; priv: " + src("snmp.v3.priv", snmp.PrivAES128))
	}
	if _, problem := inv.snmpConfig(); problem != "" && version != "" {
		inv.echo("  Not usable: " + problem + ".")
	}
	inv.echo("  Credentials: " + a.Paths.SNMPFile + " (0600; never printed)")
	inv.echo("")
	return nil
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

// secretProblem is why s cannot be a secret (” when it can).
func secretProblem(s, what string, min int) string {
	if len(s) < min {
		return upperFirst(what) + " too short: at least " + strconv.Itoa(min) + " characters."
	}
	if strings.ContainsAny(s, "\n\r\x00") {
		return upperFirst(what) + " cannot hold a line break or a NUL."
	}
	return ""
}

func (inv *invocation) snmpCommunity(args []string) error {
	p := inv.snmpParse("community", args)
	s, err := inv.readSecret(p.Has("--stdin"), "community")
	if err != nil {
		return err
	}
	if msg := secretProblem(s, "the community", 1); msg != "" {
		return inv.usageErr(msg)
	}
	c, err := inv.snmpCreds()
	if err != nil {
		return err
	}
	c.Community = s
	if err := snmpcred.Save(inv.app.Paths.SNMPFile, c); err != nil {
		return err
	}
	if err := inv.app.Conf().Set("snmp.version", snmp.V2c); err != nil {
		return err
	}
	inv.app.Out.InfoE("SNMP community set (" + inv.app.Paths.SNMPFile + "); version v2c. Try it: tacctl config snmp test <address>")
	return nil
}

// reSNMPUser is an SNMPv3 user name (SnmpAdminString, 1-32), printable
// without blanks.
var reSNMPUser = regexp.MustCompile(`^[!-~]{1,32}$`)

func (inv *invocation) snmpV3User(args []string) error {
	p := inv.snmpParse("v3-user", args)
	user := p.Args[0]
	if !reSNMPUser.MatchString(user) {
		return inv.usageErr("Invalid SNMPv3 user '" + user + "': 1-32 printable characters, no blanks.")
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
	if msg := secretProblem(ap, "the authentication passphrase", 8); msg != "" {
		return inv.usageErr(msg)
	}
	pp, err := inv.readSecret(stdin, "privacy passphrase")
	if err != nil {
		return err
	}
	if msg := secretProblem(pp, "the privacy passphrase", 8); msg != "" {
		return inv.usageErr(msg)
	}
	c, err := inv.snmpCreds()
	if err != nil {
		return err
	}
	c.User, c.AuthPass, c.PrivPass = user, ap, pp
	if err := snmpcred.Save(inv.app.Paths.SNMPFile, c); err != nil {
		return err
	}
	conf := inv.app.Conf()
	if err := conf.Set("snmp.version", snmp.V3); err != nil {
		return err
	}
	if auth != "" {
		if err := conf.Set("snmp.v3.auth", auth); err != nil {
			return err
		}
	}
	if priv != "" {
		if err := conf.Set("snmp.v3.priv", priv); err != nil {
			return err
		}
	}
	inv.app.Out.InfoE("SNMPv3 user and passphrases set (" + inv.app.Paths.SNMPFile + "); version v3, auth " +
		inv.confGet("snmp.v3.auth", snmp.AuthSHA) + ", priv " + inv.confGet("snmp.v3.priv", snmp.PrivAES128) +
		". Try it: tacctl config snmp test <address>")
	return nil
}

func (inv *invocation) snmpPort(args []string) error {
	return inv.configTunable(args, "snmp.port", []string{
		"  SNMP port: " + inv.confGet("snmp.port", strconv.Itoa(snmp.DefaultPort)),
		"",
		"  Usage: tacctl config snmp port <1-65535>",
	}, "SNMP port set to %v.")
}

func (inv *invocation) snmpTimeout(args []string) error {
	return inv.configTunable(args, "snmp.timeout", []string{
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
	a.Out.Info("SNMP credentials removed and snmp.version unset: 'device add' reads no sysName.")
	return nil
}

func (inv *invocation) snmpTest(args []string) error {
	p := inv.snmpParse("test", args)
	key := p.Args[0]
	addr, aerr := devreg.NormalizeAddress(key)
	if aerr != nil {
		// A registered device's name.
		_, res, err := inv.deviceLoad()
		if err != nil {
			return err
		}
		e, ok := res.Lookup(key, devreg.ScopeFilter{})
		if !ok || e.Address == "" {
			return inv.usageErr("'"+key+"' is neither an address nor a registered device.", "Usage: tacctl config snmp test <address|device>")
		}
		addr = e.Address
	}
	g, problem := inv.snmpGetter()
	if g == nil {
		return inv.usageErr("Cannot test: " + problem + ".")
	}
	name, err := g.SysName(inv.ctx, addr)
	var te *snmp.TimeoutError
	var re *snmp.ReportError
	switch {
	case errors.As(err, &te):
		alike := "a wrong community"
		if inv.confGet("snmp.version", "") == snmp.V3 {
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
