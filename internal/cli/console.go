package cli

// The 'console' family (docs/plans/operator-console-wp-console.md 5.1): which
// tacctl users get the login console (tacctl-console) as their shell on this
// server, and its settings, in /etc/tacctl/console.yaml (internal/console).
// The verbs change that file only, after a snapshot, and print the command
// that applies it to the accounts; they never change an account or sshd.
// '_console-policy' is the hidden verb the unprivileged console runs through
// sudo to learn its settings.

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

func init() {
	registerFamily(consoleCmd)
	registerFamily(consolePolicyCmd)
	registerSpecs("console", consoleSpecs)
}

var consoleSpecs = map[string]Spec{
	"show":             {MaxArgs: 0},
	"tiers":            {MaxArgs: 2, Args: []string{"readonly|operator|superuser", "enable|disable"}},
	"user":             {MinArgs: 1, MaxArgs: 2, Args: []string{KindUsers, "enable|disable|clear"}},
	"idle-timeout":     {MaxArgs: 1, Args: []string{""}},
	"agent-forwarding": {MaxArgs: 1, Args: []string{"enable|disable"}},
	"ssh-escape":       {MaxArgs: 1, Args: []string{"enable|disable"}},
	"system-shell":     {MinArgs: 1, MaxArgs: 2, Args: []string{"tiers|path", After("path", KindFile)}},
	"install":          {MaxArgs: 0},
	"remove":           {MaxArgs: 0},
	"check":            {MaxArgs: 0},
}

// consoleVerbs are the verbs ({Use, Short}), in usage order.
var consoleVerbs = [][2]string{
	{"show", "Tiers, per-user overrides, the effective shell per user, settings and the server's pieces"},
	{"tiers [<tier> enable|disable]", "Show or switch the console for a tier (readonly, operator, superuser)"},
	{"user <name> [enable|disable|clear]", "Show or set one user's override of the tier switch"},
	{"idle-timeout [<min>]", "Show or set the minutes idle at the prompt before the session ends (0-1440, 0: never)"},
	{"agent-forwarding [enable|disable]", "Opt in to ssh agent forwarding for console users"},
	{"ssh-escape [enable|disable]", "Opt in to ssh's escape character (~. and ~C) inside the console's ssh"},
	{"system-shell tiers [<csv>|none]", "Show or set the tiers that may start their system shell from the console"},
	{"system-shell path [<path>]", "Show or set the system shell (default /bin/bash; must be listed in /etc/shells)"},
	{"install", "Put the /etc/shells line and sshd's drop-in for console users in place (host sync of this server does too)"},
	{"remove", "Take them away again (refused while an account has the console as its shell)"},
	{"check", "Check that sshd applies the console's settings to its users (exit 1 when not)"},
}

func consoleCmd(inv *invocation) *cobra.Command {
	c := verb("console <subcommand>", "Login console: which tacctl users get it as their shell on this server, and its settings")
	c.RunE = inv.native(withPreflight, inv.console)
	added := map[string]bool{}
	for _, v := range consoleVerbs {
		word := strings.Fields(v[0])[0]
		if added[word] {
			continue // system-shell tiers|path is one command
		}
		added[word] = true
		c.AddCommand(withRun(verb(v[0], v[1]), inv.native(withPreflight, func(args []string) error {
			return inv.console(append([]string{word}, args...))
		})))
	}
	return c
}

func consoleUsage() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Login Console" + ui.NC + "\n\nUsage: tacctl console <subcommand> [arguments]\n\nSubcommands:\n")
	for _, v := range consoleVerbs {
		b.WriteString("  " + v[0] + "\n      " + v[1] + "\n")
	}
	b.WriteString(`
The console is the login shell of tacctl users on this server (tacctl-console):
tacctl commands and ssh to registered devices, nothing else. It is on for every
tier by default; 'tiers' switches a tier, 'user' overrides one user. Local
accounts that are not tacctl users are never touched.

The settings commands change /etc/tacctl/console.yaml only. The accounts' login
shells and sshd's drop-in follow it when this server's accounts are synced
('tacctl host sync <name of this server>'); idle-timeout, ssh-escape and
system-shell are read by each console session when it starts. sshd's drop-in
makes the console the only program a console user's login runs (no scp, sftp
or remote programs), closes every forwarding and turns key logins off.

'system-shell' starts the user's system shell from the console, as themselves,
logged. Superusers only by default; 'system-shell tiers' opens or closes it
per tier.

Examples:
  tacctl console show
  tacctl console tiers readonly disable
  tacctl console user jdoe enable
  tacctl console system-shell tiers superuser,operator
  tacctl console idle-timeout 15

`)
	return b.String()
}

// console dispatches: no sub-command, help, -h and --help are the usage
// (exit 0); anything else unknown is an error, then the usage (exit 1).
func (inv *invocation) console(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	run := map[string]func([]string) error{
		"show": inv.consoleShow, "tiers": inv.consoleTiers, "user": inv.consoleUser,
		"idle-timeout": inv.consoleIdle, "system-shell": inv.consoleSystemShell,
		"agent-forwarding": inv.consoleSwitch("agent-forwarding"), "ssh-escape": inv.consoleSwitch("ssh-escape"),
		"install": inv.consoleInstall, "remove": inv.consoleRemove, "check": inv.consoleCheck,
	}
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(consoleUsage())
		return nil
	default:
		if f, ok := run[sub]; ok {
			return f(rest)
		}
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(consoleUsage())
		return exit(1)
	}
}

// consoleParse parses a verb's arguments with its Spec; a bad one is the
// error line and the verb's usage, exit 1.
func (inv *invocation) consoleParse(verbName string, args []string) (Parsed, error) {
	p, err := Parse(consoleSpecs[verbName], args)
	if err == nil {
		return p, nil
	}
	return p, inv.usageErr(err.Error(), "Usage: tacctl console "+consoleUse(verbName))
}

func consoleUse(verbName string) string {
	var out []string
	for _, v := range consoleVerbs {
		if strings.Fields(v[0])[0] == verbName {
			out = append(out, v[0])
		}
	}
	return strings.Join(out, "  |  tacctl console ")
}

// consolePolicy is the policy of console.yaml as it is now.
func (inv *invocation) consolePolicy() (*console.Policy, error) {
	f, err := console.Load(inv.app.Paths.ConsoleFile)
	if err != nil {
		return nil, err
	}
	return console.NewPolicy(f, inv.app.Paths), nil
}

// consoleWrite changes console.yaml: fn runs first on a copy, so every
// refusal comes before the snapshot; then, under the lock and after a
// snapshot of the current state, on the file itself.
func (inv *invocation) consoleWrite(fn func(*console.File) error) error {
	p := inv.app.Paths.ConsoleFile
	f, err := console.Load(p)
	if err != nil {
		return err
	}
	trial := f.Clone()
	if err := fn(trial); err != nil {
		return err
	}
	if _, err := trial.Text(); err != nil {
		return err
	}
	_, err = console.Mutate(p, inv.snapshotFirst, fn)
	return err
}

// localHost is the entry of this server in the host registry (enrolled with
// --local), if it is enrolled.
func (inv *invocation) localHost() (hosts.Entry, bool, error) {
	reg, err := inv.registry()
	if err != nil {
		return hosts.Entry{}, false, err
	}
	for _, e := range reg.Entries() {
		if e.Target == hosts.Local {
			return e, true, nil
		}
	}
	return hosts.Entry{}, false, nil
}

// consoleApply says how a change reaches the accounts: the sync of this
// server. Not enrolled, no account has the console to change.
func (inv *invocation) consoleApply() error {
	e, ok, err := inv.localHost()
	if err != nil {
		return err
	}
	if ok {
		inv.echo("Apply to the accounts: tacctl host sync " + e.Name)
	} else {
		inv.echo("This server is not enrolled, so no account has the console yet: tacctl host enroll --local")
	}
	return nil
}

// --- tiers and users ------------------------------------------------------------

func (inv *invocation) consoleTiers(args []string) error {
	p, err := inv.consoleParse("tiers", args)
	if err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		for _, t := range console.Tiers {
			inv.echo(string(t) + ": " + onOff(pol.File.TierOn[t]))
		}
		return nil
	}
	t, ok := console.ParseTier(p.Args[0])
	if !ok {
		return inv.usageErr("Unknown tier '"+p.Args[0]+"': expected readonly, operator or superuser.", "Usage: tacctl console "+consoleUse("tiers"))
	}
	if len(p.Args) == 1 {
		inv.echo(onOff(pol.File.TierOn[t]))
		return nil
	}
	on, err := inv.enableWord(p.Args[1], "tiers")
	if err != nil {
		return err
	}
	if err := inv.consoleWrite(func(f *console.File) error { f.TierOn[t] = on; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("The console is " + p.Args[1] + "d for the " + string(t) + " tier.")
	return inv.consoleApply()
}

func onOff(b bool) string {
	if b {
		return console.On
	}
	return console.Off
}

// enableWord parses enable|disable.
func (inv *invocation) enableWord(w, verbName string) (bool, error) {
	switch w {
	case console.On:
		return true, nil
	case console.Off:
		return false, nil
	}
	return false, inv.usageErr("Usage: tacctl console " + consoleUse(verbName))
}

func (inv *invocation) consoleUser(args []string) error {
	p, err := inv.consoleParse("user", args)
	if err != nil {
		return err
	}
	name := p.Args[0]
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 1 {
		switch on, ok := pol.File.Users[name]; {
		case !ok:
			inv.echo("none")
		default:
			inv.echo(onOff(on))
		}
		return nil
	}
	if p.Args[1] == "clear" {
		if _, ok := pol.File.Users[name]; !ok {
			inv.app.Out.Info("'" + name + "' has no override.")
			return nil
		}
		if err := inv.consoleWrite(func(f *console.File) error { delete(f.Users, name); return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("The override of '" + name + "' is cleared: the tier decides.")
		return inv.consoleApply()
	}
	on, err := inv.enableWord(p.Args[1], "user")
	if err != nil {
		return err
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("users", name) {
		return inv.usageErr("User '" + name + "' does not exist.")
	}
	if err := inv.consoleWrite(func(f *console.File) error { f.Users[name] = on; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("The console is " + p.Args[1] + "d for '" + name + "' (a user override).")
	return inv.consoleApply()
}

// --- settings -------------------------------------------------------------------

func (inv *invocation) consoleIdle(args []string) error {
	p, err := inv.consoleParse("idle-timeout", args)
	if err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		inv.echo(strconv.Itoa(pol.File.Idle))
		return nil
	}
	n, err := strconv.Atoi(p.Args[0])
	if err != nil || n < 0 || n > console.MaxIdle || strconv.Itoa(n) != p.Args[0] {
		return inv.usageErr("Invalid number of minutes '" + p.Args[0] + "': expected 0-" + strconv.Itoa(console.MaxIdle) + " (0: never).")
	}
	if err := inv.consoleWrite(func(f *console.File) error { f.Idle = n; return nil }); err != nil {
		return err
	}
	if n == 0 {
		inv.app.Out.Info("Console sessions no longer end when idle. It applies from the next console login.")
	} else {
		inv.app.Out.Info("Console sessions end after " + p.Args[0] + " minute(s) idle at the prompt. It applies from the next console login.")
	}
	return nil
}

// consoleSwitch is the getter/setter of one enable|disable setting.
func (inv *invocation) consoleSwitch(verbName string) func([]string) error {
	return func(args []string) error {
		p, err := inv.consoleParse(verbName, args)
		if err != nil {
			return err
		}
		pol, err := inv.consolePolicy()
		if err != nil {
			return err
		}
		cur := &pol.File.SSHEscape
		if verbName == "agent-forwarding" {
			cur = &pol.File.AgentForwarding
		}
		if len(p.Args) == 0 {
			inv.echo(map[bool]string{true: "enabled", false: "disabled"}[*cur])
			return nil
		}
		on, err := inv.enableWord(p.Args[0], verbName)
		if err != nil {
			return err
		}
		if err := inv.consoleWrite(func(f *console.File) error {
			if verbName == "agent-forwarding" {
				f.AgentForwarding = on
			} else {
				f.SSHEscape = on
			}
			return nil
		}); err != nil {
			return err
		}
		if verbName == "agent-forwarding" {
			inv.app.Out.Info("Agent forwarding is " + p.Args[0] + "d for console users. The sshd drop-in follows it at the next sync.")
			return inv.consoleApply()
		}
		inv.app.Out.Info("The console's ssh escape character is " + p.Args[0] + "d. It applies from the next console login.")
		return nil
	}
}

func (inv *invocation) consoleSystemShell(args []string) error {
	p, err := inv.consoleParse("system-shell", args)
	if err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	switch p.Args[0] {
	case "tiers":
		if len(p.Args) == 1 {
			inv.echo(tierCSV(pol.File.SystemShellTiers))
			return nil
		}
		l, err := console.ParseTiers(p.Args[1])
		if err != nil {
			return err
		}
		if err := inv.consoleWrite(func(f *console.File) error { f.SystemShellTiers = l; return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("system-shell is open to: " + tierCSV(l) + ". It applies from the next console login.")
		return nil
	case "path":
		if len(p.Args) == 1 {
			inv.echo(pol.File.SystemShell)
			return nil
		}
		if err := console.CheckShell(p.Args[1], inv.app.Paths.ShellsFile); err != nil {
			return err
		}
		if err := inv.consoleWrite(func(f *console.File) error { f.SystemShell = p.Args[1]; return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("system-shell starts " + p.Args[1] + ". It applies from the next console login.")
		return nil
	}
	return inv.usageErr("Usage: tacctl console " + consoleUse("system-shell"))
}

func tierCSV(l []tier.Tier) string {
	if len(l) == 0 {
		return "none"
	}
	s := make([]string, len(l))
	for i, t := range l {
		s[i] = string(t)
	}
	return strings.Join(s, ",")
}

// --- _console-policy ------------------------------------------------------------

// consolePolicyCmd is the hidden '_console-policy' (the Readonly row of the
// tier table): the console's settings for the caller, one line of key=value
// words, so the unprivileged console need not read root's file.
func consolePolicyCmd(inv *invocation) *cobra.Command {
	c := hidden("_console-policy")
	c.RunE = inv.native(withPreflight, inv.consolePolicyLine)
	return c
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func (inv *invocation) consolePolicyLine([]string) error {
	a := inv.app
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	user := a.Env.Get("SUDO_USER")
	t := inv.tierGate().Caller(inv.ctx)
	shell := "system"
	if pol.Decide(user, t).Console {
		shell = "console"
	}
	sys := pol.SystemShell(t)
	path, perr := pol.SystemShellPath()
	if perr != nil {
		if sys {
			a.Logger(inv.ctx, "auth.warning", "console policy system_shell "+path+" unusable: "+strings.Join(msgs(perr), " "))
		}
		sys = false
	}
	who := user
	if who == "" {
		who = "root"
	}
	a.Logger(inv.ctx, "auth.info", "console policy user="+who+" tier="+string(t)+" system_shell="+yesNo(sys)+" session="+a.Env.Get("TACCTL_CONSOLE"))
	inv.echo("shell=" + shell + " idle=" + strconv.Itoa(pol.File.Idle) + " system_shell=" + yesNo(sys) +
		" system_shell_path=" + path + " ssh_escape=" + yesNo(pol.SSHEscape()) + " agent=" + yesNo(pol.AgentForwarding()) +
		" tier=" + string(t) + " list_max=" + strconv.Itoa(pol.ListMax()))
	return nil
}
