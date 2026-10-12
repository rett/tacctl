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
	"time"

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
	"tiers":            {MaxArgs: 2, Args: []string{"readonly|operator|engineer|superuser", "enable|disable"}},
	"user":             {MinArgs: 1, MaxArgs: 2, Args: []string{KindUsers, "enable|disable|clear"}},
	"idle-timeout":     {MaxArgs: 1, Args: []string{""}},
	"agent-forwarding": {MaxArgs: 1, Args: []string{"enable|disable"}},
	"ssh-escape":       {MaxArgs: 1, Args: []string{"enable|disable"}},
	"space-completion": {MaxArgs: 1, Args: []string{"on|off"}},
	"system-shell":     {MinArgs: 1, MaxArgs: 2, Args: []string{"tiers|path", After("path", KindFile)}},
	"forwarding":       {MinArgs: 1, MaxArgs: 2, Args: []string{"tiers|gateway-ports", After("gateway-ports", "enable|disable")}},
	"password-cache":   {MaxArgs: 2, Args: []string{"tiers|idle|max", ""}},
	"forget":           {MaxArgs: 0},
	"install":          {MaxArgs: 0},
	"remove":           {MaxArgs: 0},
	"check":            {MaxArgs: 0},
}

// consoleVerbs are the verbs ({Use, Short}), in usage order.
var consoleVerbs = [][2]string{
	{"show", "Tiers, per-user overrides, the effective shell per user, settings and the server's pieces"},
	{"tiers [<tier> enable|disable]", "Show or switch the console for a tier (readonly, operator, engineer, superuser; the engineer tier is always on)"},
	{"user <name> [enable|disable|clear]", "Show or set one user's override of the tier switch (never disabled for an engineer)"},
	{"idle-timeout [<min>]", "Show or set the minutes idle at the prompt before the session ends (0-1440, 0: never)"},
	{"agent-forwarding [enable|disable]", "Opt in to ssh agent forwarding for console users"},
	{"ssh-escape [enable|disable]", "Opt in to ssh's escape character (~. and ~C) inside the console's ssh"},
	{"space-completion [on|off]", "Show or set Junos-style spaces at the console's prompt: a typed space completes a fixed word and is never doubled; off turns off the refusal of repeated spaces and the completion (default on); pastes are unchanged, which assumes the terminal sends them bracketed (one that does not sends its spaces as typed ones: turn this off there); a word of dashes only (- or --) keeps its space"},
	{"forwarding tiers [<csv>|none]", "Show or set the tiers that may forward X11 and TCP ports (sshd, and the console's ssh -X/-L/-R/-D; default superuser; never engineer)"},
	{"forwarding gateway-ports [enable|disable]", "Opt in to forwarded ports on other addresses than loopback for those tiers (sshd's GatewayPorts for ssh -R, and the console's ssh -g and -L/-D bind addresses)"},
	{"system-shell tiers [<csv>|none]", "Show or set the tiers that may start their system shell from the console (never engineer)"},
	{"system-shell path [<path>]", "Show or set the system shell (default /bin/bash; must be listed in /etc/shells)"},
	{"password-cache tiers [<csv>|none]", "Show or set the tiers whose shell and console sessions may keep your network password in memory for the session (operator, engineer, superuser; default none)"},
	{"password-cache idle [<min>]", "Show or set the minutes a cached password lives without a use (1-120, default 15)"},
	{"password-cache max [<hours>]", "Show or set the hours a cached password lives from the moment it was cached (1-24, default 8)"},
	{"forget", "Forget the cached password of this shell or console session now"},
	{"install", "Put the /etc/shells line and sshd's drop-ins (console users, engineers) in place (host sync of this server does too)"},
	{"remove", "Take the console's pieces away again (refused while an account has the console as its shell; the engineers' drop-in stays)"},
	{"check", "Check that sshd applies the console's and the engineers' settings to their users (exit 1 when not)"},
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
tier by default; 'tiers' switches a tier, 'user' overrides one user. The
engineer tier has the console or no login on this server, so neither can
switch it off. Local accounts that are not tacctl users are never touched.

The settings commands change /etc/tacctl/console.yaml only. The accounts' login
shells and sshd's drop-in follow it when this server's accounts are synced
('tacctl host sync <name of this server>'); idle-timeout, ssh-escape,
space-completion and system-shell are read by each console session when it
starts. sshd's drop-in makes the console the only program a console user's login
runs (no scp, sftp or remote programs), closes every forwarding but X11 and TCP
ports for the tiers of 'forwarding tiers' (superusers by default: 'ssh -X', -L,
-R, -D and -J through this server, and 'ssh -X|-L|-R|-D <device>' in the
console), and turns key logins off.

'system-shell' starts the user's system shell from the console, as themselves,
logged. Superusers only by default; 'system-shell tiers' opens or closes it
per tier. Neither it nor forwarding is ever open to the engineer tier: a shell
or a forwarded port on this server would reach its secrets.

'password-cache' lets a tier's shell and console sessions keep the user's network
password in memory for the session, so a device pull or an ssh to a device asks
once (off for every tier by default; plain 'tacctl shell' takes --password-cache).
The password lives only in the session's own process: it is never written to a
file, and it is forgotten on exit, after the idle time, after the maximum
lifetime, when the password is changed, when a device refuses it, and with
'console forget'. It does not protect against root, who can read any process.

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
		"idle-timeout": inv.consoleIdle, "system-shell": inv.consoleSystemShell, "forwarding": inv.consoleForwarding,
		"agent-forwarding": inv.consoleSwitch("agent-forwarding"), "ssh-escape": inv.consoleSwitch("ssh-escape"),
		"space-completion": inv.consoleSpace,
		"password-cache":   inv.consolePasswordCache, "forget": inv.consoleForget,
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
			inv.echo(string(t) + ": " + consoleTierState(pol.File, t))
		}
		return nil
	}
	t, ok := console.ParseTier(p.Args[0])
	if !ok {
		return inv.usageErr("Unknown tier '"+p.Args[0]+"': expected readonly, operator, engineer or superuser.", "Usage: tacctl console "+consoleUse("tiers"))
	}
	if len(p.Args) == 1 {
		inv.echo(onOff(pol.File.TierOn[t] || t == tier.Engineer))
		return nil
	}
	on, err := inv.enableWord(p.Args[1], "tiers")
	if err != nil {
		return err
	}
	if t == tier.Engineer && !on {
		return inv.usageErr(engineerConsoleText)
	}
	if err := inv.consoleWrite(func(f *console.File) error { f.TierOn[t] = on; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("The console is " + p.Args[1] + "d for the " + string(t) + " tier.")
	return inv.consoleApply()
}

// engineerConsoleText is the refusal to switch the console off for the
// engineer tier or for one of its users: an engineer has the console or no
// login on this server.
const engineerConsoleText = "The engineer tier has the console or no login on this server; it cannot be disabled. " +
	"To keep a user off this server, remove its scope from the user."

// consoleTierState is a tier's switch as the listings word it: the engineer
// tier is always on, and a stored 'disable' (console.yaml edited by hand, or
// from before) is said to be ignored.
func consoleTierState(f *console.File, t tier.Tier) string {
	if t != tier.Engineer {
		return onOff(f.TierOn[t])
	}
	if !f.TierOn[t] {
		return console.On + " (always; the stored " + console.Off + " is ignored)"
	}
	return console.On + " (always)"
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
	if !on && inv.userTier(name, m.UserPrivLvl(name)) == tier.Engineer {
		return inv.usageErr(engineerConsoleText)
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

// consoleSpace is 'console space-completion [on|off]': whether a typed
// space at the console's prompt completes a fixed word (internal/shell). It
// is read by each console session when it starts.
func (inv *invocation) consoleSpace(args []string) error {
	p, err := inv.consoleParse("space-completion", args)
	if err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		inv.echo(spaceWord(pol.File.SpaceCompletion))
		return nil
	}
	var on bool
	switch p.Args[0] {
	case "on":
		on = true
	case "off":
	default:
		return inv.usageErr("Usage: tacctl console " + consoleUse("space-completion"))
	}
	if err := inv.consoleWrite(func(f *console.File) error { f.SpaceCompletion = on; return nil }); err != nil {
		return err
	}
	if on {
		inv.app.Out.Info("A typed space at the console's prompt completes a fixed word. It applies from the next console login.")
	} else {
		inv.app.Out.Info("A typed space at the console's prompt is an ordinary space. It applies from the next console login.")
	}
	return nil
}

// spaceWord is the on|off word of the space-completion setting.
func spaceWord(on bool) string {
	if on {
		return "on"
	}
	return "off"
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
		l, err := console.ParseTiers(p.Args[1], "system-shell")
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

// consoleForwarding is 'console forwarding tiers [<csv>|none]': the tiers
// whose console logins may forward X11 and TCP ports, and 'console
// forwarding gateway-ports [enable|disable]': whether their forwarded ports
// may listen on other addresses than loopback. A change is applied to
// sshd's drop-in like agent-forwarding.
func (inv *invocation) consoleForwarding(args []string) error {
	p, err := inv.consoleParse("forwarding", args)
	if err != nil {
		return err
	}
	if p.Args[0] != "tiers" && p.Args[0] != "gateway-ports" {
		return inv.usageErr("Usage: tacctl console " + consoleUse("forwarding"))
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if p.Args[0] == "gateway-ports" {
		if len(p.Args) == 1 {
			inv.echo(map[bool]string{true: "enabled", false: "disabled"}[pol.File.GatewayPorts])
			return nil
		}
		on, err := inv.enableWord(p.Args[1], "forwarding")
		if err != nil {
			return err
		}
		if err := inv.consoleWrite(func(f *console.File) error { f.GatewayPorts = on; return nil }); err != nil {
			return err
		}
		if on {
			inv.app.Out.Info("Forwarded ports of the forwarding tiers (" + tierCSV(pol.File.ForwardingTiers) + ") may listen on other addresses than loopback: " +
				"ssh -R to this server binds the address the client names (ssh -R 0.0.0.0:8080:host:80 binds every address), and the console's ssh takes -g and a bind address on -L and -D. " +
				"Anyone who reaches this server can then connect to those ports. The sshd drop-in follows it at the next sync.")
		} else {
			inv.app.Out.Info("Forwarded ports listen on loopback only. The sshd drop-in follows it at the next sync.")
		}
		return inv.consoleApply()
	}
	if len(p.Args) == 1 {
		inv.echo(tierCSV(pol.File.ForwardingTiers))
		return nil
	}
	l, err := console.ParseTiers(p.Args[1], "forwarding")
	if err != nil {
		return err
	}
	if err := inv.consoleWrite(func(f *console.File) error { f.ForwardingTiers = l; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("X11 and TCP forwarding is open to: " + tierCSV(l) + ". The sshd drop-in follows it at the next sync.")
	return inv.consoleApply()
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

// consolePasswordCache is 'console password-cache [tiers [<csv>|none] | idle
// [<min>] | max [<hours>]]': the password cache's tiers and lifetimes (D70).
// A session reads them when it starts.
func (inv *invocation) consolePasswordCache(args []string) error {
	p, err := inv.consoleParse("password-cache", args)
	if err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	f := pol.File
	if len(p.Args) == 0 {
		inv.echo("tiers: " + tierCSV(f.PasswordCacheTiers))
		inv.echo("idle: " + strconv.Itoa(f.PasswordCacheIdle) + " min")
		inv.echo("max: " + strconv.Itoa(f.PasswordCacheMax) + " h")
		return nil
	}
	usage := "Usage: tacctl console " + consoleUse("password-cache")
	switch p.Args[0] {
	case "tiers":
		if len(p.Args) == 1 {
			inv.echo(tierCSV(f.PasswordCacheTiers))
			return nil
		}
		l, err := console.ParsePasswordCacheTiers(p.Args[1])
		if err != nil {
			return err
		}
		if err := inv.consoleWrite(func(f *console.File) error { f.PasswordCacheTiers = l; return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("The password cache is open to: " + tierCSV(l) + ". It applies from the next console login or 'tacctl shell --password-cache'.")
		return nil
	case "idle", "max":
		isIdle := p.Args[0] == "idle"
		lo, hi, unit := 1, console.MaxPasswordCacheMax, "hour(s)"
		cur := f.PasswordCacheMax
		if isIdle {
			hi, unit, cur = console.MaxPasswordCacheIdle, "minute(s)", f.PasswordCacheIdle
		}
		if len(p.Args) == 1 {
			inv.echo(strconv.Itoa(cur))
			return nil
		}
		n, err := strconv.Atoi(p.Args[1])
		if err != nil || n < lo || n > hi || strconv.Itoa(n) != p.Args[1] {
			return inv.usageErr("Invalid number of "+unit+" '"+p.Args[1]+"': expected "+strconv.Itoa(lo)+"-"+strconv.Itoa(hi)+".", usage)
		}
		if err := inv.consoleWrite(func(f *console.File) error {
			if isIdle {
				f.PasswordCacheIdle = n
			} else {
				f.PasswordCacheMax = n
			}
			return nil
		}); err != nil {
			return err
		}
		what := "A cached password is forgotten after " + p.Args[1] + " " + unit + " without a use"
		if !isIdle {
			what = "A cached password is forgotten " + p.Args[1] + " " + unit + " after it was cached"
		}
		inv.app.Out.Info(what + ". It applies to sessions that start from now on.")
		return nil
	}
	return inv.usageErr(usage)
}

// consoleForget is 'console forget' run as a tacctl command (from bash, or
// by a caller whose line did not reach the shell's own word): the cache
// lives in the process of the shell or the console, which handles the word
// itself, so there is nothing for this process to forget.
func (inv *invocation) consoleForget(args []string) error {
	if _, err := inv.consoleParse("forget", args); err != nil {
		return err
	}
	inv.app.Out.Info("The password cache belongs to the 'tacctl shell' or console session that holds it: type 'console forget' there. Nothing is cached in this process.")
	return nil
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
	gate := inv.tierGate()
	t := gate.Caller(inv.ctx)
	enforced := t
	// An engineer stays an engineer here whatever the cap of an unreadable
	// tacctl.yaml makes of its tier (Operator): the console is its only
	// login, with no system shell and no forwarding (D18), even when
	// 'console system-shell tiers' and 'forwarding tiers' name operator.
	if gate.EngineerBound(inv.ctx) {
		t = tier.Engineer
	}
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
	// The login console marks its question with TACCTL_CONSOLE; the plain
	// shell asks the same way for the tier its lists show, and is logged
	// as what it is.
	if session := a.Env.Get("TACCTL_CONSOLE"); session != "" {
		// The variable comes through sudo's env_keep from the caller, who
		// can set it to anything (a line break among it): only a session id
		// as the console makes them is logged.
		if !console.ValidSessionID(session) {
			session = "-"
		}
		a.Logger(inv.ctx, "auth.info", "console policy user="+who+" tier="+string(t)+" system_shell="+yesNo(sys)+" session="+session)
	} else {
		a.Logger(inv.ctx, "auth.info", "shell policy user="+who+" tier="+string(t))
	}
	// tier= is the console's own view of the caller; the shell lists only
	// the verbs the gate lets the caller run (D56), so when the gate's tier
	// differs (an engineer capped by an unreadable tacctl.yaml) it is sent
	// as gate=. ParseRemote falls back to tier= when gate= is absent.
	gateField := ""
	if enforced != t {
		gateField = " gate=" + string(enforced)
	}
	// The password cache's fields (D70) only when the caller's tier has
	// it: a line without them reads as off, and a console of an older
	// tacctl ignores them.
	cache := ""
	if pol.PasswordCache(t) {
		cache = " password_cache=yes pc_idle=" + strconv.Itoa(int(pol.PasswordCacheIdle()/time.Minute)) +
			" pc_max=" + strconv.Itoa(int(pol.PasswordCacheMax()/time.Hour))
	}
	inv.echo("shell=" + shell + " idle=" + strconv.Itoa(pol.File.Idle) + " system_shell=" + yesNo(sys) +
		" system_shell_path=" + path + " ssh_escape=" + yesNo(pol.SSHEscape()) + " agent=" + yesNo(pol.AgentForwarding()) +
		" forward=" + yesNo(pol.Forwarding(t)) + " tier=" + string(t) + gateField + " list_max=" + strconv.Itoa(pol.ListMax()) +
		" space_completion=" + yesNo(pol.SpaceCompletion()) + cache)
	return nil
}
