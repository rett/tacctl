package cli

// The 'console' family (docs/plans/operator-console-wp-console.md 5.1): which
// tacctl users get the login console (tacctl-console) as their shell on this
// server, and its settings, in /etc/tacctl/console.yaml (internal/console).
// The verbs change that file only, after a snapshot, and print the command
// that applies it to the accounts; they never change an account or sshd.
// '_console-policy' is the hidden verb the unprivileged console runs through
// sudo to learn its settings.

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/audit"
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
	"idle-timeout":     {MaxArgs: 1, Args: []string{""}},
	"agent-forwarding": {MaxArgs: 1, Args: []string{"enable|disable"}},
	"ssh-escape":       {MaxArgs: 1, Args: []string{"enable|disable"}},
	"space-completion": {MaxArgs: 1, Args: []string{"on|off"}},
	"color":            {MaxArgs: 1, Args: []string{"auto|on|off"}},
	"list-max":         {MaxArgs: 1, Args: []string{""}},
	"system-shell": {MaxArgs: 3, Args: []string{"readonly|operator|engineer|superuser|user|path",
		Cond("path", KindFile, Cond("user", KindUsers, "enable|disable")), After("user", "enable|disable|clear")}},
	"forwarding":     {MinArgs: 1, MaxArgs: 2, Args: []string{"tiers|gateway-ports", After("gateway-ports", "enable|disable")}},
	"password-cache": {MaxArgs: 3, Args: []string{"tiers|idle|max|on|off|user", Cond("user", KindUsers, ""), After("user", "clear")}},
	"forget":         {MaxArgs: 0},
	"install":        {MaxArgs: 0},
	"remove":         {MaxArgs: 0},
	"check":          {MaxArgs: 0},
}

// consoleVerbs are the verbs ({Use, Short}), in usage order.
var consoleVerbs = [][2]string{
	{"show", "The shell of each user, the system shell by tier, settings and the server's pieces"},
	{"idle-timeout [<min>]", "Show or set the minutes idle at the prompt before the session ends (0-1440, 0: never)"},
	{"agent-forwarding [enable|disable]", "Opt in to ssh agent forwarding for console users"},
	{"ssh-escape [enable|disable]", "Opt in to ssh's escape character (~. and ~C) inside the console's ssh"},
	{"space-completion [on|off]", "Show or set Junos-style spaces at the console's prompt: a typed space completes a fixed word and is never doubled; off turns off the refusal of repeated spaces and the completion (default on); pastes are unchanged, which assumes the terminal sends them bracketed (one that does not sends its spaces as typed ones: turn this off there); a word of dashes only (- or --) keeps its space"},
	{"color [auto|on|off]", "Show or set the colour of the console's lists (auto, on, off)"},
	{"list-max [<n>]", "Show or set the longest list shown without asking (0: 40, <0: never)"},
	{"forwarding tiers [<csv>|none]", "Show or set the tiers that may forward X11 and TCP ports (sshd, and the console's ssh -X/-L/-R/-D; default superuser; never engineer)"},
	{"forwarding gateway-ports [enable|disable]", "Opt in to forwarded ports on other addresses than loopback for those tiers (sshd's GatewayPorts for ssh -R, and the console's ssh -g and -L/-D bind addresses)"},
	{"system-shell [<tier> enable|disable]", "Show or set the system shell for a tier (superuser always has it, engineer never; default superuser only)"},
	{"system-shell user <name> [enable|disable|clear]", "Show or set the system shell for one user, over the tier's setting (clear: the tier decides)"},
	{"system-shell path [<path>]", "Show or set the system shell (default /bin/bash; must be listed in /etc/shells)"},
	{"password-cache [on|off]", "Show or set whether your sessions keep your password in memory"},
	{"password-cache user [<name>]", "Show the users who turned the password cache on"},
	{"password-cache user <name> clear", "Clear the password cache setting of a user (back to off)"},
	{"password-cache tiers [<csv>|none]", "Show or set the tiers whose shell and console sessions may keep your network password in memory for the session (operator, engineer, superuser; default none)"},
	{"password-cache idle [<min>]", "Show or set the minutes a cached password lives without a use (1-120, default 15)"},
	{"password-cache max [<hours>]", "Show or set the hours a cached password lives from the moment it was cached (1-24, default 8)"},
	{"forget", "Forget the cached password of this shell or console session now"},
	{"install", "Put the /etc/shells line and sshd's drop-ins (console users, engineers) in place (host sync of this server does too)"},
	{"remove", "Take the console's pieces away again (refused while an account has the console as its shell; the engineers' drop-in stays)"},
	{"check", "Check that sshd applies the console's and the engineers' settings to their users (exit 1 when not)"},
}

func consoleCmd(inv *invocation) *cobra.Command {
	c := verb("console <subcommand>", "Login console: the shell of every tacctl user on this server, and its settings")
	c.RunE = inv.native(withPreflight, inv.console)
	added := map[string]bool{}
	for _, v := range consoleVerbs {
		word := strings.Fields(v[0])[0]
		if added[word] {
			continue // the forms of system-shell are one command
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
The console is the login shell of every tacctl user on this server, of every
tier (tacctl-console): tacctl commands and ssh to registered devices, nothing
else. There is no switch for it. Local accounts that are not tacctl users are
never touched.

The settings commands change /etc/tacctl/console.yaml only. The accounts' login
shells and sshd's drop-in follow it when this server's accounts are synced
('tacctl host sync <name of this server>'); idle-timeout, ssh-escape,
space-completion, color, list-max and system-shell are read by each console
session when it starts. sshd's drop-in makes the console the only program a console user's login
runs (no scp, sftp or remote programs), closes every forwarding but X11 and TCP
ports for the tiers of 'forwarding tiers' (superusers by default: 'ssh -X', -L,
-R, -D and -J through this server, and 'ssh -X|-L|-R|-D <device>' in the
console), and turns key logins off.

'system-shell' starts the user's system shell from the console, as themselves,
logged. Superusers always have it; it is off for the other tiers until a
superuser opens it ('system-shell <tier> enable|disable') or gives it to one user
('system-shell user <name> enable|disable|clear'; a user's setting wins over the
tier's, and clear returns the user to the tier's). Only a superuser can set it;
the operator tier and up can read it ('system-shell' alone lists the state). Those who have it may also open an editor
from the console ('scope block ... edit|adopt', 'device block ... edit|adopt': an
editor can start a shell). Neither it nor forwarding is ever open to the engineer
tier: a shell or a forwarded port on this server would reach its secrets.

'password-cache' lets a tier's shell and console sessions keep the user's network
password in memory for the session, so a device pull or an ssh to a device asks
once (off for every tier by default; plain 'tacctl shell' takes --password-cache).
The password lives only in the session's own process: it is never written to a
file, and it is forgotten on exit, after the idle time, after the maximum
lifetime, when the password is changed, when a device refuses it, and with
'console forget'. It does not protect against root, who can read any process.
'password-cache tiers' says which tiers are allowed to use it; for a tier that is
allowed it is off until the user turns it on for themselves ('password-cache on'
at the prompt: saved for every later session, started in this one at once;
'password-cache off' saves that, forgets the password and stops caching).
'password-cache user' lets a superuser see who turned it on and clear a setting.

Examples:
  tacctl console show
  tacctl console system-shell operator enable
  tacctl console system-shell user jdoe enable
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
		"show":         inv.consoleShow,
		"idle-timeout": inv.consoleIdle, "system-shell": inv.consoleSystemShell, "forwarding": inv.consoleForwarding,
		"agent-forwarding": inv.consoleSwitch("agent-forwarding"), "ssh-escape": inv.consoleSwitch("ssh-escape"),
		"space-completion": inv.consoleSpace, "color": inv.consoleColor, "list-max": inv.consoleListMax,
		"password-cache": inv.consolePasswordCache, "forget": inv.consoleForget,
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
// snapshot of the current state, on the file itself. The change is logged as
// 'console set key= [item=] from= to=', show saying how the setting reads
// in a file (D253); item names the part of the setting ("" for none).
func (inv *invocation) consoleWrite(key, item string, show func(*console.File) string, fn func(*console.File) error) error {
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
	inv.app.Audit().Touch()
	if _, err = console.Mutate(p, inv.snapshotFirst, fn); err != nil {
		return err
	}
	inv.detail("console set", kvp("key", key), kvp("item", item), kvp("from", show(f)), kvp("to", show(trial)))
	return nil
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

// --- settings -------------------------------------------------------------------

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
	if err := inv.consoleWrite("idle-timeout", "", func(f *console.File) string { return strconv.Itoa(f.Idle) },
		func(f *console.File) error { f.Idle = n; return nil }); err != nil {
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
		show := func(f *console.File) string {
			if verbName == "agent-forwarding" {
				return onOff(f.AgentForwarding)
			}
			return onOff(f.SSHEscape)
		}
		if err := inv.consoleWrite(verbName, "", show, func(f *console.File) error {
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
	if err := inv.consoleWrite("space-completion", "", func(f *console.File) string { return spaceWord(f.SpaceCompletion) },
		func(f *console.File) error { f.SpaceCompletion = on; return nil }); err != nil {
		return err
	}
	if on {
		inv.app.Out.Info("A typed space at the console's prompt completes a fixed word. It applies from the next console login.")
	} else {
		inv.app.Out.Info("A typed space at the console's prompt is an ordinary space. It applies from the next console login.")
	}
	return nil
}

// consoleColor is 'console color [auto|on|off]': whether the console's lists
// (Tab's columns, '?', -h and --help) are in colour. The console's
// environment is scrubbed of NO_COLOR and TACCTL_COLOR, so this is how the
// operator chooses: auto lets the terminal decide. Each console session
// reads it when it starts.
func (inv *invocation) consoleColor(args []string) error {
	p, err := inv.consoleParse("color", args)
	if err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		inv.echo(pol.File.Color)
		return nil
	}
	mode := p.Args[0]
	if !slices.Contains(console.ColorWords, mode) {
		return inv.usageErr("Usage: tacctl console " + consoleUse("color"))
	}
	if err := inv.consoleWrite("color", "", func(f *console.File) string { return f.Color },
		func(f *console.File) error { f.Color = mode; return nil }); err != nil {
		return err
	}
	switch mode {
	case console.ColorOn:
		inv.app.Out.Info("The console's lists are always in colour. It applies from the next console login.")
	case console.ColorOff:
		inv.app.Out.Info("The console's lists are never in colour. It applies from the next console login.")
	default:
		inv.app.Out.Info("The console's lists are in colour where the terminal shows it. It applies from the next console login.")
	}
	return nil
}

// consoleListMax is 'console list-max [<n>]': the longest list the console's
// Tab and '?' show without asking 'Show all N?'. 0 is the default (40), a
// negative number never asks. The argument is read here, not by Parse: a
// negative number begins with a dash.
func (inv *invocation) consoleListMax(args []string) error {
	usage := "Usage: tacctl console " + consoleUse("list-max")
	if len(args) > 1 {
		return inv.usageErr("Unknown argument: '"+args[1]+"'", usage)
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		inv.echo(listMaxWord(pol.File.ListMax))
		return nil
	}
	n, err := strconv.Atoi(args[0])
	if err != nil || n > console.MaxListMax {
		return inv.usageErr("Invalid number '"+args[0]+"': expected 1-"+strconv.Itoa(console.MaxListMax)+", 0 for the default ("+strconv.Itoa(console.DefaultListMax)+") or a negative number to never ask.", usage)
	}
	switch {
	case n == 0:
		n = console.DefaultListMax
	case n < 0:
		n = console.ListMaxNever
	}
	if err := inv.consoleWrite("list-max", "", func(f *console.File) string { return strconv.Itoa(f.ListMax) },
		func(f *console.File) error { f.ListMax = n; return nil }); err != nil {
		return err
	}
	if n == console.ListMaxNever {
		inv.app.Out.Info("The console shows a long list without asking. It applies from the next console login.")
	} else {
		inv.app.Out.Info("A list of more than " + strconv.Itoa(n) + " entries asks 'Show all N?' first at the console's prompt. It applies from the next console login.")
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

// systemShellState is the state of a tier's system shell as the listings word
// it: the superuser tier always has it and the engineer tier never can.
func systemShellState(pol *console.Policy, t tier.Tier) string {
	switch {
	case t == tier.Superuser:
		return "enabled (always)"
	case slices.Contains(console.Closed, t):
		return "disabled (never)"
	}
	return map[bool]string{true: "enabled", false: "disabled"}[pol.SystemShell(t)]
}

// systemShellUserLine is one user with a setting of their own, for the
// listing: the setting and the user's tier (or why the setting counts for
// nothing).
func (inv *invocation) systemShellUserLine(pol *console.Policy, tiers map[string]tier.Tier, name string) string {
	word := map[bool]string{true: "enabled", false: "disabled"}[pol.File.SystemShellUsers[name]]
	t, ok := tiers[name]
	switch {
	case !ok:
		return name + ": " + word + " (no such user)"
	case t == tier.Superuser || slices.Contains(console.Closed, t):
		return name + ": " + word + " (" + string(t) + "; the setting is ignored)"
	}
	return name + ": " + word + " (" + string(t) + ")"
}

// systemShellTiers are the tier of each user of the store.
func (inv *invocation) systemShellTiers() (map[string]tier.Tier, error) {
	m, err := inv.model()
	if err != nil {
		return nil, err
	}
	out := map[string]tier.Tier{}
	for _, n := range m.UserNames() {
		out[n] = inv.userTier(n, m.UserPrivLvl(n))
	}
	return out, nil
}

// consoleSystemShell is 'console system-shell': with no argument the state
// of each tier and the users with a setting of their own; '<tier> enable|
// disable' and 'user <name> enable|disable|clear' set it (the superuser's);
// 'path [<path>]' is the program. The forms that only read (no argument, a
// tier, 'user <name>', 'path') are open to the operator tier and up; every
// form that sets something is the superuser's (systemShellWrites).
func (inv *invocation) consoleSystemShell(args []string) error {
	p, err := inv.consoleParse("system-shell", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl console " + consoleUse("system-shell")
	if systemShellWrites(p.Args) {
		if err := inv.deviceVerbAllowed("console", "system-shell", tier.Superuser); err != nil {
			return err
		}
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		for _, t := range console.Tiers {
			inv.echo(string(t) + ": " + systemShellState(pol, t))
		}
		if names := pol.File.SystemShellUserNames(); len(names) > 0 {
			tiers, err := inv.systemShellTiers()
			if err != nil {
				return err
			}
			inv.echo("")
			inv.echo("Users with a setting of their own:")
			for _, n := range names {
				inv.echo("  " + inv.systemShellUserLine(pol, tiers, n))
			}
		}
		return nil
	}
	switch p.Args[0] {
	case "path":
		if len(p.Args) == 1 {
			inv.echo(pol.File.SystemShell)
			return nil
		}
		if len(p.Args) > 2 {
			return inv.usageErr("Unknown argument: '"+p.Args[2]+"'", usage)
		}
		if err := console.CheckShell(p.Args[1], inv.app.Paths.ShellsFile); err != nil {
			return err
		}
		if err := inv.consoleWrite("system-shell", "path", func(f *console.File) string { return f.SystemShell },
			func(f *console.File) error { f.SystemShell = p.Args[1]; return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("system-shell starts " + p.Args[1] + ". It applies from the next console login.")
		return nil
	case "user":
		return inv.consoleSystemShellUser(pol, p.Args[1:], usage)
	}
	t, ok := console.ParseTier(p.Args[0])
	if !ok {
		return inv.usageErr("Unknown tier '"+p.Args[0]+"': expected readonly, operator, engineer or superuser.", usage)
	}
	if len(p.Args) == 1 {
		inv.echo(systemShellState(pol, t))
		return nil
	}
	if len(p.Args) > 2 {
		return inv.usageErr("Unknown argument: '"+p.Args[2]+"'", usage)
	}
	on, err := inv.enableWord(p.Args[1], "system-shell")
	if err != nil {
		return err
	}
	if slices.Contains(console.Closed, t) && !on {
		inv.app.Out.Info("The " + string(t) + " tier never has the system shell. Nothing was changed.")
		return nil
	}
	state := func(f *console.File) string {
		return onOff(console.TierHas(f, t))
	}
	if err := inv.consoleWrite("system-shell", string(t), state, func(f *console.File) error { return f.SetSystemShell(t, on) }); err != nil {
		return err
	}
	inv.app.Out.Info("system-shell is " + p.Args[1] + "d for the " + string(t) + " tier. It applies from the next console login.")
	return nil
}

// systemShellWrites reports whether the arguments of 'console system-shell'
// set something: a tier or the path with a value, or a user with a word. The
// reads are no argument, a tier alone, 'path' alone and 'user <name>'.
func systemShellWrites(args []string) bool {
	switch {
	case len(args) >= 3:
		return true
	case len(args) == 2:
		return args[0] != "user"
	}
	return false
}

// consoleSystemShellUser is 'console system-shell user <name> [enable|
// disable|clear]': args are the words after 'user'.
func (inv *invocation) consoleSystemShellUser(pol *console.Policy, args []string, usage string) error {
	if len(args) == 0 {
		return inv.usageErr("expected at least 1 argument(s), got 0", usage)
	}
	if len(args) > 2 {
		return inv.usageErr("Unknown argument: '"+args[2]+"'", usage)
	}
	name := args[0]
	m, err := inv.model()
	if err != nil {
		return err
	}
	exists := m.Exists("users", name)
	var t tier.Tier
	if exists {
		t = inv.userTier(name, m.UserPrivLvl(name))
	}
	own, has := pol.File.SystemShellUsers[name]
	userState := func(f *console.File) string {
		on, ok := f.SystemShellUsers[name]
		if !ok {
			return "none"
		}
		return onOff(on)
	}
	if len(args) == 1 {
		switch {
		case !exists && !has:
			return inv.usageErr("User '" + name + "' does not exist.")
		case !exists:
			inv.echo(onOff(own) + "d (user setting; no such user)")
		default:
			on, why := pol.SystemShellWhy(name, t)
			inv.echo(map[bool]string{true: "enabled", false: "disabled"}[on] + " (" + why + ")")
		}
		return nil
	}
	if args[1] == "clear" {
		if !has {
			inv.app.Out.Info("'" + name + "' has no system-shell setting of their own.")
			return nil
		}
		if err := inv.consoleWrite("system-shell", "user:"+name, userState,
			func(f *console.File) error { delete(f.SystemShellUsers, name); return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("The system-shell setting of '" + name + "' is cleared: the tier decides. It applies from the next console login.")
		return nil
	}
	on, err := inv.enableWord(args[1], "system-shell")
	if err != nil {
		return err
	}
	if !exists {
		return inv.usageErr("User '" + name + "' does not exist.")
	}
	switch {
	case t == tier.Superuser && !on:
		return inv.usageErr("'" + name + "' is a superuser, and superusers always have the system shell; it cannot be disabled. Nothing was changed.")
	case slices.Contains(console.Closed, t) && on:
		return inv.usageErr(console.ClosedText(t, "system-shell"))
	case t == tier.Superuser || slices.Contains(console.Closed, t):
		// Already so (superuser enabled, engineer disabled): nothing to
		// store, which a later change of the user's tier would revive.
		inv.app.Out.Info("'" + name + "' is a" + map[bool]string{true: " superuser, who always has", false: "n engineer, who never has"}[t == tier.Superuser] + " the system shell. Nothing was changed.")
		return nil
	}
	if err := inv.consoleWrite("system-shell", "user:"+name, userState,
		func(f *console.File) error { f.SystemShellUsers[name] = on; return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("system-shell is " + args[1] + "d for '" + name + "'. It applies from the next console login.")
	return nil
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
		if err := inv.consoleWrite("forwarding", "gateway-ports", func(f *console.File) string { return onOff(f.GatewayPorts) },
			func(f *console.File) error { f.GatewayPorts = on; return nil }); err != nil {
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
	if err := inv.consoleWrite("forwarding", "tiers", func(f *console.File) string { return tierCSV(f.ForwardingTiers) },
		func(f *console.File) error { f.ForwardingTiers = l; return nil }); err != nil {
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

// consolePasswordCache is 'console password-cache [on|off | tiers [<csv>|none]
// | idle [<min>] | max [<hours>] | user [<name> [clear]]]'. The tiers are the
// permission to keep the password in a session's memory, the lifetimes are
// its limits (D70), and 'on' and 'off' are the person's own choice, off until
// they turn it on: the three words open to the operator tier and up (the
// sudoers row names them exactly) act on the caller only. Everything else is
// the superuser's. A session reads the settings when it starts; the shell and
// the console also handle 'on' and 'off' themselves (shell.Shell).
func (inv *invocation) consolePasswordCache(args []string) error {
	p, err := inv.consoleParse("password-cache", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl console " + consoleUse("password-cache")
	first := ""
	if len(p.Args) > 0 {
		first = p.Args[0]
	}
	switch first {
	case "", "on", "off":
		if len(p.Args) > 1 {
			return inv.usageErr("Unknown argument: '"+p.Args[1]+"'", usage)
		}
	case "tiers", "idle", "max", "user":
		if first != "user" && len(p.Args) > 2 {
			return inv.usageErr("Unknown argument: '"+p.Args[2]+"'", usage)
		}
		if err := inv.deviceVerbAllowed("console", "password-cache", tier.Superuser); err != nil {
			return err
		}
	default:
		return inv.usageErr(usage)
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	f := pol.File
	switch first {
	case "":
		inv.echo("tiers: " + tierCSV(f.PasswordCacheTiers))
		inv.echo("idle: " + strconv.Itoa(f.PasswordCacheIdle) + " min")
		inv.echo("max: " + strconv.Itoa(f.PasswordCacheMax) + " h")
		if user := inv.callerStoreUser(); user != "" {
			t := inv.cacheTier()
			inv.echo("your tier (" + string(t) + "): " + map[bool]string{true: "allowed", false: "not allowed"}[pol.PasswordCache(t)])
			inv.echo("your setting: " + map[bool]string{true: "on", false: "off"}[pol.PasswordCacheOn(user)])
		}
		return nil
	case "on", "off":
		return inv.consolePasswordCacheSelf(pol, first == "on")
	case "user":
		return inv.consolePasswordCacheUser(pol, p.Args[1:], usage)
	}
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
		if err := inv.consoleWrite("password-cache", "tiers", func(f *console.File) string { return tierCSV(f.PasswordCacheTiers) },
			func(f *console.File) error { f.PasswordCacheTiers = l; return nil }); err != nil {
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
		show := func(f *console.File) string {
			if isIdle {
				return strconv.Itoa(f.PasswordCacheIdle)
			}
			return strconv.Itoa(f.PasswordCacheMax)
		}
		if err := inv.consoleWrite("password-cache", p.Args[0], show, func(f *console.File) error {
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

// cacheTier is the tier the password cache is decided for: the caller's, with
// an engineer kept one when an unreadable tacctl.yaml caps the gate's tier (as
// the policy line does).
func (inv *invocation) cacheTier() tier.Tier {
	gate := inv.tierGate()
	t := gate.Caller(inv.ctx)
	if gate.EngineerBound(inv.ctx) {
		t = tier.Engineer
	}
	return t
}

// consolePasswordCacheSelf is 'console password-cache on|off': the caller's
// own choice, saved in console.yaml by the root side. The user is the one sudo
// was run by and no word names another, so nobody sets another's. 'on' needs
// the caller's tier to be allowed (the permission) and saves nothing otherwise.
func (inv *invocation) consolePasswordCacheSelf(pol *console.Policy, on bool) error {
	user := inv.callerStoreUser()
	if user == "" {
		return inv.usageErr("The password cache is each tacctl user's own choice: run this as a tacctl user. Nothing was changed.")
	}
	t := inv.cacheTier()
	has := pol.PasswordCacheOn(user)
	if on && !pol.PasswordCache(t) {
		return inv.usageErr("The password cache is not allowed for the " + string(t) + " tier; a superuser allows it with: tacctl console password-cache tiers <tiers>. Nothing was changed.")
	}
	if on == has {
		inv.app.Out.Info("The password cache is already " + map[bool]string{true: "on", false: "off"}[on] + " for you. Nothing was changed.")
		return nil
	}
	state := func(f *console.File) string {
		return map[bool]string{true: "on", false: "off"}[f.PasswordCacheUsers[user]]
	}
	if err := inv.consoleWrite("password-cache", "user:"+user, state, func(f *console.File) error {
		if on {
			f.PasswordCacheUsers[user] = true
		} else {
			delete(f.PasswordCacheUsers, user)
		}
		return nil
	}); err != nil {
		return err
	}
	if on {
		inv.app.Out.Info("The password cache is on for you: it starts in the session you typed this in, and in every session from now on, until you turn it off (console password-cache off).")
	} else {
		inv.app.Out.Info("The password cache is off for you: no session of yours keeps your password.")
	}
	return nil
}

// consolePasswordCacheUser is 'console password-cache user [<name> [clear]]'
// (the superuser's): the users who turned the cache on, one user's setting, or
// clearing it so the user is back to off.
func (inv *invocation) consolePasswordCacheUser(pol *console.Policy, args []string, usage string) error {
	if len(args) > 2 {
		return inv.usageErr("Unknown argument: '"+args[2]+"'", usage)
	}
	tiers, err := inv.systemShellTiers()
	if err != nil {
		return err
	}
	f := pol.File
	if len(args) == 0 {
		names := f.PasswordCacheUserNames()
		if len(names) == 0 {
			inv.echo("none")
		}
		for _, n := range names {
			who := "no such user"
			if t, ok := tiers[n]; ok {
				who = string(t)
			}
			inv.echo(n + ": on (" + who + ")")
		}
		return nil
	}
	name := args[0]
	_, exists := tiers[name]
	has := f.PasswordCacheUsers[name]
	if !exists && !has {
		return inv.usageErr("User '" + name + "' does not exist.")
	}
	if len(args) == 1 {
		inv.echo(map[bool]string{true: "on", false: "off"}[has])
		return nil
	}
	if args[1] != "clear" {
		return inv.usageErr(usage)
	}
	if !has {
		inv.app.Out.Info("'" + name + "' has not turned the password cache on. Nothing was changed.")
		return nil
	}
	state := func(f *console.File) string {
		return map[bool]string{true: "on", false: "off"}[f.PasswordCacheUsers[name]]
	}
	if err := inv.consoleWrite("password-cache", "user:"+name, state, func(f *console.File) error {
		delete(f.PasswordCacheUsers, name)
		return nil
	}); err != nil {
		return err
	}
	inv.app.Out.Info("The password cache setting of '" + name + "' is cleared: it is off for them. A session they have open keeps its cache until it ends or they turn it off.")
	return nil
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
	if pol.Decide(t).Console {
		shell = "console"
	}
	sys := pol.SystemShellFor(inv.callerStoreUser(), t)
	path, perr := pol.SystemShellPath()
	if perr != nil {
		if sys {
			a.Audit().Raw("auth.warning", "console policy system_shell "+path+" unusable: "+strings.Join(msgs(perr), " ")+" by="+inv.sudoUser())
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
		a.Audit().Raw("auth.info", "console policy user="+who+" tier="+string(t)+" system_shell="+yesNo(sys)+" session="+session)
	} else {
		a.Audit().Raw("auth.info", "shell policy user="+who+" tier="+string(t))
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
		// password_cache says the console starts it (the tier is allowed and
		// the user turned it on); pc_allowed is the permission alone, which
		// 'tacctl shell --password-cache' needs.
		cache = " password_cache=" + yesNo(pol.PasswordCacheOn(inv.callerStoreUser())) + " pc_allowed=yes pc_idle=" +
			strconv.Itoa(int(pol.PasswordCacheIdle()/time.Minute)) + " pc_max=" + strconv.Itoa(int(pol.PasswordCacheMax()/time.Hour))
	}
	inv.echo("shell=" + shell + " idle=" + strconv.Itoa(pol.File.Idle) + " system_shell=" + yesNo(sys) +
		" system_shell_path=" + path + " ssh_escape=" + yesNo(pol.SSHEscape()) + " agent=" + yesNo(pol.AgentForwarding()) +
		" forward=" + yesNo(pol.Forwarding(t)) + " tier=" + string(t) + gateField + " list_max=" + strconv.Itoa(pol.ListMax()) +
		" space_completion=" + yesNo(pol.SpaceCompletion()) + " color=" + pol.Color() + cache)
	return nil
}

// userSettingsMove is what 'user remove', 'user rename' and 'user add' did to
// a user's own settings in console.yaml: the system shell (settings.
// system_shell_users: shellHad, with value shellOn) and the password cache
// (settings.password_cache_users: cacheHad, always on). err says console.yaml
// could not be written.
type userSettingsMove struct {
	shellHad, shellOn, cacheHad bool
	err                         error
}

// had reports whether the user had any of them.
func (m userSettingsMove) had() bool { return m.shellHad || m.cacheHad }

// moveUserSettings carries the settings of oldname to newname (newname "":
// drops them) in console.yaml, under its lock, as part of the user verb that
// follows the store's change (the snapshot the verb took first holds
// console.yaml). A person who is renamed keeps the access they had, a user who
// is removed leaves none behind for the next user of the name; a file without
// a setting for oldname is not touched, and an absent file is not created. An
// entry already under newname (hand-edited) is replaced by the carried one, or
// dropped by the removal.
func (inv *invocation) moveUserSettings(oldname, newname string) userSettingsMove {
	p := inv.app.Paths.ConsoleFile
	f, err := console.Load(p)
	if err != nil {
		return userSettingsMove{err: err}
	}
	on, shellHad := f.SystemShellUsers[oldname]
	cacheHad := f.PasswordCacheUsers[oldname]
	m := userSettingsMove{shellHad: shellHad, shellOn: on, cacheHad: cacheHad}
	if !m.had() {
		return m
	}
	_, m.err = console.Mutate(p, nil, func(f *console.File) error {
		delete(f.SystemShellUsers, oldname)
		delete(f.PasswordCacheUsers, oldname)
		if newname != "" {
			if shellHad {
				f.SystemShellUsers[newname] = on
			}
			if cacheHad {
				f.PasswordCacheUsers[newname] = true
			}
		}
		return nil
	})
	return m
}

// userSettingsMoved reports a move: the lines of the command's output and the
// 'console set' details. It returns the error of a console.yaml that could not
// be written (the store has changed already; the command says how to finish).
func (inv *invocation) userSettingsMoved(m userSettingsMove, oldname, newname string) error {
	if !m.had() {
		return nil
	}
	out := inv.app.Out
	verb := map[bool]string{true: "moved", false: "dropped"}[newname != ""]
	if m.err != nil {
		var fix []string
		if m.shellHad {
			fix = append(fix, "tacctl console system-shell user "+oldname+" clear")
			if newname != "" {
				fix = append(fix, "tacctl console system-shell user "+newname+" "+onOff(m.shellOn))
			}
		}
		if m.cacheHad {
			fix = append(fix, "tacctl console password-cache user "+oldname+" clear")
		}
		out.Error("The console settings of '" + oldname + "' could not be " + verb + " in console.yaml: " + msgsJoin(m.err) +
			". Finish it with: " + strings.Join(fix, ", then ") + map[bool]string{true: " (the user turns the password cache on again themselves)", false: ""}[m.cacheHad && newname != ""])
		return exit(1)
	}
	report := func(what, key, word string) {
		inv.detailAt(audit.Notice, "console set", kvp("key", key), kvp("item", "user:"+oldname), kvp("from", word), kvp("to", "none"))
		if newname == "" {
			out.Info("The " + what + " setting of '" + oldname + "' (" + word + ") is dropped.")
			return
		}
		inv.detailAt(audit.Notice, "console set", kvp("key", key), kvp("item", "user:"+newname), kvp("from", "none"), kvp("to", word))
		out.Info("The " + what + " setting of '" + oldname + "' (" + word + ") moves to '" + newname + "'.")
	}
	if m.shellHad {
		report("system-shell", "system-shell", onOff(m.shellOn))
	}
	if m.cacheHad {
		report("password-cache", "password-cache", "on")
	}
	return nil
}

// callerStoreUser is the name the user settings of the caller are
// looked up under: the caller when it is a user of the store, else "" (no
// entry has that name): an entry of a name that is no store user is not
// honoured.
func (inv *invocation) callerStoreUser() string {
	user := inv.sudoUser()
	if m, err := inv.model(); err != nil || !m.Exists("users", user) {
		return ""
	}
	return user
}
