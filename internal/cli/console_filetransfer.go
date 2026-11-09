package cli

// 'console file-transfer': who may transfer files through the console, how
// much their home may hold (the quota) and how fast a transfer may go (the
// rate), per tier and per user. The settings are the system shell's in shape
// (console/filetransfer.go): the user's own setting wins over the tier's, an
// enable ends when the user moves to another tier, the superuser tier always
// has it, and the engineer tier is not closed to it. Reading is open to the
// operator tier and up, setting is the superuser's (fileTransferWrites).

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// fileTransferState is the state of a tier's file transfer as the listings
// word it.
func fileTransferState(pol *console.Policy, t tier.Tier) string {
	if t == tier.Superuser {
		return "enabled (always)"
	}
	return map[bool]string{true: "enabled", false: "disabled"}[pol.FileTransferTier(t)]
}

// fileTransferUserLine is one user with a switch of their own, for the
// listing: the setting and the user's tier (or why it counts for nothing).
func (inv *invocation) fileTransferUserLine(pol *console.Policy, tiers map[string]tier.Tier, name string) string {
	word := map[bool]string{true: "enabled", false: "disabled"}[pol.File.FileTransferUsers[name]]
	t, ok := tiers[name]
	if was, stale := pol.FileTransferStale(name, t); ok && stale {
		return name + ": " + word + " (stale: set for " + string(was) + ", now " + string(t) + ")"
	}
	switch {
	case !ok:
		return name + ": " + word + " (no such user)"
	case t == tier.Superuser:
		return name + ": " + word + " (superuser; the setting is ignored)"
	}
	return name + ": " + word + " (" + string(t) + ")"
}

// fileTransferOpened reports whether file transfer is on for anyone but the
// superuser tier, which always has it: a tier that was opened to it, or a
// user who was given it and still is in the tier it was set for. The notice
// about sshd's subsystem warns for these; a server nobody opened it on has
// only the line.
func (inv *invocation) fileTransferOpened(pol *console.Policy) bool {
	for _, t := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer} {
		if pol.FileTransferTier(t) {
			return true
		}
	}
	var tiers map[string]tier.Tier
	for _, n := range pol.File.FileTransferUserNames() {
		if !pol.File.FileTransferUsers[n] {
			continue
		}
		if tiers == nil {
			var err error
			if tiers, err = inv.systemShellTiers(); err != nil {
				// the tiers cannot be read: warn rather than stay quiet
				return true
			}
		}
		if t, ok := tiers[n]; ok {
			if _, stale := pol.FileTransferStale(n, t); !stale && pol.FileTransferFor(n, t) {
				return true
			}
		}
	}
	return false
}

// sftpSubsystemNotice prints whether sshd defines an sftp subsystem (cmd, the
// result of console.SFTPSubsystem or SSHD.SFTP; err: the check could not be
// made) and, when file transfer is on for someone and it does not, the
// warning that the console cannot serve anyone: sshd never starts the
// subsystem, and a Match block cannot define it, so the line must be in
// sshd_config itself (tacctl adds nothing global).
func (inv *invocation) sftpSubsystemNotice(pol *console.Policy, cmd string, err error) {
	switch {
	case err != nil:
		inv.echo("sshd sftp subsystem: could not be checked: " + strings.Join(msgs(err), " "))
		return
	case cmd == "":
		inv.echo("sshd sftp subsystem: none")
	default:
		inv.echo("sshd sftp subsystem: " + cmd)
	}
	if cmd == "" && inv.fileTransferOpened(pol) {
		inv.echoE(ui.Red + sftpSubsystemWarning + ui.NC)
	}
}

// sftpSubsystemWarning is the warning for a server whose sshd starts no sftp
// subsystem while file transfer is on.
const sftpSubsystemWarning = "WARNING: sshd defines no sftp subsystem: file transfer cannot start; add `Subsystem sftp ...` to sshd_config."

// fileTransferWrites reports whether the arguments of 'console
// file-transfer' set something. The reads are no argument, a tier alone,
// 'user <name>', 'quota' and 'rate' alone, 'quota|rate <tier>' and
// 'quota|rate user <name>'.
func fileTransferWrites(args []string) bool {
	switch {
	case len(args) == 0:
		return false
	case args[0] == "quota" || args[0] == "rate":
		if len(args) >= 2 && args[1] == "user" {
			return len(args) >= 4
		}
		return len(args) >= 3
	case args[0] == "user":
		return len(args) >= 3
	}
	return len(args) >= 2
}

// sizeErr turns the refusal of a size into the line and the usage, exit 1.
func (inv *invocation) sizeErr(err error, usage string) error {
	return inv.usageErr(strings.Join(msgs(err), " "), usage)
}

// consoleFileTransfer is 'console file-transfer': with no argument the state
// of each tier and the users with a switch of their own; '<tier> enable|
// disable' and 'user <name> enable|disable|clear' set it; 'quota' and 'rate'
// show or set the limits of the tiers and the users.
func (inv *invocation) consoleFileTransfer(args []string) error {
	p, err := inv.consoleParse("file-transfer", args)
	if err != nil {
		return err
	}
	usage := "Usage: tacctl console " + consoleUse("file-transfer")
	if fileTransferWrites(p.Args) {
		if err := inv.deviceVerbAllowed("console", "file-transfer", tier.Superuser); err != nil {
			return err
		}
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	if len(p.Args) == 0 {
		for _, t := range console.Tiers {
			inv.echo(string(t) + ": " + fileTransferState(pol, t))
		}
		if names := pol.File.FileTransferUserNames(); len(names) > 0 {
			tiers, err := inv.systemShellTiers()
			if err != nil {
				return err
			}
			inv.echo("")
			inv.echo("Users with a setting of their own:")
			for _, n := range names {
				inv.echo("  " + inv.fileTransferUserLine(pol, tiers, n))
			}
		}
		inv.echo("")
		cmd, err := console.SFTPSubsystem(inv.ctx, inv.app.Runner)
		inv.sftpSubsystemNotice(pol, cmd, err)
		return nil
	}
	switch p.Args[0] {
	case "user":
		return inv.consoleFileTransferUser(pol, p.Args[1:], usage)
	case "quota", "rate":
		return inv.consoleFileTransferLimit(pol, p.Args[0], p.Args[1:], usage)
	}
	t, ok := console.ParseTier(p.Args[0])
	if !ok {
		return inv.usageErr("Unknown tier '"+p.Args[0]+"': expected readonly, operator, engineer or superuser.", usage)
	}
	if len(p.Args) == 1 {
		inv.echo(fileTransferState(pol, t))
		return nil
	}
	if len(p.Args) > 2 {
		return inv.usageErr("Unknown argument: '"+p.Args[2]+"'", usage)
	}
	on, err := inv.enableWord(p.Args[1], "file-transfer")
	if err != nil {
		return err
	}
	if t == tier.Superuser && on {
		inv.app.Out.Info("The superuser tier always has file transfer. Nothing was changed.")
		return nil
	}
	state := func(f *console.File) string {
		return onOff((&console.Policy{File: f}).FileTransferTier(t))
	}
	if err := inv.consoleWrite("file-transfer", string(t), state, func(f *console.File) error { return f.SetFileTransfer(t, on) }); err != nil {
		return err
	}
	inv.app.Out.Info("File transfer is " + p.Args[1] + "d for the " + string(t) + " tier. It applies from the next console login.")
	return nil
}

// consoleFileTransferUser is 'console file-transfer user <name> [enable|
// disable|clear]': args are the words after 'user'.
func (inv *invocation) consoleFileTransferUser(pol *console.Policy, args []string, usage string) error {
	if len(args) == 0 {
		return inv.usageErr("expected at least 1 argument(s), got 0", usage)
	}
	if len(args) > 2 {
		return inv.usageErr("Unknown argument: '"+args[2]+"'", usage)
	}
	name := args[0]
	exists, t, err := inv.fileTransferUser(name)
	if err != nil {
		return err
	}
	own, has := pol.File.FileTransferUsers[name]
	userState := func(f *console.File) string {
		on, ok := f.FileTransferUsers[name]
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
			on, why := pol.FileTransferWhy(name, t)
			inv.echo(map[bool]string{true: "enabled", false: "disabled"}[on] + " (" + why + ")")
		}
		return nil
	}
	if args[1] == "clear" {
		if !has {
			inv.app.Out.Info("'" + name + "' has no file transfer setting of their own.")
			return nil
		}
		if err := inv.consoleWrite("file-transfer", "user:"+name, userState,
			func(f *console.File) error { f.DropFileTransferUser(name); return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("The file transfer setting of '" + name + "' is cleared: the tier decides. It applies from the next console login.")
		return nil
	}
	on, err := inv.enableWord(args[1], "file-transfer")
	if err != nil {
		return err
	}
	if !exists {
		return inv.usageErr("User '" + name + "' does not exist.")
	}
	switch {
	case t == tier.Superuser && !on:
		return inv.usageErr("'" + name + "' is a superuser, and superusers always have file transfer; it cannot be disabled. Nothing was changed.")
	case t == tier.Superuser:
		// Already so: nothing to store, which a later change of the user's
		// tier would revive.
		inv.app.Out.Info("'" + name + "' is a superuser, who always has file transfer. Nothing was changed.")
		return nil
	case !slices.Contains([]tier.Tier{tier.Readonly, tier.Operator, tier.Engineer}, t):
		return inv.usageErr("'" + name + "' has no tier (the account is disabled?), so file transfer cannot be switched for them. Nothing was changed.")
	}
	if err := inv.consoleWrite("file-transfer", "user:"+name, userState,
		func(f *console.File) error { f.SetFileTransferUser(name, on, t); return nil }); err != nil {
		return err
	}
	inv.app.Out.Info("File transfer is " + args[1] + "d for '" + name + "'" + map[bool]string{true: " while they are in the " + string(t) + " tier (a move to another tier ends it until it is set again)", false: ""}[on] +
		". It applies from the next console login.")
	return nil
}

// fileTransferUser is whether the user exists and the tier they have.
func (inv *invocation) fileTransferUser(name string) (exists bool, t tier.Tier, err error) {
	m, err := inv.model()
	if err != nil {
		return false, "", err
	}
	if !m.Exists("users", name) {
		return false, "", nil
	}
	return true, inv.userTier(name, m.UserPrivLvl(name)), nil
}

// fileTransferLimit is what 'quota' and 'rate' differ in.
type fileTransferLimit struct {
	key, noun string
	// none is the word of no limit (unlimited, off), tierDefault whether a
	// tier can be returned to a built-in default by the word 'default'.
	none        string
	tierDefault bool
	parse       func(string) (int64, error)
	word        func(int64) string
	value       func(*console.Policy, string, tier.Tier) (int64, string)
	tierSet     func(*console.File) map[tier.Tier]int64
	userSet     func(*console.File) map[string]int64
}

var fileTransferLimits = map[string]fileTransferLimit{
	"quota": {key: "quota", noun: "quota", none: console.Unlimited, tierDefault: true, parse: console.ParseQuota, word: console.QuotaWord,
		value:   func(p *console.Policy, u string, t tier.Tier) (int64, string) { return p.FileTransferQuota(u, t) },
		tierSet: func(f *console.File) map[tier.Tier]int64 { return f.FileTransferQuota },
		userSet: func(f *console.File) map[string]int64 { return f.FileTransferQuotaUsers }},
	"rate": {key: "rate", noun: "rate limit", none: console.RateOff, parse: console.ParseRate, word: console.RateWord,
		value:   func(p *console.Policy, u string, t tier.Tier) (int64, string) { return p.FileTransferRate(u, t) },
		tierSet: func(f *console.File) map[tier.Tier]int64 { return f.FileTransferRate },
		userSet: func(f *console.File) map[string]int64 { return f.FileTransferRateUsers }},
}

// limitText words a value with where it comes from, for the listings.
func (l fileTransferLimit) limitText(n int64, from string, t tier.Tier) string {
	switch from {
	case "tier setting":
		return l.word(n) + " (set for the " + string(t) + " tier)"
	case "default":
		return l.word(n) + " (default)"
	}
	return l.word(n) + " (" + from + ")"
}

// consoleFileTransferLimit is 'console file-transfer quota|rate ...': with no
// argument the value of each tier and the users with one of their own;
// '<tier>' shows one tier, '<tier> <size|word>' sets it (the superuser's);
// 'user <name>' shows one user's, 'user <name> <size|word|clear>' sets it.
func (inv *invocation) consoleFileTransferLimit(pol *console.Policy, which string, args []string, usage string) error {
	l := fileTransferLimits[which]
	if len(args) == 0 {
		for _, t := range console.Tiers {
			n, from := l.value(pol, "", t)
			inv.echo(string(t) + ": " + l.limitText(n, from, t))
		}
		if names := sortedUsers(l.userSet(pol.File)); len(names) > 0 {
			tiers, err := inv.systemShellTiers()
			if err != nil {
				return err
			}
			inv.echo("")
			inv.echo("Users with a " + l.noun + " of their own:")
			for _, n := range names {
				who := "no such user"
				if t, ok := tiers[n]; ok {
					who = string(t)
				}
				inv.echo("  " + n + ": " + l.word(l.userSet(pol.File)[n]) + " (" + who + ")")
			}
		}
		return nil
	}
	if args[0] == "user" {
		return inv.consoleFileTransferLimitUser(pol, l, args[1:], usage)
	}
	t, ok := console.ParseTier(args[0])
	if !ok {
		return inv.usageErr("Unknown tier '"+args[0]+"': expected readonly, operator, engineer, superuser or user.", usage)
	}
	if len(args) == 1 {
		n, from := l.value(pol, "", t)
		inv.echo(l.limitText(n, from, t))
		return nil
	}
	if len(args) > 2 {
		return inv.usageErr("Unknown argument: '"+args[2]+"'", usage)
	}
	state := func(f *console.File) string {
		if n, ok := l.tierSet(f)[t]; ok {
			return l.word(n)
		}
		return "default"
	}
	var n int64
	def := args[1] == "default" && l.tierDefault
	if !def {
		var err error
		if n, err = l.parse(args[1]); err != nil {
			return inv.sizeErr(err, usage)
		}
	}
	if err := inv.consoleWrite("file-transfer", l.key+":"+string(t), state, func(f *console.File) error {
		if l.key == "quota" {
			f.SetFileTransferQuota(t, n, def)
		} else {
			f.SetFileTransferRate(t, n)
		}
		return nil
	}); err != nil {
		return err
	}
	switch {
	case def:
		inv.app.Out.Info("The quota of the " + string(t) + " tier is back to its default (" + console.QuotaWord(console.DefaultTierQuota(t)) + "). It applies from the next console login.")
	case n == 0:
		inv.app.Out.Info("The " + string(t) + " tier has " + map[string]string{"quota": "no quota", "rate": "no rate limit"}[l.key] + ". It applies from the next console login.")
	default:
		inv.app.Out.Info("The " + l.noun + " of the " + string(t) + " tier is " + l.word(n) + map[string]string{"quota": "", "rate": " a second"}[l.key] + ". It applies from the next console login.")
	}
	return nil
}

// consoleFileTransferLimitUser is 'console file-transfer quota|rate user
// <name> [<size|word>|clear]': args are the words after 'user'.
func (inv *invocation) consoleFileTransferLimitUser(pol *console.Policy, l fileTransferLimit, args []string, usage string) error {
	if len(args) == 0 {
		return inv.usageErr("expected at least 1 argument(s), got 0", usage)
	}
	if len(args) > 2 {
		return inv.usageErr("Unknown argument: '"+args[2]+"'", usage)
	}
	name := args[0]
	exists, t, err := inv.fileTransferUser(name)
	if err != nil {
		return err
	}
	own, has := l.userSet(pol.File)[name]
	state := func(f *console.File) string {
		if n, ok := l.userSet(f)[name]; ok {
			return l.word(n)
		}
		return "none"
	}
	if len(args) == 1 {
		switch {
		case !exists && !has:
			return inv.usageErr("User '" + name + "' does not exist.")
		case !exists:
			inv.echo(l.word(own) + " (user setting; no such user)")
		default:
			n, from := l.value(pol, name, t)
			inv.echo(l.limitText(n, from, t))
		}
		return nil
	}
	if args[1] == "clear" {
		if !has {
			inv.app.Out.Info("'" + name + "' has no " + l.noun + " of their own.")
			return nil
		}
		if err := inv.consoleWrite("file-transfer", l.key+"-user:"+name, state,
			func(f *console.File) error { delete(l.userSet(f), name); return nil }); err != nil {
			return err
		}
		inv.app.Out.Info("The " + l.noun + " of '" + name + "' is cleared: the tier decides. It applies from the next console login.")
		return nil
	}
	n, err := l.parse(args[1])
	if err != nil {
		return inv.sizeErr(err, usage)
	}
	if !exists {
		return inv.usageErr("User '" + name + "' does not exist.")
	}
	if err := inv.consoleWrite("file-transfer", l.key+"-user:"+name, state,
		func(f *console.File) error { l.userSet(f)[name] = n; return nil }); err != nil {
		return err
	}
	switch {
	case n == 0 && l.key == "quota":
		inv.app.Out.Info("'" + name + "' has no quota. It applies from the next console login.")
	case n == 0:
		inv.app.Out.Info("'" + name + "' has no rate limit, whatever their tier has. It applies from the next console login.")
	default:
		inv.app.Out.Info("The " + l.noun + " of '" + name + "' is " + l.word(n) + map[string]string{"quota": "", "rate": " a second"}[l.key] + ". It applies from the next console login.")
	}
	return nil
}

// sortedUsers are the keys of m, sorted.
func sortedUsers(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
