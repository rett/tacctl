package cli

// 'console install|remove|check' (docs/plans/operator-console-wp-console.md
// 5.3): the server's pieces of the console, which 'host enroll --local' and
// 'host sync' of this server also provision. install puts the /etc/shells
// line and sshd's drop-in in place (idempotent), remove takes them away
// once no account has the console as its shell, check says whether sshd
// applies the drop-in to a console user.

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// consoleProvision puts the server's pieces in place: the symlink must be
// there (install and upgrade make it), the /etc/shells line is added, and
// sshd's drop-in is written for console.yaml's settings ('sshd -t', sshd
// reloaded; a refusal undoes it). Each piece is reported "Installed:",
// "Updated:" or "Unchanged:". An error is printed; the caller decides what
// it stops.
func (inv *invocation) consoleProvision(pol *console.Policy) error {
	a := inv.app
	p := a.Paths
	if target, err := os.Readlink(p.ConsoleCommand); err != nil || target == "" {
		a.Out.ErrorE(p.ConsoleCommand + " is missing: the console is installed with tacctl itself. Run: tacctl upgrade")
		return exit(1)
	}
	shells, err := console.EnsureShells(p.ShellsFile, p.ConsoleCommand)
	if err != nil {
		inv.consoleErr(err)
		return exit(1)
	}
	a.Out.InfoE("  " + shells.String() + ": " + p.ShellsFile + " lists " + p.ConsoleCommand)
	d := console.DropInFile{Runner: a.Runner, Path: p.SSHDDropIn}
	ch, err := d.Install(inv.ctx, console.DropIn(p.ConsoleCommand, pol.AgentForwarding(), pol.GatewayPorts(), pol.ForwardingTiers()))
	switch {
	case errors.Is(err, console.ErrSSHD):
		a.Out.ErrorE("sshd refused the console's drop-in; " + p.SSHDDropIn + " was put back as it was:")
		for _, l := range msgs(err) {
			a.Out.ErrorE("  " + strings.TrimSpace(l))
		}
		return exit(1)
	case err != nil && ch == console.Unchanged:
		inv.consoleErr(err)
		return exit(1)
	case err != nil:
		a.Out.InfoE("  " + ch.String() + ": sshd drop-in " + p.SSHDDropIn)
		inv.consoleErr(err)
		return exit(1)
	}
	a.Out.InfoE("  " + ch.String() + ": sshd drop-in " + p.SSHDDropIn)
	a.Logger(inv.ctx, "auth.info", "console provision shells="+strings.ToLower(shells.String())+" dropin="+strings.ToLower(ch.String())+" by="+inv.sudoUser())
	return nil
}

// engineerSSHDProvision puts sshd's drop-in for the engineer tier in place
// (console.EngineerDropIn, its own file): at every sync of this server and
// by 'console install', whatever the state of the console, because an
// engineer without the console has /usr/sbin/nologin and still could tunnel
// through sshd. A change is reported, an unchanged file is not (a sync says
// enough); an error is printed and returned for the caller to warn about.
func (inv *invocation) engineerSSHDProvision(pol *console.Policy) error {
	a := inv.app
	p := a.Paths
	d := console.DropInFile{Runner: a.Runner, Path: p.SSHDEngineerDropIn}
	ch, err := d.Install(inv.ctx, console.EngineerDropIn(pol.AgentForwarding()))
	if ch != console.Unchanged {
		a.Out.InfoE("  " + ch.String() + ": sshd drop-in " + p.SSHDEngineerDropIn + " (engineer tier)")
	}
	switch {
	case errors.Is(err, console.ErrSSHD):
		a.Out.ErrorE("sshd refused the engineer tier's drop-in; " + p.SSHDEngineerDropIn + " was put back as it was:")
		for _, l := range msgs(err) {
			a.Out.ErrorE("  " + strings.TrimSpace(l))
		}
	case err != nil:
		inv.consoleErr(err)
	}
	if err == nil && ch != console.Unchanged {
		a.Logger(inv.ctx, "auth.info", "console provision engineer-dropin="+strings.ToLower(ch.String())+" by="+inv.sudoUser())
	}
	if err == nil {
		// The file lived under a name that sorts after the console's (S1):
		// now that the new one is in place the old one goes, so the
		// console's forwarding tiers cannot beat it.
		od := console.DropInFile{Runner: a.Runner, Path: p.SSHDEngineerDropInOld}
		switch och, oerr := od.Remove(inv.ctx); {
		case oerr != nil && och == console.Unchanged:
			inv.consoleErr(oerr)
			err = oerr
		case och == console.Removed:
			a.Out.InfoE("  Removed: sshd drop-in " + p.SSHDEngineerDropInOld + " (replaced by " + p.SSHDEngineerDropIn + ")")
			if oerr != nil {
				inv.consoleErr(oerr)
			}
		}
	}
	return err
}

// consoleErr prints an error's lines as errors.
func (inv *invocation) consoleErr(err error) {
	for _, l := range msgs(err) {
		inv.app.Out.ErrorE(l)
	}
}

// consoleShellAccounts are this machine's accounts whose login shell is the
// console ('getent passwd').
func (inv *invocation) consoleShellAccounts() ([]string, error) {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"passwd"}})
	if err != nil || res.Code != 0 {
		return nil, errors.New("cannot list this server's accounts (getent passwd)")
	}
	var out []string
	for _, l := range strings.Split(string(res.Stdout), "\n") {
		f := strings.Split(l, ":")
		if len(f) == 7 && f[6] == inv.app.Paths.ConsoleCommand {
			out = append(out, f[0])
		}
	}
	return out, nil
}

// consoleDeprovision takes the server's pieces away: refused while an
// account still has the console as its shell (they are named, with the
// way out); otherwise sshd's drop-in goes ('sshd -t', reload) and the
// /etc/shells line.
func (inv *invocation) consoleDeprovision() error {
	a := inv.app
	p := a.Paths
	users, err := inv.consoleShellAccounts()
	if err != nil {
		a.Out.ErrorE(err.Error() + "; nothing was removed.")
		return exit(1)
	}
	if len(users) > 0 {
		a.Out.ErrorE("These accounts still have the console as their login shell: " + strings.Join(users, ", ") + ". Nothing was removed.")
		local := "<name of this server>"
		if e, ok, _ := inv.localHost(); ok {
			local = e.Name
		}
		a.Out.ErrorE("Give them " + console.SystemLoginShell + " first: tacctl console tiers <tier> disable (or console user <name> disable), then tacctl host sync " +
			local + "; or tacctl host unenroll " + local)
		return exit(1)
	}
	// The engineer tier's drop-in stays (an engineer without the console
	// still must not forward), but under its current name.
	if _, serr := os.Stat(p.SSHDEngineerDropInOld); serr == nil {
		if pol, perr := inv.consolePolicy(); perr == nil {
			if inv.engineerSSHDProvision(pol) != nil {
				return exit(1)
			}
		}
	}
	d := console.DropInFile{Runner: a.Runner, Path: p.SSHDDropIn}
	ch, err := d.Remove(inv.ctx)
	if err != nil && ch == console.Unchanged {
		a.Out.ErrorE("sshd drop-in " + p.SSHDDropIn + " was not removed:")
		for _, l := range msgs(err) {
			a.Out.ErrorE("  " + strings.TrimSpace(l))
		}
		return exit(1)
	}
	a.Out.InfoE("  " + ch.String() + ": sshd drop-in " + p.SSHDDropIn)
	if err != nil {
		inv.consoleErr(err)
	}
	sch, serr := console.RemoveShells(p.ShellsFile, p.ConsoleCommand)
	if serr != nil {
		inv.consoleErr(serr)
		return exit(1)
	}
	a.Out.InfoE("  " + sch.String() + ": " + p.ConsoleCommand + " in " + p.ShellsFile)
	a.Logger(inv.ctx, "auth.info", "console deprovision by="+inv.sudoUser())
	if err != nil {
		return exit(1)
	}
	return nil
}

// consoleCheckFiles and consoleCheckUser are the reasons the console's
// sshd settings do not hold on this server (none: they do): the drop-in and
// sshd_config, then what sshd applies to one console user. The lines
// describing what was found are printed as they are learnt.
func (inv *invocation) consoleCheckFiles(pol *console.Policy) []string {
	p := inv.app.Paths
	var problems []string
	want := console.DropIn(p.ConsoleCommand, pol.AgentForwarding(), pol.GatewayPorts(), pol.ForwardingTiers())
	switch data, err := os.ReadFile(p.SSHDDropIn); {
	case err != nil:
		inv.echo("  sshd drop-in " + p.SSHDDropIn + ": missing")
		problems = append(problems, "sshd's drop-in "+p.SSHDDropIn+" is missing")
	case string(data) != want:
		inv.echo("  sshd drop-in " + p.SSHDDropIn + ": present, differs from this release's")
		problems = append(problems, "sshd's drop-in "+p.SSHDDropIn+" differs from this release's")
	default:
		inv.echo("  sshd drop-in " + p.SSHDDropIn + ": present, current")
	}
	dir := filepath.Dir(p.SSHDDropIn)
	main := filepath.Join(filepath.Dir(dir), "sshd_config")
	if data, err := os.ReadFile(main); err == nil {
		if console.IncludesDropIns(string(data), dir) {
			inv.echo("  " + main + ": includes " + dir + "/*.conf")
		} else {
			inv.echo("  " + main + ": does not include " + dir + "/*.conf")
			problems = append(problems, main+" does not include "+dir+"/*.conf, so sshd never reads the drop-in")
		}
	}
	return problems
}

// consoleCheckUser is what sshd applies to user ("": no account has the
// console).
func (inv *invocation) consoleCheckUser(pol *console.Policy, user string) []string {
	p := inv.app.Paths
	var problems []string
	if user == "" {
		inv.echo("  sshd: not checked (no account has the console as its shell)")
		return problems
	}
	st, err := console.SSHDCheck(inv.ctx, inv.app.Runner, user)
	if err != nil {
		inv.echo("  sshd for " + user + ": could not be checked: " + strings.Join(msgs(err), " "))
		return append(problems, "sshd could not be asked what it applies to "+user)
	}
	inv.echo("  sshd for " + user + ": allowtcpforwarding " + st.TCPForwarding + ", allowagentforwarding " + st.AgentForwarding +
		", forcecommand " + dash(st.ForceCommand) + ", pubkeyauthentication " + dash(st.PubkeyAuth) + sshdGatewayPorts(st))
	return append(problems, st.Problems(pol.AgentForwarding(), inv.userForwards(pol, user), pol.GatewayPorts(), p.ConsoleCommand)...)
}

// sshdGatewayPorts is ', gatewayports <value>' when sshd printed it.
func sshdGatewayPorts(st console.SSHD) string {
	if st.GatewayPorts == "" {
		return ""
	}
	return ", gatewayports " + st.GatewayPorts
}

// consoleProbeUsers are the console accounts sshd is asked about: the
// first whose tier may not forward and the first whose tier may, so that a
// setting read before the drop-in (which sshd keeps over the tier blocks)
// shows whichever way it opens or closes.
func (inv *invocation) consoleProbeUsers(pol *console.Policy, users []string) []string {
	var closed, open string
	for _, u := range users {
		if inv.userForwards(pol, u) {
			if open == "" {
				open = u
			}
		} else if closed == "" {
			closed = u
		}
	}
	var out []string
	for _, u := range []string{closed, open} {
		if u != "" {
			out = append(out, u)
		}
	}
	return out
}

// consoleFirstValueHint names the likely cause when a user whose tier may
// not forward can: sshd keeps the first value it reads.
func (inv *invocation) consoleFirstValueHint(pol *console.Policy, probe, problems []string) []string {
	for _, p := range problems {
		if strings.Contains(p, "forwarding is") || strings.Contains(p, "gatewayports is") {
			dir := filepath.Dir(inv.app.Paths.SSHDDropIn)
			return []string{"sshd keeps the first value it reads, so an X11Forwarding, AllowTcpForwarding, GatewayPorts or DisableForwarding line read before " +
				inv.app.Paths.SSHDDropIn + " overrides it: look in " + filepath.Join(filepath.Dir(dir), "sshd_config") +
				" above its Include line and in the files of " + dir + " sorted before " + filepath.Base(inv.app.Paths.SSHDDropIn)}
		}
	}
	return nil
}

// userForwards reports whether user's tier (from the account's local
// groups) may forward X11 and TCP ports through sshd (console forwarding
// tiers); an account whose groups cannot be read may not.
func (inv *invocation) userForwards(pol *console.Policy, user string) bool {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "id", Args: []string{"-nG", "--", user}})
	if err != nil || res.Code != 0 {
		return false
	}
	return pol.Forwarding(sudoTier(strings.Fields(string(res.Stdout))))
}

// consoleInstall is 'console install': consoleProvision, then the check.
func (inv *invocation) consoleInstall(args []string) error {
	if _, err := inv.consoleParse("install", args); err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	inv.app.Out.InfoE("Console pieces on this server:")
	if err := inv.consoleProvision(pol); err != nil {
		return err
	}
	if err := inv.engineerSSHDProvision(pol); err != nil {
		return exit(1)
	}
	return inv.consoleCheckReport(pol)
}

// consoleRemove is 'console remove': consoleDeprovision.
func (inv *invocation) consoleRemove(args []string) error {
	if _, err := inv.consoleParse("remove", args); err != nil {
		return err
	}
	return inv.consoleDeprovision()
}

// consoleCheck is 'console check': whether sshd applies the console's
// settings to its users; exit 1 with the red warning when not.
func (inv *invocation) consoleCheck(args []string) error {
	if _, err := inv.consoleParse("check", args); err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	err = inv.consoleCheckReport(pol)
	if eng := inv.engineerSudoReport(); err == nil {
		err = eng
	}
	if eng := inv.engineerLoginReport(pol); err == nil {
		err = eng
	}
	return err
}

// groupMembers are the members of a local group here ('getent group'); nil
// when the group is missing or empty.
func (inv *invocation) groupMembers(group string) []string {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"group", group}})
	if err != nil || res.Code != 0 {
		return nil
	}
	var members []string
	if f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":"); len(f) >= 4 {
		for _, m := range strings.Split(f[3], ",") {
			if m != "" {
				members = append(members, m)
			}
		}
	}
	return members
}

// loginShell is the login shell of an account here ('getent passwd').
func (inv *invocation) loginShell(user string) (string, bool) {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"passwd", user}})
	if err != nil || res.Code != 0 {
		return "", false
	}
	f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":")
	if len(f) != 7 {
		return "", false
	}
	return f[6], true
}

// accountUID is the UID of an account here ('getent passwd'; false when the
// account is not there).
func (inv *invocation) accountUID(user string) (int, bool) {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"passwd", user}})
	if err != nil || res.Code != 0 {
		return 0, false
	}
	line, _, _ := strings.Cut(strings.TrimSpace(string(res.Stdout)), "\n")
	f := strings.Split(line, ":")
	if len(f) < 3 {
		return 0, false
	}
	uid, err := strconv.Atoi(f[2])
	return uid, err == nil
}

// engineerLoginReport is the check of 'console check' that an engineer
// here has the console or no login (D18): every member of tac-engineer has
// the console or a nologin shell, sshd closes forwarding for the first of
// them, and no tacctl user keeps tac-superuser once its tier is lower than
// superuser (S2: a group's tier or priv-lvl lowered, a user moved or
// disabled, not yet synced). Problems are the red warning and exit 1.
func (inv *invocation) engineerLoginReport(pol *console.Policy) error {
	inv.echo("Engineer login check:")
	members := inv.groupMembers(tier.EngineerGroup)
	server := "<name of this server>"
	var problems []string
	// The engineer tier's own sshd drop-in, whatever the console's state.
	switch data, err := os.ReadFile(inv.app.Paths.SSHDEngineerDropIn); {
	case err != nil:
		inv.echo("  sshd drop-in " + inv.app.Paths.SSHDEngineerDropIn + ": missing")
		problems = append(problems, "sshd's drop-in for the engineer tier "+inv.app.Paths.SSHDEngineerDropIn+" is missing (tacctl host sync of this server, or tacctl console install, writes it)")
	case string(data) != console.EngineerDropIn(pol.AgentForwarding()):
		inv.echo("  sshd drop-in " + inv.app.Paths.SSHDEngineerDropIn + ": present, differs from this release's")
		problems = append(problems, "sshd's drop-in for the engineer tier "+inv.app.Paths.SSHDEngineerDropIn+" differs from this release's")
	default:
		inv.echo("  sshd drop-in " + inv.app.Paths.SSHDEngineerDropIn + ": present, current")
	}
	// The engineer's file must be read before the console's (first value
	// wins), and the file it replaced must be gone.
	p := inv.app.Paths
	if filepath.Dir(p.SSHDEngineerDropIn) == filepath.Dir(p.SSHDDropIn) && filepath.Base(p.SSHDEngineerDropIn) >= filepath.Base(p.SSHDDropIn) {
		inv.echo("  sshd reads " + filepath.Base(p.SSHDDropIn) + " before " + filepath.Base(p.SSHDEngineerDropIn) + ": the console's forwarding tiers win over the engineer lockdown")
		problems = append(problems, "sshd's drop-in for the engineer tier ("+filepath.Base(p.SSHDEngineerDropIn)+") sorts after the console's ("+filepath.Base(p.SSHDDropIn)+"); sshd takes the first value, so a forwarding tier of the console beats the engineer lockdown")
	}
	if _, err := os.Stat(p.SSHDEngineerDropInOld); err == nil {
		inv.echo("  sshd drop-in " + p.SSHDEngineerDropInOld + ": present (the old name)")
		problems = append(problems, "the engineer tier's old sshd drop-in "+p.SSHDEngineerDropInOld+" is still there (tacctl console install, or host sync of this server, replaces it with "+p.SSHDEngineerDropIn+")")
	}
	engineers := append([]string(nil), members...)
	if e, ok, _ := inv.localHost(); ok {
		server = e.Name
		if m, err := inv.model(); err == nil {
			for _, r := range m.LinuxUsers(e.Scope) {
				name, lvl, _ := strings.Cut(r, "|")
				if inv.userTier(name, lvl) == tier.Engineer && !slices.Contains(engineers, name) {
					engineers = append(engineers, name)
				}
			}
		}
	}
	// Every member of tac-superuser that is a tacctl account whose tier is
	// not superuser (a group's tier or priv-lvl lowered, a user moved,
	// disabled or removed since the last sync) still holds root here: a
	// problem. A member that is no tacctl account (a local administrator
	// added by hand; its UID is outside tacctl's range) is only mentioned:
	// it is not tacctl's to flag, though a sync of this server takes it out
	// of tacctl's groups. root is neither.
	if m, err := inv.model(); err == nil {
		rng, _ := inv.configuredUIDRange()
		for _, u := range inv.groupMembers(tier.SuperuserGroup) {
			if u == "root" {
				continue
			}
			if m.User(u) == nil {
				if uid, ok := inv.accountUID(u); !ok || !rng.Has(uid) {
					inv.echo("  " + u + ": in " + tier.SuperuserGroup + ", not a tacctl account (a local administrator?); tacctl host sync " + server + " takes it out of tacctl's groups")
					continue
				}
				inv.echo("  " + u + ": still in " + tier.SuperuserGroup)
				problems = append(problems, u+" is no tacctl user (removed?) but is still in "+tier.SuperuserGroup+" here (stale membership; run: tacctl host sync "+server+")")
				continue
			}
			if t := inv.userTier(u, m.UserPrivLvl(u)); t != tier.Superuser {
				inv.echo("  " + u + ": still in " + tier.SuperuserGroup)
				who := u + " is an engineer"
				if t != tier.Engineer {
					who = u + " is " + string(t) + ", not a superuser,"
				}
				problems = append(problems, who+" but is still in "+tier.SuperuserGroup+" here (stale membership; run: tacctl host sync "+server+")")
			}
		}
	}
	probe := ""
	for _, m := range members {
		shell, ok := inv.loginShell(m)
		switch {
		case !ok:
			inv.echo("  login shell of " + m + ": could not be checked")
			problems = append(problems, "the login shell of "+m+" could not be read")
		case shell == inv.app.Paths.ConsoleCommand || filepath.Base(shell) == "nologin":
			inv.echo("  login shell of " + m + ": " + shell)
			if probe == "" {
				probe = m
			}
		default:
			inv.echo("  login shell of " + m + ": " + shell)
			problems = append(problems, m+" ("+tier.EngineerGroup+") has the login shell "+shell+", but an engineer has the console or no login: tacctl host sync "+server)
		}
	}
	if probe != "" {
		if st, err := console.SSHDCheck(inv.ctx, inv.app.Runner, probe); err != nil {
			inv.echo("  sshd for " + probe + ": could not be checked: " + strings.Join(msgs(err), " "))
			problems = append(problems, "sshd could not be asked what it applies to "+probe)
		} else {
			inv.echo("  sshd for " + probe + ": allowtcpforwarding " + st.TCPForwarding + ", allowagentforwarding " + st.AgentForwarding + sshdGatewayPorts(st))
			problems = append(problems, st.ForwardingProblems(pol.AgentForwarding(), false, false)...)
		}
	}
	if len(engineers) == 0 {
		inv.echo("  " + tier.EngineerGroup + ": no engineer here")
	}
	if len(problems) == 0 {
		inv.app.Out.InfoE("Engineers here have the console or no login, and no one below the superuser tier keeps " + tier.SuperuserGroup + ".")
		return nil
	}
	inv.echoE(ui.Red + "WARNING: an engineer can do more on this server than the console allows: " + strings.Join(problems, "; ") + "." + ui.NC)
	return exit(1)
}

// engineerSudoReport is the check of 'console check' that no member of
// tac-engineer can run anything but tacctl through sudo on this server
// (D18: engineers never get root here; the client script writes no
// tac-engineer line on the tacctl server, and the tiers sudoers give them
// tacctl's verbs only). sudo itself is asked ('sudo -n -l -U <member>', as
// root), so a rule anywhere in sudoers counts. Problems are the red
// warning and exit 1.
func (inv *invocation) engineerSudoReport() error {
	r := inv.app.Runner
	inv.echo("Engineer sudo check:")
	res, err := r.Run(inv.ctx, execx.Cmd{Name: "getent", Args: []string{"group", tier.EngineerGroup}})
	var members []string
	if err == nil && res.Code == 0 {
		if f := strings.Split(strings.TrimSpace(string(res.Stdout)), ":"); len(f) >= 4 {
			for _, m := range strings.Split(f[3], ",") {
				if m != "" {
					members = append(members, m)
				}
			}
		}
	}
	if len(members) == 0 {
		inv.echo("  " + tier.EngineerGroup + ": no member here")
		return nil
	}
	var problems []string
	for _, m := range members {
		// sudo words and wraps its answer by locale and terminal width: ask
		// for the C locale and a line no command list wraps in.
		res, err := r.Run(inv.ctx, execx.Cmd{Name: "sudo", Args: []string{"-n", "-l", "-U", m},
			Env: append(inv.app.Env.Environ(), "LC_ALL=C", "LANGUAGE=C", "COLUMNS=4096")})
		out := string(res.Stdout)
		switch other, ok := sudoBeyondTacctl(out); {
		case err != nil || !ok:
			inv.echo("  sudo for " + m + ": could not be checked")
			problems = append(problems, "sudo could not be asked what "+m+" may run")
		case len(other) > 0:
			inv.echo("  sudo for " + m + ": " + strings.Join(other, ", "))
			problems = append(problems, m+" ("+tier.EngineerGroup+") can run "+strings.Join(other, ", ")+" through sudo")
		default:
			inv.echo("  sudo for " + m + ": tacctl only")
		}
	}
	if len(problems) == 0 {
		inv.app.Out.InfoE("No member of " + tier.EngineerGroup + " can run anything but tacctl through sudo here.")
		return nil
	}
	inv.echoE(ui.Red + "WARNING: an engineer can run more than tacctl as root on this server: " + strings.Join(problems, "; ") + "." + ui.NC)
	inv.echoE(ui.Red + "Remove the sudoers rule that grants it (sudo -l -U <user> lists the rules), or move the user out of the engineer tier." + ui.NC)
	return exit(1)
}

// reSudoTags are the tags before a command list in 'sudo -l' output
// (NOPASSWD:, SETENV:, ...).
var reSudoTags = regexp.MustCompile(`^(?:[A-Z_]+:\s*)+`)

// sudoBeyondTacctl reads 'sudo -l -U <user>' output: the commands it lists
// that are not tacctl (tier.Binary, with any arguments), and whether the
// output said what the user may run at all ("is not allowed to run sudo":
// nothing; "may run the following commands": the list).
func sudoBeyondTacctl(out string) (other []string, ok bool) {
	if strings.Contains(out, "is not allowed to run sudo") {
		return nil, true
	}
	_, list, found := strings.Cut(out, "may run the following commands")
	if !found {
		return nil, false
	}
	_, list, _ = strings.Cut(list, "\n")
	// sudo wraps a long rule onto lines indented deeper than the rule's
	// own: they are its continuation.
	var rules []string
	base := -1
	for _, raw := range strings.Split(list, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if base < 0 {
			base = indent
		}
		if indent > base && len(rules) > 0 {
			rules[len(rules)-1] += " " + l
			continue
		}
		rules = append(rules, l)
	}
	for _, l := range rules {
		if strings.HasPrefix(l, "(") {
			if i := strings.IndexByte(l, ')'); i >= 0 {
				l = strings.TrimSpace(l[i+1:])
			}
		}
		for _, c := range strings.Split(l, ",") {
			c = strings.TrimSpace(reSudoTags.ReplaceAllString(strings.TrimSpace(c), ""))
			if c == "" {
				continue
			}
			if w := strings.Fields(c); w[0] != tier.Binary {
				other = append(other, c)
			}
		}
	}
	return other, true
}

// consoleCheckReport prints the check for the first account that has the
// console as its shell; problems are the red warning and exit 1.
func (inv *invocation) consoleCheckReport(pol *console.Policy) error {
	users, err := inv.consoleShellAccounts()
	if err != nil {
		inv.app.Out.WarnE(err.Error())
	}
	inv.echo("Console sshd check:")
	problems := inv.consoleCheckFiles(pol)
	probe := inv.consoleProbeUsers(pol, users)
	if len(probe) == 0 {
		problems = append(problems, inv.consoleCheckUser(pol, "")...)
	}
	for _, u := range probe {
		problems = append(problems, inv.consoleCheckUser(pol, u)...)
	}
	problems = append(problems, inv.consoleFirstValueHint(pol, probe, problems)...)
	if len(problems) == 0 {
		inv.app.Out.InfoE("The console's sshd settings are in effect.")
		return nil
	}
	inv.echoE(ui.Red + "WARNING: a console user can do more over ssh than the console allows (forward ports past the registry, run programs or sftp, log in by key): " +
		strings.Join(problems, "; ") + "." + ui.NC)
	inv.echoE(ui.Red + "Put the drop-in in place: tacctl console install" + ui.NC)
	return exit(1)
}

// consoleForLocal prepares the script of the tacctl server's own accounts
// ('host enroll --local' and the sync of that host): every user's login
// shell goes into the script (req.ConsoleShell, from console.yaml), and,
// when any user of the scope gets the console, the server's pieces are put
// in place first (consoleProvision). Without the console's symlink nobody
// gets the console (it would be a shell that does not exist) and the
// command says so; a drop-in sshd refuses is reported and the accounts are
// synced anyway (the console still runs nothing but tacctl lines; the
// check after the script says what sshd allows). It returns whether the
// check is due after the script.
func (inv *invocation) consoleForLocal(req *hosts.ScriptRequest) (bool, error) {
	a := inv.app
	pol, err := inv.consolePolicy()
	if err != nil {
		return false, err
	}
	// The engineer tier's sshd lockdown does not wait for the console: it is
	// written at every sync of this server (a failure is a warning; the
	// accounts are synced anyway and 'console check' says what sshd allows).
	if inv.engineerSSHDProvision(pol) != nil {
		a.Out.WarnE("The accounts are synced anyway; until sshd's drop-in for the engineer tier is in place an engineer can still forward ports. Fix it, then: tacctl console install")
	}
	// Without the console an account gets console.ShellWithout: bash, but
	// nologin for an engineer (the console or no login) and for a tier none.
	withoutConsole := func(_, t string) string { return console.ShellWithout(tier.Tier(t)) }
	anyConsole, engineers := false, false
	for _, r := range req.Rows {
		name, lvl, _ := strings.Cut(r, "|")
		t := inv.userTier(name, lvl)
		engineers = engineers || t == tier.Engineer
		if pol.Decide(name, t).Console {
			anyConsole = true
		}
	}
	if !anyConsole {
		req.ConsoleShell = withoutConsole
		return false, nil
	}
	if target, err := os.Readlink(a.Paths.ConsoleCommand); err != nil || target == "" {
		msg := a.Paths.ConsoleCommand + " is missing, so no account gets the login console now (all keep or get " + console.SystemLoginShell
		if engineers {
			msg += ", except engineers, who have the console or no login and get " + console.NoLoginShell
		}
		a.Out.WarnE(msg + "). Run 'tacctl upgrade', then sync this host again.")
		req.ConsoleShell = withoutConsole
		return false, nil
	}
	req.ConsoleShell = func(name, t string) string { return pol.Shell(name, tier.Tier(t)) }
	a.Out.InfoE("Console pieces on this server:")
	if err := inv.consoleProvision(pol); err != nil {
		a.Out.WarnE("The accounts are synced anyway; until sshd's drop-in is in place a console user can still forward ports or use sftp. Fix it, then: tacctl console install")
	}
	return true, nil
}

// consoleAfterLocal is the check after the server's own script ran: the
// red warning when sshd does not apply the console's settings. It never
// fails the command.
func (inv *invocation) consoleAfterLocal() {
	pol, err := inv.consolePolicy()
	if err != nil {
		return
	}
	_ = inv.consoleCheckReport(pol)
}
