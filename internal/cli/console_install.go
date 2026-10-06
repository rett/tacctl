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
	ch, err := d.Install(inv.ctx, console.DropIn(p.ConsoleCommand, pol.AgentForwarding(), pol.ForwardingTiers()))
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

// consoleCheckProblems are the reasons the console's sshd settings do not
// hold on this server (none: they do). user is a console user to ask sshd
// about ("": no account has the console, sshd is not asked). The lines
// describing what was found are printed as they are learnt.
func (inv *invocation) consoleCheckProblems(pol *console.Policy, user string) []string {
	return append(inv.consoleCheckFiles(pol), inv.consoleCheckUser(pol, user)...)
}

// consoleCheckFiles is the drop-in and sshd_config part of the check.
func (inv *invocation) consoleCheckFiles(pol *console.Policy) []string {
	p := inv.app.Paths
	var problems []string
	want := console.DropIn(p.ConsoleCommand, pol.AgentForwarding(), pol.ForwardingTiers())
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
		", forcecommand " + dash(st.ForceCommand) + ", pubkeyauthentication " + dash(st.PubkeyAuth))
	return append(problems, st.Problems(pol.AgentForwarding(), inv.userForwards(pol, user), p.ConsoleCommand)...)
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
		if strings.Contains(p, "forwarding is") {
			dir := filepath.Dir(inv.app.Paths.SSHDDropIn)
			return []string{"sshd keeps the first value it reads, so an X11Forwarding, AllowTcpForwarding or DisableForwarding line read before " +
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
	return inv.consoleCheckReport(pol)
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
	anyConsole := false
	for _, r := range req.Rows {
		name, lvl, _ := strings.Cut(r, "|")
		if pol.Decide(name, tier.ForPrivLvl(lvl)).Console {
			anyConsole = true
		}
	}
	if !anyConsole {
		req.ConsoleShell = func(string, string) string { return console.SystemLoginShell }
		return false, nil
	}
	if target, err := os.Readlink(a.Paths.ConsoleCommand); err != nil || target == "" {
		a.Out.WarnE(a.Paths.ConsoleCommand + " is missing, so no account gets the login console now (all keep or get " +
			console.SystemLoginShell + "). Run 'tacctl upgrade', then sync this host again.")
		req.ConsoleShell = func(string, string) string { return console.SystemLoginShell }
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
