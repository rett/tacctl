package cli

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// consoleShow is 'console show': the effective table, the settings and the
// state of the server's pieces. Operator tier and up.
func (inv *invocation) consoleShow(args []string) error {
	if _, err := inv.consoleParse("show", args); err != nil {
		return err
	}
	pol, err := inv.consolePolicy()
	if err != nil {
		return err
	}
	f := pol.File
	inv.echo("")
	inv.echoE(ui.Bold + "Login console" + ui.NC)
	inv.echo("--------------------------------------------")
	inv.echo("Tiers (the console is the login shell of their users on this server):")
	for _, t := range console.Tiers {
		inv.echo("  " + string(t) + ": " + consoleTierState(f, t))
	}
	inv.echo("")
	inv.echo("Settings:")
	inv.echo("  idle-timeout: " + idleText(f.Idle))
	inv.echo("  agent-forwarding: " + map[bool]string{true: "enabled", false: "disabled"}[f.AgentForwarding])
	inv.echo("  ssh-escape: " + map[bool]string{true: "enabled", false: "disabled"}[f.SSHEscape])
	inv.echo("  forwarding tiers: " + tierCSV(f.ForwardingTiers) + " (X11 and TCP ports)")
	inv.echo("  forwarding gateway-ports: " + map[bool]string{true: "enabled", false: "disabled"}[f.GatewayPorts] + " (forwarded ports on other addresses than loopback)")
	inv.echo("  system-shell tiers: " + tierCSV(f.SystemShellTiers))
	inv.echo("  system-shell path: " + f.SystemShell)
	inv.echo("  space-completion: " + spaceWord(f.SpaceCompletion) + " (a typed space completes a fixed word at the console's prompt)")
	inv.echo("  password-cache tiers: " + tierCSV(f.PasswordCacheTiers) + " (shell and console sessions that keep your network password in memory)")
	inv.echo("  password-cache idle: " + strconv.Itoa(f.PasswordCacheIdle) + " min")
	inv.echo("  password-cache max: " + strconv.Itoa(f.PasswordCacheMax) + " h")
	inv.echo("  list-max: " + strconv.Itoa(f.ListMax) + " (completions listed without asking; set in " + inv.app.Paths.ConsoleFile + ")")
	inv.echo("")

	consoleUsers, listed, err := inv.consoleUsersTable(pol)
	if err != nil {
		return err
	}
	if listed {
		inv.echo("")
	}
	return inv.consoleServerSection(pol, consoleUsers)
}

func idleText(min int) string {
	if min == 0 {
		return "never"
	}
	return strconv.Itoa(min) + " min"
}

// consoleUsersTable prints the users of the local host's scope with their
// effective shell, and the overrides that name nobody there. It returns the
// users who have the console. listed is false when the server is not
// enrolled (a line says so).
func (inv *invocation) consoleUsersTable(pol *console.Policy) (users []string, listed bool, err error) {
	e, ok, err := inv.localHost()
	if err != nil {
		return nil, false, err
	}
	if !ok {
		inv.echo("this server is not enrolled (tacctl host enroll --local): no tacctl user has an account here")
		return nil, false, nil
	}
	m, err := inv.model()
	if err != nil {
		return nil, false, err
	}
	title := "Users of " + e.Name + " (scope " + e.Scope + ")"
	tb := ui.NewTable(title, ui.Left("USERNAME"), ui.Left("TIER"), ui.Left("SHELL"), ui.Left("WHY"))
	seen := map[string]bool{}
	rows := m.LinuxUsers(e.Scope)
	for _, r := range rows {
		name, lvl, _ := strings.Cut(r, "|")
		tr := inv.userTier(name, lvl)
		d := pol.Decide(name, tr)
		seen[name] = true
		shell := "bash"
		if d.Console {
			shell = "console"
			users = append(users, name)
		}
		why := d.Why
		if _, over := pol.File.Users[name]; over && tr == tier.Engineer {
			why += "; the stored override is ignored"
		}
		tb.Add(name, string(tr), shell, why)
	}
	if tb.Len() == 0 {
		inv.echoE(ui.Bold + title + ui.NC)
		inv.echo(ui.Rule(title))
		inv.echo("  none")
	} else {
		inv.write(tb.String())
	}
	var stray []string
	for _, u := range pol.File.UserNames() {
		if !seen[u] {
			stray = append(stray, u+": "+onOff(pol.File.Users[u]))
		}
	}
	if len(stray) > 0 {
		inv.echo("Overrides of users that have no account here: " + strings.Join(stray, ", "))
	}
	return users, true, nil
}

// consoleServerSection prints the state of the server's pieces: the
// symlink, the /etc/shells line, sshd's drop-in and what sshd would apply to
// a console user, with the loud warning when forwarding is not closed.
func (inv *invocation) consoleServerSection(pol *console.Policy, consoleUsers []string) error {
	p := inv.app.Paths
	pc := console.Inspect(p)
	inv.echo("Server:")
	switch {
	case pc.Link != "":
		inv.echo("  " + pc.Command + ": symlink to " + pc.Link)
	case pc.Exists:
		inv.echo("  " + pc.Command + ": present, not a symlink")
	default:
		inv.echo("  " + pc.Command + ": missing")
	}
	inv.echo("  " + p.ShellsFile + ": " + map[bool]string{true: "lists the console", false: "does not list the console"}[pc.Shells])
	inv.echo("  sshd drop-in " + p.SSHDDropIn + ": " + map[bool]string{true: "present", false: "missing"}[pc.DropIn])
	if len(consoleUsers) == 0 {
		inv.echo("  sshd: not checked (no user has the console)")
		inv.echo("")
		return nil
	}
	var problems []string
	if !pc.DropIn {
		problems = append(problems, "sshd's drop-in "+p.SSHDDropIn+" is missing")
	}
	probe := inv.consoleProbeUsers(pol, consoleUsers)
	for _, u := range probe {
		st, err := console.SSHDCheck(inv.ctx, inv.app.Runner, u)
		if err != nil {
			inv.echo("  sshd for " + u + ": could not be checked: " + strings.Join(msgs(err), " "))
			continue
		}
		inv.echo("  sshd for " + u + ": allowtcpforwarding " + st.TCPForwarding + ", allowagentforwarding " + st.AgentForwarding +
			", forcecommand " + dash(st.ForceCommand) + ", pubkeyauthentication " + dash(st.PubkeyAuth) + sshdGatewayPorts(st))
		problems = append(problems, st.Problems(pol.AgentForwarding(), inv.userForwards(pol, u), pol.GatewayPorts(), inv.app.Paths.ConsoleCommand)...)
	}
	problems = append(problems, inv.consoleFirstValueHint(pol, probe, problems)...)
	if len(problems) > 0 {
		inv.echoE(ui.Red + "WARNING: a console user can do more over ssh than the console allows (forward ports past the registry, run programs or sftp, log in by key): " +
			strings.Join(problems, "; ") + "." + ui.NC)
		if e, ok, _ := inv.localHost(); ok {
			inv.echoE(ui.Red + "Apply the console's sshd settings: tacctl host sync " + e.Name + ui.NC)
		}
	}
	inv.echo("")
	return nil
}
