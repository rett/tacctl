package cli

// The login console (docs/plans/operator-console-wp-console.md 5.2): the
// binary started as 'tacctl-console' (the symlink paths.ConsoleCommand,
// a tacctl user's login shell on the tacctl server). It is 'tacctl shell'
// with a '<host>> ' prompt and a banner, on a scrubbed environment, with
// the idle time and the list threshold of console.yaml, every line run as
//
//	sudo [-n] TACCTL_CONSOLE=<session> <exe> <words>
//
// and one word of its own, system-shell. sshd starts it with '-c
// <command>' for a remote command, scp, sftp and rsync: one tacctl line
// passes (console.Guard), everything else is refused with exit 126.
// Sessions, refusals and system shells are logged (syslog tag
// tacctl-console).

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// consoleMain is Main for the console: sshd's ForceCommand is resolved
// (console.Forced), the environment is scrubbed (console.Scrub) and, when
// that changes it, the console executes itself again with the scrubbed one,
// so that neither it nor anything it starts (sudo, logger, id, the system
// shell) ever sees the login environment.
func consoleMain(ctx context.Context, argv, environ []string, stdio app.Stdio, build BuildInfo, exe string, euid int, runner execx.Runner) int {
	env := paths.NewEnv(environ)
	a := app.New(nil, env, exe, euid, stdio, runner)
	argv = console.Forced(argv, environ, a.Paths.ConsoleCommand)
	clean := console.Scrub(environ, a.Paths.ConsoleCommand, app.ConsoleTestEnv(env))
	if !slices.Equal(clean, environ) {
		if exe == "" || !strings.HasPrefix(exe, "/") {
			_, _ = io.WriteString(a.Out.Stderr, "tacctl-console: cannot locate the tacctl executable\n")
			return console.RefusedStatus
		}
		err := a.Runner.Exec(exe, argv, clean)
		if err != nil {
			_, _ = io.WriteString(a.Out.Stderr, "tacctl-console: cannot start: "+err.Error()+"\n")
			return console.RefusedStatus
		}
		return 0
	}
	var args []string
	if len(argv) > 1 {
		args = argv[1:]
	}
	return exitCode(RunConsole(ctx, a, build, args), a.Out)
}

// RunConsole runs the console with its arguments (none, or '-c <line>') in
// a's environment, which is the console's (consoleMain scrubbed it).
func RunConsole(ctx context.Context, a *app.App, build BuildInfo, args []string) error {
	if a.Version == "" {
		a.Version = build.Version
	}
	inv := &invocation{ctx: ctx, app: a, build: build}
	return inv.runConsoleSession(args)
}

// consolePolicyHook, when set, adjusts the policy a session got (the Go
// pty tests: an idle time in seconds); nil in tacctl.
var consolePolicyHook func(*console.Remote)

// consoleSession is the state of one console session.
type consoleSession struct {
	inv  *invocation
	sess console.Session
	pol  console.Remote
	tier tier.Tier
}

// runConsoleSession is one session of the console.
func (inv *invocation) runConsoleSession(args []string) error {
	a := inv.app
	line, cmdMode := "", false
	switch {
	case len(args) == 0:
	case len(args) == 2 && args[0] == "-c":
		line, cmdMode = args[1], true
	default:
		_, _ = io.WriteString(a.Out.Stderr, console.NoOptionsText+"\n")
		return exit(console.RefusedStatus)
	}
	exe := a.Exe
	if exe == "" || !strings.HasPrefix(exe, "/") {
		return &ExitError{Code: 1, Err: errors.New("cannot locate the tacctl executable to run commands with")}
	}
	id, err := console.NewSessionID(a.Knobs.Rand())
	if err != nil {
		return &ExitError{Code: 1, Err: err}
	}
	user := a.Env.Get("USER")
	if user == "" {
		user = a.Env.Get("LOGNAME")
	}
	f, isFile := a.Stdin.(*os.File)
	mode := console.ModeBatch
	switch {
	case cmdMode:
		mode = console.ModeCommand
	case isFile && term.IsTerminal(int(f.Fd())):
		mode = console.ModeInteractive
	}
	cs := &consoleSession{inv: inv, sess: console.Session{
		ID: id, User: user, Mode: mode,
		From: console.ClientAddr(a.Env.Get("SSH_CLIENT")), TTY: a.Env.Get("SSH_TTY"),
	}}
	cs.log("auth.info", cs.sess.StartLine())

	if cmdMode {
		root := newRoot(inv)
		first, ok := console.Guard(line, consoleRootCommand(root))
		if !ok {
			_, _ = io.WriteString(a.Out.Stderr, console.RefusedText+"\n")
			cs.log("auth.warning", cs.sess.DenyLine(first))
			cs.log("auth.info", cs.sess.EndLine(console.ReasonCommand, 0, console.RefusedStatus))
			return exit(console.RefusedStatus)
		}
	}

	marker := console.EnvMarker + "=" + id
	cs.pol = inv.consoleRemotePolicy(exe, marker)
	if consolePolicyHook != nil {
		consolePolicyHook(&cs.pol)
	}
	groups := inv.callerGroups()
	cs.tier = sudoTier(groups)
	if cs.pol.Known {
		cs.tier = cs.pol.Tier
	}
	extra := []string{marker}
	if d := a.Env.Get("DISPLAY"); cs.pol.Forward && console.ValidDisplay(d) {
		// sshd's X11 forwarding, for 'ssh -X <device>' (the tiers sudoers
		// keeps DISPLAY for tacctl).
		extra = append(extra, "DISPLAY="+d)
	}
	r := shellRun{
		exe: exe, mode: shellBatch, listMax: cs.pol.ListMax, spaceCompletion: cs.pol.SpaceCompletion,
		extraEnv: extra, console: true, systemShell: cs.systemShell, groups: groups, view: consoleView(cs.pol),
	}
	if cs.pol.PasswordCache {
		// The policy turned the cache on for this tier (D70): the shell
		// loop starts the agent, for an interactive session only.
		r.cacheMode, r.pcIdle, r.pcMax = cacheOn, cs.pol.PCIdle, cs.pol.PCMax
	}
	if groups == nil {
		r.groups = []string{}
	}
	switch mode {
	case console.ModeCommand:
		r.mode, r.line = shellCommandMode, line
	case console.ModeInteractive:
		host := shortHostname()
		r.mode, r.tty, r.idle, r.prompt = shellInteractive, f, cs.pol.Idle, host+"> "
		inv.echo("tacctl console on " + host + " — type 'help'. Devices: device list. This session is logged.")
	}
	if r.mode != shellBatch {
		if home := a.Env.Get("HOME"); home != "" {
			r.history = shellHistoryPath(home)
		}
	}
	status, sh := inv.runShell(r)
	reason, lines := sh.End()
	cs.log("auth.info", cs.sess.EndLine(reason, lines, status))
	if status != 0 {
		return exit(status)
	}
	return nil
}

// consoleView is the view of the console's lists: the tier the policy answer
// named, or viewUnread when it did not (no answer, or one without a tier).
func consoleView(pol console.Remote) tier.Tier {
	if t, ok := pol.ViewRead(); ok {
		return t
	}
	return viewUnread
}

// consoleRemotePolicy asks the root side for the caller's console policy
// ('sudo -n TACCTL_CONSOLE=<session> <exe> _console-policy'); any failure
// gives the defaults (no system shell): every line is still gated by sudo
// and the tier gate.
func (inv *invocation) consoleRemotePolicy(exe, marker string) console.Remote {
	res, err := inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "sudo", Args: []string{"-n", marker, exe, "_console-policy"}})
	if err != nil || res.Code != 0 {
		return console.DefaultRemote()
	}
	pol, _ := console.ParseRemote(string(res.Stdout))
	return pol
}

// log writes a line of the console's own to syslog.
func (cs *consoleSession) log(priority, msg string) {
	inv := cs.inv
	_, _ = inv.app.Runner.Run(inv.ctx, execx.Cmd{Name: "logger", Args: []string{"-t", console.LogTag, "-p", priority, msg}})
}

// systemShell is the console's system-shell: the user's system shell, as
// the user, with the console's environment and SHELL=<path>, on the
// terminal, when the policy opens it to the caller's tier and the session
// is interactive.
func (cs *consoleSession) systemShell(ctx context.Context, interactive bool) int {
	a := cs.inv.app
	if !interactive {
		_, _ = io.WriteString(a.Out.Stderr, console.RefusedText+"\n")
		cs.log("auth.warning", cs.sess.DenyLine(console.SystemShellWord))
		return console.RefusedStatus
	}
	if !cs.pol.SystemShell && cs.tier == tier.Engineer {
		// No setting opens it to engineers (D18): a shell on this server
		// would reach its secrets.
		a.Out.Error(console.SystemShellWord + " is never available to the engineer tier on this server.")
		cs.log("auth.warning", cs.sess.SystemShellDenyLine(string(cs.tier)))
		return 1
	}
	if !cs.pol.SystemShell {
		a.Out.Error(console.SystemShellWord + " is not available for the " + string(cs.tier) + " tier on this console. " +
			"An administrator enables it with: tacctl console system-shell tiers " + consoleTiersWith(cs.tier))
		cs.log("auth.warning", cs.sess.SystemShellDenyLine(string(cs.tier)))
		return 1
	}
	path := cs.pol.SystemShellPath
	cs.log("auth.info", cs.sess.SystemShellStartLine(path))
	start := a.Knobs.Now()
	c := execx.Cmd{Name: path, Env: console.ShellEnv(a.Env.Environ(), path)}
	code, _, err := execx.Attached(ctx, a.Runner, c, a.Stdin, a.Out.Stdout, a.Out.Stderr)
	if err != nil {
		if code == 0 {
			code = 1
		}
		a.Out.Error("cannot start " + path + ": " + err.Error())
	}
	cs.log("auth.info", cs.sess.SystemShellEndLine(code, a.Knobs.Now().Sub(start)))
	cs.inv.echo("back in the tacctl console")
	return code
}

// consoleTiersWith is the system-shell tiers list that adds t to the
// default (superuser), for the refusal's command.
func consoleTiersWith(t tier.Tier) string {
	switch t {
	case tier.Readonly, tier.Operator:
		return "superuser," + string(t)
	}
	return "<tiers>"
}

// consoleRootCommand reports whether w is a command of root a -c line may
// start with (console.Guard): a visible one.
func consoleRootCommand(root *cobra.Command) func(string) bool {
	return func(w string) bool {
		c := child(root, w)
		return c != nil && !c.Hidden
	}
}
