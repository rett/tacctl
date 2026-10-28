// Package cli is tacctl's command line: the front door that re-executes
// under sudo, dispatches the command and maps errors to exit statuses. It is
// the only package that parses argv and prints usage.
package cli

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/app"
	// The shipped backend modules register themselves.
	_ "github.com/rett/tacctl/internal/backend/all"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// invocation is one run of the CLI.
type invocation struct {
	ctx   context.Context
	app   *app.App
	build BuildInfo
	// hooks are what a test replaces (hooks.go); nil in tacctl.
	hooks *hooks
	// registryNoted: the device registry's load notes (devreg.File.Notes)
	// were printed in this run.
	registryNoted bool
	// lockdownShown: the emergency lockdown notice was decided for this process.
	lockdownShown bool

	// shellMode: completion is for the tacctl shell's lists (live names
	// with descriptions; flags only after a '-').
	shellMode bool
	// shellColor is the console's colour setting in a shell or console
	// session ("": auto; console.ColorOn, ColorOff): '--help' written by the
	// shell follows it (help_request.go).
	shellColor string
	// shellConsole: the shell is the login console. A word that starts with
	// an underscore is one of the tool's own entry points (__complete,
	// __help, _console-policy ...), not a command: the console does not run
	// it (shellExec).
	shellConsole bool
	// view is the tier whose verbs the shell lists (shell_view.go); nil:
	// everything, outside the shell.
	view viewFn

	// The model as first read (native.go: model).
	loaded bool
	m      *model.Model
	mErr   error

	// ambiguousNoted: the red lines for groups without a tier setting were
	// printed (linux.go: warnAmbiguousGroups).
	ambiguousNoted bool

	// resolved: what each host name resolved to in this invocation
	// (host_facts.go: resolveV4).
	resolved map[string]string

	// root is the command tree of this run (runWith), ar the central audit
	// lines of the command (audit.go), callerTier the tier the gate held
	// the caller to.
	root       *cobra.Command
	ar         *auditRun
	callerTier tier.Tier

	// keyAccepted: the key 'device add' is about to pin is the one a person
	// accepted by typing the device's name ('device enroll'), not one named
	// by --host-key on the command line: deviceAddReport says so.
	keyAccepted bool

	// snmpUserSeen: whether the caller may be told an SNMPv3 user's name
	// (device_snmp_override.go: snmpUserVisible), asked once.
	snmpUserSeen *bool
}

// Main runs tacctl with argv (os.Args: argv[0] is the program) and environ
// (os.Environ()) and returns the exit status. cmd/tacctl is its only caller.
// Started as tacctl-console (the login console's symlink, argv[0] with or
// without the login shell's '-'), it is the console (console_mode.go).
func Main(argv, environ []string, stdio app.Stdio, build BuildInfo) int {
	// SIGINT, SIGTERM and SIGHUP cancel ctx, so commands clean up their
	// staging directories as bash's 'trap ... EXIT' does (docs/plans/go-rewrite.md 3.5).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	// The password cache's variable is taken out of the environment before
	// anything runs, so no program tacctl starts (id, logger, sudo, ssh ...)
	// inherits it; the one verb that uses it asks for it (takeAskpass).
	environ = captureAskpass(environ)
	// The editor's variables, as the root side of a sudo line has them, the
	// same way: the verbs that open an editor ask for them (editorVars).
	environ = captureEditor(environ, os.Geteuid())
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}
	if len(argv) > 0 && console.IsConsole(argv[0]) {
		return consoleMain(ctx, argv, environ, stdio, build.resolved(debug.ReadBuildInfo), exe, os.Geteuid(), execx.Real{})
	}
	var args []string
	if len(argv) > 1 {
		args = argv[1:]
	}
	// ssh runs SSH_ASKPASS with the prompt as its only argument (askpass_cmd.go).
	args = askpassHelperArgs(environ, args)
	a := app.New(args, paths.NewEnv(environ), exe, os.Geteuid(), stdio, execx.Real{})
	code := exitCode(Run(ctx, a, build.resolved(debug.ReadBuildInfo)), a.Out)
	// What the colour sink still holds (a sequence cut short) goes out.
	_ = a.Close()
	return code
}

// Run dispatches a.Args: the sudo re-exec of bin/tacctl.sh first, then the
// command. It returns the command's error for Main to map to a status.
func Run(ctx context.Context, a *app.App, build BuildInfo) error {
	return runWith(ctx, a, build, nil)
}

// runWith is Run with the hooks a test replaces (nil: the real ones).
func runWith(ctx context.Context, a *app.App, build BuildInfo, hk *hooks) (err error) {
	if a.Version == "" {
		a.Version = build.Version
	}
	a.SetContext(ctx)
	inv := &invocation{ctx: ctx, app: a, build: build, hooks: hk}
	root := newRoot(inv)
	inv.root = root
	hk.builtTree(root)
	// '<command> -h|--help': the command's help, as the user, before sudo.
	if words, ok := helpRequest(root, a.Args); ok {
		inv.helpList(root, words)
		return nil
	}
	if needsSudo(a) {
		// A word that is no command is answered here: sudo would ask for
		// the password first to tell the person the same.
		if len(a.Args) > 0 && notACommand(root, a.Args[0]) {
			return inv.unknownCommand(root, a.Args[0])
		}
		return reexec(a)
	}
	if isComplete(a.Args) {
		return complete(ctx, a, root)
	}
	return inv.dispatch(func() error {
		cmd, rest := resolve(root, a.Args)
		return cmd.RunE(cmd, rest)
	})
}

// dispatch runs the command and writes the end line of its central audit
// lines (audit.go) where its exit status is decided, also when it panics.
func (inv *invocation) dispatch(run func() error) (err error) {
	defer inv.auditFinish(&err)
	return run()
}
