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

	"github.com/rett/tacctl/internal/app"
	// The shipped backend modules register themselves.
	_ "github.com/rett/tacctl/internal/backend/all"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
)

// invocation is one run of the CLI.
type invocation struct {
	ctx   context.Context
	app   *app.App
	build BuildInfo

	// shellMode: completion is for the tacctl shell's lists (live names
	// with descriptions; flags only after a '-').
	shellMode bool

	// The model as first read (native.go: model).
	loaded bool
	m      *model.Model
	mErr   error
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
	a := app.New(args, paths.NewEnv(environ), exe, os.Geteuid(), stdio, execx.Real{})
	return exitCode(Run(ctx, a, build.resolved(debug.ReadBuildInfo)), a.Out)
}

// Run dispatches a.Args: the sudo re-exec of bin/tacctl.sh first, then the
// command. It returns the command's error for Main to map to a status.
func Run(ctx context.Context, a *app.App, build BuildInfo) error {
	if needsSudo(a) {
		return reexec(a)
	}
	if a.Version == "" {
		a.Version = build.Version
	}
	inv := &invocation{ctx: ctx, app: a, build: build}
	root := newRoot(inv)
	if isComplete(a.Args) {
		return complete(ctx, a, root)
	}
	cmd, rest := resolve(root, a.Args)
	return cmd.RunE(cmd, rest)
}
