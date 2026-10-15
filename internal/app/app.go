// Package app holds what one tacctl invocation works with: the environment,
// the resolved paths, the program runner and the output. It is built once in
// cli.Main and handed to every command.
package app

import (
	"context"
	"io"

	"golang.org/x/term"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/ui"
)

// Stdio is the invocation's standard streams.
type Stdio struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// App is one invocation. The fields are set by New; the services a native
// command works with (tacctl.yaml, the prompter, the snapshots, the backend
// set, the model) are made on first use by the methods in services.go, so a
// command that never needs one never builds it.
type App struct {
	Args   []string // the arguments after the program name, unchanged
	Env    paths.Env
	Paths  paths.Paths
	Runner execx.Runner
	Stdin  io.Reader
	Out    ui.Output
	Exe    string // the running executable, symlinks resolved ("" if unknown)
	EUID   int
	// Version is tacctl's version (what 'tacctl version' prints), recorded
	// in snapshot manifests; the CLI sets it from the build.
	Version string
	// Knobs are the test knobs (LoadKnobs); KnobsErr is why they could not
	// be read (a malformed knob variable), which a native command reports.
	Knobs    Knobs
	KnobsErr error
	// SNMP, when set, reads sysName in place of the snmp.* settings and
	// StateDir/snmp.yaml (the CLI's tests put a stub here).
	SNMP snmp.Getter
	// Resolve looks a host name up (--server of 'config cisco|juniper|wti');
	// nil is the system resolver. The CLI's tests put a stub here.
	Resolve func(ctx context.Context, name string) ([]string, error)

	// HostsTTY, when set, says whether a terminal can answer prompts of
	// the host commands (ssh, sudo, passwd); nil asks the real terminal.
	// The CLI's tests set it, as they have none.
	HostsTTY func() bool

	svc services
	// ctx is the invocation's context (SetContext).
	ctx context.Context
	// sinks are the streams New wrapped to take the colour out of them.
	sinks []io.Closer
}

// New builds an App; paths are resolved from env and exe, the knobs read
// from env (TACCTL_TEST_ROOT, in a -tags testknobs build, moves tacctl's
// fixed host locations: paths.Paths.Reroot).
//
// It also makes the colour decision of the process, once (ui.Colour, from
// env and whether each stream is a terminal): a stream that is not coloured
// is wrapped in ui.Plain, which removes the SGR sequences from everything
// written to it, so every emitter (ui.Output, the help text, the backends)
// may write them without asking. The wrapper is flushed by Close. A stream
// that is not a file (a test's buffer, an embedding caller's writer) has no
// terminal to ask: it is passed through, and only an explicit TACCTL_COLOR
// =never or NO_COLOR strips it. ui.File gives the file behind a stream, for
// the checks and the child processes that need the terminal itself.
func New(args []string, env paths.Env, exe string, euid int, stdio Stdio, runner execx.Runner) *App {
	k, kerr := LoadKnobs(env)
	a := &App{
		Args:     append([]string(nil), args...),
		Env:      env,
		Paths:    paths.Resolve(env, exe, nil).Reroot(k.Root()),
		Runner:   runner,
		Stdin:    stdio.Stdin,
		Out:      ui.Output{Stdout: stdio.Stdout, Stderr: stdio.Stderr},
		Exe:      exe,
		EUID:     euid,
		Knobs:    k,
		KnobsErr: kerr,
	}
	if r := k.Resolver(); r != nil {
		a.Resolve = r
	}
	// A stream that is not a file is taken as able to show colour (a
	// terminal, TERM capable), so that only the user's explicit choice
	// strips it.
	capable := func(name string) string {
		switch name {
		case "TERM":
			return "xterm"
		case "NO_COLOR":
			return env.Get("NO_COLOR")
		case "TACCTL_COLOR":
			return env.Get("TACCTL_COLOR")
		}
		return ""
	}
	outFile, outIsFile := ui.File(stdio.Stdout)
	errFile, errIsFile := ui.File(stdio.Stderr)
	ttyOut := outIsFile && term.IsTerminal(int(outFile.Fd()))
	ttyErr := errIsFile && term.IsTerminal(int(errFile.Fd()))
	colOut, colErr := ui.Colour(env.Get, ttyOut, ttyErr)
	if !outIsFile {
		colOut, _ = ui.Colour(capable, true, true)
	}
	if !errIsFile {
		_, colErr = ui.Colour(capable, true, true)
	}
	if !colOut && stdio.Stdout != nil {
		w := ui.Plain(stdio.Stdout)
		a.Out.Stdout = w
		a.sinks = append(a.sinks, w)
	}
	if !colErr && stdio.Stderr != nil {
		w := ui.Plain(stdio.Stderr)
		a.Out.Stderr = w
		a.sinks = append(a.sinks, w)
	}
	return a
}

// Close writes what the wrapped streams still hold (a colour sequence cut
// short is passed on as it is, not lost). The streams stay open, and Close
// may be called again; the process calls it before it exits.
func (a *App) Close() error {
	var first error
	for _, s := range a.sinks {
		if err := s.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
