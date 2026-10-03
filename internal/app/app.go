// Package app holds what one tacctl invocation works with: the environment,
// the resolved paths, the program runner and the output. It is built once in
// cli.Main and handed to every command.
package app

import (
	"io"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
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
// command that is delegated to bash, or never needs one, never builds it.
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

	svc services
}

// New builds an App; paths are resolved from env and exe, the knobs read
// from env.
func New(args []string, env paths.Env, exe string, euid int, stdio Stdio, runner execx.Runner) *App {
	k, kerr := LoadKnobs(env)
	return &App{
		Args:     append([]string(nil), args...),
		Env:      env,
		Paths:    paths.Resolve(env, exe, nil),
		Runner:   runner,
		Stdin:    stdio.Stdin,
		Out:      ui.Output{Stdout: stdio.Stdout, Stderr: stdio.Stderr},
		Exe:      exe,
		EUID:     euid,
		Knobs:    k,
		KnobsErr: kerr,
	}
}
