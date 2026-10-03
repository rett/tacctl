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

// App is one invocation.
type App struct {
	Args   []string // the arguments after the program name, unchanged
	Env    paths.Env
	Paths  paths.Paths
	Runner execx.Runner
	Stdin  io.Reader
	Out    ui.Output
	Exe    string // the running executable, symlinks resolved ("" if unknown)
	EUID   int
}

// New builds an App; paths are resolved from env and exe.
func New(args []string, env paths.Env, exe string, euid int, stdio Stdio, runner execx.Runner) *App {
	return &App{
		Args:   append([]string(nil), args...),
		Env:    env,
		Paths:  paths.Resolve(env, exe, nil),
		Runner: runner,
		Stdin:  stdio.Stdin,
		Out:    ui.Output{Stdout: stdio.Stdout, Stderr: stdio.Stderr},
		Exe:    exe,
		EUID:   euid,
	}
}
