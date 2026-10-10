// Package execx is the only way tacctl runs another program. Every command
// is resolved through PATH at call time (exec.LookPath), so the PATH stubs
// of the bats suite (tests/helpers/mocks.bash) shadow real binaries exactly
// as they do for the bash implementation. Go tests use the scripted fake in
// internal/execx/fake.
package execx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
)

// Cmd describes one program run.
type Cmd struct {
	Name  string    // program; looked up in PATH unless it contains a slash
	Args  []string  // arguments, without the program name
	Stdin io.Reader // nil: no input (the null device)
	// Env is the complete environment of the child; nil inherits tacctl's.
	Env []string
	Dir string // working directory; "" is tacctl's
	// AsUser runs the program as that user through
	// 'sudo -u <user> -H [env <UserEnv>...] <name> <args>', as the bash
	// implementation runs ssh and podman for the invoking user
	// (lib/linux_hosts.sh _host_ssh, _linux_podman).
	AsUser  string
	UserEnv []string // KEY=value assignments passed through env(1) with AsUser
	// Credential, when set, starts the program as that user and groups
	// (setgroups, setgid and setuid in the child before exec, so no sudo
	// and nothing of the program's environment or arguments reaches its
	// log). It takes a process with the right to.
	Credential *syscall.Credential
	// Stdout and Stderr, when set, receive the output as it is produced (a
	// terminal, a live log); Result then holds only what was not streamed.
	Stdout io.Writer
	Stderr io.Writer
}

// Argv is the program and arguments actually run, AsUser applied.
func (c Cmd) Argv() []string {
	if c.AsUser == "" {
		return append([]string{c.Name}, c.Args...)
	}
	argv := []string{"sudo", "-u", c.AsUser, "-H"}
	if len(c.UserEnv) > 0 {
		argv = append(argv, "env")
		argv = append(argv, c.UserEnv...)
	}
	argv = append(argv, c.Name)
	return append(argv, c.Args...)
}

// Result is how a program ended.
type Result struct {
	Stdout []byte
	Stderr []byte
	// Code is the exit status; a program killed by a signal has 128+signal,
	// as bash's $? reports it.
	Code int
}

// Process is a started program.
type Process interface {
	// Wait waits for the program to end. A non-zero exit is a Result, not
	// an error.
	Wait() (Result, error)
	// Signal sends sig to the program.
	Signal(sig os.Signal) error
	// Pid is the program's process id.
	Pid() int
}

// Runner runs programs. A non-zero exit status is reported in Result.Code
// with a nil error; the error is for a program that could not be started
// (not found, not executable) or a cancelled context.
type Runner interface {
	Run(ctx context.Context, c Cmd) (Result, error)
	Start(ctx context.Context, c Cmd) (Process, error)
	LookPath(name string) (string, error)
	// Exec replaces tacctl with path (execve(2)): argv[0] is the name the
	// program sees, env its whole environment. It returns only on failure.
	Exec(path string, argv []string, env []string) error
}

// Real runs programs on the host.
type Real struct{}

var _ Runner = Real{}

// LookPath resolves name through PATH (exec.LookPath).
func (Real) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

// Run runs c to completion.
func (r Real) Run(ctx context.Context, c Cmd) (Result, error) {
	p, err := r.Start(ctx, c)
	if err != nil {
		// The shell's statuses: 127 not found, 126 found but not runnable.
		code := 126
		if errors.Is(err, exec.ErrNotFound) {
			code = 127
		}
		return Result{Code: code}, err
	}
	return p.Wait()
}

// Start starts c and returns at once.
func (Real) Start(ctx context.Context, c Cmd) (Process, error) {
	argv := c.Argv()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdin = c.Stdin
	cmd.Env = c.Env
	cmd.Dir = c.Dir
	if c.Credential != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: c.Credential}
	}
	p := &realProcess{ctx: ctx, cmd: cmd}
	cmd.Stdout = &p.stdout
	if c.Stdout != nil {
		cmd.Stdout = c.Stdout
	}
	cmd.Stderr = &p.stderr
	if c.Stderr != nil {
		cmd.Stderr = c.Stderr
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return p, nil
}

// Exec replaces the process image (syscall.Exec).
func (Real) Exec(path string, argv []string, env []string) error {
	return syscall.Exec(path, argv, env)
}

type realProcess struct {
	ctx            context.Context
	cmd            *exec.Cmd
	stdout, stderr bytes.Buffer
}

func (p *realProcess) Wait() (Result, error) {
	err := p.cmd.Wait()
	res := Result{Stdout: p.stdout.Bytes(), Stderr: p.stderr.Bytes()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return res, nil
	case errors.As(err, &exitErr):
		res.Code = exitCode(exitErr.ProcessState)
		// exec.CommandContext kills the child on cancellation; say so.
		return res, p.ctx.Err()
	default:
		res.Code = 1
		return res, err
	}
}

func (p *realProcess) Signal(sig os.Signal) error { return p.cmd.Process.Signal(sig) }
func (p *realProcess) Pid() int                   { return p.cmd.Process.Pid }

// exitCode maps a finished process to a shell exit status.
func exitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}
