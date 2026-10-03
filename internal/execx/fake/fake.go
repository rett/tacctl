// Package fake is an execx.Runner for Go tests: it runs nothing, records
// every call and answers from a script of rules. WP0.1 provides the basics;
// the scripting API grows with the packages that need it.
package fake

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/execx"
)

// ErrNotFound is what LookPath, Run and Start return for a program marked
// Missing.
var ErrNotFound = errors.New("executable file not found in $PATH")

// ExecCall is one Exec: what tacctl would have replaced itself with.
type ExecCall struct {
	Path string
	Argv []string
	Env  []string
}

type rule struct {
	match func(execx.Cmd) bool
	res   execx.Result
	err   error
}

// Runner is the fake. The zero value is ready: every program exists at
// /fake/bin/<name> and exits 0 with no output.
type Runner struct {
	mu      sync.Mutex
	rules   []rule
	missing map[string]bool
	calls   []execx.Cmd
	execs   []ExecCall
	// ExecErr, when set, is returned by Exec (as a failed execve would be).
	ExecErr error
}

var _ execx.Runner = (*Runner)(nil)

// On answers every later call whose argv (execx.Cmd.Argv, AsUser applied)
// starts with prefix with res. Rules added later take precedence.
func (f *Runner) On(prefix []string, res execx.Result) {
	p := append([]string(nil), prefix...)
	f.When(func(c execx.Cmd) bool { return hasPrefix(c.Argv(), p) }, res, nil)
}

// When answers calls for which match is true with res and err.
func (f *Runner) When(match func(execx.Cmd) bool, res execx.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule{match: match, res: res, err: err})
}

// Missing makes the named programs absent from PATH.
func (f *Runner) Missing(names ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing == nil {
		f.missing = map[string]bool{}
	}
	for _, n := range names {
		f.missing[n] = true
	}
}

// Calls returns every Run and Start so far, in order.
func (f *Runner) Calls() []execx.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]execx.Cmd(nil), f.calls...)
}

// Argvs returns the argv of every Run and Start so far, each joined by
// spaces: the form of the bats CALLS_LOG.
func (f *Runner) Argvs() []string {
	var out []string
	for _, c := range f.Calls() {
		out = append(out, strings.Join(c.Argv(), " "))
	}
	return out
}

// Execs returns every Exec so far.
func (f *Runner) Execs() []ExecCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ExecCall(nil), f.execs...)
}

// LookPath returns /fake/bin/<name>, an absolute name as is, or ErrNotFound
// for a program marked Missing.
func (f *Runner) LookPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing[name] {
		return "", fmt.Errorf("exec: %q: %w", name, ErrNotFound)
	}
	if strings.Contains(name, "/") {
		return name, nil
	}
	return "/fake/bin/" + name, nil
}

// Run records c and returns the result of the newest matching rule.
func (f *Runner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	if err := ctx.Err(); err != nil {
		return execx.Result{Code: 1}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, c)
	if f.missing[c.Argv()[0]] {
		return execx.Result{Code: 127}, fmt.Errorf("exec: %q: %w", c.Argv()[0], ErrNotFound)
	}
	for i := len(f.rules) - 1; i >= 0; i-- {
		if f.rules[i].match(c) {
			r := f.rules[i].res
			if c.Stdout != nil {
				_, _ = c.Stdout.Write(r.Stdout)
				r.Stdout = nil
			}
			if c.Stderr != nil {
				_, _ = c.Stderr.Write(r.Stderr)
				r.Stderr = nil
			}
			return r, f.rules[i].err
		}
	}
	return execx.Result{}, nil
}

// Start is Run, answered when the process is waited for.
func (f *Runner) Start(ctx context.Context, c execx.Cmd) (execx.Process, error) {
	res, err := f.Run(ctx, c)
	if errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return &process{res: res, err: err}, nil
}

// Exec records the call and returns ExecErr: nil stands for "tacctl was
// replaced", so the caller's code after Exec is what a test can observe.
func (f *Runner) Exec(path string, argv []string, env []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.execs = append(f.execs, ExecCall{
		Path: path,
		Argv: append([]string(nil), argv...),
		Env:  append([]string(nil), env...),
	})
	return f.ExecErr
}

type process struct {
	res     execx.Result
	err     error
	signals []os.Signal
}

func (p *process) Wait() (execx.Result, error) { return p.res, p.err }
func (p *process) Signal(sig os.Signal) error {
	p.signals = append(p.signals, sig)
	return nil
}
func (p *process) Pid() int { return 4242 }

func hasPrefix(argv, prefix []string) bool {
	if len(prefix) > len(argv) {
		return false
	}
	for i, p := range prefix {
		if argv[i] != p {
			return false
		}
	}
	return true
}
