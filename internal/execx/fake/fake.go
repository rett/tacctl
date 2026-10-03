// Package fake is an execx.Runner for Go tests: it runs nothing, records
// every call and answers from a script of rules (docs/plans/go-rewrite.md
// 3.6). It is the Go counterpart of tests/helpers/mocks.bash: where a bats
// test writes stub_cmd systemctl 'exit 3' and asserts stub_called, a Go test
// scripts On([]string{"systemctl"}, execx.Result{Code: 3}) and asserts
// Called("systemctl", "restart", "tacquito").
//
// Scripting: On (by argv prefix), When and Func (by predicate), Seq (a
// different answer per call), Fail, Missing and Install (what LookPath
// finds), ExecErr (what a failed execve returns), Strict (an unscripted call
// is an error instead of a silent success). Asserting: Calls, Records,
// Argvs, Called, CalledRegexp, Count, ArgvContains, Signals, Execs.
package fake

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/execx"
)

// ErrNotFound is what LookPath, Run and Start return for a program marked
// Missing.
var ErrNotFound = errors.New("executable file not found in $PATH")

// ErrUnscripted is what Run and Start return for a call no rule matches
// while Strict is set.
var ErrUnscripted = errors.New("fake: no rule for this command")

// Record is one Run or Start as it was made. Cmd.Stdin, when it was set, is
// replaced by a reader over Stdin, so a Func rule can read the input too.
type Record struct {
	Cmd   execx.Cmd
	Stdin []byte // everything Cmd.Stdin held; nil when it was nil
}

// ExecCall is one Exec: what tacctl would have replaced itself with.
type ExecCall struct {
	Path string
	Argv []string
	Env  []string
}

type rule struct {
	match func(execx.Cmd) bool
	// fn, when set, computes the answer; res and err are used otherwise.
	fn  func(execx.Cmd) (execx.Result, error)
	res execx.Result
	err error
}

// Runner is the fake. The zero value is ready: every program exists at
// /fake/bin/<name> and exits 0 with no output.
type Runner struct {
	mu      sync.Mutex
	rules   []rule
	missing map[string]bool
	paths   map[string]string
	records []Record
	execs   []ExecCall
	signals []os.Signal
	// ExecErr, when set, is returned by Exec (as a failed execve would be).
	ExecErr error
	// Strict makes a call that no rule matches fail with ErrUnscripted
	// (Result.Code 127, as for a program that is not there) instead of
	// succeeding silently. Use it where a test must account for every
	// program the code under test runs.
	Strict bool
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

// Func answers calls for which match is true with whatever fn returns, so a
// rule can look at the call: read Cmd.Stdin, write a file named in Args,
// answer by the working directory. Rules added later take precedence.
func (f *Runner) Func(match func(execx.Cmd) bool, fn func(execx.Cmd) (execx.Result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rules = append(f.rules, rule{match: match, fn: fn})
}

// OnFunc is Func for calls whose argv starts with prefix.
func (f *Runner) OnFunc(prefix []string, fn func(execx.Cmd) (execx.Result, error)) {
	p := append([]string(nil), prefix...)
	f.Func(func(c execx.Cmd) bool { return hasPrefix(c.Argv(), p) }, fn)
}

// Seq answers the calls whose argv starts with prefix one result at a time,
// in order; the last result answers every call after that. It is the way to
// script "fails the first time, works the second" (systemctl restart, then
// is-active). With no results the rule answers with the zero Result.
func (f *Runner) Seq(prefix []string, results ...execx.Result) {
	var mu sync.Mutex
	n := 0
	f.OnFunc(prefix, func(execx.Cmd) (execx.Result, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(results) == 0 {
			return execx.Result{}, nil
		}
		r := results[min(n, len(results)-1)]
		n++
		return r, nil
	})
}

// Fail answers the calls whose argv starts with prefix with exit status code
// and stderr text (a trailing newline is added when it has none).
func (f *Runner) Fail(prefix []string, code int, stderr string) {
	if stderr != "" && !strings.HasSuffix(stderr, "\n") {
		stderr += "\n"
	}
	f.On(prefix, execx.Result{Code: code, Stderr: []byte(stderr)})
}

// Install makes LookPath(name) return path instead of /fake/bin/<name>, and
// undoes Missing for it.
func (f *Runner) Install(name, path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.paths == nil {
		f.paths = map[string]string{}
	}
	f.paths[name] = path
	delete(f.missing, name)
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
		delete(f.paths, n)
	}
}

// Calls returns every Run and Start so far, in order.
func (f *Runner) Calls() []execx.Cmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]execx.Cmd, len(f.records))
	for i, r := range f.records {
		out[i] = r.Cmd
	}
	return out
}

// Records returns every Run and Start so far with the input each was given.
func (f *Runner) Records() []Record {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]Record(nil), f.records...)
}

// Called reports whether some Run or Start had an argv starting with prefix
// (AsUser applied): Called("systemctl", "restart", "tacquito").
func (f *Runner) Called(prefix ...string) bool { return f.Count(prefix...) > 0 }

// Count is how many Runs and Starts had an argv starting with prefix.
func (f *Runner) Count(prefix ...string) int {
	n := 0
	for _, c := range f.Calls() {
		if hasPrefix(c.Argv(), prefix) {
			n++
		}
	}
	return n
}

// CalledRegexp reports whether the space-joined argv of some call matches
// the regular expression, as the bats helper stub_called does with grep -E
// on CALLS_LOG; it panics on a bad expression.
func (f *Runner) CalledRegexp(pattern string) bool {
	re := regexp.MustCompile(pattern)
	for _, a := range f.Argvs() {
		if re.MatchString(a) {
			return true
		}
	}
	return false
}

// ArgvContains reports whether s appears in the argv of any call: the check
// behind "a secret never reaches the argv of a child process" (docs/plans/
// go-rewrite.md 2.3).
func (f *Runner) ArgvContains(s string) bool {
	for _, a := range f.Argvs() {
		if strings.Contains(a, s) {
			return true
		}
	}
	return false
}

// Signals returns the signals sent to processes started with Start, in order.
func (f *Runner) Signals() []os.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]os.Signal(nil), f.signals...)
}

// Reset forgets every recorded call, exec and signal. Rules, Missing,
// Install, ExecErr and Strict stay.
func (f *Runner) Reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records, f.execs, f.signals = nil, nil, nil
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

// LookPath returns the path given to Install, /fake/bin/<name>, an absolute
// name as is, or ErrNotFound for a program marked Missing.
func (f *Runner) LookPath(name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.missing[name] {
		return "", fmt.Errorf("exec: %q: %w", name, ErrNotFound)
	}
	if p, ok := f.paths[name]; ok {
		return p, nil
	}
	if strings.Contains(name, "/") {
		return name, nil
	}
	return "/fake/bin/" + name, nil
}

// Run records c and returns the answer of the newest matching rule (the zero
// Result when none matches, unless Strict).
func (f *Runner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	if err := ctx.Err(); err != nil {
		return execx.Result{Code: 1}, err
	}
	var stdin []byte
	if c.Stdin != nil {
		stdin, _ = io.ReadAll(c.Stdin)
		if stdin == nil {
			stdin = []byte{}
		}
		c.Stdin = bytes.NewReader(stdin)
	}
	f.mu.Lock()
	f.records = append(f.records, Record{Cmd: c, Stdin: stdin})
	if f.missing[c.Argv()[0]] {
		f.mu.Unlock()
		return execx.Result{Code: 127}, fmt.Errorf("exec: %q: %w", c.Argv()[0], ErrNotFound)
	}
	var matched *rule
	for i := len(f.rules) - 1; i >= 0; i-- {
		if f.rules[i].match(c) {
			matched = &f.rules[i]
			break
		}
	}
	strict := f.Strict
	f.mu.Unlock()
	if matched == nil {
		if strict {
			return execx.Result{Code: 127}, fmt.Errorf("%w: %s", ErrUnscripted, strings.Join(c.Argv(), " "))
		}
		return execx.Result{}, nil
	}
	// A rule's function runs unlocked, so it may call back into the Runner.
	r, err := matched.res, matched.err
	if matched.fn != nil {
		r, err = matched.fn(c)
	}
	if c.Stdout != nil {
		_, _ = c.Stdout.Write(r.Stdout)
		r.Stdout = nil
	}
	if c.Stderr != nil {
		_, _ = c.Stderr.Write(r.Stderr)
		r.Stderr = nil
	}
	return r, err
}

// Start is Run, answered when the process is waited for.
func (f *Runner) Start(ctx context.Context, c execx.Cmd) (execx.Process, error) {
	res, err := f.Run(ctx, c)
	if errors.Is(err, ErrNotFound) || errors.Is(err, ErrUnscripted) {
		return nil, err
	}
	return &process{f: f, res: res, err: err}, nil
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
	f   *Runner
	res execx.Result
	err error
}

func (p *process) Wait() (execx.Result, error) { return p.res, p.err }
func (p *process) Signal(sig os.Signal) error {
	p.f.mu.Lock()
	defer p.f.mu.Unlock()
	p.f.signals = append(p.f.signals, sig)
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
