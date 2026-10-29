package cli

// Several hosts at once ('host sync' and 'host check' with --concurrency,
// above 1). The batch runner of the device verbs (internal/devconf/batch)
// runs one job per host; this file is what makes a host's work safe to run
// beside another's.
//
// A host's work has two kinds of step. The steps that talk to the host (the
// ssh calls, with the host's own hosts.Env) run side by side. Every step that
// touches what the hosts share on this server (the model and the settings
// read once, the UID ledger, the host records, the registry of devices, the
// staging addresses, the audit lines, this server's output) runs through
// hostStep.serial, one host at a time; the invocation's output is the host's
// own while it does, so what such a step prints joins the host's output. The
// output of a host is printed in the order the hosts were typed, a host's
// whole text at once, when it and every host before it have ended, so lines
// of two hosts never mix.
//
// Without --concurrency (or with 1) nothing here is used: serial is a plain
// call, the output goes where it always went, and the hosts are asked what
// they were asked.

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

// hostConcurrencyFlag is the flag of both verbs.
var hostConcurrencyFlag = Flag{Names: []string{"--concurrency"}, Value: true}

// hostConcurrency reads --concurrency: the number of hosts at once, 1 or more.
func (inv *invocation) hostConcurrency(value, usage string) (int, error) {
	n, err := atoiIn(value, 1, 1<<20)
	if err != nil {
		return 0, inv.usageErr("--concurrency takes a number of hosts, 1 or more: '"+value+"'", usage)
	}
	return n, nil
}

// hostStep is how the work of one host reaches what it shares.
type hostStep struct {
	// ctx is the context of the host's ssh calls: the invocation's, or the
	// job's.
	ctx context.Context
	// serial runs fn with the use of the invocation to itself.
	serial func(fn func())
	// concurrent: the host runs beside others. No terminal is used (the
	// hosts are reached with ssh's BatchMode and sudo -n), and nothing is
	// asked.
	concurrent bool
}

// sequentialStep is the step of a host that runs alone.
func (inv *invocation) sequentialStep() *hostStep {
	return &hostStep{ctx: inv.ctx, serial: func(fn func()) { fn() }}
}

// quiet makes the environment of a host that runs beside others use no
// terminal: ssh in BatchMode, sudo without a password, nothing read from
// standard input.
func (st *hostStep) quiet(he *hosts.Env) {
	if st.concurrent {
		he.NoTerminal()
	}
}

// hostChunk is one write of a host's output.
type hostChunk struct {
	stderr bool
	b      []byte
}

// hostBuf holds the output of one host, standard output and standard error
// in the order written.
type hostBuf struct {
	mu     sync.Mutex
	chunks []hostChunk
}

type hostBufStream struct {
	b      *hostBuf
	stderr bool
}

func (w hostBufStream) Write(p []byte) (int, error) {
	w.b.mu.Lock()
	defer w.b.mu.Unlock()
	w.b.chunks = append(w.b.chunks, hostChunk{stderr: w.stderr, b: append([]byte(nil), p...)})
	return len(p), nil
}

// output is the ui.Output that writes into the buffer.
func (b *hostBuf) output() ui.Output {
	return ui.Output{Stdout: hostBufStream{b, false}, Stderr: hostBufStream{b, true}}
}

// replay writes what the host wrote to o.
func (b *hostBuf) replay(o ui.Output) {
	b.mu.Lock()
	chunks := b.chunks
	b.chunks = nil
	b.mu.Unlock()
	for _, c := range chunks {
		w := o.Stdout
		if c.stderr {
			w = o.Stderr
		}
		_, _ = w.Write(c.b)
	}
}

// hostPool runs one job per host through the batch runner.
type hostPool struct {
	inv  *invocation
	real ui.Output
	// mu is the lock of serial.
	mu    sync.Mutex
	bufs  []*hostBuf
	names []string
}

// hostJob is the work of host i: failed says the host's own work failed (it
// has said so), err ends the whole command.
type hostJob func(st *hostStep, i int) (failed bool, err error)

// runHostPool runs job for each of names, concurrency at once, and prints
// each host's output in the order of names. It returns the batch summary and
// what each host reported; the first of errs that is not an interrupt is
// what the caller returns after it has printed what it prints.
func (inv *invocation) runHostPool(names []string, concurrency int, job hostJob) (sum batch.Summary, failed []bool, errs []error) {
	p := &hostPool{inv: inv, real: inv.app.Out, names: names}
	failed, errs = make([]bool, len(names)), make([]error, len(names))
	jobs := make([]batch.Job, len(names))
	for i, name := range names {
		p.bufs = append(p.bufs, &hostBuf{})
		jobs[i] = batch.Job{Name: name, Do: func(ctx context.Context) batch.Result {
			st := &hostStep{ctx: ctx, concurrent: true, serial: func(fn func()) { p.serial(i, fn) }}
			f, err := job(st, i)
			failed[i], errs[i] = f, err
			switch {
			case err != nil:
				return batch.Result{Status: batch.StatusFailed, Reason: strings.Join(msgs(err), " "), Err: err}
			case f:
				return batch.Result{Status: batch.StatusFailed, Reason: "failed"}
			}
			return batch.Result{}
		}}
	}
	ctx, interrupts, stop := inv.batchInterrupts()
	defer stop()
	sum = batch.Run(ctx, batch.Options{Concurrency: concurrency, Interrupts: interrupts, Clock: inv.app.Knobs.Now},
		jobs, &orderedView{p: p})
	return sum, failed, errs
}

// serial runs fn with the invocation to itself and its output the host i's.
func (p *hostPool) serial(i int, fn func()) {
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.inv.app
	saved := a.Out
	a.Out = p.bufs[i].output()
	defer func() { a.Out = saved }()
	fn()
}

// firstError is the error that ends the command: the first host's, in the
// order typed, that is not an interrupt.
func firstError(errs []error) error {
	for _, err := range errs {
		if err != nil && !errors.Is(err, ui.ErrInterrupted) {
			return err
		}
	}
	return nil
}

// orderedView prints the hosts in the order typed: a host's output as soon
// as it and all before it have ended. It runs on the runner's goroutine
// only, so it writes to the invocation's real output, which the hosts'
// serial steps never touch.
type orderedView struct {
	p    *hostPool
	done []bool
	next int
}

func (v *orderedView) Begin(names []string) { v.done = make([]bool, len(names)) }

func (v *orderedView) Update(e batch.Event) {
	switch e.Phase {
	case batch.PhaseDone:
	case batch.PhaseSkipped:
		// not started (an interrupt): say so in the host's place
		v.p.bufs[e.Index].output().WarnE(e.Name + ": not started (interrupted).")
	default:
		return
	}
	v.done[e.Index] = true
	for v.next < len(v.done) && v.done[v.next] {
		v.p.bufs[v.next].replay(v.p.real)
		v.next++
	}
}

func (v *orderedView) End(batch.Summary) {}
