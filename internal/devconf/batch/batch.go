// Package batch is the runner behind the device verbs that touch many
// devices at once (docs/plans/0.2.4-plan.md D67, section 5): a pool of
// workers over a list of jobs, one job per device, with a per-job timeout,
// a failure budget, a stop on the first authentication failure and a
// two-stage interrupt. 'device config pull' and 'diff' use it in 0.2.4 and
// the 0.2.5 apply (canary first) will, so it knows nothing about devices:
// a Job is a name and a function.
//
// The package has no terminal, no signal handling, no global state and no
// wall-clock read. The caller hands it the interrupt channel and the clock;
// progress goes to a View, which is only ever called from the goroutine
// that called Run, so a view needs no locking and workers never write
// anywhere.
package batch

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Exit statuses of a batch verb (D67). ExitDiffers is the status
// '--exit-code' gives to a run in which no device failed but one differs,
// as git diff does; it is also the usage status, which the caller decides
// before Run is reached.
const (
	ExitOK          = 0
	ExitFailed      = 1
	ExitDiffers     = 2
	ExitUsage       = 2
	ExitInterrupted = 130
)

// ErrInterrupted is the cancellation cause of the context of a job that
// the second interrupt (or the cancellation of Run's own context) cut off.
// context.Cause(ctx) returns it inside the job.
var ErrInterrupted = errors.New("interrupted")

// Status is how one job ended.
type Status int

const (
	// StatusOK: the job did what it was asked. The zero value, so a job
	// that has nothing to say returns Result{}. Differences are not a
	// failure (Result.Differs).
	StatusOK Status = iota
	// StatusFailed: the job could not do it. Result.Reason says why.
	StatusFailed
	// StatusAuthFailed: the device rejected the login. With
	// Options.StopOnAuthFailure the pool starts nothing new after it.
	StatusAuthFailed
	// StatusTimeout: the per-job timeout ended the job. The runner sets it
	// on a job that returned StatusFailed after its context's deadline.
	StatusTimeout
	// StatusInterrupted: the second interrupt cancelled the job. The runner
	// sets it on a job that returned StatusFailed after the cancellation.
	StatusInterrupted
	// StatusNotStarted: the pool stopped before the job began. Only the
	// runner sets it; Reason says which stop it was.
	StatusNotStarted
)

// String is the status word of the record and of --json.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusFailed:
		return "failed"
	case StatusAuthFailed:
		return "auth-failed"
	case StatusTimeout:
		return "timeout"
	case StatusInterrupted:
		return "interrupted"
	case StatusNotStarted:
		return "not-started"
	}
	return fmt.Sprintf("status(%d)", int(s))
}

// Failure reports whether the status counts against the exit status and
// the failure budget. A job that was never started is not a failure of its
// own; the stop that skipped it is reported by the Summary.
func (s Status) Failure() bool {
	switch s {
	case StatusFailed, StatusAuthFailed, StatusTimeout, StatusInterrupted:
		return true
	}
	return false
}

// Result is what a job reports.
type Result struct {
	Status Status
	// Reason is the short text after "failed: " in the view. The runner
	// fills it for the statuses it assigns itself; a job that returns a
	// failure without one gets the status word.
	Reason string
	// Differs names what differs from what was expected (section names,
	// for a pull). Meaningful with StatusOK only; it is not a failure.
	Differs []string
	// Err is the underlying error, for the caller's own use (--json,
	// log lines). The runner never prints it.
	Err error
	// Value is the job's own payload, handed through to the view and the
	// Summary untouched.
	Value any
}

// Text is the line the view shows for the result (D67): "ok",
// "ok, differs in aaa,snmp", "failed: <reason>", "interrupted",
// "not started".
func (r Result) Text() string {
	switch r.Status {
	case StatusOK:
		if len(r.Differs) > 0 {
			return "ok, differs in " + strings.Join(r.Differs, ",")
		}
		return "ok"
	case StatusInterrupted:
		return "interrupted"
	case StatusNotStarted:
		return "not started"
	}
	return "failed: " + r.Reason
}

// Job is one unit of work, one device. Do must honour ctx: its deadline is
// the per-job timeout and its cancellation is the second interrupt (a job
// that ignores it holds Run until it returns). Do runs on a pool goroutine,
// so it may share nothing but what is safe to share.
type Job struct {
	Name string
	Do   func(ctx context.Context) Result
}

// Options are the settings of a run.
type Options struct {
	// Concurrency is the requested pool size (--concurrency) and Cap the
	// configured ceiling (device.config.max_concurrency); the pool is the
	// smaller of the two and of the number of jobs (PoolSize). Zero or
	// negative leaves that term out.
	Concurrency int
	Cap         int
	// Timeout is the budget of one job, connect included; its context is
	// cancelled when it ends. Zero or negative means none.
	Timeout time.Duration
	// MaxFailures stops the pool from starting new jobs after that many
	// failures. Zero or negative means no limit. Jobs already running
	// finish, so a pool wider than one can exceed the budget.
	MaxFailures int
	// StopOnAuthFailure stops the pool from starting new jobs after the
	// first StatusAuthFailed (one wrong password must not lock an account
	// out on every device).
	StopOnAuthFailure bool
	// Interrupts delivers one value per interrupt the operator gave: the
	// first stops new jobs from starting and lets the running ones finish
	// within their timeout, the second cancels their contexts. The caller
	// owns the signal handling; nil means none. A closed channel means no
	// more are coming.
	Interrupts <-chan struct{}
	// Clock stamps the events; it is called only from the goroutine that
	// called Run. Nil leaves every time zero.
	Clock func() time.Time
}

// PoolSize is the number of workers for n jobs: the smaller of the
// requested concurrency, the cap and n, and at least one when there is any
// job. A requested or cap value below one leaves that term out.
func PoolSize(concurrency, limit, n int) int {
	if n <= 0 {
		return 0
	}
	p := n
	if concurrency > 0 && concurrency < p {
		p = concurrency
	}
	if limit > 0 && limit < p {
		p = limit
	}
	return p
}

// Phase is where a job is in an Event.
type Phase int

const (
	// PhaseRunning: a worker took the job.
	PhaseRunning Phase = iota
	// PhaseDone: the job ended; Event.Result is its result.
	PhaseDone
	// PhaseSkipped: the pool stopped before the job; Event.Result carries
	// StatusNotStarted and the reason.
	PhaseSkipped
)

// Event is one change a View is told about. Every job is queued from
// Begin on; it then gets PhaseRunning and PhaseDone, or PhaseSkipped.
type Event struct {
	Index  int // position in the job list (the registry's order)
	Name   string
	Phase  Phase
	Result Result
	At     time.Time
}

// View is the progress display. Run calls it from its own goroutine only,
// never concurrently, so an implementation needs no lock; it must not
// block for long, since it holds the dispatcher. The terminal and --json
// views are the caller's; Board keeps the state a terminal view repaints.
type View interface {
	// Begin is called once, before any job starts, with every name in the
	// order of the list: all are queued.
	Begin(names []string)
	// Update reports one job's change.
	Update(e Event)
	// End is called once, after the last job ended, with the Summary Run
	// returns.
	End(s Summary)
}

// Stop is why a pool stopped starting jobs.
type Stop int

const (
	StopNone Stop = iota
	StopInterrupted
	StopMaxFailures
	StopAuthFailure
)

// Entry is one job in the Summary.
type Entry struct {
	Name     string
	Result   Result
	Started  time.Time
	Finished time.Time
}

// Duration is how long the job ran by the injected clock; zero for a job
// that did not start.
func (e Entry) Duration() time.Duration {
	if e.Started.IsZero() || e.Finished.IsZero() {
		return 0
	}
	return e.Finished.Sub(e.Started)
}

// Summary is the outcome of a run.
type Summary struct {
	// Entries are the jobs in the order of the list, not of arrival.
	Entries []Entry
	// OK counts the jobs that succeeded, differing ones included; Differ
	// is the part of them that differs; Failed counts every failure
	// status; NotStarted the jobs the pool never began.
	OK         int
	Differ     int
	Failed     int
	AuthFailed int
	NotStarted int
	// Pool is the number of workers the run used.
	Pool int
	// Stop is why starting ended early, the first reason that applied.
	// Interrupted is true when an interrupt (or the cancellation of Run's
	// context) arrived before the last job ended, whatever else stopped
	// the run.
	Stop        Stop
	Interrupted bool
}

// Line is the one-line count (D67): "12 ok, 2 differ, 1 failed". The
// counts are disjoint, so they add up to the jobs that ran: ok is the
// devices that matched, differ the ones that succeeded and differ. Zero
// counts are left out, except that a run with nothing to count says "0 ok".
func (s Summary) Line() string {
	var parts []string
	if n := s.OK - s.Differ; n > 0 {
		parts = append(parts, fmt.Sprintf("%d ok", n))
	}
	if s.Differ > 0 {
		parts = append(parts, fmt.Sprintf("%d differ", s.Differ))
	}
	if s.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", s.Failed))
	}
	if len(parts) == 0 {
		return "0 ok"
	}
	return strings.Join(parts, ", ")
}

// StopLine says why the run ended early and how many jobs it left, or is
// empty when every job was started and no interrupt came.
func (s Summary) StopLine() string {
	switch {
	case s.Interrupted:
		return fmt.Sprintf("interrupted: %d not started", s.NotStarted)
	case s.Stop == StopMaxFailures:
		return fmt.Sprintf("stopped at the failure limit: %d not started", s.NotStarted)
	case s.Stop == StopAuthFailure:
		return fmt.Sprintf("stopped at the first authentication failure: %d not started", s.NotStarted)
	}
	return ""
}

// ExitCode is the exit status of the run (D67): 130 for an interrupt, 1
// when any job failed, 2 when exitOnDiffer is set ('--exit-code') and a
// device differs, else 0. A difference is otherwise not a failure.
func (s Summary) ExitCode(exitOnDiffer bool) int {
	switch {
	case s.Interrupted:
		return ExitInterrupted
	case s.Failed > 0:
		return ExitFailed
	case exitOnDiffer && s.Differ > 0:
		return ExitDiffers
	}
	return ExitOK
}

// done is a worker's report to the dispatcher.
type done struct {
	i int
	r Result
}

// Run executes the jobs and returns how it went. A pool of PoolSize
// workers takes the jobs in list order; every job gets its own context
// with the per-job timeout. view may be nil. Cancelling ctx is the same as
// the second interrupt. Run returns when every started job has returned.
func Run(ctx context.Context, opt Options, jobs []Job, view View) Summary {
	if view == nil {
		view = nopView{}
	}
	now := opt.Clock
	if now == nil {
		now = func() time.Time { return time.Time{} }
	}
	n := len(jobs)
	pool := PoolSize(opt.Concurrency, opt.Cap, n)
	sum := Summary{Entries: make([]Entry, n), Pool: pool}
	names := make([]string, n)
	for i, j := range jobs {
		names[i] = j.Name
		sum.Entries[i].Name = j.Name
	}
	view.Begin(names)

	runCtx, cancelRun := context.WithCancelCause(ctx)
	defer cancelRun(nil)

	results := make(chan done, n) // never blocks a worker
	interrupts := opt.Interrupts
	parent := ctx.Done()
	next, running, failures := 0, 0, 0
	stopped, interrupted := false, false

	// stop ends the starting of jobs, for the first reason that applies:
	// every job not yet started is reported as skipped, in list order.
	stop := func(why Stop, reason string) {
		if stopped {
			return
		}
		stopped = true
		sum.Stop = why
		for ; next < n; next++ {
			r := Result{Status: StatusNotStarted, Reason: reason}
			sum.Entries[next].Result = r
			sum.NotStarted++
			view.Update(Event{Index: next, Name: names[next], Phase: PhaseSkipped, Result: r, At: now()})
		}
	}
	interrupt := func(hard bool) {
		sum.Interrupted = true
		stop(StopInterrupted, "interrupted")
		if hard {
			cancelRun(ErrInterrupted)
		}
	}

	for {
		for !stopped && next < n && running < pool {
			i := next
			next++
			running++
			at := now()
			sum.Entries[i].Started = at
			view.Update(Event{Index: i, Name: names[i], Phase: PhaseRunning, At: at})
			go func() {
				results <- done{i, runJob(runCtx, opt.Timeout, jobs[i])}
			}()
		}
		if running == 0 {
			break
		}
		select {
		case d := <-results:
			running--
			at := now()
			r := d.r
			sum.Entries[d.i].Result = r
			sum.Entries[d.i].Finished = at
			if r.Status == StatusOK {
				sum.OK++
				if len(r.Differs) > 0 {
					sum.Differ++
				}
			} else if r.Status.Failure() {
				sum.Failed++
				failures++
				if r.Status == StatusAuthFailed {
					sum.AuthFailed++
				}
			}
			view.Update(Event{Index: d.i, Name: names[d.i], Phase: PhaseDone, Result: r, At: at})
			switch {
			case r.Status == StatusAuthFailed && opt.StopOnAuthFailure:
				stop(StopAuthFailure, "authentication failed on another device")
			case opt.MaxFailures > 0 && failures >= opt.MaxFailures && r.Status.Failure():
				stop(StopMaxFailures, "failure limit reached")
			}
		case _, ok := <-interrupts:
			if !ok {
				interrupts = nil
				break
			}
			interrupt(interrupted)
			interrupted = true
		case <-parent:
			parent = nil
			interrupt(true)
			interrupted = true
		}
	}

	view.End(sum)
	return sum
}

// runJob runs one job under its own deadline and settles its result: an
// error with a nil status is a failure, and a failure that came with an
// expired deadline or a cancelled run is a timeout or an interruption.
func runJob(parent context.Context, timeout time.Duration, j Job) Result {
	var (
		ctx    context.Context
		cancel context.CancelFunc
	)
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(parent, timeout)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}
	defer cancel()

	r := j.Do(ctx)
	if r.Status == StatusOK && r.Err != nil {
		r.Status = StatusFailed
	}
	if r.Status == StatusFailed {
		switch {
		case parent.Err() != nil:
			r.Status = StatusInterrupted
			r.Reason = "interrupted"
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			r.Status = StatusTimeout
			if r.Reason == "" {
				r.Reason = "timeout after " + timeout.String()
			}
		}
	}
	if r.Status != StatusOK && r.Status != StatusInterrupted && r.Reason == "" {
		r.Reason = r.Status.String()
	}
	return r
}

type nopView struct{}

func (nopView) Begin([]string) {}
func (nopView) Update(Event)   {}
func (nopView) End(Summary)    {}
