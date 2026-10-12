package batch

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// recView records the events of a run. It takes no lock on purpose: Run
// promises to call a view from one goroutine, and -race holds it to that.
type recView struct {
	names  []string
	events []Event
	end    *Summary
	hook   func(Event)
}

func (v *recView) Begin(names []string) { v.names = names }
func (v *recView) Update(e Event) {
	v.events = append(v.events, e)
	if v.hook != nil {
		v.hook(e)
	}
}
func (v *recView) End(s Summary) { v.end = &s }

// stepClock is a fixed clock: each call is one second after the last. Run
// reads it from one goroutine, so it needs no lock.
func stepClock() func() time.Time {
	t := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	return func() time.Time {
		t = t.Add(time.Second)
		return t
	}
}

func result(s Status) func(context.Context) Result {
	return func(context.Context) Result { return Result{Status: s} }
}

func jobsOf(n int, do func(i int) func(context.Context) Result) []Job {
	jobs := make([]Job, n)
	for i := range jobs {
		jobs[i] = Job{Name: fmt.Sprintf("dev%d", i), Do: do(i)}
	}
	return jobs
}

func statuses(s Summary) []Status {
	var out []Status
	for _, e := range s.Entries {
		out = append(out, e.Result.Status)
	}
	return out
}

func TestPoolSize(t *testing.T) {
	for _, c := range []struct{ conc, limit, n, want int }{
		{8, 8, 20, 8},
		{4, 8, 20, 4},
		{16, 8, 20, 8},
		{64, 64, 3, 3},
		{0, 0, 5, 5},
		{0, 8, 5, 5},
		{0, 3, 5, 3},
		{-1, -1, 5, 5},
		{8, 8, 1, 1},
		{8, 8, 0, 0},
	} {
		if got := PoolSize(c.conc, c.limit, c.n); got != c.want {
			t.Errorf("PoolSize(%d, %d, %d) = %d, want %d", c.conc, c.limit, c.n, got, c.want)
		}
	}
}

func TestRunNoJobs(t *testing.T) {
	v := &recView{}
	s := Run(context.Background(), Options{Concurrency: 4}, nil, v)
	if v.end == nil || len(v.names) != 0 || len(v.events) != 0 {
		t.Fatalf("view: names=%v events=%v end=%v", v.names, v.events, v.end)
	}
	if s.Pool != 0 || s.ExitCode(false) != ExitOK || s.Line() != "0 ok" || s.StopLine() != "" {
		t.Fatalf("summary: %+v", s)
	}
}

// The pool is min(concurrency, cap, jobs): never wider, and as wide as that
// when the jobs can all be in flight at once.
func TestRunPoolBound(t *testing.T) {
	for _, c := range []struct {
		conc, limit, n, want int
	}{
		{8, 2, 7, 2},  // the cap wins
		{3, 8, 7, 3},  // the flag wins
		{8, 8, 2, 2},  // the number of jobs wins
		{0, 0, 4, 4},  // no limit asked
		{1, 64, 5, 1}, // sequential
	} {
		var mu sync.Mutex
		cur, peak := 0, 0
		started := make(chan struct{}, c.n)
		gate := make(chan struct{})
		jobs := jobsOf(c.n, func(int) func(context.Context) Result {
			return func(context.Context) Result {
				mu.Lock()
				cur++
				peak = max(peak, cur)
				mu.Unlock()
				started <- struct{}{}
				<-gate
				mu.Lock()
				cur--
				mu.Unlock()
				return Result{}
			}
		})
		out := make(chan Summary, 1)
		go func() {
			out <- Run(context.Background(), Options{Concurrency: c.conc, Cap: c.limit}, jobs, nil)
		}()
		for range c.want {
			<-started // the pool is saturated before anything is released
		}
		close(gate)
		s := <-out
		if peak != c.want || s.Pool != c.want {
			t.Errorf("conc=%d cap=%d n=%d: peak %d, pool %d, want %d", c.conc, c.limit, c.n, peak, s.Pool, c.want)
		}
		if s.OK != c.n || s.ExitCode(false) != ExitOK {
			t.Errorf("conc=%d cap=%d n=%d: %+v", c.conc, c.limit, c.n, s)
		}
	}
}

// With one worker the order is the list's; counts, lines and exit statuses
// follow D67: differences are not failures.
func TestRunResultsAndExit(t *testing.T) {
	jobs := []Job{
		{Name: "a", Do: result(StatusOK)},
		{Name: "b", Do: func(context.Context) Result { return Result{Differs: []string{"aaa", "snmp"}} }},
		{Name: "c", Do: func(context.Context) Result { return Result{Status: StatusFailed, Reason: "no route"} }},
		{Name: "d", Do: func(context.Context) Result { return Result{Err: errors.New("boom")} }},
		{Name: "e", Do: result(StatusOK)},
	}
	v := &recView{}
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, v)

	if want := []Status{StatusOK, StatusOK, StatusFailed, StatusFailed, StatusOK}; !reflect.DeepEqual(statuses(s), want) {
		t.Fatalf("statuses %v, want %v", statuses(s), want)
	}
	if s.OK != 3 || s.Differ != 1 || s.Failed != 2 || s.NotStarted != 0 || s.Stop != StopNone || s.Interrupted {
		t.Fatalf("summary %+v", s)
	}
	if got := s.Line(); got != "2 ok, 1 differ, 2 failed" {
		t.Errorf("Line %q", got)
	}
	if s.StopLine() != "" {
		t.Errorf("StopLine %q", s.StopLine())
	}
	if s.Entries[1].Result.Text() != "ok, differs in aaa,snmp" || s.Entries[2].Result.Text() != "failed: no route" {
		t.Errorf("texts %q %q", s.Entries[1].Result.Text(), s.Entries[2].Result.Text())
	}
	// A job that reported an error and no status is a failure with the
	// status word as its reason.
	if r := s.Entries[3].Result; r.Status != StatusFailed || r.Reason != "failed" || r.Err == nil {
		t.Errorf("job d: %+v", r)
	}
	if s.ExitCode(false) != ExitFailed || s.ExitCode(true) != ExitFailed {
		t.Errorf("exit %d %d", s.ExitCode(false), s.ExitCode(true))
	}
	if v.end == nil || !reflect.DeepEqual(v.end.Entries, s.Entries) {
		t.Errorf("End got %+v", v.end)
	}
}

func TestSummaryExitCode(t *testing.T) {
	for _, c := range []struct {
		name   string
		s      Summary
		differ bool
		want   int
	}{
		{"all ok", Summary{OK: 3}, false, 0},
		{"differs, no flag", Summary{OK: 3, Differ: 2}, false, 0},
		{"differs, exit-code", Summary{OK: 3, Differ: 2}, true, 2},
		{"failed", Summary{OK: 2, Failed: 1}, false, 1},
		{"failed beats differs", Summary{OK: 2, Differ: 1, Failed: 1}, true, 1},
		{"interrupted", Summary{OK: 2, NotStarted: 3, Interrupted: true}, false, 130},
		{"interrupted beats failed", Summary{Failed: 1, Interrupted: true}, true, 130},
		{"interrupted, nothing left", Summary{OK: 2, Interrupted: true}, false, 130},
	} {
		if got := c.s.ExitCode(c.differ); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
}

// Each job has its own deadline; a failure that comes with an expired one is
// a timeout, and the job that finished in time is untouched.
func TestRunTimeout(t *testing.T) {
	jobs := []Job{
		{Name: "slow", Do: func(ctx context.Context) Result {
			<-ctx.Done()
			return Result{Status: StatusFailed, Err: ctx.Err()}
		}},
		{Name: "fast", Do: func(ctx context.Context) Result {
			if _, ok := ctx.Deadline(); !ok {
				return Result{Status: StatusFailed, Reason: "no deadline"}
			}
			return Result{}
		}},
	}
	s := Run(context.Background(), Options{Concurrency: 2, Timeout: 20 * time.Millisecond}, jobs, nil)
	slow := s.Entries[0].Result
	if slow.Status != StatusTimeout || slow.Reason != "timeout after 20ms" || slow.Text() != "failed: timeout after 20ms" {
		t.Errorf("slow: %+v", slow)
	}
	if s.Entries[1].Result.Status != StatusOK {
		t.Errorf("fast: %+v", s.Entries[1].Result)
	}
	if s.Failed != 1 || s.ExitCode(false) != ExitFailed || s.Interrupted {
		t.Errorf("summary %+v", s)
	}
}

func TestRunNoTimeoutMeansNoDeadline(t *testing.T) {
	var has bool
	jobs := []Job{{Name: "a", Do: func(ctx context.Context) Result {
		_, has = ctx.Deadline()
		return Result{}
	}}}
	Run(context.Background(), Options{}, jobs, nil)
	if has {
		t.Error("a deadline without a timeout")
	}
}

// A job that names its own reason keeps it, even at the deadline.
func TestRunTimeoutKeepsJobReason(t *testing.T) {
	jobs := []Job{{Name: "a", Do: func(ctx context.Context) Result {
		<-ctx.Done()
		return Result{Status: StatusFailed, Reason: "connect timed out"}
	}}}
	s := Run(context.Background(), Options{Timeout: time.Millisecond}, jobs, nil)
	if r := s.Entries[0].Result; r.Status != StatusTimeout || r.Reason != "connect timed out" {
		t.Errorf("%+v", r)
	}
}

func TestRunMaxFailures(t *testing.T) {
	jobs := jobsOf(6, func(i int) func(context.Context) Result {
		if i%2 == 0 {
			return result(StatusFailed)
		}
		return result(StatusOK)
	})
	v := &recView{}
	s := Run(context.Background(), Options{Concurrency: 1, MaxFailures: 2}, jobs, v)
	// dev0 fails, dev1 ok, dev2 fails: the budget is spent.
	want := []Status{StatusFailed, StatusOK, StatusFailed, StatusNotStarted, StatusNotStarted, StatusNotStarted}
	if !reflect.DeepEqual(statuses(s), want) {
		t.Fatalf("statuses %v, want %v", statuses(s), want)
	}
	if s.Stop != StopMaxFailures || s.NotStarted != 3 || s.Failed != 2 || s.Interrupted {
		t.Errorf("summary %+v", s)
	}
	if got := s.StopLine(); got != "stopped at the failure limit: 3 not started" {
		t.Errorf("StopLine %q", got)
	}
	if got := s.Entries[3].Result; got.Reason != "failure limit reached" || got.Text() != "not started" {
		t.Errorf("skipped: %+v", got)
	}
	if s.ExitCode(false) != ExitFailed {
		t.Errorf("exit %d", s.ExitCode(false))
	}
	// The skipped jobs were reported to the view, never started.
	skipped := 0
	for _, e := range v.events {
		if e.Phase == PhaseSkipped {
			skipped++
			if e.Index < 3 {
				t.Errorf("skipped index %d", e.Index)
			}
		}
	}
	if skipped != 3 {
		t.Errorf("skipped events %d", skipped)
	}
}

func TestRunMaxFailuresZeroIsNoLimit(t *testing.T) {
	jobs := jobsOf(5, func(int) func(context.Context) Result { return result(StatusFailed) })
	s := Run(context.Background(), Options{Concurrency: 1}, jobs, nil)
	if s.Failed != 5 || s.NotStarted != 0 || s.Stop != StopNone {
		t.Errorf("%+v", s)
	}
}

// An authentication failure starts nothing new, but the job already running
// finishes and is counted.
func TestRunStopOnAuthFailure(t *testing.T) {
	gate := make(chan struct{})
	jobs := jobsOf(5, func(i int) func(context.Context) Result {
		switch i {
		case 0:
			return func(context.Context) Result {
				<-gate
				return Result{}
			}
		case 1:
			return func(context.Context) Result {
				return Result{Status: StatusAuthFailed, Reason: "authentication failed"}
			}
		}
		return result(StatusOK)
	})
	v := &recView{}
	// dev1's failure is processed before dev0 can be released: dev0 waits
	// for the view to see the skip.
	v.hook = func(e Event) {
		if e.Phase == PhaseSkipped && e.Index == 2 {
			close(gate)
		}
	}
	s := Run(context.Background(), Options{Concurrency: 2, StopOnAuthFailure: true}, jobs, v)
	want := []Status{StatusOK, StatusAuthFailed, StatusNotStarted, StatusNotStarted, StatusNotStarted}
	if !reflect.DeepEqual(statuses(s), want) {
		t.Fatalf("statuses %v, want %v", statuses(s), want)
	}
	if s.Stop != StopAuthFailure || s.AuthFailed != 1 || s.Failed != 1 || s.NotStarted != 3 {
		t.Errorf("summary %+v", s)
	}
	if got := s.StopLine(); got != "stopped at the first authentication failure: 3 not started" {
		t.Errorf("StopLine %q", got)
	}
	if s.Entries[1].Result.Text() != "failed: authentication failed" {
		t.Errorf("text %q", s.Entries[1].Result.Text())
	}
}

func TestRunAuthFailureWithoutStop(t *testing.T) {
	jobs := jobsOf(4, func(i int) func(context.Context) Result {
		if i == 1 {
			return result(StatusAuthFailed)
		}
		return result(StatusOK)
	})
	s := Run(context.Background(), Options{Concurrency: 1}, jobs, nil)
	if s.OK != 3 || s.AuthFailed != 1 || s.Failed != 1 || s.NotStarted != 0 || s.Stop != StopNone {
		t.Errorf("%+v", s)
	}
}

// The first interrupt only stops new jobs: a running job keeps its context
// and finishes. The second cancels the contexts of the rest.
func TestRunTwoStageInterrupt(t *testing.T) {
	gate := make(chan struct{})
	skipped := make(chan struct{}, 8)
	finished := make(chan int, 8)
	jobs := jobsOf(5, func(i int) func(context.Context) Result {
		switch i {
		case 0: // finishes after the first interrupt, and must be untouched
			return func(ctx context.Context) Result {
				<-gate
				if ctx.Err() != nil {
					return Result{Status: StatusFailed, Reason: "cancelled early"}
				}
				return Result{}
			}
		case 1: // waits for the second interrupt
			return func(ctx context.Context) Result {
				<-ctx.Done()
				if !errors.Is(context.Cause(ctx), ErrInterrupted) {
					return Result{Status: StatusFailed, Reason: "cause " + context.Cause(ctx).Error()}
				}
				return Result{Status: StatusFailed, Err: ctx.Err()}
			}
		}
		return result(StatusOK)
	})
	v := &recView{hook: func(e Event) {
		switch e.Phase {
		case PhaseSkipped:
			skipped <- struct{}{}
		case PhaseDone:
			finished <- e.Index
		}
	}}
	intr := make(chan struct{})
	out := make(chan Summary, 1)
	go func() {
		out <- Run(context.Background(), Options{Concurrency: 2, Interrupts: intr}, jobs, v)
	}()

	intr <- struct{}{}
	for range 3 {
		<-skipped // dev2..dev4 skipped: the pool has stopped starting
	}
	close(gate)
	if i := <-finished; i != 0 { // dev0 ended, with a live context
		t.Fatalf("job %d ended first", i)
	}
	intr <- struct{}{} // dev1 is still running: this one cuts it off
	s := <-out

	want := []Status{StatusOK, StatusInterrupted, StatusNotStarted, StatusNotStarted, StatusNotStarted}
	if !reflect.DeepEqual(statuses(s), want) {
		t.Fatalf("statuses %v, want %v", statuses(s), want)
	}
	if !s.Interrupted || s.Stop != StopInterrupted || s.NotStarted != 3 || s.OK != 1 || s.Failed != 1 {
		t.Errorf("summary %+v", s)
	}
	if got := s.StopLine(); got != "interrupted: 3 not started" {
		t.Errorf("StopLine %q", got)
	}
	if s.Entries[1].Result.Text() != "interrupted" {
		t.Errorf("text %q", s.Entries[1].Result.Text())
	}
	if s.ExitCode(false) != ExitInterrupted || s.ExitCode(true) != ExitInterrupted {
		t.Errorf("exit %d", s.ExitCode(false))
	}
}

// An interrupt with nothing left to start still ends in 130, and the running
// jobs finish on their own.
func TestRunInterruptWithNothingLeft(t *testing.T) {
	gate := make(chan struct{})
	seen := make(chan struct{})
	jobs := jobsOf(2, func(int) func(context.Context) Result {
		return func(ctx context.Context) Result {
			seen <- struct{}{}
			<-gate
			if ctx.Err() != nil {
				return Result{Status: StatusFailed}
			}
			return Result{}
		}
	})
	intr := make(chan struct{})
	out := make(chan Summary, 1)
	go func() {
		out <- Run(context.Background(), Options{Concurrency: 2, Interrupts: intr}, jobs, nil)
	}()
	<-seen
	<-seen
	intr <- struct{}{} // taken by the dispatcher before it reads any result
	close(gate)
	s := <-out
	if s.OK != 2 || s.NotStarted != 0 || !s.Interrupted || s.ExitCode(false) != ExitInterrupted {
		t.Errorf("summary %+v exit %d", s, s.ExitCode(false))
	}
	if got := s.StopLine(); got != "interrupted: 0 not started" {
		t.Errorf("StopLine %q", got)
	}
}

// Cancelling Run's own context is the second interrupt.
func TestRunContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	running := make(chan struct{})
	jobs := jobsOf(3, func(i int) func(context.Context) Result {
		return func(ctx context.Context) Result {
			if i == 0 {
				close(running)
			}
			<-ctx.Done()
			return Result{Status: StatusFailed, Err: ctx.Err()}
		}
	})
	out := make(chan Summary, 1)
	go func() { out <- Run(ctx, Options{Concurrency: 1}, jobs, nil) }()
	<-running
	cancel()
	s := <-out
	want := []Status{StatusInterrupted, StatusNotStarted, StatusNotStarted}
	if !reflect.DeepEqual(statuses(s), want) || !s.Interrupted || s.ExitCode(false) != ExitInterrupted {
		t.Errorf("statuses %v summary %+v", statuses(s), s)
	}
}

// A closed interrupt channel means no more interrupts, not endless ones.
func TestRunClosedInterruptChannel(t *testing.T) {
	intr := make(chan struct{})
	close(intr)
	jobs := jobsOf(3, func(int) func(context.Context) Result { return result(StatusOK) })
	s := Run(context.Background(), Options{Concurrency: 1, Interrupts: intr}, jobs, nil)
	if s.OK != 3 || s.Interrupted || s.ExitCode(false) != ExitOK {
		t.Errorf("%+v", s)
	}
}

// The view sees every job queued, then running and done in the clock's
// stamps, and the Board turns that into D67's words.
func TestRunViewAndBoard(t *testing.T) {
	jobs := []Job{
		{Name: "sw1", Do: result(StatusOK)},
		{Name: "sw2", Do: func(context.Context) Result { return Result{Differs: []string{"aaa"}} }},
		{Name: "sw3", Do: func(context.Context) Result { return Result{Status: StatusFailed, Reason: "unreachable"} }},
	}
	rec := &recView{}
	var board Board
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, multi{rec, &board})

	if want := []string{"sw1", "sw2", "sw3"}; !reflect.DeepEqual(rec.names, want) {
		t.Errorf("names %v", rec.names)
	}
	var seq []string
	for _, e := range rec.events {
		seq = append(seq, fmt.Sprintf("%s %d %s", e.Name, e.Phase, e.At.Format("15:04:05")))
	}
	want := []string{
		"sw1 0 12:00:01", "sw1 1 12:00:02",
		"sw2 0 12:00:03", "sw2 1 12:00:04",
		"sw3 0 12:00:05", "sw3 1 12:00:06",
	}
	if !reflect.DeepEqual(seq, want) {
		t.Errorf("events\n got %q\nwant %q", seq, want)
	}

	var lines []string
	for _, r := range board.Rows() {
		lines = append(lines, r.Name+": "+r.Text)
	}
	if want := []string{"sw1: ok", "sw2: ok, differs in aaa", "sw3: failed: unreachable"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("board %q", lines)
	}
	if d := board.Row(1).Duration(); d != time.Second {
		t.Errorf("duration %v", d)
	}
	if d := s.Entries[2].Duration(); d != time.Second {
		t.Errorf("entry duration %v", d)
	}
	if sum, ok := board.Summary(); !ok || sum.Line() != "1 ok, 1 differ, 1 failed" {
		t.Errorf("board summary %v %v", sum.Line(), ok)
	}
}

func TestBoardStates(t *testing.T) {
	var b Board
	b.Begin([]string{"a", "b", "c"})
	b.Update(Event{Index: 0, Name: "a", Phase: PhaseRunning})
	b.Update(Event{Index: 2, Name: "c", Phase: PhaseSkipped, Result: Result{Status: StatusNotStarted}})
	b.Update(Event{Index: 9, Name: "x", Phase: PhaseRunning}) // ignored
	var got []string
	for _, r := range b.Rows() {
		got = append(got, r.Text)
	}
	if want := []string{"running", "queued", "not started"}; !reflect.DeepEqual(got, want) {
		t.Errorf("%q", got)
	}
	if _, ok := b.Summary(); ok {
		t.Error("summary before End")
	}
	if b.Row(1).Settled || !b.Row(2).Settled {
		t.Error("settled flags")
	}
}

func TestStatusStrings(t *testing.T) {
	var got []string
	for s := StatusOK; s <= StatusNotStarted; s++ {
		got = append(got, s.String())
	}
	want := "ok failed auth-failed timeout interrupted not-started"
	if strings.Join(got, " ") != want {
		t.Errorf("%q", got)
	}
}

// multi fans one run out to several views.
type multi []View

func (m multi) Begin(names []string) {
	for _, v := range m {
		v.Begin(names)
	}
}
func (m multi) Update(e Event) {
	for _, v := range m {
		v.Update(e)
	}
}
func (m multi) End(s Summary) {
	for _, v := range m {
		v.End(s)
	}
}
