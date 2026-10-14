package batch

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

// runLog is an ordered log shared by jobs and a fake Sleep.
type runLog struct {
	mu sync.Mutex
	l  []string
}

func (r *runLog) add(s string) {
	r.mu.Lock()
	r.l = append(r.l, s)
	r.mu.Unlock()
}

func (r *runLog) get() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.l...)
}

// shaped builds jobs named dev0.. with the given shapes; each logs
// "run:<name>" and returns what outcome says for its index (default ok).
func shaped(log *runLog, shapes []string, outcome map[int]Status) []Job {
	jobs := make([]Job, len(shapes))
	for i, sh := range shapes {
		jobs[i] = Job{Name: fmt.Sprintf("dev%d", i), Shape: sh, Do: func(context.Context) Result {
			log.add(fmt.Sprintf("run:dev%d", i))
			return Result{Status: outcome[i]}
		}}
	}
	return jobs
}

func TestCanaryByShape(t *testing.T) {
	const (
		ok   = StatusOK
		fail = StatusFailed
	)
	for _, c := range []struct {
		name      string
		shapes    []string
		outcome   map[int]Status
		canary    bool
		maxFail   int
		order     []string
		statuses  []Status
		skipped   int
		notStart  int
		failed    int
		stopWhy   Stop
		skipNames []string // jobs whose Reason names their canary
	}{
		{
			name:     "all ok, canaries first then list order",
			shapes:   []string{"A", "A", "B", "B", "A"},
			canary:   true,
			order:    []string{"dev0", "dev2", "dev1", "dev3", "dev4"},
			statuses: []Status{ok, ok, ok, ok, ok},
		},
		{
			name:     "canary off: shapes ignored, list order, no skip",
			shapes:   []string{"A", "A", "B", "B", "A"},
			outcome:  map[int]Status{0: fail},
			order:    []string{"dev0", "dev1", "dev2", "dev3", "dev4"},
			statuses: []Status{fail, ok, ok, ok, ok},
			failed:   1,
		},
		{
			name:      "canary of A fails: A skipped, B proceeds",
			shapes:    []string{"A", "A", "B", "B", "A"},
			outcome:   map[int]Status{0: fail},
			canary:    true,
			order:     []string{"dev0", "dev2", "dev3"},
			statuses:  []Status{fail, StatusSkipped, ok, ok, StatusSkipped},
			skipped:   2,
			failed:    1,
			skipNames: []string{"dev1", "dev4"},
		},
		{
			name:     "canary of B fails with a failure limit: the run stops",
			shapes:   []string{"A", "A", "B", "B", "A"},
			outcome:  map[int]Status{2: fail},
			canary:   true,
			maxFail:  1,
			order:    []string{"dev0", "dev2"},
			statuses: []Status{ok, StatusNotStarted, fail, StatusSkipped, StatusNotStarted},
			skipped:  1,
			notStart: 2,
			failed:   1,
			stopWhy:  StopMaxFailures,
		},
		{
			name:     "a follower failing does not skip its shape",
			shapes:   []string{"A", "A", "A"},
			outcome:  map[int]Status{1: fail},
			canary:   true,
			order:    []string{"dev0", "dev1", "dev2"},
			statuses: []Status{ok, fail, ok},
			failed:   1,
		},
		{
			name:     "no shape: ungated, never skipped, after the canaries",
			shapes:   []string{"", "A", "", "A"},
			outcome:  map[int]Status{1: fail},
			canary:   true,
			order:    []string{"dev1", "dev0", "dev2"},
			statuses: []Status{ok, fail, ok, StatusSkipped},
			skipped:  1,
			failed:   1,
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var log runLog
			v := &recView{}
			sum := Run(context.Background(), Options{Canary: c.canary, MaxFailures: c.maxFail, Concurrency: 1},
				shaped(&log, c.shapes, c.outcome), v)
			var order []string
			for _, s := range log.get() {
				order = append(order, s[len("run:"):])
			}
			if !reflect.DeepEqual(order, c.order) {
				t.Errorf("order = %v, want %v", order, c.order)
			}
			if got := statuses(sum); !reflect.DeepEqual(got, c.statuses) {
				t.Errorf("statuses = %v, want %v", got, c.statuses)
			}
			if sum.Skipped != c.skipped || sum.NotStarted != c.notStart || sum.Failed != c.failed || sum.Stop != c.stopWhy {
				t.Errorf("skipped %d notstarted %d failed %d stop %v, want %d %d %d %v",
					sum.Skipped, sum.NotStarted, sum.Failed, sum.Stop, c.skipped, c.notStart, c.failed, c.stopWhy)
			}
			for _, e := range v.events {
				if e.Result.Status == StatusSkipped {
					if e.Phase != PhaseSkipped || e.Result.Reason != "canary dev0 failed" && e.Result.Reason != "canary dev1 failed" &&
						e.Result.Reason != "canary dev2 failed" {
						t.Errorf("skip event of %s: %+v", e.Name, e)
					}
				}
			}
			if v.end == nil || !reflect.DeepEqual(*v.end, sum) {
				t.Error("End did not get the summary Run returned")
			}
		})
	}
}

// With a wide pool no follower starts before its canary's PhaseDone; the
// events the view sees are the record.
func TestCanaryFollowersWaitForTheirCanary(t *testing.T) {
	shapes := []string{"A", "A", "A", "B", "B", "A", "B"}
	var log runLog
	v := &recView{}
	sum := Run(context.Background(), Options{Canary: true, Concurrency: 7},
		shaped(&log, shapes, nil), v)
	if sum.OK != len(shapes) || sum.Pool != 7 {
		t.Fatalf("summary %+v", sum)
	}
	doneAt := map[string]int{}
	for k, e := range v.events {
		if e.Phase == PhaseDone {
			doneAt[e.Name] = k
		}
	}
	canaryOf := map[string]string{"A": "dev0", "B": "dev3"}
	for k, e := range v.events {
		if e.Phase != PhaseRunning {
			continue
		}
		c := canaryOf[shapes[e.Index]]
		if e.Name == c {
			continue
		}
		if d, ok := doneAt[c]; !ok || d > k {
			t.Errorf("%s started (event %d) before its canary %s ended (%d)", e.Name, k, c, d)
		}
	}
}

// A cancelled context stops the run: what was not started is NotStarted
// (not Skipped, whatever the canary did) and the run is Interrupted.
func TestCanaryCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	jobs := []Job{
		{Name: "c1", Shape: "A", Do: func(ctx context.Context) Result {
			<-ctx.Done()
			return Result{Status: StatusFailed, Reason: "cut"}
		}},
		{Name: "f1", Shape: "A", Do: result(StatusOK)},
		{Name: "c2", Shape: "B", Do: func(ctx context.Context) Result {
			<-ctx.Done()
			return Result{Status: StatusFailed, Reason: "cut"}
		}},
		{Name: "f2", Shape: "B", Do: result(StatusOK)},
	}
	v := &recView{hook: func(e Event) {
		if e.Phase == PhaseRunning && e.Name == "c2" {
			cancel()
		}
	}}
	sum := Run(ctx, Options{Canary: true, Concurrency: 2}, jobs, v)
	want := []Status{StatusInterrupted, StatusNotStarted, StatusInterrupted, StatusNotStarted}
	if got := statuses(sum); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses = %v, want %v", got, want)
	}
	if !sum.Interrupted || sum.Stop != StopInterrupted || sum.Skipped != 0 || sum.NotStarted != 2 {
		t.Errorf("summary %+v", sum)
	}
	if sum.ExitCode(false) != ExitInterrupted {
		t.Errorf("exit = %d", sum.ExitCode(false))
	}
}

func TestPauseOrdering(t *testing.T) {
	for _, c := range []struct {
		name   string
		shapes []string
		canary bool
		pool   int
		pause  time.Duration
		want   []string
	}{
		{
			name:   "serial: a pause between every pair, none after the last",
			shapes: []string{"", "", ""},
			pool:   1, pause: time.Minute,
			want: []string{"run:dev0", "sleep:1m0s", "run:dev1", "sleep:1m0s", "run:dev2"},
		},
		{
			name:   "canary waves are separated too",
			shapes: []string{"A", "A", "B"},
			canary: true, pool: 1, pause: 5 * time.Second,
			want: []string{"run:dev0", "sleep:5s", "run:dev2", "sleep:5s", "run:dev1"},
		},
		{
			name:   "no pause set: no sleep",
			shapes: []string{"", ""},
			pool:   1,
			want:   []string{"run:dev0", "run:dev1"},
		},
		{
			name:   "wide pool: the first fill is not delayed",
			shapes: []string{"", ""},
			pool:   2, pause: time.Second,
			want: []string{"run:dev0", "run:dev1"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			var log runLog
			opt := Options{Canary: c.canary, Concurrency: c.pool, Pause: c.pause,
				Sleep: func(_ context.Context, d time.Duration) { log.add("sleep:" + d.String()) }}
			sum := Run(context.Background(), opt, shaped(&log, c.shapes, nil), nil)
			if sum.OK != len(c.shapes) {
				t.Fatalf("summary %+v", sum)
			}
			got := log.get()
			if c.pool > 1 {
				// the two jobs of the first fill race; only the set matters
				if len(got) != 2 {
					t.Fatalf("log = %v", got)
				}
				return
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("log = %v, want %v", got, c.want)
			}
		})
	}
}

// A first interrupt ends a pause at once and starts nothing more.
func TestPauseInterrupted(t *testing.T) {
	var log runLog
	intr := make(chan struct{}, 1)
	woke := make(chan struct{})
	opt := Options{Concurrency: 1, Pause: time.Hour, Interrupts: intr,
		Sleep: func(ctx context.Context, d time.Duration) {
			log.add("sleep")
			intr <- struct{}{}
			<-ctx.Done() // the stop must cancel the pause
			close(woke)
		}}
	sum := Run(context.Background(), opt, shaped(&log, []string{"", "", ""}, nil), nil)
	<-woke // Run does not wait for an abandoned pause; the stop cancelled it
	if got, want := log.get(), []string{"run:dev0", "sleep"}; !reflect.DeepEqual(got, want) {
		t.Errorf("log = %v, want %v", got, want)
	}
	want := []Status{StatusOK, StatusNotStarted, StatusNotStarted}
	if got := statuses(sum); !reflect.DeepEqual(got, want) {
		t.Errorf("statuses = %v, want %v", got, want)
	}
	if !sum.Interrupted || sum.NotStarted != 2 {
		t.Errorf("summary %+v", sum)
	}
}

// Without Sleep the pause is a real timer; a tiny one proves the path.
func TestPauseRealTimer(t *testing.T) {
	var log runLog
	sum := Run(context.Background(), Options{Concurrency: 1, Pause: time.Millisecond},
		shaped(&log, []string{"", ""}, nil), nil)
	if sum.OK != 2 {
		t.Errorf("summary %+v", sum)
	}
}

func TestProgressAndBoard(t *testing.T) {
	jobs := []Job{{Name: "d", Do: func(ctx context.Context) Result {
		Progress(ctx, "checked")
		Progress(ctx, "committed, verifying")
		Progress(ctx, "confirming")
		return Result{Status: StatusOK}
	}}}
	var b Board
	var texts []string
	v := &recView{hook: func(e Event) {
		b.Update(e)
		texts = append(texts, b.Row(0).Text)
	}}
	b.Begin([]string{"d"})
	sum := Run(context.Background(), Options{}, jobs, v)
	if sum.OK != 1 {
		t.Fatalf("summary %+v", sum)
	}
	var steps []string
	for _, e := range v.events {
		if e.Phase == PhaseProgress {
			steps = append(steps, e.Step)
		}
	}
	if want := []string{"checked", "committed, verifying", "confirming"}; !reflect.DeepEqual(steps, want) {
		t.Errorf("steps = %v, want %v", steps, want)
	}
	want := []string{"running", "running: checked", "running: committed, verifying", "running: confirming", "ok"}
	if !reflect.DeepEqual(texts, want) {
		t.Errorf("board texts = %v, want %v", texts, want)
	}
	if v.events[0].Phase != PhaseRunning || v.events[len(v.events)-1].Phase != PhaseDone {
		t.Errorf("events out of order: %+v", v.events)
	}
	Progress(context.Background(), "ignored") // no reporter: a no-op
}

func TestBoardSkippedRow(t *testing.T) {
	var b Board
	jobs := []Job{
		{Name: "c", Shape: "A", Do: result(StatusFailed)},
		{Name: "f", Shape: "A", Do: result(StatusOK)},
	}
	Run(context.Background(), Options{Canary: true}, jobs, &b)
	r := b.Row(1)
	if !r.Settled || r.Text != "skipped: canary c failed" {
		t.Errorf("row = %+v", r)
	}
	if s := StatusSkipped.String(); s != "skipped" || StatusSkipped.Failure() {
		t.Errorf("StatusSkipped: %q failure=%v", s, StatusSkipped.Failure())
	}
}

func TestRolledBackAndPendingCounters(t *testing.T) {
	jobs := []Job{
		{Name: "a", Do: func(context.Context) Result {
			return Result{Status: StatusFailed, Reason: "verify failed", RolledBack: true}
		}},
		{Name: "b", Do: func(context.Context) Result {
			return Result{Status: StatusFailed, Reason: "lost the device", Pending: true}
		}},
		{Name: "c", Do: result(StatusOK)},
	}
	sum := Run(context.Background(), Options{Concurrency: 1}, jobs, nil)
	if sum.RolledBack != 1 || sum.Pending != 1 || sum.Failed != 2 || sum.OK != 1 {
		t.Errorf("summary %+v", sum)
	}
	if got, want := sum.Entries[0].Result.Text(), "failed: verify failed (rolled back)"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
	if got, want := sum.Entries[1].Result.Text(), "failed: lost the device (PENDING)"; got != want {
		t.Errorf("text = %q, want %q", got, want)
	}
	if sum.ExitCode(false) != ExitFailed {
		t.Errorf("exit = %d", sum.ExitCode(false))
	}
}
