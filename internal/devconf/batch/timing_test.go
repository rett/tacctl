package batch

import (
	"context"
	"testing"
	"time"
)

// A job that marks its phases gets the time between the marks, by the
// injected clock: every clock reading is one second, so the readings of one
// sequential job are the start, one per mark and the end.
func TestMarksGiveThePhaseDurations(t *testing.T) {
	jobs := []Job{{Name: "sw1", Do: func(ctx context.Context) Result {
		Mark(ctx, "connect")
		Mark(ctx, "login")
		Mark(ctx, "read")
		return Result{}
	}}}
	v := &recView{}
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, v)
	ts := s.Timings()
	if len(ts) != 1 {
		t.Fatalf("timings: %+v", ts)
	}
	tm := ts[0]
	if tm.Name != "sw1" || tm.Total != 4*time.Second {
		t.Fatalf("timing: %+v", tm)
	}
	want := []StepTime{{"connect", time.Second}, {"login", time.Second}, {"read", time.Second}}
	if len(tm.Steps) != len(want) {
		t.Fatalf("steps: %+v", tm.Steps)
	}
	for i, w := range want {
		if tm.Steps[i] != w {
			t.Errorf("step %d: %+v, want %+v", i, tm.Steps[i], w)
		}
	}
}

// A mark is no event: a view sees the same events as without marks, and the
// device's row says nothing more than it did (the default output of every
// verb is the same with and without the marks).
func TestMarksAreNotViewEvents(t *testing.T) {
	run := func(mark bool) []Event {
		jobs := []Job{{Name: "sw1", Do: func(ctx context.Context) Result {
			if mark {
				Mark(ctx, "connect")
			}
			Progress(ctx, "checked")
			return Result{}
		}}}
		v := &recView{}
		Run(context.Background(), Options{Concurrency: 1, Clock: func() time.Time { return time.Time{} }}, jobs, v)
		for i := range v.events {
			v.events[i].Marks = nil
		}
		return v.events
	}
	a, b := run(false), run(true)
	if len(a) != len(b) {
		t.Fatalf("events differ: %+v vs %+v", a, b)
	}
	for i := range a {
		if a[i].Phase != b[i].Phase || a[i].Step != b[i].Step {
			t.Errorf("event %d: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// The done event and the board's row carry the marks, so a view can print a
// device's timing as the device ends.
func TestDoneEventAndRowCarryTheMarks(t *testing.T) {
	jobs := []Job{{Name: "sw1", Do: func(ctx context.Context) Result {
		Mark(ctx, "connect")
		return Result{}
	}}}
	b := &Board{}
	v := &recView{hook: b.Update}
	b.Begin([]string{"sw1"})
	Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, v)
	var done Event
	for _, e := range v.events {
		if e.Phase == PhaseDone {
			done = e
		}
	}
	if len(done.Marks) != 1 || done.Marks[0].Step != "connect" {
		t.Fatalf("done event marks: %+v", done.Marks)
	}
	tm, ok := b.Row(0).Timing()
	if !ok || tm.Total != 2*time.Second || len(tm.Steps) != 1 || tm.Steps[0].Duration != time.Second {
		t.Fatalf("row timing: %+v ok=%v", tm, ok)
	}
}

// A phase that did not happen is absent, not zero: a job that marks fewer
// phases has fewer steps, and a job that marks none has no step at all.
func TestAbsentPhasesAreAbsent(t *testing.T) {
	jobs := []Job{
		{Name: "pull", Do: func(ctx context.Context) Result {
			Mark(ctx, "connect")
			Mark(ctx, "read")
			return Result{}
		}},
		{Name: "apply", Do: func(ctx context.Context) Result {
			Mark(ctx, "connect")
			Mark(ctx, "read")
			Mark(ctx, "commit")
			return Result{}
		}},
		{Name: "bare", Do: result(StatusOK)},
	}
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, nil)
	ts := s.Timings()
	if len(ts) != 3 {
		t.Fatalf("timings: %+v", ts)
	}
	names := func(tm Timing) (out []string) {
		for _, st := range tm.Steps {
			out = append(out, st.Step)
		}
		return
	}
	if got := names(ts[0]); len(got) != 2 || got[0] != "connect" || got[1] != "read" {
		t.Errorf("pull steps: %v", got)
	}
	if got := names(ts[1]); len(got) != 3 || got[2] != "commit" {
		t.Errorf("apply steps: %v", got)
	}
	if got := names(ts[2]); len(got) != 0 {
		t.Errorf("bare steps: %v", got)
	}
}

// A device that failed shows the phases it reached, then the time it spent in
// the one it failed in, named by how it ended.
func TestFailedDeviceShowsThePhasesReached(t *testing.T) {
	jobs := []Job{
		{Name: "sw1", Do: func(ctx context.Context) Result {
			Mark(ctx, "connect")
			return Result{Status: StatusAuthFailed, Reason: "refused"}
		}},
		{Name: "sw2", Do: func(ctx context.Context) Result {
			return Result{Status: StatusFailed, Reason: "unreachable"}
		}},
	}
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, nil)
	ts := s.Timings()
	if len(ts) != 2 {
		t.Fatalf("timings: %+v", ts)
	}
	if len(ts[0].Steps) != 2 || ts[0].Steps[0].Step != "connect" || ts[0].Steps[1].Step != "auth-failed" {
		t.Errorf("sw1: %+v", ts[0].Steps)
	}
	if len(ts[1].Steps) != 1 || ts[1].Steps[0].Step != "failed" || ts[1].Steps[0].Duration != time.Second {
		t.Errorf("sw2: %+v", ts[1].Steps)
	}
	// the steps add up to the total
	for _, tm := range ts {
		var sum time.Duration
		for _, st := range tm.Steps {
			sum += st.Duration
		}
		if sum != tm.Total {
			t.Errorf("%s: steps %v, total %v", tm.Name, sum, tm.Total)
		}
	}
}

// A job that was never started has no timing.
func TestNotStartedHasNoTiming(t *testing.T) {
	jobs := []Job{
		{Name: "sw1", Do: result(StatusFailed)},
		{Name: "sw2", Do: result(StatusOK)},
	}
	s := Run(context.Background(), Options{Concurrency: 1, MaxFailures: 1, Clock: stepClock()}, jobs, nil)
	ts := s.Timings()
	if len(ts) != 1 || ts[0].Name != "sw1" {
		t.Fatalf("timings: %+v", ts)
	}
}

// The same phase marked twice (a second connection) adds up in the order of
// its first mark.
func TestRepeatedPhasesAddUp(t *testing.T) {
	jobs := []Job{{Name: "sw1", Do: func(ctx context.Context) Result {
		Mark(ctx, "connect")
		Mark(ctx, "read")
		Mark(ctx, "connect")
		return Result{}
	}}}
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, nil)
	tm := s.Timings()[0]
	if len(tm.Steps) != 2 || tm.Steps[0] != (StepTime{"connect", 2 * time.Second}) || tm.Steps[1] != (StepTime{"read", time.Second}) {
		t.Fatalf("steps: %+v", tm.Steps)
	}
}

// Quiet takes the marks of a part of a job out: its time stays in the phase
// that the next mark closes.
func TestQuietDropsMarks(t *testing.T) {
	jobs := []Job{{Name: "sw1", Do: func(ctx context.Context) Result {
		Mark(Quiet(ctx), "connect")
		Mark(ctx, "verify")
		return Result{}
	}}}
	s := Run(context.Background(), Options{Concurrency: 1, Clock: stepClock()}, jobs, nil)
	tm := s.Timings()[0]
	if len(tm.Steps) != 1 || tm.Steps[0].Step != "verify" {
		t.Fatalf("steps: %+v", tm.Steps)
	}
}

// Mark outside a job is a no-op.
func TestMarkOutsideAJob(t *testing.T) {
	Mark(context.Background(), "connect")
	Mark(Quiet(context.Background()), "connect")
}

func TestSlowest(t *testing.T) {
	ts := []Timing{{Name: "a", Total: time.Second}, {Name: "b", Total: 3 * time.Second}, {Name: "c", Total: 3 * time.Second}}
	if got, ok := Slowest(ts); !ok || got.Name != "b" {
		t.Errorf("slowest: %+v ok=%v (the first of equals)", got, ok)
	}
	if _, ok := Slowest(nil); ok {
		t.Error("no timings have no slowest")
	}
}

// Timings of several runs of one device (the check and the apply of one
// run) are one timing: the phases add up by name in the order first seen and
// so do the totals.
func TestMergeTimings(t *testing.T) {
	a := []Timing{
		{Name: "sw1", Total: 5 * time.Second, Steps: []StepTime{{"connect", 2 * time.Second}, {"read", 3 * time.Second}}},
		{Name: "sw2", Total: time.Second, Steps: []StepTime{{"connect", time.Second}}},
	}
	b := []Timing{
		{Name: "sw1", Total: 6 * time.Second, Steps: []StepTime{{"connect", time.Second}, {"commit", 5 * time.Second}}},
		{Name: "sw3", Total: time.Second, Steps: []StepTime{{"read", time.Second}}},
	}
	got := MergeTimings(a, b)
	if len(got) != 3 || got[0].Name != "sw1" || got[1].Name != "sw2" || got[2].Name != "sw3" {
		t.Fatalf("merged: %+v", got)
	}
	m := got[0]
	want := []StepTime{{"connect", 3 * time.Second}, {"read", 3 * time.Second}, {"commit", 5 * time.Second}}
	if m.Total != 11*time.Second || len(m.Steps) != 3 || m.Steps[0] != want[0] || m.Steps[1] != want[1] || m.Steps[2] != want[2] {
		t.Errorf("sw1: %+v", m)
	}
	// the inputs are not changed
	if len(a[0].Steps) != 2 || a[0].Total != 5*time.Second {
		t.Errorf("input changed: %+v", a[0])
	}
}
