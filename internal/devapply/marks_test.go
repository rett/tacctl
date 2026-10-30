package devapply

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/batch"
)

// marksOf runs do as the one job of a batch and returns the steps the driver
// marked, in order. The device is dialled before the job, so the dial's own
// marks (devssh's) are not among them.
func marksOf(t *testing.T, do func(ctx context.Context) Outcome) []string {
	t.Helper()
	clock := testStart
	var out Outcome
	s := batch.Run(context.Background(), batch.Options{Concurrency: 1, Clock: func() time.Time {
		clock = clock.Add(time.Second)
		return clock
	}}, []batch.Job{{Name: "example-sw1", Do: func(ctx context.Context) batch.Result {
		out = do(ctx)
		return batch.Result{}
	}}}, nil)
	_ = out
	var steps []string
	for _, m := range s.Entries[0].Marks {
		steps = append(steps, m.Step)
	}
	return steps
}

// An apply marks the end of each phase it passed: the pre-flight reads, the
// read and the plan, the load of the candidate, the commit check, the
// confirmed commit, the verification on a fresh login (whose own connect and
// login are part of it, not phases of the device's) and the confirm.
func TestApplyMarksItsPhases(t *testing.T) {
	d := newDevice(t, nil)
	p := &planner{desired: desiredLines()}
	rev := d.reviewed(p)
	in := d.input(p)
	var o Outcome
	got := marksOf(t, func(ctx context.Context) Outcome {
		o = Driver{}.Apply(ctx, in, rev)
		return o
	})
	wantExit(t, o, ExitApplied, ResultApplied)
	want := []string{"preflight", "read", "load", "check", "commit", "verify", "confirm", "record"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("marks %v, want %v", got, want)
	}
}

// A check stops after the commit check: it marks no commit or confirm.
func TestCheckMarksUpToTheCheck(t *testing.T) {
	d := newDevice(t, nil)
	in := d.input(&planner{desired: desiredLines()})
	var o Outcome
	got := marksOf(t, func(ctx context.Context) Outcome {
		o = Driver{}.Check(ctx, in)
		return o
	})
	wantExit(t, o, ExitChecked, ResultChecked)
	want := []string{"preflight", "read", "load", "check"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("marks %v, want %v", got, want)
	}
}

// A device with nothing to change has only read: the phases it did not reach
// are absent.
func TestNoChangeMarksOnlyTheRead(t *testing.T) {
	d := newDevice(t, nil)
	p := &planner{desired: desiredLines()}
	apply(t, d, p, nil)
	in := d.input(p)
	got := marksOf(t, func(ctx context.Context) Outcome {
		return Driver{}.Check(ctx, in)
	})
	want := []string{"preflight", "read"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("marks %v, want %v", got, want)
	}
}
