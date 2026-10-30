package batch

import (
	"time"
)

// StepMark is one phase a job marked (the function Mark): its name and when the
// dispatcher took it, by the injected clock.
type StepMark struct {
	Step string
	At   time.Time
}

// StepTime is how long one phase of a device took.
type StepTime struct {
	Step     string
	Duration time.Duration
}

// Timing is where one device's time went: the phases it reached in order,
// each with the time since the one before, and the total. A phase that did
// not happen is not in it. A device that did not succeed ends with the time
// since its last phase, named by how it ended ("failed", "auth-failed",
// "timeout", "interrupted"), so the phases add up to the total and the one
// it stuck in is seen. A phase that was marked more than once (a second
// connection) is one step with the times added, at the place of its first
// mark.
type Timing struct {
	Name  string
	Steps []StepTime
	Total time.Duration
}

// timingOf is the timing of a job that ran; false for one that did not
// start or has not ended.
func timingOf(name string, started, finished time.Time, marks []StepMark, r Result) (Timing, bool) {
	if started.IsZero() || finished.IsZero() {
		return Timing{}, false
	}
	t := Timing{Name: name, Total: finished.Sub(started)}
	prev := started
	for _, m := range marks {
		t.add(m.Step, m.At.Sub(prev))
		prev = m.At
	}
	if r.Status != StatusOK {
		t.add(r.Status.String(), finished.Sub(prev))
	}
	return t, true
}

// add adds d to the step, appending it when it is new.
func (t *Timing) add(step string, d time.Duration) {
	for i := range t.Steps {
		if t.Steps[i].Step == step {
			t.Steps[i].Duration += d
			return
		}
	}
	t.Steps = append(t.Steps, StepTime{step, d})
}

// Timing is the timing of the job by the marks it made; false for a job that
// did not run.
func (e Entry) Timing() (Timing, bool) {
	return timingOf(e.Name, e.Started, e.Finished, e.Marks, e.Result)
}

// Timing is the timing of the job as a view saw it end; false until it is
// done.
func (r Row) Timing() (Timing, bool) {
	return timingOf(r.Name, r.Started, r.Finished, r.Marks, r.Result)
}

// Timings are the timings of the jobs that ran, in the order of the list.
func (s Summary) Timings() []Timing {
	var out []Timing
	for _, e := range s.Entries {
		if t, ok := e.Timing(); ok {
			out = append(out, t)
		}
	}
	return out
}

// Slowest is the timing with the longest total, the first of equals; false
// for none.
func Slowest(ts []Timing) (Timing, bool) {
	var best Timing
	found := false
	for _, t := range ts {
		if !found || t.Total > best.Total {
			best, found = t, true
		}
	}
	return best, found
}

// MergeTimings joins the timings of several runs over the same devices (a
// pull, the check and the apply of one command): a device's phases add up by
// name in the order first seen, and so do its totals. The devices come in
// the order they first appear. The arguments are not changed.
func MergeTimings(runs ...[]Timing) []Timing {
	var out []Timing
	at := map[string]int{}
	for _, run := range runs {
		for _, t := range run {
			i, ok := at[t.Name]
			if !ok {
				at[t.Name] = len(out)
				out = append(out, Timing{Name: t.Name})
				i = len(out) - 1
			}
			out[i].Total += t.Total
			for _, s := range t.Steps {
				out[i].add(s.Step, s.Duration)
			}
		}
	}
	return out
}
