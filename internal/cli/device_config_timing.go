package cli

// '--timing' of 'device config pull', 'diff --pull', 'plan --pull' and
// 'apply': where the time of each device went. The phases come from the batch
// runner's marks (batch.Mark; devssh, devapply and the pull mark them as they
// pass), by the runner's injected clock; nothing is stored, and a run
// without the option prints what it printed before.

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf/batch"
)

// batchClock is the clock the batch stamps its events with, so the durations
// of a run are the time the invocation sees (a test replaces it:
// hooks.batchClock).
func (inv *invocation) batchClock() func() time.Time {
	if inv.hooks != nil && inv.hooks.batchClock != nil {
		return inv.hooks.batchClock
	}
	return inv.app.Knobs.Now
}

// timingText is a duration as the timing shows it: whole milliseconds under
// a second, else seconds with one decimal.
func timingText(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// timingLines are the lines of the text summary: one per device that ran,
// its phases in the order they happened with their time and its total, then
// the slowest device. None when no device ran.
func timingLines(ts []batch.Timing) []string {
	slow, ok := batch.Slowest(ts)
	if !ok {
		return nil
	}
	width := 0
	for _, t := range ts {
		width = max(width, len(t.Name))
	}
	lines := []string{"  timing:"}
	for _, t := range ts {
		var parts []string
		for _, s := range t.Steps {
			parts = append(parts, cleanLine(s.Step)+" "+timingText(s.Duration))
		}
		parts = append(parts, "total "+timingText(t.Total))
		lines = append(lines, fmt.Sprintf("    %-*s  %s", width, t.Name, strings.Join(parts, "  ")))
	}
	return append(lines, "  slowest: "+slow.Name+" ("+timingText(slow.Total)+")")
}

// timingStepJSON is one phase of a device's timing in --json.
type timingStepJSON struct {
	Step string `json:"step"`
	MS   int64  `json:"ms"`
}

// timingsJSON is the "timings" object of a device in --json: its phases in
// order with their milliseconds, and the total. Slowest marks the slowest
// device where all the devices are printed together.
type timingsJSON struct {
	TotalMS int64            `json:"total_ms"`
	Steps   []timingStepJSON `json:"steps"`
	Slowest bool             `json:"slowest,omitempty"`
}

// timingsOf is the object of a device's timing.
func timingsOf(t batch.Timing) *timingsJSON {
	j := &timingsJSON{TotalMS: t.Total.Milliseconds(), Steps: []timingStepJSON{}}
	for _, s := range t.Steps {
		j.Steps = append(j.Steps, timingStepJSON{Step: s.Step, MS: s.Duration.Milliseconds()})
	}
	return j
}

// timingsByName are the objects of the timings by device name, the slowest
// marked.
func timingsByName(ts []batch.Timing) map[string]*timingsJSON {
	out := map[string]*timingsJSON{}
	for _, t := range ts {
		out[t.Name] = timingsOf(t)
	}
	if slow, ok := batch.Slowest(ts); ok {
		out[slow.Name].Slowest = true
	}
	return out
}

// timingSummaryJSON is the "timings" object of a summary line: the slowest
// device and its total (nil when no device ran).
func timingSummaryJSON(ts []batch.Timing) map[string]any {
	slow, ok := batch.Slowest(ts)
	if !ok {
		return nil
	}
	return map[string]any{"slowest": slow.Name, "slowest_ms": slow.Total.Milliseconds()}
}

// printTiming prints the timing of a run as its summary does: the lines, or
// with asJSON one object (the summary of a verb that prints none of its own,
// whose devices are in the objects of the timings). It goes where the verb's
// notes go, to standard error when err.
func (inv *invocation) printTiming(ts []batch.Timing, asJSON, err bool) {
	put := inv.echo
	if err {
		put = inv.stderrLine
	}
	if !asJSON {
		for _, l := range timingLines(ts) {
			put(l)
		}
		return
	}
	m := timingSummaryJSON(ts)
	if m == nil {
		return
	}
	devs := []map[string]any{}
	for _, t := range ts {
		j := timingsOf(t)
		devs = append(devs, map[string]any{"name": t.Name, "total_ms": j.TotalMS, "steps": j.Steps})
	}
	m["devices"] = devs
	b, _ := json.Marshal(map[string]any{"timings": m})
	put(string(b))
}
