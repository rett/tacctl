package plan

import (
	"regexp"
	"strings"
	"testing"
)

// The break-glass hold in a plan (D124): the planner is given the fact and
// reports it; the cover page marks the device; the three lines of the
// after-steps stand whether or not the device is held.
func TestBreakglassHeldReportCoverAndAfterSteps(t *testing.T) {
	for _, name := range []string{"juniper.synthetic-lab", "cisco.reference-lab"} {
		var f fixture
		for _, c := range fixtures(t) {
			if c.name == name {
				f = c
			}
		}
		exp, cur, plain := f.load(t)
		free, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatal(err)
		}
		o := f.options()
		o.BreakglassHeld = &BreakglassHold{Since: "2026-10-10 14:02", By: "alice"}
		held, err := Plan(f.vendor, exp, cur, plain, o)
		if err != nil {
			t.Fatal(err)
		}
		h, w := f.header(), Wrapper{ConfirmMinutes: 5}
		rep := regexp.MustCompile(`\n[#!] *`).ReplaceAllString(Report(held, h, w), " ")
		for _, want := range []string{"BREAK-GLASS HELD on this device since 2026-10-10 14:02 by alice", "tacctl breakglass release " + h.Device} {
			if !strings.Contains(rep, want) {
				t.Errorf("%s: the report lacks %q:\n%s", name, want, rep)
			}
		}
		if strings.Contains(Report(free, h, w), "BREAK-GLASS") {
			t.Errorf("%s: a device that is not held is reported as held", name)
		}
		// Only the report and the cover differ; the region is the same.
		if Region(held, h, w) != Region(free, h, w) {
			t.Errorf("%s: the hold changed the region", name)
		}
		// The three lines are in both, at the very end of the after-steps.
		for _, d := range []Delta{free, held} {
			after := After(d, h, w)
			lines := strings.Split(strings.TrimRight(after, "\n"), "\n")
			if len(lines) < 3 {
				t.Fatalf("%s: after-steps of %d lines", name, len(lines))
			}
			last := lines[len(lines)-3:]
			if !strings.Contains(last[0], "Locked out (the paste cut your session and no login works)? A superuser runs: tacctl breakglass hold "+h.Device+" --reason") ||
				!strings.Contains(last[1], "local") || !strings.Contains(last[2], "tacctl breakglass release "+h.Device) {
				t.Errorf("%s: the last lines of the after-steps:\n%s", name, strings.Join(last, "\n"))
			}
		}
		if s := StatusFor(held, h); !s.BreakglassHeld {
			t.Errorf("%s: the status is not marked", name)
		}
		if !strings.Contains(Cover([]DeviceStatus{StatusFor(held, h), StatusFor(free, h)}), "[break-glass held]") {
			t.Errorf("%s: the cover page does not mark the device", name)
		}
		if strings.Count(Cover([]DeviceStatus{StatusFor(free, h)}), "break-glass") != 0 {
			t.Errorf("%s: the cover page of a free device is marked", name)
		}
	}
}
