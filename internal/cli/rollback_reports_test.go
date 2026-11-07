package cli

import (
	"strings"
	"testing"
)

// The limits of the stored reports (0.2.26) are keys of tacctl.yaml every
// older release refuses: every target removes them after a snapshot, needs no
// --yes for them, and says the reports in the homes stay.

func TestRollbackRemovesTheReportLimitsOfTheConfig(t *testing.T) {
	for _, target := range []string{"0.2.24", "0.2.23", "0.2.22"} {
		t.Run(target, func(t *testing.T) {
			hs := rollback0224State(t)
			hs.step("", "config", "reports", "max-size", "20Mi")
			hs.step("", "config", "reports", "max-count", "0")
			hs.step("", "server", "name", "core-1")
			before := tree(t, hs.dir)
			hs.run(hs.runner(), "rollback", target)
			hs.expect(0, "This was a dry run: nothing was changed.", "")
			out := hs.all()
			for _, want := range []string{"remove reports.max_size", "remove reports.max_count", "--apply takes a snapshot of the state first", "[does]"} {
				if !strings.Contains(out, want) {
					t.Errorf("the dry run lacks %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "--yes") {
				t.Errorf("the dry run asks for --yes:\n%s", out)
			}
			if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
				t.Errorf("the dry run changed %q", got)
			}
			snaps := hs.snapshots()
			hs.run(hs.runner(), "rollback", target, "--apply")
			hs.expect(0, "tacctl upgrade --branch "+target, "")
			out = hs.all()
			for _, want := range []string{"holds the 0.2.26 state", "The reports in the users' homes stay", "'tacctl config reports max-size' or 'max-count'",
				target + " has no 'device reports' verbs"} {
				if !strings.Contains(out, want) {
					t.Errorf("--apply lacks %q:\n%s", want, out)
				}
			}
			if hs.snapshots() != snaps+1 {
				t.Errorf("snapshots %d -> %d: one must be taken, the keys are dropped", snaps, hs.snapshots())
			}
			if o := hs.overrides(); strings.Contains(o, "reports") || !strings.Contains(o, "name: core-1") {
				t.Errorf("tacctl.yaml after --apply:\n%s", o)
			}
		})
	}
}

// With no limit set, a rollback takes no snapshot for them and still ends with
// the note about the reports.
func TestRollbackWithoutReportLimitsTakesNoSnapshotForThem(t *testing.T) {
	hs := rollback0224State(t)
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.24", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.24 can read.", "")
	if hs.snapshots() != snaps {
		t.Error("a snapshot was taken")
	}
	if !strings.Contains(hs.all(), "The reports in the users' homes stay") {
		t.Errorf("no note about the reports:\n%s", hs.all())
	}
}
