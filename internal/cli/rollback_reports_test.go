package cli

import (
	"os"
	"path/filepath"
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
			for _, want := range []string{"holds the 0.2.28 state", "The reports in the users' homes stay", "'tacctl config reports max-size', 'config reports max-count' or 'tacctl user reports-limit'",
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

// The users' own limits are user data a rollback drops: the dry run lists each
// user with the values, --apply refuses without --yes, takes a snapshot that
// holds them, removes the keys and names the users in the audit line and in a
// note that says how they are set again.
func TestRollbackRemovesTheUsersReportLimits(t *testing.T) {
	for _, target := range []string{"0.2.24", "0.2.22"} {
		t.Run(target, func(t *testing.T) {
			hs := rollback0224State(t)
			hs.step("", "user", "reports-limit", "bob", "max-size", "20Mi")
			hs.step("", "user", "reports-limit", "bob", "max-count", "50")
			hs.step("", "user", "reports-limit", "erin", "max-count", "0")
			before := tree(t, hs.dir)
			hs.run(hs.runner(), "rollback", target)
			hs.expect(0, "This was a dry run: nothing was changed.", "")
			out := hs.all()
			for _, want := range []string{"--apply takes a snapshot of the state first", "remove the report limits of bob (max-size 20 MiB, max-count 50 reports)",
				"remove the report limits of erin (max-count no cap)", "Limits of the stored reports are removed from the store",
				"To convert the state: tacctl rollback " + target + " --apply --yes"} {
				if !strings.Contains(out, want) {
					t.Errorf("the dry run lacks %q:\n%s", want, out)
				}
			}
			if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
				t.Errorf("the dry run changed %q", got)
			}

			hs.run(hs.runner(), "rollback", target, "--apply")
			hs.expect(1, "", "The warnings above need your decision")
			if !strings.Contains(hs.read("state/store.yaml"), "reports_max_size") {
				t.Fatal("a refused apply changed the store")
			}
			snaps := hs.snapshots()
			r := hs.runner()
			hs.run(r, "rollback", target, "--apply", "--yes")
			hs.expect(0, "Applying.", "")
			out = hs.all()
			for _, want := range []string{"store.yaml: removed the report limits of 2 users",
				"The own limits of the stored reports were removed from the store for 2 users; " + target + " does not know the keys:",
				"  bob: max-size 20 MiB, max-count 50 reports", "  erin: max-count no cap",
				"'tacctl user reports-limit <user> max-size|max-count <value>' sets them again",
				"holds the 0.2.28 state", "The reports in the users' homes stay"} {
				if !strings.Contains(out, want) {
					t.Errorf("--apply lacks %q:\n%s", want, out)
				}
			}
			if hs.snapshots() != snaps+1 {
				t.Errorf("snapshots %d -> %d", snaps, hs.snapshots())
			}
			snap := newestSnapshot(t, hs)
			held, err := os.ReadFile(filepath.Join(snap, "store.yaml"))
			if err != nil || !strings.Contains(string(held), "reports_max_size: 20971520") || !strings.Contains(string(held), "reports_max_count: 0") {
				t.Errorf("the snapshot does not hold the limits (%v):\n%s", err, held)
			}
			if live := hs.read("state/store.yaml"); strings.Contains(live, "reports_max") || !strings.Contains(live, "bob:") || !strings.Contains(live, "erin:") {
				t.Errorf("the store after:\n%s", live)
			}
			var line string
			for _, l := range auditLines(r) {
				if strings.Contains(l, "rollback target="+target) {
					line = l
				}
			}
			if !strings.Contains(line, " limit-users=bob,erin by=") {
				t.Errorf("the audit line: %q", line)
			}
			// the second dry run has nothing of it left
			hs.run(hs.runner(), "rollback", target)
			hs.expect(0, "", "")
			if out := hs.all(); strings.Contains(out, "report limits") || strings.Contains(out, "Limits of the stored") {
				t.Errorf("a second dry run still lists the keys:\n%s", out)
			}
		})
	}
}
