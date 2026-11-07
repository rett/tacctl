package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 'tacctl rollback 0.2.25', the release before this one, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// With no limit of the stored reports set, 0.2.25 reads everything: the dry run
// lists nothing to do and --apply converts nothing, even with an email address
// in the store and the break-glass firewall set (0.2.24's own; the 0.2.23
// target removes them), takes no snapshot and asks for no --yes. It ends with
// the upgrade and says the reports stay in the homes and the verbs are not in
// 0.2.25.
func TestRollback0225ConvertsNothingWithoutLimits(t *testing.T) {
	hs := rollback0224State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.step("", "server", "name", "core-1")
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"breakglass:\n  firewall: drop\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.25", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.25 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.25 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.25: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.25 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"remove email", "remove server", "remove breakglass", "firewall", "[does]", "add scope", "Warnings", "--yes", "email"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run says %q:\n%s", not, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.25", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.25 can read.", "")
	out = hs.all()
	for _, want := range []string{"tacctl upgrade --branch 0.2.25", "The reports in the users' homes stay: they are the users' own files, and 0.2.25 has no 'device reports' verbs to list or remove them."} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply lacks %q:\n%s", want, out)
		}
	}
	if head := beforeReportsNote(out); strings.Contains(head, "holds the") || strings.Contains(head, "took first") || strings.Contains(head, "Until the upgrade") || strings.Contains(head, "firewall is removed") {
		t.Errorf("--apply speaks of a snapshot, a command to avoid or the firewall:\n%s", out)
	}
	if hs.snapshots() != snaps {
		t.Error("a snapshot was taken: there is nothing to convert")
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
	if !strings.Contains(hs.store(), "email:") || !strings.Contains(hs.overrides(), "name: core-1") || !strings.Contains(hs.overrides(), "firewall: drop") {
		t.Error("the store lost an email address or tacctl.yaml the server name or the firewall setting")
	}
}

// The two settings of the file go after a snapshot and need no --yes; the
// users' own limits are data and need it. The snapshot holds the 0.2.26 state
// and the note says 0.2.25 cannot restore it; the reports in the homes and the
// pull records are not touched.
func TestRollback0225RemovesTheLimitsAfterASnapshot(t *testing.T) {
	hs := rollback0224State(t)
	hs.step("", "config", "reports", "max-size", "20Mi")
	hs.step("", "config", "reports", "max-count", "0")
	report := filepath.Join(hs.dir, "home", "alice", "reports", "devices", "inventory-20261106.txt")
	if err := os.MkdirAll(filepath.Dir(report), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, []byte("sw1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := tree(t, hs.dir)

	// settings alone: a snapshot, no --yes
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "To convert the state: tacctl rollback 0.2.25 --apply\n", "")
	out := hs.all()
	for _, want := range []string{"--apply takes a snapshot of the state first", "remove reports.max_size", "remove reports.max_count", "[does]"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "--yes") || strings.Contains(out, "Warnings") {
		t.Errorf("the settings alone ask for --yes:\n%s", out)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}

	// with a user's own limit: --yes
	hs.step("", "user", "reports-limit", "bob", "max-count", "7")
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "To convert the state: tacctl rollback 0.2.25 --apply --yes", "")
	hs.run(hs.runner(), "rollback", "0.2.25", "--apply")
	hs.expect(1, "", "The warnings above need your decision")
	if !strings.Contains(hs.read("state/tacctl.yaml"), "max_size") || !strings.Contains(hs.read("state/store.yaml"), "reports_max_count") {
		t.Fatal("a refused apply changed a file")
	}

	snaps := hs.snapshots()
	r := hs.runner()
	hs.run(r, "rollback", "0.2.25", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out = hs.all()
	for _, want := range []string{"tacctl.yaml: removed 2 keys", "store.yaml: removed the report limits of 1 user", "  bob: max-count 7 reports",
		"holds the 0.2.26 state", "0.2.25's restore refuses a tacctl.yaml with a key it does not know and a store.yaml with a field it does not know.",
		"tacctl upgrade --branch 0.2.25", "The reports in the users' homes stay", "0.2.25 has no 'device reports' verbs"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply lacks %q:\n%s", want, out)
		}
	}
	if hs.snapshots() != snaps+1 {
		t.Errorf("snapshots %d -> %d: one is taken, the keys are dropped", snaps, hs.snapshots())
	}
	if o := hs.overrides(); strings.Contains(o, "reports") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	if s := hs.store(); strings.Contains(s, "reports_max") {
		t.Errorf("the store after --apply:\n%s", s)
	}
	held, err := os.ReadFile(filepath.Join(newestSnapshot(t, hs), "tacctl.yaml"))
	if err != nil || !strings.Contains(string(held), "max_size: 20971520") {
		t.Errorf("the snapshot does not hold the settings (%v):\n%s", err, held)
	}
	if got, err := os.ReadFile(report); err != nil || string(got) != "sw1\n" {
		t.Errorf("the report: %q %v", got, err)
	}
	var line string
	for _, l := range auditLines(r) {
		if strings.Contains(l, "rollback target=0.2.25") {
			line = l
		}
	}
	if !strings.Contains(line, "keys=2") || !strings.Contains(line, " limit-users=bob by=") {
		t.Errorf("the audit line: %q", line)
	}
	// a second run has nothing left
	snaps = hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.25", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.25 can read.", "")
	if hs.snapshots() != snaps {
		t.Error("the second run took a snapshot")
	}
}

// The note of the snapshot says what the older release's restore refuses for
// what the rollback removed: a key of tacctl.yaml (the settings), a field of
// the store (a user's own limit), or both. It never names a tacctl.yaml key
// when only a store field went.
func TestRollbackSnapshotNoteNamesWhatTheRestoreRefuses(t *testing.T) {
	const keysTail = "'s restore refuses a tacctl.yaml with a key it does not know."
	const fieldsTail = "'s restore refuses a store.yaml with a field it does not know."
	const bothTail = "'s restore refuses a tacctl.yaml with a key it does not know and a store.yaml with a field it does not know."
	for _, c := range []struct {
		name, target, tail string
		steps              [][]string
	}{
		{"settings only", "0.2.25", keysTail, [][]string{{"config", "reports", "max-size", "20Mi"}}},
		{"a user's limit only", "0.2.25", fieldsTail, [][]string{{"user", "reports-limit", "bob", "max-count", "7"}}},
		{"both", "0.2.25", bothTail, [][]string{{"config", "reports", "max-count", "0"}, {"user", "reports-limit", "bob", "max-count", "7"}}},
		{"settings only, 0.2.24", "0.2.24", keysTail, [][]string{{"config", "reports", "max-size", "20Mi"}}},
		{"a user's limit only, 0.2.24", "0.2.24", fieldsTail, [][]string{{"user", "reports-limit", "bob", "max-count", "7"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := rollback0224State(t)
			for _, st := range c.steps {
				hs.step("", st...)
			}
			hs.run(hs.runner(), "rollback", c.target, "--apply", "--yes")
			hs.expect(0, "Applying.", "")
			out := hs.all()
			if !strings.Contains(out, "holds the 0.2.26 state") || !strings.Contains(out, c.target+c.tail) {
				t.Errorf("the note lacks %q:\n%s", c.target+c.tail, out)
			}
			if c.tail == fieldsTail && strings.Contains(out, "a tacctl.yaml with a key") {
				t.Errorf("a store field alone names a tacctl.yaml key:\n%s", out)
			}
		})
	}
}

// The per-tier drop-in is left as it is while 0.2.25 and this release write the
// same text, and an emergency lockdown on the scope an enrolled host answers
// stays in the target (0.2.25 has the lockdown).
func TestRollback0225LeavesTheDropInAndTheLockdown(t *testing.T) {
	hs := rollback0224State(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.25", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.25 can read.", "")
	if got := hs.read("sudoers.d/tacctl-tiers"); got == "" || len(changedFiles(before, tree(t, hs.dir))) != 0 {
		t.Errorf("the tiers drop-in changed: %q", changedFiles(before, tree(t, hs.dir)))
	}
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    tacctl:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	hs.run(hs.runner(), "rollback", "0.2.25", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.25 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	hs.run(hs.runner(), "rollback", "0.2.22")
	hs.expect(1, "", "Scope tacctl is locked down and has enrolled hosts (authsrv)")
}

// 0.2.25 is the release before this one; this release is not a target.
func TestRollback0225IsTheReleaseBeforeThisOne(t *testing.T) {
	hs := rollback0224State(t)
	hs.run(hs.runner(), "rollback", "0.2.26")
	hs.expect(1, "", "prepares the state for 0.2.25 (the release before this one), 0.2.24, 0.2.23")
	hs.run(hs.runner(), "rollback", "v0.2.25")
	hs.expect(0, "Roll back to 0.2.25 (dry run)", "")
}
