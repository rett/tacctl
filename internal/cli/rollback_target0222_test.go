package cli

import (
	"strings"
	"testing"
)

// 'tacctl rollback 0.2.22', the release before this one, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// 0.2.22 reads every file this release writes, so the dry run lists nothing to
// do and --apply converts nothing: the server name, the timing scale (0.2.22's
// own), the server address and the users stay, no snapshot is taken (there is
// no file to convert) and no --yes is asked.
func TestRollback0222ConvertsNothing(t *testing.T) {
	hs := rollback0221State(t)
	hs.withTimeoutScale()
	hs.step("", "server", "name", "core-1")
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.22", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.22 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.22 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.22: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.22 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "[does]", "add scope", "Warnings", "--yes", "timing scale", "timeout_scale"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run says %q:\n%s", not, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.22 can read.", "")
	out = hs.all()
	if !strings.Contains(out, "tacctl upgrade --branch 0.2.22") {
		t.Errorf("--apply lacks the upgrade:\n%s", out)
	}
	// no snapshot was taken, so none is promised
	if strings.Contains(out, "holds the") || strings.Contains(out, "took first") || strings.Contains(out, "takes a snapshot") {
		t.Errorf("--apply speaks of a snapshot that was not taken:\n%s", out)
	}
	if strings.Contains(out, "Until the upgrade") {
		t.Errorf("--apply names a command to avoid; 0.2.22 reads them all:\n%s", out)
	}
	if hs.snapshots() != snaps {
		t.Error("a snapshot was taken: there is nothing to convert")
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
	if o := hs.overrides(); !strings.Contains(o, "name: core-1") || !strings.Contains(o, "timeout_scale") {
		t.Errorf("tacctl.yaml lost a key of 0.2.22:\n%s", o)
	}
	if d := hs.read("state/devices.yaml"); !strings.Contains(d, "timeout_scale") {
		t.Errorf("devices.yaml lost the timing scale of a device:\n%s", d)
	}
}

// 0.2.22 reads a user name with a period and has the emergency lockdown, so
// neither stops its rollback, in the dry run and with --apply; 0.2.19 refuses
// the name, 0.2.18 the lockdown.
func TestRollback0222IsNotStoppedByADottedNameOrALockdown(t *testing.T) {
	hs := rollback0221State(t)
	hs.write("state/store.yaml", strings.Replace(hs.store(), "\n  erin:", "\n  erin.smith:", 1), 0o600)
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    lab:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	hs.run(hs.runner(), "rollback", "0.2.22")
	hs.expect(0, "Roll back to 0.2.22 (dry run)", "")
	if strings.Contains(hs.all(), "locked down") {
		t.Errorf("the dry run names the lockdown as a reason:\n%s", hs.all())
	}
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.22 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	hs.run(hs.runner(), "rollback", "0.2.19")
	hs.expect(1, "", "erin.smith")
}

// The older targets still remove the timing scale and name the commands that
// write it, and 0.2.22 is told apart from them in the refusal of a version
// that is not a target.
func TestRollback0222IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0221State(t)
	hs.withTimeoutScale()
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Applying.", "")
	if !strings.Contains(hs.all(), "Until the upgrade, do not run 'tacctl device timeout-scale'") {
		t.Errorf("0.2.21 lacks the note:\n%s", hs.all())
	}
	hs.run(hs.runner(), "rollback", "0.2.23")
	hs.expect(1, "", "prepares the state for 0.2.22 (the release before this one), 0.2.21")
}

// The snapshot is announced, and its state named, only when the apply takes
// one: the plan's header and the closing paragraph agree with what happened,
// for the 0.2.22 target and for the older ones, with a file to convert and
// without.
func TestRollbackSnapshotIsSpokenOfOnlyWhenTaken(t *testing.T) {
	for _, v := range []string{"0.2.22", "0.2.21"} {
		hs := rollback0221State(t)
		hs.run(hs.runner(), "rollback", v, "--apply")
		hs.expect(0, "Nothing to convert", "")
		if out := hs.all(); strings.Contains(out, "holds the") || strings.Contains(out, "takes a snapshot of the state first") || !strings.Contains(out, "takes no snapshot") {
			t.Errorf("%s with nothing to convert:\n%s", v, out)
		}
	}
	hs := rollback0221State(t)
	hs.step("", "server", "name", "core-1")
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	if hs.snapshots() == snaps {
		t.Error("no snapshot was taken")
	}
	for _, want := range []string{"--apply takes a snapshot of the state first", "holds the 0.2.23 state. Restore it with 0.2.23 only"} {
		if !strings.Contains(out, want) {
			t.Errorf("0.2.21 with a file to convert lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "holds the 0.2.22 state") || strings.Contains(out, "takes no snapshot") {
		t.Errorf("0.2.21:\n%s", out)
	}
}
