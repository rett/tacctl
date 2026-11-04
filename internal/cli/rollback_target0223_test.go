package cli

import (
	"strings"
	"testing"
)

// 'tacctl rollback 0.2.23', the release before this one, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// This release changed no stored file, so 0.2.23 reads everything: the dry run
// lists nothing to do and --apply converts nothing, even with an email address
// in the store (0.2.23's own; the 0.2.22 target removes it), takes no snapshot
// and asks for no --yes.
func TestRollback0223ConvertsNothing(t *testing.T) {
	hs := rollback0221State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.step("", "server", "name", "core-1")
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.23", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.23 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.23 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.23: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.23 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"remove email", "remove server", "[does]", "add scope", "Warnings", "--yes", "email"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run says %q:\n%s", not, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.23", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.23 can read.", "")
	out = hs.all()
	if !strings.Contains(out, "tacctl upgrade --branch 0.2.23") {
		t.Errorf("--apply lacks the upgrade:\n%s", out)
	}
	if strings.Contains(out, "holds the") || strings.Contains(out, "took first") || strings.Contains(out, "Until the upgrade") {
		t.Errorf("--apply speaks of a snapshot or a command to avoid:\n%s", out)
	}
	if hs.snapshots() != snaps {
		t.Error("a snapshot was taken: there is nothing to convert")
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
	if !strings.Contains(hs.store(), "email:") || !strings.Contains(hs.overrides(), "name: core-1") {
		t.Error("the store lost an email address or tacctl.yaml the server name")
	}
}

// The 0.2.22 target still removes the email address, and a name with a period
// and an emergency lockdown stop neither 0.2.23 nor 0.2.22.
func TestRollback0223IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0221State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.run(hs.runner(), "rollback", "0.2.22")
	hs.expect(0, "remove email of bob", "")
	hs.write("state/store.yaml", strings.Replace(hs.store(), "\n  erin:", "\n  erin.smith:", 1), 0o600)
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    lab:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	hs.run(hs.runner(), "rollback", "0.2.23", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.23 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
}
