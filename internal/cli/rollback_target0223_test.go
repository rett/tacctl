package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.23', two releases before this one (0.2.24 is the release
// before it), on the host sandbox with this server enrolled. The plan's own cases are internal/lifecycle's.

// rollback0223State is rollback0221State with the per-tier sudoers drop-in
// 0.2.23 wrote, not the older text the state of the targets 0.2.20 to 0.2.22
// has: the rollback to 0.2.23 leaves it. rollback0223ThisReleaseState has this
// release's text, which the rollback to 0.2.23 rewrites.
func rollback0223State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollback0221State(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers0223(), 0o640)
	return hs
}

func rollback0223ThisReleaseState(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollback0221State(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	return hs
}

// 0.2.24 and this release changed no stored file 0.2.23 reads strictly but
// breakglass.firewall (rollback_firewall.go; this state has it unset), so
// 0.2.23 reads the rest: on a host whose per-tier drop-in is 0.2.23's the dry
// run lists nothing to do and --apply converts nothing, even with an email address
// in the store (0.2.23's own; the 0.2.22 target removes it), takes no snapshot
// and asks for no --yes.
func TestRollback0223ConvertsNothing(t *testing.T) {
	hs := rollback0223State(t)
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
// stops neither 0.2.23 nor 0.2.22. An emergency lockdown on the scope the
// enrolled host answers stays in the rollback to 0.2.23 (the host's sshd
// drop-in is one only this release and 0.2.23 lift), and is a reason to
// refuse every older target, 0.2.22 first.
func TestRollback0223IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0223State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.run(hs.runner(), "rollback", "0.2.22")
	hs.expect(0, "remove email of bob", "")
	hs.write("state/store.yaml", strings.Replace(hs.store(), "\n  erin:", "\n  erin.smith:", 1), 0o600)
	// both targets read the stored name with a period
	hs.run(hs.runner(), "rollback", "0.2.22")
	hs.expect(0, "remove email of bob", "")
	hs.run(hs.runner(), "rollback", "0.2.23", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.23 can read.", "")

	// the scope of the enrolled host is the one locked
	if reg := hs.registry(); !strings.Contains(reg, "|tacctl|") {
		t.Fatalf("the enrolled host is not in the scope the lockdown names:\n%s", reg)
	}
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    tacctl:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.23", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	if strings.Contains(hs.all(), "locked down") {
		t.Errorf("the dry run of 0.2.23 names the lockdown as a reason:\n%s", hs.all())
	}
	hs.run(hs.runner(), "rollback", "0.2.23", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.23 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the rollback to 0.2.23 changed %q", got)
	}
	for _, v := range []string{"0.2.22", "0.2.21"} {
		for _, args := range [][]string{{"rollback", v}, {"rollback", v, "--apply"}} {
			hs.run(hs.runner(), args...)
			hs.expect(1, "", "Scope tacctl is locked down and has enrolled hosts (authsrv)")
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("a refused rollback changed %q", got)
	}
}

// With this release's per-tier drop-in (the operator's 'log failures *' is a
// row 0.2.23 lacks) the dry run shows the step and writes nothing, --apply
// puts back 0.2.23's text after 'visudo -cf', takes no snapshot, needs no
// --yes and touches no other file, and the second --apply has nothing left. A
// drop-in tacctl did not write is left, and the 0.2.22 target, which also
// recognises this release's text, puts back its own.
func TestRollback0223PutsBackTheDropIn(t *testing.T) {
	hs := rollback0223ThisReleaseState(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.23")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"put back the per-tier sudoers drop-in 0.2.23 writes",
		"(0.2.23's text, after 'visudo -cf': the operator's rule of 'log failures *' is taken out)", "To convert the state: tacctl rollback 0.2.23 --apply"} {
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
	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.23", "--apply")
	hs.expect(0, "Applying.", "")
	out = hs.all()
	for _, want := range []string{"sudoers.d/tacctl-tiers: rewritten with the text 0.2.23 writes", "Next steps", "tacctl upgrade --branch 0.2.23"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if !r.CalledRegexp(`^visudo -cf `) {
		t.Errorf("no visudo check: %q", r.Argvs())
	}
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers0223() || strings.Contains(got, "log failures *") || !strings.Contains(got, "device clone") {
		t.Errorf("the tiers drop-in is not 0.2.23's:\n%s", got)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 1 || !strings.HasSuffix(got[0], "sudoers.d/tacctl-tiers") {
		t.Errorf("--apply changed %q", got)
	}
	if hs.snapshots() != snaps || strings.Contains(out, "took first") {
		t.Error("a snapshot was taken or named: the drop-in is not in it")
	}
	hs.run(nil, "rollback", "0.2.23", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.23 can read.", "")

	// a drop-in tacctl did not write is left
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers()+"# edited\n", 0o640)
	before = tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.23", "--apply")
	hs.expect(0, "", "")
	if !strings.Contains(hs.all(), "leaves ") {
		t.Errorf("an edited drop-in is not said to be left:\n%s", hs.all())
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("an edited drop-in was changed: %q", got)
	}

	// the 0.2.22 target puts back its own text over this release's
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	r = hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.22", "--apply")
	hs.expect(0, "Applying.", "")
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers0222() {
		t.Errorf("the tiers drop-in is not 0.2.22's:\n%s", got)
	}
}
