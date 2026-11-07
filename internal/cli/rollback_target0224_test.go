package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.24', the release before this one, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// rollback0224State is rollback0221State with the per-tier sudoers drop-in
// 0.2.24 and 0.2.25 wrote (no row of 'device reports'), which the rollback to 0.2.24
// and 0.2.25 leaves.
func rollback0224State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollback0221State(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers0225(), 0o640)
	return hs
}

// beforeReportsNote is out up to the note every target ends with: the reports
// in the users' homes stay and the commands of the limits (0.2.26) write a
// key the older release refuses (rollbackReportLimitsNote).
func beforeReportsNote(out string) string {
	before, _, _ := strings.Cut(out, "The reports in the users' homes stay")
	return before
}

// This release changed no stored file 0.2.24 reads but the limits of the stored reports, so 0.2.24 reads everything: the dry run
// lists nothing to do and --apply converts nothing, even with an email address
// in the store and the break-glass firewall set (0.2.24's own; the 0.2.23
// target removes them), takes no snapshot and asks for no --yes.
func TestRollback0224ConvertsNothing(t *testing.T) {
	hs := rollback0224State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.step("", "server", "name", "core-1")
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"breakglass:\n  firewall: drop\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.24", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.24 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.24 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.24: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.24 --apply"} {
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
	hs.run(hs.runner(), "rollback", "0.2.24", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.24 can read.", "")
	out = hs.all()
	if !strings.Contains(out, "tacctl upgrade --branch 0.2.24") {
		t.Errorf("--apply lacks the upgrade:\n%s", out)
	}
	if out = beforeReportsNote(out); strings.Contains(out, "holds the") || strings.Contains(out, "took first") || strings.Contains(out, "Until the upgrade") || strings.Contains(out, "firewall is removed") {
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

// The 0.2.23 target is told apart from 0.2.24: it removes the firewall setting
// and puts back its own per-tier drop-in, which 0.2.24 does not. An emergency
// lockdown on the scope the enrolled host answers stays in both.
func TestRollback0224IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0224State(t)
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"breakglass:\n  firewall: drop\n", 0o640)
	hs.run(hs.runner(), "rollback", "0.2.23")
	hs.expect(0, "remove breakglass.firewall", "")
	if !strings.Contains(hs.all(), "put back the per-tier sudoers drop-in 0.2.23 writes") {
		t.Errorf("0.2.23 leaves the drop-in:\n%s", hs.all())
	}
	hs.run(hs.runner(), "rollback", "0.2.24")
	hs.expect(0, "nothing to remove (every key of tacctl.yaml is one 0.2.24 knows)", "")

	if reg := hs.registry(); !strings.Contains(reg, "|tacctl|") {
		t.Fatalf("the enrolled host is not in the scope the lockdown names:\n%s", reg)
	}
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    tacctl:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.24", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.24 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the rollback to 0.2.24 changed %q", got)
	}
	for _, v := range []string{"0.2.22", "0.2.21"} {
		hs.run(hs.runner(), "rollback", v)
		hs.expect(1, "", "Scope tacctl is locked down and has enrolled hosts (authsrv)")
	}
}

// The 0.2.23 target still puts back its per-tier drop-in over the text of 0.2.24
// and this release, and the older targets recognise it.
func TestRollback0224LeavesTheDropIn(t *testing.T) {
	hs := rollback0224State(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.24", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.24 can read.", "")
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers0225() {
		t.Errorf("the tiers drop-in changed:\n%s", got)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
}
