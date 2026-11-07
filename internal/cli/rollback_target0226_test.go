package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.26', the release before this one, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// rollback0226State is rollback0221State with this release's per-tier sudoers
// drop-in, which 0.2.26 wrote too: the rollback to 0.2.26 leaves it.
func rollback0226State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollback0221State(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	return hs
}

// This release changed no stored file 0.2.26 reads strictly, so 0.2.26 reads
// everything: the dry run lists nothing to do and --apply converts nothing,
// even with an email address in the store, the break-glass firewall set and
// the limits of the stored reports (the settings and a user's own; the
// 0.2.25 target removes them), takes no snapshot, asks for no --yes and
// leaves a pull record and a report byte for byte. A second run does the
// same.
func TestRollback0226ConvertsNothing(t *testing.T) {
	hs := rollback0226State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.step("", "server", "name", "core-1")
	hs.step("", "config", "reports", "max-size", "20Mi")
	hs.step("", "config", "reports", "max-count", "0")
	hs.step("", "user", "reports-limit", "bob", "max-count", "7")
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"breakglass:\n  firewall: drop\n", 0o640)
	record := `{"version": 1, "devices": {"sw1": {"address": "192.0.2.11", "vendor": "juniper", "serial": "SN000001",
 "members": [{"id": "0", "role": "master", "model": "EX4300-48T", "serial": "SN000001", "release": "21.4R3", "status": "present", "priority": 255, "components": []}]}}}
`
	hs.write("var-lib/devices-config.json", record, 0o600)
	report := filepath.Join(hs.dir, "home", "alice", "reports", "devices", "inventory-20261106.txt")
	if err := os.MkdirAll(filepath.Dir(report), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report, []byte("sw1  EX4300-48T  SN000001\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.26", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.26 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.26 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.26: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.26 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"remove email", "remove server", "remove breakglass", "remove reports", "firewall", "[does]", "add scope", "Warnings", "--yes", "email", "report limits", "Limits of the stored"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run says %q:\n%s", not, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	snaps := hs.snapshots()
	for i := 0; i < 2; i++ {
		hs.run(hs.runner(), "rollback", "0.2.26", "--apply")
		hs.expect(0, "Nothing to convert: every file is one 0.2.26 can read.", "")
		out = hs.all()
		if !strings.Contains(out, "tacctl upgrade --branch 0.2.26") {
			t.Errorf("--apply lacks the upgrade:\n%s", out)
		}
		for _, not := range []string{"holds the", "took first", "Until the upgrade", "firewall is removed", "The reports in the users' homes stay", "restore refuses"} {
			if strings.Contains(out, not) {
				t.Errorf("--apply (run %d) says %q:\n%s", i+1, not, out)
			}
		}
		if hs.snapshots() != snaps {
			t.Errorf("run %d took a snapshot: there is nothing to convert", i+1)
		}
		if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
			t.Errorf("--apply (run %d) changed %q", i+1, got)
		}
	}
	if got := hs.read("var-lib/devices-config.json"); got != record {
		t.Errorf("the pull record changed:\n%s", got)
	}
	if got, err := os.ReadFile(report); err != nil || string(got) != "sw1  EX4300-48T  SN000001\n" {
		t.Errorf("the report: %q %v", got, err)
	}
	o, s := hs.overrides(), hs.store()
	if !strings.Contains(s, "email:") || !strings.Contains(o, "name: core-1") || !strings.Contains(o, "firewall: drop") ||
		!strings.Contains(o, "max_size: 20971520") || !strings.Contains(o, "max_count: 0") || !strings.Contains(s, "reports_max_count") {
		t.Errorf("a key or a field was lost:\n%s\n%s", o, s)
	}
}

// The 0.2.25 target is told apart from 0.2.26: it removes the limits of the
// stored reports, which 0.2.26 keeps. An emergency lockdown on the scope the
// enrolled host answers stays in both, and the older targets refuse it.
func TestRollback0226IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0226State(t)
	hs.step("", "config", "reports", "max-size", "20Mi")
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "remove reports.max_size", "")
	hs.run(hs.runner(), "rollback", "0.2.26")
	hs.expect(0, "nothing to remove (every key of tacctl.yaml is one 0.2.26 knows)", "")
	if strings.Contains(hs.all(), "remove reports.max_size") {
		t.Errorf("0.2.26 removes a setting it has:\n%s", hs.all())
	}

	if reg := hs.registry(); !strings.Contains(reg, "|tacctl|") {
		t.Fatalf("the enrolled host is not in the scope the lockdown names:\n%s", reg)
	}
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    tacctl:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.26", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.26 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") || !strings.Contains(o, "max_size") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the rollback to 0.2.26 changed %q", got)
	}
	for _, v := range []string{"0.2.22", "0.2.21"} {
		hs.run(hs.runner(), "rollback", v)
		hs.expect(1, "", "Scope tacctl is locked down and has enrolled hosts (authsrv)")
	}
}

// The per-tier drop-in is this release's text and 0.2.26 wrote the same, so
// it is left; the 0.2.25 target puts back its own, without the rows of
// 'device reports'.
func TestRollback0226LeavesTheDropIn(t *testing.T) {
	hs := rollback0226State(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.26", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.26 can read.", "")
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers() {
		t.Errorf("the tiers drop-in changed:\n%s", got)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "put back the per-tier sudoers drop-in 0.2.25 writes", "")
}

// 0.2.26 is the release before this one; this release is not a target, and
// the refusal names 0.2.26 first.
func TestRollback0226IsTheReleaseBeforeThisOne(t *testing.T) {
	hs := rollback0226State(t)
	hs.run(hs.runner(), "rollback", "0.2.27")
	hs.expect(1, "", "prepares the state for 0.2.26 (the release before this one), 0.2.25, 0.2.24, 0.2.23")
	hs.run(hs.runner(), "rollback", "v0.2.26")
	hs.expect(0, "Roll back to 0.2.26 (dry run)", "")
}
