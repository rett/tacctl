package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.27', the release before 0.2.28, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// rollback0227State is rollback0221State with this release's per-tier sudoers
// drop-in, which 0.2.27 wrote too: the rollback to 0.2.27 leaves it.
func rollback0227State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollback0221State(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	return hs
}

// This release changed no stored file 0.2.27 reads strictly, so 0.2.27 reads
// everything: the dry run lists nothing to do and --apply converts nothing,
// even with an email address in the store, the break-glass firewall set and
// the limits of the stored reports (the settings and a user's own; the
// 0.2.25 target removes them), takes no snapshot, asks for no --yes and
// leaves a pull record, a report (a PDF one too) and the marker of the offer
// of the PDF tools byte for byte. A second run does the same.
func TestRollback0227ConvertsNothing(t *testing.T) {
	hs := rollback0227State(t)
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
	pdf := filepath.Join(hs.dir, "home", "alice", "reports", "devices", "inventory-20261107.pdf")
	if err := os.WriteFile(pdf, []byte("%PDF-1.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hs.write("var-lib/pdf-tools-offered", "tacctl 0.2.27 offered\n", 0o644)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.27", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.27 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.27 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.27: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.27 --apply"} {
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
		hs.run(hs.runner(), "rollback", "0.2.27", "--apply")
		hs.expect(0, "Nothing to convert: every file is one 0.2.27 can read.", "")
		out = hs.all()
		if !strings.Contains(out, "tacctl upgrade --branch 0.2.27") {
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
	if got, err := os.ReadFile(pdf); err != nil || string(got) != "%PDF-1.7\n" {
		t.Errorf("the PDF report: %q %v", got, err)
	}
	if got := hs.read("var-lib/pdf-tools-offered"); got != "tacctl 0.2.27 offered\n" {
		t.Errorf("the marker of the PDF offer: %q", got)
	}
	o, s := hs.overrides(), hs.store()
	if !strings.Contains(s, "email:") || !strings.Contains(o, "name: core-1") || !strings.Contains(o, "firewall: drop") ||
		!strings.Contains(o, "max_size: 20971520") || !strings.Contains(o, "max_count: 0") || !strings.Contains(s, "reports_max_count") {
		t.Errorf("a key or a field was lost:\n%s\n%s", o, s)
	}
}

// The 0.2.25 target is told apart from 0.2.27 and 0.2.26: it removes the limits of the
// stored reports, which 0.2.27 keeps. An emergency lockdown on the scope the
// enrolled host answers stays in both, and the older targets refuse it.
func TestRollback0227IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0227State(t)
	hs.step("", "config", "reports", "max-size", "20Mi")
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "remove reports.max_size", "")
	hs.run(hs.runner(), "rollback", "0.2.27")
	hs.expect(0, "nothing to remove (every key of tacctl.yaml is one 0.2.27 knows)", "")
	if strings.Contains(hs.all(), "remove reports.max_size") {
		t.Errorf("0.2.27 removes a setting it has:\n%s", hs.all())
	}
	hs.run(hs.runner(), "rollback", "0.2.26")
	hs.expect(0, "nothing to remove (every key of tacctl.yaml is one 0.2.26 knows)", "")

	if reg := hs.registry(); !strings.Contains(reg, "|tacctl|") {
		t.Fatalf("the enrolled host is not in the scope the lockdown names:\n%s", reg)
	}
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    tacctl:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.27", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.27 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") || !strings.Contains(o, "max_size") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the rollback to 0.2.27 changed %q", got)
	}
	for _, v := range []string{"0.2.22", "0.2.21"} {
		hs.run(hs.runner(), "rollback", v)
		hs.expect(1, "", "Scope tacctl is locked down and has enrolled hosts (authsrv)")
	}
}

// The per-tier drop-in is this release's text and 0.2.27 wrote the same, so
// it is left; the 0.2.25 target puts back its own, without the rows of
// 'device reports'.
func TestRollback0227LeavesTheDropIn(t *testing.T) {
	hs := rollback0227State(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.27", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.27 can read.", "")
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers() {
		t.Errorf("the tiers drop-in changed:\n%s", got)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "put back the per-tier sudoers drop-in 0.2.25 writes", "")
}

// 0.2.27 is the release before 0.2.28; this release is not a target, and the
// refusal names 0.2.28 as the release before this one, and 0.2.27 after it.
func TestRollback0227IsAccepted(t *testing.T) {
	hs := rollback0227State(t)
	hs.run(hs.runner(), "rollback", "0.2.30")
	hs.expect(1, "", "prepares the state for 0.2.29 (the release before this one), 0.2.28, 0.2.27, 0.2.26, 0.2.25, 0.2.24")
	hs.run(hs.runner(), "rollback", "v0.2.27")
	hs.expect(0, "Roll back to 0.2.27 (dry run)", "")
}

// The one thing this release writes that 0.2.27 refuses is the console's file
// transfer settings (its console.yaml reader answers "settings: unknown key"):
// the dry run lists the key, --apply takes a snapshot, removes it and nothing
// else of console.yaml, says what to avoid until the upgrade and why the
// snapshot cannot be restored by 0.2.27, and a second run converts nothing.
// With the settings unset nothing of this is said (TestRollback0227ConvertsNothing).
func TestRollback0227RemovesTheFileTransferSettings(t *testing.T) {
	hs := rollback0227State(t)
	hs.step("", "console", "idle-timeout", "12")
	hs.step("", "console", "file-transfer", "operator", "enable")
	hs.step("", "console", "file-transfer", "quota", "operator", "1G")
	hs.step("", "console", "file-transfer", "user", "bob", "disable")
	if y := hs.read("state/console.yaml"); !strings.Contains(y, "file_transfer:") || !strings.Contains(y, "idle_timeout: 12") {
		t.Fatalf("console.yaml:\n%s", y)
	}
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.27")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"--apply takes a snapshot of the state first", "console.yaml: take out the settings 0.2.27 does not know   [does]",
		"remove settings.file_transfer: tiers operator,superuser, 1 user switch, 1 quota", "0.2.27's parser rejects the file transfer settings 0.2.28 added to console.yaml; everything else is kept"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Warnings") || strings.Contains(out, "--yes") {
		t.Errorf("the dry run asks for --yes:\n%s", out)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.27", "--apply")
	hs.expect(0, "", "")
	out = hs.all()
	for _, want := range []string{"console.yaml: removed settings.file_transfer", "tacctl upgrade --branch 0.2.27",
		"Restore it with 0.2.30 only", "0.2.27's restore puts back a console.yaml with a setting it does not know",
		"Until the upgrade, do not run 'tacctl console file-transfer' with a tier, a user, a quota or a rate to set"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply lacks %q:\n%s", want, out)
		}
	}
	if hs.snapshots() != snaps+1 {
		t.Errorf("snapshots: %d, was %d", hs.snapshots(), snaps)
	}
	y := hs.read("state/console.yaml")
	if strings.Contains(y, "file_transfer") || !strings.Contains(y, "idle_timeout: 12") {
		t.Errorf("console.yaml after --apply:\n%s", y)
	}
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers() {
		t.Error("the tiers drop-in changed")
	}
	// a second run has nothing to convert and takes no snapshot
	snaps = hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.27", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.27 can read.", "")
	if strings.Contains(hs.all(), "Until the upgrade") || hs.snapshots() != snaps {
		t.Errorf("the second run:\n%s", hs.all())
	}
	// the 0.2.26 target does the same, and it names its own version
	hs.step("", "console", "file-transfer", "readonly", "enable")
	hs.run(hs.runner(), "rollback", "0.2.26", "--apply")
	hs.expect(0, "", "")
	if out = hs.all(); !strings.Contains(out, "console.yaml: removed settings.file_transfer") || !strings.Contains(out, "0.2.26's restore puts back a console.yaml") ||
		!strings.Contains(out, "Until the upgrade, do not run 'tacctl console file-transfer'") || !strings.Contains(out, "run 'tacctl rollback 0.2.26 --apply' again") {
		t.Errorf("0.2.26:\n%s", out)
	}
}
