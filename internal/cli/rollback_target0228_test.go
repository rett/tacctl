package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.28', the release before this one, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// This release changed no stored file 0.2.28 reads strictly, so 0.2.28 reads
// everything: the dry run lists nothing to do and --apply converts nothing,
// even with the console's file transfer settings, an email address in the
// store, the break-glass firewall and the limits of the stored reports set,
// takes no snapshot, asks for no --yes and leaves a pull record, a report (a
// PDF one too) and the marker of the offer of the PDF tools byte for byte. A
// second run does the same.
func TestRollback0228ConvertsNothing(t *testing.T) {
	hs := rollback0227State(t)
	hs.step("", "user", "email", "bob", "bob@example.net")
	hs.step("", "server", "name", "core-1")
	hs.step("", "config", "reports", "max-size", "20Mi")
	hs.step("", "config", "reports", "max-count", "0")
	hs.step("", "user", "reports-limit", "bob", "max-count", "7")
	hs.step("", "console", "file-transfer", "operator", "enable")
	hs.step("", "console", "file-transfer", "quota", "operator", "1G")
	hs.step("", "console", "file-transfer", "user", "bob", "disable")
	if y := hs.read("state/console.yaml"); !strings.Contains(y, "file_transfer:") {
		t.Fatalf("console.yaml:\n%s", y)
	}
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
	consoleYAML := hs.read("state/console.yaml")
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.28", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.28 (dry run)", "nothing to remove (every key of tacctl.yaml is one 0.2.28 knows)",
		"--apply converts no file of tacctl's own and takes no snapshot",
		"nothing to do for 0.2.28: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.28 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"remove email", "remove server", "remove breakglass", "remove reports", "remove settings", "file_transfer", "firewall", "[does]", "add scope", "Warnings", "--yes", "email", "report limits", "Limits of the stored"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run says %q:\n%s", not, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	snaps := hs.snapshots()
	for i := 0; i < 2; i++ {
		hs.run(hs.runner(), "rollback", "0.2.28", "--apply")
		hs.expect(0, "Nothing to convert: every file is one 0.2.28 can read.", "")
		out = hs.all()
		if !strings.Contains(out, "tacctl upgrade --branch 0.2.28") {
			t.Errorf("--apply lacks the upgrade:\n%s", out)
		}
		for _, not := range []string{"holds the", "took first", "Until the upgrade", "firewall is removed", "The reports in the users' homes stay", "restore refuses", "restore puts back"} {
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
	if got := hs.read("state/console.yaml"); got != consoleYAML {
		t.Errorf("console.yaml changed:\n%s", got)
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

// The 0.2.27 target is told apart from 0.2.28 on the same state: it takes the
// file transfer settings out of console.yaml (0.2.27 refuses the key) after a
// snapshot, which 0.2.28 keeps. An emergency lockdown on the scope the
// enrolled host answers stays in both, and the older targets refuse it.
func TestRollback0228IsToldApartFromTheOlderTargets(t *testing.T) {
	hs := rollback0227State(t)
	hs.step("", "console", "file-transfer", "operator", "enable")
	hs.run(hs.runner(), "rollback", "0.2.27")
	hs.expect(0, "remove settings.file_transfer", "")
	hs.run(hs.runner(), "rollback", "0.2.28")
	hs.expect(0, "nothing to remove (every key of tacctl.yaml is one 0.2.28 knows)", "")
	if strings.Contains(hs.all(), "settings.file_transfer") {
		t.Errorf("0.2.28 removes a setting it has:\n%s", hs.all())
	}

	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    tacctl:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.28", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.28 can read.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	if y := hs.read("state/console.yaml"); !strings.Contains(y, "file_transfer:") {
		t.Errorf("console.yaml lost the settings:\n%s", y)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the rollback to 0.2.28 changed %q", got)
	}
	for _, v := range []string{"0.2.22", "0.2.21"} {
		hs.run(hs.runner(), "rollback", v)
		hs.expect(1, "", "Scope tacctl is locked down and has enrolled hosts (authsrv)")
	}
}

// The per-tier drop-in is this release's text and 0.2.28 wrote the same, so
// it is left; the 0.2.25 target puts back its own, without the rows of
// 'device reports'.
func TestRollback0228LeavesTheDropIn(t *testing.T) {
	hs := rollback0227State(t)
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.28", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.28 can read.", "")
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers() {
		t.Errorf("the tiers drop-in changed:\n%s", got)
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("--apply changed %q", got)
	}
	hs.run(hs.runner(), "rollback", "0.2.25")
	hs.expect(0, "put back the per-tier sudoers drop-in 0.2.25 writes", "")
}

// 0.2.28 is the release before this one; this release is not a target, and
// the refusal names 0.2.28 first.
func TestRollback0228IsTheReleaseBeforeThisOne(t *testing.T) {
	hs := rollback0227State(t)
	hs.run(hs.runner(), "rollback", "0.2.29")
	hs.expect(1, "", "'0.2.29' is not a release to roll back to: 'tacctl rollback' prepares the state for 0.2.28 (the release before this one), 0.2.27, 0.2.26, 0.2.25, 0.2.24")
	hs.run(hs.runner(), "rollback", "v0.2.28")
	hs.expect(0, "Roll back to 0.2.28 (dry run)", "")
}
