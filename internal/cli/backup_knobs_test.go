//go:build testknobs

package cli

import (
	"os"
	"testing"
)

// The restore paths whose render fails, through the TACCTL_FAULT knob (the
// bats suite overrides backend_tacacs_render_commit|stage for these, which
// only bash can do).

// The worst case for consistency: the commit replaces tacquito.yaml and
// rendered.json, then fails. Every artifact, its record, the store and
// tacctl.yaml are put back.
func TestBackupRestoreACommitThatFailsPutsEveryFileBack(t *testing.T) {
	sb := renderedSandbox(t)
	sb.mkSnapshot("20250101_000000_000", fixture(t, "store.minimal.yaml"), "")
	before := sb.liveState()
	sb.run("y\n", []string{"backup", "restore", "20250101_000000_000"}, "TACCTL_FAULT=render-commit:tacacs")
	sb.expect(1, "", "Snapshot 20250101_000000_000 was not restored: ")
	if after := sb.liveState(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
	if l := sb.leftovers(".restore.*"); len(l) != 0 {
		t.Errorf("left behind: %q", l)
	}
	if sb.runner.Called("systemctl", "restart") {
		t.Error("a failed restore restarted a backend")
	}
}

func TestBackupRestoreLegacyARenderThatFailsPutsEveryFileBack(t *testing.T) {
	sb := renderedSandbox(t)
	sb.write("state/backups/tacquito.yaml.20250101_000000", fixture(t, "golden/tacquito.minimal.rendered.yaml"), 0o600)
	before := sb.liveState()
	sb.run("y\n", []string{"backup", "restore", "20250101_000000", "--legacy"}, "TACCTL_FAULT=render-stage:tacacs")
	sb.expect(1, "Check passed. Nothing was written.", "Old-style backup 20250101_000000 was not restored. Store, tacctl.yaml and ")
	if after := sb.liveState(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
	if l := sb.leftovers(".restore.*"); len(l) != 0 {
		t.Errorf("left behind: %q", l)
	}
	if _, err := os.Stat(sb.path("state/store.yaml.tacctl-new")); !os.IsNotExist(err) {
		t.Error("temporary store file left behind")
	}
}
