package cli

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// A restore is a render like any other (D126): a hold goes with a snapshot
// that lacks it, and the report names the holds before and after.
func TestBreakglassHoldGoesWithARestoredSnapshotThatLacksIt(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	if out := sb.hold(t, "lab-sw", "console recovery", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold: %q %q", out, sb.stderr())
	}
	if strings.Contains(sb.renderedConfig(), `"192.168.0.0/16"`) {
		t.Fatal("the hold did not carve")
	}
	// The newest snapshot with no hold in it.
	snaps, _ := filepath.Glob(sb.path("state", "backups", "2*"))
	slices.Sort(snaps)
	var id string
	for i := len(snaps) - 1; i >= 0; i-- {
		if !strings.Contains(sb.read("state/backups/"+filepath.Base(snaps[i])+"/tacctl.yaml"), "breakglass_hold") {
			id = filepath.Base(snaps[i])
			break
		}
	}
	if id == "" {
		t.Fatalf("no snapshot without the hold: %v", snaps)
	}
	out := plain(sb.run("y\n", []string{"backup", "restore", id}))
	if sb.code != 0 {
		t.Fatalf("restore: %d %q %q", sb.code, out, sb.stderr())
	}
	want := "Break-glass holds change: held now: lab-sw (192.168.1.1); held after the restore: none (tacctl breakglass list)."
	if !strings.Contains(out, want) {
		t.Errorf("the restore does not name the holds:\n%s", out)
	}
	if got := sb.renderedConfig(); got != original {
		t.Errorf("the restored rendering is not the original:\n%s", got)
	}
	if o := sb.overrides(); strings.Contains(o, "breakglass_hold") {
		t.Errorf("the hold is left:\n%s", o)
	}
}
