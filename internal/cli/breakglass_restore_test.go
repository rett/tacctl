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

// The files a restore renders are worded by the registry the restore puts
// back (D237): a hold is a host's when the restored registry has the host and
// a device's when it does not, in both directions, and 'config validate' reads
// the files as up to date. The restore makes no more restarts than before.
func TestBackupRestoreWordsAHoldByTheRestoredRegistry(t *testing.T) {
	sb := engineerSandbox(t)
	sandboxRADIUS(sb)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nbackends:\n  enabled:\n  - tacacs\n  - radius\n", 0o600)
	sb.write("state/linux-hosts", hostLines, 0o600)
	sb.recordHostAddress("web2", "192.168.1.12")
	sb.run("", []string{"config", "render"})
	if sb.code != 0 {
		t.Fatalf("render: %d %q", sb.code, sb.stderr())
	}
	holdHost(t, sb, "web1", "locked out of sudo")

	// Two snapshots of one hold: one with web1 enrolled, one without.
	snap := func(id, registry string) {
		sb.mkSnapshot(id, sb.read("state/store.yaml"), sb.read("state/tacctl.yaml"))
		sb.write("state/backups/"+id+"/linux-hosts", registry, 0o600)
	}
	const withoutWeb1 = "db1|root@10.99.0.20||prod|192.0.2.1|\nweb2|root@web2.example.net||lab|192.0.2.1|\n"
	snap("20200101_000000_001", hostLines)
	snap("20200101_000000_002", withoutWeb1)

	files := func(word string) {
		t.Helper()
		other := "device"
		if word == "device" {
			other = "host"
		}
		for _, c := range []struct{ file, text string }{
			{"tacquito.yaml", sb.renderedConfig()}, {"clients.conf", sb.read("raddb/tacctl-radius.conf")},
		} {
			if !strings.Contains(c.text, "("+word+" web1)") || strings.Contains(c.text, "("+other+" web1)") {
				t.Errorf("%s does not word the hold as a %s's:\n%s", c.file, word, c.text)
			}
		}
		if out := plain(sb.run("", []string{"config", "validate"})); !strings.Contains(out, "up to date") ||
			strings.Contains(out, "out of date") {
			t.Errorf("validate (exit %d):\n%s", sb.code, out)
		}
	}
	restore := func(id string) {
		t.Helper()
		before := sb.restarts()
		out := plain(sb.run("y\n", []string{"backup", "restore", id}))
		if sb.code != 0 {
			t.Fatalf("restore %s: %d %q %q", id, sb.code, out, sb.stderr())
		}
		if n := sb.restarts() - before; n != 2 {
			t.Errorf("restore %s: %d restarts, want one per backend", id, n)
		}
	}

	// The registry that has no web1 comes back over a live one that has it.
	files("host")
	restore("20200101_000000_002")
	files("device")
	// And the one that has web1 over one that has not.
	restore("20200101_000000_001")
	files("host")
	if got := sb.read("state/linux-hosts"); got != hostLines {
		t.Errorf("registry %q", got)
	}
}
