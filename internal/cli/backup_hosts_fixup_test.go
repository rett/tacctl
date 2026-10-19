package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
)

// Review fix-ups of WP14.7 (D191, D192).

// 'host move --all' is one change: one snapshot, taken before the first
// move, and not one per host (Retention keeps 30, so a snapshot per host
// would push the state before the batch out of the list).
func TestHostMoveAllTakesOneSnapshot(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "prod", "add", "192.0.2.0/24")
	hs.expect(0, "", "")
	const n = 35
	var reg strings.Builder
	for i := range n {
		fmt.Fprintf(&reg, "h%02d|admin@h%02d.example.net||lab|192.0.2.1|\n", i, i)
	}
	if err := os.WriteFile(hs.path("state/linux-hosts"), []byte(reg.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	// Some snapshots already, the oldest of them the state before the batch.
	for i := range 3 {
		hs.write(fmt.Sprintf("state/backups/2020010%d_000000_001/store.yaml", i+1), "", 0o600)
	}
	before := hs.snapshotDirs()

	// Each host has an address of its own, all answered by prod.
	r := hs.runner()
	r.OnFunc([]string{"getent", "ahostsv4"}, func(c execx.Cmd) (execx.Result, error) {
		var i int
		_, _ = fmt.Sscanf(c.Args[1], "h%d.", &i)
		return execx.Result{Stdout: []byte(fmt.Sprintf("192.0.2.%d STREAM\n", 10+i))}, nil
	})
	out := plain(hs.run(r, "host", "move", "--all", "--yes", "--allow-uid-mismatch", "--remove-home"))
	hs.expect(0, "", "")
	if got := strings.Count(out, "Config snapshot saved"); got != 1 {
		t.Errorf("%d snapshot lines, want 1:\n%s", got, out)
	}
	after := hs.snapshotDirs()
	for _, d := range before {
		if !slices.Contains(after, d) {
			t.Errorf("the snapshot %s is gone after the batch", filepath.Base(d))
		}
	}
	if len(after) != len(before)+1 {
		t.Fatalf("%d snapshots after, %d before", len(after), len(before))
	}
	pre := after[len(after)-1]
	if got := readIn(t, pre, "linux-hosts"); got != reg.String() {
		t.Errorf("the batch snapshot is not the state before the first move:\n%s", got)
	}
	if got := hs.registry(); strings.Contains(got, "|lab|") || strings.Count(got, "|prod|") != n {
		t.Errorf("not every host moved:\n%s", got)
	}
}

// A busy host registry stops 'backup restore' before anything changes.
func TestBackupRestoreWithABusyRegistryChangesNothing(t *testing.T) {
	sb := hostsSandbox(t)
	defer hosts.SetLockWait(100 * time.Millisecond)()
	unlock, err := (&hosts.Registry{Path: sb.path("state/linux-hosts")}).Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	before := sb.hostState()
	snaps := len(sb.snapshotDirs())
	live := sb.read("state/store.yaml")

	sb.run("y\n", []string{"backup", "restore", "20200101_000000_002"})
	errs := sb.stderr()
	if sb.code == 0 || !strings.Contains(errs, "locked by another tacctl command") || !strings.Contains(errs, "Nothing was changed.") {
		t.Errorf("exit %d, stderr %q", sb.code, errs)
	}
	if !mapsEqual(sb.hostState(), before) {
		t.Error("the host files changed")
	}
	if len(sb.snapshotDirs()) != snaps {
		t.Error("a snapshot was taken")
	}
	if sb.read("state/store.yaml") != live {
		t.Error("the store changed")
	}
}

// A snapshot that does not know the hosts needs no lock on the registry.
func TestBackupRestoreWithoutHostsIgnoresABusyRegistry(t *testing.T) {
	sb := hostsSandbox(t)
	defer hosts.SetLockWait(100 * time.Millisecond)()
	unlock, err := (&hosts.Registry{Path: sb.path("state/linux-hosts")}).Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
}

// A file that cannot be read cannot be compared; the note says so, before
// the question, and the restore still puts the host files back.
func TestBackupRestoreSaysWhenTheHostFilesCannotBeCompared(t *testing.T) {
	for _, file := range []string{"state/linux-uids", "state/linux-hosts"} {
		sb := hostsSandbox(t)
		// A directory where the file should be: reading it fails, and it is
		// not a missing file.
		if err := os.Remove(sb.path(file)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(sb.path(file), 0o700); err != nil {
			t.Fatal(err)
		}
		out := plain(sb.run("n\n", []string{"backup", "restore", "20200101_000000_002"}))
		sb.expect(0, "Cancelled.", "")
		i, j := strings.Index(out, "could not compare the host files: "), strings.Index(out, "Cancelled.")
		if i < 0 || j < i || !strings.Contains(out, "; the restore still puts them back") {
			t.Errorf("%s: no line before the question:\n%s", file, out)
		}
	}
}

func TestRestoreLedgerNoteReportsAnUnreadableLedger(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	if err := os.WriteFile(good, []byte(liveLedger), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(dir, "bad")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{good, bad}, {bad, good}} {
		if _, err := restoreLedgerNote(hosts.UIDs{Path: c[0]}, hosts.UIDs{Path: c[1]}); err == nil {
			t.Errorf("no error for %v", c)
		}
	}
}

// A host step that fails after the render does not leave the restore half
// done: the backends are still restarted, and the failure is a warning that
// names the snapshot to go back to.
func TestBackupRestoreWithAFailingHostStepStillRestarts(t *testing.T) {
	sb := hostsSandbox(t)
	// A directory where the ledger should be: the last of the host files
	// cannot be put back.
	if err := os.Remove(sb.path("state/linux-uids")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sb.path("state/linux-uids"), 0o700); err != nil {
		t.Fatal(err)
	}
	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_002"}))
	if sb.code != 0 {
		t.Fatalf("exit %d: %s", sb.code, sb.stderr())
	}
	dirs := sb.snapshotDirs()
	pre := filepath.Base(dirs[len(dirs)-1])
	for _, want := range []string{
		"Restored snapshot 20200101_000000_002.",
		"The host state was not fully put back: ",
		"The state from before the restore is in snapshot " + pre + ". To undo the restore: tacctl backup restore " + pre + ".",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("no restart: %q", sb.runner.Argvs())
	}
	// The registry went back before the ledger failed.
	if got := sb.read("state/linux-hosts"); got != snapRegistry {
		t.Errorf("registry %q", got)
	}
}
