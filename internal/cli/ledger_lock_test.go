package cli

// The UID ledger's lock (0.2.16 WP16.5, D238-D242): the commands that write
// the ledger or decide from it hold <state>/.linux-uids.lock for their
// read-modify-write window and nothing longer; the commands that only
// display it take none.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/hosts"
)

// busyLedger is the refusal after the (shortened) wait.
const busyLedger = "the UID ledger (linux-uids) is locked by another tacctl command; try again in a moment (waited 100ms)"

// holdLedger takes the ledger's lock as another command would and keeps it
// until the test ends. The wait is one variable of the process: the test
// must be serial and calls shortLockWait.
func holdLedger(t *testing.T, sb *sandbox) {
	t.Helper()
	shortLockWait(t)
	unlock, err := (hosts.UIDs{Path: sb.path("state/linux-uids")}).Lock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(unlock)
}

// 'config linux uid <user> <uid>' holds the lock from the holder check to the
// end of the write: a ledger another command holds refuses it, with nothing
// changed; the listing and the lookup take no lock.
func TestLedgerLockRefusesConfigLinuxUIDAndNotTheListing(t *testing.T) {
	serial(t)
	hs := newHostSandbox(t)
	const ledger = "# range 80000-89999\nalice:80000\nbob:80001\n"
	hs.write("state/linux-uids", ledger, 0o600)
	holdLedger(t, hs.sandbox)

	hs.run(nil, "config", "linux", "uid", "alice", "80005")
	hs.expect(1, "", "[ERROR] "+busyLedger)
	if got := hs.read("state/linux-uids"); got != ledger {
		t.Errorf("the ledger changed: %q", got)
	}

	// Display readers: the listing, the lookup, the UID column.
	out := plain(hs.run(nil, "config", "linux", "uid"))
	hs.expect(0, "alice", "")
	if !strings.Contains(out, "80001") {
		t.Errorf("listing %q", out)
	}
	hs.run(nil, "config", "linux", "uid", "bob")
	hs.expect(0, "80001\n", "")
	hs.run(nil, "user", "list")
	hs.expect(0, "80000", "")
	hs.run(nil, "config", "linux", "uid-range")
	hs.expect(0, "is numbered for 80000-89999", "")
}

// A ledger that has to be renumbered is rewritten under the lock, so a held
// lock refuses the listing that would have done it; the file is as it was.
func TestLedgerLockRefusesARenumberingAndNothingChanges(t *testing.T) {
	serial(t)
	hs := newHostSandbox(t)
	const legacy = "alice:20000\nbob:20001\n"
	hs.write("state/linux-uids", legacy, 0o600)
	holdLedger(t, hs.sandbox)
	hs.run(nil, "config", "linux", "uid")
	hs.expect(1, "", "[ERROR] "+busyLedger)
	if got := hs.read("state/linux-uids"); got != legacy {
		t.Errorf("the ledger changed: %q", got)
	}
	if left, _ := filepath.Glob(hs.path("state", "linux-uids.pre-renumber-*")); len(left) != 0 {
		t.Errorf("a backup of a renumbering that did not happen: %q", left)
	}
	// 'config linux uid-range' checks first and changes nothing.
	hs.run(nil, "config", "linux", "uid-range", "70000-79999")
	hs.expect(1, "", "[ERROR] "+busyLedger)
	if got := hs.read("state/linux-uids"); got != legacy {
		t.Errorf("uid-range changed the ledger: %q", got)
	}
	if data, err := os.ReadFile(hs.path("state", "tacctl.yaml")); err == nil && strings.Contains(string(data), "uid_min") {
		t.Errorf("uid-range changed tacctl.yaml:\n%s", data)
	}
}

// 'host sync' is refused at the first thing it does with the ledger, before
// any ssh to a host.
func TestLedgerLockRefusesHostSyncBeforeAnySSH(t *testing.T) {
	serial(t)
	hs := newHostSandbox(t)
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	hs.write("state/linux-uids", "# range 80000-89999\nalice:80000\n", 0o600)
	holdLedger(t, hs.sandbox)
	r := hs.runner()
	hs.run(r, "host", "sync", "web1")
	hs.expect(1, "", "[ERROR] "+busyLedger)
	if n := r.Count("ssh") + r.Count("ssh-keyscan"); n != 0 {
		t.Errorf("%d ssh calls: %q", n, r.Argvs())
	}
	if got := hs.read("state/linux-uids"); got != "# range 80000-89999\nalice:80000\n" {
		t.Errorf("the ledger changed: %q", got)
	}
}

// A sync holds the ledger's lock while the script is built and lets go
// before the script is copied and run: at the first ssh call of the run the
// lock is free, and a command that needs it does not wait for the host.
func TestLedgerLockIsNotHeldAcrossTheRunOnTheHost(t *testing.T) {
	serial(t)
	hs := newHostSandbox(t)
	hs.write("state/linux-hosts", "web1|admin@web1.example.net||lab|192.0.2.1|\n", 0o600)
	shortLockWait(t)
	uids := hosts.UIDs{Path: hs.path("state/linux-uids")}
	var inRun []error
	r := hs.runner()
	r.Func(func(c execx.Cmd) bool { return c.Name == "ssh" }, func(c execx.Cmd) (execx.Result, error) {
		joined := strings.Join(c.Args, " ")
		if strings.Contains(joined, "mktemp") || strings.Contains(joined, "rm -f") {
			// Another command's window, in the middle of the run on the host.
			inRun = append(inRun, uids.WithLock(func() error { _, err := uids.For("zed"); return err }))
		}
		if strings.Contains(joined, "mktemp") {
			b, _ := io.ReadAll(c.Stdin)
			hs.pushed = string(b)
			return execx.Result{Stdout: []byte("/tmp/tacctl.AbCd1234\n")}, nil
		}
		return execx.Result{}, nil
	})
	hs.run(r, "host", "sync", "web1", "--allow-uid-mismatch", "--remove-home")
	hs.expect(0, "web1: synced (3 users).", "")
	if len(inRun) < 2 {
		t.Fatalf("the run made %d ssh calls that matter", len(inRun))
	}
	for i, err := range inRun {
		if err != nil {
			t.Errorf("call %d: the ledger lock was held during the run: %v", i, err)
		}
	}
	// The sync allocated the numbers it sent, and the window in the run took
	// the next one.
	want := "# range 80000-89999\nalice:80000\nbob:80001\ncarol:80002\nzed:80003\n"
	if got := hs.read("state/linux-uids"); got != want {
		t.Errorf("ledger %q, want %q", got, want)
	}
	if !strings.Contains(hs.pushed, "alice:superuser:80000\\nbob:operator:80001\\ncarol:readonly:80002") {
		t.Errorf("script users:\n%s", strings.SplitN(hs.pushed, "# --- tacctl", 2)[0])
	}
}

// 'user rename' needs the ledger twice: the pre-change snapshot copies it
// under the lock, and the move holds it. A ledger another command holds
// refuses the rename at the snapshot, with nothing changed.
func TestLedgerLockRefusesUserRenameBeforeAnythingChanges(t *testing.T) {
	serial(t)
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", renameLedger, 0o600)
	holdLedger(t, sb)
	store := sb.store()
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(1, "", "[ERROR] "+busyLedger)
	if sb.store() != store {
		t.Error("the store changed")
	}
	if sb.read("state/linux-uids") != renameLedger {
		t.Errorf("ledger %q", sb.read("state/linux-uids"))
	}
	if sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Error("tacquito was restarted")
	}
}

// The move itself, with the lock held past the wait: the error is the move's
// (the command reports the rename as done and names the snapshot to restore),
// and the ledger is as it was. Released, the move goes through.
func TestLedgerLockMoveUIDReportsABusyLedger(t *testing.T) {
	serial(t)
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", renameLedger, 0o600)
	inv := &invocation{app: newHarness(t, nil, sb.env...).app, hooks: newTestHooks()}
	shortLockWait(t)
	unlock, err := (hosts.UIDs{Path: sb.path("state/linux-uids")}).Lock()
	if err != nil {
		t.Fatal(err)
	}
	mv := inv.moveUID("alice", "zed")
	if !errors.Is(mv.err, hosts.ErrLedgerBusy) || mv.moved {
		t.Errorf("move %+v", mv)
	}
	if sb.read("state/linux-uids") != renameLedger {
		t.Errorf("ledger %q", sb.read("state/linux-uids"))
	}
	unlock()
	if mv := inv.moveUID("alice", "zed"); mv.err != nil || !mv.moved || mv.uid != "80001" {
		t.Errorf("move after release %+v", mv)
	}
}

// The restore takes the ledger's lock for the put (first, so a held ledger
// stops it before a host file changes) and takes none with --keep-uids.
func TestLedgerLockRestoreHostsUnderTheLock(t *testing.T) {
	serial(t)
	sb := hostsSandbox(t)
	inv := &invocation{app: newHarness(t, nil, sb.env...).app, hooks: newTestHooks()}
	dir := sb.path("state/backups/20200101_000000_002")
	before := sb.hostState()
	shortLockWait(t)
	unlock, err := (hosts.UIDs{Path: sb.path("state/linux-uids")}).Lock()
	if err != nil {
		t.Fatal(err)
	}

	// Held: the restore is refused, and no host file has changed.
	if err := inv.restoreHosts(dir, false); !errors.Is(err, hosts.ErrLedgerBusy) {
		t.Fatalf("restoreHosts: %v", err)
	}
	if !mapsEqual(sb.hostState(), before) {
		t.Errorf("a host file changed:\n%v\nwant\n%v", sb.hostState(), before)
	}

	// --keep-uids does not need the lock: the rest comes back, the ledger stays.
	if err := inv.restoreHosts(dir, true); err != nil {
		t.Fatalf("restoreHosts --keep-uids with the ledger held: %v", err)
	}
	got := sb.hostState()
	if got["linux-hosts"] != snapRegistry || got["linux-uids"] != liveLedger {
		t.Errorf("state after --keep-uids: %v", got)
	}

	// Released: the ledger is put back, and the lock is let go again.
	unlock()
	if err := inv.restoreHosts(dir, false); err != nil {
		t.Fatalf("restoreHosts: %v", err)
	}
	if got := sb.hostState()["linux-uids"]; got != snapLedger {
		t.Errorf("ledger %q, want %q", got, snapLedger)
	}
	if err := (hosts.UIDs{Path: sb.path("state/linux-uids")}).WithLock(func() error { return nil }); err != nil {
		t.Errorf("the restore kept the lock: %v", err)
	}
}

// 'backup restore' end to end with the ledger held: refused at the
// pre-restore snapshot (which copies the ledger under the lock) with nothing
// changed; with --keep-uids, which touches the ledger not at all, it goes
// through.
func TestLedgerLockBackupRestore(t *testing.T) {
	serial(t)
	sb := hostsSandbox(t)
	holdLedger(t, sb)
	before := sb.hostState()
	snaps := len(sb.snapshotDirs())
	live := sb.read("state/store.yaml")

	sb.run("y\n", []string{"backup", "restore", "20200101_000000_002"})
	sb.expect(1, "", "[ERROR] "+busyLedger)
	if !strings.Contains(sb.stderr(), "Nothing was changed.") {
		t.Errorf("stderr %q", sb.stderr())
	}
	if !mapsEqual(sb.hostState(), before) || len(sb.snapshotDirs()) != snaps || sb.read("state/store.yaml") != live {
		t.Error("the refused restore changed something")
	}

	sb.run("y\n", []string{"backup", "restore", "20200101_000000_002", "--keep-uids"})
	sb.expect(0, "Restored snapshot 20200101_000000_002.", "")
	got := sb.hostState()
	if got["linux-hosts"] != snapRegistry || got["linux-uids"] != liveLedger {
		t.Errorf("state after --keep-uids: %v", got)
	}
	// The undo snapshot of the restore holds the ledger it left alone.
	dirs := sb.snapshotDirs()
	if len(dirs) != snaps+1 {
		t.Fatalf("%d snapshots, want %d", len(dirs), snaps+1)
	}
	if got := readIn(t, dirs[len(dirs)-1], "linux-uids"); got != liveLedger {
		t.Errorf("the pre-restore snapshot holds %q", got)
	}

	// Display: the diff against a snapshot reads the ledger without a lock.
	sb.run("", []string{"backup", "diff", "20200101_000000_002"})
	sb.expect(0, "linux-uids", "")
}

// The warning after a restore is computed from the ledger the pre-restore
// snapshot copied against the one that was put back, so a number allocated
// after the question is in it (D242).
func TestLedgerLockRestoreWarningComesFromThePreRestoreCopy(t *testing.T) {
	sb := hostsSandbox(t)
	inv := &invocation{app: newHarness(t, nil, sb.env...).app, hooks: newTestHooks()}
	snap := sb.path("state/backups/20200101_000000_002")
	head, ledger := inv.restoreHostsNote(snap, false)
	if !strings.Contains(ledger, "bob (80001 becomes 80009), carol (80002, dropped)") {
		t.Fatalf("the note of the question: %q", ledger)
	}
	if len(head) == 0 {
		t.Fatal("no registry note")
	}

	// dave was given a number after the question, before the pre-restore copy.
	sb.write("state/backups/20200101_000000_003/store.yaml", "", 0o600)
	sb.write("state/backups/20200101_000000_003/linux-hosts", liveRegistry, 0o600)
	sb.write("state/backups/20200101_000000_003/linux-uids", liveLedger+"dave:80003\n", 0o600)
	after := inv.restoreHostsNoteAfter(head, ledger, snap, "20200101_000000_003")
	if len(after) != len(head)+1 {
		t.Fatalf("lines %q", after)
	}
	last := after[len(after)-1]
	if !strings.Contains(last, "carol (80002, dropped), dave (80003, dropped)") {
		t.Errorf("the ledger line after the restore: %q", last)
	}
	// A pre-restore snapshot that cannot be read leaves the question's line.
	after = inv.restoreHostsNoteAfter(head, ledger, snap, "(none)")
	if after[len(after)-1] != ledger {
		t.Errorf("without a copy: %q", after)
	}
}
