package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 0.2.14 WP14.7 (D188-D190): the registry of enrolled hosts, its records,
// the staging addresses and the UID ledger are part of a snapshot, in the
// modes they are kept in; linux-hosts is in every snapshot (empty when there
// is no registry); the dedupe compares all of it.

func (e *env) writeRecord(name, text string) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Join(e.state, "hosts"), 0o700); err != nil {
		e.t.Fatal(err)
	}
	e.write("hosts/"+name+".json", text)
}

// rotated is a host record with a provisioner entry (the part of a record a
// restore must bring back, D209), the old login being old.
func rotated(old string) string {
	return `{"provisioner":{"at":"2026-01-01T00:00:00Z","by":"admin","old":"` + old +
		`","new":"tacprov","auth":"key","old_removed":false}}` + "\n"
}

// synced is a host record that holds what a sync writes (the volatile part,
// D209), stamped with n.
func synced(n string) string {
	return `{"last_sync":{"at":"` + n + `","by":"admin","command":"sync","ok":true,"protocol":"3",` +
		`"created":[],"updated":[],"removed":[]},"facts":{"at":"` + n + `","os_name":"debian"}}` + "\n"
}

func TestSnapshotHoldsTheHostFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n")
	e.writeRecord("web1", "{}\n")
	e.write("staging", "192.0.2.9/32|lab|host|web1|2026-01-01\n")
	e.write("linux-uids", "# range 80000-89999\nalice:80000\n")
	// Not part of it: the provisioner's lock, a record being written, the
	// lock of the registry.
	e.write("host-provisioner-web1.lock", "")
	e.write(".hosts.lock", "")
	e.write("hosts/.web1.123", "partial")

	id := e.take()
	dir := filepath.Join(e.backups(), id)
	for name, want := range map[string]string{
		"linux-hosts":     "web1|web1||lab|192.0.2.1|\n",
		"hosts/web1.json": "{}\n",
		"staging":         "192.0.2.9/32|lab|host|web1|2026-01-01\n",
		"linux-uids":      "# range 80000-89999\nalice:80000\n",
	} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || string(data) != want {
			t.Errorf("%s: %q %v", name, data, err)
		}
		if m := mode(t, filepath.Join(dir, name)); m != 0o600 {
			t.Errorf("%s mode %o", name, m)
		}
	}
	if m := mode(t, filepath.Join(dir, "hosts")); m != 0o700 {
		t.Errorf("hosts directory mode %o", m)
	}
	for _, n := range []string{"host-provisioner-web1.lock", ".hosts.lock", "hosts/.web1.123"} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s is in the snapshot", n)
		}
	}
}

// D189: linux-hosts is written even when there is no registry, empty; the
// other entries only when they exist.
func TestSnapshotWithoutHostsHasAnEmptyRegistryOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	id := e.take()
	dir := filepath.Join(e.backups(), id)
	st, err := os.Stat(filepath.Join(dir, "linux-hosts"))
	if err != nil || !st.Mode().IsRegular() || st.Size() != 0 || st.Mode().Perm() != 0o600 {
		t.Fatalf("linux-hosts: %v %v", st, err)
	}
	if !KnowsHosts(dir) {
		t.Error("a snapshot with an empty linux-hosts does not know the hosts")
	}
	for _, n := range []string{"hosts", "staging", "linux-uids"} {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("%s in a snapshot made without it", n)
		}
	}
	// Taken again with nothing changed: deduped (an absent registry equals the
	// empty one the snapshot holds).
	if again := e.take(); again != "" {
		t.Errorf("an unchanged state made %s", again)
	}
	// An empty registry file is the same state.
	e.write("linux-hosts", "")
	if again := e.take(); again != "" {
		t.Errorf("an empty registry made %s", again)
	}
}

// D190: a change of any host entry makes the next Take write a snapshot.
func TestSnapshotDedupeSeesTheHostFiles(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.take()
	steps := []struct {
		what string
		do   func()
	}{
		{"a registry line", func() { e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n") }},
		{"a changed registry line", func() { e.write("linux-hosts", "web1|web1||ops|192.0.2.1|\n") }},
		{"a record", func() { e.writeRecord("web1", rotated("old1")) }},
		{"a changed record", func() { e.writeRecord("web1", rotated("old2")) }},
		{"a second record", func() { e.writeRecord("web2", rotated("old1")) }},
		{"staging", func() { e.write("staging", "192.0.2.9/32|lab|host|web1|2026-01-01\n") }},
		{"the ledger", func() { e.write("linux-uids", "# range 80000-89999\nalice:80000\n") }},
		{"a changed ledger", func() { e.appendTo("linux-uids", "bob:80001\n") }},
		{"a removed record", func() { _ = os.Remove(filepath.Join(e.state, "hosts", "web2.json")) }},
		{"a removed staging file", func() { _ = os.Remove(filepath.Join(e.state, "staging")) }},
		{"a removed ledger", func() { _ = os.Remove(filepath.Join(e.state, "linux-uids")) }},
		{"a removed registry", func() { _ = os.Remove(filepath.Join(e.state, "linux-hosts")) }},
	}
	for _, s := range steps {
		s.do()
		if id := e.take(); id == "" {
			t.Errorf("%s made no snapshot", s.what)
		}
		if id := e.take(); id != "" {
			t.Errorf("after %s, an unchanged state made %s", s.what, id)
		}
	}
	// The lock files and a record being written are no change.
	e.write(".hosts.lock", "")
	e.write("host-provisioner-web1.lock", "")
	e.write("hosts/.web1.1", "partial")
	if id := e.take(); id != "" {
		t.Errorf("lock files made %s", id)
	}
}

// A snapshot of 0.2.13 or older (no linux-hosts) is never the current state:
// the first Take after the upgrade writes one that knows the hosts.
func TestSnapshotWithoutLinuxHostsIsNotCurrent(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.mkSnapshot("20200101_000000_001", "version: 1\n")
	if KnowsHosts(filepath.Join(e.backups(), "20200101_000000_001")) {
		t.Fatal("a hand-made snapshot knows the hosts")
	}
	id := e.take()
	if id == "" {
		t.Fatal("the store equals the newest snapshot, which does not know the hosts: no snapshot was taken")
	}
	if !KnowsHosts(filepath.Join(e.backups(), id)) {
		t.Error("the new snapshot does not know the hosts")
	}
}

// D209, D210: what a sync writes into a record (last_sync, facts) is no change
// for the dedupe; a provisioner entry is.
func TestSnapshotDedupeIgnoresWhatASyncWrites(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n")
	e.writeRecord("web1", synced("2026-01-01T00:00:00Z"))
	e.writeRecord("web2", rotated("old1"))
	id := e.take()
	if id == "" {
		t.Fatal("no first snapshot")
	}

	// A sync of web1 (a new stamp, other facts, a failed run) and of web2
	// (the provisioner entry stays).
	e.writeRecord("web1", synced("2026-02-02T00:00:00Z"))
	if again := e.take(); again != "" {
		t.Errorf("a sync of one host made %s", again)
	}
	e.writeRecord("web1", `{"last_sync":{"at":"x","ok":false,"reason":"unreachable"}}`+"\n")
	e.writeRecord("web2", `{"last_sync":{"at":"x"},"provisioner":`+
		`{"old_removed":false,"auth":"key","new":"tacprov","old":"old1","by":"admin","at":"2026-01-01T00:00:00Z"}}`+"\n")
	if again := e.take(); again != "" {
		t.Errorf("a sync, with the provisioner fields in another order, made %s", again)
	}
	if got := e.snapshots(); len(got) != 1 {
		t.Errorf("snapshots %v", got)
	}

	// A rotation of web2 is a change; so is a flag of it.
	e.writeRecord("web2", rotated("old2"))
	if e.take() == "" {
		t.Error("a changed provisioner entry made no snapshot")
	}
	e.writeRecord("web2", strings.Replace(rotated("old2"), `"old_removed":false`, `"old_removed":true`, 1))
	if e.take() == "" {
		t.Error("a provisioner entry that gained old_removed made no snapshot")
	}
	// A provisioner entry that went (the record was replaced) is one too.
	e.writeRecord("web2", synced("2026-03-03T00:00:00Z"))
	if e.take() == "" {
		t.Error("a record that lost its provisioner entry made no snapshot")
	}
	if again := e.take(); again != "" {
		t.Errorf("an unchanged state made %s", again)
	}
}

// D210: a record on one side only is equal when it holds nothing but what a
// sync writes; with a provisioner entry it is not.
func TestSnapshotDedupeOfARecordOnOneSideOnly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n")
	e.take()

	// Live has a record the snapshot lacks.
	e.writeRecord("web1", synced("2026-01-01T00:00:00Z"))
	if again := e.take(); again != "" {
		t.Errorf("a record of a sync only made %s", again)
	}
	e.writeRecord("web1", "{}\n")
	if again := e.take(); again != "" {
		t.Errorf("an empty record made %s", again)
	}
	e.writeRecord("web1", rotated("old1"))
	if e.take() == "" {
		t.Error("a live record with a provisioner entry made no snapshot")
	}

	// The snapshot has a record the live state lacks.
	if err := os.Remove(filepath.Join(e.state, "hosts", "web1.json")); err != nil {
		t.Fatal(err)
	}
	if e.take() == "" {
		t.Error("a snapshot record with a provisioner entry that went made no snapshot")
	}
	e.writeRecord("web1", synced("2026-01-01T00:00:00Z"))
	e.take()
	if err := os.Remove(filepath.Join(e.state, "hosts", "web1.json")); err != nil {
		t.Fatal(err)
	}
	if again := e.take(); again != "" {
		t.Errorf("a snapshot record of a sync only that went made %s", again)
	}
}

// A record that cannot be read is compared by its bytes.
func TestSnapshotDedupeOfAnUnreadableRecord(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n")
	e.writeRecord("web1", "not json\n")
	if e.take() == "" {
		t.Fatal("no first snapshot")
	}
	if again := e.take(); again != "" {
		t.Errorf("the same unreadable record made %s", again)
	}
	e.writeRecord("web1", "not json either\n")
	if e.take() == "" {
		t.Error("another unreadable record made no snapshot")
	}
}

// D211: with Exact the records are compared byte for byte.
func TestSnapshotExactSeesWhatASyncWrites(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n")
	e.writeRecord("web1", synced("2026-01-01T00:00:00Z"))
	e.take()
	e.writeRecord("web1", synced("2026-02-02T00:00:00Z"))
	e.s.Exact = true
	if e.take() == "" {
		t.Error("an exact comparison ignored a changed last_sync")
	}
	e.s.Exact = false
	e.writeRecord("web1", synced("2026-03-03T00:00:00Z"))
	if again := e.take(); again != "" {
		t.Errorf("the comparison stayed exact: %s", again)
	}
}

// D239: the copy of the UID ledger into a snapshot is made under the ledger's
// lock, and the lock is let go when the copy is done. A snapshot without a
// ledger takes none. A lock that cannot be taken fails the snapshot with the
// lock's own error, and leaves no snapshot.
func TestSnapshotCopiesTheLedgerUnderItsLock(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-uids", "# range 80000-89999\nalice:80000\n")
	held := false
	locks := 0
	e.s.LedgerLock = func() (func(), error) {
		locks++
		held = true
		return func() { held = false }, nil
	}

	id := e.take()
	if locks != 1 || held {
		t.Errorf("%d locks taken, held after: %v", locks, held)
	}
	if data, err := os.ReadFile(filepath.Join(e.backups(), id, "linux-uids")); err != nil || string(data) != "# range 80000-89999\nalice:80000\n" {
		t.Errorf("copy %q %v", data, err)
	}

	// No ledger: no lock.
	e2 := newEnv(t)
	n := 0
	e2.s.LedgerLock = func() (func(), error) { n++; return func() {}, nil }
	e2.take()
	if n != 0 {
		t.Errorf("%d locks for a snapshot without a ledger", n)
	}
}

func TestSnapshotFailsWithTheLedgerLocksOwnError(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.write("linux-uids", "alice:80000\n")
	busy := errors.New("the UID ledger (linux-uids) is locked by another tacctl command")
	e.s.LedgerLock = func() (func(), error) { return nil, busy }
	if id, err := e.s.Take(); err != busy || id != "" {
		t.Errorf("Take: %q, %v", id, err)
	}
	if ids := IDs(e.backups()); len(ids) != 0 {
		t.Errorf("snapshots %q", ids)
	}
	if left, _ := filepath.Glob(filepath.Join(e.backups(), ".snap.*")); len(left) != 0 {
		t.Errorf("left behind: %q", left)
	}
}
