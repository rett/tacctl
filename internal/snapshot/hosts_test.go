package snapshot

import (
	"os"
	"path/filepath"
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

func TestSnapshotHoldsTheHostFiles(t *testing.T) {
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
	e := newEnv(t)
	e.take()
	steps := []struct {
		what string
		do   func()
	}{
		{"a registry line", func() { e.write("linux-hosts", "web1|web1||lab|192.0.2.1|\n") }},
		{"a changed registry line", func() { e.write("linux-hosts", "web1|web1||ops|192.0.2.1|\n") }},
		{"a record", func() { e.writeRecord("web1", "{}\n") }},
		{"a changed record", func() { e.writeRecord("web1", "{\"a\":1}\n") }},
		{"a second record", func() { e.writeRecord("web2", "{}\n") }},
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
