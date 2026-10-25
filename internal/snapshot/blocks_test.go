package snapshot

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// writeBlock puts a block file under the live blocks directory, directories
// 0700 and the file 0600 as the store makes them.
func (e *env) writeBlock(rel, text string) {
	e.t.Helper()
	p := filepath.Join(e.state, "blocks", filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// The configuration blocks of 0.2.7 are part of a snapshot, in the modes they
// are kept in at every depth, and a change to any of them (new file, changed
// bytes, removed file) makes the next Take write a new one.
func TestSnapshotHoldsTheBlocks(t *testing.T) {
	e := newEnv(t)
	first := e.take()
	if first == "" {
		t.Fatal("no first snapshot")
	}
	if _, err := os.Lstat(filepath.Join(e.backups(), first, "blocks")); err == nil {
		t.Fatal("blocks in a snapshot made without any")
	}
	// A directory with no file in it is no block: nothing new.
	if err := os.MkdirAll(filepath.Join(e.state, "blocks", "lab", "juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if id := e.take(); id != "" {
		t.Errorf("an empty blocks directory made %s", id)
	}

	e.writeBlock("lab/juniper/snmp", "set snmp community lab-ro authorization read-only\n")
	e.writeBlock("_devices/jsw1.lab.example.net/juniper/system", "set system time-zone UTC\n")
	second := e.take()
	if second == "" || second == first {
		t.Fatalf("blocks did not make a snapshot: %q", second)
	}
	snap := filepath.Join(e.backups(), second, "blocks")
	for _, d := range []string{"", "lab", "lab/juniper", "_devices", "_devices/jsw1.lab.example.net", "_devices/jsw1.lab.example.net/juniper"} {
		st, err := os.Stat(filepath.Join(snap, filepath.FromSlash(d)))
		if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
			t.Errorf("directory %q: %v %v", d, st, err)
		}
	}
	for _, f := range []string{"lab/juniper/snmp", "_devices/jsw1.lab.example.net/juniper/system"} {
		st, err := os.Stat(filepath.Join(snap, filepath.FromSlash(f)))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("file %q: %v %v", f, st, err)
		}
	}
	got := BlockFiles(snap)
	if want := []string{"_devices/jsw1.lab.example.net/juniper/system", "lab/juniper/snmp"}; !slices.Equal(got, want) {
		t.Errorf("BlockFiles = %q, want %q", got, want)
	}
	data, err := os.ReadFile(filepath.Join(snap, "lab", "juniper", "snmp"))
	if err != nil || string(data) != "set snmp community lab-ro authorization read-only\n" {
		t.Errorf("block in the snapshot: %q %v", data, err)
	}

	// Unchanged: nothing new. A changed byte, a new file, a removed one: new.
	if id := e.take(); id != "" {
		t.Errorf("an unchanged state made %s", id)
	}
	e.writeBlock("lab/juniper/snmp", "set snmp community lab-ro authorization read-write\n")
	if id := e.take(); id == "" {
		t.Fatal("a changed block made no snapshot")
	}
	e.writeBlock("lab/juniper/system", "set system domain-name lab.example.net\n")
	if id := e.take(); id == "" {
		t.Fatal("a new block made no snapshot")
	}
	if err := os.Remove(filepath.Join(e.state, "blocks", "lab", "juniper", "system")); err != nil {
		t.Fatal(err)
	}
	if id := e.take(); id == "" {
		t.Error("a removed block made no snapshot")
	}
	// The last one holds what is live.
	ids := IDs(e.backups())
	if !e.s.current(filepath.Join(e.backups(), ids[0])) {
		t.Error("the newest snapshot is not the live state")
	}
}

// A symbolic link is not a block file and is never followed into a snapshot.
func TestBlockFilesSkipSymbolicLinks(t *testing.T) {
	e := newEnv(t)
	e.writeBlock("lab/juniper/snmp", "x\n")
	out := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(out, []byte("outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(e.state, "blocks", "lab", "juniper", "system")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(out), filepath.Join(e.state, "blocks", "linked")); err != nil {
		t.Fatal(err)
	}
	got := BlockFiles(filepath.Join(e.state, "blocks"))
	if want := []string{"lab/juniper/snmp"}; !slices.Equal(got, want) {
		t.Errorf("BlockFiles = %q, want %q", got, want)
	}
	id := e.take()
	if id == "" {
		t.Fatal("no snapshot")
	}
	if got := BlockFiles(filepath.Join(e.backups(), id, "blocks")); !slices.Equal(got, []string{"lab/juniper/snmp"}) {
		t.Errorf("snapshot holds %q", got)
	}
}

func TestBlockFilesOfNothing(t *testing.T) {
	if got := BlockFiles(""); got != nil {
		t.Errorf("BlockFiles(\"\") = %q", got)
	}
	if got := BlockFiles(filepath.Join(t.TempDir(), "absent")); got != nil {
		t.Errorf("BlockFiles(absent) = %q", got)
	}
}
