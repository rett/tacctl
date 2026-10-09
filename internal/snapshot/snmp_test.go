package snapshot

import (
	"os"
	"path/filepath"
	"testing"
)

// WP10.8a A5: snmp.yaml and the per-scope credential files are part of a
// snapshot, in the modes they are kept in, and a change to either makes the
// next Take write a new one (the live state no longer equals the newest).
func TestSnapshotHoldsTheSNMPCredentials(t *testing.T) {
	e := newEnv(t)
	first := e.take()
	if first == "" {
		t.Fatal("no first snapshot")
	}
	for _, n := range []string{"snmp.yaml", "snmp"} {
		if _, err := os.Lstat(filepath.Join(e.backups(), first, n)); err == nil {
			t.Fatalf("%s in a snapshot made without credentials", n)
		}
	}
	// A scope's credentials make a new snapshot, 0600 in a 0700 directory.
	if err := os.Mkdir(filepath.Join(e.state, "snmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	e.write("snmp/lab.yaml", "community: lab-secret\n")
	second := e.take()
	if second == "" || second == first {
		t.Fatalf("credentials of a scope did not make a snapshot: %q", second)
	}
	st, err := os.Stat(filepath.Join(e.backups(), second, "snmp"))
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0o700 {
		t.Errorf("snmp directory: %v %v", st, err)
	}
	st, err = os.Stat(filepath.Join(e.backups(), second, "snmp", "lab.yaml"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("lab.yaml: %v %v", st, err)
	}
	// Unchanged: nothing new. A changed byte, or a second file: new.
	if id := e.take(); id != "" {
		t.Errorf("an unchanged state made %s", id)
	}
	e.write("snmp/lab.yaml", "community: changed\n")
	third := e.take()
	if third == "" {
		t.Fatal("a changed credential file made no snapshot")
	}
	e.write("snmp.yaml", "community: default\n")
	fourth := e.take()
	if fourth == "" {
		t.Fatal("the default file made no snapshot")
	}
	data, err := os.ReadFile(filepath.Join(e.backups(), fourth, "snmp.yaml"))
	if err != nil || string(data) != "community: default\n" {
		t.Errorf("snmp.yaml in the snapshot: %q %v", data, err)
	}
	// A removed scope file is a change too.
	if err := os.Remove(filepath.Join(e.state, "snmp", "lab.yaml")); err != nil {
		t.Fatal(err)
	}
	if id := e.take(); id == "" {
		t.Error("removing a credential file made no snapshot")
	}
}
