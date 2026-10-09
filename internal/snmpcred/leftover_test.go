package snmpcred

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WP10.8a B10: a credentials file the name already has (a leftover of an
// earlier scope, kept by a rollback) is never overwritten by a rename and is
// reported to a new scope of the name.
func TestRenameScopeNeverOverwritesAFile(t *testing.T) {
	dir := t.TempDir()
	if err := SaveScope(dir, "lab", Creds{Community: "lab-community"}); err != nil {
		t.Fatal(err)
	}
	if err := SaveScope(dir, "dmz", Creds{Community: "leftover-community"}); err != nil {
		t.Fatal(err)
	}
	err := RenameScope(dir, "lab", "dmz")
	if err == nil || !strings.Contains(err.Error(), "SNMP credentials for a scope named 'dmz' are already on disk") {
		t.Fatalf("rename onto a leftover: %v", err)
	}
	for scope, want := range map[string]string{"lab": "lab-community", "dmz": "leftover-community"} {
		if c, err := LoadScope(dir, scope); err != nil || c.Community != want {
			t.Errorf("%s: %q %v (want %q: nothing was touched)", scope, c.Community, err, want)
		}
	}
	// Nothing to move is nothing to refuse, whatever the target holds.
	if err := RenameScope(dir, "nosuch", "dmz"); err != nil {
		t.Errorf("no source file: %v", err)
	}
	// A free name still works.
	if err := RenameScope(dir, "lab", "lab2"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lab2.yaml")); err != nil {
		t.Error(err)
	}
}

func TestCheckNoScopeFile(t *testing.T) {
	dir := t.TempDir()
	if err := CheckNoScopeFile(dir, "lab"); err != nil {
		t.Errorf("no file: %v", err)
	}
	if err := SaveScope(dir, "lab", Creds{Community: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := CheckNoScopeFile(dir, "lab"); err == nil || !strings.Contains(err.Error(), filepath.Join(dir, "lab.yaml")) {
		t.Errorf("a leftover: %v", err)
	}
	if err := CheckNoScopeFile(dir, "../x"); err == nil {
		t.Error("an invalid name passed")
	}
}
