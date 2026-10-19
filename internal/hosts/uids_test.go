package hosts

import (
	"os"
	"path/filepath"
	"testing"
)

// Rename moves every line of the old name to the new one where it stands:
// the '#' lines, the order and the numbers stay, and so does the mode.
func TestUIDsRenameMovesTheLinesInPlace(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "linux-uids")
	writeFile(t, p, "# range 80000-89999\nbob:80001\n# kept by hand\nAlice:80000\ncarol:80002\nAlice:80000\n")
	moved, err := UIDs{Path: p}.Rename("Alice", "alice")
	if err != nil || !moved {
		t.Fatalf("moved %v, %v", moved, err)
	}
	if got, want := readFile(t, p), "# range 80000-89999\nbob:80001\n# kept by hand\nalice:80000\ncarol:80002\nalice:80000\n"; got != want {
		t.Errorf("ledger %q, want %q", got, want)
	}
	if st, err := os.Stat(p); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, %v", st, err)
	}
	if uid, _ := (UIDs{Path: p}).Lookup("alice"); uid != "80000" {
		t.Errorf("alice has %q", uid)
	}
	if uid, _ := (UIDs{Path: p}).Lookup("Alice"); uid != "" {
		t.Errorf("Alice still has %q", uid)
	}
	// Moved: a second rename of the old name finds nothing.
	if moved, err := (UIDs{Path: p}).Rename("Alice", "alice"); moved || err != nil {
		t.Errorf("again: %v, %v", moved, err)
	}
}

// No line for the old name, no file, or a new name that has a line already:
// the ledger is not written.
func TestUIDsRenameLeavesTheLedgerAlone(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "linux-uids")
	if moved, err := (UIDs{Path: p}).Rename("a", "b"); moved || err != nil {
		t.Errorf("no file: %v, %v", moved, err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Error("a missing ledger was created")
	}
	const text = "# range 80000-89999\nAlice:80000\nalice:80003\nbob:80001\n"
	writeFile(t, p, text)
	for _, c := range [][2]string{{"carol", "dave"}, {"Alice", "alice"}, {"Alice", "bob"}} {
		moved, err := UIDs{Path: p}.Rename(c[0], c[1])
		if moved || err != nil {
			t.Errorf("%v: %v, %v", c, moved, err)
		}
		if readFile(t, p) != text {
			t.Errorf("%v changed the ledger: %q", c, readFile(t, p))
		}
	}
}

// A ledger that cannot be written is an error and is left as it was.
func TestUIDsRenameWriteFailure(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "linux-uids")
	writeFile(t, p, "ann:80000\n")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0o700) }()
	if os.Geteuid() == 0 {
		t.Skip("root writes anywhere")
	}
	if moved, err := (UIDs{Path: p}).Rename("ann", "bea"); moved || err == nil {
		t.Errorf("moved %v, %v", moved, err)
	}
	if readFile(t, p) != "ann:80000\n" {
		t.Errorf("ledger %q", readFile(t, p))
	}
}
