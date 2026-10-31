package snapshot

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Keep copies a snapshot, its subdirectories included, with private modes and
// a record; a copy that exists is left as it is but for its note; the copy
// outlives the original; Unkeep removes it.
func TestKeep(t *testing.T) {
	root := t.TempDir()
	backups, kept := filepath.Join(root, "backups"), filepath.Join(root, "backups-kept")
	id := "20261030_010101_001"
	if err := os.MkdirAll(filepath.Join(backups, id, "snmp", "devices"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"store.yaml": "version: 1\n", "manifest": "{}\n", "snmp/lab.yaml": "a\n", "snmp/devices/sw1.yaml": "b\n"}
	for rel, text := range files {
		if err := os.WriteFile(filepath.Join(backups, id, rel), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(backups, id, "link")); err != nil {
		t.Fatal(err)
	}
	info := KeptInfo{Note: "before the upgrade", User: "alice", SID: "k3x9a0bq", At: "2026-10-30T01:02:03Z"}
	got, created, err := Keep(backups, kept, id, info)
	if err != nil || !created || got != filepath.Join(kept, id) {
		t.Fatalf("Keep = %q, %v, %v", got, created, err)
	}
	for rel, text := range files {
		b, err := os.ReadFile(filepath.Join(got, rel))
		st, serr := os.Stat(filepath.Join(got, rel))
		if err != nil || string(b) != text || serr != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %q %v %v", rel, b, err, serr)
		}
	}
	for _, d := range []string{kept, got, filepath.Join(got, "snmp")} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, st, err)
		}
	}
	if st, err := os.Stat(filepath.Join(got, KeptName)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("the record: %v %v", st, err)
	}
	if _, err := os.Lstat(filepath.Join(got, "link")); err == nil {
		t.Error("a symlink was copied")
	}
	if r := ReadKept(got); r != info {
		t.Errorf("ReadKept = %+v", r)
	}
	if ids := KeptIDs(kept); len(ids) != 1 || ids[0] != id {
		t.Errorf("KeptIDs %v", ids)
	}

	// the original goes (a retention); the copy stays; a second Keep with no
	// note changes nothing, with one it replaces the note only
	if err := os.RemoveAll(filepath.Join(backups, id)); err != nil {
		t.Fatal(err)
	}
	if p, created, err := Keep(backups, kept, id, KeptInfo{User: "bob"}); err != nil || created || p != got {
		t.Errorf("second Keep = %q, %v, %v", p, created, err)
	}
	if r := ReadKept(got); r != info {
		t.Errorf("a Keep without a note changed the record: %+v", r)
	}
	if _, created, err := Keep(backups, kept, id, KeptInfo{Note: "new note", User: "bob"}); err != nil || created {
		t.Errorf("third Keep = %v, %v", created, err)
	}
	// a new note replaces the record: who set it and when
	want := KeptInfo{Note: "new note", User: "bob"}
	if r := ReadKept(got); r != want {
		t.Errorf("ReadKept = %+v, want %+v", r, want)
	}
	if m, _ := filepath.Glob(filepath.Join(kept, ".keep.*")); len(m) != 0 {
		t.Errorf("left %v", m)
	}
	for _, bad := range []string{"", "..", "../x", "x", "20261030_010101_002"} {
		if _, _, err := Keep(backups, kept, bad, KeptInfo{}); err == nil {
			t.Errorf("Keep(%q) did not fail", bad)
		}
		if KeptPath(kept, bad) != "" {
			t.Errorf("KeptPath(%q)", bad)
		}
	}
	if err := Unkeep(kept, id); err != nil {
		t.Fatal(err)
	}
	if ids := KeptIDs(kept); len(ids) != 0 {
		t.Errorf("KeptIDs after Unkeep %v", ids)
	}
	if err := Unkeep(kept, id); err == nil {
		t.Error("Unkeep of a copy that is gone did not fail")
	}
}

// Several keeps of one id at once all succeed, one makes the copy, and the
// copy is whole.
func TestKeepConcurrent(t *testing.T) {
	root := t.TempDir()
	backups, kept := filepath.Join(root, "backups"), filepath.Join(root, "backups-kept")
	id := "20261030_010101_001"
	if err := os.MkdirAll(filepath.Join(backups, id), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"store.yaml", "manifest", "a", "b", "c"} {
		if err := os.WriteFile(filepath.Join(backups, id, f), []byte(f+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const n = 12
	var wg sync.WaitGroup
	created := make([]bool, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, created[i], errs[i] = Keep(backups, kept, id, KeptInfo{User: "u", At: "2026-10-30T01:02:03Z"})
		}(i)
	}
	close(start)
	wg.Wait()
	made := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Errorf("keep %d: %v", i, errs[i])
		}
		if created[i] {
			made++
		}
	}
	if made != 1 {
		t.Errorf("%d keeps made the copy, want 1", made)
	}
	for _, f := range []string{"store.yaml", "manifest", "a", "b", "c", KeptName} {
		if _, err := os.Stat(filepath.Join(kept, id, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(kept, ".keep.*")); len(m) != 0 {
		t.Errorf("left %v", m)
	}
}
