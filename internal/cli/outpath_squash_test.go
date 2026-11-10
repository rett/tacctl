package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// squashedDir makes a directory inside the sandbox's home that its owner
// cannot write, with a file in it: what a home on an NFS export with
// root_squash that others may search (0755, say) is to the two commands that
// write as root under sudo, where root is mapped to an unprivileged account
// and the path check, which ran as root and only looks at where the path is,
// has passed. The test process is not root, so the refusal comes from the
// kernel, as the server's does (EACCES).
func squashedDir(t *testing.T, home string) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root writes into a directory without the write permission, so there is no refusal to see")
	}
	d := filepath.Join(home, "squashed")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "old.sh"), []byte("# old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d, 0o700) })
	return d
}

// leftIn is the names in dir, to prove that a refused write left nothing.
func leftIn(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

// A path inside a home that others may search but root, mapped to an
// unprivileged account, cannot write (an NFS root_squash export) passes the
// check of outPath and is refused by the write: each of the three commands
// that write as root says in one line which path was not written and why
// ("Permission denied"), exits 1, and leaves no new or half-written file and
// the old one as it was.
func TestOutPathRootSquashedHomeIsRefusedPlainly(t *testing.T) {
	hs := newHostSandbox(t)
	d := squashedDir(t, hs.dir)
	want := []string{"old.sh"}
	same := func(what string) {
		t.Helper()
		if got := leftIn(t, d); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s: left %v, want %v", what, got, want)
		}
		if b, _ := os.ReadFile(filepath.Join(d, "old.sh")); string(b) != "# old\n" {
			t.Errorf("%s: the old file is now %q", what, b)
		}
	}
	for _, name := range []string{"new.sh", "old.sh"} {
		path := filepath.Join(d, name)
		hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "--output", path)
		hs.expect(1, "", "Cannot write "+path+": Permission denied")
		same("script " + name)
		hs.run(nil, "config", "linux", "remove-script", "--output", path)
		hs.expect(1, "", "install: cannot ")
		if !strings.Contains(hs.err.String(), "'"+path+"': Permission denied") {
			t.Errorf("remove-script %s: %q", name, hs.err.String())
		}
		same("remove-script " + name)
	}

	// 'config render --dry-run --out': a directory to make, then one that
	// exists and is empty
	out := filepath.Join(d, "preview")
	hs.run(nil, "config", "render", "--dry-run", "--out", out)
	hs.expect(1, "", "Cannot create '"+out+"': Permission denied")
	same("render --dry-run (new directory)")
}

// The same for a directory that exists, is empty and cannot be written.
func TestOutPathRootSquashedEmptyDirIsRefusedPlainly(t *testing.T) {
	sb := newSandbox(t, true)
	home := sb.homePath("")
	d := squashedDir(t, home)
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(d, "old.sh")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o500); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"config", "render", "--dry-run", "--out", d})
	sb.expect(1, "", "Cannot write "+d+"/")
	if !strings.Contains(sb.stderr(), ": Permission denied") {
		t.Errorf("not told why: %q", sb.stderr())
	}
	if got := leftIn(t, d); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}

// A home that others may not search (0700, 0750), seen as the unprivileged
// account root is mapped to, is refused by the path check itself, for every
// command that names a path (the three that write as root are run here): the
// check cannot resolve the path. Mode 0000 stands for it here, since the test
// user owns the directory and could search anything less. Nothing is written.
func TestOutPathRootSquashedHomeOthersCannotSearchIsRefusedByTheCheck(t *testing.T) {
	hs := newHostSandbox(t)
	if os.Geteuid() == 0 {
		t.Skip("root searches a directory without the search permission, so there is no refusal to see")
	}
	d := filepath.Join(hs.dir, "closed")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(d, 0o700) })
	path := filepath.Join(d, "x")
	for _, args := range [][]string{
		{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.10", "--output", path},
		{"config", "linux", "remove-script", "--output", path},
		{"config", "render", "--dry-run", "--out", path},
	} {
		hs.run(nil, args...)
		if hs.code != 1 {
			t.Errorf("%v: status %d, want 1", args, hs.code)
		}
		flag := args[len(args)-2]
		if want := flag + " '" + path + "' cannot be resolved (Permission denied)"; !strings.Contains(hs.err.String(), want) {
			t.Errorf("%v: stderr %q, want it to hold %q", args, hs.err.String(), want)
		}
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := leftIn(t, d); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}
