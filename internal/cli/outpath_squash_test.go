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
// account root is mapped to, is refused by the path check itself for the
// commands that write as root (the three of them are run here): the check
// cannot resolve the path, and says what the system says, with the path and
// without the hint about '~'. Mode 0000 stands for it here, since the test
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
		if strings.Contains(hs.err.String(), "~") {
			t.Errorf("%v: the refusal carries the hint about '~': %q", args, hs.err.String())
		}
	}
	if err := os.Chmod(d, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := leftIn(t, d); len(got) != 0 {
		t.Errorf("left %v", got)
	}
}

// closedForRoot makes a mode-0000 directory in dir and returns it with a hook
// that stands for the identity switch of asCaller: inside the function it runs
// the directory can be searched (the caller owns it), outside it cannot (root
// mapped to an unprivileged account by root_squash). The switch itself needs
// root, so it cannot be done here (withFSIdentity is tested with the system
// calls injected, TestWithFSIdentity): what is tested is that the check's file
// system calls run inside the hook and the root variant's do not. calls counts
// the runs.
func closedForRoot(t *testing.T, dir string) (closed string, hook func(func() error) error, calls *int) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root searches a directory without the search permission, so there is no refusal to see")
	}
	closed = filepath.Join(dir, "closed")
	if err := os.Mkdir(closed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	n := 0
	return closed, func(fn func() error) error {
		n++
		if err := os.Chmod(closed, 0o700); err != nil {
			return err
		}
		defer func() { _ = os.Chmod(closed, 0o000) }()
		return fn()
	}, &n
}

// The check of the commands that write as the caller runs as the caller: a
// home others cannot search is no obstacle to it, where the root variant,
// which the commands that write as root keep, is refused.
func TestOutPathAsCallerSearchesAsTheCaller(t *testing.T) {
	inv, sb := outInv(t)
	closed, hook, calls := closedForRoot(t, sb.home)
	inv.hooks.asCallerRun = hook
	path := filepath.Join(closed, "x")

	if _, err := inv.outPath("--out", path); err == nil || !strings.Contains(err.Error(), "cannot be resolved (Permission denied)") {
		t.Errorf("as root: %v, want the refusal", err)
	}
	if *calls != 0 {
		t.Errorf("the root variant ran %d times as the caller", *calls)
	}
	got, err := inv.outPathAsCaller("--out", path)
	if err != nil || got != path {
		t.Errorf("as the caller: %q, %v; want %q", got, err, path)
	}
	if *calls != 1 {
		t.Errorf("the check ran as the caller %d times, want 1", *calls)
	}
	// the other rules are the same: a spelling is refused with the hint,
	// outside the home is refused, whoever asks
	for _, c := range []struct{ p, want string }{{"~/x", "starts with '~'"}, {"/etc/x", "not inside your home"}} {
		if _, err := inv.outPathAsCaller("--out", c.p); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.p, err)
		}
	}
	// a failure of the hook's own (the identity not taken) is a refusal too
	inv.hooks.asCallerRun = func(func() error) error { return os.ErrPermission }
	if _, err := inv.outPathAsCaller("--out", path); err == nil || !strings.Contains(err.Error(), "cannot be resolved (Permission denied)") {
		t.Errorf("a failed switch: %v", err)
	}
}

// The three commands that write as the caller run the check as the caller
// (the hook stands for the identity switch, see closedForRoot): 'plan' gets
// past the check in a directory that root, mapped by root_squash, cannot
// search; 'support-bundle' names a folder of the home, so it is only seen to
// take the hook.
func TestOutPathCommandsThatWriteAsTheCallerCheckAsTheCaller(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	closed, hook, calls := closedForRoot(t, b.sb.homePath("."))
	b.sb.hooks.asCallerRun = hook
	path := filepath.Join(closed, "p.txt")

	b.run("device", "config", "plan", "lab-j", "--out", path)
	if strings.Contains(b.sb.stderr(), "cannot be resolved") || *calls == 0 {
		t.Errorf("plan --out: exit %d, %d runs as the caller: %q", b.sb.code, *calls, b.sb.stderr())
	}
	*calls = 0
	b.run("device", "config", "plan", "lab-j", "--out-dir", filepath.Join(closed, "d"))
	if strings.Contains(b.sb.stderr(), "cannot be resolved") || *calls == 0 {
		t.Errorf("plan --out-dir: exit %d, %d runs as the caller: %q", b.sb.code, *calls, b.sb.stderr())
	}
	*calls = 0
	b.run("device", "support-bundle", "lab-j")
	if strings.Contains(b.sb.stderr(), "cannot be resolved") || *calls == 0 {
		t.Errorf("support-bundle: exit %d, %d runs as the caller: %q", b.sb.code, *calls, b.sb.stderr())
	}
}

// 'device reports export --out' too (a report that does not exist is no
// matter: the check comes first).
func TestOutPathReportsExportChecksAsTheCaller(t *testing.T) {
	b := newReportsBox(t)
	closed, hook, calls := closedForRoot(t, b.sb.homePath("."))
	b.sb.hooks.asCallerRun = hook
	b.as("alice", asSuper, "export", "anything", "--out", filepath.Join(closed, "x.csv"))
	if strings.Contains(b.sb.stderr(), "cannot be resolved") || *calls == 0 {
		t.Errorf("export --out: exit %d, %d runs as the caller: %q", b.sb.code, *calls, b.sb.stderr())
	}
}
