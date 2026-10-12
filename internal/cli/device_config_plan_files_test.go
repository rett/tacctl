package cli

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
)

// fakeThread is a thread's identity as the system calls see it: the groups,
// the file-system user and group. ignoreUID and ignoreGID make the setter
// do nothing (the way setfsuid(2) fails: silently, returning the previous
// value).
type fakeThread struct {
	uid, gid      int
	groups        []int
	ignoreUID     bool
	ignoreGID     bool
	failGetgroups bool
	failSetgroups bool
}

func (f *fakeThread) sys() fsIdentity {
	return fsIdentity{
		getgroups: func() ([]int, error) {
			if f.failGetgroups {
				return nil, errors.New("getgroups failed")
			}
			return slices.Clone(f.groups), nil
		},
		setgroups: func(g []int) error {
			if f.failSetgroups {
				return errors.New("setgroups: operation not permitted")
			}
			f.groups = slices.Clone(g)
			return nil
		},
		setfsuid: func(id int) (int, error) {
			prev := f.uid
			if !f.ignoreUID {
				f.uid = id
			}
			return prev, nil
		},
		setfsgid: func(id int) (int, error) {
			prev := f.gid
			if !f.ignoreGID {
				f.gid = id
			}
			return prev, nil
		},
	}
}

// asCaller's identity logic, with the system calls injected: the caller's
// ids and no supplementary group inside, the thread's own identity back
// after (and proved), a change that did not take is an error, and a thread
// that could not be restored is reported so that it is not reused.
func TestWithFSIdentity(t *testing.T) {
	root := func() *fakeThread { return &fakeThread{groups: []int{0, 4, 27}} }

	// the normal run
	th := root()
	var seen fakeThread
	err, restored := withFSIdentity(th.sys(), 1000, 100, func() error {
		seen = fakeThread{uid: th.uid, gid: th.gid, groups: slices.Clone(th.groups)}
		return nil
	})
	if err != nil || !restored {
		t.Fatalf("run: %v restored=%v", err, restored)
	}
	if seen.uid != 1000 || seen.gid != 100 || !slices.Equal(seen.groups, []int{100}) {
		t.Errorf("inside: uid %d gid %d groups %v (want 1000 100 [100]: no supplementary group)", seen.uid, seen.gid, seen.groups)
	}
	if th.uid != 0 || th.gid != 0 || !slices.Equal(th.groups, []int{0, 4, 27}) {
		t.Errorf("after: uid %d gid %d groups %v: the thread's identity is not back", th.uid, th.gid, th.groups)
	}

	// fn's error comes back, the identity too
	th = root()
	want := errors.New("disk full")
	if err, restored := withFSIdentity(th.sys(), 1000, 100, func() error { return want }); !errors.Is(err, want) || !restored {
		t.Errorf("fn error: %v restored=%v", err, restored)
	}
	if th.uid != 0 || th.gid != 0 || !slices.Equal(th.groups, []int{0, 4, 27}) {
		t.Errorf("after an error: %+v", th)
	}

	// a setfsuid that does not take is an error, never a silent root; the
	// group already changed is put back
	th = root()
	th.ignoreUID = true
	called := false
	err, restored = withFSIdentity(th.sys(), 1000, 100, func() error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "file-system user was not changed") || called || !restored {
		t.Errorf("silent setfsuid: %v called=%v restored=%v", err, called, restored)
	}
	if th.gid != 0 || !slices.Equal(th.groups, []int{0, 4, 27}) {
		t.Errorf("after a refused change: %+v", th)
	}
	// likewise the group
	th = root()
	th.ignoreGID = true
	err, restored = withFSIdentity(th.sys(), 1000, 100, func() error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "file-system group was not changed") || !restored || !slices.Equal(th.groups, []int{0, 4, 27}) {
		t.Errorf("silent setfsgid: %v restored=%v %+v", err, restored, th)
	}

	// the identity cannot be put back: said, so that the thread is not reused
	th = root()
	err, restored = withFSIdentity(th.sys(), 1000, 100, func() error {
		th.ignoreUID = true // from here the thread keeps what it has
		return nil
	})
	if err != nil || restored {
		t.Errorf("unrestorable: %v restored=%v", err, restored)
	}

	// the groups of the process cannot be read or written: nothing changed
	th = root()
	th.failGetgroups = true
	if err, restored := withFSIdentity(th.sys(), 1000, 100, func() error { called = true; return nil }); err == nil || !restored || th.uid != 0 {
		t.Errorf("getgroups: %v restored=%v %+v", err, restored, th)
	}
	th = root()
	th.failSetgroups = true
	if err, restored := withFSIdentity(th.sys(), 1000, 100, func() error { called = true; return nil }); err == nil || !restored || th.uid != 0 || th.gid != 0 {
		t.Errorf("setgroups: %v restored=%v %+v", err, restored, th)
	}
}

// A device that cannot be planned has no plain file: --out writes nothing
// (and says so), as --out-dir already did.
func TestPlanPlainOutWritesNothingForADeviceThatCannotBePlanned(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"new-j", "192.168.1.21", "juniper"})
	dir := t.TempDir()
	f := filepath.Join(dir, "new-j.set")
	b.run("device", "config", "plan", "new-j", "--plain", "--out", f)
	if b.sb.code != 1 {
		t.Errorf("exit %d", b.sb.code)
	}
	if _, err := os.Stat(f); err == nil {
		t.Error("an empty plain file for a device that could not be planned")
	}
	if !strings.Contains(b.sb.stderr(), "new-j: no file written") || !strings.Contains(b.sb.stderr(), "new-j cannot be planned: not pulled") {
		t.Errorf("stderr %q", b.sb.stderr())
	}
	// --out-dir: the same, one line
	b.run("device", "config", "plan", "new-j", "--plain", "--out-dir", filepath.Join(dir, "d"))
	if _, err := os.Stat(filepath.Join(dir, "d", "new-j.set")); err == nil || !strings.Contains(b.sb.stderr(), "new-j: no file written") {
		t.Errorf("out-dir: %v %q", err, b.sb.stderr())
	}
}

// The name of the cleanup's file is a file of the run: the plain file of a
// device called x.cleanup is the same file, and --force must not let one
// replace the other.
func TestPlanCleanupFileNameIsReserved(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-j.cleanup", "192.168.1.27", "juniper"})
	text := b.expected("lab-j") + "\n" + `set system tacplus-server 192.0.2.99 secret "` + strayKey + `"` + "\n"
	b.serve("juniper", text)
	b.servePlain(text)
	b.run("device", "config", "pull", "--all")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	dir := filepath.Join(t.TempDir(), "sets")
	for _, force := range []bool{false, true} {
		args := []string{"device", "config", "plan", "--all", "--plain", "--converge", "--out-dir", dir}
		if force {
			args = append(args, "--force")
		}
		b.run(args...)
		if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "lab-j.cleanup.set") || !strings.Contains(b.sb.stderr(), "is taken") {
			t.Errorf("force=%v: exit %d %q", force, b.sb.code, b.sb.stderr())
		}
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 0 {
		t.Errorf("files written for a run that was refused: %v", ents)
	}
}

// COVER.txt is reserved only when a cover is written: a device of that name
// is fine alone.
func TestPlanCoverNameIsReservedOnlyForACover(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"COVER", "192.168.1.20", "juniper"}, [3]string{"other", "192.168.1.28", "juniper"})
	b.serve("juniper", b.expected("COVER"))
	b.run("device", "config", "pull", "--all")
	dir := filepath.Join(t.TempDir(), "out")
	b.run("device", "config", "plan", "COVER", "--out-dir", dir)
	if b.sb.code != 0 {
		t.Fatalf("one device named COVER: %d %q", b.sb.code, b.sb.stderr())
	}
	if _, err := os.Stat(filepath.Join(dir, "COVER.txt")); err != nil {
		t.Errorf("its file: %v", err)
	}
	// with two devices the cover takes the name
	b.run("device", "config", "plan", "--all", "--out-dir", filepath.Join(t.TempDir(), "two"))
	if b.sb.code != 2 || !strings.Contains(b.sb.stderr(), "COVER.txt") {
		t.Errorf("two devices: %d %q", b.sb.code, b.sb.stderr())
	}
}

// The audit line quotes a path that holds a space, so its fields keep their
// boundaries; a plain path is as it was.
func TestPlanAuditQuotesAPathWithSpaces(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	dir := filepath.Join(t.TempDir(), "with space")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "lab j.txt")
	b.run("device", "config", "plan", "lab-j", "--out", f)
	if b.sb.code != 0 {
		t.Fatalf("exit %d %s", b.sb.code, b.sb.stderr())
	}
	al := b.auditLines("device config plan")
	if len(al) != 1 || !strings.HasSuffix(al[0], ` out="`+f+`"`) {
		t.Errorf("audit %q", al)
	}
	if auditValue("/tmp/plain.txt") != "/tmp/plain.txt" || auditValue("-") != "-" || auditValue("a=b") != `"a=b"` || auditValue("a\"b") != `"a\"b"` {
		t.Error("auditValue")
	}
}

// The plain view is read for the pull it was taken with: after another pull
// stamped the record, an old view is not compared with the new sections (and
// the report says there is none).
func TestPlanIgnoresAPlainViewOfAnotherPull(t *testing.T) {
	b := planBoxJunos(t)
	b.run("device", "config", "pull", "lab-j")
	out := b.run("device", "config", "plan", "lab-j")
	if strings.Contains(unwrapPlan(out), "The pull has no plain view") {
		t.Fatalf("the plain view of this pull was not read:\n%s", out)
	}
	b.editRecord("lab-j", func(r *devconf.Record) { r.Pulled = r.Pulled.Add(time.Second) })
	out = b.run("device", "config", "plan", "lab-j")
	if !strings.Contains(unwrapPlan(out), "The pull has no plain view") {
		t.Errorf("a plain view of another pull was used:\n%s", out)
	}
}
