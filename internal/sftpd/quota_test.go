package sftpd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
)

// 4. The quota.

func quotaEnv(t *testing.T, limit int64) *env {
	return newEnv(t, func(c *Config) { c.Quota = limit })
}

func bytesOf(n int) string { return strings.Repeat("q", n) }

// diskUsage is the sum of the sizes of the regular files of the home.
func diskUsage(t *testing.T, e *env) int64 {
	t.Helper()
	var sum int64
	err := filepath.WalkDir(e.home, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			sum += fi.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func wantQuotaRefusal(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s succeeded, want disk quota exceeded", what)
		return
	}
	if !strings.Contains(err.Error(), "disk quota exceeded") {
		t.Errorf("%s: %v, want a status message disk quota exceeded", what, err)
	}
	if code(err) != fxFailure {
		t.Errorf("%s: status %d, want failure (%d)", what, code(err), fxFailure)
	}
}

func TestQuotaExactFitAndOneByteOver(t *testing.T) {
	e := quotaEnv(t, 100)
	e.put("a", bytesOf(100)) // exactly the quota
	if got := diskUsage(t, e); got != 100 {
		t.Fatalf("disk usage %d, want 100", got)
	}
	wantQuotaRefusal(t, "one byte more in a new file", putFile(e.client, "b", "x"))
	if got := diskUsage(t, e); got != 100 {
		t.Errorf("disk usage %d after the refusal, want 100", got)
	}
	// An empty file costs nothing.
	e.put("empty", "")
	// Appending one byte to the full file is over too.
	f, err := e.client.OpenFile("a", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write([]byte("x"))
	wantQuotaRefusal(t, "append of one byte", err)
	_ = f.Close()
	if e.read("a") != bytesOf(100) {
		t.Error("the file changed")
	}
}

func TestQuotaOneByteOverInOnePacketWritesNothing(t *testing.T) {
	e := quotaEnv(t, 100)
	wantQuotaRefusal(t, "101 bytes", putFile(e.client, "a", bytesOf(101)))
	if got := e.read("a"); got != "" {
		t.Errorf("%d bytes were written past the limit, want none", len(got))
	}
	if got := refusals(e.rec.all()); len(got) != 1 || got[0] != "quota" {
		t.Errorf("refusals = %v, want one quota", got)
	}
}

func TestQuotaLargeUploadStopsAtTheLimit(t *testing.T) {
	const limit = 100 << 10
	e := quotaEnv(t, limit)
	err := putFile(e.client, "big", bytesOf(500<<10)) // several packets
	wantQuotaRefusal(t, "500 KiB into 100 KiB", err)
	if got := diskUsage(t, e); got > limit {
		t.Errorf("disk usage %d is over the quota %d", got, limit)
	}
	// One refusal event for the handle, not one per packet.
	n := 0
	for _, r := range refusals(e.rec.all()) {
		if r == "quota" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d quota refusals, want 1 per handle", n)
	}
}

func TestQuotaOverwriteShrinking(t *testing.T) {
	e := quotaEnv(t, 100)
	e.put("a", bytesOf(100))
	e.put("a", bytesOf(10)) // truncated by the open, then 10 bytes
	e.put("b", bytesOf(90))
	wantQuotaRefusal(t, "one byte more", putFile(e.client, "c", "x"))
	// Overwriting a file with a bigger one frees its old size first.
	e.put("b", bytesOf(90))
	e.put("a", bytesOf(10))
	if got := diskUsage(t, e); got != 100 {
		t.Errorf("disk usage %d, want 100", got)
	}
	// Overwriting in place (no growth) is allowed at the limit.
	h, err := e.client.OpenFile("a", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("ZZZ"), 2); err != nil {
		t.Errorf("overwrite inside the file at the limit: %v", err)
	}
	_, err = h.WriteAt([]byte("Z"), 10)
	wantQuotaRefusal(t, "write one byte past the end at the limit", err)
	_ = h.Close()
	if e.read("a") != "qqZZZqqqqq" {
		t.Errorf("a = %q", e.read("a"))
	}
}

func TestQuotaDeleteThenUpload(t *testing.T) {
	e := quotaEnv(t, 100)
	e.put("a", bytesOf(60))
	e.put("b", bytesOf(40))
	wantQuotaRefusal(t, "upload when full", putFile(e.client, "c", "x"))
	if err := e.client.Remove("a"); err != nil {
		t.Fatal(err)
	}
	e.put("c", bytesOf(60))
	wantQuotaRefusal(t, "upload when full again", putFile(e.client, "d", "x"))
	// A directory with files: remove the files, then the directory.
	if err := e.client.Remove("c"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}
	e.put("dir/f", bytesOf(60))
	if err := e.client.Remove("dir/f"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.RemoveDirectory("dir"); err != nil {
		t.Fatal(err)
	}
	e.put("c", bytesOf(60))
}

func TestQuotaRenameThatReplacesFreesRoom(t *testing.T) {
	e := quotaEnv(t, 100)
	e.put("a", bytesOf(60))
	e.put("b", bytesOf(40))
	if err := e.client.PosixRename("b", "a"); err != nil { // a (60) is gone
		t.Fatal(err)
	}
	e.put("c", bytesOf(60))
	wantQuotaRefusal(t, "upload when full", putFile(e.client, "d", "x"))
	// A rename that only moves, and one onto itself, change nothing.
	if err := e.client.Rename("c", "c2"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.PosixRename("c2", "c2"); err != nil {
		t.Fatal(err)
	}
	wantQuotaRefusal(t, "upload when still full", putFile(e.client, "d", "x"))
	// A refused plain rename onto an existing file frees nothing.
	if err := e.client.Rename("c2", "a"); err == nil {
		t.Fatal("rename onto an existing file succeeded")
	}
	wantQuotaRefusal(t, "upload after a refused rename", putFile(e.client, "d", "x"))
}

func TestQuotaDeleteAndDownloadAreNeverLimited(t *testing.T) {
	e := newEnv(t, nil)
	e.write("big", bytesOf(500))
	e.write("sub/f", bytesOf(500))
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	e.start(Config{Home: e.home, Quota: 100, Audit: e.rec.add}) // already over
	wantQuotaRefusal(t, "upload when over", putFile(e.client, "new", "x"))
	if got, err := e.get("big"); err != nil || len(got) != 500 {
		t.Errorf("download when over: %d bytes, %v", len(got), err)
	}
	if err := e.client.Chmod("big", 0o600); err != nil {
		t.Errorf("chmod when over: %v", err)
	}
	if err := e.client.Rename("big", "big2"); err != nil {
		t.Errorf("rename when over: %v", err)
	}
	if err := e.client.Remove("big2"); err != nil {
		t.Errorf("delete when over: %v", err)
	}
	wantQuotaRefusal(t, "upload still over", putFile(e.client, "new", bytesOf(100)))
	if err := e.client.Remove("sub/f"); err != nil {
		t.Errorf("delete when over: %v", err)
	}
	e.put("new", bytesOf(100))
}

func TestQuotaMeasureAtStart(t *testing.T) {
	e := newEnv(t, nil)
	e.write("a", bytesOf(30))
	e.write("d/b", bytesOf(20))
	e.write(".ssh/authorized_keys", bytesOf(10)) // counts
	// A hard link to a file counts once.
	if err := os.Link(filepath.Join(e.home, "a"), filepath.Join(e.home, "a-link")); err != nil {
		t.Fatal(err)
	}
	// A symbolic link to a file counts as nothing, whatever it points at.
	big := filepath.Join(e.root, "big-outside")
	if err := os.WriteFile(big, []byte(bytesOf(1000)), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(big, filepath.Join(e.home, "tobig")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(e.root, filepath.Join(e.home, "toroot")); err != nil {
		t.Fatal(err)
	}
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	h := mustHome(t, e.home)
	if got, ok := measure(h, maxMeasureDepth); got != 60 || !ok {
		t.Errorf("measure = %d, %v, want 60, true (30 + 20 + 10, the hard link once, no link followed)", got, ok)
	}
	// And the same through a session: 60 used of 100 leaves 40.
	e.start(Config{Home: e.home, Quota: 100})
	e.put("n", bytesOf(40))
	wantQuotaRefusal(t, "one byte over what was measured", putFile(e.client, "m", "x"))
}

func TestQuotaRemeasureWhenStale(t *testing.T) {
	clk := newClock()
	e := newEnvSeams(t, func(c *Config) { c.Quota = 100 }, seams{now: clk.now})
	// Another session (or tacctl) fills the home after the start.
	e.write("other", bytesOf(100))
	clk.advance(5 * time.Second) // 5 s is not older than 5 s
	e.put("a", "x")              // the stale measure says the home is empty
	if e.read("a") != "x" {
		t.Fatal("upload within the stale measure failed")
	}
	clk.advance(time.Second) // 6 s: the open for writing measures again
	wantQuotaRefusal(t, "upload after the home was measured again", putFile(e.client, "b", "x"))
	// The measure is now fresh: freeing room is seen at once through the
	// session's own bookkeeping, and an outside change not until it is stale.
	if err := os.Remove(filepath.Join(e.home, "other")); err != nil {
		t.Fatal(err)
	}
	wantQuotaRefusal(t, "upload before the next measure", putFile(e.client, "b", "x"))
	clk.advance(6 * time.Second)
	e.put("b", bytesOf(99))
}

func TestQuotaMeasureIsOnlyAtOpenForWriting(t *testing.T) {
	clk := newClock()
	e := newEnvSeams(t, func(c *Config) { c.Quota = 100 }, seams{now: clk.now})
	h, err := e.client.OpenFile("a", os.O_WRONLY|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	e.write("other", bytesOf(100))
	clk.advance(time.Hour) // no open for writing: no measure
	if _, err := h.WriteAt([]byte("x"), 0); err != nil {
		t.Errorf("write on an open handle after a long time: %v", err)
	}
	_ = h.Close()
	// Reading and listing never measure.
	if _, err := e.get("other"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.ReadDir("/"); err != nil {
		t.Fatal(err)
	}
}

func TestQuotaZeroMeansNoCheckAndNoMeasure(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		h := mustHome(t, t.TempDir())
		s := newServer(h, Config{Quota: limit}, seams{now: time.Now})
		if s.quota != nil {
			t.Errorf("Quota %d: a quota was set up", limit)
		}
	}
	e := newEnv(t, nil)
	e.put("big", bytesOf(300<<10))
	if got := diskUsage(t, e); got != 300<<10 {
		t.Errorf("disk usage %d", got)
	}
}

func TestQuotaSparseWriteIsRefused(t *testing.T) {
	e := quotaEnv(t, 100)
	h, err := e.client.OpenFile("sparse", os.O_WRONLY|os.O_CREATE)
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.WriteAt([]byte("x"), 1<<40)
	wantQuotaRefusal(t, "a write at 1 TiB", err)
	_, err = h.WriteAt([]byte("x"), 1<<62)
	wantQuotaRefusal(t, "a write at 4 EiB", err)
	_, err = h.WriteAt([]byte("x"), 99)
	if err != nil {
		t.Errorf("a write that ends at the limit: %v", err)
	}
	_ = h.Close()
}

func TestQuotaHardLinkedFileIsFreedWithItsLastName(t *testing.T) {
	e := newEnv(t, nil)
	e.write("a", bytesOf(50))
	if err := os.Link(filepath.Join(e.home, "a"), filepath.Join(e.home, "b")); err != nil {
		t.Fatal(err)
	}
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	e.start(Config{Home: e.home, Quota: 100})
	if err := e.client.Remove("b"); err != nil { // a still has the inode
		t.Fatal(err)
	}
	wantQuotaRefusal(t, "51 bytes after removing one name of 50", putFile(e.client, "c", bytesOf(51)))
	if err := e.client.Remove("a"); err != nil { // the last name
		t.Fatal(err)
	}
	e.put("c", bytesOf(100))
}

func TestQuotaConcurrentWritersStayUnderTheLimit(t *testing.T) {
	const limit = 100 << 10
	e := quotaEnv(t, limit)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				_ = putFile(e.client, fmt.Sprintf("w%d-%d", w, i), bytesOf(1<<10))
			}
		}()
	}
	wg.Wait()
	got := diskUsage(t, e)
	if got > limit {
		t.Errorf("disk usage %d is over the quota %d", got, limit)
	}
	if got < limit-(8<<10) {
		t.Errorf("disk usage %d is far under the quota %d: the quota refused what fits", got, limit)
	}
}

func TestStatVFSReportsTheQuota(t *testing.T) {
	e := quotaEnv(t, 10<<20)
	e.put("a", bytesOf(1<<20))
	v, err := e.client.StatVFS("/")
	if err != nil {
		t.Fatal(err)
	}
	if v.TotalSpace() != 10<<20 {
		t.Errorf("total = %d, want %d", v.TotalSpace(), 10<<20)
	}
	if want := uint64(9 << 20); v.FreeSpace() != want {
		t.Errorf("free = %d, want %d", v.FreeSpace(), want)
	}
	if v.Bavail != v.Bfree {
		t.Errorf("available %d differs from free %d", v.Bavail, v.Bfree)
	}
	if _, err := e.client.StatVFS(".ssh"); code(err) != fxPermissionDenied {
		t.Errorf("statvfs of .ssh: %v", err)
	}
	// Over the quota: nothing free, never negative.
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	e.start(Config{Home: e.home, Quota: 1 << 19})
	v, err = e.client.StatVFS("/")
	if err != nil || v.FreeSpace() != 0 || v.TotalSpace() != 1<<19 {
		t.Errorf("over quota: %+v, %v", v, err)
	}
}

func TestStatVFSWithoutQuotaIsTheFileSystem(t *testing.T) {
	e := newEnv(t, nil)
	v, err := e.client.StatVFS("/")
	if err != nil {
		t.Fatal(err)
	}
	if v.Blocks == 0 || v.Frsize == 0 {
		t.Errorf("statvfs = %+v", v)
	}
}

// A walk that could not see the whole home must not make the usage smaller:
// the quota then counts the home as full until a later walk is complete.

// unmeasurable are the ways a directory can hide its content from the walk:
// no read (cannot be listed), no search (the entries cannot be stat'ed), and
// neither.
var unmeasurable = []os.FileMode{0o100, 0o400, 0o000}

func TestQuotaUnmeasurableDirectoryCountsAsFull(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	for _, mode := range unmeasurable {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%04o/nested=%v", mode, nested), func(t *testing.T) {
				clk := newClock()
				e := newEnvSeams(t, func(c *Config) { c.Quota = 100 }, seams{now: clk.now})
				dir, file := "hide", "hide/F"
				if nested {
					dir, file = "top/hide", "top/hide/F"
				}
				e.write(file, bytesOf(100))
				e.write("small", "x")
				if err := os.Chmod(filepath.Join(e.home, dir), mode); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(filepath.Join(e.home, dir), 0o755) })
				clk.advance(6 * time.Second) // the open for writing measures again
				wantQuotaRefusal(t, "growing upload while a directory cannot be measured", putFile(e.client, "g", "x"))
				// What does not make the home bigger keeps working.
				if got, err := e.get("small"); err != nil || got != "x" {
					t.Errorf("download while incomplete: %q, %v", got, err)
				}
				e.put("empty", "")
				// A write in place that stays within the file's size (an upload
				// that truncates first looks like growth, and is refused).
				h, err := e.client.OpenFile("small", os.O_WRONLY)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := h.Write([]byte("y")); err != nil {
					t.Errorf("write in place while incomplete: %v", err)
				}
				_ = h.Close()
				if e.read("small") != "y" {
					t.Error("the write in place did not happen")
				}
				if err := e.client.Remove("empty"); err != nil {
					t.Errorf("delete while incomplete: %v", err)
				}
				wantQuotaRefusal(t, "growing upload after a delete", putFile(e.client, "g", "x"))
				// The directory readable again and a later walk: the real usage
				// (100, the limit) decides, and then the file removed gives room.
				if err := os.Chmod(filepath.Join(e.home, dir), 0o755); err != nil {
					t.Fatal(err)
				}
				clk.advance(6 * time.Second)
				wantQuotaRefusal(t, "upload over the real usage", putFile(e.client, "g", "x"))
				if err := os.Remove(filepath.Join(e.home, file)); err != nil {
					t.Fatal(err)
				}
				clk.advance(6 * time.Second)
				e.put("g", bytesOf(98)) // 98 + the 1 of small
			})
		}
	}
}

func TestQuotaDepthCapCountsAsFull(t *testing.T) {
	clk := newClock()
	e := newEnvSeams(t, func(c *Config) { c.Quota = 100 }, seams{now: clk.now, measureDepth: 3})
	e.write("a/b/c/d/F", bytesOf(10)) // four levels below the home
	clk.advance(6 * time.Second)
	// The 10 bytes are far from the 100 of the quota, but the walk did not
	// see them: the home counts as full.
	wantQuotaRefusal(t, "upload with files below the walk's depth", putFile(e.client, "g", "x"))
	// Within the depth the walk is complete and counts what is there.
	e2 := newEnvSeams(t, func(c *Config) { c.Quota = 100 }, seams{now: clk.now, measureDepth: 3})
	e2.write("a/b/F", bytesOf(60))
	clk.advance(6 * time.Second)
	e2.put("g", bytesOf(40))
	wantQuotaRefusal(t, "one byte over", putFile(e2.client, "h", "x"))
}

func TestMeasureReportsWhetherItWasComplete(t *testing.T) {
	e := newEnv(t, nil)
	e.write("a/b/F", bytesOf(7))
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	h := mustHome(t, e.home)
	if n, ok := measure(h, 8); n != 7 || !ok {
		t.Errorf("measure = %d, %v, want 7, true", n, ok)
	}
	if _, ok := measure(h, 1); ok {
		t.Error("a walk cut at depth 1 says it was complete")
	}
}

func TestQuotaStatVFSOfAnIncompleteMeasureIsFull(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	e := quotaEnv(t, 8192)
	e.write("hide/F", "x")
	if err := os.Chmod(filepath.Join(e.home, "hide"), 0o100); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(e.home, "hide"), 0o755) })
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	e.start(Config{Home: e.home, Quota: 8192})
	sv, err := e.client.StatVFS("/")
	if err != nil {
		t.Fatal(err)
	}
	if sv.Bfree != 0 {
		t.Errorf("free blocks = %d, want 0 while the home cannot be measured", sv.Bfree)
	}
}

// A client may not make its own tree unmeasurable and unlistable.
func TestSetstatRefusesClearingTheOwnersReadOrSearchOfADirectory(t *testing.T) {
	e := quotaEnv(t, 100)
	if err := e.client.Mkdir("d"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o100, 0o400, 0o000, 0o277, 0o077} {
		err := e.client.Chmod("d", mode)
		if code(err) != fxOpUnsupported {
			t.Errorf("chmod %04o of a directory: %v, want unsupported", mode, err)
		}
		if fi, _ := os.Stat(filepath.Join(e.home, "d")); fi.Mode().Perm() != 0o755 {
			t.Errorf("mode after the refused chmod %04o = %v", mode, fi.Mode())
		}
	}
	if got := refusals(e.rec.all()); len(got) != 5 || got[0] != "unsupported" {
		t.Errorf("refusals = %v, want 5 unsupported", got)
	}
	// What keeps the owner's r and x is fine, and so is any mode of a file.
	if err := e.client.Chmod("d", 0o500); err != nil {
		t.Errorf("chmod 0500 of a directory: %v", err)
	}
	if err := e.client.Chmod("d", 0o700); err != nil {
		t.Errorf("chmod 0700 of a directory: %v", err)
	}
	e.write("f", "x")
	if err := e.client.Chmod("f", 0o000); err != nil {
		t.Errorf("chmod 0000 of a file: %v", err)
	}
	// Times only, on a directory.
	if err := e.client.Chtimes("d", time.Unix(1e9, 0), time.Unix(1e9, 0)); err != nil {
		t.Errorf("chtimes of a directory: %v", err)
	}
}

// A file that was removed (or replaced) while a handle on it is open keeps
// its data, so it keeps its room until the last handle on it closes.

func TestQuotaRemovedFileWithAnOpenHandleKeepsItsRoom(t *testing.T) {
	clk := newClock()
	e := newEnvSeams(t, func(c *Config) { c.Quota = 100 }, seams{now: clk.now})
	var held []interface{ Close() error }
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("f%d", i)
		h, err := e.client.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, h)
		if _, err := h.Write([]byte(bytesOf(100))); err != nil {
			if i == 0 {
				t.Fatalf("the first write: %v", err)
			}
			wantQuotaRefusal(t, fmt.Sprintf("write %d while the removed files are held", i), err)
			break
		}
		if i > 0 {
			t.Errorf("write %d of 100 bytes succeeded under a quota of 100 with %d removed files held", i, i)
		}
		if err := e.client.Remove(name); err != nil {
			t.Fatal(err)
		}
		clk.advance(6 * time.Second) // and the next open for writing measures the home again
	}
	// The data the handles hold is on the disk, outside the home's names.
	for _, h := range held {
		_ = h.Close()
	}
	// The last close gives the room back.
	e.put("fresh", bytesOf(100))
}

func TestQuotaRoomIsGivenBackWithTheLastHandle(t *testing.T) {
	e := quotaEnv(t, 100)
	h1, err := e.client.OpenFile("a", os.O_RDWR|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h1.Write([]byte(bytesOf(100))); err != nil {
		t.Fatal(err)
	}
	h2, err := e.client.OpenFile("a", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.client.Remove("a"); err != nil {
		t.Fatal(err)
	}
	wantQuotaRefusal(t, "upload with two handles on a removed file", putFile(e.client, "b", "x"))
	_ = h1.Close()
	wantQuotaRefusal(t, "upload with one handle left", putFile(e.client, "b", "x"))
	_ = h2.Close()
	e.put("b", bytesOf(100))
}

func TestQuotaFileReplacedByRenameWhileOpenKeepsItsRoom(t *testing.T) {
	e := quotaEnv(t, 150)
	h, err := e.client.OpenFile("a", os.O_RDWR|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write([]byte(bytesOf(100))); err != nil {
		t.Fatal(err)
	}
	e.put("b", bytesOf(10))
	if err := e.client.PosixRename("b", "a"); err != nil {
		t.Fatal(err)
	}
	// 10 bytes under the name a, and the 100 the handle holds.
	wantQuotaRefusal(t, "41 bytes with 110 in use", putFile(e.client, "c", bytesOf(41)))
	e.put("c", bytesOf(40))
	_ = h.Close()
	if err := e.client.Remove("c"); err != nil {
		t.Fatal(err)
	}
	e.put("d", bytesOf(140))
}

// A held file that is written after its name is gone is counted as it grows.
func TestQuotaHeldRemovedFileStillGrowsTheUsage(t *testing.T) {
	e := quotaEnv(t, 100)
	h, err := e.client.OpenFile("a", os.O_RDWR|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.client.Remove("a"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Write([]byte(bytesOf(60))); err != nil {
		t.Fatal(err)
	}
	wantQuotaRefusal(t, "41 bytes beside 60 held", putFile(e.client, "b", bytesOf(41)))
	_, err = h.Write([]byte(bytesOf(41)))
	wantQuotaRefusal(t, "growing the removed file past the quota", err)
	_ = h.Close()
}

// A truncating open reads the size, cuts the file and lowers the usage as one
// step under the quota's lock. A write on another handle of the same file
// that is running when the cut happens must not leave the usage below the
// disk: the open is held before its cut, a write is started and is in its
// write when the cut is let go.
//
// The write waits for the file to be cut, up to a deadline on a real timer: with
// the lock held by the write the cut cannot happen until the write is over, so
// the wait ends by the deadline; without the lock the cut comes at once.
func TestQuotaTruncatingOpenDoesNotLoseAConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte(bytesOf(100)), 0o644); err != nil {
		t.Fatal(err)
	}
	atCut, letCut, inWrite := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s := newServer(mustHome(t, dir), Config{Quota: 1000}, seams{now: time.Now, beforeTruncate: func() {
		close(atCut)
		<-letCut
	}})
	// The writer's handle: no truncation, so no hook.
	b, err := s.openFile(&sftp.Request{Method: "Put", Filepath: "/f", Flags: 0x2}, true) // SSH_FXF_WRITE
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	opened := make(chan error, 1)
	go func() {
		a, err := s.openFile(&sftp.Request{Method: "Put", Filepath: "/f", Flags: 0x2 | 0x10}, true) // WRITE | TRUNC
		if err == nil {
			_ = a.Close()
		}
		opened <- err
	}()
	<-atCut
	wrote := make(chan error, 1)
	go func() {
		w := func() (int, error) {
			close(inWrite)
			for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				if fi, err := b.f.Stat(); err == nil && fi.Size() == 0 {
					break
				}
			}
			return b.f.WriteAt([]byte(bytesOf(100)), 0)
		}
		_, err := s.quota.write(b.f, 100, 0, false, w)
		wrote <- err
	}()
	<-inWrite
	close(letCut)
	if err := <-wrote; err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-opened; err != nil {
		t.Fatalf("truncating open: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.quota.usage(); got != fi.Size() {
		t.Errorf("usage %d, the file on the disk has %d", got, fi.Size())
	}
}
