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
	if got := measure(h); got != 60 {
		t.Errorf("measure = %d, want 60 (30 + 20 + 10, the hard link once, no link followed)", got)
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
