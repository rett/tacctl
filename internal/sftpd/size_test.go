package sftpd

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/sys/unix"
)

// 5. The size by setstat and fsetstat. The client of OpenSSH (scp) sets the
// final size of an uploaded file with an fsetstat of the size alone.

// The attribute flags of a request, as the protocol has them.
const (
	attrSize  = 0x1
	attrUID   = 0x2
	attrPerms = 0x4
)

// attrReq is a Setstat request with the size and, when the flags say so,
// the owner (uid, gid) and the mode, in the order of the protocol.
func attrReq(path string, flags uint32, size uint64, rest ...uint32) *sftp.Request {
	b := binary.BigEndian.AppendUint64(nil, size)
	for _, v := range rest {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return &sftp.Request{Method: "Setstat", Filepath: path, Flags: flags, Attrs: b}
}

func fileSize(t *testing.T, dir, rel string) int64 {
	t.Helper()
	fi, err := os.Stat(filepath.Join(dir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}

// What scp does: upload, then an fsetstat of the final size on the open handle.
func TestFsetstatSizeAfterUpload(t *testing.T) {
	for _, quota := range []int64{0, 100} {
		e := newEnv(t, func(c *Config) { c.Quota = quota })
		f, err := e.client.OpenFile("up", os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte("123456789")); err != nil {
			t.Fatal(err)
		}
		if err := f.Truncate(9); err != nil {
			t.Fatalf("quota %d: fsetstat of the size alone: %v", quota, err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		if got := e.read("up"); got != "123456789" {
			t.Errorf("quota %d: content %q", quota, got)
		}
		if got := strings.Join(describe(e.rec.all()), "|"); got != "setstat /up|upload /up 9" {
			t.Errorf("quota %d: events %q", quota, got)
		}
	}
}

func TestSetstatSizeCutsAndExtends(t *testing.T) {
	e := newEnv(t, nil)
	e.write("f", "abcdef")
	if err := e.client.Truncate("f", 3); err != nil {
		t.Fatalf("shrink by setstat: %v", err)
	}
	if got := e.read("f"); got != "abc" {
		t.Errorf("after shrinking: %q", got)
	}
	if err := e.client.Truncate("f", 5); err != nil {
		t.Fatalf("extend by setstat: %v", err)
	}
	if got := e.read("f"); got != "abc\x00\x00" {
		t.Errorf("after extending: %q", got)
	}
	h, err := e.client.OpenFile("f", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	if err := h.Truncate(0); err != nil {
		t.Fatalf("empty by fsetstat: %v", err)
	}
	if fileSize(t, e.home, "f") != 0 {
		t.Error("the file is not empty")
	}
}

func TestSetstatSizeWithinAndBeyondTheQuota(t *testing.T) {
	e := quotaEnv(t, 100)
	e.put("a", bytesOf(40))
	if err := e.client.Truncate("a", 100); err != nil {
		t.Fatalf("growing to the limit: %v", err)
	}
	if got := diskUsage(t, e); got != 100 {
		t.Errorf("disk %d, want 100", got)
	}
	// Same size at the limit: nothing grows, so it is allowed (scp does this).
	if err := e.client.Truncate("a", 100); err != nil {
		t.Errorf("the size it has, at the limit: %v", err)
	}
	wantQuotaRefusal(t, "one byte more", e.client.Truncate("a", 101))
	wantQuotaRefusal(t, "upload with the home full", putFile(e.client, "b", "x"))
	if got := fileSize(t, e.home, "a"); got != 100 {
		t.Errorf("a refused extension changed the size to %d", got)
	}
	e.rec.reset()
	wantQuotaRefusal(t, "a size far beyond", e.client.Truncate("a", 1<<40))
	if got := strings.Join(refusals(e.rec.all()), ","); got != "quota" {
		t.Errorf("refusals %q, want quota", got)
	}
	// Through a handle, the same.
	h, err := e.client.OpenFile("a", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	wantQuotaRefusal(t, "fsetstat beyond", h.Truncate(150))
}

func TestSetstatSizeShrinkingReleasesTheQuota(t *testing.T) {
	e := quotaEnv(t, 100)
	e.put("a", bytesOf(100))
	wantQuotaRefusal(t, "upload into a full home", putFile(e.client, "b", "x"))
	if err := e.client.Truncate("a", 30); err != nil {
		t.Fatal(err)
	}
	e.put("b", bytesOf(70))
	wantQuotaRefusal(t, "upload over the room that was freed", putFile(e.client, "c", "x"))
	// By a handle.
	h, err := e.client.OpenFile("b", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Truncate(0); err != nil {
		t.Fatal(err)
	}
	_ = h.Close()
	e.put("c", bytesOf(70))
	if got := diskUsage(t, e); got != 100 {
		t.Errorf("disk %d, want 100", got)
	}
}

func TestSetstatSizeRefusedWhereTheRulesRefuse(t *testing.T) {
	e := sshEnv(t)
	e.write("hl", "data")
	if err := os.Link(filepath.Join(e.home, "hl"), filepath.Join(e.home, "hl2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("plain", filepath.Join(e.home, "sl")); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ path, reason string }{
		{"hl", "link"},
		{"hl2", "link"},
		{"sl", "symlink"},
		{".ssh/authorized_keys", ".ssh"},
		{".ssh", ".ssh"},
		{"a/../.ssh/authorized_keys", ".ssh"},
		{"/", "outside the home"},
	} {
		e.rec.reset()
		err := e.client.Truncate(c.path, 0)
		if code(err) != fxPermissionDenied {
			t.Errorf("truncate %q: %v, want permission denied", c.path, err)
		}
		if got := strings.Join(refusals(e.rec.all()), ","); got != c.reason {
			t.Errorf("truncate %q: refusals %q, want %q", c.path, got, c.reason)
		}
	}
	// A directory: no rule of ours, the kernel's answer.
	if err := e.client.Truncate("dir", 0); err == nil {
		t.Error("truncate of a directory succeeded")
	}
	// A fifo is not a regular file.
	if err := unix.Mkfifo(filepath.Join(e.home, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Truncate("fifo", 0); code(err) != fxOpUnsupported {
		t.Errorf("truncate of a fifo: %v", err)
	}
	if e.read("hl") != "data" || e.read("hl2") != "data" || e.read("plain") != "x" ||
		e.read(".ssh/authorized_keys") != "ssh-ed25519 AAAA example-key alice@example.net\n" {
		t.Error("a refused request changed a file")
	}
}

func TestSetstatSizeNegativeOrAbsurdIsRefused(t *testing.T) {
	for _, quota := range []int64{0, 1000} {
		e := newEnv(t, func(c *Config) { c.Quota = quota })
		e.write("f", "content")
		for _, n := range []int64{-1, -1 << 62, 1<<62 + 1, 1<<63 - 1} {
			if err := e.client.Truncate("f", n); code(err) != fxOpUnsupported {
				t.Errorf("quota %d: truncate to %d: %v, want unsupported", quota, n, err)
			}
		}
		if e.read("f") != "content" {
			t.Errorf("quota %d: a refused size changed the file", quota)
		}
	}
}

// A request that asks for a size and a new owner is refused whole.
func TestSetstatSizeWithOwnerIsRefusedWhole(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newServer(mustHome(t, dir), Config{Quota: 1000}, seams{now: time.Now})
	r := attrReq("/f", attrSize|attrUID|attrPerms, 0, 0, 0, 0o600)
	if err := s.Filecmd(r); reasonOf(err) != reasonUnsupported {
		t.Errorf("size with owner: %v, want unsupported", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "f"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 7 || fi.Mode().Perm() != 0o644 {
		t.Errorf("a refused request changed the file: size %d, mode %v", fi.Size(), fi.Mode())
	}
	if got := s.quota.usage(); got != 7 {
		t.Errorf("usage %d, want 7", got)
	}
}

// Size and mode in one request: the size first, then the mode; a size that is
// refused leaves the mode as it was.
func TestSetstatSizeAndModeTogether(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(bytesOf(60)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The walk of the start counts 120 of the 150.
	s := newServer(mustHome(t, dir), Config{Quota: 150}, seams{now: time.Now})
	if err := s.Filecmd(attrReq("/a", attrSize|attrPerms, 30, 0o600)); err != nil {
		t.Fatalf("size and mode: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "a")); fi.Size() != 30 || fi.Mode().Perm() != 0o600 {
		t.Errorf("size %d mode %v, want 30 and 0600", fi.Size(), fi.Mode().Perm())
	}
	// Usage is 90 now; b may grow by 60 at most.
	if err := s.Filecmd(attrReq("/b", attrSize|attrPerms, 130, 0o600)); reasonOf(err) != reasonQuota {
		t.Errorf("size and mode over the quota: %v, want the quota's refusal", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "b")); fi.Size() != 60 || fi.Mode().Perm() != 0o644 {
		t.Errorf("refused request: size %d mode %v, want 60 and 0644", fi.Size(), fi.Mode().Perm())
	}
	// A directory: the size is refused and the mode is not applied.
	if err := s.Filecmd(attrReq("/d", attrSize|attrPerms, 0, 0o700)); err == nil {
		t.Error("size on a directory succeeded")
	}
	if fi, _ := os.Stat(filepath.Join(dir, "d")); fi.Mode().Perm() != 0o755 {
		t.Errorf("a directory's mode changed to %v by a refused request", fi.Mode().Perm())
	}
	if got := s.quota.usage(); got != 90 {
		t.Errorf("usage %d, want 90", got)
	}
}

// A file whose name is gone between the pin and the size: counted while a
// handle of the session holds it, and not once nothing does.
func TestSetstatSizeOfAnUnlinkedFile(t *testing.T) {
	setup := func(t *testing.T) (*server, string) {
		dir := t.TempDir()
		var s *server
		s = newServer(mustHome(t, dir), Config{Quota: 100}, seams{now: time.Now, afterPin: func() {
			if err := s.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/a"}); err != nil {
				panic(err)
			}
		}})
		return s, dir
	}
	t.Run("held", func(t *testing.T) {
		s, dir := setup(t)
		h, err := s.openFile(&sftp.Request{Method: "Put", Filepath: "/a", Flags: 0x2 | 0x8}, true) // WRITE | CREAT
		if err != nil {
			t.Fatal(err)
		}
		if _, err := h.WriteAt([]byte(bytesOf(60)), 0); err != nil {
			t.Fatal(err)
		}
		if err := s.Filecmd(attrReq("/a", attrSize, 80)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, "a")); err == nil {
			t.Fatal("the name is still there")
		}
		if fi, _ := h.f.Stat(); fi.Size() != 80 {
			t.Errorf("size %d, want 80", fi.Size())
		}
		if got := s.quota.usage(); got != 80 {
			t.Errorf("usage with the handle open %d, want 80", got)
		}
		_ = h.Close()
		if got := s.quota.usage(); got != 0 {
			t.Errorf("usage after the last handle closed %d, want 0", got)
		}
	})
	t.Run("not held", func(t *testing.T) {
		s, dir := setup(t)
		if err := os.WriteFile(filepath.Join(dir, "a"), []byte(bytesOf(60)), 0o644); err != nil {
			t.Fatal(err)
		}
		s.quota.mu.Lock()
		s.quota.remeasure()
		s.quota.mu.Unlock()
		if err := s.Filecmd(attrReq("/a", attrSize, 80)); err != nil {
			t.Fatal(err)
		}
		if got := s.quota.usage(); got != 0 {
			t.Errorf("usage %d, want 0: the file has no name and no handle", got)
		}
	})
}

// A size set while a write of the session is under way is counted once: the
// size is read and the file cut under the lock a write holds.
//
// The write waits for the file to be cut, up to a deadline on a real timer:
// with the lock held by the write the cut cannot happen until the write is
// over, so the wait ends by the deadline; without the lock the cut comes at
// once.
func TestSetstatSizeDoesNotLoseAConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "f"), []byte(bytesOf(100)), 0o644); err != nil {
		t.Fatal(err)
	}
	atPin, letGo, inWrite := make(chan struct{}), make(chan struct{}), make(chan struct{})
	s := newServer(mustHome(t, dir), Config{Quota: 1000}, seams{now: time.Now, afterPin: func() {
		close(atPin)
		<-letGo
	}})
	b, err := s.openFile(&sftp.Request{Method: "Put", Filepath: "/f", Flags: 0x2}, true) // WRITE
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	done := make(chan error, 1)
	go func() { done <- s.Filecmd(attrReq("/f", attrSize, 0)) }()
	select {
	case <-atPin:
	case err := <-done:
		t.Fatalf("setstat ended before it was changing the file: %v", err)
	}
	wrote := make(chan error, 1)
	go func() {
		w := func() (int, error) {
			close(inWrite)
			for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
				if fi, err := b.f.Stat(); err == nil && fi.Size() == 0 {
					break
				}
			}
			return b.f.WriteAt([]byte(bytesOf(100)), 100)
		}
		_, err := s.quota.write(b.f, 100, 100, false, w)
		wrote <- err
	}()
	<-inWrite
	close(letGo)
	if err := <-wrote; err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("setstat: %v", err)
	}
	if got, disk := s.quota.usage(), fileSize(t, dir, "f"); got != disk {
		t.Errorf("usage %d, the file on the disk has %d", got, disk)
	}
}
