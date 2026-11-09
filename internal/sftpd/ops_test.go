package sftpd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 1. The home is "/".

func TestRealPathIsRoot(t *testing.T) {
	e := newEnv(t, nil)
	for _, in := range []string{".", "", "/", "..", "../..", "/..", "a/..", "./"} {
		got, err := e.client.RealPath(in)
		if err != nil || got != "/" {
			t.Errorf("RealPath(%q) = %q, %v; want /", in, got, err)
		}
	}
	if got, err := e.client.Getwd(); err != nil || got != "/" {
		t.Errorf("Getwd = %q, %v; want /", got, err)
	}
	if got, _ := e.client.RealPath("a/./b/../c"); got != "/a/c" {
		t.Errorf("RealPath(a/./b/../c) = %q, want /a/c", got)
	}
}

func TestPathsStayInsideHome(t *testing.T) {
	e := newEnv(t, nil)
	// A secret next to the home, where "../" would lead.
	if err := os.WriteFile(filepath.Join(e.root, "secret"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.client.MkdirAll("/etc"); err != nil {
		t.Fatal(err)
	}
	e.put("/etc/passwd", "inside")
	if got := e.read("etc/passwd"); got != "inside" {
		t.Errorf("home/etc/passwd = %q", got)
	}
	// Relative and absolute spellings reach the same file.
	for _, p := range []string{"etc/passwd", "/etc/passwd", "./etc/passwd", "/../etc/passwd", "../../etc/passwd", "/etc/../etc/passwd", "//etc//passwd"} {
		got, err := e.get(p)
		if err != nil || got != "inside" {
			t.Errorf("get %q = %q, %v", p, got, err)
		}
	}
	// ".." cannot leave: the secret one level up is not there.
	for _, p := range []string{"../secret", "/../secret", "../../../secret", "etc/../../secret"} {
		if _, err := e.get(p); code(err) != fxNoSuchFile {
			t.Errorf("get %q: err = %v, want no such file", p, err)
		}
	}
	// Writing "outside" lands inside.
	e.put("../planted", "x")
	if !e.exists("planted") {
		t.Error("../planted was not written in the home")
	}
	if _, err := os.Lstat(filepath.Join(e.root, "planted")); err == nil {
		t.Error("../planted left the home")
	}
	// A stat of the root is the home.
	fi, err := e.client.Stat("/../..")
	if err != nil || !fi.IsDir() {
		t.Errorf("Stat(/../..) = %v, %v", fi, err)
	}
}

func TestHomeReachedThroughALink(t *testing.T) {
	e := newEnv(t, nil)
	// Home may itself be a link (the caller's configuration).
	link := filepath.Join(e.root, "homelink")
	if err := os.Symlink(e.home, link); err != nil {
		t.Fatal(err)
	}
	e.write("f", "hello")
	if err := e.stop(); err != nil {
		t.Fatal(err)
	}
	e.start(Config{Home: link})
	if got, err := e.get("f"); err != nil || got != "hello" {
		t.Errorf("get f = %q, %v", got, err)
	}
}

func TestServeNeedsAHome(t *testing.T) {
	for _, home := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		a, b := pipePair()
		err := Serve(a, Config{Home: home})
		if err == nil {
			t.Errorf("Serve(Home=%q) = nil, want an error", home)
		}
		_ = b.Close()
	}
}

// 3. The operations.

func TestStatLstatFstat(t *testing.T) {
	e := newEnv(t, nil)
	e.write("d/f", "12345")
	fi, err := e.client.Stat("d/f")
	if err != nil || fi.Size() != 5 || fi.Name() != "f" || fi.IsDir() {
		t.Errorf("Stat d/f = %v, %v", fi, err)
	}
	fi, err = e.client.Lstat("d")
	if err != nil || !fi.IsDir() {
		t.Errorf("Lstat d = %v, %v", fi, err)
	}
	f, err := e.client.Open("d/f")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || fi.Size() != 5 {
		t.Errorf("Fstat = %v, %v", fi, err)
	}
	if _, err := e.client.Stat("nope"); code(err) != fxNoSuchFile {
		t.Errorf("Stat nope: %v", err)
	}
	if _, err := e.client.Stat("d/f/x"); err == nil {
		t.Error("Stat through a file succeeded")
	}
	// The mode and the time come from the file.
	when := time.Date(2026, 10, 12, 13, 11, 0, 0, time.UTC)
	if err := os.Chtimes(filepath.Join(e.home, "d/f"), when, when); err != nil {
		t.Fatal(err)
	}
	fi, _ = e.client.Stat("d/f")
	if !fi.ModTime().Equal(when) {
		t.Errorf("ModTime = %v, want %v", fi.ModTime(), when)
	}
}

func TestListDirectory(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 250; i++ { // more than one batch of the library
		e.write(fmt.Sprintf("d/f%03d", i), "x")
	}
	if err := os.Mkdir(filepath.Join(e.home, "d", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	ents, err := e.client.ReadDir("d")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 251 {
		t.Fatalf("ReadDir returned %d entries, want 251", len(ents))
	}
	seen := map[string]bool{}
	for _, fi := range ents {
		if seen[fi.Name()] {
			t.Errorf("duplicate entry %s", fi.Name())
		}
		seen[fi.Name()] = true
		if fi.Name() == "sub" && !fi.IsDir() {
			t.Error("sub is not a directory")
		}
	}
	if ents, err := e.client.ReadDir("/"); err != nil || len(ents) != 1 {
		t.Errorf("ReadDir / = %d entries, %v", len(ents), err)
	}
	if _, err := e.client.ReadDir("d/f000"); err == nil {
		t.Error("ReadDir of a file succeeded")
	}
	if _, err := e.client.ReadDir("nope"); code(err) != fxNoSuchFile {
		t.Errorf("ReadDir nope: %v", err)
	}
}

func TestDownload(t *testing.T) {
	e := newEnv(t, nil)
	big := strings.Repeat("0123456789abcdef", 8192) // 128 KiB: several packets
	e.write("big", big)
	got, err := e.get("big")
	if err != nil || got != big {
		t.Errorf("download of 128 KiB: %d bytes, %v", len(got), err)
	}
	if _, err := e.client.Open("/"); err == nil {
		t.Error("Open of a directory for reading succeeded")
	}
	if _, err := e.client.Open("missing"); code(err) != fxNoSuchFile {
		t.Errorf("Open missing: %v", err)
	}
}

func TestUploadCreateTruncateAppendPwrite(t *testing.T) {
	e := newEnv(t, nil)
	big := strings.Repeat("xyz", 50000) // 150 KB over several packets
	e.put("up", big)
	if got := e.read("up"); got != big {
		t.Errorf("upload: %d bytes stored, want %d", len(got), len(big))
	}
	// Truncate through the open flags.
	e.put("up", "short")
	if got := e.read("up"); got != "short" {
		t.Errorf("after the overwrite = %q", got)
	}
	// Append.
	f, err := e.client.OpenFile("up", os.O_WRONLY|os.O_APPEND)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("+more")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if got := e.read("up"); got != "short+more" {
		t.Errorf("after the append = %q", got)
	}
	// Writes at offsets, in any order (what a parallel scp does).
	g, err := e.client.OpenFile("pw", os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.WriteAt([]byte("world"), 6); err != nil {
		t.Fatal(err)
	}
	if _, err := g.WriteAt([]byte("hello "), 0); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if got := e.read("pw"); got != "hello world" {
		t.Errorf("pwrite = %q", got)
	}
	// O_EXCL on an existing file fails.
	if _, err := e.client.OpenFile("pw", os.O_WRONLY|os.O_CREATE|os.O_EXCL); err == nil {
		t.Error("exclusive create of an existing file succeeded")
	}
	// Read and write on one handle.
	h, err := e.client.OpenFile("pw", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.WriteAt([]byte("J"), 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := h.ReadAt(buf, 0); err != nil || string(buf) != "Jello" {
		t.Errorf("ReadAt = %q, %v", buf, err)
	}
	_ = h.Close()
	// Uploading to a directory fails.
	if err := e.client.Mkdir("dir"); err != nil {
		t.Fatal(err)
	}
	if err := putFile(e.client, "dir", "x"); err == nil {
		t.Error("upload onto a directory succeeded")
	}
	// New files are not executable and not special.
	fi, _ := os.Stat(filepath.Join(e.home, "up"))
	if fi.Mode().Perm()&0o111 != 0 || fi.Mode()&os.ModeType != 0 {
		t.Errorf("mode of a new file = %v", fi.Mode())
	}
}

func TestMkdirRmdirRemove(t *testing.T) {
	e := newEnv(t, nil)
	if err := e.client.Mkdir("a"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Mkdir("a"); err == nil {
		t.Error("mkdir of an existing directory succeeded")
	}
	if err := e.client.Mkdir("x/y"); code(err) != fxNoSuchFile {
		t.Errorf("mkdir below a missing parent: %v", err)
	}
	if err := e.client.MkdirAll("a/b/c"); err != nil || !e.exists("a/b/c") {
		t.Errorf("MkdirAll: %v", err)
	}
	e.put("a/f", "x")
	if err := e.client.RemoveDirectory("a"); err == nil {
		t.Error("rmdir of a non-empty directory succeeded")
	}
	if err := e.client.Remove("a/b"); err == nil || !e.exists("a/b") {
		t.Errorf("Remove of a directory: %v", err)
	}
	if err := e.client.Remove("a/f"); err != nil || e.exists("a/f") {
		t.Errorf("Remove of a file: %v", err)
	}
	if err := e.client.RemoveDirectory("a/b/c"); err != nil || e.exists("a/b/c") {
		t.Errorf("rmdir: %v", err)
	}
	if err := e.client.Remove("a/f"); code(err) != fxNoSuchFile {
		t.Errorf("Remove of a missing file: %v", err)
	}
	// The home itself cannot be removed, renamed over or made.
	for _, p := range []string{"/", ".", "..", "a/.."} {
		if err := e.client.RemoveDirectory(p); code(err) != fxPermissionDenied {
			t.Errorf("rmdir %q: %v", p, err)
		}
		if err := e.client.Mkdir(p); code(err) != fxPermissionDenied {
			t.Errorf("mkdir %q: %v", p, err)
		}
		if err := e.client.Rename("a", p); code(err) != fxPermissionDenied {
			t.Errorf("rename a %q: %v", p, err)
		}
	}
	if _, err := os.Stat(e.home); err != nil {
		t.Fatal(err)
	}
}

func TestRenameAndPosixRename(t *testing.T) {
	e := newEnv(t, nil)
	e.put("one", "1")
	e.put("two", "2")
	if err := e.client.Rename("one", "uno"); err != nil || !e.exists("uno") || e.exists("one") {
		t.Errorf("rename: %v", err)
	}
	// Plain rename does not replace.
	if err := e.client.Rename("uno", "two"); err == nil {
		t.Error("rename onto an existing file succeeded")
	}
	if e.read("two") != "2" || e.read("uno") != "1" {
		t.Error("a refused rename changed a file")
	}
	// posix-rename replaces.
	if err := e.client.PosixRename("uno", "two"); err != nil {
		t.Fatal(err)
	}
	if e.read("two") != "1" || e.exists("uno") {
		t.Error("posix-rename did not replace")
	}
	// Directories move with their content.
	e.write("d/x", "x")
	if err := e.client.Rename("d", "e"); err != nil || e.read("e/x") != "x" {
		t.Errorf("rename of a directory: %v", err)
	}
	if err := e.client.Rename("missing", "z"); code(err) != fxNoSuchFile {
		t.Errorf("rename of a missing file: %v", err)
	}
}

func TestSetstat(t *testing.T) {
	e := newEnv(t, nil)
	e.write("f", "content")
	if err := e.client.Chmod("f", 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(e.home, "f")); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode())
	}
	// Only the permission bits: a setuid bit is not taken.
	if err := e.client.Chmod("f", 0o4755); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(e.home, "f")); fi.Mode()&os.ModeSetuid != 0 || fi.Mode().Perm() != 0o755 {
		t.Errorf("mode after chmod 4755 = %v", fi.Mode())
	}
	at := time.Date(2026, 10, 12, 13, 11, 0, 0, time.UTC)
	mt := at.Add(time.Hour)
	if err := e.client.Chtimes("f", at, mt); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(e.home, "f")); !fi.ModTime().Equal(mt) {
		t.Errorf("mtime = %v, want %v", fi.ModTime(), mt)
	}
	// On a directory, and through an open handle (fsetstat).
	if err := e.client.Mkdir("d"); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Chmod("d", 0o700); err != nil {
		t.Fatal(err)
	}
	h, err := e.client.OpenFile("f", os.O_WRONLY)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Chmod(0o640); err != nil {
		t.Errorf("fsetstat chmod: %v", err)
	}
	_ = h.Close()
	if fi, _ := os.Stat(filepath.Join(e.home, "f")); fi.Mode().Perm() != 0o640 {
		t.Errorf("mode after fsetstat = %v", fi.Mode())
	}
	// Owner and size changes are refused.
	if err := e.client.Chown("f", 0, 0); code(err) != fxOpUnsupported {
		t.Errorf("chown: %v", err)
	}
	if err := e.client.Truncate("f", 0); code(err) != fxOpUnsupported {
		t.Errorf("truncate by setstat: %v", err)
	}
	if e.read("f") != "content" {
		t.Error("a refused setstat changed the file")
	}
	if err := e.client.Chmod("missing", 0o600); code(err) != fxNoSuchFile {
		t.Errorf("chmod of a missing file: %v", err)
	}
	if err := e.client.Chmod("/", 0o777); code(err) != fxPermissionDenied {
		t.Errorf("chmod of the home: %v", err)
	}
}

// The fallback of chmod for kernels without fchmodat2 is the same change.
func TestChmodPinned(t *testing.T) {
	dir := t.TempDir()
	h, err := openHome(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer h.close()
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	tf, _ := h.resolve(vpath{"f"})
	defer tf.close()
	if err := tf.chmodPinned(0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "f")); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", fi.Mode())
	}
	tl, _ := h.resolve(vpath{"l"})
	defer tl.close()
	if err := tl.chmodPinned(0o777); reasonOf(err) != reasonSymlink {
		t.Errorf("chmod of a link: %v", err)
	}
	if fi, _ := os.Stat(filepath.Join(dir, "f")); fi.Mode().Perm() != 0o600 {
		t.Errorf("the link's target was changed: %v", fi.Mode())
	}
}

func TestOtherRequestsAreRefused(t *testing.T) {
	e := newEnv(t, nil)
	e.write("f", "x")
	if err := e.client.Symlink("f", "l"); code(err) != fxPermissionDenied {
		t.Errorf("symlink: %v", err)
	}
	if err := e.client.Link("f", "h"); err == nil {
		t.Error("hard link succeeded")
	}
	if e.exists("l") || e.exists("h") {
		t.Error("a link was created")
	}
	if _, err := e.client.ReadLink("f"); err == nil {
		t.Error("readlink succeeded")
	}
}

// The library hands a READ request on a handle opened only for writing to the
// writer, as a write of zeros; the server refuses it.
func TestReadOnWriteOnlyHandleWritesNothing(t *testing.T) {
	for _, quota := range []int64{0, 1000} {
		for _, fl := range []int{os.O_WRONLY, os.O_WRONLY | os.O_APPEND, os.O_WRONLY | os.O_TRUNC | os.O_CREATE} {
			e := newEnv(t, func(c *Config) { c.Quota = quota })
			e.write("f", "hello world")
			h, err := e.client.OpenFile("f", fl)
			if err != nil {
				t.Fatal(err)
			}
			want := e.read("f") // an open with O_TRUNC emptied it
			b := make([]byte, 5)
			for _, off := range []int64{0, 3, 100} {
				if _, err := h.ReadAt(b, off); code(err) != fxOpUnsupported {
					t.Errorf("quota %d flags %#x: read at %d on a write-only handle: %v, want unsupported", quota, fl, off, err)
				}
			}
			if got := e.read("f"); got != want {
				t.Errorf("quota %d flags %#x: a read request changed the file from %q to %q", quota, fl, want, got)
			}
			// The handle still writes.
			if _, err := h.Write([]byte("HE")); err != nil {
				t.Errorf("quota %d flags %#x: write after the refused reads: %v", quota, fl, err)
			}
			if err := h.Close(); err != nil {
				t.Errorf("close: %v", err)
			}
			if got := e.read("f"); !strings.Contains(got, "HE") {
				t.Errorf("quota %d flags %#x: the write did not happen: %q", quota, fl, got)
			}
			if got := refusals(e.rec.all()); len(got) != 1 || got[0] != "unsupported" {
				t.Errorf("refusals = %v, want one unsupported for the handle", got)
			}
		}
	}
}

// A handle opened to read and write is not affected.
func TestReadWriteHandleStillReadsAndWrites(t *testing.T) {
	e := newEnv(t, nil)
	e.write("f", "hello world")
	h, err := e.client.OpenFile("f", os.O_RDWR)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 5)
	if n, err := h.ReadAt(b, 6); n != 5 || err != nil || string(b) != "world" {
		t.Errorf("read: %d, %v, %q", n, err, b)
	}
	if _, err := h.WriteAt([]byte("J"), 0); err != nil {
		t.Error(err)
	}
	_ = h.Close()
	if e.read("f") != "Jello world" {
		t.Errorf("file = %q", e.read("f"))
	}
}
