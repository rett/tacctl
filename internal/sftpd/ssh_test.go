package sftpd

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// 2. .ssh is out of reach.

// sshSpellings are the ways to name the .ssh entry of the home, or the
// file under it, after cleaning.
var sshSpellings = []string{
	".ssh",
	"/.ssh",
	"./.ssh",
	"//.ssh",
	".ssh/",
	".ssh/.",
	"a/../.ssh",
	"/a/b/../../.ssh",
	"../.ssh",
	"/../../.ssh",
	".ssh/authorized_keys",
	"/.ssh/authorized_keys",
	".ssh/../.ssh/authorized_keys",
	"./.ssh/./authorized_keys",
	"//.ssh//authorized_keys",
	".ssh/sub/new",
	".ssh/missing",
}

func sshEnv(t *testing.T) *env {
	e := newEnv(t, nil)
	e.write(".ssh/authorized_keys", "ssh-ed25519 AAAA example-key alice@example.net\n")
	e.write("a/placeholder", "x")
	e.write("plain", "x")
	return e
}

func TestSSHRefusedForEveryOperation(t *testing.T) {
	e := sshEnv(t)
	for _, p := range sshSpellings {
		check := func(op string, err error) {
			t.Helper()
			if code(err) != fxPermissionDenied {
				t.Errorf("%s %q: err = %v, want permission denied", op, p, err)
			}
		}
		_, err := e.client.Stat(p)
		check("stat", err)
		_, err = e.client.Lstat(p)
		check("lstat", err)
		_, err = e.client.ReadDir(p)
		check("list", err)
		_, err = e.client.Open(p)
		check("open", err)
		_, err = e.client.Create(p)
		check("create", err)
		_, err = e.client.OpenFile(p, os.O_WRONLY|os.O_APPEND)
		check("append", err)
		_, err = e.client.OpenFile(p, os.O_WRONLY|os.O_TRUNC)
		check("truncate", err)
		check("mkdir", e.client.Mkdir(p))
		check("mkdirall", e.client.MkdirAll(p))
		check("remove", e.client.Remove(p))
		check("rmdir", e.client.RemoveDirectory(p))
		check("rename from", e.client.Rename(p, "moved"))
		check("rename to", e.client.Rename("plain", p))
		check("posix-rename from", e.client.PosixRename(p, "moved"))
		check("posix-rename to", e.client.PosixRename("plain", p))
		check("chmod", e.client.Chmod(p, 0o777))
		check("chtimes", e.client.Chtimes(p, time.Now(), time.Now()))
		check("chown", e.client.Chown(p, 1, 1))
		check("truncate by setstat", e.client.Truncate(p, 0))
	}
	// Nothing changed on disk.
	if got := e.read(".ssh/authorized_keys"); got != "ssh-ed25519 AAAA example-key alice@example.net\n" {
		t.Errorf("authorized_keys changed: %q", got)
	}
	fi, _ := os.Stat(filepath.Join(e.home, ".ssh"))
	if fi.Mode().Perm() != 0o755 {
		t.Errorf(".ssh mode changed to %v", fi.Mode())
	}
	if e.exists("moved") || e.exists(".ssh/sub") || e.exists(".ssh/missing") || !e.exists("plain") {
		t.Error("a refused request changed the home")
	}
	for _, r := range refusals(e.rec.all()) {
		if r != ".ssh" {
			t.Errorf("refusal reason %q, want .ssh", r)
		}
	}
}

func TestSSHHiddenFromListing(t *testing.T) {
	e := sshEnv(t)
	ents, err := e.client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, fi := range ents {
		names = append(names, fi.Name())
	}
	if len(names) != 2 || names[0] != "a" || names[1] != "plain" {
		t.Errorf("listing of / = %v, want [a plain]", names)
	}
	// Other directories named .ssh are ordinary, and so is the spelling
	// in another case: the rule is the entry of the home, as written.
	e.write("a/.ssh/k", "x")
	e.write(".SSH/k", "x")
	if got, err := e.get("a/.ssh/k"); err != nil || got != "x" {
		t.Errorf("a/.ssh/k = %q, %v", got, err)
	}
	if got, err := e.get(".SSH/k"); err != nil || got != "x" {
		t.Errorf(".SSH/k = %q, %v", got, err)
	}
	ents, _ = e.client.ReadDir("a")
	if len(ents) != 2 {
		t.Errorf("listing of a = %d entries, want 2", len(ents))
	}
}

func TestSSHRealPathIsOnlyAString(t *testing.T) {
	e := sshEnv(t)
	// Resolving the name gives the cleaned name; whatever is done with it
	// is refused.
	got, err := e.client.RealPath("a/../.ssh")
	if err != nil || got != "/.ssh" {
		t.Errorf("RealPath = %q, %v", got, err)
	}
}

// Symbolic links: never followed.

func linkEnv(t *testing.T) *env {
	e := sshEnv(t)
	e.write("real/f", "ok")
	e.write("outside-target", "x")
	if err := os.WriteFile(filepath.Join(e.root, "outside"), []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"tossh":       ".ssh",
		"tossh-file":  ".ssh/authorized_keys",
		"toabs":       filepath.Join(e.root, "outside"),
		"toparent":    "../outside",
		"todir":       "real",
		"tofile":      "real/f",
		"toself":      "toself",
		"dangling":    "nothing",
		"toabs-ssh":   filepath.Join(e.home, ".ssh"),
		"real/inlink": "../.ssh",
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(e.home, name)); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func TestSymlinksAreListedAndLstatedAsLinks(t *testing.T) {
	e := linkEnv(t)
	for _, n := range []string{"tossh", "toabs", "todir", "tofile", "dangling", "toself"} {
		fi, err := e.client.Lstat(n)
		if err != nil {
			t.Errorf("lstat %s: %v", n, err)
			continue
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			t.Errorf("lstat %s: mode %v, want a symlink", n, fi.Mode())
		}
	}
	ents, err := e.client.ReadDir("/")
	if err != nil {
		t.Fatal(err)
	}
	links := 0
	for _, fi := range ents {
		if fi.Mode()&os.ModeSymlink != 0 {
			links++
		}
		if fi.Name() == ".ssh" {
			t.Error(".ssh is listed")
		}
	}
	if links != 9 {
		t.Errorf("%d links listed, want 9", links)
	}
}

func TestSymlinksAreNeverFollowed(t *testing.T) {
	e := linkEnv(t)
	through := []string{"tossh", "tossh-file", "toabs", "toparent", "todir", "tofile", "toself", "dangling", "toabs-ssh",
		"tossh/authorized_keys", "todir/f", "toabs/x", "real/inlink/authorized_keys", "tossh/x/y"}
	for _, p := range through {
		check := func(op string, err error) {
			t.Helper()
			if err == nil {
				t.Errorf("%s %q succeeded through a link", op, p)
			}
		}
		_, err := e.client.Stat(p)
		check("stat", err)
		_, err = e.client.ReadDir(p)
		check("list", err)
		_, err = e.client.Open(p)
		check("open", err)
		_, err = e.client.OpenFile(p, os.O_WRONLY)
		check("open for write", err)
		_, err = e.client.Create(p + "/new")
		check("create below", err)
		check("mkdir below", e.client.Mkdir(p+"/d"))
		check("chmod", e.client.Chmod(p, 0o777))
		check("chtimes", e.client.Chtimes(p, time.Now(), time.Now()))
		_, err = e.client.ReadLink(p)
		check("readlink", err)
	}
	// "todir/../plain" is lexically "/plain": it is not through the link.
	if _, err := e.client.Stat("todir/../plain"); err != nil {
		t.Errorf("todir/../plain: %v (cleaned to /plain, not through the link)", err)
	}
	// The refusals through a link are of the "symlink" kind.
	got := refusals(e.rec.all())
	seen := map[string]bool{}
	for _, r := range got {
		seen[r] = true
	}
	if !seen["symlink"] {
		t.Errorf("no refusal with reason symlink in %v", got)
	}
	// Nothing was created or changed through a link.
	for _, n := range []string{"new", "d"} {
		for _, dir := range []string{e.home, filepath.Join(e.home, ".ssh"), e.root} {
			if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
				t.Errorf("%s was created in %s", n, dir)
			}
		}
	}
	if fi, _ := os.Stat(filepath.Join(e.root, "outside")); fi.Mode().Perm() != 0o644 {
		t.Errorf("the file outside the home was changed: %v", fi.Mode())
	}
	if got := e.read(".ssh/authorized_keys"); got != "ssh-ed25519 AAAA example-key alice@example.net\n" {
		t.Errorf("authorized_keys changed: %q", got)
	}
}

func TestSymlinkAndHardlinkCreationRefused(t *testing.T) {
	e := sshEnv(t)
	if err := e.client.Symlink(".ssh", "l1"); code(err) != fxPermissionDenied {
		t.Errorf("symlink to .ssh: %v", err)
	}
	if err := e.client.Symlink("/etc/passwd", "l2"); code(err) != fxPermissionDenied {
		t.Errorf("symlink to /etc/passwd: %v", err)
	}
	if err := e.client.Symlink("plain", "l3"); code(err) != fxPermissionDenied {
		t.Errorf("symlink to a file in the home: %v", err)
	}
	if err := e.client.Link("plain", "h1"); err == nil {
		t.Error("hard link to a file in the home succeeded")
	}
	if err := e.client.Link(".ssh/authorized_keys", "h2"); err == nil {
		t.Error("hard link of authorized_keys succeeded")
	}
	for _, n := range []string{"l1", "l2", "l3", "h1", "h2"} {
		if e.exists(n) {
			t.Errorf("%s was created", n)
		}
	}
	got := refusals(e.rec.all())
	if len(got) < 5 {
		t.Errorf("refusals = %v, want one per request", got)
	}
}

// A link can be removed or moved as the entry it is, never through.
func TestLinkItselfCanBeRemovedAndRenamed(t *testing.T) {
	e := linkEnv(t)
	if err := e.client.Remove("todir"); err != nil || e.exists("todir") {
		t.Errorf("remove of a link: %v", err)
	}
	if !e.exists("real/f") {
		t.Error("removing the link removed its target")
	}
	if err := e.client.Rename("tofile", "moved"); err != nil || !e.exists("moved") {
		t.Errorf("rename of a link: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(e.home, "moved")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the moved entry is not the link: %v, %v", fi, err)
	}
	if !e.exists("real/f") {
		t.Error("renaming the link moved its target")
	}
	// A link cannot be written over by an upload.
	if err := putFile(e.client, "tossh-file", "x"); err == nil {
		t.Error("upload over a link succeeded")
	}
	if got := e.read(".ssh/authorized_keys"); got[:3] != "ssh" {
		t.Errorf("authorized_keys changed: %q", got)
	}
}

// A directory swapped for a link between a check and the use must not be
// followed: the resolution never looks and then follows.
func TestDirectorySwappedForLinkIsNotFollowed(t *testing.T) {
	e := newEnv(t, nil)
	e.write("real/f", "ok")
	e.write(".ssh/f", "secret")
	if err := os.Symlink(".ssh", filepath.Join(e.home, "lnk")); err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(e.home, "real"), filepath.Join(e.home, "lnk")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Exchange the directory and the link atomically.
			if err := unix.Renameat2(unix.AT_FDCWD, a, unix.AT_FDCWD, b, unix.RENAME_EXCHANGE); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	var opened, leaked int
	for i := 0; i < 400; i++ {
		got, err := e.get("real/f")
		if err == nil {
			opened++
			if got != "ok" {
				leaked++
			}
		}
	}
	close(stop)
	wg.Wait()
	if leaked != 0 {
		t.Fatalf("%d of %d reads returned the content of .ssh/f through a swapped link", leaked, opened)
	}
	t.Logf("%d of 400 reads found the directory in place, the others the link", opened)
}
