package cli

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A report file is opened without following a link and without blocking, and
// what was opened must be a regular file: a link swapped in after the listing,
// a FIFO and a device node are refused before a byte is read.
func TestReportContentRefusesWhatIsNotARegularFile(t *testing.T) {
	dir := t.TempDir()
	pl := reportPlace{user: "alice", home: dir, dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.txt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := pl.content("real.txt", 0); err != nil || string(b) != "one\ntwo\n" {
		t.Fatalf("a regular file: %q %v", b, err)
	}
	for _, c := range []struct{ file, want string }{
		{"link.txt", "is a symbolic link"},
		{"pipe.txt", "is not a regular file"},
	} {
		done := make(chan error, 2)
		go func() {
			_, err := pl.content(c.file, 0)
			_, _, err2 := pl.head(c.file, 200)
			done <- err
			done <- err2
		}()
		for range 2 {
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s: %v, want %q", c.file, err, c.want)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s: the read blocked", c.file)
			}
		}
	}
	// a device node (the null device is the one every system has)
	dev := reportPlace{user: "alice", home: "/dev", dir: "/dev"}
	if _, err := dev.content("null", 0); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Errorf("a device node: %v", err)
	}
	// the metadata file is read the same way
	if m, note := readReportMeta(filepath.Join(dir, "pipe.txt")); m != nil || note == "" {
		t.Errorf("a FIFO as metadata: %v %q", m, note)
	}
}

// content stops at the limit it is given, and says so without returning the
// start of the file.
func TestReportContentIsCapped(t *testing.T) {
	dir := t.TempDir()
	pl := reportPlace{user: "alice", home: dir, dir: dir}
	if err := os.WriteFile(filepath.Join(dir, "r.txt"), []byte(strings.Repeat("x", 100)), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := pl.content("r.txt", 100); err != nil || len(b) != 100 {
		t.Errorf("at the limit: %d %v", len(b), err)
	}
	if b, err := pl.content("r.txt", 99); err == nil || !strings.Contains(err.Error(), "larger than 99 bytes") || b != nil {
		t.Errorf("over the limit: %d %v", len(b), err)
	}
}

// show --content reads the first lines of the file and no more, however big
// the file is: a sparse file of 3 GiB is shown in its first 200 lines and the
// output says there is more, without a count it did not read. export stops at
// the size limit in force.
func TestReportsShowContentDoesNotReadTheWholeFile(t *testing.T) {
	b := newReportsBox(t)
	if err := os.MkdirAll(b.dir("alice"), 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(b.dir("alice"), "huge.txt")
	var head strings.Builder
	for i := 1; i <= 300; i++ {
		head.WriteString("line\n")
	}
	if err := os.WriteFile(p, []byte(head.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(p, 3<<30); err != nil {
		t.Skipf("no sparse file of 3 GiB here: %v", err)
	}
	done := make(chan string, 1)
	go func() { done <- b.as("alice", asSuper, "show", "huge", "--content") }()
	var out string
	select {
	case out = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("show --content did not finish")
	}
	if countLines(out, "line") != 200 || !strings.Contains(out, "... more; 'tacctl device reports export huge' prints all of it.") {
		t.Errorf("show --content: %d lines\n%.300s", strings.Count(out, "\n"), out)
	}
	if strings.Contains(out, "more lines") {
		t.Errorf("a count of lines nobody read:\n%.300s", out)
	}
	// export refuses a file over the size limit in force, naming the number
	b.sb.asAlice("", "config", "reports", "max-size", "1Ki")
	b.sb.expect(0, "", "")
	b.as("alice", asSuper, "export", "huge")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Cannot read the report: huge.txt is larger than 1024 bytes") {
		t.Errorf("export: %d %q", b.sb.code, b.sb.stderr())
	}
}
