package sftpd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pkg/sftp"
)

// wantTooMany checks the answer to an open that is over the limit.
func wantTooMany(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s succeeded, want too many open files", what)
		return
	}
	// Through the client the status is a code; called directly, the error
	// still unwraps to it.
	if !strings.Contains(err.Error(), "too many open files") || !(code(err) == fxFailure || errors.Is(err, sftp.ErrSSHFxFailure)) {
		t.Errorf("%s: %v, want a failure status with too many open files", what, err)
	}
}

// listRequest is the request for the listing of a directory.
func listRequest(p string) *sftp.Request {
	return &sftp.Request{Method: "List", Filepath: p}
}

func TestHandleLimitForFiles(t *testing.T) {
	e := newEnvSeams(t, nil, seams{maxHandles: 4})
	e.write("f", "x")
	var open []*sftp.File
	for i := 0; i < 4; i++ {
		h, err := e.client.Open("f")
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		open = append(open, h)
	}
	_, err := e.client.Open("f")
	wantTooMany(t, "the fifth open", err)
	_, err = e.client.OpenFile("g", os.O_WRONLY|os.O_CREATE)
	wantTooMany(t, "an open for writing", err)
	if e.exists("g") {
		t.Error("a refused open created the file")
	}
	if got := refusals(e.rec.all()); len(got) != 2 || got[0] != "too many open files" {
		t.Errorf("refusals = %v, want two too many open files", got)
	}
	// Closing gives a place back.
	_ = open[0].Close()
	h, err := e.client.Open("f")
	if err != nil {
		t.Fatalf("open after a close: %v", err)
	}
	_ = h.Close()
	for _, h := range open[1:] {
		_ = h.Close()
	}
	for i := 0; i < 20; i++ { // nothing leaks over many opens and closes
		w, err := e.client.OpenFile("w", os.O_WRONLY|os.O_CREATE)
		if err != nil {
			t.Fatalf("open for writing %d: %v", i, err)
		}
		_ = w.Close()
	}
}

// An open that fails for another reason holds no place.
func TestHandleLimitCountsOnlyOpenHandles(t *testing.T) {
	e := newEnvSeams(t, nil, seams{maxHandles: 2})
	e.write("f", "x")
	e.write(".ssh/k", "x")
	for i := 0; i < 10; i++ {
		_, _ = e.client.Open("missing")
		_, _ = e.client.Open(".ssh/k")
		_, _ = e.client.Open("/")
		_, _ = e.client.ReadDir("missing")
		_, _ = e.client.ReadDir("f")
	}
	a, err := e.client.Open("f")
	if err != nil {
		t.Fatal(err)
	}
	b, err := e.client.Open("f")
	if err != nil {
		t.Fatalf("second handle after failed opens: %v", err)
	}
	_ = a.Close()
	_ = b.Close()
}

// The listers are closed by the library with their handle; here they are
// opened and closed by hand, as the library does.
func TestHandleLimitForListings(t *testing.T) {
	e := newEnv(t, nil)
	e.write("d/f", "x")
	s := newServer(mustHome(t, e.home), Config{Home: e.home}, seams{maxHandles: 3})
	var ls []io.Closer
	for i := 0; i < 3; i++ {
		la, err := s.Filelist(listRequest("/d"))
		if err != nil {
			t.Fatalf("listing %d: %v", i, err)
		}
		ls = append(ls, la.(io.Closer))
	}
	_, err := s.Filelist(listRequest("/d"))
	wantTooMany(t, "the fourth listing", err)
	if reasonOf(err) != reasonTooMany {
		t.Errorf("reason = %q", reasonOf(err))
	}
	// A stat is no handle.
	if _, err := s.Filelist(&sftp.Request{Method: "Stat", Filepath: "/d"}); err != nil {
		t.Errorf("stat at the limit: %v", err)
	}
	_ = ls[0].Close()
	_ = ls[0].Close() // twice gives back one place only
	la, err := s.Filelist(listRequest("/d"))
	if err != nil {
		t.Fatalf("listing after a close: %v", err)
	}
	ls = append(ls, la.(io.Closer))
	_, err = s.Filelist(listRequest("/d"))
	wantTooMany(t, "a listing past the limit after a double close", err)
	for _, c := range ls {
		_ = c.Close()
	}
}

func TestHandleLimitMixedFilesAndListingsThroughTheClient(t *testing.T) {
	e := newEnvSeams(t, nil, seams{maxHandles: 3})
	e.write("d/f", "x")
	var open []*sftp.File
	for i := 0; i < 3; i++ {
		h, err := e.client.Open("d/f")
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, h)
	}
	_, err := e.client.ReadDir("d")
	wantTooMany(t, "a listing with three files open", err)
	_ = open[0].Close()
	if ents, err := e.client.ReadDir("d"); err != nil || len(ents) != 1 {
		t.Errorf("listing after a close: %v, %v", ents, err)
	}
	// The client closed the listing's handle: its place is free again.
	h, err := e.client.Open("d/f")
	if err != nil {
		t.Errorf("open after a listing: %v", err)
	} else {
		_ = h.Close()
	}
	for _, h := range open[1:] {
		_ = h.Close()
	}
}

func TestSessionEndsWithHandlesOpen(t *testing.T) {
	e := newEnvSeams(t, nil, seams{maxHandles: 3})
	e.write("f", "x")
	for i := 0; i < 3; i++ {
		if _, err := e.client.Open("f"); err != nil {
			t.Fatal(err)
		}
	}
	// The library reports a session that ends with handles open as an
	// unexpected end of the stream; what matters is that it ends.
	if err := e.stop(); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("Serve with handles open: %v", err)
	}
}

// The listing is read as the client asks for it and the directory is not
// held in memory: many handles on a big directory cost a batch each.
func TestListingsDoNotSnapshotTheDirectory(t *testing.T) {
	e := newEnv(t, nil)
	long := strings.Repeat("n", 200)
	for i := 0; i < 2000; i++ {
		if err := os.WriteFile(filepath.Join(e.home, fmt.Sprintf("%s%04d", long, i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s := newServer(mustHome(t, e.home), Config{Home: e.home}, seams{})
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := heap()
	var held []io.Closer
	const n = 200
	for i := 0; i < n; i++ {
		la, err := s.Filelist(listRequest("/"))
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, la.(io.Closer))
		ls := make([]os.FileInfo, 100)
		if got, err := la.ListAt(ls, 0); got != 100 || err != nil {
			t.Fatalf("first batch: %d, %v", got, err)
		}
	}
	grown := int64(heap()) - int64(before)
	// A snapshot of 2000 entries with 200-byte names, 200 times over, is
	// over 100 MiB; a batch of 100 entries each is a few MiB at most.
	if grown > 32<<20 {
		t.Errorf("heap grew by %d MiB for %d listings of a 2000-entry directory", grown>>20, n)
	}
	runtime.KeepAlive(held)
	for _, c := range held {
		_ = c.Close()
	}
}

// listAll reads a listing in batches of size, the way the library does.
func listAll(t *testing.T, la sftp.ListerAt, size int) []string {
	t.Helper()
	var names []string
	for {
		ls := make([]os.FileInfo, size)
		n, err := la.ListAt(ls, int64(len(names)))
		for _, fi := range ls[:n] {
			names = append(names, fi.Name())
		}
		if err == io.EOF {
			return names
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestListerOffsets(t *testing.T) {
	e := newEnv(t, nil)
	for i := 0; i < 250; i++ {
		e.write(fmt.Sprintf("d/f%03d", i), "x")
	}
	s := newServer(mustHome(t, e.home), Config{Home: e.home}, seams{})
	open := func() sftp.ListerAt {
		la, err := s.Filelist(listRequest("/d"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = la.(io.Closer).Close() })
		return la
	}
	la := open()
	all := listAll(t, la, 100)
	if len(all) != 250 {
		t.Fatalf("%d entries, want 250", len(all))
	}
	seen := map[string]bool{}
	for _, n := range all {
		if seen[n] {
			t.Errorf("duplicate %s", n)
		}
		seen[n] = true
	}
	// The same listing in other batch sizes gives the same entries.
	if got := listAll(t, open(), 7); strings.Join(got, ",") != strings.Join(all, ",") {
		t.Error("batches of 7 gave another listing")
	}
	// At the end: EOF, again and again.
	ls := make([]os.FileInfo, 100)
	if n, err := la.ListAt(ls, 250); n != 0 || err != io.EOF {
		t.Errorf("at the end: %d, %v", n, err)
	}
	if n, err := la.ListAt(ls, 1000); n != 0 || err != io.EOF {
		t.Errorf("past the end: %d, %v", n, err)
	}
	// A non-sequential offset: back to the start, then forward and back.
	for _, off := range []int64{0, 130, 30, 249, 100, 0} {
		n, err := la.ListAt(ls, off)
		want := min(100, 250-int(off))
		if n != want {
			t.Errorf("at %d: %d entries, want %d (%v)", off, n, want, err)
			continue
		}
		for i := 0; i < n; i++ {
			if ls[i].Name() != all[int(off)+i] {
				t.Errorf("at %d entry %d is %s, want %s", off, i, ls[i].Name(), all[int(off)+i])
				break
			}
		}
	}
	// A first read at a later offset skips ahead.
	small := make([]os.FileInfo, 3)
	if n, _ := open().ListAt(small, 200); n != 3 || small[0].Name() != all[200] {
		t.Errorf("a first read at offset 200: %d, %v", n, small[0])
	}
}

func TestListerHidesSSHAndSurvivesRemovals(t *testing.T) {
	e := sshEnv(t)
	for i := 0; i < 150; i++ {
		e.write(fmt.Sprintf("f%03d", i), "x")
	}
	s := newServer(mustHome(t, e.home), Config{Home: e.home}, seams{})
	la, err := s.Filelist(listRequest("/"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = la.(io.Closer).Close() }()
	names := listAll(t, la, 100)
	if len(names) != 152 { // a, plain and the 150
		t.Errorf("%d entries, want 152", len(names))
	}
	for _, n := range names {
		if n == ".ssh" {
			t.Error(".ssh is listed")
		}
	}
	// Removed after the listing began: simply not there.
	la2, err := s.Filelist(listRequest("/"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = la2.(io.Closer).Close() }()
	first := make([]os.FileInfo, 10)
	if n, err := la2.ListAt(first, 0); n != 10 || err != nil {
		t.Fatalf("first batch: %d, %v", n, err)
	}
	for i := 0; i < 150; i++ {
		_ = os.Remove(filepath.Join(e.home, fmt.Sprintf("f%03d", i)))
	}
	if rest := listAll(t, la2, 100); len(rest) > 152 {
		t.Errorf("%d entries after the removals", len(rest))
	}
}
