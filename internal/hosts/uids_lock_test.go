package hosts

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/ui"
)

// ledgerNumbers are the name:uid lines of the ledger at p.
func ledgerNumbers(t *testing.T, p string) []string {
	t.Helper()
	var out []string
	for _, l := range strings.Split(readFile(t, p), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// distinctNumbers fails when two lines of the ledger share a name or a
// number.
func distinctNumbers(t *testing.T, lines []string) {
	t.Helper()
	names, uids := map[string]bool{}, map[string]bool{}
	for _, l := range lines {
		name, uid, _ := strings.Cut(l, ":")
		if names[name] || uids[uid] {
			t.Errorf("a name or a number twice in the ledger: %q", lines)
		}
		names[name], uids[uid] = true, true
	}
}

// For replaces the file whole (a temporary file beside it, renamed over it),
// keeps its mode at 0600, and leaves nothing behind.
func TestUIDsForIsAtomic(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p := filepath.Join(dir, "linux-uids")
	u := UIDs{Path: p}

	// A new ledger: the range record, then the line.
	if uid, err := u.For("alice"); err != nil || uid != "80000" {
		t.Fatalf("alice: %q, %v", uid, err)
	}
	if got, want := readFile(t, p), "# range 80000-89999\nalice:80000\n"; got != want {
		t.Errorf("ledger %q, want %q", got, want)
	}
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}

	// The file is replaced, not appended to: another inode, the same bytes
	// before the new line.
	if uid, err := u.For("bob"); err != nil || uid != "80001" {
		t.Fatalf("bob: %q, %v", uid, err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Error("For wrote the ledger in place")
	}
	if after.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", after.Mode().Perm())
	}
	if got, want := readFile(t, p), "# range 80000-89999\nalice:80000\nbob:80001\n"; got != want {
		t.Errorf("ledger %q, want %q", got, want)
	}

	// A known name allocates nothing and writes nothing.
	if uid, err := u.For("alice"); err != nil || uid != "80000" {
		t.Fatalf("alice again: %q, %v", uid, err)
	}
	if again, _ := os.Stat(p); !os.SameFile(after, again) {
		t.Error("a lookup rewrote the ledger")
	}

	// No temporary file is left beside it.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "linux-uids" {
			t.Errorf("left beside the ledger: %s", e.Name())
		}
	}
}

// A last line with no newline is not joined to the new one, and the lines
// and '#' lines already there stay as they are.
func TestUIDsForKeepsTheFile(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "linux-uids")
	writeFile(t, p, "# range 80000-89999\n# kept by hand\nann:80004\ncy:80000")
	if uid, err := (UIDs{Path: p}).For("dee"); err != nil || uid != "80005" {
		t.Fatalf("dee: %q, %v", uid, err)
	}
	if got, want := readFile(t, p), "# range 80000-89999\n# kept by hand\nann:80004\ncy:80000\ndee:80005\n"; got != want {
		t.Errorf("ledger %q, want %q", got, want)
	}
}

// Allocations that hold the lock, from as many goroutines as there are
// names, give every name its own number and leave one line per name. Without
// the lock they read the same file and the same highest number: this test
// fails (duplicate numbers or lost lines) when Lock does not exclude.
func TestUIDsForUnderTheLockGivesDistinctNumbers(t *testing.T) {
	t.Parallel()
	p := filepath.Join(t.TempDir(), "linux-uids")
	u := UIDs{Path: p}
	const n = 16
	got := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = u.WithLock(func() error {
				uid, err := u.For(fmt.Sprintf("user%02d", i))
				got[i] = uid
				return err
			})
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("user%02d: %v", i, err)
		}
	}
	lines := ledgerNumbers(t, p)
	if len(lines) != n {
		t.Errorf("%d lines for %d users: %q", len(lines), n, lines)
	}
	distinctNumbers(t, lines)
	sort.Strings(got)
	for i, uid := range got {
		if want := fmt.Sprint(80000 + i); uid != want {
			t.Errorf("numbers %q: the %dth is %q, want %q", got, i, uid, want)
		}
	}
}

// Two WriteScript runs that meet new users at once (two 'host sync' of two
// hosts, or a sync and 'config linux script') give every user one number: the
// ledger lock covers the build of the users, which allocates (D238).
func TestWriteScriptConcurrentRunsAllocateDistinctNumbers(t *testing.T) {
	t.Parallel()
	base, _, _ := testEnv(t)
	if err := os.WriteFile(base.Paths.Tarball(), []byte("not really a tarball\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	const runs, per = 8, 4
	users := make([]string, runs)
	errs := make([]error, runs)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := *base
			var out, errb bytes.Buffer
			e.Out = ui.Output{Stdout: &out, Stderr: &errb}
			var rows []string
			for j := 0; j < per; j++ {
				rows = append(rows, fmt.Sprintf("u%d-%d|15", i, j))
			}
			<-start
			res, err := e.WriteScript(ScriptRequest{Scope: "lab", Server: "192.0.2.10", Method: Tacplus,
				Output: filepath.Join(t.TempDir(), "x.sh"), Secret: "0123456789abcdef0123456789abcdef", Rows: rows, Temp: true})
			users[i], errs[i] = res.Users, err
		}()
	}
	close(start)
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("run %d: %v", i, err)
		}
	}
	lines := ledgerNumbers(t, base.Paths.UIDs)
	if len(lines) != runs*per {
		t.Errorf("%d lines for %d users: %q", len(lines), runs*per, lines)
	}
	distinctNumbers(t, lines)
	// And each script carries the numbers the ledger holds.
	held := map[string]bool{}
	for _, l := range lines {
		held[l] = true
	}
	for i, us := range users {
		for _, l := range strings.Split(us, "\n") {
			f := strings.Split(l, ":")
			if len(f) != 3 || !held[f[0]+":"+f[2]] {
				t.Errorf("run %d sent %q, not in the ledger %q", i, l, lines)
			}
		}
	}
}

// The lock file is the ledger's own, beside it, 0600; it stays after the
// lock is let go and can be taken again.
func TestUIDsLockFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	u := UIDs{Path: filepath.Join(dir, "linux-uids")}
	unlock, err := u.Lock()
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, ".linux-uids.lock"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("lock file: %v, %v", st, err)
	}
	if _, err := os.Stat(u.Path); err == nil {
		t.Error("taking the lock made the ledger")
	}
	unlock()
	if err := u.WithLock(func() error { return nil }); err != nil {
		t.Errorf("after unlock: %v", err)
	}
}

// A lock held past the wait is ErrLedgerBusy, with the wait in the text, and
// whatever needed the lock changed nothing. The wait is one variable of the
// package (SetLockWait), so the test is not parallel.
func TestUIDsLockRefusesAfterTheWait(t *testing.T) {
	restore := SetLockWait(100 * time.Millisecond)
	defer restore()
	dir := t.TempDir()
	u := UIDs{Path: filepath.Join(dir, "linux-uids")}
	writeFile(t, u.Path, "# range 80000-89999\nann:80000\n")
	unlock, err := u.Lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	_, err = u.Lock()
	if !errors.Is(err, ErrLedgerBusy) {
		t.Fatalf("second Lock: %v", err)
	}
	const want = "the UID ledger (linux-uids) is locked by another tacctl command; try again in a moment (waited 100ms)"
	if err.Error() != want {
		t.Errorf("message %q, want %q", err, want)
	}
	if err := u.WithLock(func() error { t.Error("fn ran without the lock"); return nil }); !errors.Is(err, ErrLedgerBusy) {
		t.Errorf("WithLock: %v", err)
	}
	// The registry's lock is another file: not blocked by the ledger's.
	unlockReg, err := (&Registry{Path: filepath.Join(dir, "linux-hosts")}).Lock()
	if err != nil {
		t.Errorf("registry lock while the ledger's is held: %v", err)
	} else {
		unlockReg()
	}

	// The readers that decide wait for it too.
	if _, err := Removed(nil, u, nil); !errors.Is(err, ErrLedgerBusy) {
		t.Errorf("Removed: %v", err)
	}
	e, _, errb := testEnv(t)
	e.Paths.UIDs = u.Path
	if err := os.WriteFile(e.Paths.Tarball(), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = e.WriteScript(ScriptRequest{Scope: "lab", Server: "192.0.2.10", Method: Tacplus,
		Output: filepath.Join(dir, "x.sh"), Secret: "0123456789abcdef0123456789abcdef", Rows: []string{"bob|15"}})
	if !errors.Is(err, ErrLedgerBusy) {
		t.Errorf("WriteScript: %v (%q)", err, errb.String())
	}
	if _, serr := os.Stat(filepath.Join(dir, "x.sh")); serr == nil {
		t.Error("WriteScript wrote a script without the ledger")
	}
	if got := readFile(t, u.Path); got != "# range 80000-89999\nann:80000\n" {
		t.Errorf("ledger changed: %q", got)
	}
}

// WriteScript lets go of the lock before it returns: the next holder takes
// it at once, so a run on a host after the script never holds it.
func TestWriteScriptReleasesTheLock(t *testing.T) {
	restore := SetLockWait(100 * time.Millisecond)
	defer restore()
	e, _, _ := testEnv(t)
	if err := os.WriteFile(e.Paths.Tarball(), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, temp := range []bool{false, true} {
		_, err := e.WriteScript(ScriptRequest{Scope: "lab", Server: "192.0.2.10", Method: Tacplus, Temp: temp,
			Output: filepath.Join(t.TempDir(), "x.sh"), Secret: "0123456789abcdef0123456789abcdef", Rows: []string{"bob|15"}})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.UIDs().WithLock(func() error { return nil }); err != nil {
			t.Errorf("temp %v: the lock is still held: %v", temp, err)
		}
	}
	// A failed check leaves none either.
	if _, err := e.WriteScript(ScriptRequest{Scope: "lab", Server: "x;y", Method: Tacplus, Secret: "0123456789abcdef"}); err == nil {
		t.Fatal("bad server accepted")
	}
	if err := e.UIDs().WithLock(func() error { return nil }); err != nil {
		t.Errorf("after a refusal: %v", err)
	}
}
