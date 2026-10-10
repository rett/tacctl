package askpass

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeClock is the agent's clock in the tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *fakeClock { return &fakeClock{t: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// recorder collects Notify events.
type recorder struct {
	mu sync.Mutex
	ev []Event
}

func (r *recorder) add(e Event) {
	r.mu.Lock()
	r.ev = append(r.ev, e)
	r.mu.Unlock()
}

func (r *recorder) take() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.ev
	r.ev = nil
	return out
}

// shortTemp is a temporary directory whose path leaves room for a socket
// name (sun_path is 108 bytes).
func shortTemp(t *testing.T) string {
	t.Helper()
	base := os.TempDir()
	if len(base) > 40 {
		base = "/tmp"
	}
	d, err := os.MkdirTemp(base, "ap")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	return d
}

type rig struct {
	a     *Agent
	c     *Client
	clock *fakeClock
	rec   *recorder
	path  string
	token string
	dir   string
}

// newRig is a listening agent with a fake clock and no background sweep,
// and a client for it.
func newRig(t *testing.T, mod func(*Options)) *rig {
	t.Helper()
	r := &rig{clock: newClock(), rec: &recorder{}, dir: filepath.Join(shortTemp(t), "run")}
	o := Options{Now: r.clock.Now, Notify: r.rec.add, SweepEvery: -1, noHarden: true}
	if mod != nil {
		mod(&o)
	}
	a, err := New(o)
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	r.a = a
	r.path, r.token, err = a.Listen(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	r.c, err = NewClient(a.Env())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// events delivers what the agent queued and returns it.
func (r *rig) events() []Event {
	r.a.Flush()
	return r.rec.take()
}

var requireMlock = flag.Bool("require-mlock", false, "fail, not skip, the tests that need mlock")

// skipNoLock skips (or, with -require-mlock, fails) when New could not
// lock memory.
func skipNoLock(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, ErrNoLock) {
		if *requireMlock {
			t.Fatalf("mlock is required: %v", err)
		}
		t.Skipf("mlock is not available here: %v", err)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// raw sends line and body on a fresh connection and returns the answer
// line ("" when the agent closed without one).
func (r *rig) raw(t *testing.T, line string, body []byte) string {
	t.Helper()
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(append([]byte(line+"\n"), body...)); err != nil {
		return "" // the agent already closed on us
	}
	ans, err := readLine(c, maxLine)
	if err != nil {
		return ""
	}
	return ans
}

var bg = context.Background()

func TestRoundTrip(t *testing.T) {
	r := newRig(t, nil)
	secret := []byte("correct horse battery staple")

	if ok, err := r.c.Have(bg); err != nil || ok {
		t.Fatalf("Have outside a line: %v, %v", ok, err)
	}
	if _, err := r.c.Get(bg); !errors.Is(err, ErrNotInFlight) {
		t.Fatalf("Get outside a line: %v", err)
	}
	if err := r.c.Store(bg, secret); !errors.Is(err, ErrNotInFlight) {
		t.Fatalf("Store outside a line: %v", err)
	}
	r.a.setInFlight(true)
	if ok, err := r.c.Have(bg); err != nil || ok {
		t.Fatalf("Have with nothing stored: %v, %v", ok, err)
	}
	if _, err := r.c.Get(bg); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Get with nothing stored: %v", err)
	}
	if err := r.c.Store(bg, secret); err != nil {
		t.Fatal(err)
	}
	if ev := r.events(); len(ev) != 1 || ev[0].Kind != EventStored {
		t.Fatalf("events after store: %+v", ev)
	}
	if ok, err := r.c.Have(bg); err != nil || !ok {
		t.Fatalf("Have after store: %v, %v", ok, err)
	}
	got, err := r.c.Get(bg)
	if err != nil || string(got) != string(secret) {
		t.Fatalf("Get: %q, %v", got, err)
	}
	Zero(got)
	if !r.a.Cached() {
		t.Fatal("Cached is false after store")
	}
	if err := r.c.Forget(bg); err != nil {
		t.Fatal(err)
	}
	if ev := r.events(); len(ev) != 1 || ev[0].Kind != EventForgotten || ev[0].Why != WhyRejected {
		t.Fatalf("events after forget: %+v", ev)
	}
	if r.a.Cached() {
		t.Fatal("Cached after forget")
	}
}

func TestInFlightGating(t *testing.T) {
	r := newRig(t, nil)
	if err := r.a.Store([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	r.a.setInFlight(true)
	if ok, _ := r.c.Have(bg); !ok {
		t.Fatal("Have is no while in flight")
	}
	r.a.setInFlight(false)
	if ok, err := r.c.Have(bg); err != nil || ok {
		t.Fatalf("Have after the line ended: %v, %v", ok, err)
	}
	if b, err := r.c.Get(bg); !errors.Is(err, ErrNotInFlight) || b != nil {
		t.Fatalf("Get after the line ended: %q, %v", b, err)
	}
	if err := r.c.Store(bg, []byte("other")); !errors.Is(err, ErrNotInFlight) {
		t.Fatalf("Store after the line ended: %v", err)
	}
	// The password itself is still held for the next line.
	if !r.a.Cached() {
		t.Fatal("password lost between lines")
	}
	r.a.setInFlight(true)
	b, err := r.c.Get(bg)
	if err != nil || string(b) != "pw" {
		t.Fatalf("Get on the next line: %q, %v", b, err)
	}
	Zero(b)
}

// A second get on one line is a retry of a refused password: refused, and
// the password is forgotten.
func TestSecondGetIsARejection(t *testing.T) {
	r := newRig(t, nil)
	_ = r.a.Store([]byte("pw"))
	r.a.setInFlight(true)
	r.events()
	b, err := r.c.Get(bg)
	if err != nil {
		t.Fatal(err)
	}
	Zero(b)
	if _, err := r.c.Get(bg); !errors.Is(err, ErrLimit) {
		t.Fatalf("second Get: %v", err)
	}
	if r.a.Cached() || !allZero(r.a.pg.b) {
		t.Fatal("the password survived a second get on the line")
	}
	if ev := r.events(); len(ev) != 1 || ev[0] != (Event{EventForgotten, WhyRejected}) {
		t.Fatalf("events: %+v", ev)
	}
	if _, err := r.c.Get(bg); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Get after the rejection: %v", err)
	}

	// A new line starts a new count.
	_ = r.a.Store([]byte("pw2"))
	r.a.setInFlight(false)
	r.a.setInFlight(true)
	if b, err := r.c.Get(bg); err != nil || string(b) != "pw2" {
		t.Fatalf("Get on a new line: %q, %v", b, err)
	} else {
		Zero(b)
	}
	// have is not a get.
	_ = r.a.Store([]byte("pw3"))
	r.a.setInFlight(true)
	for i := 0; i < 3; i++ {
		if ok, err := r.c.Have(bg); err != nil || !ok {
			t.Fatalf("Have %d: %v, %v", i, ok, err)
		}
	}
}

func TestMaxGetsOptions(t *testing.T) {
	r := newRig(t, func(o *Options) { o.MaxGets = 2 })
	_ = r.a.Store([]byte("pw"))
	r.a.setInFlight(true)
	for i := 0; i < 2; i++ {
		b, err := r.c.Get(bg)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		Zero(b)
	}
	if _, err := r.c.Get(bg); !errors.Is(err, ErrLimit) || r.a.Cached() {
		t.Fatalf("third get: %v (cached %v)", err, r.a.Cached())
	}

	u := newRig(t, func(o *Options) { o.MaxGets = -1 })
	_ = u.a.Store([]byte("pw"))
	u.a.setInFlight(true)
	for i := 0; i < 20; i++ {
		b, err := u.c.Get(bg)
		if err != nil {
			t.Fatalf("unlimited get %d: %v", i, err)
		}
		Zero(b)
	}
}

// The helper's path: ssh asks again after a refused password.
func TestHelperRetryForgets(t *testing.T) {
	r := newRig(t, nil)
	env := r.a.Env()
	_ = r.a.Store([]byte("stale pw"))
	r.a.setInFlight(true)
	var out bytes.Buffer
	if err := RunHelper(bg, env, "alice@192.0.2.1's password:", &out); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := RunHelper(bg, env, "alice@192.0.2.1's password:", &out); !errors.Is(err, ErrLimit) || out.Len() != 0 {
		t.Fatalf("second helper run: %v, %q", err, out.String())
	}
	if r.a.Cached() {
		t.Fatal("the stale password is still cached")
	}
	if err := RunHelper(bg, env, "alice@192.0.2.1's password:", &out); !errors.Is(err, ErrEmpty) || out.Len() != 0 {
		t.Fatalf("third helper run: %v, %q", err, out.String())
	}
}

// A repeated store of the same bytes must not stretch the maximum
// lifetime; different bytes are a new password with its own.
func TestRepeatedStoreKeepsLifetime(t *testing.T) {
	r := newRig(t, func(o *Options) { o.Idle, o.Max = 30*time.Minute, time.Hour })
	r.a.setInFlight(true)
	if err := r.c.Store(bg, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	r.clock.Advance(25 * time.Minute)
	if err := r.c.Store(bg, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if ev := r.events(); len(ev) != 1 || ev[0].Kind != EventStored {
		t.Fatalf("a repeated store is no new store: %+v", ev)
	}
	// It counted as use: 50 minutes since the first store, 25 since the
	// second, so the idle time has not run out.
	r.clock.Advance(25 * time.Minute)
	if !r.a.Cached() {
		t.Fatal("the repeated store did not restart the idle time")
	}
	if err := r.a.Store([]byte("pw")); err != nil {
		t.Fatal(err)
	}
	// 61 minutes since the first store: the maximum, however often since.
	r.clock.Advance(11 * time.Minute)
	if r.a.Cached() {
		t.Fatal("repeated stores extended the maximum lifetime")
	}
	if ev := r.events(); len(ev) != 1 || ev[0] != (Event{EventForgotten, WhyMax}) {
		t.Fatalf("events: %+v", ev)
	}

	// Different bytes start a new lifetime.
	_ = r.c.Store(bg, []byte("pw-a"))
	r.clock.Advance(50 * time.Minute)
	_ = r.c.Store(bg, []byte("pw-a")) // idle only
	_ = r.c.Store(bg, []byte("pw-b")) // new password
	r.clock.Advance(20 * time.Minute) // 70 min since pw-a, 20 since pw-b
	if !r.a.Cached() {
		t.Fatal("a different password did not get its own lifetime")
	}
	b, err := r.c.Get(bg)
	if err != nil || string(b) != "pw-b" {
		t.Fatalf("Get: %q, %v", b, err)
	}
	Zero(b)
}

func TestTokenRefused(t *testing.T) {
	r := newRig(t, nil)
	_ = r.a.Store([]byte("pw"))
	r.a.setInFlight(true)

	bad := &Client{Path: r.c.Path, Token: strings.Repeat("0", tokenLen), ExpectUID: r.c.ExpectUID}
	if _, err := bad.Get(bg); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong token Get: %v", err)
	}
	if err := bad.Store(bg, []byte("evil")); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong token Store: %v", err)
	}
	if err := bad.Forget(bg); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong token Forget: %v", err)
	}
	// Prefixes, truncations and the verb without a token are no token.
	for _, line := range []string{"get", r.token[:10] + " get", " get", "", r.token[:tokenLen-1] + " get", r.token + "x get"} {
		if ans := r.raw(t, line, nil); ans != "err denied" {
			t.Errorf("%q answered %q", line, ans)
		}
	}
	if got := r.a.Cached(); !got {
		t.Fatal("a refused request changed the cache")
	}
	b, err := r.c.Get(bg)
	if err != nil || string(b) != "pw" {
		t.Fatalf("the right token after refusals: %q, %v", b, err)
	}
	Zero(b)
}

func TestMalformedRequests(t *testing.T) {
	r := newRig(t, nil)
	r.a.setInFlight(true)
	for line, want := range map[string]string{
		r.token + " bogus":                       "err bad-request",
		r.token:                                  "err bad-request",
		r.token + " get extra":                   "err bad-request",
		r.token + " store":                       "err bad-request",
		r.token + " store 0":                     "err bad-secret",
		r.token + " store -1":                    "err bad-secret",
		r.token + " store 1025":                  "err bad-secret",
		r.token + " store 04":                    "err bad-secret",
		r.token + " store x":                     "err bad-secret",
		r.token + "  get":                        "err bad-request",
		r.token + " get\r":                       "err bad-request",
		r.token + " have ":                       "err bad-request",
		r.token + " store 3 4":                   "err bad-request",
		r.token + " GET":                         "err bad-request",
		strings.Repeat("a", 200):                 "",
		r.token + " " + strings.Repeat("g", 200): "",
	} {
		if ans := r.raw(t, line, nil); ans != want {
			t.Errorf("%q: answered %q, want %q", line, ans, want)
		}
	}
	if r.a.Cached() {
		t.Fatal("malformed requests stored something")
	}
}

func TestStoreBodyValidation(t *testing.T) {
	r := newRig(t, func(o *Options) { o.MaxGets = -1 })
	r.a.setInFlight(true)
	if err := r.c.Store(bg, []byte("first")); err != nil {
		t.Fatal(err)
	}
	// A body with a line break, one that is short, and a client that
	// hangs up mid-body each leave the earlier password in place.
	if ans := r.raw(t, r.token+" store 5", []byte("a\nbcd")); ans != "err bad-secret" {
		t.Errorf("line break body: %q", ans)
	}
	if ans := r.raw(t, r.token+" store 5", []byte("a\x00bcd")); ans != "err bad-secret" {
		t.Errorf("NUL body: %q", ans)
	}
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c.Write([]byte(r.token + " store 10\nabc"))
	_ = c.Close()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if allZero(r.a.pg.stage()) { // racy read is fine: only polling for the end
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	b, err := r.c.Get(bg)
	if err != nil || string(b) != "first" {
		t.Fatalf("after rejected stores: %q, %v", b, err)
	}
	Zero(b)
	if err := r.c.Store(bg, []byte("bad\nsecret")); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("client-side check: %v", err)
	}
	if err := r.c.Store(bg, make([]byte, MaxSecret+1)); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("too long: %v", err)
	}
	if err := r.c.Store(bg, nil); !errors.Is(err, ErrBadSecret) {
		t.Fatalf("empty: %v", err)
	}
	long := []byte(strings.Repeat("x", MaxSecret))
	if err := r.c.Store(bg, long); err != nil {
		t.Fatalf("a secret of MaxSecret bytes: %v", err)
	}
	got, err := r.c.Get(bg)
	if err != nil || len(got) != MaxSecret {
		t.Fatalf("Get of MaxSecret bytes: %d, %v", len(got), err)
	}
	Zero(got)
}

func TestPeerUIDRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is always an allowed peer")
	}
	r := newRig(t, func(o *Options) { o.UID = os.Geteuid() + 1 })
	_ = r.a.Store([]byte("pw"))
	r.a.setInFlight(true)
	// This process is neither the agent's user nor root: no answer.
	if ok, err := r.c.Have(bg); ok || !errors.Is(err, ErrDenied) {
		t.Fatalf("Have from the wrong uid: %v, %v", ok, err)
	}
	if b, err := r.c.Get(bg); !errors.Is(err, ErrDenied) || b != nil {
		t.Fatalf("Get from the wrong uid: %q, %v", b, err)
	}
	if ans := r.raw(t, r.token+" get", nil); ans != "" {
		t.Fatalf("raw get from the wrong uid answered %q", ans)
	}
	if !r.a.Cached() {
		t.Fatal("the refused peer changed the cache")
	}
}

func TestClientExpectsOwner(t *testing.T) {
	r := newRig(t, nil)
	r.a.setInFlight(true)
	c := *r.c
	c.ExpectUID = os.Geteuid() + 1
	if _, err := c.Have(bg); !errors.Is(err, ErrPeer) {
		t.Fatalf("socket of another user: %v", err)
	}
	// A path that is not a socket is never connected to.
	f := filepath.Join(shortTemp(t), "plain")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c = *r.c
	c.Path = f
	if _, err := c.Have(bg); !errors.Is(err, ErrPeer) {
		t.Fatalf("regular file: %v", err)
	}
	c.Path = filepath.Join(shortTemp(t), "none.sock")
	if _, err := c.Have(bg); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("missing socket: %v", err)
	}
}

func TestSocketAndDirModes(t *testing.T) {
	r := newRig(t, nil)
	fi, err := os.Stat(r.path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 || fi.Mode()&os.ModeSocket == 0 {
		t.Errorf("socket mode %v", fi.Mode())
	}
	di, err := os.Stat(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("directory mode %v", di.Mode())
	}
	if r.a.Env() != r.path+":"+r.token {
		t.Errorf("Env %q", r.a.Env())
	}
}

func TestListenDirChecks(t *testing.T) {
	base := shortTemp(t)
	// An existing directory with loose permissions is tightened.
	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	a, err := New(Options{noHarden: true, SweepEvery: -1})
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, _, err := a.Listen(loose); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(loose); fi.Mode().Perm() != 0o700 {
		t.Errorf("loose directory left at %v", fi.Mode())
	}
	if _, _, err := a.Listen(loose); err == nil {
		t.Error("a second Listen was accepted")
	}

	// A link to a directory is refused, whoever owns the target.
	b, err := New(Options{noHarden: true, SweepEvery: -1})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	link := filepath.Join(base, "link")
	if err := os.Symlink(loose, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Listen(link); !errors.Is(err, ErrNoDir) {
		t.Errorf("symlinked directory: %v", err)
	}
	if _, _, err := b.Listen("relative/dir"); !errors.Is(err, ErrNoDir) {
		t.Errorf("relative directory: %v", err)
	}
	file := filepath.Join(base, "file")
	_ = os.WriteFile(file, nil, 0o600)
	if _, _, err := b.Listen(file); !errors.Is(err, ErrNoDir) {
		t.Errorf("a file: %v", err)
	}
	long := filepath.Join(base, strings.Repeat("d", 120))
	if _, _, err := b.Listen(long); !errors.Is(err, ErrNoDir) {
		t.Errorf("a path too long for a socket: %v", err)
	}
}

func TestStaleSocketsRemoved(t *testing.T) {
	dir := filepath.Join(shortTemp(t), "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	host := hostTag()
	// A socket file whose listener is gone: connect says ECONNREFUSED.
	dead := func(name string) string {
		p := filepath.Join(dir, name)
		ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: p, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		ln.SetUnlinkOnClose(false)
		_ = ln.Close()
		return p
	}
	// The pid in the name is of no importance: this process's own pid
	// (alive) names a dead socket, and a pid that is not running names
	// nothing special.
	stale1 := dead("ap-" + host + "-" + strconv.Itoa(os.Getpid()) + "-deadbeef.sock")
	stale2 := dead("ap-" + host + "-4194303-deadbeef.sock")
	otherHost := dead("ap-some.other.host-4194303-deadbeef.sock")
	notOurs := dead("other.sock")
	badName := dead("ap-" + host + "-x.sock")

	// A live agent of this host in the same directory.
	live := newRig(t, nil)
	a, err := New(Options{noHarden: true, SweepEvery: -1})
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	liveDir := filepath.Dir(live.path)
	// Move the dead sockets next to the live one.
	moved := map[*string]string{}
	for _, p := range []*string{&stale1, &stale2, &otherHost, &notOurs, &badName} {
		np := filepath.Join(liveDir, filepath.Base(*p))
		if err := os.Rename(*p, np); err != nil {
			t.Fatal(err)
		}
		moved[p] = np
	}
	if _, _, err := a.Listen(liveDir); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{moved[&stale1], moved[&stale2]} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s: the socket of a dead shell was left", filepath.Base(p))
		}
	}
	for _, p := range []string{live.path, moved[&otherHost], moved[&notOurs], moved[&badName]} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed", filepath.Base(p))
		}
	}
	if !strings.HasPrefix(filepath.Base(live.path), "ap-"+host+"-") {
		t.Errorf("socket name %q has no host tag", filepath.Base(live.path))
	}
	// The live agent still answers.
	live.a.setInFlight(true)
	if _, err := live.c.Have(bg); err != nil {
		t.Errorf("the live agent was disturbed: %v", err)
	}
}

func TestIdleExpiry(t *testing.T) {
	r := newRig(t, func(o *Options) { o.Idle, o.Max = 10*time.Minute, time.Hour })
	r.a.setInFlight(true)
	if err := r.c.Store(bg, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	r.events()

	r.clock.Advance(9 * time.Minute)
	b, err := r.c.Get(bg) // resets the idle time
	if err != nil {
		t.Fatalf("get inside the idle time: %v", err)
	}
	Zero(b)
	r.clock.Advance(9 * time.Minute) // 18 min since store, 9 since get
	// (have answers nothing after the line's get; Cached applies expiry.)
	if !r.a.Cached() {
		t.Fatal("the idle time did not restart at the get")
	}
	if ok, err := r.c.Have(bg); ok || err != nil {
		t.Fatalf("Have after the line's get: %v, %v", ok, err)
	}
	r.clock.Advance(time.Minute) // 10 since the get
	if r.a.Cached() {
		t.Fatal("still cached after the idle time")
	}
	if ev := r.events(); len(ev) != 1 || ev[0] != (Event{EventForgotten, WhyIdle}) {
		t.Fatalf("events: %+v", ev)
	}
	if !allZero(r.a.pg.b) {
		t.Fatal("the page was not zeroed on expiry")
	}
	if _, err := r.c.Get(bg); !errors.Is(err, ErrEmpty) {
		t.Fatalf("Get after expiry: %v", err)
	}
}

func TestMaxLifetime(t *testing.T) {
	r := newRig(t, func(o *Options) { o.Idle, o.Max, o.MaxGets = 20*time.Minute, time.Hour, -1 })
	r.a.setInFlight(true)
	_ = r.c.Store(bg, []byte("pw"))
	r.events()
	// A get every 15 minutes keeps it from idling, not from the maximum.
	for i := 0; i < 3; i++ {
		r.clock.Advance(15 * time.Minute)
		b, err := r.c.Get(bg)
		if err != nil {
			t.Fatalf("get %d: %v", i, err)
		}
		Zero(b)
	}
	r.clock.Advance(15 * time.Minute) // 60 minutes since the store
	if _, err := r.c.Get(bg); !errors.Is(err, ErrEmpty) {
		t.Fatalf("get at the maximum: %v", err)
	}
	if ev := r.events(); len(ev) != 1 || ev[0] != (Event{EventForgotten, WhyMax}) {
		t.Fatalf("events: %+v", ev)
	}
	if !allZero(r.a.pg.b) {
		t.Fatal("the page was not zeroed at the maximum")
	}
}

func TestSweepZeroesWithoutRequests(t *testing.T) {
	r := newRig(t, func(o *Options) { o.Idle = 5 * time.Minute })
	_ = r.a.Store([]byte("pw"))
	r.clock.Advance(4 * time.Minute)
	r.a.Sweep()
	if !r.a.Cached() {
		t.Fatal("swept before the idle time")
	}
	r.events()
	r.clock.Advance(time.Minute)
	r.a.Sweep()
	if r.a.pg.secret()[0] != 0 || !allZero(r.a.pg.b) {
		t.Fatal("the secret is still in the page after the sweep")
	}
	if ev := r.events(); len(ev) != 1 || ev[0].Why != WhyIdle {
		t.Fatalf("events: %+v", ev)
	}
}

func TestBackgroundSweep(t *testing.T) {
	r := newRig(t, func(o *Options) { o.Idle, o.SweepEvery = time.Minute, 5*time.Millisecond })
	_ = r.a.Store([]byte("pw"))
	r.clock.Advance(2 * time.Minute)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		ev := r.events()
		if len(ev) == 1 && ev[0].Why == WhyIdle {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the background sweep did not forget the password")
}

func TestZeroisation(t *testing.T) {
	r := newRig(t, nil)
	r.a.setInFlight(true)
	secret := []byte("Zq9-needle-needle-needle")
	if err := r.c.Store(bg, secret); err != nil {
		t.Fatal(err)
	}
	pg := r.a.pg.b
	if !strings.Contains(string(pg), string(secret)) {
		t.Fatal("the secret is not in the locked page")
	}
	if !allZero(r.a.pg.stage()) {
		t.Fatal("the staging slot was not cleared after the store")
	}
	if !r.a.Forget(WhyCommand) {
		t.Fatal("Forget said nothing was cached")
	}
	if !allZero(pg) {
		t.Fatal("the page is not zero after Forget")
	}
	if r.a.Forget(WhyCommand) {
		t.Fatal("a second Forget said it forgot something")
	}
	if ev := r.events(); len(ev) != 2 || ev[1] != (Event{EventForgotten, WhyCommand}) {
		t.Fatalf("events: %+v", ev)
	}

	// A replacement store overwrites the longer secret completely.
	_ = r.a.Store([]byte(strings.Repeat("A", 100)))
	_ = r.c.Store(bg, []byte("short"))
	if i := strings.Index(string(pg), "AAAA"); i >= 0 {
		t.Fatal("bytes of the replaced secret remain in the page")
	}
	// Close zeroes the page before it is unmapped; the mapping is gone
	// afterwards, so the check is that Close forgets and is silent.
	r.events()
	r.a.Close()
	if ev := r.events(); len(ev) != 0 {
		t.Fatalf("Close notified: %+v", ev)
	}
	if r.a.pg.b != nil {
		t.Fatal("the page is still held after Close")
	}
}

func TestSecretNotInErrors(t *testing.T) {
	r := newRig(t, nil)
	secret := "very-secret-value-12345"
	r.a.setInFlight(true)
	bad := &Client{Path: r.c.Path, Token: strings.Repeat("1", tokenLen), ExpectUID: r.c.ExpectUID}
	err := bad.Store(bg, []byte(secret))
	if err == nil || strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), bad.Token) {
		t.Fatalf("error text: %v", err)
	}
	for _, e := range []error{ErrNoAgent, ErrBadEnv, ErrDenied, ErrPeer, ErrNotInFlight, ErrEmpty, ErrLimit, ErrBusy, ErrBadSecret, ErrProtocol, ErrClosed, ErrNoLock, ErrNoDir} {
		if strings.Contains(e.Error(), secret) {
			t.Fatalf("%v", e)
		}
	}
	// Errors for a bad environment value do not repeat it.
	_, perr := NewClient("/nonexistent:" + strings.Repeat("z", 64))
	if perr == nil || strings.Contains(perr.Error(), "zzzz") {
		t.Fatalf("ParseEnv error: %v", perr)
	}
}

func TestCloseIsFinal(t *testing.T) {
	r := newRig(t, nil)
	r.a.setInFlight(true)
	_ = r.c.Store(bg, []byte("pw"))
	r.a.Close()
	r.a.Close()
	if _, err := os.Lstat(r.path); err == nil {
		t.Error("the socket file is left")
	}
	if _, err := r.c.Get(bg); !errors.Is(err, ErrNoAgent) {
		t.Errorf("Get after Close: %v", err)
	}
	if err := r.a.Store([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Errorf("Store after Close: %v", err)
	}
	if r.a.Forget(WhyExit) || r.a.Cached() {
		t.Error("state after Close")
	}
	r.a.Sweep()
	r.a.setInFlight(true)
	if _, _, err := r.a.Listen(r.dir); !errors.Is(err, ErrClosed) {
		t.Errorf("Listen after Close: %v", err)
	}
}

func TestHardenSetsNotDumpable(t *testing.T) {
	prev, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Skip(err)
	}
	t.Cleanup(func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, uintptr(prev), 0, 0, 0) })
	a, err := New(Options{SweepEvery: -1})
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if got, _ := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); got != 0 {
		t.Fatalf("dumpable is %d after New", got)
	}
	// The process can still find its own executable and files (the shell
	// does, to run its lines).
	if _, err := os.Executable(); err != nil {
		t.Fatalf("os.Executable after New: %v", err)
	}
	if _, err := os.Readlink("/proc/self/exe"); err != nil {
		t.Fatalf("/proc/self/exe after New: %v", err)
	}
}

func TestConcurrent(t *testing.T) {
	r := newRig(t, func(o *Options) {
		o.Idle, o.Max, o.SweepEvery, o.MaxGets = 40*time.Millisecond, time.Second, time.Millisecond, -1
		o.Now = nil // the real clock, so the sweeper and the requests race for real
	})
	want := map[string]bool{}
	for i := 0; i < 7; i++ {
		want["pw-"+strconv.Itoa(i)] = true
	}
	var seen atomic.Int64
	var wg sync.WaitGroup
	stop := make(chan struct{})
	run := func(f func(i int)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				f(i)
			}
		}()
	}
	for g := 0; g < 4; g++ {
		run(func(i int) {
			_ = r.c.Store(bg, []byte("pw-"+strconv.Itoa(i%7)))
		})
		run(func(int) {
			if b, err := r.c.Get(bg); err == nil {
				// Whatever it is, it is exactly one of the values stored.
				if !want[string(b)] {
					t.Errorf("a value that was never stored: %q", b)
				}
				seen.Add(1)
				Zero(b)
			}
		})
		run(func(int) { _, _ = r.c.Have(bg) })
	}
	run(func(i int) { _ = r.c.Forget(bg) })
	run(func(i int) { r.a.setInFlight(i%5 != 0) })
	run(func(int) { r.a.Sweep(); _ = r.a.Cached() })
	run(func(i int) { _ = r.a.Store([]byte("pw-" + strconv.Itoa(i%7))) })
	time.Sleep(400 * time.Millisecond)
	close(stop)
	wg.Wait()
	if seen.Load() == 0 {
		t.Error("no get succeeded: the test checked nothing")
	}
	r.a.setInFlight(false)
	r.a.Forget(WhyExit)
	if !allZero(r.a.pg.b) {
		t.Fatal("the page is not zero after the last forget")
	}
}

// TestSequentialStoresNeverBusy: a client that sends its next store the
// moment it has the answer to the last one never finds the staging slot
// busy (the agent releases it before it replies), whether the earlier body
// was good or bad.
func TestSequentialStoresNeverBusy(t *testing.T) {
	r := newRig(t, func(o *Options) { o.MaxGets = -1 })
	r.a.setInFlight(true)
	for i := 0; i < 200; i++ {
		if err := r.c.Store(bg, []byte("pw-"+strconv.Itoa(i%7))); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
		// A bad body (line break) answers bad-secret, then a good one must
		// still be taken.
		if ans := r.raw(t, r.token+" store 3", []byte("a\nb")); ans != "err bad-secret" {
			t.Fatalf("bad body %d: %q", i, ans)
		}
	}
	if !r.a.Cached() {
		t.Fatal("nothing cached after the stores")
	}
}

// rawAll is raw reading the whole answer until the agent closes.
func (r *rig) rawAll(t *testing.T, line string) string {
	t.Helper()
	c, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte(line + "\n")); err != nil {
		return ""
	}
	b, _ := io.ReadAll(c)
	return string(b)
}

// Every answer but a successful get is short and carries no secret byte,
// whatever the request, with the agent in flight and holding a password.
func TestSecretOnlyInAnAuthorisedGet(t *testing.T) {
	r := newRig(t, func(o *Options) { o.MaxGets = -1 })
	const secret = "hunter2-hunter2"
	_ = r.a.Store([]byte(secret))
	r.a.setInFlight(true)
	wrong := strings.Repeat("f", tokenLen)
	for _, line := range []string{
		r.token + " have",
		wrong + " get",
		wrong + " have",
		r.token + " get extra",
		r.token + " store 0",
		r.token + " store 5000",
		r.token + " nonsense",
		r.token,
		"get",
		"",
	} {
		if ans := r.rawAll(t, line); strings.Contains(ans, secret) {
			t.Fatalf("%q answered %q", line, ans)
		}
	}
	// The control: the authorised get does carry it, so the check above
	// can fail.
	if ans := r.rawAll(t, r.token+" get"); ans != "ok 15\n"+secret {
		t.Fatalf("the authorised get answered %q", ans)
	}
}

// A line's token is minted at BeginLine and dead after EndLine: the token of
// the previous line is refused (denied, not merely out of flight), the new
// line's token works, and a client holding the old one cannot ask.
func TestPerLineTokens(t *testing.T) {
	r := newRig(t, nil)
	ctx := bg
	// Nothing is open before the first line: the token Listen made is
	// refused while no line runs.
	if _, err := r.c.Get(ctx); !errors.Is(err, ErrNotInFlight) {
		t.Fatalf("get before any line: %v", err)
	}
	env1 := r.a.BeginLine()
	c1, err := NewClient(env1)
	if err != nil {
		t.Fatal(err)
	}
	if env1 == r.a.path+":"+r.token || !strings.HasPrefix(env1, r.path+":") {
		t.Errorf("the line's value %q is not a new token on the same socket", env1)
	}
	// The token Listen made no longer opens anything.
	if _, err := r.c.Have(ctx); !errors.Is(err, ErrDenied) {
		t.Errorf("the Listen token during a line: %v", err)
	}
	if err := c1.Store(ctx, []byte("pw-1")); err != nil {
		t.Fatal(err)
	}
	if have, err := c1.Have(ctx); err != nil || !have {
		t.Fatalf("have in the line: %v %v", have, err)
	}
	r.a.EndLine()
	// The line is over: its token is refused, whether or not the password
	// is still cached (it is).
	if !r.a.Cached() {
		t.Fatal("EndLine forgot the password")
	}
	for name, f := range map[string]func() error{
		"have":   func() error { _, err := c1.Have(ctx); return err },
		"get":    func() error { _, err := c1.Get(ctx); return err },
		"store":  func() error { return c1.Store(ctx, []byte("pw-x")) },
		"forget": func() error { return c1.Forget(ctx) },
	} {
		if err := f(); !errors.Is(err, ErrDenied) {
			t.Errorf("%s with the ended line's token: %v", name, err)
		}
	}
	if !r.a.Cached() {
		t.Error("a request with a dead token changed the cache")
	}
	// The next line has its own token; the old one stays dead.
	env2 := r.a.BeginLine()
	if env2 == env1 {
		t.Fatal("two lines, one token")
	}
	c2, _ := NewClient(env2)
	if _, err := c1.Get(ctx); !errors.Is(err, ErrDenied) {
		t.Errorf("previous line's token during the next: %v", err)
	}
	b, err := c2.Get(ctx)
	if err != nil || string(b) != "pw-1" {
		t.Fatalf("get in the next line: %q %v", b, err)
	}
	Zero(b)
	// One get per line: the counters start again with each line.
	if _, err := c2.Get(ctx); !errors.Is(err, ErrLimit) {
		t.Errorf("second get on one line: %v", err)
	}
	if r.a.Cached() {
		t.Error("the second get did not forget")
	}
	// The line's get was served: its token still forgets, but stores
	// nothing (a process that read it out of ssh's environment cannot put a
	// password in).
	if err := c2.Store(ctx, []byte("pw-x")); !errors.Is(err, ErrLimit) {
		t.Errorf("store after the line's get: %v", err)
	}
	r.a.EndLine()
	env3 := r.a.BeginLine()
	c3, _ := NewClient(env3)
	if err := c3.Store(ctx, []byte("pw-2")); err != nil {
		t.Fatal(err)
	}
	b, err = c3.Get(ctx)
	if err != nil || string(b) != "pw-2" {
		t.Errorf("get on a new line after a limit: %q %v", b, err)
	}
	Zero(b)
	r.a.EndLine()
	// Not listening or closed: no value.
	r.a.Close()
	if got := r.a.BeginLine(); got != "" {
		t.Errorf("BeginLine on a closed agent: %q", got)
	}
}

// An agent that never listened has no line to open.
func TestBeginLineWithoutListen(t *testing.T) {
	a, err := New(Options{SweepEvery: -1, noHarden: true})
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if got := a.BeginLine(); got != "" {
		t.Errorf("BeginLine without Listen: %q", got)
	}
}

// A request belongs to the line whose token it carried, even when it waits:
// a store's body held back across EndLine and the next BeginLine is refused
// and nothing is stored, and the next line sees nothing.
func TestStoreBodyHeldAcrossLinesIsRefused(t *testing.T) {
	r := newRig(t, nil)
	env1 := r.a.BeginLine()
	_, tok1, err := ParseEnv(env1)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", r.path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write([]byte(tok1 + " store 9\n")); err != nil {
		t.Fatal(err)
	}
	// The agent is now waiting for nine bytes. The line ends, the next
	// begins.
	// (stageMu is held while the body is awaited.)
	deadline := time.Now().Add(3 * time.Second)
	for r.a.stageMu.TryLock() {
		r.a.stageMu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("the agent never started waiting for the body")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.a.EndLine()
	env2 := r.a.BeginLine()
	c2, _ := NewClient(env2)
	if _, err := conn.Write([]byte("late-body")); err != nil {
		t.Fatal(err)
	}
	ans, err := readLine(conn, maxLine)
	if err != nil || ans != "err denied" {
		t.Fatalf("answer to the held body: %q %v", ans, err)
	}
	if r.a.Cached() {
		t.Fatal("a store of the previous line landed in the next")
	}
	if _, err := c2.Get(bg); !errors.Is(err, ErrEmpty) {
		t.Errorf("the next line got %v, want nothing cached", err)
	}
	if !allZero(r.a.pg.stage()) {
		t.Error("the staged body was not zeroed")
	}
}

// A request whose token matched for one line and that is acted on after the
// line ended and another began is refused: get, have, store and forget alike.
func TestRequestAcrossLinesIsRefused(t *testing.T) {
	for _, verb := range []string{"get", "have", "forget", "store"} {
		r := newRig(t, func(o *Options) { o.MaxGets = -1 })
		env1 := r.a.BeginLine()
		c1, _ := NewClient(env1)
		if err := c1.Store(bg, []byte("pw-line-1")); err != nil {
			t.Fatal(err)
		}
		var env2 string
		fired := false
		hook := func() {
			if fired {
				return
			}
			fired = true
			r.a.EndLine()
			env2 = r.a.BeginLine()
		}
		afterTokenCheck.Store(&hook)
		var err error
		switch verb {
		case "get":
			_, err = c1.Get(bg)
		case "have":
			_, err = c1.Have(bg)
		case "forget":
			err = c1.Forget(bg)
		case "store":
			err = c1.Store(bg, []byte("pw-stale"))
		}
		afterTokenCheck.Store(nil)
		if !errors.Is(err, ErrDenied) {
			t.Errorf("%s across lines: %v", verb, err)
		}
		if env2 == "" {
			t.Fatalf("%s: the hook did not run", verb)
		}
		// The password of line 1 is still there, untouched by the stale
		// request (a forget would have emptied it, a store replaced it).
		c2, _ := NewClient(env2)
		b, err := c2.Get(bg)
		if err != nil || string(b) != "pw-line-1" {
			t.Errorf("%s: the next line got %q %v", verb, b, err)
		}
		Zero(b)
	}
}
