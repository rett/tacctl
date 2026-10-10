package askpass

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// fakeServer is a socket of this user whose connections are handed to fn.
func fakeServer(t *testing.T, fn func(net.Conn)) string {
	t.Helper()
	p := filepath.Join(shortTemp(t), "fake.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				fn(c)
			}()
		}
	}()
	return p
}

func fakeClient(path string) *Client {
	return &Client{Path: path, Token: strings.Repeat("a", tokenLen), ExpectUID: os.Geteuid(), Timeout: 2 * time.Second}
}

// L7: the body of a get is a secret as the agent would have stored it.
func TestClientRejectsBadBody(t *testing.T) {
	for name, body := range map[string]string{
		"line break": "ok 3\nab\n",
		"CR":         "ok 3\nab\r",
		"NUL":        "ok 3\nab\x00",
	} {
		t.Run(name, func(t *testing.T) {
			p := fakeServer(t, func(c net.Conn) {
				_, _ = readLine(c, maxLine)
				_, _ = c.Write([]byte(body))
			})
			if b, err := fakeClient(p).Get(bg); !errors.Is(err, ErrProtocol) || b != nil {
				t.Fatalf("Get = %q, %v", b, err)
			}
		})
	}
	p := fakeServer(t, func(c net.Conn) {
		_, _ = readLine(c, maxLine)
		_, _ = c.Write([]byte("ok 3\nabc"))
	})
	if b, err := fakeClient(p).Get(bg); err != nil || string(b) != "abc" {
		t.Fatalf("a good body: %q, %v", b, err)
	}
}

// The client's second check: a socket that passes the owner test but is
// served by another uid gets nothing written, not even the token.
func TestClientPeerUIDBranch(t *testing.T) {
	var got atomic.Int64
	p := fakeServer(t, func(c net.Conn) {
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		b := make([]byte, 256)
		n, _ := c.Read(b)
		got.Add(int64(n))
	})
	save := peerOf
	t.Cleanup(func() { peerOf = save })
	peerOf = func(*net.UnixConn) (int, error) { return os.Geteuid() + 1, nil }

	c := fakeClient(p)
	for name, call := range map[string]func() error{
		"have":   func() error { _, err := c.Have(bg); return err },
		"get":    func() error { _, err := c.Get(bg); return err },
		"store":  func() error { return c.Store(bg, []byte("pw")) },
		"forget": func() error { return c.Forget(bg) },
	} {
		if err := call(); !errors.Is(err, ErrPeer) {
			t.Errorf("%s: %v", name, err)
		}
	}
	time.Sleep(450 * time.Millisecond)
	if n := got.Load(); n != 0 {
		t.Fatalf("%d bytes were sent to a server of the wrong user", n)
	}
	// An unreadable credential is the same refusal.
	peerOf = func(*net.UnixConn) (int, error) { return -1, syscall.EINVAL }
	if err := c.Forget(bg); !errors.Is(err, ErrPeer) {
		t.Fatalf("peer credentials unavailable: %v", err)
	}
}

// L2: the socket is opened once and what was opened is what is checked.
func TestClientSocketPathChecks(t *testing.T) {
	r := newRig(t, nil)
	r.a.setInFlight(true)
	_ = r.a.Store([]byte("pw"))
	base := shortTemp(t)

	// A link as the last component is refused, even to our own socket.
	link := filepath.Join(base, "link.sock")
	if err := os.Symlink(r.path, link); err != nil {
		t.Fatal(err)
	}
	c := *r.c
	c.Path = link
	if _, err := c.Have(bg); !errors.Is(err, ErrPeer) {
		t.Fatalf("symlinked socket: %v", err)
	}
	// A link in a directory component is followed, and what it leads to
	// is checked like any path: ours, a socket.
	dirLink := filepath.Join(base, "dir")
	if err := os.Symlink(r.dir, dirLink); err != nil {
		t.Fatal(err)
	}
	c.Path = filepath.Join(dirLink, filepath.Base(r.path))
	if ok, err := c.Have(bg); err != nil || !ok {
		t.Fatalf("socket through a directory link: %v, %v", ok, err)
	}
	// A directory, a regular file and a missing path are never connected.
	for _, p := range []string{r.dir, filepath.Join(base, "none.sock")} {
		c.Path = p
		if _, err := c.Have(bg); err == nil {
			t.Errorf("%s was accepted", p)
		}
	}
	// The expected owner is the owner of the opened file.
	c = *r.c
	c.ExpectUID = os.Geteuid() + 1
	if _, err := c.Have(bg); !errors.Is(err, ErrPeer) {
		t.Fatalf("other owner: %v", err)
	}
}

// L3: the socket directory's parent and the directory itself.
func TestListenParentChecks(t *testing.T) {
	newAgent := func(t *testing.T) *Agent {
		a, err := New(Options{noHarden: true, SweepEvery: -1})
		skipNoLock(t, err)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(a.Close)
		return a
	}
	base := shortTemp(t)
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(base, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}

	open := mk("open", 0o777)
	if _, _, err := newAgent(t).Listen(filepath.Join(open, "tacctl")); !errors.Is(err, ErrNoDir) {
		t.Errorf("parent writable by everyone: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(open, "tacctl")); err == nil {
		t.Error("a directory was created in the unsafe parent")
	}
	grp := mk("grp", 0o770)
	if _, _, err := newAgent(t).Listen(filepath.Join(grp, "tacctl")); !errors.Is(err, ErrNoDir) {
		t.Errorf("parent writable by the group: %v", err)
	}
	sticky := mk("sticky", 0o777|os.ModeSticky)
	if _, _, err := newAgent(t).Listen(filepath.Join(sticky, "tacctl")); err != nil {
		t.Errorf("a sticky parent (like /tmp): %v", err)
	}
	ok := mk("ok", 0o755)
	if _, _, err := newAgent(t).Listen(filepath.Join(ok, "tacctl")); err != nil {
		t.Errorf("an ordinary parent: %v", err)
	}

	// A link in the parent chain is resolved, and the path handed out is
	// the resolved one.
	linkDir := filepath.Join(base, "viaLink")
	if err := os.Symlink(ok, linkDir); err != nil {
		t.Fatal(err)
	}
	a := newAgent(t)
	p, _, err := a.Listen(filepath.Join(linkDir, "sub"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(p, "viaLink") {
		t.Errorf("socket path %q still goes through the link", p)
	}

	// Created parents are 0700.
	deep := filepath.Join(ok, "a", "b", "c")
	if _, _, err := newAgent(t).Listen(deep); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(ok, "a"), filepath.Join(ok, "a", "b"), deep} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v, %v", d, fi, err)
		}
	}
}

// L5: the lifetimes are wall-clock time.
func TestClockSemantics(t *testing.T) {
	now := wallClock()
	if now.Round(0) != now || strings.Contains(now.String(), "m=") {
		t.Fatalf("the default clock carries a monotonic reading: %v", now)
	}

	r := newRig(t, func(o *Options) { o.Idle, o.Max = 10*time.Minute, time.Hour })
	r.a.setInFlight(true)
	_ = r.c.Store(bg, []byte("pw"))
	r.events()
	// A suspend: the wall clock jumps, nothing else happens.
	r.clock.Advance(3 * time.Hour)
	if ok, _ := r.c.Have(bg); ok {
		t.Fatal("a password outlived a clock jump past both lifetimes")
	}
	if ev := r.events(); len(ev) != 1 || ev[0].Why != WhyIdle {
		t.Fatalf("events: %+v", ev)
	}

	// The clock set back: a step within the slack is nothing, a larger one
	// ends the lifetime (the elapsed time is unknown).
	_ = r.c.Store(bg, []byte("pw"))
	r.events()
	r.clock.Advance(-30 * time.Second)
	if !r.a.Cached() {
		t.Fatal("a small step back forgot the password")
	}
	r.clock.Advance(-2 * time.Minute)
	if r.a.Cached() {
		t.Fatal("a clock set back kept the password")
	}
	if ev := r.events(); len(ev) != 1 || ev[0].Why != WhyClock {
		t.Fatalf("events: %+v", ev)
	}
}

// L8: events come in the order the changes happened.
func TestNotifyOrder(t *testing.T) {
	var mu sync.Mutex
	var seq []Event
	r := newRig(t, func(o *Options) {
		o.Notify = func(e Event) {
			mu.Lock()
			seq = append(seq, e)
			mu.Unlock()
			if len(seq)%7 == 0 {
				time.Sleep(time.Millisecond) // a slow callback
			}
		}
	})
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 150; i++ {
				_ = r.a.Store([]byte("pw-" + strconv.Itoa(g) + "-" + strconv.Itoa(i)))
				r.a.Forget(WhyCommand)
			}
		}()
	}
	wg.Wait()
	r.a.Flush()
	mu.Lock()
	defer mu.Unlock()
	if len(seq) < 100 {
		t.Fatalf("only %d events", len(seq))
	}
	// A forget is reported only for a held password, so the first event
	// is a store and a forget is never followed by another forget.
	if seq[0].Kind != EventStored {
		t.Fatalf("the first event is %+v", seq[0])
	}
	for i := 1; i < len(seq); i++ {
		if seq[i].Kind == EventForgotten && seq[i-1].Kind == EventForgotten {
			t.Fatalf("two forgets in a row at %d: delivery is out of order", i)
		}
	}
	if last := seq[len(seq)-1]; last.Kind != EventForgotten && r.a.Cached() == false {
		t.Fatalf("the last event %+v does not match the state", last)
	}
}

// Close does not wait for, or deliver, queued events, and Flush after
// Close returns.
func TestNotifyAfterClose(t *testing.T) {
	r := newRig(t, nil)
	_ = r.a.Store([]byte("pw"))
	r.a.Close()
	r.a.Flush()
	if ev := r.rec.take(); len(ev) > 1 {
		t.Fatalf("events after close: %+v", ev)
	}
}

// failingListener fails every accept and records when it was asked.
type failingListener struct {
	mu    sync.Mutex
	times []time.Time
}

func (f *failingListener) AcceptUnix() (*net.UnixConn, error) {
	f.mu.Lock()
	f.times = append(f.times, time.Now())
	f.mu.Unlock()
	return nil, &net.OpError{Op: "accept", Err: syscall.EMFILE}
}

func (f *failingListener) calls() []time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]time.Time(nil), f.times...)
}

// L9: a persistent accept error backs off. Each sleep lasts at least its
// backoff step (a timer never fires early), so the gaps between attempts are
// at least 5, 10, 20, 40 and 80 ms whatever the machine's load: a busy loop
// could not have them. The test waits for the attempts with a deadline, not a
// fixed time.
func TestAcceptBacksOff(t *testing.T) {
	a, err := New(Options{noHarden: true, SweepEvery: -1})
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	fl := &failingListener{}
	a.wg.Add(1)
	go a.accept(fl)
	const attempts = 6
	deadline := time.Now().Add(10 * time.Second)
	for len(fl.calls()) < attempts {
		if time.Now().After(deadline) {
			t.Fatalf("only %d accept attempts in 10 s", len(fl.calls()))
		}
		time.Sleep(5 * time.Millisecond)
	}
	ts := fl.calls()
	step := acceptBackoffMin
	for i := 1; i < attempts; i++ {
		if gap := ts[i].Sub(ts[i-1]); gap < step {
			t.Errorf("attempt %d came %v after the one before; the backoff step is %v", i+1, gap, step)
		}
		step *= 2
	}
	a.Close() // must stop the loop in its sleep
	after := len(fl.calls())
	// The longest sleep in flight is acceptBackoffMax: wait that out and a
	// little more, with a deadline, and see that no attempt came.
	time.Sleep(acceptBackoffMax + 100*time.Millisecond)
	if len(fl.calls()) != after {
		t.Fatal("the accept loop kept running after Close")
	}
}

func TestNextBackoff(t *testing.T) {
	d := time.Duration(0)
	prev := d
	for i := 0; i < 20; i++ {
		d = nextBackoff(d)
		if d < prev || d > acceptBackoffMax {
			t.Fatalf("step %d: %v after %v", i, d, prev)
		}
		prev = d
	}
	if d != acceptBackoffMax {
		t.Fatalf("settles at %v", d)
	}
}

// I2: a tracer is refused.
func TestTracedProcessRefused(t *testing.T) {
	save, saveHarden := procStatus, hardenProcess
	t.Cleanup(func() { procStatus, hardenProcess = save, saveHarden })
	hardenProcess = func() error { return nil }
	procStatus = func() ([]byte, error) {
		return []byte("Name:\tx\nTracerPid:\t4242\nUid:\t1\n"), nil
	}
	if a, err := New(Options{SweepEvery: -1}); !errors.Is(err, ErrTraced) || a != nil {
		t.Fatalf("New under a tracer: %v", err)
	}
	for _, c := range []struct {
		text string
		pid  int
	}{
		{"Name:\tx\nTracerPid:\t0\n", 0},
		{"Name:\tx\nTracerPid:\t4242\n", 4242},
		{"no such line\n", 0},
	} {
		if got := tracerPid([]byte(c.text)); got != c.pid {
			t.Errorf("tracerPid(%q) = %d, want %d", c.text, got, c.pid)
		}
	}
}

// The process is marked not dumpable before the tracer check and before the
// page is allocated: a tracer that attaches later cannot read the page, and
// one that is attached already is refused with the process already marked.
func TestHardenBeforeTracerCheckAndPage(t *testing.T) {
	save, saveHarden := procStatus, hardenProcess
	t.Cleanup(func() { procStatus, hardenProcess = save, saveHarden })
	var order []string
	hardenProcess = func() error { order = append(order, "harden"); return nil }
	procStatus = func() ([]byte, error) {
		order = append(order, "status")
		return []byte("Name:\tx\nTracerPid:\t0\n"), nil
	}
	a, err := New(Options{SweepEvery: -1})
	skipNoLock(t, err)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if got := strings.Join(order, ","); got != "harden,status" {
		t.Errorf("order %q, want harden then the tracer check", got)
	}
	// Traced: refused, with the process hardened first and no page left.
	order = nil
	procStatus = func() ([]byte, error) {
		order = append(order, "status")
		return []byte("Name:\tx\nTracerPid:\t77\n"), nil
	}
	if a, err := New(Options{SweepEvery: -1}); !errors.Is(err, ErrTraced) || a != nil {
		t.Fatalf("traced: %v", err)
	}
	if got := strings.Join(order, ","); got != "harden,status" {
		t.Errorf("traced order %q", got)
	}
	// A process that cannot be marked is no agent.
	hardenProcess = func() error { return syscall.EPERM }
	if a, err := New(Options{SweepEvery: -1}); err == nil || a != nil || !strings.Contains(err.Error(), "not dumpable") {
		t.Errorf("harden failure: %v", err)
	}
}
