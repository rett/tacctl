package askpass

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Options configure an Agent. The zero value is the defaults.
type Options struct {
	// UID is the user the agent serves: a peer must have this uid or 0
	// (default: the effective uid of the process).
	UID int
	// Idle is how long a stored password lives without a get (default
	// DefaultIdle); Max is its lifetime from the store (DefaultMax). The
	// policy's bounds (1-120 minutes, 1-24 hours) are the caller's.
	Idle, Max time.Duration
	// MaxGets is how many gets are answered per in-flight mark
	// (BeginLine starts a new count): 0 is one, a negative number
	// is no limit. Another get within the mark is taken for a retry of a
	// password a device refused (ssh asks up to three times per method):
	// it is refused and the password is forgotten (WhyRejected), so a
	// stale password cannot lock the account out.
	MaxGets int
	// Now is the clock (default: the wall clock without the monotonic
	// reading, which does not run while the machine is suspended).
	Now func() time.Time
	// Notify, when set, is told when a password is stored and when it is
	// forgotten, except by Close. Events are delivered in the order they
	// happened, one at a time, by a goroutine of the agent, with no lock
	// held: the callback may call the agent, but it must not block for
	// long, it must serialise its own terminal writes, and it must not
	// take a lock the caller of Close holds (Close waits for a callback
	// that is running). Events not yet delivered when Close runs are
	// dropped; Flush waits for them.
	Notify func(Event)
	// SweepEvery is how often the agent looks for an expired password on
	// its own (default one second; negative: never, a test drives Sweep).
	// Every request and every state query checks expiry as well.
	SweepEvery time.Duration

	// noHarden skips PR_SET_DUMPABLE and the tracer check (tests).
	noHarden bool
}

// EventKind is what happened to the cached password.
type EventKind int

// The events.
const (
	EventStored EventKind = iota + 1
	EventForgotten
)

// Event is a change of the cache. Why is set for EventForgotten (one of
// the Why* constants).
type Event struct {
	Kind EventKind
	Why  string
}

// clockSlack is how far back the clock may step before the agent stops
// trusting the lifetimes (NTP steps are small; a clock set back to stretch
// them is not).
const clockSlack = time.Minute

// wallClock is time.Now without the monotonic reading: the lifetimes are
// wall-clock time, and the monotonic clock stops during a suspend.
func wallClock() time.Time { return time.Now().Round(0) }

// procStatus reads /proc/self/status (a test replaces it).
var procStatus = func() ([]byte, error) { return os.ReadFile("/proc/self/status") }

// tracerPid is the TracerPid of a /proc/<pid>/status text, 0 when there is
// none or the text has no such line.
func tracerPid(status []byte) int {
	for _, l := range strings.Split(string(status), "\n") {
		if v, ok := strings.CutPrefix(l, "TracerPid:"); ok {
			n, _ := strconv.Atoi(strings.TrimSpace(v))
			return n
		}
	}
	return 0
}

// queued is a pending event, or a barrier (done) Flush waits on.
type queued struct {
	ev   Event
	done chan struct{}
}

// Agent is the password cache of one shell session.
type Agent struct {
	uid      int
	idle     time.Duration
	max      time.Duration
	getLimit int // gets per in-flight mark; 0: no limit
	now      func() time.Time
	notify   func(Event)
	sweep    time.Duration
	pg       *page
	stageMu  sync.Mutex // one store body is received at a time
	quit     chan struct{}
	wake     chan struct{} // new events are queued
	sem      chan struct{} // bounds concurrent connections
	wg       sync.WaitGroup
	listenMu sync.Mutex   // Listen and Close
	reqs     atomic.Int64 // requests that passed the peer check (tests)

	mu       sync.Mutex // everything below
	closed   bool
	has      bool
	n        int
	stored   time.Time
	lastGet  time.Time
	inFlight bool
	gets     int
	spent    bool   // the line's get was served: only forget still answers
	gen      uint64 // bumped by BeginLine and EndLine: a request belongs to one line
	q        []queued
	ln       *net.UnixListener
	path     string
	token    string
	conns    map[*net.UnixConn]struct{}
}

// New allocates the locked page, marks the process not dumpable and
// returns an agent that does not listen yet. It fails with ErrNoLock when
// the page cannot be locked and with ErrTraced when a debugger or tracer
// is attached (it could read the page).
func New(o Options) (*Agent, error) {
	a := &Agent{
		uid: o.UID, idle: o.Idle, max: o.Max,
		now: o.Now, notify: o.Notify, sweep: o.SweepEvery,
		quit:  make(chan struct{}),
		wake:  make(chan struct{}, 1),
		sem:   make(chan struct{}, 8),
		conns: map[*net.UnixConn]struct{}{},
	}
	switch {
	case o.MaxGets == 0:
		a.getLimit = 1
	case o.MaxGets > 0:
		a.getLimit = o.MaxGets
	}
	if a.uid <= 0 {
		a.uid = os.Geteuid()
	}
	if a.idle <= 0 {
		a.idle = DefaultIdle
	}
	if a.max <= 0 {
		a.max = DefaultMax
	}
	if a.now == nil {
		a.now = wallClock
	}
	if a.sweep == 0 {
		a.sweep = time.Second
	}
	pg, err := a.arm(o.noHarden)
	if err != nil {
		return nil, err
	}
	a.pg = pg
	if a.notify != nil {
		a.wg.Add(1)
		go a.deliver()
	}
	return a, nil
}

// hardenProcess marks the process not dumpable (tests replace it).
var hardenProcess = harden

// arm hardens the process and allocates the page, in that order: the
// process is marked not dumpable before anything else (before the tracer
// check, so a debugger that attaches afterwards cannot read what comes),
// then a tracer already attached refuses the agent, then the page is
// allocated and locked.
func (a *Agent) arm(noHarden bool) (*page, error) {
	if !noHarden {
		if err := hardenProcess(); err != nil {
			return nil, fmt.Errorf("cannot mark the process not dumpable: %w", err)
		}
		// Unreadable status: nothing to go on, carry on.
		if st, err := procStatus(); err == nil && tracerPid(st) != 0 {
			return nil, ErrTraced
		}
	}
	return newPage()
}

// Listen creates the socket in dir (a private directory: SocketDir),
// starts answering and returns the socket's path and the session token.
// dir is created 0700 when it is missing and tightened to 0700 when it is
// the user's; one that is a link, is another user's, or lies in a parent
// that others can write to (without the sticky bit) is refused. Sockets
// left by shells of this host that died are removed.
func (a *Agent) Listen(dir string) (path, token string, err error) {
	a.listenMu.Lock()
	defer a.listenMu.Unlock()
	a.mu.Lock()
	closed, listening := a.closed, a.ln != nil
	a.mu.Unlock()
	switch {
	case closed:
		return "", "", ErrClosed
	case listening:
		return "", "", errors.New("the password cache is already listening")
	}
	dfd, real, err := openPrivateDir(dir)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = unix.Close(dfd) }()
	host := hostTag()
	removeStale(real, host)
	var rnd [4]byte
	var tok [tokenLen / 2]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(tok[:]); err != nil {
		return "", "", err
	}
	name := fmt.Sprintf("ap-%s-%d-%s.sock", host, os.Getpid(), hex.EncodeToString(rnd[:]))
	path = filepath.Join(real, name)
	if len(path) > sunPathMax {
		return "", "", fmt.Errorf("%w: %s is too long for a socket", ErrNoDir, dir)
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return "", "", err
	}
	// The directory is 0700, so the window before this is closed to others.
	if err := unix.Fchmodat(dfd, name, 0o600, 0); err != nil {
		_ = ln.Close()
		return "", "", err
	}
	token = hex.EncodeToString(tok[:])
	a.mu.Lock()
	a.ln, a.path, a.token = ln, path, token
	a.mu.Unlock()
	a.wg.Add(1)
	go a.accept(ln)
	if a.sweep > 0 {
		a.wg.Add(1)
		go a.sweeper()
	}
	return path, token, nil
}

// Env is the value of EnvVar for the commands the shell runs, or "" when
// the agent is not listening.
func (a *Agent) Env() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ln == nil {
		return ""
	}
	return a.path + ":" + a.token
}

// BeginLine opens the agent for one command line that uses the cache and
// returns the value of EnvVar for that line: the socket path and a token
// minted now. The token is the only one the agent accepts, it is valid until
// EndLine, and it answers have, get and store (one get, Options.MaxGets) only
// while the line runs. It returns "" when the agent is not listening, is
// closed, or cannot make a token.
func (a *Agent) BeginLine() string {
	var tok [tokenLen / 2]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.ln == nil {
		return ""
	}
	a.token = hex.EncodeToString(tok[:])
	a.inFlight, a.gets, a.spent = true, 0, false
	a.gen++
	return a.path + ":" + a.token
}

// EndLine closes the agent: the line's token stops working at once and
// nothing is answered until the next BeginLine. A shell calls it after
// Listen too, so the token Listen made (which a session never hands out) is
// not valid either.
func (a *Agent) EndLine() {
	a.mu.Lock()
	a.token, a.inFlight, a.gets, a.spent = "", false, 0, false
	a.gen++
	a.mu.Unlock()
}

// setInFlight marks whether a command is running without changing the
// token (the agent's own tests drive the protocol with the token Listen
// returned; production goes through BeginLine and EndLine).
func (a *Agent) setInFlight(on bool) {
	a.mu.Lock()
	a.inFlight, a.gets, a.spent = on, 0, false
	a.mu.Unlock()
}

// Cached reports whether a password is held (expiry applied).
func (a *Agent) Cached() bool {
	a.mu.Lock()
	a.expireLocked()
	has := a.has
	a.mu.Unlock()
	return has
}

// Store caches a copy of secret (in-process; the socket's store is the
// same), replacing any earlier one. The caller zeroes its own copy.
//
// Storing the bytes that are already held only counts as use (it
// restarts the idle time): the maximum lifetime runs from the first store
// of those bytes and a repeated store cannot stretch it. Different bytes
// start a new lifetime, so a caller must store only a password it was
// given by the person (prompted for), never one it fetched with Get.
func (a *Agent) Store(secret []byte) error {
	if !validSecret(secret) {
		return ErrBadSecret
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return ErrClosed
	}
	a.replaceLocked(secret)
	return nil
}

// replaceLocked makes secret the cached password. The same bytes as the
// held ones restart the idle time only; others zero the slot first, so no
// byte of a longer earlier secret survives, and restart both lifetimes.
func (a *Agent) replaceLocked(secret []byte) {
	slot := a.pg.secret()
	now := a.now()
	if a.has && subtle.ConstantTimeCompare(slot[:a.n], secret) == 1 {
		a.lastGet = now
		return
	}
	Zero(slot)
	copy(slot, secret)
	a.has, a.n, a.stored, a.lastGet = true, len(secret), now, now
	a.enqueueLocked(Event{Kind: EventStored})
}

// Forget zeroes the cached password; why is one of the Why* constants. It
// reports whether there was one.
func (a *Agent) Forget(why string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.forgetLocked(why)
}

// Sweep forgets the password when it has expired. The agent calls it
// itself every Options.SweepEvery.
func (a *Agent) Sweep() {
	a.mu.Lock()
	a.expireLocked()
	a.mu.Unlock()
}

// Flush returns when the events queued so far have been delivered to
// Options.Notify (or the agent was closed).
func (a *Agent) Flush() {
	if a.notify == nil {
		return
	}
	done := make(chan struct{})
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.q = append(a.q, queued{done: done})
	a.mu.Unlock()
	select {
	case a.wake <- struct{}{}:
	default:
	}
	select {
	case <-done:
	case <-a.quit:
	}
}

// Close stops listening, drops the connections, zeroes and releases the
// page and removes the socket. It is silent (no Notify; Forget(WhyExit)
// and Flush first to say so) and idempotent. It waits for a Notify
// callback that is running.
func (a *Agent) Close() {
	a.listenMu.Lock()
	defer a.listenMu.Unlock()
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return
	}
	a.closed = true
	close(a.quit)
	ln := a.ln
	for c := range a.conns {
		_ = c.Close()
	}
	a.mu.Unlock()
	if ln != nil {
		_ = ln.Close() // unlinks the socket
	}
	a.wg.Wait()
	a.mu.Lock()
	a.has, a.n, a.q = false, 0, nil
	a.pg.release()
	a.mu.Unlock()
}

// enqueueLocked queues an event for delivery, in order, with the state
// change that caused it (the lock is held).
func (a *Agent) enqueueLocked(ev Event) {
	if a.notify == nil {
		return
	}
	a.q = append(a.q, queued{ev: ev})
	select {
	case a.wake <- struct{}{}:
	default:
	}
}

// deliver is the one goroutine that calls Notify.
func (a *Agent) deliver() {
	defer a.wg.Done()
	for {
		select {
		case <-a.quit:
			return
		case <-a.wake:
		}
		for {
			a.mu.Lock()
			if a.closed || len(a.q) == 0 {
				a.mu.Unlock()
				break
			}
			it := a.q[0]
			a.q = a.q[1:]
			a.mu.Unlock()
			if it.done != nil {
				close(it.done)
				continue
			}
			a.notify(it.ev)
		}
	}
}

// forgetLocked zeroes the secret slot and queues the event; it reports
// whether a password was held.
func (a *Agent) forgetLocked(why string) bool {
	if a.pg.b == nil { // closed
		return false
	}
	Zero(a.pg.secret())
	was := a.has
	a.has, a.n = false, 0
	if was {
		a.enqueueLocked(Event{Kind: EventForgotten, Why: why})
	}
	return was
}

// expireLocked applies the idle and maximum lifetimes. A clock that went
// back by more than clockSlack since the store or the last get ends the
// lifetime too: the elapsed time can no longer be known.
func (a *Agent) expireLocked() {
	if !a.has || a.closed {
		return
	}
	now := a.now()
	idleAt, maxAt := a.lastGet.Add(a.idle), a.stored.Add(a.max)
	switch {
	case now.Before(a.stored.Add(-clockSlack)) || now.Before(a.lastGet.Add(-clockSlack)):
		a.forgetLocked(WhyClock)
	case !now.Before(maxAt) && !maxAt.After(idleAt):
		a.forgetLocked(WhyMax)
	case !now.Before(idleAt):
		a.forgetLocked(WhyIdle)
	case !now.Before(maxAt):
		a.forgetLocked(WhyMax)
	}
}

func (a *Agent) sweeper() {
	defer a.wg.Done()
	t := time.NewTicker(a.sweep)
	defer t.Stop()
	for {
		select {
		case <-a.quit:
			return
		case <-t.C:
			a.Sweep()
		}
	}
}

// acceptor is what accept needs of a listener.
type acceptor interface {
	AcceptUnix() (*net.UnixConn, error)
}

// Accept errors back off from acceptBackoffMin, doubling, to
// acceptBackoffMax (a descriptor shortage must not become a busy loop).
const (
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

func nextBackoff(d time.Duration) time.Duration {
	switch {
	case d < acceptBackoffMin:
		return acceptBackoffMin
	case d*2 > acceptBackoffMax:
		return acceptBackoffMax
	}
	return d * 2
}

func (a *Agent) accept(ln acceptor) {
	defer a.wg.Done()
	var delay time.Duration
	for {
		c, err := ln.AcceptUnix()
		if err != nil {
			select {
			case <-a.quit:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			delay = nextBackoff(delay)
			t := time.NewTimer(delay)
			select {
			case <-a.quit:
				t.Stop()
				return
			case <-t.C:
			}
			continue
		}
		delay = 0
		select {
		case a.sem <- struct{}{}:
		default:
			_ = c.Close()
			continue
		}
		a.mu.Lock()
		if a.closed {
			a.mu.Unlock()
			<-a.sem
			_ = c.Close()
			return
		}
		a.conns[c] = struct{}{}
		a.wg.Add(1)
		a.mu.Unlock()
		go func() {
			defer a.wg.Done()
			defer func() {
				a.mu.Lock()
				delete(a.conns, c)
				a.mu.Unlock()
				<-a.sem
				_ = c.Close()
			}()
			a.handle(c)
		}()
	}
}

// reply writes one answer line.
func reply(c net.Conn, s string) { _, _ = c.Write([]byte(s + "\n")) }

// handle serves one connection: one request.
func (a *Agent) handle(c *net.UnixConn) {
	_ = c.SetDeadline(time.Now().Add(ioTimeout)) // real time: the clock is the lifetimes'
	if uid, err := peerUID(c); err != nil || (uid != a.uid && uid != 0) {
		return // no answer to the wrong user
	}
	a.reqs.Add(1)
	line, err := readLine(c, maxLine)
	if err != nil {
		return
	}
	f := strings.Split(line, " ")
	a.mu.Lock()
	tok, gen := a.token, a.gen
	a.mu.Unlock()
	if tok == "" || subtle.ConstantTimeCompare([]byte(f[0]), []byte(tok)) != 1 {
		reply(c, ansErr+" "+codeDenied)
		return
	}
	// The token matched for line number gen. Whatever this request goes on
	// to do (and a store waits for its body) it does only while that line
	// is still the current one: the handlers compare the generation again
	// under the lock.
	if f := afterTokenCheck.Load(); f != nil {
		(*f)()
	}
	switch {
	case len(f) == 2 && f[1] == verbHave:
		a.handleHave(c, gen)
	case len(f) == 2 && f[1] == verbGet:
		a.handleGet(c, gen)
	case len(f) == 3 && f[1] == verbStore:
		n, err := strconv.Atoi(f[2])
		if err != nil || n < 1 || n > MaxSecret || strconv.Itoa(n) != f[2] {
			reply(c, ansErr+" "+codeBadSecret)
			return
		}
		a.handleStore(c, n, gen)
	case len(f) == 2 && f[1] == verbForget:
		a.mu.Lock()
		if a.gen != gen {
			a.mu.Unlock()
			reply(c, ansErr+" "+codeDenied)
			return
		}
		a.forgetLocked(WhyRejected)
		a.mu.Unlock()
		reply(c, ansOK)
	default:
		reply(c, ansErr+" "+codeBadRequest)
	}
}

// afterTokenCheck, when set, runs after a request's token matched and
// before it is acted on (a test ends the line there).
var afterTokenCheck atomic.Pointer[func()]

func (a *Agent) handleHave(c net.Conn, gen uint64) {
	a.mu.Lock()
	if a.gen != gen {
		a.mu.Unlock()
		reply(c, ansErr+" "+codeDenied)
		return
	}
	a.expireLocked()
	// After the line's get only forget is answered.
	ok := a.has && a.inFlight && !a.closed && !a.spent
	a.mu.Unlock()
	if ok {
		reply(c, ansOK)
		return
	}
	reply(c, ansNo)
}

func (a *Agent) handleGet(c net.Conn, gen uint64) {
	a.mu.Lock()
	a.expireLocked()
	var out string
	switch {
	case a.gen != gen:
		out = ansErr + " " + codeDenied
	case a.closed:
		out = ansErr + " " + codeClosed
	case !a.inFlight:
		out = ansErr + " " + codeNotInFlt
	case !a.has:
		out = ansNo
	case a.getLimit > 0 && a.gets >= a.getLimit:
		// Another get on one line: the first password was refused (ssh
		// retries). Not a second try with it.
		a.forgetLocked(WhyRejected)
		out = ansErr + " " + codeLimit
	default:
		a.gets++
		if a.getLimit > 0 && a.gets >= a.getLimit {
			// The line has its password: its token is good for forget now
			// (a device refused it) and for nothing else.
			a.spent = true
		}
		a.lastGet = a.now()
		// The secret goes from the locked page to the kernel with no
		// copy in between. The socket's buffer is empty and the peer's
		// to drain; the deadline bounds a stuck write.
		_, _ = c.Write([]byte(ansOK + " " + strconv.Itoa(a.n) + "\n"))
		_, _ = c.Write(a.pg.secret()[:a.n])
	}
	a.mu.Unlock()
	if out != "" {
		reply(c, out)
	}
}

func (a *Agent) handleStore(c net.Conn, n int, gen uint64) {
	// The answer is written after the staging slot is zeroed and stageMu is
	// released: a client that sends its next store the moment it has the
	// answer must not find the slot busy.
	reply(c, a.storeBody(c, n, gen))
}

// storeBody receives the n bytes of a store and returns the answer line.
// The stage is zeroed and stageMu released when it returns.
func (a *Agent) storeBody(c net.Conn, n int, gen uint64) string {
	a.mu.Lock()
	a.expireLocked()
	closed, inFlight, spent, stale := a.closed, a.inFlight, a.spent, a.gen != gen
	a.mu.Unlock()
	switch {
	case stale:
		return ansErr + " " + codeDenied
	case closed:
		return ansErr + " " + codeClosed
	case !inFlight:
		return ansErr + " " + codeNotInFlt
	case spent:
		return ansErr + " " + codeLimit
	}
	if !a.stageMu.TryLock() {
		return ansErr + " " + codeBusy
	}
	defer a.stageMu.Unlock()
	// The body is read straight into the locked page's staging slot.
	stage := a.pg.stage()
	defer Zero(stage)
	if _, err := io.ReadFull(c, stage[:n]); err != nil || !validSecret(stage[:n]) {
		return ansErr + " " + codeBadSecret
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	// The body may have been held back across lines: it belongs to the one
	// whose token came with the header.
	if a.gen != gen {
		return ansErr + " " + codeDenied
	}
	if a.closed || !a.inFlight || a.spent {
		return ansErr + " " + codeNotInFlt
	}
	a.replaceLocked(stage[:n])
	return ansOK
}

// peerUID is the uid of the process at the other end of c (SO_PEERCRED).
func peerUID(c *net.UnixConn) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var cerr error
	if err := rc.Control(func(fd uintptr) {
		u, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if e != nil {
			cerr = e
			return
		}
		uid = int(u.Uid)
	}); err != nil {
		return -1, err
	}
	return uid, cerr
}
