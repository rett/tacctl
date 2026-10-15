package fakedev

// The configure model of the fake Junos device (docs/plans/0.2.9-apply-
// plan.md D142): a committed configuration read from the transcript
// directory's 'config.set', a shared candidate, sessions in shared,
// exclusive and private mode, 'commit confirmed' with a timer and the
// banner of a pending commit before every prompt, the commit history and
// the rollback. It is on when the directory has a 'config.set';
// a directory without one behaves as it always did.
//
// The files, all optional and read when they are needed (config.set once, at
// the first session; dirty.shared once with it):
//
//	config.set          the committed configuration: 'set' lines (a capture's
//	                    '# ' header is dropped)
//	device              'hostname <h>', 'model <m>', 'junos <release>' lines:
//	                    what 'show version' says when it has no file of its own
//	                    (the committed 'system host-name' wins for the prompt)
//	class               the class of a login: '<class>' for everyone or
//	                    '<user> <class>' lines (default super-user)
//	local               '<user> <password> [<class>]': local accounts that log
//	                    in beside the transcript's own login
//	template            '<user> <template> <class>': the login is a TACACS+
//	                    one mapped to a local template user ('show cli
//	                    authorization' prints Junos's quoted form)
//	root                the password of the root login, whose shell is a csh
//	                    ('cli' starts the CLI; an exec of 'sh -c "...; exec
//	                    cli"' starts it at once)
//	switch              the '{master:0}' line before every prompt: absent or
//	                    empty is '{master:0}', 'off' none, '<role>:<n>' that
//	banner              (the transcript's) text before the first prompt
//	echo.plain          the CLI echoes a command without the trailing space
//	                    the device adds
//	load.errors         '<prefix> => <message>' (or a tab): a statement that
//	                    begins with the prefix prints the message and is not
//	                    applied
//	version-gate        '<prefix>' (a syntax error at the statement) or
//	                    '<prefix> => check' (accepted, refused by commit check)
//	check.errors        '<message>' (always) or '<prefix> => <message>' (when
//	                    the candidate adds a statement with that prefix): the
//	                    commit check and the commit fail with them
//	exclusive.held-by   a user holding the exclusive lock (read at each use)
//	dirty.shared        'set' lines staged in the shared candidate by a
//	                    stranger (a first line 'user <name>' names him)
//	verify.fail        while a confirmed commit is pending a new login is
//	                    refused: 'deny' (the default: authentication fails),
//	                    'close' (accepted, then closed) or 'hang'
//	commit.drop         the connection of the session that typed 'commit
//	                    confirmed' closes once it is applied; 'after-output'
//	                    prints the answer first, the default does not
//	drop                '<command prefix>' lines: such a command closes the
//	                    connection unanswered, before it is applied
//	slow                '<command prefix> => <seconds>' lines ('*' matches
//	                    every command): the answer waits on the clock
//	timer.minute        seconds one minute of 'commit confirmed' lasts on the
//	                    server's clock (default 60; bats sets 1)
//	netconf.private.confirm
//	                    'refuse': a NETCONF private session's confirmed
//	                    commit is refused as the command line refuses it
//	                    (absent: accepted); see junos_config_netconf.go, which
//	                    also says how the knobs above act over NETCONF
//
// The device writes 'committed.set' (to the state directory, the transcript
// directory unless WithStateDir) at its first use and after every commit, the
// observable configuration of the device.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Clock is the time the configure model uses: the commit times and the
// timer of 'commit confirmed'. A test injects a FakeClock (WithClock) and
// advances it; a server without one uses the real time.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func()) ClockTimer
}

// ClockTimer is what AfterFunc returns.
type ClockTimer interface{ Stop() bool }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) ClockTimer {
	return time.AfterFunc(d, f)
}

// FakeClock is a Clock that only moves when Advance is called.
type FakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	c       *FakeClock
	at      time.Time
	f       func()
	stopped bool
	fired   bool
}

// NewFakeClock is a clock that stands at start.
func NewFakeClock(start time.Time) *FakeClock { return &FakeClock{now: start} }

// Now is the time of the clock.
func (c *FakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// AfterFunc runs f once the clock has been advanced by d.
func (c *FakeClock) AfterFunc(d time.Duration, f func()) ClockTimer {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{c: c, at: c.now.Add(d), f: f}
	c.timers = append(c.timers, t)
	return t
}

// Stop prevents the function from running; it reports whether it had not
// run yet.
func (t *fakeTimer) Stop() bool {
	t.c.mu.Lock()
	defer t.c.mu.Unlock()
	was := !t.stopped && !t.fired
	t.stopped = true
	return was
}

// Advance moves the clock on by d and runs, in order of their time and on
// this goroutine, every timer that has fallen due; a timer that a callback
// sets is run too when it falls within d.
func (c *FakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	target := c.now.Add(d)
	c.mu.Unlock()
	for {
		c.mu.Lock()
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.stopped && !t.fired && !t.at.After(target) && (next == nil || t.at.Before(next.at)) {
				next = t
			}
		}
		if next == nil {
			c.now = target
			c.mu.Unlock()
			return
		}
		next.fired = true
		if next.at.After(c.now) {
			c.now = next.at
		}
		c.mu.Unlock()
		next.f()
	}
}

// Timers is how many timers are set and neither run nor stopped.
func (c *FakeClock) Timers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, t := range c.timers {
		if !t.stopped && !t.fired {
			n++
		}
	}
	return n
}

// WithClock sets the clock of the configure model (the real time when not
// given).
func WithClock(c Clock) Option { return func(s *Server) { s.clock = c } }

// WithStateDir sets the directory the model writes 'committed.set' to (the
// transcript directory when not given): for a test that serves a directory
// of the repository.
func WithStateDir(dir string) Option { return func(s *Server) { s.stateDir = dir } }

// JunosCommit is one entry of the commit history, newest first in
// Server.History.
type JunosCommit struct {
	Time    time.Time
	User    string
	Via     string
	Comment string
	// RollbackIn is the minutes of a confirmed commit's window (0 for a
	// commit that is not confirmed); the entry says it for good, as the
	// device's history does, also after a 'commit check' confirmed it: it
	// is not a pending marker (PendingUntil and the prompt's banner are).
	RollbackIn int
}

type junosPending struct {
	timer  ClockTimer
	until  time.Time
	before *jcfg
	// owner is the NETCONF session whose close rolls the commit back at
	// once (0.2.4 spike (d)); nil for a commit of the command line, which
	// only the window's end rolls back.
	owner *jsession
}

// junosDevice is the state of the configure model, shared by the sessions
// of one Server.
type junosDevice struct {
	s    *Server
	mu   sync.Mutex
	born time.Time

	committed *jcfg
	versions  []*jcfg // newest first; versions[0] is committed
	history   []JunosCommit
	shared    *jcfg // nil: no staged change
	stranger  string
	excl      *jsession
	sessions  map[*jsession]struct{}
	pending   *junosPending
	nextID    int
}

// jsession is one CLI of the model.
type jsession struct {
	id        int
	user      string
	class     string
	since     time.Time
	configure bool
	exclusive bool
	private   bool
	base      *jcfg // private: the committed configuration it started from
	cand      *jcfg // private: its candidate
	edit      []string
	pageLen   int
	junosPage bool
}

const historyMax = 50

// junos is the configure model of the server, or nil when the transcript
// directory has no 'config.set'.
func (s *Server) junos() *junosDevice {
	s.junosMu.Lock()
	defer s.junosMu.Unlock()
	if s.jdev != nil {
		return s.jdev
	}
	text, ok := s.t.read("config.set")
	if !ok {
		return nil
	}
	if s.clock == nil {
		s.clock = realClock{}
	}
	d := &junosDevice{s: s, born: s.clock.Now(), sessions: map[*jsession]struct{}{}}
	d.committed = parseSetText(stripCaptureHeader(text))
	d.versions = []*jcfg{d.committed.clone()}
	d.history = []JunosCommit{{Time: d.born, User: jtExpiryUser, Via: jtExpiryVia}}
	if ds, ok := s.t.read("dirty.shared"); ok {
		d.stranger = "bob"
		var rest []string
		for _, l := range strings.Split(ds, "\n") {
			if u, ok := strings.CutPrefix(strings.TrimSpace(l), "user "); ok && len(strings.Fields(u)) == 1 {
				d.stranger = strings.TrimSpace(u)
				continue
			}
			rest = append(rest, l)
		}
		c := d.committed.clone()
		for _, p := range parseSetText(strings.Join(rest, "\n")).stmts {
			c.set(p)
		}
		d.shared = c
	}
	d.writeCommitted()
	s.jdev = d
	return d
}

// Committed is the device's committed configuration as 'set' lines (what
// 'committed.set' holds), or "" when the model is off.
func (s *Server) Committed() string {
	d := s.junos()
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.committed.setText()
}

// Candidate is the shared candidate as 'set' lines: the committed
// configuration when nothing is staged.
func (s *Server) Candidate() string {
	d := s.junos()
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sharedOrCommitted().setText()
}

// History is the commit history, newest first.
func (s *Server) History() []JunosCommit {
	d := s.junos()
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.history)
}

// PendingUntil is when the device rolls the confirmed commit back, if one
// is pending.
func (s *Server) PendingUntil() (time.Time, bool) {
	d := s.junos()
	if d == nil {
		return time.Time{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending == nil {
		return time.Time{}, false
	}
	return d.pending.until, true
}

// ExclusiveHolder is the user that holds the exclusive lock, "" when none
// does (the 'exclusive.held-by' knob counts).
func (s *Server) ExclusiveHolder() string {
	d := s.junos()
	if d == nil {
		return ""
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.holder()
}

// --- the knob files ------------------------------------------------------------------------

// rules reads a knob file as lines; a blank line and a '#' line are dropped.
func (d *junosDevice) rules(name string) []string {
	text, ok := d.s.t.read(name)
	if !ok {
		return nil
	}
	var out []string
	for _, l := range strings.Split(stripCaptureHeader(text), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// splitRule cuts '<prefix> => <message>' (or at a tab).
func splitRule(l string) (prefix, msg string, ok bool) {
	if i := strings.Index(l, "\t"); i >= 0 {
		return strings.TrimSpace(l[:i]), strings.TrimSpace(l[i+1:]), true
	}
	if i := strings.Index(l, " => "); i >= 0 {
		return strings.TrimSpace(l[:i]), strings.TrimSpace(l[i+4:]), true
	}
	return strings.TrimSpace(l), "", false
}

// hasPrefixWords reports whether text begins with the words of prefix.
func hasPrefixWords(text, prefix string) bool {
	text, prefix = strings.Join(strings.Fields(text), " "), strings.Join(strings.Fields(prefix), " ")
	return text == prefix || strings.HasPrefix(text, prefix+" ")
}

func (d *junosDevice) knobWord(name string) (string, bool) {
	t, ok := d.s.t.read(name)
	if !ok {
		return "", false
	}
	f := strings.Fields(t)
	if len(f) == 0 {
		return "", true
	}
	return f[0], true
}

// holder is the exclusive lock's holder, or "".
func (d *junosDevice) holder() string {
	if d.excl != nil {
		return d.excl.user
	}
	u, _ := d.knobWord("exclusive.held-by")
	return u
}

// minute is how long one minute of 'commit confirmed' lasts.
func (d *junosDevice) minute() time.Duration {
	if w, ok := d.knobWord("timer.minute"); ok {
		if n, err := strconv.ParseFloat(w, 64); err == nil && n > 0 {
			return time.Duration(n * float64(time.Second))
		}
	}
	return time.Minute
}

// switchLine is the '{master:0}' text before a prompt ("" for none).
func (d *junosDevice) switchLine() string {
	w, ok := d.knobWord("switch")
	switch {
	case !ok || w == "":
		return fmt.Sprintf(jtMasterFmt, "master:0")
	case w == "off":
		return ""
	}
	return fmt.Sprintf(jtMasterFmt, w)
}

// hostname is the name the prompt carries.
func (d *junosDevice) hostname() string {
	for _, s := range d.committed.stmts {
		if len(s) == 3 && s[0] == "system" && s[1] == "host-name" {
			return s[2]
		}
	}
	return d.deviceInfo("hostname", "example-sw1")
}

func (d *junosDevice) deviceInfo(key, def string) string {
	for _, l := range d.rules("device") {
		if k, v, ok := strings.Cut(l, " "); ok && k == key && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return def
}

// classOf is the class of a login.
func (d *junosDevice) classOf(user string) string {
	for _, l := range d.rules("local") {
		if f := strings.Fields(l); len(f) == 3 && f[0] == user {
			return f[2]
		}
	}
	class := "super-user"
	for _, l := range d.rules("class") {
		f := strings.Fields(l)
		switch {
		case len(f) == 1:
			class = f[0]
		case len(f) == 2 && f[0] == user:
			return f[1]
		}
	}
	return class
}

// mayConfigure is whether the class may enter configuration mode.
func mayConfigure(class string) bool {
	c, ok := jtClasses[class]
	return !ok || c.configure
}

// --- what the server asks of the model (fakedev.go) -----------------------------------------------

// junosAccept reports whether the model has a local account or a root login
// for this user and password.
func (s *Server) junosAccept(user, pw string) bool {
	if !s.t.exists("config.set") {
		return false
	}
	if user == "root" {
		if p, ok := s.t.read("root"); ok {
			if f := strings.Fields(p); len(f) == 1 && f[0] == pw {
				return true
			}
		}
	}
	if text, ok := s.t.read("local"); ok {
		for _, l := range strings.Split(text, "\n") {
			if f := strings.Fields(l); len(f) >= 2 && !strings.HasPrefix(f[0], "#") && f[0] == user && f[1] == pw {
				return true
			}
		}
	}
	return false
}

// junosLoginMode is how a new connection is treated while the model holds a
// pending confirmed commit and has the 'verify.fail' knob: "" (normally),
// "deny", "close" or "hang".
func (s *Server) junosLoginMode() string {
	if !s.t.exists("verify.fail") {
		return ""
	}
	d := s.junos()
	if d == nil {
		return ""
	}
	d.mu.Lock()
	pending := d.pending != nil
	d.mu.Unlock()
	if !pending {
		return ""
	}
	switch w, _ := d.knobWord("verify.fail"); w {
	case "close", "hang":
		return w
	}
	return "deny"
}

// --- the state operations (callers hold d.mu) -----------------------------------------------------

func (d *junosDevice) sharedOrCommitted() *jcfg {
	if d.shared != nil {
		return d.shared
	}
	return d.committed
}

// modified is whether the shared candidate holds a staged change.
func (d *junosDevice) modified() bool {
	return d.shared != nil && !d.shared.equal(d.committed)
}

func (d *junosDevice) writeCommitted() {
	dir := d.s.stateDir
	if dir == "" {
		dir = d.s.t.dir
	}
	tmp := filepath.Join(dir, ".committed.set.tmp")
	if err := os.WriteFile(tmp, []byte(d.committed.setText()), 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, filepath.Join(dir, "committed.set"))
}

// record makes the committed configuration the next version and adds the
// history entry.
func (d *junosDevice) record(user, via, comment string, rollbackIn int) {
	d.versions = slices.Insert(d.versions, 0, d.committed.clone())
	d.history = slices.Insert(d.history, 0, JunosCommit{
		Time: d.s.clock.Now(), User: user, Via: via, Comment: comment, RollbackIn: rollbackIn,
	})
	if len(d.versions) > historyMax {
		d.versions = d.versions[:historyMax]
	}
	if len(d.history) > historyMax {
		d.history = d.history[:historyMax]
	}
	d.writeCommitted()
}

// expire is the timer of a confirmed commit: the device commits the
// configuration it had before, as itself.
func (d *junosDevice) expire(p *junosPending) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.pending != p {
		return
	}
	d.pending = nil
	d.committed = p.before.clone()
	d.record(jtExpiryUser, jtExpiryVia, "", 0)
}

// formatTime is a commit's time in the history.
func formatTime(t time.Time) string { return t.UTC().Format(jtTimeLayout) }

// historyText is 'show system commit'.
func (d *junosDevice) historyText() string {
	var b strings.Builder
	for i, h := range d.history {
		fmt.Fprintf(&b, "%-3d %s by %s via %s", i, formatTime(h.Time), h.User, h.Via)
		if h.RollbackIn > 0 {
			mins := h.RollbackIn
			if h.Via == jtNetconfVia && mins > 0 {
				// a commit made over NETCONF reads the window rounded
				// down: a one-minute window is 'rollback in 0mins' [C: one
				// observation on the lab switch, plan N5]
				mins--
			}
			b.WriteString(" " + fmt.Sprintf(jtRollbackInFmt, mins))
		}
		b.WriteString("\n")
		if h.Comment != "" {
			b.WriteString("    " + h.Comment + "\n")
		}
		// the device's own marker under a commit that waits for its confirm
		// (entry 0 only: a later commit or a check confirmed it) [C: plan N5]
		if i == 0 && d.pending != nil {
			b.WriteString("    " + jtRollbackPending + "\n")
		}
	}
	// a saved rescue configuration (the 'rescue' knob): the marker line
	// ends the answer
	if _, ok := d.s.t.read("rescue"); ok {
		fmt.Fprintf(&b, jtRescueFmt+"\n", formatTime(d.born), jtExpiryUser, jtCommitVia)
	}
	return b.String()
}

// authorizationText is 'show cli authorization'.
func (d *junosDevice) authorizationText(user string) string {
	class := d.classOf(user)
	var b strings.Builder
	header := fmt.Sprintf("Current user: %-12s login: %-12s class: %s\n", user, user, class)
	for _, l := range d.rules("template") {
		if f := strings.Fields(l); len(f) == 3 && f[0] == user {
			header = fmt.Sprintf("Current user: '%s' login: '%s' class '%s'\n", f[1], user, f[2])
		}
	}
	b.WriteString(header)
	b.WriteString("Permissions:\n")
	for _, p := range jtClasses[class].perms {
		fmt.Fprintf(&b, "    %s\n", p)
	}
	b.WriteString("Individual command authorization:\nAllow regular expression: none\nDeny regular expression: none\n" +
		"Allow configuration regular expression: none\nDeny configuration regular expression: none\n")
	return b.String()
}

// versionText is 'show version' when the transcript has no file for it.
func (d *junosDevice) versionText() string {
	model := d.deviceInfo("model", "ex4300-48mp")
	rel := d.deviceInfo("junos", "25.4R1.12")
	return fmt.Sprintf("Hostname: %s\nModel: %s\nFamily: junos\nJunos: %s\nJUNOS Base OS boot [%s]\n",
		d.hostname(), model, rel, rel)
}

// show configuration [path] [| display set]: the committed configuration.
func (d *junosDevice) showConfiguration(path []string, displaySet bool) string {
	if displaySet {
		return d.committed.under(path).setText()
	}
	text := d.committed.braceText(path)
	if len(path) == 0 && len(d.history) > 0 {
		h := d.history[0]
		text = fmt.Sprintf(jtLastCommitFmt, formatTime(h.Time), h.User) + "\n" + text
	}
	return text
}

func durationOf(secs float64) time.Duration { return time.Duration(secs * float64(time.Second)) }
