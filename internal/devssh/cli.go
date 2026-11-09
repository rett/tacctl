package devssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/rett/tacctl/internal/devconf/batch"
)

// The vendors a CLI session knows (the names of devreg's registry).
const (
	VendorCisco   = "cisco"
	VendorJuniper = "juniper"
)

// Mode is how a CLI session reaches the device's command line.
type Mode int

// The channel types. ModeDefault is the vendor's: one 'exec' channel per
// command on Junos, one 'shell' channel with the prompt detector on IOS
// (plan section 3; WP11.0 confirms or corrects, and WithMode selects).
const (
	ModeDefault Mode = iota
	ModeExec
	ModeShell
)

// maxLoginOutput is the most the login banner of a shell may be.
const maxLoginOutput = 64 << 10

// learnPatience is how many quiet periods learning waits, after it typed
// the empty line a second time, for a device to answer one (see learn).
const learnPatience = 10

// maxPromptLine is the longest last line examined as a prompt or a more-
// prompt; a longer one is output.
const maxPromptLine = 512

// CLISession runs commands on a device's command line. Run is safe for
// concurrent use but commands run one after the other; Close does not wait
// for a command in flight.
//
// A shell session finds the end of a command's output by the prompt. On
// Junos it knows the two prompts of the mode a command can lead to
// (operational '> ', configure '# ', the same user@host): a command that
// changes the mode ends when the other mode's prompt stands at the end of
// the output, and the session is then in that mode. A command that changes
// the prompt in any other way (a host name, a Cisco mode) is never seen to
// end and Run waits for its context. So does a question the device asks
// ('Exit with uncommitted changes? [yes,no]', a password prompt): a caller
// that writes uses 'configure private' or 'configure exclusive' and never
// sends a bare 'exit' while it has changes.
type CLISession interface {
	// Run runs cmd and returns its output without the echoed command and
	// the prompt, lines ended with '\n'. A command is one line without
	// control characters (and, in a shell session, without '?', which a
	// device answers with inline help as it is typed). A shell session
	// pages through '--More--' by itself (a safety net: the vendor's Reader
	// turns paging off first). Output over MaxOutput is ErrOutputTooLarge
	// and ends the session. A shell session whose output cannot be
	// delimited with certainty (the prompt seen more often than commands
	// were sent, output between commands) ends with ErrProtocol and is
	// closed: no output is better than output of another command.
	//
	// When ctx ends the call returns ErrTimeout or context.Canceled and
	// the session is closed. If it ends while a channel is being opened or
	// a request or a write is blocked on the device, the whole client is
	// closed: a Client is one device's job and its context the job's
	// deadline.
	Run(ctx context.Context, cmd string) (string, error)
	// Commands is the command lines Run has sent, in order, as the caller
	// gave them (a copy). Nothing else goes through a session: the keys
	// typed ahead to find the end of an output and the answers to a pager
	// are not commands, and no password is ever typed by it. A line is
	// kept as it was sent, a secret in it included: the caller masks the
	// secrets when it reads or records Commands, never in the command.
	Commands() []string
	Close() error
}

// CLIOption changes how CLI opens a session.
type CLIOption func(*cliConfig)

type cliConfig struct {
	mode Mode
	pty  bool
	cmd  string
}

// WithMode selects the channel type instead of the vendor's.
func WithMode(m Mode) CLIOption { return func(c *cliConfig) { c.mode = m } }

// WithPTY has a shell session request a pseudo-terminal (vt100, 200
// columns), for a device that gives no command line without one.
func WithPTY() CLIOption { return func(c *cliConfig) { c.pty = true } }

// WithCommand has a shell session run cmd on the channel instead of the
// login shell (an 'exec' request on the channel, with input from the
// session: root's csh needs 'cli' to reach the Junos command line). A
// session so opened is a shell session whatever the vendor's default
// (combined with WithMode(ModeExec) it is refused). cmd is one line without
// control characters and is not part of Commands.
func WithCommand(cmd string) CLIOption { return func(c *cliConfig) { c.cmd = cmd } }

// profile is a vendor's command line.
type profile struct {
	// prompt matches a line that may be the device waiting for a command
	// (the last line of the output, without a trailing newline).
	prompt *regexp.Regexp
	mode   Mode
	// other is the prompt of the mode a command can lead to, given the
	// prompt of the mode the session is in; "" when the profile has none.
	other func(prompt string) string
}

var profiles = map[string]profile{
	VendorJuniper: {prompt: regexp.MustCompile(`^\S+@\S+> $`), mode: ModeExec, other: junosOtherPrompt},
	VendorCisco:   {prompt: regexp.MustCompile(`^\S+[>#]$`), mode: ModeShell},
}

// The endings of the Junos prompts, in one place: the operational prompt is
// 'user@host> ' and the configure-mode prompt is 'user@host# ', after a
// location line ('[edit]', '[edit system login]', with a '{master:0}'
// prefix on a virtual chassis) that is output of the command before it.
// [L] Observed on one 25.4 virtual chassis only; correct here after the
// lab spike (L1).
const (
	junosOperSuffix   = "> "
	junosConfigSuffix = "# "
)

// reJunosLocation matches the location line a Junos device prints before a
// configure-mode prompt ('[edit]', '[edit protocols bgp]', optionally
// prefixed '{master:0}' on a virtual chassis). It is output, never a
// prompt. [L] as above.
var reJunosLocation = regexp.MustCompile(`^(?:\{[a-z-]+(?::[a-z0-9]+)?\})?\[edit(?: [^\]]*)?\]$`)

// LocationLine reports whether line is the location line a Junos device
// prints before a configure-mode prompt: '[edit]' or '[edit <path>]',
// optionally prefixed '{master:0}'. The line is output of the command
// whose prompt follows it and stays in Run's result; a caller that does not
// want it removes it with this.
func LocationLine(line string) bool { return reJunosLocation.MatchString(line) }

// junosOtherPrompt is the prompt of the other mode: 'u@h> ' and 'u@h# '.
func junosOtherPrompt(prompt string) string {
	switch {
	case strings.HasSuffix(prompt, junosOperSuffix):
		return strings.TrimSuffix(prompt, junosOperSuffix) + junosConfigSuffix
	case strings.HasSuffix(prompt, junosConfigSuffix):
		return strings.TrimSuffix(prompt, junosConfigSuffix) + junosOperSuffix
	}
	return ""
}

// rePager matches a line that is a more-prompt of IOS (' --More-- ') or
// Junos ('---(more)---', '---(more 12%)---'), nothing else on it.
var rePager = regexp.MustCompile(`^\s*(?:--\s*More\s*--|---\(more[^)]*\)---)\s*$`)

// rePagerErased is a more-prompt followed by the erase sequence of a device
// that was given a key: the typed-ahead empty line, taken for it, so the
// marker stayed in the stream. It is not output.
var rePagerErased = regexp.MustCompile(` ?(?:--\s*More\s*--|---\(more[^)]*\)---)\s*\x08+ *\x08*`)

// CLI opens a command-line session for vendor ('cisco' or 'juniper').
// Opening a shell session waits (the connect timeout) for the prompt; an
// exec session opens a channel per command.
func (c *Client) CLI(vendor string, opts ...CLIOption) (CLISession, error) {
	prof, ok := profiles[vendor]
	if !ok {
		return nil, fmt.Errorf("devssh: no command-line profile for vendor %q", vendor)
	}
	var cfg cliConfig
	for _, o := range opts {
		o(&cfg)
	}
	if cfg.cmd != "" {
		if err := checkCommand(cfg.cmd); err != nil {
			return nil, err
		}
		switch cfg.mode {
		case ModeExec:
			return nil, errors.New("devssh: WithCommand is for a shell session")
		case ModeDefault:
			cfg.mode = ModeShell
		}
	}
	if cfg.mode == ModeDefault {
		cfg.mode = prof.mode
	}
	if cfg.mode == ModeExec {
		return &execSession{c: c}, nil
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	sh, err := c.openShell(ctx, prof, cfg)
	if err != nil {
		return nil, err
	}
	batch.Mark(c.ctx, "session")
	return sh, nil
}

// checkCommand refuses a command that is more than one line or holds a
// control character: in a shell the rest would run as further input.
func checkCommand(cmd string) error {
	if strings.IndexFunc(cmd, unicode.IsControl) >= 0 {
		return errors.New("devssh: a command is one line without control characters")
	}
	return nil
}

// checkShellCommand adds what only a shell reacts to as it is typed: '?'
// is inline help on IOS and Junos, answered at once and never as a command.
func checkShellCommand(cmd string) error {
	if err := checkCommand(cmd); err != nil {
		return err
	}
	if strings.Contains(cmd, "?") {
		return errors.New("devssh: a command in a shell session must not contain '?' (inline help)")
	}
	return nil
}

// closedError is the error of a channel call that failed on the wire.
func closedError(err error) error {
	return fmt.Errorf("%w: %s", ErrClosed, sanitize(err.Error()))
}

// execSession is one exec channel per command.
type execSession struct {
	c   *Client
	mu  sync.Mutex
	log cmdLog
}

func (e *execSession) Close() error { return nil }

func (e *execSession) Commands() []string { return e.log.list() }

// cmdLog is the ordered command lines a session has sent.
type cmdLog struct {
	mu   sync.Mutex
	cmds []string
}

func (l *cmdLog) add(cmd string) {
	l.mu.Lock()
	l.cmds = append(l.cmds, cmd)
	l.mu.Unlock()
}

func (l *cmdLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.cmds...)
}

func (e *execSession) Run(ctx context.Context, cmd string) (string, error) {
	if err := checkCommand(cmd); err != nil {
		return "", err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.c.ctxErr(); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", callError(ctx, e.c)
	}
	out := newSink()
	var sess *ssh.Session
	err := e.c.within(ctx, func() error {
		s, err := e.c.conn.NewSession()
		if err != nil {
			return closedError(err)
		}
		s.Stdout, s.Stderr = out, out
		e.log.add(cmd)
		if err := s.Start(cmd); err != nil {
			_ = s.Close()
			return closedError(err)
		}
		sess = s
		return nil
	})
	if err != nil {
		return "", err
	}
	go func() { out.close(sess.Wait()) }()
	// The call's context closes the channel, which ends Wait.
	unhook := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer func() { unhook(); _ = sess.Close() }()

	var buf []byte
	for {
		ch := out.take()
		if ch.overflow || len(buf)+len(ch.data) > MaxOutput {
			return "", ErrOutputTooLarge
		}
		buf = append(buf, ch.data...)
		if ch.closed {
			return e.finish(ctx, buf, ch.err)
		}
		if err := out.wait(ctx); err != nil {
			return "", callError(ctx, e.c)
		}
	}
}

// finish is the result of an exec channel that ended with waitErr. A
// channel closed without an exit status is an error whatever the device
// sent: nothing tells a short success from a dropped connection.
func (e *execSession) finish(ctx context.Context, raw []byte, waitErr error) (string, error) {
	var exit *ssh.ExitError
	switch {
	case waitErr == nil:
		return normalise(string(raw)), nil
	case errors.As(waitErr, &exit):
		return normalise(string(raw)), CommandError{Status: exit.ExitStatus()}
	}
	if ctx.Err() != nil || e.c.ctxErr() != nil {
		return "", callError(ctx, e.c)
	}
	return "", fmt.Errorf("%w: %s: the channel ended without an exit status", ErrClosed, e.c.addr)
}

// callError is the typed error of a call whose context ended (or, when the
// client's own context ended, that one).
func callError(ctx context.Context, c *Client) error {
	if err := c.ctxErr(); err != nil {
		return err
	}
	if err := contextError(ctx, c.addr); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrClosed, c.addr)
}

// normalise ends lines with '\n' and drops the carriage returns.
func normalise(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.ReplaceAll(s, "\r", "")
}

// shell is one shell channel with the prompt learned at login.
type shell struct {
	c     *Client
	sess  io.Closer
	in    io.Writer
	out   *sink
	prof  profile
	quiet time.Duration

	mu     sync.Mutex // serialises Run; guards prompt and alt
	prompt string     // the prompt of the mode the session is in
	alt    string     // the prompt of the mode a command can lead to; "" none
	broken atomic.Bool
	log    cmdLog
	// area is what the device printed before its prompt in the answer to
	// the last empty line typed ahead (PromptArea); areaOK is set once a
	// command completed.
	area   []string
	areaOK bool
	// late: learning ended with an answer to a typed-ahead empty line
	// possibly still on its way (see learn); the first Run allows for it.
	late bool
}

// PromptArea is a shell session that tells what the device prints before
// its prompt: a Junos switch's '{master:0}' line, and the line '# commit
// confirmed will be rolled back in N minutes' while a confirmed commit is
// pending (0.2.9 lab L2). Run drops these lines from the end of a command's
// output; PromptArea returns them as the device printed them in its answer
// to the last empty line Run typed ahead (the location line not among
// them, blank lines dropped). ok is false before a command has completed,
// and after one whose answer to the empty line did not stand on a line of
// its own: a device that does not echo the empty line prints both prompts
// on one line, and what stands before its prompt cannot be told.
type PromptArea interface {
	PromptArea() (lines []string, ok bool)
}

// PromptArea is the prompt area of the last command (see the interface).
func (s *shell) PromptArea() ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.area), s.areaOK
}

// openShell starts the shell channel and learns the prompt.
func (c *Client) openShell(ctx context.Context, prof profile, cfg cliConfig) (*shell, error) {
	out := newSink()
	var sess *ssh.Session
	var in io.Writer
	err := c.within(ctx, func() error {
		s, err := c.conn.NewSession()
		if err != nil {
			return closedError(err)
		}
		s.Stdout, s.Stderr = out, out
		w, err := s.StdinPipe()
		if err != nil {
			_ = s.Close()
			return closedError(err)
		}
		if cfg.pty {
			if err := s.RequestPty("vt100", 0, 200, ssh.TerminalModes{}); err != nil {
				_ = s.Close()
				return fmt.Errorf("%w: the device refused a terminal", ErrClosed)
			}
		}
		if cfg.cmd != "" {
			if err := s.Start(cfg.cmd); err != nil {
				_ = s.Close()
				return fmt.Errorf("%w: the device refused the command", ErrClosed)
			}
		} else if err := s.Shell(); err != nil {
			_ = s.Close()
			return fmt.Errorf("%w: the device refused a shell", ErrClosed)
		}
		sess, in = s, w
		return nil
	})
	if err != nil {
		return nil, err
	}
	go func() { out.close(sess.Wait()) }()
	return c.learnShell(ctx, prof, out, sess, in)
}

// learnShell learns the prompt of a shell channel whose output goes to out.
func (c *Client) learnShell(ctx context.Context, prof profile, out *sink, sess io.Closer, in io.Writer) (*shell, error) {
	sh := &shell{c: c, sess: sess, in: in, out: out, prof: prof, quiet: c.quiet}
	unhook := context.AfterFunc(ctx, func() { _ = sess.Close() })
	prompt, late, err := sh.learn(ctx)
	unhook()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	sh.prompt, sh.late = prompt, late
	if prof.other != nil {
		sh.alt = prof.other(prompt)
	}
	return sh, nil
}

// Close closes the channel without waiting for a command in flight; that
// command's Run returns ErrClosed.
func (s *shell) Close() error {
	// Only the channel is closed: closing the stdin pipe races with a
	// write in flight inside x/crypto/ssh.
	err := s.sess.Close()
	s.broken.Store(true)
	return err
}

func (s *shell) Commands() []string { return s.log.list() }

func (s *shell) Run(ctx context.Context, cmd string) (string, error) {
	if err := checkShellCommand(cmd); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prevArea := s.area
	s.area, s.areaOK = nil, false
	if s.broken.Load() {
		return "", fmt.Errorf("%w: %s", ErrClosed, s.c.addr)
	}
	if err := s.c.ctxErr(); err != nil {
		return "", err
	}
	if ctx.Err() != nil {
		return "", callError(ctx, s.c)
	}
	// An abandoned command leaves its output in the stream: the session is
	// closed rather than guessed at.
	unhook := context.AfterFunc(ctx, func() { _ = s.sess.Close() })
	defer unhook()
	fail := func(err error) (string, error) {
		s.broken.Store(true)
		_ = s.sess.Close()
		return "", err
	}
	// Nothing is expected between commands: anything there is output that
	// would be taken for the next command's. The one thing that may be
	// there is the answer to an empty line typed ahead at login that was
	// still on its way when the prompt was learned (see learn): it is
	// part of the stream the command's answer is read from, and body
	// drops it.
	late := s.late
	c := s.out.take()
	if c.overflow || (len(c.data) > 0 && (!s.late || !s.lateShape(c.data, prevArea))) {
		return fail(fmt.Errorf("%w: %s: output between commands", ErrProtocol, s.c.addr))
	}
	carry := c.data
	s.late = false
	s.log.add(cmd)
	if err := s.c.write(ctx, s.in, []byte(cmd+"\n")); err != nil {
		return fail(err)
	}
	body, err := s.read(ctx, cmd, carry, prevArea, late)
	if err != nil {
		return fail(err)
	}
	return stripEcho(body, cmd), nil
}

// reJunosChassis matches the line a Junos virtual chassis or cluster prints
// before every prompt ('{master:0}').
var reJunosChassis = regexp.MustCompile(`^\{[a-z-]+(?::[a-z0-9]+)?\}$`)

// PendingBanner matches the line a Junos device prints before the prompt of
// every session while a confirmed commit is pending, the minutes left in it
// [C: '# commit confirmed will be rolled back in 2 minutes'; '1 minute' for
// one]. The first group is the minutes. internal/devapply reads the state
// from it.
var PendingBanner = regexp.MustCompile(`^# commit confirmed will be rolled back in ([1-9][0-9]{0,4}) minutes?$`)

// staleLine reports whether line, one the device printed in front of its
// prompt in a late answer, is nothing but what a device prints there: a
// blank line, the location line, the chassis line, the banner of a pending
// confirmed commit, or a line it printed before the prompt of the last
// command (area). The first command after a login has no area, and a
// session in the state of a pending confirmed commit (the verification
// login of an apply) has the banner in every answer.
func staleLine(line string, area []string) bool {
	t := strings.TrimSpace(line)
	if t == "" || LocationLine(t) || reJunosChassis.MatchString(t) || PendingBanner.MatchString(t) {
		return true
	}
	return slices.ContainsFunc(area, func(a string) bool { return strings.TrimSpace(a) == t })
}

// The partial forms of the lines staleLine knows: the start of a chassis or
// location line, and what can follow the text of the banner.
var (
	reChassisStart  = regexp.MustCompile(`^\{[a-z-]*(?::[a-z0-9]*)?\}?$`)
	reLocationStart = regexp.MustCompile(`^(?:\{[a-z-]+(?::[a-z0-9]+)?\})?\[[^\]]*\]?$`)
	reBannerEnd     = regexp.MustCompile(`^(?:[1-9][0-9]{0,4}(?: (?:m(?:i(?:n(?:u(?:t(?:e(?:s)?)?)?)?)?)?)?)?)?$`)
)

// bannerStart is the text of the banner up to its minutes.
const bannerStart = "# commit confirmed will be rolled back in "

// staleStart reports whether part, a last line cut short (no line end after
// it yet), is the start of a line staleLine accepts, or all of it.
func staleStart(part string, area []string) bool {
	t := strings.TrimSpace(part)
	if staleLine(part, area) || reChassisStart.MatchString(t) || reLocationStart.MatchString(t) {
		return true
	}
	if rest, ok := strings.CutPrefix(t, bannerStart); ok {
		return reBannerEnd.MatchString(rest)
	}
	if strings.HasPrefix(bannerStart, part) { // part has no white space to trim off
		return true
	}
	return slices.ContainsFunc(area, func(a string) bool { return strings.HasPrefix(strings.TrimSpace(a), t) })
}

// lateShape reports whether data, taken from the stream between commands,
// can be a late answer to an empty line: lines that stand in front of a
// prompt, and then the start of a prompt (or all of it) as the last line;
// that last line can also be the start of a line in front of the prompt
// (the data is cut inside it, with no line end yet). A prompt line that is
// complete is not one: the device prints the echo after its prompt on the
// same line, and a prompt that ends its line is counted by read.
func (s *shell) lateShape(data []byte, area []string) bool {
	lines := strings.Split(normalise(string(data)), "\n")
	last := lines[len(lines)-1]
	for _, l := range lines[:len(lines)-1] {
		if !staleLine(l, area) {
			return false
		}
	}
	for _, p := range []string{s.prompt, s.alt} {
		if p != "" && strings.HasPrefix(p, last) {
			return true
		}
	}
	return last == "" || staleStart(last, area)
}

// hit is a complete line of the output that is the prompt, n times over
// (a device that does not echo an empty line puts its prompts on one).
type hit struct{ start, n int }

// outBuf is the output of one read: the bytes, where the last line and the
// one before it start, and the lines that are the prompt, so the tail is
// examined without rescanning.
type outBuf struct {
	b          []byte
	line, prev int // offsets of the last line and of the line before it; prev -1: none
	prompt     string
	hits       []hit
	// alt is the prompt of the mode a command can lead to ("" none) and
	// altHits the lines that are it, kept apart from the prompt's.
	alt     string
	altHits []hit
	// echo is the command sent. The first line of the output, when it is
	// the command echoed, is not a prompt whatever it holds (a command
	// that is the text of a prompt); the prompt is only taken at the
	// start of a line after the echo.
	echo string
	// area is what the device printed before the prompt of the command
	// before this one (PromptArea): body knows it for what it drops.
	area []string
	// late is set for the first command after a login that ended with an
	// answer to an empty line outstanding (shell.late): only its output
	// can hold that answer in front of the echo, so only body's dropLate
	// looks for it there. A stream that is out of step on a later command
	// stays as it is, for the parser to refuse.
	late bool
}

// isEcho reports whether line, the first line of the output, is the echo
// of the command sent.
func (o *outBuf) isEcho(line string) bool {
	return o.prev == -1 && o.echo != "" && strings.TrimSpace(line) == o.echo
}

func (o *outBuf) add(p []byte) {
	base := len(o.b)
	o.b = append(o.b, p...)
	for off := 0; ; {
		i := bytes.IndexByte(p[off:], '\n')
		if i < 0 {
			return
		}
		end := base + off + i
		line := strings.TrimRight(string(o.b[o.line:end]), "\r")
		if !o.isEcho(line) {
			if n := repeats(line, o.prompt); n > 0 {
				o.hits = append(o.hits, hit{o.line, n})
			}
			if n := repeats(line, o.alt); n > 0 {
				o.altHits = append(o.altHits, hit{o.line, n})
			}
		}
		off += i + 1
		o.prev, o.line = o.line, base+off
	}
}

// reset forgets the prompts counted so far.
func (o *outBuf) reset() { o.hits, o.altHits = nil, nil }

// at is which prompt the tail line is: 0 the session's, 1 the other
// mode's, -1 none. The echo of the command is none.
func (o *outBuf) at(tail string) int {
	if o.isEcho(tail) {
		return -1
	}
	if repeats(tail, o.prompt) > 0 {
		return 0
	}
	if repeats(tail, o.alt) > 0 {
		return 1
	}
	return -1
}

// count is how many times prompt k (0 the session's, 1 the other mode's)
// has been seen: the complete lines that are it, and the tail when that is.
func (o *outBuf) count(k int) int {
	p, hits := o.prompt, o.hits
	if k == 1 {
		p, hits = o.alt, o.altHits
	}
	n := 0
	for _, h := range hits {
		n += h.n
	}
	if t, ok := o.tail(); ok && !o.isEcho(t) {
		n += repeats(t, p)
	}
	return n
}

// repeats is how many times line is prompt (and nothing else), 0 if it is
// not.
func repeats(line, prompt string) int {
	if prompt == "" || line == "" || len(line) > maxPromptLine || len(line)%len(prompt) != 0 {
		return 0
	}
	n := len(line) / len(prompt)
	if line != strings.Repeat(prompt, n) {
		return 0
	}
	return n
}

// tail is the line still being written, without a carriage return; ok is
// false for a line too long to be a prompt.
func (o *outBuf) tail() (string, bool) {
	if len(o.b)-o.line > maxPromptLine {
		return "", false
	}
	return strings.TrimRight(string(o.b[o.line:]), "\r"), true
}

// prompts is how many times the prompt has been seen: the complete lines
// that are it, and the tail when that is.
func (o *outBuf) prompts() int { return o.count(0) }

// skipErase drops the erase sequence a device writes over a more-prompt
// after the key was pressed (backspaces, blanks, backspaces), right where
// the prompt stood and nowhere else. state is 0 when nothing is expected.
func skipErase(p []byte, state int) ([]byte, int) {
	for len(p) > 0 && state > 0 {
		c := p[0]
		switch {
		case state == 1 && c == '\b':
			state = 2
		case state == 2 && c == '\b':
		case state == 2 && c == ' ':
			state = 3
		case state == 3 && c == ' ':
		case state == 3 && c == '\b':
			state = 4
		case state == 4 && c == '\b':
		default:
			return p, 0
		}
		p = p[1:]
	}
	return p, state
}

// errInconsistent is a shell whose output can no longer be delimited.
func (s *shell) errInconsistent(why string) error {
	return fmt.Errorf("%w: %s: %s", ErrProtocol, s.c.addr, why)
}

// closedOrCtx is the error of an output channel that ended.
func (s *shell) closedOrCtx(ctx context.Context) error {
	if ctx.Err() != nil || s.c.ctxErr() != nil {
		return callError(ctx, s.c)
	}
	return fmt.Errorf("%w: %s", ErrClosed, s.c.addr)
}

// waitQuiet waits for new output, the context, or q of silence (quiet is
// then true).
func (s *shell) waitQuiet(ctx context.Context, q time.Duration) (quiet bool, err error) {
	t := time.NewTimer(q)
	defer t.Stop()
	select {
	case <-s.out.notify:
		return false, nil
	case <-t.C:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// learn reads the login and returns the prompt. Nothing seen before the
// device has been silent for the quiet period counts: the prompt is the
// last line of the quiet output, and it is confirmed by typing an empty
// line, to which the device answers with the prompt again. The prompt has
// been seen once more for each empty line it answered; more than the empty
// lines sent is ambiguous (ErrHandshake).
//
// No answer within the quiet period is the one step that rests on timing
// alone: the device flushed what was typed ahead at login, or it is slow
// (a loaded device answers later than the quiet period). Both are met by
// typing the empty line once more, and then either answer count is right:
// one (the first line was lost) or two (both answered, the first late).
// After the retry a device that stays silent is waited for patiently
// (learnPatience quiet periods since the retry) before it counts as one
// that does not answer an empty line (ErrHandshake): judging it after one
// more quiet period would fail a merely slow device.
//
// late is set when two lines were typed and one answer came: the device
// flushed the first, or it answers the second still. In the second case the
// answer arrives, in front of the echo, while the first command is run (or
// before it is typed); Run and body allow for it (lateShape, dropLate).
func (s *shell) learn(ctx context.Context) (prompt string, late bool, err error) {
	var buf []byte
	var retriedAt time.Time
	base, sent, quiet := 0, 0, false
	for {
		ch := s.out.take()
		if ch.overflow || len(buf)+len(ch.data) > maxLoginOutput {
			return "", false, fmt.Errorf("%w: %s: the login output is too long for a banner", ErrHandshake, s.c.addr)
		}
		buf = append(buf, ch.data...)
		if len(ch.data) > 0 {
			quiet = false
		}
		if ch.closed {
			return "", false, s.closedOrCtx(ctx)
		}
		if quiet && len(buf) > 0 {
			quiet = false
			tail := string(buf[bytes.LastIndexByte(buf, '\n')+1:])
			tail = promptUnit(strings.TrimRight(tail, "\r"), s.prof.prompt)
			if tail != "" {
				k := countPrompts(buf, tail)
				got := k - base
				switch {
				case sent == 0:
					if err := s.c.write(ctx, s.in, []byte("\n")); err != nil {
						return "", false, err
					}
					base, sent = k, 1
				case got > sent:
					return "", false, fmt.Errorf("%w: %s: the prompt cannot be told from the banner", ErrHandshake, s.c.addr)
				case got >= 1:
					return tail, sent == 2 && got == 1, nil
				case sent == 1:
					if err := s.c.write(ctx, s.in, []byte("\n")); err != nil {
						return "", false, err
					}
					sent, retriedAt = 2, time.Now()
				case time.Since(retriedAt) >= learnPatience*s.quiet:
					return "", false, fmt.Errorf("%w: %s: the device does not answer an empty line with its prompt", ErrHandshake, s.c.addr)
				}
			}
		}
		var err error
		if len(buf) > 0 {
			quiet, err = s.waitQuiet(ctx, s.quiet)
		} else {
			err = s.out.wait(ctx)
		}
		if err != nil {
			return "", false, callError(ctx, s.c)
		}
	}
}

// promptUnit is the prompt a last line is: the line itself, or the shortest
// text it repeats that the detector takes for a prompt (a device that does
// not echo an empty line writes its prompt twice on one line). "" if the
// line is no prompt.
func promptUnit(line string, detect *regexp.Regexp) string {
	if line == "" || len(line) > maxPromptLine {
		return ""
	}
	for l := 1; l <= len(line); l++ {
		if len(line)%l != 0 || line != strings.Repeat(line[:l], len(line)/l) {
			continue
		}
		if detect.MatchString(line[:l]) {
			return line[:l]
		}
	}
	return ""
}

// countPrompts is how many times buf, lines and the unterminated last
// line, holds prompt (a line of it repeated counts each repeat).
func countPrompts(buf []byte, prompt string) int {
	n := 0
	for _, line := range strings.Split(string(buf), "\n") {
		n += repeats(strings.TrimRight(line, "\r"), prompt)
	}
	return n
}

// read collects the output of the command just sent, up to the prompt.
//
// The end of the output is found by counting. A line that is the prompt
// does not end it by itself, since output can hold such a line: the first
// time the prompt stands at the end an empty line is typed ahead, and each
// of those makes the device print the prompt once more. The output is over
// when the prompt has been seen 1 + (empty lines sent) times, the last one
// at the end, and nothing more arrives for the quiet period. More prompts
// than that, or output after the last, is ErrProtocol. The lines between
// the first prompt and the second are what the device prints before every
// prompt ('{master:0}' on Junos switches); they are dropped from the end
// of the output too.
//
// A profile with two prompts (Junos: operational and configure) counts
// each one apart, and the prompt that stands at the end is the one that
// counts: the output is over when that one has been seen 1 + (empty lines
// sent) times. A line of the other prompt in the middle of the output (a
// banner or a message that looks like it) is output, and one at the end
// that the device does not repeat when the empty line is typed ahead is
// not a prompt: the device's own prompt then stands at the end, or the
// counts disagree (ErrProtocol). When the prompt that ended the output is
// the other mode's, the session is in that mode from then on. A prompt
// line is never the echo of the command.
//
// A more-prompt at the end that stays for a quiet period is answered with
// a space, and the count starts again (the more-prompt takes the line that
// was typed ahead).
func (s *shell) read(ctx context.Context, cmd string, carry []byte, area []string, late bool) (string, error) {
	o := outBuf{prev: -1, prompt: s.prompt, alt: s.alt, echo: strings.TrimSpace(cmd), area: area, late: late}
	sent := 0
	erase := 0
	seenErased := 0 // end of the last typed-ahead-key artifact seen
	quiet := false
	for {
		ch := s.out.take()
		data := ch.data
		if carry != nil {
			data, carry = append(carry, data...), nil
		}
		if ch.overflow || len(o.b)+len(data) > MaxOutput {
			return "", ErrOutputTooLarge
		}
		if len(data) > 0 {
			quiet = false
		}
		if erase > 0 {
			data, erase = skipErase(data, erase)
		}
		o.add(data)
		// A more-prompt that took the typed-ahead line as its key: the
		// line is gone and the count starts again.
		if erase == 0 && len(data) > 0 {
			from := max(len(o.b)-len(data)-128, 0)
			if m := rePagerErased.FindIndex(o.b[from:]); m != nil && from+m[1] > seenErased {
				seenErased = from + m[1]
				o.reset()
				sent = 0
			}
		}

		tail, short := o.tail()
		pager := short && rePager.MatchString(tail)
		// k is the prompt at the end (the session's or the other mode's).
		k := -1
		if short {
			k = o.at(tail)
		}
		atPrompt := k >= 0
		total := 0
		if atPrompt {
			total = o.count(k)
		}
		switch {
		case pager && quiet:
			o.b = o.b[:o.line]
			o.reset()
			sent = 0
			erase = 1
			seenErased = min(seenErased, len(o.b))
			if err := s.c.write(ctx, s.in, []byte(" ")); err != nil {
				return "", err
			}
		case pager:
		case atPrompt && sent == 0:
			if err := s.c.write(ctx, s.in, []byte("\n")); err != nil {
				return "", err
			}
			sent = 1
		case atPrompt && total > 1+sent:
			return "", s.errInconsistent("the prompt was seen more often than commands were sent")
		case atPrompt && total == 1+sent && quiet:
			if k == 1 {
				// The command changed the mode: the session is in it.
				s.prompt, s.alt = s.alt, s.prompt
			}
			return s.body(&o, k), nil
		}
		quiet = false
		if ch.closed {
			return "", s.closedOrCtx(ctx)
		}
		var err error
		if pager || (atPrompt && total == 1+sent) {
			quiet, err = s.waitQuiet(ctx, s.pageOrSettle(pager))
		} else {
			err = s.out.wait(ctx)
		}
		if err != nil {
			return "", callError(ctx, s.c)
		}
	}
}

// pageOrSettle is the silence to wait for: a more-prompt is answered after
// a fraction of the quiet period (a device that pages is waiting for the
// key), the end of the output after all of it.
func (s *shell) pageOrSettle(pager bool) time.Duration {
	if pager {
		return max(s.quiet/5, 10*time.Millisecond)
	}
	return s.quiet
}

// body is the output up to the first prompt (k: 0 the session's, 1 the
// other mode's), less the lines the device prints before a prompt. The
// location line of a configure mode ('{master:0}[edit]') is output and is
// kept even when the device prints it before every prompt.
func (s *shell) body(o *outBuf, k int) string {
	hits := o.hits
	if k == 1 {
		hits = o.altHits
	}
	start := o.line
	if len(hits) > 0 {
		start = hits[0].start
	}
	text := rePagerErased.ReplaceAllString(normalise(string(o.b[:start])), "")
	if o.late {
		text = o.dropLate(text)
	}
	// What the device printed between its first prompt and its second
	// (the answer to the empty line, less the echo) it prints before every
	// prompt.
	var extras []string
	if len(hits) > 0 {
		end := o.line
		if len(hits) > 1 {
			end = hits[1].start
		}
		first := hits[0].start
		mid := normalise(string(o.b[first:end]))
		_, mid, _ = strings.Cut(mid, "\n") // the prompt line itself
		for _, l := range strings.Split(mid, "\n") {
			if t := strings.TrimSpace(l); t != "" && !LocationLine(t) {
				extras = append(extras, l)
			}
		}
	}
	s.area, s.areaOK = slices.Clone(extras), len(hits) > 0
	// The location line stands last, right before the prompt: it is set
	// aside while the lines before it are trimmed, and put back.
	keep := ""
	if t := strings.TrimSuffix(text, "\n"); t != "" {
		j := strings.LastIndexByte(t, '\n')
		if LocationLine(strings.TrimSpace(t[j+1:])) {
			keep = text[j+1:]
			text = text[:j+1]
		}
	}
	for i := len(extras) - 1; i >= 0; i-- {
		trimmed := strings.TrimSuffix(text, "\n")
		j := strings.LastIndexByte(trimmed, '\n')
		if trimmed[j+1:] != extras[i] || trimmed == "" {
			break
		}
		if j < 0 {
			text = ""
		} else {
			text = trimmed[:j+1]
		}
	}
	return text + keep
}

// dropLate takes the late answer to an empty line off the start of text, the
// output up to the first prompt, and leaves the echo of the command in its
// place. The device printed that answer (its line break, the line it
// prints before every prompt, and its prompt) before it read the command,
// so it stands in front of the echo, and the prompt shares its line with
// the echo: 'alice@rtr1> configure exclusive'. Only that is dropped: lines a
// device prints in front of a prompt (staleLine), then the prompt, once or
// more, followed by exactly the command sent. Any other line in front, or
// any other text after the prompt, is output and stays, and so does the
// same line later in the output.
func (o *outBuf) dropLate(text string) string {
	if o.echo == "" {
		return text
	}
	rest, first := text, true
	for {
		line, more, nl := strings.Cut(rest, "\n")
		if !nl {
			return text
		}
		t := strings.TrimSpace(line)
		if first && t == o.echo {
			return text // the echo, as it should be
		}
		if cmd, ok := o.afterPrompt(line); ok {
			if strings.TrimSpace(cmd) != o.echo {
				return text
			}
			return o.echo + "\n" + more
		}
		if !staleLine(line, o.area) {
			return text
		}
		rest, first = more, false
	}
}

// afterPrompt is what stands on line after the prompt (or the other mode's,
// or either of them more than once); ok is false when the line does not
// start with one.
func (o *outBuf) afterPrompt(line string) (string, bool) {
	line = strings.TrimRight(line, "\r")
	found := false
	for line != "" {
		cut := false
		for _, p := range []string{o.prompt, o.alt} {
			if p != "" && strings.HasPrefix(line, p) {
				line, cut, found = line[len(p):], true, true
				break
			}
		}
		if !cut {
			break
		}
	}
	return line, found
}

// stripEcho drops the echo of cmd from the start of body: the first line
// when it is the command, or, for a command longer than the terminal is
// wide, the lines the device wrote it in (see wrappedEcho).
func stripEcho(body, cmd string) string {
	first, rest, _ := strings.Cut(body, "\n")
	if strings.TrimSpace(first) == strings.TrimSpace(cmd) {
		return rest
	}
	if rest, ok := wrappedEcho(body, strings.TrimSpace(cmd)); ok {
		return rest
	}
	return body
}

// minWrappedCmd is the shortest command whose echo is looked for in pieces:
// a terminal is 80 columns wide, less the prompt.
const minWrappedCmd = 40

// wrappedEcho drops from the start of body the echo of a command that was
// longer than the terminal is wide. A device (IOS) scrolls such a line as it
// echoes it: the first lines are the start of the command, cut where the
// line ran out, and then a '$' and the rest of it, with backspaces and
// carriage returns (dropped by normalise) in between. The echo is the lines
// at the start of body that, cleaned of control characters, are pieces of cmd
// (a '$' marks where the display was cut), up to the line whose last piece
// ends cmd, when the first line is the start of cmd. Anything else is output and body is
// left as it is (ok false).
func wrappedEcho(body, cmd string) (string, bool) {
	if len(cmd) < minWrappedCmd {
		return body, false
	}
	lines := strings.SplitAfter(body, "\n")
	n, ended := 0, false
	for i, l := range lines {
		pieces := echoPieces(strings.TrimRight(l, "\n"), cmd)
		if len(pieces) == 0 || i == 0 && (len(pieces[0]) < 8 || !strings.HasPrefix(cmd, pieces[0])) {
			break
		}
		n = i + 1
		if p := pieces[len(pieces)-1]; len(p) >= 3 && strings.HasSuffix(cmd, p) {
			ended = true // the last piece ends the command: what follows is output
			break
		}
	}
	if n == 0 || !ended {
		return body, false
	}
	return strings.Join(lines[n:], ""), true
}

// echoPieces are the pieces of cmd a line of its echo holds, none when the
// line is not made only of pieces of cmd.
func echoPieces(line, cmd string) []string {
	t := strings.TrimSpace(cleanTerminal(line))
	if t == "" {
		return nil
	}
	if strings.Contains(cmd, t) {
		return []string{t}
	}
	var out []string
	for _, p := range strings.Split(t, "$") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		if !strings.Contains(cmd, p) {
			return nil
		}
		out = append(out, p)
	}
	return out
}

var reEscape = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// cleanTerminal is the text a terminal would show for line: a backspace moves
// the cursor back and the next character overwrites, the other control
// characters and the escape sequences are dropped.
func cleanTerminal(line string) string {
	var row []rune
	cur := 0
	for _, r := range reEscape.ReplaceAllString(line, "") {
		switch {
		case r == '\b':
			cur = max(cur-1, 0)
		case r == '\r':
			cur = 0
		case unicode.IsControl(r):
		case cur < len(row):
			row[cur] = r
			cur++
		default:
			row = append(row, r)
			cur++
		}
	}
	return string(row)
}
