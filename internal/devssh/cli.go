package devssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"golang.org/x/crypto/ssh"
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

// maxPromptLine is the longest last line examined as a prompt or a more-
// prompt; a longer one is output.
const maxPromptLine = 512

// CLISession runs commands on a device's command line. Run is safe for
// concurrent use but commands run one after the other; Close does not wait
// for a command in flight.
//
// A session is for show-only use: a shell session finds the end of a
// command's output by the prompt, so a command that changes the prompt
// (configure, a mode change) is never seen to end and Run waits for its
// context.
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
	Close() error
}

// CLIOption changes how CLI opens a session.
type CLIOption func(*cliConfig)

type cliConfig struct {
	mode Mode
	pty  bool
}

// WithMode selects the channel type instead of the vendor's.
func WithMode(m Mode) CLIOption { return func(c *cliConfig) { c.mode = m } }

// WithPTY has a shell session request a pseudo-terminal (vt100, 200
// columns), for a device that gives no command line without one.
func WithPTY() CLIOption { return func(c *cliConfig) { c.pty = true } }

// profile is a vendor's command line.
type profile struct {
	// prompt matches a line that may be the device waiting for a command
	// (the last line of the output, without a trailing newline).
	prompt *regexp.Regexp
	mode   Mode
}

var profiles = map[string]profile{
	VendorJuniper: {prompt: regexp.MustCompile(`^\S+@\S+> $`), mode: ModeExec},
	VendorCisco:   {prompt: regexp.MustCompile(`^\S+[>#]$`), mode: ModeShell},
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
	if cfg.mode == ModeDefault {
		cfg.mode = prof.mode
	}
	if cfg.mode == ModeExec {
		return &execSession{c: c}, nil
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.timeout)
	defer cancel()
	return c.openShell(ctx, prof, cfg.pty)
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
	c  *Client
	mu sync.Mutex
}

func (e *execSession) Close() error { return nil }

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
	sess  *ssh.Session
	in    io.Writer
	out   *sink
	prof  profile
	quiet time.Duration

	mu     sync.Mutex // serialises Run; guards prompt
	prompt string     // the device's prompt line, learned at login
	broken atomic.Bool
}

// openShell starts the shell channel and learns the prompt.
func (c *Client) openShell(ctx context.Context, prof profile, pty bool) (*shell, error) {
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
		if pty {
			if err := s.RequestPty("vt100", 0, 200, ssh.TerminalModes{}); err != nil {
				_ = s.Close()
				return fmt.Errorf("%w: the device refused a terminal", ErrClosed)
			}
		}
		if err := s.Shell(); err != nil {
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
	sh := &shell{c: c, sess: sess, in: in, out: out, prof: prof, quiet: c.quiet}
	unhook := context.AfterFunc(ctx, func() { _ = sess.Close() })
	prompt, err := sh.learn(ctx)
	unhook()
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	sh.prompt = prompt
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

func (s *shell) Run(ctx context.Context, cmd string) (string, error) {
	if err := checkShellCommand(cmd); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
	// would be taken for the next command's.
	if c := s.out.take(); len(c.data) > 0 || c.overflow {
		return fail(fmt.Errorf("%w: %s: output between commands", ErrProtocol, s.c.addr))
	}
	if err := s.c.write(ctx, s.in, []byte(cmd+"\n")); err != nil {
		return fail(err)
	}
	body, err := s.read(ctx)
	if err != nil {
		return fail(err)
	}
	return stripEcho(body, cmd), nil
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
		if n := repeats(strings.TrimRight(string(o.b[o.line:end]), "\r"), o.prompt); n > 0 {
			o.hits = append(o.hits, hit{o.line, n})
		}
		off += i + 1
		o.prev, o.line = o.line, base+off
	}
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
func (o *outBuf) prompts() int {
	n := 0
	for _, h := range o.hits {
		n += h.n
	}
	if t, ok := o.tail(); ok {
		n += repeats(t, o.prompt)
	}
	return n
}

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
// been seen once more for each empty line it answered; fewer (the device
// flushed what was typed ahead at login) is retried once, more is
// ambiguous, and either is ErrHandshake.
func (s *shell) learn(ctx context.Context) (string, error) {
	var buf []byte
	want, retried, quiet := 0, false, false
	for {
		ch := s.out.take()
		if ch.overflow || len(buf)+len(ch.data) > maxLoginOutput {
			return "", fmt.Errorf("%w: %s: the login output is too long for a banner", ErrHandshake, s.c.addr)
		}
		buf = append(buf, ch.data...)
		if len(ch.data) > 0 {
			quiet = false
		}
		if ch.closed {
			return "", s.closedOrCtx(ctx)
		}
		if quiet && len(buf) > 0 {
			quiet = false
			tail := string(buf[bytes.LastIndexByte(buf, '\n')+1:])
			tail = promptUnit(strings.TrimRight(tail, "\r"), s.prof.prompt)
			if tail != "" {
				k := countPrompts(buf, tail)
				switch {
				case want == 0:
					if err := s.c.write(ctx, s.in, []byte("\n")); err != nil {
						return "", err
					}
					want = k + 1
				case k == want:
					return tail, nil
				case k > want:
					return "", fmt.Errorf("%w: %s: the prompt cannot be told from the banner", ErrHandshake, s.c.addr)
				case retried:
					return "", fmt.Errorf("%w: %s: the device does not answer an empty line with its prompt", ErrHandshake, s.c.addr)
				default:
					retried = true
					if err := s.c.write(ctx, s.in, []byte("\n")); err != nil {
						return "", err
					}
					want = k + 1
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
			return "", callError(ctx, s.c)
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
// A more-prompt at the end that stays for a quiet period is answered with
// a space, and the count starts again (the more-prompt takes the line that
// was typed ahead).
func (s *shell) read(ctx context.Context) (string, error) {
	o := outBuf{prev: -1, prompt: s.prompt}
	sent := 0
	erase := 0
	seenErased := 0 // end of the last typed-ahead-key artifact seen
	quiet := false
	for {
		ch := s.out.take()
		data := ch.data
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
				o.hits = nil
				sent = 0
			}
		}

		tail, short := o.tail()
		pager := short && rePager.MatchString(tail)
		total := o.prompts()
		atPrompt := short && repeats(tail, s.prompt) > 0
		switch {
		case pager && quiet:
			o.b = o.b[:o.line]
			o.hits = nil
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
			return s.body(&o), nil
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

// body is the output up to the first prompt, less the lines the device
// prints before a prompt.
func (s *shell) body(o *outBuf) string {
	start := o.line
	if len(o.hits) > 0 {
		start = o.hits[0].start
	}
	text := rePagerErased.ReplaceAllString(normalise(string(o.b[:start])), "")
	// What the device printed between its first prompt and its second
	// (the answer to the empty line, less the echo) it prints before every
	// prompt.
	var extras []string
	if len(o.hits) > 0 {
		end := o.line
		if len(o.hits) > 1 {
			end = o.hits[1].start
		}
		first := o.hits[0].start
		mid := normalise(string(o.b[first:end]))
		_, mid, _ = strings.Cut(mid, "\n") // the prompt line itself
		for _, l := range strings.Split(mid, "\n") {
			if t := strings.TrimSpace(l); t != "" {
				extras = append(extras, l)
			}
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
	return text
}

// stripEcho drops the first line when it is the command the device echoed.
func stripEcho(body, cmd string) string {
	first, rest, _ := strings.Cut(body, "\n")
	if strings.TrimSpace(first) == strings.TrimSpace(cmd) {
		return rest
	}
	return body
}
