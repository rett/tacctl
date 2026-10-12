package devssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// The terminal a TermSession asks for: what a menu-driven device (a WTI
// console server) paints its screens for.
const (
	termType = "vt100"
	termRows = 24
	termCols = 80
)

// maxSend is the most one Send writes; a menu is driven by short key
// sequences, and a pasted block (a list of firewall rules) is a few KiB.
const maxSend = 64 << 10

// maxStringSeq is the most a string-type escape sequence (an OSC or a DCS,
// ended by BEL or ESC \) swallows before the stream is taken for text
// again: a device that never terminates one must not hide what follows it.
const maxStringSeq = 4096

// evalWhole is the screen size up to which the done predicate runs after
// every arrival; past it, only when the screen has doubled since the last
// run, so that a device streaming megabytes costs a linear amount of work
// (a menu screen is a few KiB).
const evalWhole = 1 << 20

// TermSession is a terminal on a menu-driven device: a pty (vt100, 80x24)
// with a shell channel, driven by keys and read as whole screens. Unlike a
// CLISession it has no prompt to count and refuses nothing a menu needs:
// ESC and '<' '>' pass through Send, and the end of a screen is whatever
// the caller's predicate says it is, or the device going quiet. It is the
// transport of a table-driven reader (one declared page after another), not
// a place for conversation.
//
// Calls are serialised; Close is the exception and may be called at any
// time, from any goroutine, and sends nothing.
//
// What a screen is. Expect returns the text the device printed since the
// last Send, in order, as plain lines ended with '\n' (the line still being
// written is the last, without one): escape sequences are removed, CRLF is
// one newline, a bare carriage return moves back to the start of the line
// so that what is printed over it replaces it (the erase of a pager prompt
// leaves blanks), backspace steps back, BEL and the other control bytes
// are dropped, a tab is a blank, 'erase to end of line' truncates the line
// and the cursor-positioning and clear-screen sequences start a new line.
// That is all of vt100 this takes: a device that repaints whole screens
// has each paint follow the one before in the text, and the page a caller
// reads is its last (or, for a pager, each one in turn). The device's echo
// of what was typed, when it echoes, is part of the text.
//
// Send starts a new screen: what the device sent and Expect has not
// returned is discarded, so that the text of one answer is never mixed
// into the next; an Expect that returned on its predicate saw the screen
// it was waiting for and the rest of that paint (a cursor move) is not
// needed. A second Expect with no Send between continues the same screen.
//
// Rules for a driver over it (the WTI reader of wti-interface.md section
// 8; this package knows no vendor):
//
//   - Send what a page's table row lists, never a conversation. Keys go as
//     typed on the unit: '/N' CR for a page, a number CR for an item, ESC
//     for 'return to previous menu', '<' '>' to page a list. Never type
//     into a prompt that takes text, a number or a secret in a read, and
//     do not log a screen: pages print community strings and the secret
//     prompt prints its value in clear.
//   - A pager answers itself and is never left waiting: 'Enter: SPACE for
//     page, ENTER for line' (a help screen) is answered with SPACE, and
//     '<CR> for more ports, <ESC> to quit' (a status list) with ESC once
//     the part wanted is read. A menu page is complete when its footer
//     ('Enter: #<CR> to change' ... or '<ESC> to return to previous menu')
//     has been seen: the predicate is the footer, and Expect returns on
//     it; an unexpected title is an abort, not a retry.
//   - Expect with a nil predicate, or one that stays false, returns after
//     the quiet period (Target.Quiet) once output has arrived, with what
//     arrived: it is the fallback that keeps an unexpected screen from
//     costing the whole deadline, and the caller checks the text itself. A
//     device that has sent nothing at all costs the context's deadline
//     (ErrTimeout).
//   - Leave a top-level menu with ESC and the unit writes its whole
//     configuration to flash, another person's unsaved live edit included.
//     A read goes back to the top-level page, and Close ends it there:
//     Close is the tested-safe exit and sends nothing.
//
// Errors are the package's: ErrTimeout or context.Canceled when a context
// ends (the session is then closed: what the device is showing is no
// longer known), ErrClosed when the device ends the channel, even in the
// middle of a screen (the partial screen is never returned as a result),
// ErrOutputTooLarge past MaxOutput since the last Send. Their text names
// the device and the failure, never the screen.
type TermSession interface {
	// Send types p: printable text, CR (and LF) and ESC. The other control
	// bytes (Ctrl-C, Ctrl-D, tab, backspace, DEL, NUL) and invalid UTF-8
	// are refused before anything is written, as is an empty or a longer
	// than 64 KiB p.
	Send(ctx context.Context, p []byte) error
	// Expect collects the screen. It returns, in the order tried: as soon
	// as done reports true for the screen so far (done may be nil), or
	// when the device has been silent for the quiet period after output
	// arrived (the screen then may be incomplete: the caller checks), or
	// with an error. done runs on the caller's goroutine, on text that
	// can hold secrets; it must not keep it.
	Expect(ctx context.Context, done func(screen string) bool) (string, error)
	// Close closes the channel and sends nothing. Later calls, and a call
	// in flight, return ErrClosed.
	Close() error
}

// Terminal opens a terminal session (a pty of 80x24, then a shell) and
// returns without reading: the banner and the first prompt are what the
// first Expect collects. ctx and the connect timeout bound only the
// opening; each call has its own context.
func (c *Client) Terminal(ctx context.Context) (TermSession, error) {
	if err := c.ctxErr(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
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
		if err := s.RequestPty(termType, termRows, termCols, ssh.TerminalModes{}); err != nil {
			_ = s.Close()
			return fmt.Errorf("%w: the device refused a terminal", ErrClosed)
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
	return &terminal{c: c, sess: sess, in: in, out: out, quiet: c.quiet}, nil
}

// terminal is one shell channel on a pty.
type terminal struct {
	c     *Client
	sess  *ssh.Session
	in    io.Writer
	out   *sink
	quiet time.Duration

	mu     sync.Mutex // serialises Send and Expect; guards scr and total
	scr    screen
	total  int // bytes received since the last Send
	broken atomic.Bool
}

// Close closes the channel only: closing the stdin pipe races with a write
// in flight inside x/crypto/ssh, and the channel's close is all that the
// device is told.
func (t *terminal) Close() error {
	if t.broken.Swap(true) {
		return nil // closed already, by a call or by an earlier Close
	}
	if err := t.sess.Close(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// fail closes the session and returns err.
func (t *terminal) fail(err error) error {
	t.broken.Store(true)
	_ = t.sess.Close()
	return err
}

// usable is nil when a call may proceed.
func (t *terminal) usable(ctx context.Context) error {
	if t.broken.Load() {
		return fmt.Errorf("%w: %s", ErrClosed, t.c.addr)
	}
	if err := t.c.ctxErr(); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return t.fail(callError(ctx, t.c))
	}
	return nil
}

// closedErr is the error of an output channel that ended.
func (t *terminal) closedErr(ctx context.Context) error {
	if ctx.Err() != nil || t.c.ctxErr() != nil {
		return t.fail(callError(ctx, t.c))
	}
	return t.fail(fmt.Errorf("%w: %s", ErrClosed, t.c.addr))
}

// checkTermInput refuses what a menu is never typed and what has an effect
// of its own on a terminal line (interrupt, end of file, erase).
func checkTermInput(p []byte) error {
	switch {
	case len(p) == 0:
		return errors.New("devssh: nothing to send")
	case len(p) > maxSend:
		return errors.New("devssh: too much to send at once")
	case !utf8.Valid(p):
		return errors.New("devssh: input is not valid UTF-8")
	}
	for _, r := range string(p) {
		if r == '\r' || r == '\n' || r == 0x1b {
			continue
		}
		if unicode.IsControl(r) {
			return errors.New("devssh: a control character other than CR, LF and ESC cannot be sent")
		}
	}
	return nil
}

func (t *terminal) Send(ctx context.Context, p []byte) error {
	if err := checkTermInput(p); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(ctx); err != nil {
		return err
	}
	// A new screen: what is left of the last one is not this answer's.
	switch ch := t.out.take(); {
	case ch.overflow:
		return t.fail(ErrOutputTooLarge)
	case ch.closed:
		return t.closedErr(ctx)
	}
	t.scr.reset()
	t.total = 0
	if err := t.c.write(ctx, t.in, p); err != nil {
		return t.fail(err)
	}
	return nil
}

func (t *terminal) Expect(ctx context.Context, done func(screen string) bool) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.usable(ctx); err != nil {
		return "", err
	}
	first, quiet, nextEval := true, false, 0
	for {
		ch := t.out.take()
		if ch.overflow || t.total+len(ch.data) > MaxOutput {
			return "", t.fail(ErrOutputTooLarge)
		}
		if len(ch.data) > 0 {
			t.total += len(ch.data)
			t.scr.write(ch.data)
			quiet = false
		}
		if done != nil && t.total > 0 && (first || len(ch.data) > 0) {
			if n := t.scr.size(); n <= evalWhole || n >= nextEval {
				text := t.scr.String()
				nextEval = 2 * len(text)
				if done(text) {
					return text, nil
				}
			}
		}
		first = false
		if ch.closed {
			return "", t.closedErr(ctx)
		}
		if quiet {
			return t.scr.String(), nil
		}
		var err error
		if t.total > 0 {
			quiet, err = t.waitQuiet(ctx)
		} else {
			err = t.out.wait(ctx)
		}
		if err != nil {
			return "", t.fail(callError(ctx, t.c))
		}
	}
}

// waitQuiet waits for new output, the context, or the quiet period (quiet
// is then true).
func (t *terminal) waitQuiet(ctx context.Context) (quiet bool, err error) {
	tm := time.NewTimer(t.quiet)
	defer tm.Stop()
	select {
	case <-t.out.notify:
		return false, nil
	case <-tm.C:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}

// The states of the escape-sequence scanner.
const (
	stText     = iota
	stEsc      // after ESC
	stEscInter // ESC and intermediate bytes (ESC ( B)
	stCSI      // ESC [ and its parameters
	stString   // OSC, DCS, PM, APC: up to BEL or ESC \
	stStringEsc
)

// screen turns the byte stream of a terminal into plain lines, one byte at
// a time, so that a sequence split over two reads is no problem. The
// cursor is always inside the line (col <= len(line)): nothing is padded,
// so the text is never larger than what the device sent.
type screen struct {
	text   []byte // finished lines, each ended with '\n'
	line   []byte // the line being written
	col    int    // the cursor's column within line
	state  int
	params []byte // the parameters of the CSI in progress
	strLen int    // bytes swallowed by the string sequence in progress
}

func (s *screen) reset() {
	*s = screen{text: s.text[:0], line: s.line[:0], params: s.params[:0]}
}

func (s *screen) size() int { return len(s.text) + len(s.line) }

// String is the finished lines and the line in progress.
func (s *screen) String() string {
	b := make([]byte, 0, s.size())
	b = append(b, s.text...)
	b = append(b, s.line...)
	return string(b)
}

func (s *screen) write(p []byte) {
	for _, b := range p {
		s.put(b)
	}
}

// commit finishes the line.
func (s *screen) commit() {
	s.text = append(s.text, s.line...)
	s.text = append(s.text, '\n')
	s.line = s.line[:0]
	s.col = 0
}

// newLine is what a cursor jump (home, a row, a clear) is to the text: the
// next thing printed does not continue the line.
func (s *screen) newLine() {
	if len(s.line) > 0 {
		s.commit()
	}
	s.col = 0
}

// char writes b at the cursor, over what is there.
func (s *screen) char(b byte) {
	if s.col < len(s.line) {
		s.line[s.col] = b
	} else {
		s.line = append(s.line, b)
	}
	s.col++
}

func (s *screen) put(b byte) {
	switch s.state {
	case stText:
		switch {
		case b == 0x1b:
			s.state = stEsc
		case b == '\n':
			s.commit()
		case b == '\r':
			s.col = 0
		case b == '\b':
			if s.col > 0 {
				s.col--
			}
		case b == '\t':
			s.char(' ')
		case b < 0x20 || b == 0x7f:
			// BEL, NUL, shifts, DEL: no text.
		default:
			s.char(b)
		}
	case stEsc:
		switch {
		case b == '[':
			s.state, s.params = stCSI, s.params[:0]
		case b == ']' || b == 'P' || b == 'X' || b == '^' || b == '_':
			s.state, s.strLen = stString, 0
		case b >= 0x20 && b <= 0x2f:
			s.state = stEscInter
		case b == 0x1b:
		default:
			s.state = stText // a two-byte sequence (ESC 7, ESC =, ESC M)
		}
	case stEscInter:
		if b < 0x20 || b > 0x2f {
			s.state = stText
		}
	case stCSI:
		switch {
		case b >= 0x20 && b <= 0x3f:
			if len(s.params) < 64 {
				s.params = append(s.params, b)
			}
		case b >= 0x40 && b <= 0x7e:
			s.state = stText
			s.csi(b)
		case b == 0x1b:
			s.state = stEsc
		}
	case stString:
		s.strLen++
		switch {
		case b == 0x07:
			s.state = stText
		case b == 0x1b:
			s.state = stStringEsc
		case s.strLen > maxStringSeq:
			s.state = stText
		}
	case stStringEsc:
		if b == '\\' {
			s.state = stText
			return
		}
		s.state = stEsc
		s.put(b)
	}
}

// paramN is the first numeric parameter of the CSI in progress, def when
// it has none.
func (s *screen) paramN(def int) int {
	n, seen := 0, false
	for _, c := range s.params {
		if c < '0' || c > '9' {
			break
		}
		seen = true
		if n < 1<<16 {
			n = n*10 + int(c-'0')
		}
	}
	if !seen {
		return def
	}
	return n
}

// csi acts on a finished control sequence: the few that change what the
// text is, and nothing for colour, modes and the rest.
func (s *screen) csi(final byte) {
	switch final {
	case 'K': // erase in line
		switch s.paramN(0) {
		case 0:
			s.line = s.line[:s.col]
		case 1:
			for i := 0; i < s.col && i < len(s.line); i++ {
				s.line[i] = ' '
			}
		case 2:
			s.line, s.col = s.line[:0], 0
		}
	case 'D': // cursor back
		s.col = max(s.col-s.paramN(1), 0)
	case 'G': // column
		s.col = min(max(s.paramN(1)-1, 0), len(s.line))
	case 'C': // cursor forward: a gap between two words
		if n := len(s.line); n > 0 && s.col == n && s.line[n-1] != ' ' {
			s.char(' ')
		}
	case 'H', 'f', 'J', 'A', 'B', 'E', 'F', 'd':
		s.newLine()
	}
}
