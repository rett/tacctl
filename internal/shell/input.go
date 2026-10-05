package shell

import (
	"bytes"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// The line editor is golang.org/x/term's Terminal. input is what it reads
// from: the terminal's bytes, rewritten so that the editor does what the
// shell needs.
//
//   - Ctrl-C ends the line as interrupted: the rest of what was read is
//     dropped, the terminal's pending input flushed, and the editor gets the
//     interrupt marker and Enter (the line is shown with '^C' and
//     discarded, not run and not recorded).
//   - Ctrl-Z and Ctrl-\ are dropped (there is no job control).
//   - Esc-b and Esc-f become the word moves the editor knows (Alt-Left and
//     Alt-Right).
//   - Inside a bracketed paste, newlines and tabs become spaces, other
//     control characters are dropped and the paste is cut at PasteMax
//     bytes, so a paste never runs anything by itself.
//   - While a Ctrl-R search is on, Backspace and Ctrl-G become search
//     markers, and any key the search does not take ends the search first.
//   - A read waits at most the idle time (errIdle) and returns errStop when
//     the shell was told to stop (a SIGTERM or SIGHUP).

// PasteMax is the most a bracketed paste adds to a line.
const PasteMax = 4096

// The markers input inserts for the editor's key callback: runes of the
// private-use area, which input drops when the terminal sends them.
const (
	markBackspace = '' // Backspace during a search
	markAccept    = '' // end the search, keep the match
	markCancel    = '' // end the search, back to the line before it
	markInterrupt = '' // Ctrl-C
)

var (
	errIdle = errors.New("idle timeout")
	errStop = errors.New("stopped by a signal")
)

var (
	seqPasteStart = []byte("\x1b[200~")
	seqPasteEnd   = []byte("\x1b[201~")
	seqWordLeft   = []byte("\x1b[1;3D")
	seqWordRight  = []byte("\x1b[1;3C")
)

// input reads the terminal fd for the editor and writes the editor's output.
type input struct {
	fd   int
	out  io.Writer
	idle time.Duration
	// wake is the read end of a pipe that becomes readable when the shell
	// must stop (-1: none).
	wake int
	ed   *editor

	pending []byte // rewritten bytes the editor has not read yet
	carry   []byte // the start of an escape sequence, waiting for its end
	paste   bool
	pasted  int
}

func (in *input) Write(p []byte) (int, error) { return in.out.Write(p) }

func (in *input) Read(p []byte) (int, error) {
	for len(in.pending) == 0 {
		raw, err := in.wait()
		if err != nil {
			return 0, err
		}
		in.pending = in.rewrite(raw)
	}
	n := copy(p, in.pending)
	in.pending = in.pending[n:]
	return n, nil
}

// wait polls the terminal (and the wake pipe) for at most the idle time and
// reads what is there.
func (in *input) wait() ([]byte, error) {
	ms := -1
	if in.idle > 0 {
		ms = int(in.idle / time.Millisecond)
	}
	fds := []unix.PollFd{{Fd: int32(in.fd), Events: unix.POLLIN}}
	if in.wake >= 0 {
		fds = append(fds, unix.PollFd{Fd: int32(in.wake), Events: unix.POLLIN})
	}
	for {
		n, err := unix.Poll(fds, ms)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errIdle
		}
		break
	}
	if len(fds) > 1 && fds[1].Revents != 0 {
		return nil, errStop
	}
	buf := make([]byte, 1024)
	n, err := unix.Read(in.fd, buf)
	if err == unix.EINTR || err == unix.EAGAIN {
		return nil, nil
	}
	if n <= 0 || err != nil {
		return nil, io.EOF
	}
	return buf[:n], nil
}

// rewrite turns the bytes read into what the editor gets.
func (in *input) rewrite(raw []byte) []byte {
	b := append(in.carry, raw...)
	in.carry = nil
	var out []byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if c != '\t' {
			in.ed.lastTab = false
		}
		// The private-use markers never come from the terminal.
		if c == 0xEE && i+2 < len(b) && b[i+1] == 0x80 && b[i+2] >= 0x80 && b[i+2] <= 0x83 {
			i += 2
			continue
		}
		if c == 0x1b {
			rest := b[i:]
			if partialEscape(rest) {
				in.carry = append([]byte(nil), rest...)
				break
			}
		}
		if in.paste {
			if bytes.HasPrefix(b[i:], seqPasteEnd) {
				out = append(out, seqPasteEnd...)
				in.paste = false
				i += len(seqPasteEnd) - 1
				continue
			}
			switch {
			case c == '\r' || c == '\n' || c == '\t':
				c = ' '
			case c < 0x20 || c == 0x7f:
				continue
			}
			if in.pasted >= PasteMax {
				continue
			}
			in.pasted++
			out = append(out, c)
			continue
		}
		if in.ed.searching {
			switch {
			case c == 0x7f || c == 0x08:
				out = appendRune(out, markBackspace)
				continue
			case c == 0x07: // Ctrl-G
				in.ed.searching = false
				out = appendRune(out, markCancel)
				continue
			case c == 0x03:
				in.ed.searching = false
				out = appendRune(out, markCancel)
			case c == 0x12 || c >= 0x20:
				out = append(out, c)
				continue
			default:
				in.ed.searching = false
				out = appendRune(out, markAccept)
			}
		}
		switch c {
		case 0x03: // Ctrl-C: the line ends here, the rest is dropped
			in.flush()
			return append(appendRune(out, markInterrupt), '\r')
		case 0x1a, 0x1c: // Ctrl-Z, Ctrl-\: no job control
			continue
		case 0x12: // Ctrl-R
			in.ed.searching = true
			out = append(out, c)
			continue
		case 0x1b:
			rest := b[i:]
			switch {
			case bytes.HasPrefix(rest, seqPasteStart):
				in.paste, in.pasted = true, 0
				out = append(out, seqPasteStart...)
				i += len(seqPasteStart) - 1
				continue
			case len(rest) >= 2 && rest[1] == 'b':
				out = append(out, seqWordLeft...)
				i++
				continue
			case len(rest) >= 2 && rest[1] == 'f':
				out = append(out, seqWordRight...)
				i++
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

// partialEscape reports whether b (which starts with Esc) may be the start
// of a sequence input rewrites and ends before it is complete.
func partialEscape(b []byte) bool {
	if len(b) == 1 {
		return true
	}
	for _, seq := range [][]byte{seqPasteStart, seqPasteEnd} {
		if len(b) < len(seq) && bytes.HasPrefix(seq, b) {
			return true
		}
	}
	return false
}

// flush drops what the terminal holds unread (tcflush TCIFLUSH) and the
// carried partial sequence.
func (in *input) flush() {
	in.carry = nil
	_ = unix.IoctlSetInt(in.fd, unix.TCFLSH, unix.TCIFLUSH)
}

func appendRune(b []byte, r rune) []byte { return utf8.AppendRune(b, r) }
