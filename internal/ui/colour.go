package ui

import (
	"bytes"
	"io"
	"strings"
)

// Colour decides, once per process, which output streams are styled. get
// reads an environment variable (os.Getenv in production, a map in tests);
// ttyOut and ttyErr say whether stdout and stderr are terminals. The
// order is fixed:
//
//  1. TACCTL_COLOR=always or never (any letter case) wins for both streams.
//  2. Else a non-empty NO_COLOR means never (https://no-color.org).
//  3. Else a stream is coloured when it is a terminal and TERM is neither
//     empty nor "dumb".
//
// Any other value of TACCTL_COLOR is ignored. Colour is pure: it reads
// nothing but its arguments.
func Colour(get func(string) string, ttyOut, ttyErr bool) (out, err bool) {
	switch strings.ToLower(strings.TrimSpace(get("TACCTL_COLOR"))) {
	case "always":
		return true, true
	case "never":
		return false, false
	}
	if get("NO_COLOR") != "" {
		return false, false
	}
	term := get("TERM")
	if term == "" || term == "dumb" {
		return false, false
	}
	return ttyOut, ttyErr
}

// esc is the escape byte that opens every terminal control sequence.
const esc = 0x1b

// maxSeq bounds the sequence StripSGR holds back. A real SGR sequence is
// a few bytes; a longer run of parameter bytes is not one and is passed
// through, so a stream of garbage cannot grow the buffer without limit.
const maxSeq = 64

// flushAt is the size at which a Write's output is handed to the
// underlying writer before the rest of the input is scanned.
const flushAt = 32 << 10

// StripSGR returns a sink that writes to w everything written to it except
// SGR sequences, "ESC [ <digits, ';' and ':'> m", which it removes. Every
// other byte passes through unchanged, including the other CSI sequences
// (ESC[K, ESC[2A, ESC[J, ...), other escapes, and a lone ESC.
//
// A sequence split across two Writes is held until it completes, so the
// bytes of one sequence are never half written. A sequence that is still
// incomplete when Close is called is written to w as it is, not dropped.
// Close does not close w. The sink is not safe for concurrent use.
//
// Write returns len(p) and nil when w accepted what was kept. When w
// fails, Write returns 0 and w's error; the sink is not used after that.
func StripSGR(w io.Writer) io.WriteCloser {
	return &sgrStripper{w: w}
}

type sgrStripper struct {
	w       io.Writer
	pending []byte // a partial sequence, starting with ESC
	out     []byte // scratch for the kept bytes of one Write, reused
}

func (s *sgrStripper) Write(p []byte) (int, error) {
	n := len(p)
	// Fast path: nothing held back and no escape in p; hand p over
	// without copying it.
	if len(s.pending) == 0 && bytes.IndexByte(p, esc) < 0 {
		if n == 0 {
			return 0, nil
		}
		if _, err := s.w.Write(p); err != nil {
			return 0, err
		}
		return n, nil
	}
	s.out = s.out[:0]
	for len(p) > 0 {
		if len(s.pending) == 0 {
			i := bytes.IndexByte(p, esc)
			if i < 0 {
				s.out = append(s.out, p...)
				break
			}
			s.out = append(s.out, p[:i]...)
			s.pending = append(s.pending, esc)
			p = p[i+1:]
			continue
		}
		b := p[0]
		p = p[1:]
		switch {
		case len(s.pending) == 1:
			// Just seen ESC; only '[' continues a CSI sequence.
			if b == '[' {
				s.pending = append(s.pending, b)
				continue
			}
			s.out = append(s.out, esc)
			s.pending = s.pending[:0]
			if b == esc { // ESC ESC: the second may open a sequence
				s.pending = append(s.pending, esc)
			} else {
				s.out = append(s.out, b)
			}
		case b >= 0x20 && b <= 0x3f && len(s.pending) < maxSeq:
			// Parameter and intermediate bytes: keep collecting.
			s.pending = append(s.pending, b)
		case b >= 0x40 && b <= 0x7e:
			// Final byte: drop the sequence only when it is SGR.
			if b != 'm' || !sgrParams(s.pending[2:]) {
				s.out = append(s.out, s.pending...)
				s.out = append(s.out, b)
			}
			s.pending = s.pending[:0]
		default:
			// Not a CSI sequence after all (or too long): emit what was
			// held and reconsider b from the top.
			s.out = append(s.out, s.pending...)
			s.pending = s.pending[:0]
			if b == esc {
				s.pending = append(s.pending, esc)
			} else {
				s.out = append(s.out, b)
			}
		}
		if len(s.out) >= flushAt {
			if err := s.flush(); err != nil {
				return 0, err
			}
		}
	}
	if err := s.flush(); err != nil {
		return 0, err
	}
	return n, nil
}

// flush writes the kept bytes to the underlying writer.
func (s *sgrStripper) flush() error {
	if len(s.out) == 0 {
		return nil
	}
	_, err := s.w.Write(s.out)
	s.out = s.out[:0]
	return err
}

// Close writes a held, never-completed sequence (or a lone ESC) to the
// underlying writer unchanged. It is safe to call more than once.
func (s *sgrStripper) Close() error {
	if len(s.pending) == 0 {
		return nil
	}
	_, err := s.w.Write(s.pending)
	s.pending = s.pending[:0]
	return err
}

// sgrParams reports whether b, the bytes between "ESC [" and a final 'm',
// are the parameters of an SGR sequence: digits, ';' and ':' only.
func sgrParams(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && c != ';' && c != ':' {
			return false
		}
	}
	return true
}
