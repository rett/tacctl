package ui

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestColour(t *testing.T) {
	cases := []struct {
		name         string
		env          map[string]string
		ttyOut, ttyE bool
		out, err     bool
	}{
		{"terminals, xterm", map[string]string{"TERM": "xterm"}, true, true, true, true},
		{"only stdout a terminal", map[string]string{"TERM": "xterm"}, true, false, true, false},
		{"only stderr a terminal", map[string]string{"TERM": "xterm"}, false, true, false, true},
		{"pipes", map[string]string{"TERM": "xterm"}, false, false, false, false},
		{"TERM empty", nil, true, true, false, false},
		{"TERM dumb", map[string]string{"TERM": "dumb"}, true, true, false, false},
		{"NO_COLOR set", map[string]string{"TERM": "xterm", "NO_COLOR": "1"}, true, true, false, false},
		{"NO_COLOR empty is unset", map[string]string{"TERM": "xterm", "NO_COLOR": ""}, true, true, true, true},
		{"always into pipes", map[string]string{"TACCTL_COLOR": "always"}, false, false, true, true},
		{"always beats TERM dumb", map[string]string{"TACCTL_COLOR": "always", "TERM": "dumb"}, false, true, true, true},
		{"always beats NO_COLOR", map[string]string{"TACCTL_COLOR": "always", "NO_COLOR": "1"}, false, false, true, true},
		{"never on terminals", map[string]string{"TACCTL_COLOR": "never", "TERM": "xterm"}, true, true, false, false},
		{"never, any letter case", map[string]string{"TACCTL_COLOR": "NEVER"}, true, true, false, false},
		{"unknown value ignored", map[string]string{"TACCTL_COLOR": "auto", "TERM": "xterm"}, true, false, true, false},
		{"unknown value, NO_COLOR", map[string]string{"TACCTL_COLOR": "yes", "NO_COLOR": "1", "TERM": "xterm"}, true, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := Colour(envMap(c.env), c.ttyOut, c.ttyE)
			if out != c.out || err != c.err {
				t.Errorf("Colour = (%v, %v), want (%v, %v)", out, err, c.out, c.err)
			}
		})
	}
}

// strip runs the chunks through StripSGR, one Write each, and returns what
// reached the underlying writer after Close.
func strip(t *testing.T, chunks ...string) string {
	t.Helper()
	var b bytes.Buffer
	s := StripSGR(&b)
	for _, c := range chunks {
		n, err := s.Write([]byte(c))
		if err != nil || n != len(c) {
			t.Fatalf("Write(%q) = %d, %v", c, n, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestStripSGRRemovesSGR(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", "plain"},
		{"", ""},
		{"\033[0;32m[INFO]\033[0m ok\n", "[INFO] ok\n"},
		{"\033[1mbold\033[0m", "bold"},
		{"\033[m", ""},
		{"\033[38;5;196mx\033[0m", "x"},
		{"\033[38:2:1:2:3mx", "x"},
		{"a\033[1m\033[36mb", "ab"},
		{"\xe2\x9c\x93 \033[1mutf8\033[0m", "\xe2\x9c\x93 utf8"},
	}
	for _, c := range cases {
		if got := strip(t, c.in); got != c.want {
			t.Errorf("strip(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestStripSGRKeepsOtherEscapes(t *testing.T) {
	for _, in := range []string{
		"\033[K", "\033[2A", "\033[J", "\033[2K\r", "\033[H\033[2J",
		"\033[?25l", "\033[1;5H", "\033[3 q", "\033[1;2m3", // see below
		"\033]0;title\007", "\033(B", "\033=", "\033c",
		"a\033Mb", "\033\033", "\033[\n", "\033[1\n",
	} {
		want := in
		if in == "\033[1;2m3" { // a real SGR: removed, the digit stays
			want = "3"
		}
		if got := strip(t, in); got != want {
			t.Errorf("strip(%q) = %q, want %q", in, got, want)
		}
	}
	// SGR next to a kept sequence: only the SGR goes.
	if got := strip(t, "\033[1m\033[K\033[0m\033[2A"); got != "\033[K\033[2A" {
		t.Errorf("mixed = %q", got)
	}
	// An escape that opens nothing does not swallow the SGR after it.
	if got := strip(t, "\033\033[1mx"); got != "\033x" {
		t.Errorf("ESC ESC [1m = %q", got)
	}
}

func TestStripSGRSplitAcrossWrites(t *testing.T) {
	want := "ab"
	whole := "a\033[0;32mb"
	for i := 1; i < len(whole); i++ {
		if got := strip(t, whole[:i], whole[i:]); got != want {
			t.Errorf("split at %d: %q, want %q", i, got, want)
		}
	}
	// One byte at a time, with a kept sequence in the middle.
	in := "\033[1mx\033[2Ay\033[0m"
	var parts []string
	for i := range in {
		parts = append(parts, in[i:i+1])
	}
	if got := strip(t, parts...); got != "x\033[2Ay" {
		t.Errorf("byte at a time = %q", got)
	}
}

func TestStripSGRNothingHalfWritten(t *testing.T) {
	var b bytes.Buffer
	s := StripSGR(&b)
	if _, err := s.Write([]byte("a\033[0;3")); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "a" {
		t.Errorf("after the first write: %q, want %q", got, "a")
	}
	if _, err := s.Write([]byte("2mb")); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "ab" {
		t.Errorf("after the second write: %q, want %q", got, "ab")
	}
}

func TestStripSGRPartialFlushedOnClose(t *testing.T) {
	for _, in := range []string{"x\033", "x\033[", "x\033[0;3", "x\033[2"} {
		var b bytes.Buffer
		s := StripSGR(&b)
		_, _ = s.Write([]byte(in))
		if b.String() != "x" {
			t.Errorf("%q: held bytes written early: %q", in, b.String())
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		if b.String() != in {
			t.Errorf("%q: after Close %q", in, b.String())
		}
		if err := s.Close(); err != nil || b.String() != in {
			t.Errorf("%q: second Close wrote or failed: %q, %v", in, b.String(), err)
		}
	}
	// A lone ESC is not corrupted by what follows.
	if got := strip(t, "\033", "x"); got != "\033x" {
		t.Errorf("ESC then x = %q", got)
	}
	if got := strip(t, "\033"); got != "\033" {
		t.Errorf("lone ESC = %q", got)
	}
}

func TestStripSGRTooLongIsNotHeld(t *testing.T) {
	in := "\033[" + strings.Repeat("1;", 200) + "m"
	var b bytes.Buffer
	s := StripSGR(&b)
	_, _ = s.Write([]byte(in))
	_ = s.Close()
	if got := b.String(); got != in {
		t.Errorf("over-long sequence changed: %d bytes of %d", len(got), len(in))
	}
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func TestStripSGRPropagatesWriteError(t *testing.T) {
	boom := errors.New("boom")
	s := StripSGR(failWriter{boom})
	for _, in := range []string{"plain", "\033[1mbold"} {
		if n, err := s.Write([]byte(in)); !errors.Is(err, boom) || n != 0 {
			t.Errorf("Write(%q) = %d, %v; want 0, boom", in, n, err)
		}
	}
	s = StripSGR(failWriter{boom})
	_, _ = s.Write([]byte("\033"))
	if err := s.Close(); !errors.Is(err, boom) {
		t.Errorf("Close = %v, want boom", err)
	}
}

func TestStripSGRLargeWrites(t *testing.T) {
	plain := strings.Repeat("0123456789abcdef", 1<<16) // 1 MiB
	styled := strings.Repeat("\033[1mline of text\033[0m\n", 1<<15)
	wantStyled := strings.Repeat("line of text\n", 1<<15)

	var b bytes.Buffer
	s := StripSGR(&b)
	if _, err := s.Write([]byte(plain)); err != nil || b.String() != plain {
		t.Fatalf("plain: err %v, equal %v", err, b.String() == plain)
	}
	b.Reset()
	if _, err := s.Write([]byte(styled)); err != nil || b.String() != wantStyled {
		t.Fatalf("styled: err %v, len %d want %d", err, b.Len(), len(wantStyled))
	}
	if cap(s.(*sgrStripper).out) > 4*flushAt {
		t.Errorf("scratch grew to %d for a %d byte write", cap(s.(*sgrStripper).out), len(styled))
	}

	// A pass-through write costs no allocation once the sink exists.
	data := []byte(plain[:4096])
	sink := StripSGR(discard{})
	if n := testing.AllocsPerRun(50, func() { _, _ = sink.Write(data) }); n != 0 {
		t.Errorf("plain write allocates %v times", n)
	}
	// Nor does a styled one, after the scratch buffer has grown.
	sdata := []byte(styled[:4096])
	_, _ = sink.Write(sdata)
	if n := testing.AllocsPerRun(50, func() { _, _ = sink.Write(sdata) }); n != 0 {
		t.Errorf("styled write allocates %v times", n)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
