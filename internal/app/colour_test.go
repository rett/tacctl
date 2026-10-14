package app

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/term"

	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/testpty"
	"github.com/rett/tacctl/internal/ui"
)

// stream is one process stream of a test: the file New is given and how to
// read what was written to it.
type stream struct {
	f    *os.File
	tty  bool
	read func() string
}

func pipeStream(t *testing.T) *stream {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	s := &stream{f: w}
	s.read = func() string {
		_ = w.Close() // what is written is all there is
		b, _ := io.ReadAll(r)
		return string(b)
	}
	return s
}

func ptyStream(t *testing.T) *stream {
	t.Helper()
	m, sl, err := testpty.Open()
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = sl.Close() })
	var mu sync.Mutex
	var got bytes.Buffer
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := m.Read(buf)
			mu.Lock()
			got.Write(buf[:n])
			mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	s := &stream{f: sl, tty: true}
	s.read = func() string {
		// A marker written to the terminal itself: when it arrives,
		// everything before it has.
		_, _ = sl.WriteString("#END#")
		for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(5 * time.Millisecond) {
			mu.Lock()
			s := got.String()
			mu.Unlock()
			if i := strings.Index(s, "#END#"); i >= 0 {
				return s[:i]
			}
		}
		t.Fatal("the terminal's output did not arrive")
		return ""
	}
	return s
}

// The colour decision of a process, made in New: a pipe is plain, a
// terminal coloured, NO_COLOR and TACCTL_COLOR override, and a stream that
// is not a file (a test's buffer) keeps what it is written unless the user
// said never.
func TestNewColourDecision(t *testing.T) {
	const (
		colOut, plainOut = "\033[0;32m[INFO]\033[0m x", "[INFO] x"
		colErr, plainErr = "\033[0;31m[ERROR]\033[0m y", "[ERROR] y"
	)
	const col, plain = true, false
	for _, c := range []struct {
		name     string
		env      []string
		out, err string // "pipe", "pty"
		wantOut  bool   // coloured
		wantErr  bool
	}{
		{"pipes", nil, "pipe", "pipe", plain, plain},
		{"pipes always", []string{"TACCTL_COLOR=always"}, "pipe", "pipe", col, col},
		{"pipes always, NO_COLOR", []string{"TACCTL_COLOR=always", "NO_COLOR=1"}, "pipe", "pipe", col, col},
		{"pipes, TERM set", []string{"TERM=xterm"}, "pipe", "pipe", plain, plain},
		{"terminals", []string{"TERM=xterm"}, "pty", "pty", col, col},
		{"terminals, no TERM", nil, "pty", "pty", plain, plain},
		{"terminals, dumb", []string{"TERM=dumb"}, "pty", "pty", plain, plain},
		{"terminals, NO_COLOR", []string{"TERM=xterm", "NO_COLOR=1"}, "pty", "pty", plain, plain},
		{"terminals, never", []string{"TERM=xterm", "TACCTL_COLOR=never"}, "pty", "pty", plain, plain},
		{"stdout piped, stderr terminal", []string{"TERM=xterm"}, "pipe", "pty", plain, col},
		{"stdout terminal, stderr piped", []string{"TERM=xterm"}, "pty", "pipe", col, plain},
		{"terminal, always", []string{"TERM=xterm", "TACCTL_COLOR=always"}, "pty", "pipe", col, col},
	} {
		t.Run(c.name, func(t *testing.T) {
			mk := func(kind string) *stream {
				if kind == "pty" {
					return ptyStream(t)
				}
				return pipeStream(t)
			}
			so, se := mk(c.out), mk(c.err)
			a := New(nil, paths.NewEnv(c.env), "", 0, Stdio{Stdin: strings.NewReader(""), Stdout: so.f, Stderr: se.f}, &fake.Runner{})
			a.Out.Info("x")
			a.Out.Error("y")
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			wantOut, wantErr := plainOut, plainErr
			if c.wantOut {
				wantOut = colOut
			}
			if c.wantErr {
				wantErr = colErr
			}
			if got := strings.TrimRight(so.read(), "\r\n"); got != wantOut {
				t.Errorf("stdout %q, want %q", got, wantOut)
			}
			if got := strings.TrimRight(se.read(), "\r\n"); got != wantErr {
				t.Errorf("stderr %q, want %q", got, wantErr)
			}
		})
	}
}

// What is not a file is passed through, and only the user's explicit choice
// strips it (the Go tests of the packages above build their App on buffers).
func TestNewBuffersKeepTheirColour(t *testing.T) {
	for _, c := range []struct {
		env  []string
		want bool
	}{
		{nil, true},
		{[]string{"TERM=dumb"}, true},
		{[]string{"NO_COLOR=1"}, false},
		{[]string{"TACCTL_COLOR=never"}, false},
		{[]string{"TACCTL_COLOR=always", "NO_COLOR=1"}, true},
	} {
		var out, errb bytes.Buffer
		a := New(nil, paths.NewEnv(c.env), "", 0, Stdio{Stdout: &out, Stderr: &errb}, &fake.Runner{})
		a.Out.Info("x")
		a.Out.Error("y")
		_ = a.Close()
		if got := strings.Contains(out.String(), "\033[") && strings.Contains(errb.String(), "\033["); got != c.want {
			t.Errorf("%v: coloured %v, want %v (%q %q)", c.env, got, c.want, out.String(), errb.String())
		}
	}
}

// A stream with its colour taken out is still the file behind it for the
// terminal checks and the programs that are started with it, and a colour
// sequence cut in two writes is whole when it comes out.
func TestNewKeepsTheFileBehind(t *testing.T) {
	s := ptyStream(t)
	p := pipeStream(t)
	a := New(nil, paths.NewEnv([]string{"NO_COLOR=1", "TERM=xterm"}), "", 0, Stdio{Stdout: s.f, Stderr: p.f}, &fake.Runner{})
	if a.Out.Stdout == io.Writer(s.f) {
		t.Fatal("stdout was not wrapped: NO_COLOR is set")
	}
	f, ok := ui.File(a.Out.Stdout)
	if !ok || f != s.f || !term.IsTerminal(int(f.Fd())) {
		t.Errorf("ui.File(stdout) = %v %v", f, ok)
	}
	if f, ok := ui.File(a.Out.Stderr); !ok || f != p.f {
		t.Errorf("ui.File(stderr) = %v %v", f, ok)
	}
	// Held until the sequence ends; a sequence never completed is written
	// by Close, not lost.
	_, _ = io.WriteString(a.Out.Stderr, "a\033[1")
	_, _ = io.WriteString(a.Out.Stderr, ";31mb\033[")
	_, _ = io.WriteString(a.Out.Stderr, "K\033[3")
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if got := p.read(); got != "ab\033[K\033[3" {
		t.Errorf("stderr %q", got)
	}
}

// Coloured streams are the files themselves: no wrapper, no copy.
func TestNewLeavesColouredStreamsAlone(t *testing.T) {
	p := pipeStream(t)
	a := New(nil, paths.NewEnv([]string{"TACCTL_COLOR=always"}), "", 0, Stdio{Stdout: p.f, Stderr: p.f}, &fake.Runner{})
	if a.Out.Stdout != io.Writer(p.f) || a.Out.Stderr != io.Writer(p.f) || len(a.sinks) != 0 {
		t.Errorf("wrapped: %T %T", a.Out.Stdout, a.Out.Stderr)
	}
}
