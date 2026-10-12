package askpass

import (
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/testpty"
)

// ptyOut collects what is written to the pty master (the terminal's
// display).
type ptyOut struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (p *ptyOut) text() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.buf.String()
}

func startPty(t *testing.T) (master, slave *os.File, out *ptyOut) {
	t.Helper()
	m, s, err := testpty.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = s.Close() })
	out = &ptyOut{}
	go func() {
		b := make([]byte, 256)
		for {
			n, err := m.Read(b)
			if n > 0 {
				out.mu.Lock()
				out.buf.Write(b[:n])
				out.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return m, s, out
}

func waitFor(t *testing.T, out *ptyOut, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.text(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never saw %q, terminal showed %q", want, out.text())
}

type promptResult struct {
	b   []byte
	err error
}

func runPrompt(s *os.File) chan promptResult {
	ch := make(chan promptResult, 1)
	go func() {
		b, err := Prompt(s, "Password: ")
		ch <- promptResult{b, err}
	}()
	return ch
}

func result(t *testing.T, ch chan promptResult) promptResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("Prompt did not return")
		return promptResult{}
	}
}

func TestPromptNoEcho(t *testing.T) {
	m, s, out := startPty(t)
	before, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	ch := runPrompt(s)
	waitFor(t, out, "Password: ")
	// Typing with an edit: 'Zx' erased, a multi-byte character erased.
	if _, err := io.WriteString(m, "hunterX\x7f2é\x7fZ\x7f!\r"); err != nil {
		t.Fatal(err)
	}
	r := result(t, ch)
	if r.err != nil || string(r.b) != "hunter2!" {
		t.Fatalf("Prompt = %q, %v", r.b, r.err)
	}
	if cap(r.b) != MaxSecret {
		t.Errorf("buffer capacity %d", cap(r.b))
	}
	Zero(r.b)
	waitFor(t, out, "\n")
	if shown := out.text(); strings.Contains(shown, "hunter") || strings.Contains(shown, "2!") {
		t.Fatalf("the terminal echoed the password: %q", shown)
	}
	after, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if *after != *before {
		t.Fatalf("the terminal settings were not restored:\nbefore %+v\nafter  %+v", *before, *after)
	}
}

func TestPromptCancelAndEmpty(t *testing.T) {
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"ctrl-c":     {"abc\x03", ErrCancelled},
		"ctrl-d":     {"\x04", ErrCancelled},
		"empty":      {"\r", ErrBadSecret},
		"kill line":  {"abc\x15\r", ErrBadSecret},
		"line break": {"\n", ErrBadSecret},
	} {
		t.Run(name, func(t *testing.T) {
			m, s, out := startPty(t)
			ch := runPrompt(s)
			waitFor(t, out, "Password: ")
			_, _ = io.WriteString(m, tc.in)
			r := result(t, ch)
			if !errors.Is(r.err, tc.want) || r.b != nil {
				t.Fatalf("Prompt = %q, %v", r.b, r.err)
			}
			if strings.Contains(out.text(), "abc") {
				t.Fatalf("echo: %q", out.text())
			}
		})
	}
}

func TestPromptTooLong(t *testing.T) {
	m, s, out := startPty(t)
	ch := runPrompt(s)
	waitFor(t, out, "Password: ")
	go func() { _, _ = io.WriteString(m, strings.Repeat("a", MaxSecret+5)+"\r") }()
	r := result(t, ch)
	if !errors.Is(r.err, ErrBadSecret) {
		t.Fatalf("Prompt = %d bytes, %v", len(r.b), r.err)
	}
}

func TestPromptNeedsTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "notty")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := Prompt(f, "Password: "); !errors.Is(err, ErrNoTerminal) {
		t.Fatalf("a file: %v", err)
	}
}

func TestDropRune(t *testing.T) {
	b := []byte("aé€")
	b = dropRune(b)
	if string(b) != "aé" {
		t.Fatalf("%q", b)
	}
	b = dropRune(b)
	b = dropRune(b)
	b = dropRune(b)
	if len(b) != 0 {
		t.Fatalf("%q", b)
	}
}

// whatIsLeft types sentinel on the pty master and reports what the slave
// reads: a leftover of the earlier input would come first.
func whatIsLeft(t *testing.T, m, s *os.File) string {
	t.Helper()
	// The earlier input is in the line discipline by now.
	time.Sleep(50 * time.Millisecond)
	if _, err := io.WriteString(m, "sentinel\n"); err != nil {
		t.Fatal(err)
	}
	ch := make(chan string, 1)
	go func() {
		b := make([]byte, 256)
		n, _ := unix.Read(int(s.Fd()), b)
		ch <- string(b[:n])
	}()
	select {
	case got := <-ch:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("the terminal produced no input")
		return ""
	}
}

// M1: nothing typed after the end of the prompt is left for the next
// reader of the terminal (the shell would run it as a command).
func TestPromptLeavesNoInputBehind(t *testing.T) {
	long := strings.Repeat("a", MaxSecret) + "TAILSECRET"
	for name, tc := range map[string]struct {
		in   string
		want error
	}{
		"after ctrl-c":     {"abc\x03rm -rf x\r", ErrCancelled},
		"after ctrl-d":     {"abc\x04rm -rf x\r", ErrCancelled},
		"after ctrl-\\":    {"abc\x1crm -rf x\r", ErrCancelled},
		"after overflow":   {long + "\r", ErrBadSecret},
		"typed ahead":      {"good\rls -l\r", nil},
		"overflow, cancel": {long + "\x03next\r", ErrCancelled},
	} {
		t.Run(name, func(t *testing.T) {
			m, s, out := startPty(t)
			ch := runPrompt(s)
			waitFor(t, out, "Password: ")
			if _, err := io.WriteString(m, tc.in); err != nil {
				t.Fatal(err)
			}
			r := result(t, ch)
			if !errors.Is(r.err, tc.want) {
				t.Fatalf("Prompt = %q, %v", r.b, r.err)
			}
			Zero(r.b)
			if got := whatIsLeft(t, m, s); got != "sentinel\n" {
				t.Fatalf("input left behind: %q", got)
			}
			if shown := out.text(); strings.Contains(shown, "TAILSECRET") || strings.Contains(shown, "rm -rf") {
				t.Fatalf("echo: %q", shown)
			}
		})
	}
}

// L10: a signal to the process restores the terminal, ends the prompt and
// is delivered again to the process's own handlers.
func TestPromptSignals(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			ours := make(chan os.Signal, 4)
			signal.Notify(ours, sig) // another subscriber: the process survives
			defer signal.Stop(ours)

			m, s, out := startPty(t)
			_ = m
			before, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			ch := runPrompt(s)
			waitFor(t, out, "Password: ")
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				t.Fatal(err)
			}
			r := result(t, ch)
			if !errors.Is(r.err, ErrCancelled) || r.b != nil {
				t.Fatalf("Prompt = %q, %v", r.b, r.err)
			}
			// The first delivery is ours (Prompt's subscription saw it
			// too); the second is Prompt's own re-raise.
			for i := 0; i < 2; i++ {
				select {
				case <-ours:
				case <-time.After(3 * time.Second):
					t.Fatalf("signal %d of 2 never reached the process's own handler", i+1)
				}
			}
			after, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
			if err != nil {
				t.Fatal(err)
			}
			if *after != *before {
				t.Fatalf("terminal not restored after %v", sig)
			}
		})
	}
}
