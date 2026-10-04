// Package shell is 'tacctl shell': a line loop that runs one tacctl command
// per line. It runs as the invoking user and never holds privilege: each
// line is handed to Options.Exec, which runs it as 'sudo [-n] tacctl
// <words>' with the terminal attached (internal/cli/shell.go). The shell's
// own words are help, history, exit and quit; everything else is a tacctl
// command, tokenized by Tokenize (quotes and backslash, nothing else).
//
// Three modes: interactive (stdin is a terminal: prompt, line editor,
// completion, history), batch (stdin is not a terminal: one command per
// line, no prompt, stop at the first non-zero status) and a single
// command (-c). The loop has no job control, spawns no editor or pager,
// bounds every line (LineMax) and can end itself after an idle time, so
// the login console of 0.2.2 reuses it as it is.
package shell

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rett/tacctl/internal/ui"
)

// LineMax is the longest line the shell runs, in bytes.
const LineMax = 4096

// DefaultPrompt is the interactive prompt.
const DefaultPrompt = "tacctl> "

// Options are what the shell works with.
type Options struct {
	// Prompt is the interactive prompt (DefaultPrompt when empty).
	Prompt string
	Out    ui.Output
	// Idle ends an interactive session after that long without input at
	// the prompt (0: never). It does not run while a command does.
	Idle time.Duration
	// History records the lines of an interactive session and of -c (nil:
	// none; a History without a file is kept in memory only).
	History *History
	// Complete answers Tab.
	Complete Completer
	// Help is the text of 'help <words>'; false when there is none.
	Help func(words []string) (string, bool)
	// Exec runs a tacctl command with the terminal's stdout and stderr and
	// the given stdin, and returns its exit status.
	Exec func(ctx context.Context, words []string, stdin io.Reader) int
}

// Shell runs lines.
type Shell struct {
	o Options
}

// New is a shell with o.
func New(o Options) *Shell {
	if o.Prompt == "" {
		o.Prompt = DefaultPrompt
	}
	return &Shell{o: o}
}

func (s *Shell) errorf(format string, a ...any) { s.o.Out.Error(fmt.Sprintf(format, a...)) }

// run runs one line; quit is true for exit and quit.
func (s *Shell) run(ctx context.Context, line string, stdin io.Reader) (status int, quit bool) {
	if len(line) > LineMax {
		s.errorf("line too long (more than %d bytes)", LineMax)
		return 2, false
	}
	if strings.Contains(line, RedactedMark) {
		s.errorf("this line has a value redacted by the history; type the command in full")
		return 2, false
	}
	words, err := Tokenize(line)
	if err != nil {
		s.errorf("%v", err)
		return 2, false
	}
	if len(words) == 0 {
		return 0, false
	}
	switch words[0] {
	case "exit", "quit":
		if len(words) > 1 {
			s.errorf("%s takes no arguments", words[0])
			return 2, false
		}
		return 0, true
	case "history":
		if len(words) > 1 {
			s.errorf("history takes no arguments")
			return 2, false
		}
		if s.o.History != nil {
			for i, l := range s.o.History.Entries() {
				_, _ = fmt.Fprintf(s.o.Out.Stdout, "%5d  %s\n", i+1, l)
			}
		}
		return 0, false
	case "help":
		text, ok := "", false
		if s.o.Help != nil {
			text, ok = s.o.Help(words[1:])
		}
		if !ok {
			s.errorf("no help for '%s'; 'help' lists the commands", strings.Join(words[1:], " "))
			return 1, false
		}
		_, _ = io.WriteString(s.o.Out.Stdout, text)
		return 0, false
	}
	return s.o.Exec(ctx, words, stdin), false
}

// Command runs one line (-c), recorded in the history, with stdin for the
// command, and returns its status.
func (s *Shell) Command(ctx context.Context, line string, stdin io.Reader) int {
	if s.o.History != nil {
		s.o.History.Add(line)
	}
	status, _ := s.run(ctx, line, stdin)
	return status
}

// Batch runs the lines of r in order, without prompt or history, and stops
// at the first that ends with a non-zero status (whose status it returns),
// at exit or quit, or when ctx is cancelled (a signal). The commands get no
// stdin: r is the script.
func (s *Shell) Batch(ctx context.Context, r io.Reader) int {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), LineMax+2)
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		status, quit := s.run(ctx, line, nil)
		if ctx.Err() != nil && status == 0 {
			status = 130
		}
		if status != 0 || quit || ctx.Err() != nil {
			return status
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		s.errorf("line too long (more than %d bytes)", LineMax)
		return 2
	}
	return 0
}

// Interactive runs the prompt loop on the terminal tty until exit, quit,
// Ctrl-D, the idle time or a SIGTERM/SIGHUP. The terminal is in raw mode
// only while a line is read; a command runs with it as the shell found it.
//
// Signals: Ctrl-Z and Ctrl-\ are ignored, and the commands inherit that
// (there is no job control: nothing can be stopped and left behind).
// SIGINT is caught, not ignored, so a command gets the default: Ctrl-C
// while a command runs ends the command and the shell carries on. At the
// prompt the terminal is raw and Ctrl-C is a key (input.go).
func (s *Shell) Interactive(ctx context.Context, tty *os.File) int {
	ctx = context.WithoutCancel(ctx)
	fd := int(tty.Fd())

	signal.Ignore(syscall.SIGTSTP, syscall.SIGQUIT)
	defer signal.Reset(syscall.SIGTSTP, syscall.SIGQUIT)
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGWINCH)
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		signal.Stop(sigs)
		s.errorf("%v", err)
		return 1
	}
	defer func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) }()

	hist := s.o.History
	if hist == nil {
		hist = NewHistory("", nil)
	}
	ed := &editor{prompt: s.o.Prompt, hist: hist, complete: s.o.Complete}
	in := &input{fd: fd, out: s.o.Out.Stdout, idle: s.o.Idle, wake: p[0], ed: ed}
	t := term.NewTerminal(in, s.o.Prompt)
	ed.t = t
	t.AutoCompleteCallback = ed.key
	hist.skip = func() bool { return ed.interrupted }
	t.History = hist

	var stop atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range sigs {
			switch sig {
			case syscall.SIGWINCH:
				if w, h, err := term.GetSize(fd); err == nil {
					_ = t.SetSize(w, h)
				}
			case syscall.SIGTERM, syscall.SIGHUP:
				stop.CompareAndSwap(0, int32(sig.(syscall.Signal)))
				_, _ = unix.Write(p[1], []byte{1})
			}
		}
	}()
	defer func() {
		signal.Stop(sigs)
		close(sigs)
		<-done
	}()

	for {
		if sig := stop.Load(); sig != 0 {
			return 128 + int(sig)
		}
		old, err := term.MakeRaw(fd)
		if err != nil {
			s.errorf("cannot set up the terminal: %v", err)
			return 1
		}
		if w, h, err := term.GetSize(fd); err == nil {
			_ = t.SetSize(w, h)
		}
		ed.interrupted = false
		t.SetBracketedPasteMode(true)
		line, err := t.ReadLine()
		t.SetBracketedPasteMode(false)
		_ = term.Restore(fd, old)
		if ed.interrupted {
			continue
		}
		switch {
		case errors.Is(err, errIdle):
			_, _ = fmt.Fprintf(s.o.Out.Stdout, "\nidle timeout after %s\n", idleText(s.o.Idle))
			return 0
		case errors.Is(err, errStop):
			_, _ = io.WriteString(s.o.Out.Stdout, "\n")
			return 128 + int(stop.Load())
		case errors.Is(err, io.EOF):
			_, _ = io.WriteString(s.o.Out.Stdout, "\n")
			return 0
		case err != nil && !errors.Is(err, term.ErrPasteIndicator):
			s.errorf("%v", err)
			return 1
		}
		status, quit := s.run(ctx, line, tty)
		if quit {
			return 0
		}
		if status != 0 {
			_, _ = fmt.Fprintf(s.o.Out.Stderr, "[exit %d]\n", status)
		}
	}
}

// idleText is d in minutes when it is whole minutes.
func idleText(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%d min", int(d/time.Minute))
	}
	return d.String()
}
