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
// bounds every line (LineMax) and can end itself after an idle time; the
// login console (tacctl-console) runs it with one more word of its own,
// system-shell (Options.SystemShell). With a password cache
// (Options.Cache, D70 of docs/plans/0.2.4-plan.md) it has one more word,
// 'console forget', marks each command line as in flight for the cache, and
// forgets the cached password when the person changes their own.
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

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/ui"
)

// LineMax is the longest line the shell runs, in bytes.
const LineMax = 4096

// DefaultPrompt is the interactive prompt.
const DefaultPrompt = "tacctl> "

// PasswordCache is the shell's side of the password cache of the session
// (internal/askpass: the agent lives in this process). The loop opens it
// for the command lines that use it, and only those, for the time they run,
// forgets the password on 'console forget' and when the person changes
// their password, and prints what it queued (a password stored, a password
// forgotten and why) between lines.
type PasswordCache interface {
	// BeginLine opens the cache for one command line when words run a verb
	// that uses it, and returns the line's value of TACCTL_ASKPASS (a token
	// minted for this line); "" when the line does not use the cache, which
	// is then not opened at all.
	BeginLine(words []string) string
	// EndLine closes the cache again: the line's token is dead.
	EndLine()
	// Forget empties the cache (why is one of askpass.Why*) and reports
	// whether a password was held.
	Forget(why string) bool
	// Notices returns, and clears, the lines to show the person (events
	// that happened since the last call).
	Notices() []string
}

type lineEnvKey struct{}

// WithLineEnv is ctx carrying the line's value of TACCTL_ASKPASS for Exec.
func WithLineEnv(ctx context.Context, env string) context.Context {
	return context.WithValue(ctx, lineEnvKey{}, env)
}

// LineEnv is the value of TACCTL_ASKPASS the loop opened the cache with for
// this command line ("" when there is none): Exec puts it in the
// environment of the process it starts, and nowhere else.
func LineEnv(ctx context.Context) string {
	v, _ := ctx.Value(lineEnvKey{}).(string)
	return v
}

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
	// Complete answers Tab and '?'.
	Complete Completer
	// CompleteFixed answers a typed blank (SpaceCompletion): like Complete,
	// but it need not offer, and must not look up, the live names (users,
	// hosts ...): only fixed words count there. Nil: Complete.
	CompleteFixed Completer
	// Explain answers '?' where Complete offers no word.
	Explain Explainer
	// ListMax is the longest list Tab or '?' shows without asking 'Show
	// all <n> <kind>?' first: 0 is DefaultListMax, a negative number never
	// asks.
	ListMax int
	// SpaceCompletion makes a typed blank Junos-style at the prompt (never
	// two in a row; at the end of a fixed word it completes the word or
	// lists the choices). A paste is not affected. Off: a blank is a blank.
	// Interactive only.
	SpaceCompletion bool
	// Help is the text of 'help <words>'; false when there is none.
	Help func(words []string) (string, bool)
	// Exec runs a tacctl command with the terminal's stdout and stderr and
	// the given stdin, and returns its exit status.
	Exec func(ctx context.Context, words []string, stdin io.Reader) int
	// SystemShell, when set, is the word system-shell (the console's): it
	// is listed and completed with the shell's own words and runs this
	// with whether the session is interactive; it returns the status. Nil:
	// system-shell is no word of the shell's (a tacctl command, unknown).
	SystemShell func(ctx context.Context, interactive bool) int
	// Cache is the session's password cache; nil: none (the cache is off,
	// or the mode keeps no process around: -c and batch).
	Cache PasswordCache
}

// Why a session ended (Shell.End).
const (
	EndExit    = "exit"    // exit or quit
	EndEOF     = "eof"     // Ctrl-D, or the end of a batch
	EndIdle    = "idle"    // the idle timeout
	EndHangup  = "hangup"  // SIGHUP
	EndSignal  = "signal"  // SIGTERM, or a signal during a batch
	EndCommand = "command" // the one line of -c
	EndFailed  = "failed"  // a batch stopped at a line that failed
	EndError   = "error"   // the terminal failed
)

// Shell runs lines.
type Shell struct {
	o Options

	// interactive: Interactive is running (the terminal is tty).
	interactive bool
	tty         *os.File
	lines       int
	reason      string
}

// End is why the last session ended (EndExit ...) and how many lines it
// ran (the lines with a word, the shell's own words included).
func (s *Shell) End() (reason string, lines int) { return s.reason, s.lines }

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
	s.lines++
	if words[0] == SystemShellWord && s.o.SystemShell != nil {
		if len(words) > 1 {
			s.errorf("%s takes no arguments", SystemShellWord)
			return 2, false
		}
		status := s.o.SystemShell(ctx, s.interactive)
		if s.interactive && s.tty != nil {
			reclaimTerminal(int(s.tty.Fd()))
		}
		return status, false
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
	if isConsoleForget(words) {
		return s.consoleForget(words), false
	}
	if c := s.o.Cache; c != nil {
		// The cache is open only for the lines that use it, for as long as
		// they run, with a token made for the line; any other line, the
		// shell's own words and the prompt leave it shut.
		if env := c.BeginLine(words); env != "" {
			ctx = WithLineEnv(ctx, env)
			defer c.EndLine()
		}
	}
	status = s.o.Exec(ctx, words, stdin)
	if s.o.Cache != nil && changesOwnPassword(words) {
		// The password the cache holds is the old one now (or the person
		// meant to leave it): either way it goes.
		s.o.Cache.Forget(askpass.WhyPasswd)
	}
	return status, false
}

// isConsoleForget reports whether words are 'console forget': a word of the
// shell and the console, never run through sudo.
func isConsoleForget(words []string) bool {
	return len(words) >= 2 && words[0] == "console" && words[1] == "forget"
}

// changesOwnPassword reports whether the line is 'passwd' or 'user passwd'
// (the latter may be the person's own account).
func changesOwnPassword(words []string) bool {
	return words[0] == "passwd" || (len(words) >= 2 && words[0] == "user" && words[1] == "passwd")
}

// consoleForget is 'console forget': the password cache is emptied now.
func (s *Shell) consoleForget(words []string) int {
	if len(words) > 2 {
		s.errorf("console forget takes no arguments")
		return 2
	}
	c := s.o.Cache
	if c == nil {
		_, _ = fmt.Fprintln(s.o.Out.Stdout, "no password is cached: the password cache is not on in this session")
		return 0
	}
	if !c.Forget(askpass.WhyCommand) {
		_, _ = fmt.Fprintln(s.o.Out.Stdout, "no password is cached")
		return 0
	}
	s.printNotices()
	return 0
}

// printNotices writes what the password cache queued, to stderr: after the
// line that caused it and before the next prompt, never in the middle of
// the editor.
func (s *Shell) printNotices() {
	if s.o.Cache == nil {
		return
	}
	for _, l := range s.o.Cache.Notices() {
		_, _ = fmt.Fprintln(s.o.Out.Stderr, l)
	}
}

// Command runs one line (-c), recorded in the history, with stdin for the
// command, and returns its status.
func (s *Shell) Command(ctx context.Context, line string, stdin io.Reader) int {
	if s.o.History != nil {
		s.o.History.Add(line)
	}
	status, _ := s.run(ctx, line, stdin)
	s.reason = EndCommand
	return status
}

// Batch runs the lines of r in order, without prompt or history, and stops
// at the first that ends with a non-zero status (whose status it returns),
// at exit or quit, or when ctx is cancelled (a signal). The commands get no
// stdin: r is the script.
func (s *Shell) Batch(ctx context.Context, r io.Reader) int {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), LineMax+2)
	s.reason = EndEOF
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		status, quit := s.run(ctx, line, nil)
		if ctx.Err() != nil && status == 0 {
			status = 130
		}
		switch {
		case ctx.Err() != nil:
			s.reason = EndSignal
		case status != 0:
			s.reason = EndFailed
		case quit:
			s.reason = EndExit
		}
		if status != 0 || quit || ctx.Err() != nil {
			return status
		}
	}
	if errors.Is(sc.Err(), bufio.ErrTooLong) {
		s.errorf("line too long (more than %d bytes)", LineMax)
		s.reason = EndFailed
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
	s.interactive, s.tty, s.reason = true, tty, EndError
	defer func() { s.interactive, s.tty = false, nil }()

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
	ed := &editor{prompt: s.o.Prompt, hist: hist, complete: s.o.Complete, completeFixed: s.o.CompleteFixed, explain: s.o.Explain, listMax: s.o.ListMax,
		systemShell: s.o.SystemShell != nil, spaces: s.o.SpaceCompletion}
	if ed.listMax == 0 {
		ed.listMax = DefaultListMax
	}
	in := &input{fd: fd, out: s.o.Out.Stdout, idle: s.o.Idle, wake: p[0], ed: ed}
	ed.out, ed.readKey = in, in.key
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
				setSize(t, ed, fd)
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

	stopped := func() int {
		sig := stop.Load()
		s.reason = EndSignal
		if sig == int32(syscall.SIGHUP) {
			s.reason = EndHangup
		}
		return 128 + int(sig)
	}
	for {
		if stop.Load() != 0 {
			return stopped()
		}
		s.printNotices()
		old, err := term.MakeRaw(fd)
		if err != nil {
			s.errorf("cannot set up the terminal: %v", err)
			return 1
		}
		setSize(t, ed, fd)
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
			s.reason = EndIdle
			return 0
		case errors.Is(err, errStop):
			_, _ = io.WriteString(s.o.Out.Stdout, "\n")
			return stopped()
		case errors.Is(err, io.EOF):
			_, _ = io.WriteString(s.o.Out.Stdout, "\n")
			s.reason = EndEOF
			return 0
		case err != nil && !errors.Is(err, term.ErrPasteIndicator):
			s.errorf("%v", err)
			return 1
		}
		status, quit := s.run(ctx, line, tty)
		if quit {
			s.reason = EndExit
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

// setSize gives the line editor the terminal's size. A terminal that
// reports no size (0x0: a pty nobody sized, as expect(1) and some serial
// consoles leave it) keeps the editor's 80x24: a width of 0 would wrap the
// line after every character.
func setSize(t *term.Terminal, ed *editor, fd int) {
	if w, h, err := term.GetSize(fd); err == nil && w > 0 && h > 0 {
		_ = t.SetSize(w, h)
		ed.width.Store(int32(min(w, 1<<15)))
		ed.height.Store(int32(min(h, 1<<15)))
	}
}

// reclaimTerminal makes the shell's process group the terminal's
// foreground group again: a program that took the terminal for job
// control (an interactive bash, the system shell) and did not give it back
// when it ended (it was killed) would leave the shell in the background,
// stopped by SIGTTOU at its next terminal change. SIGTTOU is ignored while
// the shell takes the terminal back (a background group may then).
func reclaimTerminal(fd int) {
	pgrp := unix.Getpgrp()
	fg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || fg == pgrp {
		return
	}
	signal.Ignore(syscall.SIGTTOU)
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pgrp)
	signal.Reset(syscall.SIGTTOU)
}
