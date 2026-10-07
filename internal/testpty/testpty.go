// Package testpty runs a program on a pseudo-terminal for tests: the
// program gets a new session with the pty as its controlling terminal, so
// Ctrl-C, Ctrl-Z and Ctrl-\ typed on the master generate signals for its
// foreground process group exactly as on an ssh login. It is built on
// golang.org/x/sys/unix alone (no cgo, no new module) and starts the program
// with os.StartProcess, so it needs no os/exec.
//
// Every Session has a hard deadline: when it passes, the whole process
// group is killed and every later Expect fails, so a test never hangs.
package testpty

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Open returns the master and slave ends of a new pty.
func Open() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		_ = m.Close()
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// Options describe the program to start.
type Options struct {
	Path string   // the executable
	Argv []string // argv, argv[0] included
	Env  []string // the whole environment
	Dir  string   // working directory ("" is the caller's)
	// Rows and Cols are the window size (24x80 when zero).
	Rows, Cols uint16
	// Deadline is the hard limit of the session (10 s when zero).
	Deadline time.Duration
}

// Session is a program running on a pty.
type Session struct {
	Master *os.File
	proc   *os.Process

	mu     sync.Mutex
	buf    []byte
	mark   int
	notify chan struct{}

	done    chan struct{}
	state   *os.ProcessState
	waitErr error
	timer   *time.Timer
	expired chan struct{}
	once    sync.Once
}

// Start runs the program on a new pty.
func Start(o Options) (*Session, error) {
	if o.Rows == 0 {
		o.Rows, o.Cols = 24, 80
	}
	if o.Deadline == 0 {
		o.Deadline = 10 * time.Second
	}
	m, s, err := Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = s.Close() }()
	if err := unix.IoctlSetWinsize(int(s.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: o.Rows, Col: o.Cols}); err != nil {
		_ = m.Close()
		return nil, err
	}
	p, err := os.StartProcess(o.Path, o.Argv, &os.ProcAttr{
		Dir:   o.Dir,
		Env:   o.Env,
		Files: []*os.File{s, s, s},
		Sys:   &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0},
	})
	if err != nil {
		_ = m.Close()
		return nil, err
	}
	ss := &Session{Master: m, proc: p, notify: make(chan struct{}, 1), done: make(chan struct{}), expired: make(chan struct{})}
	go ss.read()
	go func() {
		ss.state, ss.waitErr = p.Wait()
		close(ss.done)
	}()
	ss.timer = time.AfterFunc(o.Deadline, func() {
		close(ss.expired)
		ss.kill()
	})
	return ss, nil
}

func (s *Session) read() {
	b := make([]byte, 4096)
	for {
		n, err := s.Master.Read(b)
		if n > 0 {
			s.mu.Lock()
			s.buf = append(s.buf, b[:n]...)
			s.mu.Unlock()
			select {
			case s.notify <- struct{}{}:
			default:
			}
		}
		if err != nil {
			return
		}
	}
}

// kill ends the program's whole process group (it is a session leader, so
// its group id is its pid): the children it started go with it.
func (s *Session) kill() {
	_ = syscall.Kill(-s.proc.Pid, syscall.SIGKILL)
	_ = s.proc.Kill()
}

// Resize sets the window size; the kernel sends SIGWINCH to the
// terminal's foreground process group.
func (s *Session) Resize(rows, cols uint16) error {
	return unix.IoctlSetWinsize(int(s.Master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: cols})
}

// Pid is the program's process id.
func (s *Session) Pid() int { return s.proc.Pid }

// Send types str on the terminal.
func (s *Session) Send(str string) error {
	_, err := s.Master.Write([]byte(str))
	return err
}

// ErrDeadline is returned once the session's deadline has passed.
var ErrDeadline = errors.New("testpty: session deadline passed")

// Expect waits up to d for re in the output after the mark; on a match the
// mark moves past it. On failure the error carries the output seen.
func (s *Session) Expect(re string, d time.Duration) error {
	rx := regexp.MustCompile(re)
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		s.mu.Lock()
		tail := s.buf[s.mark:]
		if loc := rx.FindIndex(tail); loc != nil {
			s.mark += loc[1]
			s.mu.Unlock()
			return nil
		}
		snap := string(tail)
		s.mu.Unlock()
		select {
		case <-s.notify:
		case <-s.expired:
			return fmt.Errorf("%w waiting for %q; output: %q", ErrDeadline, re, snap)
		case <-t.C:
			return fmt.Errorf("timed out waiting for %q; output: %q", re, snap)
		}
	}
}

// Settle waits d and returns what arrived after the mark, moving the mark
// to the end.
func (s *Session) Settle(d time.Duration) string {
	t := time.NewTimer(d)
	select {
	case <-t.C:
	case <-s.expired:
		t.Stop()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := string(s.buf[s.mark:])
	s.mark = len(s.buf)
	return out
}

// Output is everything the program has written so far.
func (s *Session) Output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.buf)
}

// Wait waits up to d for the program to end and returns its state. When it
// does not end in time it is killed and an error returned.
func (s *Session) Wait(d time.Duration) (*os.ProcessState, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-s.done:
		return s.state, s.waitErr
	case <-t.C:
	case <-s.expired:
	}
	s.kill()
	<-s.done
	return s.state, fmt.Errorf("testpty: the program did not end within %v (killed)", d)
}

// Close kills whatever is left of the session, reaps the program and closes
// the master. It is safe to call more than once.
func (s *Session) Close() {
	s.once.Do(func() {
		s.timer.Stop()
		s.kill()
		<-s.done
		_ = s.Master.Close()
	})
}
