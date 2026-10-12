package askpass

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
)

// Prompt writes prompt to tty and reads a line from it without echo, for
// the plain CLI and the root-side pull when the agent has nothing. The
// result is in a buffer made for it and sized MaxSecret (no regrowth, no
// stray copies); the caller zeroes it (Zero).
//
// Prompt owns the terminal for the call. It is read in its non-canonical
// mode with the signal keys off: Ctrl-C, Ctrl-D and Ctrl-\ end the prompt
// (ErrCancelled), Backspace and Ctrl-U edit, other control bytes are
// ignored. A line longer than MaxSecret is read to its end and discarded
// (ErrBadSecret). On every way out the terminal's settings are restored
// and what was typed but not read is flushed, so the rest of a cancelled
// or overlong entry (or anything typed ahead) is never left for the shell
// to run as a command. A signal sent to the process (SIGINT, SIGQUIT,
// SIGTSTP, SIGTERM, SIGHUP) restores the terminal, ends the prompt and is
// then delivered again to the process, so its own handlers or its default
// action run. tty not a terminal is ErrNoTerminal; an empty line is
// ErrBadSecret.
func Prompt(tty *os.File, prompt string) ([]byte, error) {
	fd := int(tty.Fd())
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, ErrNoTerminal
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG
	raw.Iflag &^= unix.ICRNL | unix.INLCR | unix.IGNCR
	raw.Cc[unix.VMIN], raw.Cc[unix.VTIME] = 1, 0
	// TCSETSF drops what was typed ahead: it is not the password. The same
	// flush ends the prompt (restore).
	if err := unix.IoctlSetTermios(fd, unix.TCSETSF, &raw); err != nil {
		return nil, ErrNoTerminal
	}
	restore := func() { _ = unix.IoctlSetTermios(fd, unix.TCSETSF, old) }

	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		restore()
		return nil, fmt.Errorf("cannot read the password: %w", err)
	}
	// A signal must not leave the terminal silent, and must end the read.
	sigs := make(chan os.Signal, 1)
	signals := []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTERM, syscall.SIGHUP}
	signal.Notify(sigs, signals...)
	done, exited := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case sig := <-sigs:
			restore()
			signal.Stop(sigs) // only this subscription: others keep theirs
			_, _ = unix.Write(p[1], []byte{1})
			_ = unix.Kill(os.Getpid(), sig.(syscall.Signal))
		case <-done:
		}
	}()
	defer func() {
		close(done)
		<-exited
		signal.Stop(sigs)
		restore()
		_ = unix.Close(p[0])
		_ = unix.Close(p[1])
		_, _ = tty.WriteString("\n")
	}()

	_, _ = tty.WriteString(prompt)

	buf := make([]byte, 0, MaxSecret)
	overflow := false
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}, {Fd: int32(p[0]), Events: unix.POLLIN}}
	var one [1]byte
	for {
		fds[0].Revents, fds[1].Revents = 0, 0
		if _, err := unix.Poll(fds, -1); err != nil {
			if err == unix.EINTR {
				continue
			}
			Zero(buf)
			return nil, ErrCancelled
		}
		if fds[1].Revents != 0 { // a signal
			Zero(buf)
			return nil, ErrCancelled
		}
		n, err := unix.Read(fd, one[:])
		if err == unix.EINTR || err == unix.EAGAIN {
			continue
		}
		if err != nil || n == 0 {
			Zero(buf)
			return nil, ErrCancelled
		}
		switch c := one[0]; {
		case c == '\n' || c == '\r':
			if overflow || !validSecret(buf) {
				Zero(buf)
				return nil, ErrBadSecret
			}
			return buf, nil
		case c == 0x03 || c == 0x04 || c == 0x1c: // ^C ^D ^\
			Zero(buf)
			return nil, ErrCancelled
		case overflow:
			// Discard to the end of the line.
		case c == 0x15: // ^U
			Zero(buf)
			buf = buf[:0]
		case c == 0x7f || c == 0x08:
			buf = dropRune(buf)
		case c < 0x20:
		default:
			if len(buf) == MaxSecret {
				Zero(buf)
				buf, overflow = buf[:0], true
				continue
			}
			buf = append(buf, c)
		}
	}
}

// dropRune removes the last UTF-8 character of b, zeroing its bytes.
func dropRune(b []byte) []byte {
	for len(b) > 0 {
		c := b[len(b)-1]
		b[len(b)-1] = 0
		b = b[:len(b)-1]
		if c&0xC0 != 0x80 { // not a continuation byte: the lead was removed
			break
		}
	}
	return b
}
