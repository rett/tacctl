package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/term"
)

// ErrReported is returned by a prompt that has already printed its
// complaint (a rejected or mismatched password): the command exits 1 without
// printing anything more.
var ErrReported = errors.New("already reported")

// ErrInterrupted is returned by Password when the user types Ctrl-C on a
// terminal; the command exits 130, as bash does when SIGINT kills it.
var ErrInterrupted = errors.New("interrupted")

// Prompter reads answers from standard input the way the bash code does. It
// reads stdin only (never /dev/tty), so a script that pipes 'y' into tacctl
// works, and one bufio.Reader serves every prompt of the run so no read
// swallows the input of the next. Create one per run with NewPrompter.
type Prompter struct {
	in  *bufio.Reader
	f   *os.File // the input when it is a file, for the terminal checks
	tty bool
	out Output
}

// NewPrompter prompts on in, writing prompts and echo to out.Stderr. When in
// is an *os.File on a terminal, prompts are shown and Password masks.
func NewPrompter(in io.Reader, out Output) *Prompter {
	p := &Prompter{in: bufio.NewReader(in), out: out}
	if f, ok := in.(*os.File); ok {
		p.f = f
		p.tty = term.IsTerminal(int(f.Fd()))
	}
	return p
}

// Interactive reports whether input is a terminal.
func (p *Prompter) Interactive() bool { return p.tty }

// Ask is 'read -rp "<prompt>" answer || true': it returns the line read with
// surrounding blanks (space, tab) removed, "" at end of input (a final line
// without a newline is still returned). Like bash, it shows the prompt on
// stderr only when input is a terminal.
func (p *Prompter) Ask(prompt string) string {
	if p.tty {
		_, _ = io.WriteString(p.out.Stderr, prompt)
	}
	line, _ := p.in.ReadString('\n')
	line = strings.TrimSuffix(line, "\n")
	return strings.Trim(line, " \t")
}

// Confirm asks and is true only for exactly "y" or "Y": the
// '[[ "$c" != "y" && "$c" != "Y" ]]' sites (install, uninstall, group
// remove, user remove, backend and RADIUS prompts, restore, rollback).
func (p *Prompter) Confirm(prompt string) bool {
	a := p.Ask(prompt)
	return a == "y" || a == "Y"
}

// ConfirmPrefix asks and is true for any answer starting with y or Y: the
// '[[ "$c" =~ ^[Yy] ]]' sites (the 'clear'/'remove --all' prompts, tcp6,
// sudoers install).
func (p *Prompter) ConfirmPrefix(prompt string) bool {
	a := p.Ask(prompt)
	return a != "" && (a[0] == 'y' || a[0] == 'Y')
}

// Password is read_password_masked: the prompt on stderr, then characters
// until Enter or end of input, each echoed to stderr as '*'; DEL and
// backspace remove the last character ("\b \b"). On a terminal the loop runs
// in raw mode (x/term); otherwise it consumes piped input the same way,
// echoing the same bytes, as the bash does. A newline is printed at the end.
// Ctrl-C on a terminal returns ErrInterrupted.
func (p *Prompter) Password(prompt string) (string, error) {
	_, _ = io.WriteString(p.out.Stderr, prompt)
	var restore func()
	if p.tty {
		fd := int(p.f.Fd())
		if old, err := term.MakeRaw(fd); err == nil {
			restore = func() { _ = term.Restore(fd, old) }
		}
	}
	done := func() {
		if restore != nil {
			restore()
		}
	}
	var pw []byte
	for {
		ch, err := p.readChar()
		if err != nil {
			break
		}
		c := ch[0]
		if c == 0 {
			continue // bash's read drops NUL bytes
		}
		if c == '\n' || (p.tty && c == '\r') {
			break
		}
		if p.tty && c == 0x03 {
			done()
			_, _ = io.WriteString(p.out.Stderr, "\n")
			return "", ErrInterrupted
		}
		if c == 0x7f || c == '\b' {
			if len(pw) > 0 {
				_, size := utf8.DecodeLastRune(pw)
				pw = pw[:len(pw)-size]
				_, _ = io.WriteString(p.out.Stderr, "\b \b")
			}
			continue
		}
		pw = append(pw, ch...)
		_, _ = io.WriteString(p.out.Stderr, "*")
	}
	done()
	_, _ = io.WriteString(p.out.Stderr, "\n")
	return string(pw), nil
}

// readChar reads one character as bash's 'read -n1' does in a UTF-8 locale:
// a whole well-formed multibyte sequence, else a single byte.
func (p *Prompter) readChar() ([]byte, error) {
	b, err := p.in.ReadByte()
	if err != nil {
		return nil, err
	}
	ch := []byte{b}
	need := 0
	switch {
	case b >= 0xf0 && b <= 0xf4:
		need = 3
	case b >= 0xe0:
		if b < 0xf0 {
			need = 2
		}
	case b >= 0xc2 && b < 0xe0:
		need = 1
	}
	for ; need > 0; need-- {
		next, err := p.in.Peek(1)
		if err != nil || next[0]&0xc0 != 0x80 {
			break
		}
		_, _ = p.in.ReadByte()
		ch = append(ch, next[0])
	}
	return ch, nil
}

// PromptPassword is prompt_password: ask for a password (username, when not
// empty, is for the equals-the-username check; minLength is the
// 'password.min_length' setting). Blank input, or end of input, generates a
// password from rng (nil means crypto/rand) and prints it. A typed password
// must pass PasswordStrength and be typed twice. Every complaint is printed
// here, exactly as the bash prints it, and ErrReported is returned: the
// caller just exits 1. Prompts and notices go to stderr.
func (p *Prompter) PromptPassword(username string, minLength int, rng io.Reader) (string, error) {
	password, err := p.Password("  Enter password (leave blank to auto-generate): ")
	if err != nil {
		return "", err
	}
	if password == "" {
		password, err = GeneratePassword(rng)
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(p.out.Stderr, "  Generated password: %s%s%s\n", Bold, password, NC)
		return password, nil
	}
	if err := PasswordStrength(password, username, minLength); err != nil {
		p.out.ErrorLines(err)
		return "", ErrReported
	}
	confirm, err := p.Password("  Confirm password: ")
	if err != nil {
		return "", err
	}
	if password != confirm {
		_, _ = fmt.Fprintf(p.out.Stderr, "  %sPasswords do not match.%s\n", Red, NC)
		return "", ErrReported
	}
	return password, nil
}
