package console

import (
	"encoding/hex"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/shell"
)

// LogTag is the syslog tag of the console's own lines.
const LogTag = "tacctl-console"

// EnvMarker is the variable that marks a tacctl line as run from a console
// session: the console puts 'TACCTL_CONSOLE=<session>' on each sudo command
// line (tier.EnvKeep keeps it), and the root side reads it ('tacctl ssh'
// hardens its ssh for it and logs console=<session>).
const EnvMarker = "TACCTL_CONSOLE"

// reSessionID is a session id: 12 lowercase hex digits.
var reSessionID = regexp.MustCompile(`^[0-9a-f]{12}$`)

// NewSessionID is a session id: 6 bytes of r (crypto/rand) in hex.
func NewSessionID(r io.Reader) (string, error) {
	b := make([]byte, 6)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", fmt.Errorf("cannot make a console session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// ValidSessionID reports whether s is a session id as NewSessionID makes
// them.
func ValidSessionID(s string) bool { return reSessionID.MatchString(s) }

// MarkerValue is a TACCTL_CONSOLE value as it goes into a log line: the id,
// or '?' for anything that is not one (the variable comes through sudo
// from the caller, who could set it to anything).
func MarkerValue(s string) string {
	if ValidSessionID(s) {
		return s
	}
	return "?"
}

// LogValue is v made safe for one 'key=value' field of a log line: '-' when
// empty, every byte outside [A-Za-z0-9._:/@+-] replaced by '?', at most 64
// bytes.
func LogValue(v string) string {
	if v == "" {
		return "-"
	}
	if len(v) > 64 {
		v = v[:64]
	}
	b := []byte(v)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._:/@+-", c) >= 0:
		default:
			b[i] = '?'
		}
	}
	return string(b)
}

// Session is one console session, for its log lines.
type Session struct {
	ID   string
	User string
	// From is the client's address (the first field of SSH_CLIENT), TTY
	// the terminal (SSH_TTY); "" for none.
	From, TTY string
	// Mode is interactive, command or batch.
	Mode string
}

// Modes of a session.
const (
	ModeInteractive = "interactive"
	ModeCommand     = "command"
	ModeBatch       = "batch"
)

// Reasons a session ends: the shell's (shell.End), and command for a -c
// string that was refused.
const (
	ReasonExit    = shell.EndExit
	ReasonEOF     = shell.EndEOF
	ReasonIdle    = shell.EndIdle
	ReasonHangup  = shell.EndHangup
	ReasonSignal  = shell.EndSignal
	ReasonCommand = shell.EndCommand
	ReasonFailed  = shell.EndFailed
	ReasonError   = shell.EndError
	// ReasonLocked: the required password change was not made (declined,
	// interrupted or failed), so the session ended at its opening.
	ReasonLocked = shell.EndLocked
)

// StartLine is the log line of the session's start.
func (s Session) StartLine() string {
	return "console start session=" + s.ID + " user=" + LogValue(s.User) + " from=" + LogValue(s.From) +
		" tty=" + LogValue(s.TTY) + " mode=" + s.Mode
}

// EndLine is the log line of the session's end.
func (s Session) EndLine(reason string, lines, status int) string {
	return "console end session=" + s.ID + " user=" + LogValue(s.User) + " reason=" + reason +
		" lines=" + strconv.Itoa(lines) + " status=" + strconv.Itoa(status)
}

// DenyLine is the log line of a refused -c string. first is a verb (Guard,
// VerbWord) or "": then the line reads "first=- len=<n>", n the length of
// the string, and no word of it is logged, because a refused string can be a
// password typed at the prompt.
func (s Session) DenyLine(first string, n int) string {
	l := "console DENY session=" + s.ID + " user=" + LogValue(s.User) + " reason=command first=" + LogValue(first)
	if first == "" {
		l += " len=" + strconv.Itoa(n)
	}
	return l
}

// PasswordChangeLine is the log line of the required password change at the
// opening of a session (0.2.20): event is "required" (the session opens held
// to it), "unknown" (it could not be read whether one is required, and the
// session opens held), "done" (the password was changed and the session goes
// on) or "failed" (it was not, and the session ends with status).
func (s Session) PasswordChangeLine(event string, status int) string {
	l := "console password-change " + event + " session=" + s.ID + " user=" + LogValue(s.User)
	if event == "failed" {
		l += " status=" + strconv.Itoa(status)
	}
	return l
}

// PasswordChangeDenyLine is the log line of a line refused because a password
// change is required: first is a verb of tacctl or a word of the console, or
// "": then the line reads "first=- len=<n>" and no word of it is logged, as
// for DenyLine, because a refused line can be a password typed at the prompt.
func (s Session) PasswordChangeDenyLine(first string, n int) string {
	l := "console DENY session=" + s.ID + " user=" + LogValue(s.User) + " reason=password-change first=" + LogValue(first)
	if first == "" {
		l += " len=" + strconv.Itoa(n)
	}
	return l
}

// SystemShellDenyLine is the log line of a refused system-shell.
func (s Session) SystemShellDenyLine(tier string) string {
	return "console system-shell DENY session=" + s.ID + " user=" + LogValue(s.User) + " tier=" + LogValue(tier)
}

// SystemShellStartLine is the log line of a system shell's start.
func (s Session) SystemShellStartLine(path string) string {
	return "console system-shell start session=" + s.ID + " user=" + LogValue(s.User) + " tty=" + LogValue(s.TTY) +
		" shell=" + LogValue(path)
}

// SystemShellEndLine is the log line of a system shell's end.
func (s Session) SystemShellEndLine(status int, d time.Duration) string {
	return "console system-shell end session=" + s.ID + " user=" + LogValue(s.User) + " status=" + strconv.Itoa(status) +
		" duration=" + Seconds(d)
}

// Seconds is d in whole seconds, as log lines give durations.
func Seconds(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	return strconv.FormatInt(int64(d/time.Second), 10)
}

// ClientAddr is the client's address from SSH_CLIENT ('<ip> <port>
// <port>'); "" when there is none.
func ClientAddr(sshClient string) string {
	f := strings.Fields(sshClient)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
