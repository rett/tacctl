package devssh

import (
	"errors"
	"strconv"
	"strings"
	"unicode"
)

// The typed errors. A caller derives a record's result from them with
// errors.Is and errors.As and never parses the text. Their text names the
// device and the failure and never a credential: the password is not held
// anywhere an error is built from.
var (
	// ErrAuth: the device rejected the password (or asked for something
	// the password source cannot answer).
	ErrAuth = errors.New("authentication failed")
	// ErrTimeout: a connect, a hello, a command or an RPC did not finish
	// in time (the connect timeout, or the deadline of the context).
	ErrTimeout = errors.New("timed out")
	// ErrNoSubsystem: the device refused the 'netconf' subsystem (NETCONF
	// is not enabled for ssh on it).
	ErrNoSubsystem = errors.New("the device refused the netconf subsystem")
	// ErrUnreachable: no TCP connection (refused, no route, unresolvable).
	ErrUnreachable = errors.New("device unreachable")
	// ErrHandshake: the ssh handshake failed before authentication: no
	// common algorithm (a device that needs Target.Legacy), or the device
	// closed the connection.
	ErrHandshake = errors.New("ssh handshake failed")
	// ErrProtocol: the device broke the NETCONF framing or answered a
	// hello or an RPC the client cannot use.
	ErrProtocol = errors.New("protocol error")
	// ErrClosed: the session or the client was closed, or the device
	// ended the channel, before the exchange finished.
	ErrClosed = errors.New("session closed")
	// ErrOutputTooLarge: a reply grew past MaxOutput; the session is
	// closed.
	ErrOutputTooLarge = errors.New("output too large")
)

// ErrHostKey is a host key the client did not accept: the device offered
// Offered and it is none of the pinned keys, or nothing is pinned at all (a
// connection is then never made). The CLI shows Fingerprint and raises the
// hostkey notice; it never prompts.
type ErrHostKey struct {
	// Offered is the key the device presented, '<type> <base64>' as
	// devreg.HostKey holds it (empty when no connection was made).
	Offered string
	// Fingerprint is Offered as 'SHA256:<base64>' (empty with Offered).
	Fingerprint string
	// Pinned are the keys that were pinned (empty: none were).
	Pinned []string
}

// Unpinned reports that no host key is pinned for the device.
func (e ErrHostKey) Unpinned() bool { return len(e.Pinned) == 0 }

func (e ErrHostKey) Error() string {
	if e.Unpinned() {
		return "no host key is pinned for the device"
	}
	if e.Offered == "" {
		return "the device's host key is not one of the pinned keys"
	}
	typ, _, _ := strings.Cut(e.Offered, " ")
	return "the device offered a host key (" + typ + " " + e.Fingerprint + ") that is not pinned"
}

// CommandError is a CLI command that ended with a non-zero exit status (an
// exec channel only; a shell session has no status). Run returns the output
// with it.
type CommandError struct{ Status int }

func (e CommandError) Error() string {
	return "the command ended with status " + strconv.Itoa(e.Status)
}

// RPCError is an <rpc-error> in a NETCONF reply: the first error's
// severity, tag and message, as the device wrote them. RPC returns the
// reply with it.
type RPCError struct {
	Severity, Tag, Message string
}

func (e RPCError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = e.Tag
	}
	if msg == "" {
		msg = "unspecified error"
	}
	return "the device answered with an rpc-error: " + msg
}

// maxErrText is the longest device-controlled text an error carries.
const maxErrText = 200

// sanitize makes device-controlled text safe to print: control and
// formatting characters (escape sequences, bidi overrides, line breaks)
// become '?', and the text is cut at maxErrText bytes. Every string a
// device can influence goes through it before it enters an error.
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= maxErrText {
			b.WriteString("...")
			break
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' || r == unicode.ReplacementChar {
			r = '?'
		}
		b.WriteRune(r)
	}
	return b.String()
}
