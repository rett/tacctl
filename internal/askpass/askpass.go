// Package askpass is the password cache of docs/plans/0.2.4-plan.md D70: an
// agent that lives inside the user's own 'tacctl shell' / 'tacctl-console'
// process and keeps the network login password of the session in memory,
// and the client side that asks it (the root-side 'device config pull' and
// the _askpass helper that ssh runs as SSH_ASKPASS).
//
// The agent (Agent) holds the secret in a page of its own, allocated with
// mmap and locked with mlock, in a process marked not dumpable; it is
// zeroed when it is forgotten or expires and never converted to a Go
// string. It listens on a Unix socket in a private directory (SocketDir)
// and answers only
//
//   - a peer whose uid is the user's or root's (SO_PEERCRED),
//   - a request that carries the session token Listen returned, and
//   - while the shell has a line in flight (BeginLine ... EndLine).
//
// The location and the token travel together in the environment variable
// EnvVar as '<socket path>:<token>'; Client parses it. The token is minted
// for each line (BeginLine) and invalid after it (EndLine), so a value read
// from an earlier line, or by another process of the user after the line
// ended, opens nothing; during the line it opens one get.
//
// Wire protocol: one request per connection, one line, the token first:
//
//	<token> have            -> ok | no
//	<token> get             -> ok <n>\n<n bytes> | no
//	<token> store <n>\n<n bytes>   -> ok
//	<token> forget          -> ok
//
// Every refusal is 'err <code>' (the Err* values of the client map the
// codes); a peer with the wrong uid gets no answer at all. A secret is 1 to
// MaxSecret bytes without a line break or NUL.
//
// Gets: by default one per in-flight line (Options.MaxGets). A second get
// on the same line is taken for ssh retrying a password the device refused
// (three tries per method): it is refused and the password is forgotten.
//
// Lifetimes are wall-clock time (the monotonic clock stops while the
// machine sleeps). The idle time restarts at each get; the maximum runs
// from the store of those bytes, and storing the same bytes again does not
// extend it (a caller stores only a password the person typed, never one
// it fetched).
//
// What it does not do: root reads any process, and so does the user's own
// code with the token; mlock keeps the page out of swap but not out of a
// hibernation image; a debugger attached before the agent starts is
// refused (ErrTraced), one attached by root later is not stopped. The
// cache protects the password against other users and against its landing
// in files, logs, argv or the environment. The secret is never put in an
// error, a log line or a message of this package.
package askpass

import (
	"errors"
	"io"
	"runtime"
	"time"
)

// EnvVar is the environment variable that carries '<socket path>:<token>'
// from the shell to the commands it runs (kept through sudo by the tiers
// drop-in's env_keep, see internal/tier).
const EnvVar = "TACCTL_ASKPASS"

// HelperEnv is the marker the root side puts, as '=1', in the environment of
// the ssh it runs as the user: ssh executes SSH_ASKPASS with the prompt as
// its only argument and no way to give the program arguments of its own, so
// SSH_ASKPASS names the tacctl binary itself and tacctl takes 'one argument
// and this marker' for the helper verb '_askpass <prompt>'.
const HelperEnv = "TACCTL_ASKPASS_HELPER"

// MaxSecret is the longest secret the cache holds, in bytes.
const MaxSecret = 1024

// Defaults of the lifetimes (D70 (4)): the idle time without a get and the
// maximum lifetime from the store.
const (
	DefaultIdle = 15 * time.Minute
	DefaultMax  = 8 * time.Hour
)

// Why a password was forgotten (Event.Why, the argument of Agent.Forget).
// The shell prints 'password forgotten (<why>)'.
const (
	WhyIdle     = "idle timeout"
	WhyMax      = "maximum lifetime"
	WhyRejected = "rejected by a device"
	WhyPasswd   = "password changed"
	WhyCommand  = "console forget"
	WhyExit     = "session ended"
	WhyClock    = "clock changed"
)

// Errors. None of them carries the secret or the token.
var (
	// ErrNoAgent: no cache is configured (EnvVar unset) or none answers.
	ErrNoAgent = errors.New("no password cache is available")
	// ErrBadEnv: the value of EnvVar is not '<absolute path>:<token>'.
	ErrBadEnv = errors.New("the password cache setting is malformed")
	// ErrDenied: the agent refused the token, or closed the connection.
	ErrDenied = errors.New("the password cache refused the request")
	// ErrPeer: the socket is not the expected user's.
	ErrPeer = errors.New("the password cache socket is not owned by the expected user")
	// ErrNotInFlight: the agent answers only while a command is running.
	ErrNotInFlight = errors.New("the password cache is not answering now")
	// ErrEmpty: nothing is cached (never stored, forgotten or expired).
	ErrEmpty = errors.New("no password is cached")
	// ErrLimit: the agent already answered as often as it allows for this
	// command (Options.MaxGets).
	ErrLimit = errors.New("the password cache answered the allowed number of times")
	// ErrBusy: another store is being received.
	ErrBusy = errors.New("the password cache is busy")
	// ErrBadSecret: empty, longer than MaxSecret, or with a line break or
	// NUL.
	ErrBadSecret = errors.New("the password cannot be cached")
	// ErrProtocol: the other side did not speak the protocol.
	ErrProtocol = errors.New("the password cache answered unexpectedly")
	// ErrClosed: the agent was closed.
	ErrClosed = errors.New("the password cache is closed")
	// ErrNoLock: the secret page could not be locked in memory
	// (RLIMIT_MEMLOCK, or no mlock): the agent is not started rather than
	// let the password reach swap.
	ErrNoLock = errors.New("cannot lock memory for the password cache")
	// ErrTraced: a tracer is attached to the process (TracerPid in
	// /proc/self/status), which could read the page: the agent is not
	// started.
	ErrTraced = errors.New("the process is being traced; no password cache")
	// ErrNoDir: no usable directory for the socket.
	ErrNoDir = errors.New("no private directory for the password cache socket")
	// ErrNoTerminal: Prompt needs a terminal.
	ErrNoTerminal = errors.New("no terminal to read the password from")
	// ErrCancelled: the person cancelled the prompt (Ctrl-C, Ctrl-D).
	ErrCancelled = errors.New("password entry cancelled")
	// ErrNotPassword: the helper was asked for something that is not a
	// password prompt.
	ErrNotPassword = errors.New("not a password prompt")
)

// Zero overwrites b. Callers of Client.Get and Prompt zero what they got as
// soon as they are done with it.
func Zero(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

// validSecret reports whether b can be cached.
func validSecret(b []byte) bool {
	if len(b) == 0 || len(b) > MaxSecret {
		return false
	}
	for _, c := range b {
		if c == '\n' || c == '\r' || c == 0 {
			return false
		}
	}
	return true
}

// Verbs and answer words of the wire protocol.
const (
	verbHave   = "have"
	verbGet    = "get"
	verbStore  = "store"
	verbForget = "forget"

	ansOK  = "ok"
	ansNo  = "no"
	ansErr = "err"
)

// Codes after 'err'.
const (
	codeDenied     = "denied"
	codeNotInFlt   = "not-in-flight"
	codeLimit      = "limit"
	codeBusy       = "busy"
	codeBadRequest = "bad-request"
	codeBadSecret  = "bad-secret"
	codeClosed     = "closed"
)

const (
	// maxLine bounds a request or answer line.
	maxLine = 96
	// tokenLen is the token in characters: 32 random bytes in hex.
	tokenLen = 64
	// ioTimeout bounds one request from connect to answer.
	ioTimeout = 5 * time.Second
	// sunPathMax is the longest socket path (sun_path is 108 bytes with
	// the NUL).
	sunPathMax = 107
)

// readLine reads a line of at most limit bytes, without the line break, one
// byte at a time: nothing is buffered, so the bytes that follow the line
// (a secret) are never read into memory the caller does not control.
func readLine(r io.Reader, limit int) (string, error) {
	var one [1]byte
	line := make([]byte, 0, 32)
	for {
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return "", err
		}
		if one[0] == '\n' {
			return string(line), nil
		}
		if len(line) >= limit {
			return "", ErrProtocol
		}
		line = append(line, one[0])
	}
}
