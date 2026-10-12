package askpass

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// peerOf is peerUID (a test replaces it).
var peerOf = peerUID

// Client asks an Agent. The root-side 'device config pull' uses it with
// ExpectUID set to the invoking user's uid; the _askpass helper runs as the
// user. A Client sends nothing until the socket has proved to be that
// user's (owner of the file, SO_PEERCRED of the connection): a path from
// the environment must not make a privileged process talk to, or give a
// password to, someone else's server. The path is opened once (O_PATH,
// O_NOFOLLOW), the open file is what is checked, and the connection is
// made through that descriptor, so a link swapped in between changes
// nothing.
type Client struct {
	// Path and Token are the two parts of EnvVar.
	Path, Token string
	// ExpectUID is the uid the server must run as (NewClient: the
	// process's effective uid).
	ExpectUID int
	// Timeout bounds a request (ioTimeout when zero); a context's
	// deadline applies as well.
	Timeout time.Duration
}

// ParseEnv splits the value of EnvVar into the socket path and the token.
// "" is ErrNoAgent; anything that is not an absolute clean path, a colon
// and a 64-character lower-case hex token is ErrBadEnv.
func ParseEnv(v string) (path, token string, err error) {
	if v == "" {
		return "", "", ErrNoAgent
	}
	i := strings.LastIndexByte(v, ':')
	if i < 0 {
		return "", "", ErrBadEnv
	}
	path, token = v[:i], v[i+1:]
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > sunPathMax || strings.IndexByte(path, 0) >= 0 {
		return "", "", ErrBadEnv
	}
	if len(token) != tokenLen {
		return "", "", ErrBadEnv
	}
	for _, c := range []byte(token) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", "", ErrBadEnv
		}
	}
	return path, token, nil
}

// NewClient is the client for the value of EnvVar, expecting the server to
// run as the current effective uid.
func NewClient(env string) (*Client, error) {
	path, token, err := ParseEnv(env)
	if err != nil {
		return nil, err
	}
	return &Client{Path: path, Token: token, ExpectUID: os.Geteuid()}, nil
}

// Env is the value of EnvVar this client was made from.
func (c *Client) Env() string { return c.Path + ":" + c.Token }

// Have asks whether a password is cached and may be fetched now.
func (c *Client) Have(ctx context.Context) (bool, error) {
	ans, body, err := c.do(ctx, verbHave, nil)
	if err != nil {
		return false, err
	}
	Zero(body)
	return ans == ansOK, nil
}

// Get fetches the cached password. The caller zeroes it (Zero) when done.
// ErrEmpty when none is cached.
func (c *Client) Get(ctx context.Context) ([]byte, error) {
	ans, body, err := c.do(ctx, verbGet, nil)
	if err != nil {
		return nil, err
	}
	if ans != ansOK || len(body) == 0 {
		Zero(body)
		return nil, ErrEmpty
	}
	if !validSecret(body) {
		Zero(body)
		return nil, ErrProtocol
	}
	return body, nil
}

// Store asks the agent to cache secret, which a device has accepted. The
// caller keeps (and zeroes) its own copy.
func (c *Client) Store(ctx context.Context, secret []byte) error {
	if !validSecret(secret) {
		return ErrBadSecret
	}
	_, _, err := c.do(ctx, verbStore+" "+strconv.Itoa(len(secret)), secret)
	return err
}

// Forget tells the agent to drop the password (a device rejected it).
func (c *Client) Forget(ctx context.Context) error {
	_, _, err := c.do(ctx, verbForget, nil)
	return err
}

// do sends '<token> <req>\n' and the optional body, and reads the answer.
// The answer 'ok <n>' brings n bytes, returned as body.
func (c *Client) do(ctx context.Context, req string, payload []byte) (ans string, body []byte, err error) {
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = ioTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	sfd, err := c.openSocket()
	if err != nil {
		return "", nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", "/proc/self/fd/"+strconv.Itoa(sfd))
	_ = unix.Close(sfd)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrNoAgent, unwrapOp(err))
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return "", nil, ErrProtocol
	}
	if uid, err := peerOf(uc); err != nil || uid != c.ExpectUID {
		return "", nil, ErrPeer
	}
	out := net.Buffers{[]byte(c.Token + " " + req + "\n")}
	if payload != nil {
		out = append(out, payload)
	}
	if _, err := out.WriteTo(conn); err != nil {
		return "", nil, closedOrProtocol(err)
	}
	line, err := readLine(conn, maxLine)
	if err != nil {
		return "", nil, closedOrProtocol(err)
	}
	f := strings.Split(line, " ")
	switch {
	case len(f) == 1 && (f[0] == ansOK || f[0] == ansNo):
		return f[0], nil, nil
	case len(f) == 2 && f[0] == ansOK:
		n, err := strconv.Atoi(f[1])
		if err != nil || n < 1 || n > MaxSecret {
			return "", nil, ErrProtocol
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(conn, b); err != nil {
			Zero(b)
			return "", nil, ErrProtocol
		}
		return ansOK, b, nil
	case len(f) == 2 && f[0] == ansErr:
		return "", nil, codeError(f[1])
	}
	return "", nil, ErrProtocol
}

// closedOrProtocol: a connection the agent closed without an answer is how
// it refuses a peer; anything else (a timeout, a garbled line) is not.
func closedOrProtocol(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return ErrDenied
	}
	return ErrProtocol
}

// codeError maps an 'err <code>' answer to its error.
func codeError(code string) error {
	switch code {
	case codeDenied:
		return ErrDenied
	case codeNotInFlt:
		return ErrNotInFlight
	case codeLimit:
		return ErrLimit
	case codeBusy:
		return ErrBusy
	case codeBadSecret:
		return ErrBadSecret
	case codeClosed:
		return ErrClosed
	}
	return ErrProtocol
}

// openSocket opens Path as an O_PATH descriptor without following a link
// in the last component and checks what it opened: a socket of the
// expected user. The caller closes the descriptor.
func (c *Client) openSocket() (int, error) {
	fd, err := unix.Open(c.Path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return -1, ErrPeer
		}
		return -1, fmt.Errorf("%w: %v", ErrNoAgent, err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK || int(st.Uid) != c.ExpectUID {
		_ = unix.Close(fd)
		return -1, ErrPeer
	}
	return fd, nil
}

// unwrapOp is the innermost cause of a path or dial error, without the
// path: the text of an error from this package is for a person.
func unwrapOp(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err
	}
	return err
}

// RunHelper is the _askpass helper: prompt is the text ssh passed as
// argument 1 and env the value of EnvVar. When the prompt is a password
// prompt (IsPasswordPrompt) and the agent has the password, it is written
// to w followed by a line break, as ssh expects; any other case is an
// error and nothing is written (the command exits 1 and ssh falls back to
// asking, or fails).
func RunHelper(ctx context.Context, env, prompt string, w io.Writer) error {
	if !IsPasswordPrompt(prompt) {
		return ErrNotPassword
	}
	c, err := NewClient(env)
	if err != nil {
		return err
	}
	secret, err := c.Get(ctx)
	if err != nil {
		return err
	}
	defer Zero(secret)
	if _, err := w.Write(secret); err != nil {
		return err
	}
	_, err = w.Write([]byte{'\n'})
	return err
}

// IsPasswordPrompt reports whether ssh's askpass prompt text asks for the
// account password: 'Password:', '(user@host) Password:' (keyboard
// interactive) or 'user@host's password:', case-insensitive, one line.
// Host key questions ('Are you sure you want to continue connecting'),
// passphrases ('Enter passphrase for key ...'), PINs, one-time codes and
// every other text are not.
func IsPasswordPrompt(text string) bool {
	t := strings.TrimSpace(text)
	if t == "" || len(t) > 256 || strings.ContainsAny(t, "\r\n") {
		return false
	}
	t = strings.ToLower(t)
	t, ok := strings.CutSuffix(t, ":")
	if !ok {
		return false
	}
	t = strings.TrimSpace(t)
	if rest, ok := strings.CutPrefix(t, "("); ok {
		who, after, ok := strings.Cut(rest, ") ")
		if !ok || who == "" || strings.ContainsAny(who, " \t()") {
			return false
		}
		t = strings.TrimSpace(after)
	}
	if t == "password" {
		return true
	}
	if who, ok := strings.CutSuffix(t, "'s password"); ok {
		return strings.Contains(who, "@") && !strings.ContainsAny(who, " \t'()")
	}
	return false
}
