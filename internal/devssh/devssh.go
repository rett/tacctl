// Package devssh is tacctl's native SSH client for network devices
// (docs/plans/0.2.4-plan.md D60, D61): a thin driver on
// golang.org/x/crypto/ssh that reads a device's configuration over a CLI
// channel or the NETCONF subsystem. It is pure: no terminal, no logging, no
// package state, no clock but the deadlines of the contexts it is given.
//
// What it guarantees, and what the callers rely on:
//
//   - The host key is pinned. A device is connected to only with at least
//     one pinned key (the registry's, as '<type> <base64>' texts), and the
//     handshake succeeds only if the key the device offers is one of them:
//     no trust on first use, no prompt, no known_hosts file.
//   - The password comes from the PasswordSource alone, is asked for at
//     most once per connection and is sent at most once: if the device
//     rejects it, the next method is not tried with it, so a wrong password
//     costs one attempt per device, not three.
//   - Nothing secret is in an error, and nothing is written anywhere:
//     errors carry typed causes and device-side text, which is cleaned of
//     control characters and cut short first. The password is a Go string
//     and cannot be zeroed; the memo drops its reference after the send.
//   - A device cannot make the client use unbounded memory: a command's
//     output or a NETCONF message is at most MaxOutput, and the session is
//     closed when a device sends more.
//
// Two things callers must know. On Junos the exit status of an exec channel
// does not signal a CLI error (a syntax error exits 0 and its text,
// 'error: ...' or 'syntax error', is in the output): the vendor reader
// inspects the output. And an exec channel that ends without an exit status
// is an error (ErrClosed), never a short success.
//
// internal/devssh/fakedev is the in-process device the tests and the
// bats suite run against.
package devssh

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// DefaultPort is the ssh port a Target with Port 0 connects to.
const DefaultPort = 22

// DefaultConnectTimeout bounds the TCP connect, the handshake and the
// authentication (10 s: plan section 5), and the first prompt of a shell or
// the hello of a NETCONF session; a Target with ConnectTimeout 0 has it.
const DefaultConnectTimeout = 10 * time.Second

// DefaultQuiet is the silence a shell session waits for (a Target with
// Quiet 0): long enough for a device to answer a line typed ahead, short
// enough that a command costs a fraction of a second.
const DefaultQuiet = 150 * time.Millisecond

// MaxOutput is the most one command's output or one NETCONF message may
// hold; a device that sends more has the session closed (ErrOutputTooLarge).
const MaxOutput = 32 << 20

// PasswordSource returns the password; Dial calls it at most once per
// connection, and only when the device asks for a password. Both the
// 'password' and the 'keyboard-interactive' methods answer from it
// (keyboard-interactive only to a prompt that is a password prompt). It
// must return promptly and must not prompt on a terminal: the caller
// resolves the password before Dial (docs/plans/0.2.4-plan.md section 5)
// and the source only hands it over. A source that blocks costs the
// connect timeout (Dial returns ErrTimeout) and its goroutine is left to
// finish.
type PasswordSource func() (string, error)

// Dialer opens the TCP connection (tests, and the test-build knob that
// sends every device to the fake one). Nil is a net.Dialer.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// Target is one device to connect to.
type Target struct {
	Host string
	Port int // 0 is DefaultPort
	User string
	// HostKeys are the pinned host keys, '<type> <base64>' as
	// devreg.HostKey.String writes them. At least one must parse: with
	// none, Dial refuses with ErrHostKey (Unpinned) before connecting.
	HostKeys []string
	// Legacy adds the algorithms old IOS needs to the client's lists (the
	// SHA-1 key exchanges, the CBC ciphers x/crypto implements and ssh-rsa
	// host keys), as devreg.Profile does for the system ssh. The default
	// sets stay first.
	Legacy   bool
	Password PasswordSource
	// ConnectTimeout is DefaultConnectTimeout when zero.
	ConnectTimeout time.Duration
	// Quiet is the silence a shell session waits for before it trusts what
	// it sees (a prompt is the end of the output, a more-prompt is a
	// pager): DefaultQuiet when zero.
	Quiet  time.Duration
	Dialer Dialer
}

// addr is host:port.
func (t Target) addr() string {
	port := t.Port
	if port == 0 {
		port = DefaultPort
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(port))
}

func (t Target) quietPeriod() time.Duration {
	if t.Quiet > 0 {
		return t.Quiet
	}
	return DefaultQuiet
}

func (t Target) timeout() time.Duration {
	if t.ConnectTimeout > 0 {
		return t.ConnectTimeout
	}
	return DefaultConnectTimeout
}

// legacyKex are the key exchanges Legacy appends to the supported ones.
var legacyKex = []string{
	ssh.InsecureKeyExchangeDH14SHA1,
	ssh.InsecureKeyExchangeDHGEXSHA1,
	ssh.InsecureKeyExchangeDH1SHA1,
}

// legacyCiphers are the ciphers Legacy appends to the supported ones: the
// CBC ciphers old IOS offers (aes192-cbc and aes256-cbc, which it offers
// too, x/crypto does not implement).
var legacyCiphers = []string{
	ssh.InsecureCipherAES128CBC,
	ssh.InsecureCipherTripleDESCBC,
}

// Client is an authenticated connection to one device. It is safe for
// concurrent use; the sessions it opens are each for one caller at a time.
type Client struct {
	conn    *ssh.Client
	addr    string
	timeout time.Duration
	quiet   time.Duration
	// ctx is the context Dial was given: the connection lives within it.
	ctx context.Context

	mu     sync.Mutex
	closed bool
	stop   func() bool // detaches the AfterFunc that closes the client
}

// Dial connects to the device, checks its host key against the pinned ones
// and authenticates. ctx scopes the connection: when it ends the client is
// closed and every pending call returns ErrTimeout (a deadline) or
// context.Canceled. The errors are those of errors.go.
func Dial(ctx context.Context, t Target) (*Client, error) {
	pins, err := parsePins(t.HostKeys)
	if err != nil {
		return nil, err
	}
	if t.Password == nil {
		return nil, errors.New("devssh: no password source")
	}
	addr := t.addr()
	hs, cancel := context.WithTimeout(ctx, t.timeout())
	defer cancel()

	dial := t.Dialer
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(hs, "tcp", addr)
	if err != nil {
		return nil, dialError(ctx, hs, addr, err)
	}

	st := &dialState{pins: pins, password: &passwordMemo{src: t.Password, ctx: hs}}
	cfg := &ssh.ClientConfig{
		User:              t.User,
		Auth:              st.methods(),
		HostKeyCallback:   st.hostKey,
		HostKeyAlgorithms: hostKeyAlgorithms(pins, t.Legacy),
		ClientVersion:     "SSH-2.0-tacctl",
	}
	if t.Legacy {
		sup := ssh.SupportedAlgorithms()
		cfg.KeyExchanges = append(sup.KeyExchanges, legacyKex...)
		cfg.Ciphers = append(sup.Ciphers, legacyCiphers...)
	}
	// The deadline and the cancellation of the context close the socket,
	// which fails the handshake wherever it stands.
	unhook := context.AfterFunc(hs, func() { _ = conn.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
	if !unhook() && err == nil {
		// The context ended just as the handshake did.
		err = hs.Err()
	}
	if err != nil {
		_ = conn.Close()
		return nil, st.classify(ctx, hs, addr, err)
	}
	c := &Client{conn: ssh.NewClient(sc, chans, reqs), addr: addr, timeout: t.timeout(), quiet: t.quietPeriod(), ctx: ctx}
	stop := context.AfterFunc(ctx, func() { _ = c.Close() })
	c.mu.Lock()
	c.stop = stop
	closed := c.closed
	c.mu.Unlock()
	if closed {
		stop()
	}
	return c, nil
}

// Close ends the connection and every session on it; later calls are
// no-ops.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	stop := c.stop
	c.mu.Unlock()
	if stop != nil {
		stop()
	}
	return c.conn.Close()
}

// ServerVersion is the identification string the device sent
// ('SSH-2.0-...').
func (c *Client) ServerVersion() string { return sanitize(string(c.conn.ServerVersion())) }

// ctxErr is why the client's context ended, as a typed error; nil while it
// is live.
func (c *Client) ctxErr() error { return contextError(c.ctx, c.addr) }

// contextError maps a finished context to ErrTimeout or context.Canceled.
func contextError(ctx context.Context, addr string) error {
	switch err := ctx.Err(); {
	case err == nil:
		return nil
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%w: %s", ErrTimeout, addr)
	default:
		return err
	}
}

// within runs fn, a blocking ssh call (opening a channel, a channel
// request), so that ctx bounds it. Neither can be interrupted, so when ctx
// ends first the connection is closed, which ends the call, and the typed
// context error is returned. That is connection-fatal on purpose: a Client
// is one device's job, and its context is the job's deadline.
func (c *Client) within(ctx context.Context, fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = c.Close()
		<-done
		return callError(ctx, c)
	}
}

// dialState is what one Dial's callbacks record, for classifying the
// failure afterwards.
type dialState struct {
	pins     []ssh.PublicKey
	password *passwordMemo

	mu      sync.Mutex
	offered ssh.PublicKey // the key the device presented
	badKey  bool          // ... and it was not pinned
}

var errHostKeyRejected = errors.New("host key not pinned")

// hostKey is the HostKeyCallback: the offered key must equal a pinned one.
func (s *dialState) hostKey(_ string, _ net.Addr, key ssh.PublicKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offered = key
	for _, p := range s.pins {
		if bytes.Equal(p.Marshal(), key.Marshal()) {
			return nil
		}
	}
	s.badKey = true
	return errHostKeyRejected
}

// methods are the authentication methods, in the order PasswordAuth names
// them: keyboard-interactive, then password.
func (s *dialState) methods() []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.KeyboardInteractive(s.password.challenge),
		ssh.PasswordCallback(s.password.plain),
	}
}

// classify turns the error of a failed handshake into a typed one.
func (s *dialState) classify(ctx, hs context.Context, addr string, err error) error {
	s.mu.Lock()
	bad, offered := s.badKey, s.offered
	s.mu.Unlock()
	switch {
	case bad:
		return hostKeyError(s.pins, offered)
	case s.password.srcErr() != nil:
		return s.password.srcErr()
	case ctx.Err() != nil:
		return contextError(ctx, addr)
	case errors.Is(hs.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: connecting to %s", ErrTimeout, addr)
	case s.password.sent() > 0 || strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%w: %s", ErrAuth, addr)
	}
	return fmt.Errorf("%w: %s: %s", ErrHandshake, addr, sanitize(err.Error()))
}

// dialError is the error of a failed TCP connect.
func dialError(ctx, hs context.Context, addr string, err error) error {
	switch {
	case ctx.Err() != nil:
		return contextError(ctx, addr)
	case errors.Is(hs.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: connecting to %s", ErrTimeout, addr)
	}
	return fmt.Errorf("%w: %s", ErrUnreachable, sanitize(err.Error()))
}

// parsePins reads the pinned key texts; a text that does not parse is
// skipped, and none left is ErrHostKey (Unpinned).
func parsePins(texts []string) ([]ssh.PublicKey, error) {
	var pins []ssh.PublicKey
	for _, t := range texts {
		f := strings.Fields(t)
		if len(f) != 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil {
			continue
		}
		key, err := ssh.ParsePublicKey(raw)
		if err != nil || key.Type() != f[0] {
			continue
		}
		pins = append(pins, key)
	}
	if len(pins) == 0 {
		return nil, ErrHostKey{}
	}
	return pins, nil
}

// keyText is a key as devreg.HostKey.String writes it.
func keyText(k ssh.PublicKey) string {
	return k.Type() + " " + base64.StdEncoding.EncodeToString(k.Marshal())
}

func hostKeyError(pins []ssh.PublicKey, offered ssh.PublicKey) ErrHostKey {
	e := ErrHostKey{}
	for _, p := range pins {
		e.Pinned = append(e.Pinned, keyText(p))
	}
	if offered != nil {
		e.Offered, e.Fingerprint = keyText(offered), ssh.FingerprintSHA256(offered)
	}
	return e
}

// hostKeyAlgorithms is the order the client offers host key algorithms:
// those of the pinned keys first (so a device that holds several key types
// shows the pinned one, as ssh does with known_hosts), then the rest of the
// supported ones, and ssh-rsa (SHA-1) only with legacy. Certificates are
// never offered: a pin is a key.
func hostKeyAlgorithms(pins []ssh.PublicKey, legacy bool) []string {
	var out []string
	add := func(algs ...string) {
		for _, a := range algs {
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	for _, p := range pins {
		switch p.Type() {
		case ssh.KeyAlgoRSA:
			add(ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256)
			if legacy {
				add(ssh.KeyAlgoRSA)
			}
		default:
			add(p.Type())
		}
	}
	for _, a := range ssh.SupportedAlgorithms().HostKeys {
		if !strings.Contains(a, "-cert-") {
			add(a)
		}
	}
	if legacy {
		add(ssh.KeyAlgoRSA)
	}
	return out
}

// write sends p on w within ctx. A write blocks when the device does not
// read and its window is full; when ctx ends first the connection is
// closed, as within does, which ends the write.
func (c *Client) write(ctx context.Context, w io.Writer, p []byte) error {
	done := make(chan error, 1)
	go func() { _, err := w.Write(p); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			return callError(ctx, c)
		}
		return nil
	case <-ctx.Done():
		_ = c.Close()
		<-done
		return callError(ctx, c)
	}
}
