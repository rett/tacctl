package hosts

// Host-key pinning of enrolled hosts (docs/plans/operator-console.md 3.7):
// after 'host enroll' or 'host sync' has run its script on a host, the
// host's public keys are read over the same authenticated ssh connection
// (the administrator's own ssh, checked against their known_hosts:
// ReadKeysCommand, read-only), and the command line cross-checks them with
// an ssh-keyscan of the target and pins only the keys both agree on, in
// the device registry, so 'tacctl ssh <host>' can check them. The registry
// lives in internal/devreg, which reads this package; the pinning itself is
// therefore handed in as Env.PinHostKeys by the command line. The client
// script is not involved.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
)

// KeyPinner pins the ssh host keys of the enrolled host name, reachable at
// host on port; session is what ReadKeysCommand printed over the
// enrolment's connection (sessionErr when it could not be read). It prints
// what it did; a failure is a warning, never the end of an enroll or a
// sync.
type KeyPinner func(ctx context.Context, name, host string, port int, session []byte, sessionErr error)

// ReadKeysCommand is the read-only remote command that prints the host's
// public ssh host keys.
const ReadKeysCommand = "cat /etc/ssh/ssh_host_*_key.pub"

// ErrKeysUnread is a session read that printed nothing (no .pub file the
// login may read, or the command failed).
var ErrKeysUnread = errors.New("the host's public key files could not be read over the enrolment session")

// ScanTarget is the host and port whose keys are pinned for an enrolled
// host: the host part of '[user@]host' and the port (22 when empty). ok is
// false for a host enrolled with --local, which is reached without ssh.
func ScanTarget(target, port string) (host string, p int, ok bool) {
	if target == Local || target == "" {
		return "", 0, false
	}
	host = target
	if _, h, found := strings.Cut(target, "@"); found {
		host = h
	}
	p = 22
	if n, err := strconv.Atoi(port); err == nil && n > 0 && n < 65536 {
		p = n
	}
	return host, p, host != ""
}

// PinKeys pins the keys of e when the command line gave a pinner and e is
// reached over ssh.
// The keys come from the last RunScript of env with ReadKeys set.
func (env *Env) PinKeys(ctx context.Context, e Entry) {
	if env.PinHostKeys == nil {
		return
	}
	if host, port, ok := ScanTarget(e.Target, e.Port); ok {
		session, err := env.sessionKeys, env.sessionErr
		if session == nil && err == nil {
			err = ErrKeysUnread
		}
		env.PinHostKeys(ctx, e.Name, host, port, session, err)
	}
}

// readKeys runs ReadKeysCommand on target over the connection s shares
// with the script run, before it is closed.
func (env *Env) readKeys(ctx context.Context, s SSH, target string) {
	c := s.Cmd("-T", target, ReadKeysCommand)
	c.Stderr = io.Discard
	res, err := env.Runner.Run(ctx, c)
	switch {
	case err != nil:
		env.sessionErr = err
	case len(bytes.TrimSpace(res.Stdout)) == 0:
		env.sessionErr = ErrKeysUnread
	default:
		env.sessionKeys = res.Stdout
	}
}
