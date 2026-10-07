package hosts

// 'host target': a test connection to a host's new ssh target before the
// registry line changes. It logs in exactly as 'host enroll' and 'host
// sync' do (the invoking user's ssh, agent, port and identity; BatchMode
// without a terminal), asks how the login reaches root, and reads the
// host's public keys and facts over the same connection.

import (
	"context"
	"io"
	"strings"
)

// ProbeCommand is the read-only remote command that says how the login
// reaches root: 'root' (it is root), 'sudo' (sudo without a password) or
// 'sudo-password' (sudo would ask, or the login may not sudo).
const ProbeCommand = `if [ "$(id -u)" = 0 ]; then echo root; elif sudo -n true 2>/dev/null; then echo sudo; else echo sudo-password; fi`

// Probe is what a test connection found.
type Probe struct {
	// Connected: ssh logged in and ran ProbeCommand.
	Connected bool
	// Root is ProbeCommand's answer.
	Root string
	// Keys is what ReadKeysCommand printed (KeysErr when nothing).
	Keys    []byte
	KeysErr error
}

// TestTarget logs in to target as RunScript would and reads, over one
// connection that it closes at the end: ProbeCommand, the host's keys and
// its facts (e.Facts). ssh's own messages go to stderr.
func (e *Env) TestTarget(ctx context.Context, target, port, identity string) Probe {
	var p Probe
	e.Facts, e.sessionKeys, e.sessionErr = nil, nil, nil
	s := e.ssh(port, identity)
	c := s.Cmd("-T", target, ProbeCommand)
	c.Stderr = e.Out.Stderr
	res, err := e.Runner.Run(ctx, c)
	if err == nil && res.Code == 0 {
		p.Connected = true
		p.Root = strings.TrimSpace(string(res.Stdout))
		e.readKeys(ctx, s, target)
		e.readFacts(ctx, s, target)
		p.Keys, p.KeysErr = e.sessionKeys, e.sessionErr
		if p.Keys == nil && p.KeysErr == nil {
			p.KeysErr = ErrKeysUnread
		}
	}
	closer := s.Cmd("-O", "exit", target)
	closer.Stdout, closer.Stderr = io.Discard, io.Discard
	_, _ = e.Runner.Run(context.WithoutCancel(ctx), closer)
	return p
}

// TTYAvailable reports whether stdin is a terminal that can answer a
// prompt (sudo's password during 'host sync').
func (e *Env) TTYAvailable() bool { return e.stdinTTY() }
