package hosts

// Host-key pinning of enrolled hosts (docs/plans/operator-console.md 3.7):
// after 'host enroll' or 'host sync' has run its script on a host, the
// host's ssh keys are read and pinned in the device registry, so 'tacctl
// ssh <host>' can check them. The registry lives in internal/devreg, which
// reads this package; the pinning itself is therefore handed in as
// Env.PinHostKeys by the command line, and this file only says which host
// and port are scanned. The client script is not involved.

import (
	"context"
	"strconv"
	"strings"
)

// KeyPinner pins the ssh host keys of the enrolled host name, reachable at
// host on port. It prints what it did; a failure is a warning, never the
// end of an enroll or a sync.
type KeyPinner func(ctx context.Context, name, host string, port int)

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
func (env *Env) PinKeys(ctx context.Context, e Entry) {
	if env.PinHostKeys == nil {
		return
	}
	if host, port, ok := ScanTarget(e.Target, e.Port); ok {
		env.PinHostKeys(ctx, e.Name, host, port)
	}
}
