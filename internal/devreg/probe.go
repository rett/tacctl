package devreg

// Reachability (docs/plans/operator-console.md 3.3): a TCP connect to the
// entry's ssh port, 3 seconds, all entries at once, in-process. Only
// 'device check' and 'device list --probe' probe. The server often has no
// path to the devices' management ports, so a timeout is routinely a false
// alarm; the help text says so.

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// ProbeTimeout is how long a probe waits for a connection.
const ProbeTimeout = 3 * time.Second

// The results of a probe.
const (
	ProbeOpen        = "open"
	ProbeClosed      = "closed"
	ProbeTimedOut    = "timeout"
	ProbeUnreachable = "unreachable"
)

// Dialer opens a connection; tests replace ProbeDial with one that never
// leaves the machine.
type Dialer func(ctx context.Context, network, address string) (net.Conn, error)

// ProbeDial is the dialer of every probe (nil: a net.Dialer).
var ProbeDial Dialer

// ProbeTarget is the host (a name or an address) and port of one probe.
type ProbeTarget struct {
	Host string
	Port int
}

// Addr is host:port.
func (t ProbeTarget) Addr() string { return net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) }

// Probe connects to every target at once and returns, in order, open,
// closed (refused), timeout, or unreachable (no route, no such name).
func Probe(ctx context.Context, targets []ProbeTarget) []string {
	dial := ProbeDial
	if dial == nil {
		d := &net.Dialer{}
		dial = d.DialContext
	}
	out := make([]string, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, cancel := context.WithTimeout(ctx, ProbeTimeout)
			defer cancel()
			conn, err := dial(c, "tcp", t.Addr())
			out[i] = probeResult(err)
			if conn != nil {
				_ = conn.Close()
			}
		}()
	}
	wg.Wait()
	return out
}

func probeResult(err error) string {
	var ne net.Error
	switch {
	case err == nil:
		return ProbeOpen
	case errors.Is(err, syscall.ECONNREFUSED):
		return ProbeClosed
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ProbeTimedOut
	}
	return ProbeUnreachable
}
