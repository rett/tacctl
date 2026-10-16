package cli

import (
	"context"
	"errors"
	"io"
	"strconv"

	"github.com/rett/tacctl/internal/devreg"
)

// newTestHooks are the hooks of a test's invocations: the real ones, except
// the two reads of the machine no test may make. Nothing reaches a real
// address through the host-key fallback of a legacy-ssh device (it reads
// nothing unless a test sets hooks.keyFallback, or sets realKeyFallback with
// a device dial, as the fake old device's test does), and the suite never
// reads the real terminal's login record.
func newTestHooks() *hooks {
	return &hooks{
		keyFallback: func(*invocation) devreg.KeyFallback {
			return func(_ context.Context, address string, port int) ([]devreg.HostKey, error) {
				return nil, errors.New("tests do not dial " + address + ":" + strconv.Itoa(port))
			}
		},
		terminalLine: func() string { return "" },
	}
}

// terminal makes stdin count as a terminal (or not) for the sandbox's runs.
func (sb *sandbox) terminal(tty bool) {
	sb.t.Helper()
	sb.hooks.sshTerminal = func(io.Reader) bool { return tty }
}
