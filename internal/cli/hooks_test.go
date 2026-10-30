package cli

import (
	"context"
	"errors"
	"io"
	"strconv"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
)

// newTestHooks are the hooks of a test's invocations: the real ones, except
// the two reads of the machine no test may make. Nothing reaches a real
// address through the host-key fallback of a legacy-ssh device (it reads
// nothing unless a test sets hooks.keyFallback, or sets realKeyFallback with
// a device dial, as the fake old device's test does), and the suite never
// reads the real terminal's login record.
func newTestHooks() *hooks {
	return &hooks{
		askpassFromApp: true,
		keyFallback: func(*invocation) devreg.KeyFallback {
			return func(_ context.Context, address string, port int, _ bool, _ devssh.ScanTiming) ([]devreg.HostKey, error) {
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

// parallelized holds the tests that were decided: run side by side with the
// others (true) or alone, before any parallel test starts (false).
var parallelized sync.Map

// parallel makes the test run side by side with the others. It is called by
// the helpers that build a sandbox, once per test (a second call, and a call
// for a test that chose serial, do nothing). A test that sets the process
// environment, signals the process or writes a package-level registry calls
// serial first.
func parallel(t *testing.T) {
	t.Helper()
	if _, seen := parallelized.LoadOrStore(t, true); !seen {
		t.Parallel()
	}
}

// serial keeps the test out of the parallel set; it is the first statement
// of a test that cannot share the process (see parallel). Go runs every
// serial test before the first parallel one starts.
func serial(t *testing.T) {
	t.Helper()
	if v, seen := parallelized.Swap(t, false); seen && v.(bool) {
		t.Fatal("serial() after the test went parallel: make it the first statement of the test")
	}
}

// mustBeSerial fails a test that went parallel but uses something that
// writes process-wide state.
func mustBeSerial(t *testing.T) {
	t.Helper()
	if v, seen := parallelized.Load(t); !seen || v.(bool) {
		t.Fatal("this needs a serial test: call serial(t) first in the test")
	}
}
