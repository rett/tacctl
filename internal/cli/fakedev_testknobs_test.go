//go:build testknobs

package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devreg"
)

// In a test build the hidden verb is there, prints where it listens and the
// key it pins, and the dial knob sends every device to a loopback address.
func TestFakeDeviceVerbAndDialKnob(t *testing.T) {
	root := newRoot(&invocation{})
	if child(root, "_fake-device") == nil {
		t.Fatal("no _fake-device in a test build")
	}
	sb := newSandbox(t, false)
	dir := t.TempDir()
	out := sb.run("", []string{"_fake-device", dir, "--seconds", "1"})
	f := strings.Fields(out)
	if sb.code != 0 || len(f) != 3 || !strings.HasPrefix(f[0], "127.0.0.1:") || f[1] != "ssh-ed25519" {
		t.Errorf("exit %d output %q", sb.code, out)
	}
	sb.run("", []string{"_fake-device"})
	sb.expect(1, "", "Usage: tacctl _fake-device <dir>")
	sb.run("", []string{"_fake-device", filepath.Join(dir, "nope")})
	sb.expect(1, "", "is not a transcript directory")

	h := newHarness(t, nil, "TACCTL_TEST_DEVICE_DIAL=127.0.0.1:2222", "TACCTL_TEST_DEVICE_PASSWORD=pw")
	inv := &invocation{app: h.app, hooks: newTestHooks()}
	if inv.deviceDialer() == nil || h.app.Knobs.DevicePassword() != "pw" {
		t.Error("the knobs did not take effect in a test build")
	}
	// A malformed knob is an error, not a silent no-op.
	h = newHarness(t, nil, "TACCTL_TEST_DEVICE_DIAL=192.0.2.10:22")
	if h.app.KnobsErr == nil {
		t.Error("a non-loopback dial was accepted")
	}
}

// The quiet knob reaches every device session's Target, and wins over the
// tests' hook; with neither the Target has no Quiet (devssh's default).
func TestDeviceQuietKnobReachesTheTarget(t *testing.T) {
	e := devreg.Entry{Address: "192.0.2.10"}
	h := newHarness(t, nil, "TACCTL_TEST_DEVICE_QUIET=25ms")
	inv := &invocation{app: h.app, hooks: &hooks{deviceQuiet: 40 * time.Millisecond}}
	if q := inv.deviceTarget(e, "alice", nil).Quiet; q != 25*time.Millisecond {
		t.Errorf("knob and hook: Quiet = %v, want 25ms", q)
	}
	inv = &invocation{app: h.app}
	if q := inv.deviceQuiet(); q != 25*time.Millisecond {
		t.Errorf("knob, no hooks: %v, want 25ms", q)
	}
	h = newHarness(t, nil)
	inv = &invocation{app: h.app, hooks: &hooks{deviceQuiet: 40 * time.Millisecond}}
	if q := inv.deviceTarget(e, "alice", nil).Quiet; q != 40*time.Millisecond {
		t.Errorf("hook only: Quiet = %v, want 40ms", q)
	}
	inv = &invocation{app: h.app, hooks: newTestHooks()}
	if q := inv.deviceTarget(e, "alice", nil).Quiet; q != 0 {
		t.Errorf("neither: Quiet = %v, want 0", q)
	}
	for _, bad := range []string{"fast", "-1ms", "2s"} {
		if h = newHarness(t, nil, "TACCTL_TEST_DEVICE_QUIET="+bad); h.app.KnobsErr == nil {
			t.Errorf("TACCTL_TEST_DEVICE_QUIET=%s was accepted", bad)
		}
	}
}
