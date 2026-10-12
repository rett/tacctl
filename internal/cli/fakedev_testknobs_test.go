//go:build testknobs

package cli

import (
	"path/filepath"
	"strings"
	"testing"
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
	inv := &invocation{app: h.app}
	if inv.deviceDialer() == nil || h.app.Knobs.DevicePassword() != "pw" {
		t.Error("the knobs did not take effect in a test build")
	}
	// A malformed knob is an error, not a silent no-op.
	h = newHarness(t, nil, "TACCTL_TEST_DEVICE_DIAL=192.0.2.10:22")
	if h.app.KnobsErr == nil {
		t.Error("a non-loopback dial was accepted")
	}
}
