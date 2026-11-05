//go:build !testknobs

package cli

import (
	"testing"

	"github.com/rett/tacctl/internal/devreg"
)

// A production build has neither the fake device verb nor the knobs that
// send a pull to it, whatever the environment holds.
func TestFakeDeviceAndDeviceKnobsAreAbsentWithoutTestKnobs(t *testing.T) {
	root := newRoot(&invocation{})
	for _, c := range root.Commands() {
		if c.Name() == "_fake-device" || c.Name() == "_snmp-agent" {
			t.Errorf("a production build has the test command %s", c.Name())
		}
	}
	h := newHarness(t, nil, "TACCTL_TEST_DEVICE_DIAL=127.0.0.1:2222", "TACCTL_TEST_DEVICE_PASSWORD=fakedev-password")
	inv := &invocation{app: h.app, hooks: newTestHooks()}
	if d := inv.deviceDialer(); d != nil {
		t.Error("the dial knob took effect in a build without the tag")
	}
	if pw := h.app.Knobs.DevicePassword(); pw != "" {
		t.Errorf("the password knob took effect: %q", pw)
	}
}

// A production build never shortens the quiet period of a device session:
// the knob is ignored and no Target carries a Quiet, so devssh's default
// (150 ms) applies.
func TestDeviceQuietIsZeroWithoutTestKnobs(t *testing.T) {
	h := newHarness(t, nil, "TACCTL_TEST_DEVICE_QUIET=25ms")
	for name, hk := range map[string]*hooks{"no hooks": nil, "empty hooks": {}} {
		inv := &invocation{app: h.app, hooks: hk}
		if q := inv.deviceQuiet(); q != 0 {
			t.Errorf("%s: deviceQuiet = %v, want 0", name, q)
		}
		if tg := inv.deviceTarget(devreg.Entry{Address: "192.0.2.10"}, "alice", nil); tg.Quiet != 0 {
			t.Errorf("%s: Target.Quiet = %v, want 0", name, tg.Quiet)
		}
	}
}
