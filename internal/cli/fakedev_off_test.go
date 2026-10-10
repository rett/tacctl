//go:build !testknobs

package cli

import (
	"testing"
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
	inv := &invocation{app: h.app}
	if d := inv.deviceDialer(); d != nil {
		t.Error("the dial knob took effect in a build without the tag")
	}
	if pw := h.app.Knobs.DevicePassword(); pw != "" {
		t.Errorf("the password knob took effect: %q", pw)
	}
}
