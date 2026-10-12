package conf

import "testing"

// The three keys 'device config pull' reads (0.2.4, D68): their ranges and
// defaults.
func TestDeviceConfigKeys(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, c := range []struct {
		path string
		val  any
		ok   bool
	}{
		{"device.config.max_concurrency", 1, true}, {"device.config.max_concurrency", 64, true},
		{"device.config.max_concurrency", 0, false}, {"device.config.max_concurrency", 65, false},
		{"device.config.timeout", 10, true}, {"device.config.timeout", 600, true},
		{"device.config.timeout", 9, false}, {"device.config.timeout", 601, false},
		{"device.config.transport", "auto", true}, {"device.config.transport", "netconf", true},
		{"device.config.transport", "ssh", true}, {"device.config.transport", "telnet", false},
		{"device.config.nope", 1, false},
	} {
		msg := s.Validate(c.path, c.val, false)
		if (msg == "") != c.ok {
			t.Errorf("%s = %v: %q", c.path, c.val, msg)
		}
	}
	for path, want := range map[string]any{"device.config.max_concurrency": 8, "device.config.transport": "auto", "device.config.timeout": 90} {
		got, ok := s.ImplicitDefault(path)
		if !ok || got != want {
			t.Errorf("default of %s = %v %v", path, got, ok)
		}
	}
	if !Added024Key("device.config.timeout") || Added024Key("snmp.timeout") || Added023Key("device.config.timeout") {
		t.Error("the rollback tables do not place the device.config keys in 0.2.4")
	}
	if !Unknown022("device.config.transport") {
		t.Error("a 0.2.2 binary knows device.config.transport")
	}
}
