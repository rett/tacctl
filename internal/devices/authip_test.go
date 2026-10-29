package devices

import "testing"

// The address a device is told to authenticate against: --server, else the
// address a RADIUS listener is bound to, else the recorded server address
// (0.2.21), else the detected one; the address tacctl reaches the devices
// from stays the detected one.
func TestAuthIPOrder(t *testing.T) {
	d := Data{ServerIP: "192.0.2.1"}
	for _, c := range []struct {
		name, server, recorded, bound, want string
	}{
		{"nothing recorded", "", "", "", "192.0.2.1"},
		{"recorded", "", "203.0.113.9", "", "203.0.113.9"},
		{"--server wins", "198.51.100.7", "203.0.113.9", "", "198.51.100.7"},
		{"a bound listener keeps its address", "", "203.0.113.9", "192.0.2.77", "192.0.2.77"},
		{"--server over a bound listener", "198.51.100.7", "", "192.0.2.77", "198.51.100.7"},
	} {
		d.AuthServer, d.DefaultServer = c.server, c.recorded
		if got := d.authIP(c.bound); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
		if got := d.source(); got != "192.0.2.1" {
			t.Errorf("%s: the source is %s", c.name, got)
		}
	}
}
