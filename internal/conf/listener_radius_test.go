package conf

import (
	"strings"
	"testing"
)

// tests/unit/render_radius.bats (0.1.18): "listeners: the schema takes udp
// and udp6 for radius, auth or acct, and refuses tcp and 'both'".
func TestListenerSchemaRadiusTakesUDPAuthOrAcctAndRefusesTCPAndBoth(t *testing.T) {
	c := tempConf(t)
	must(t, c.SetJSON("listeners.radius.mgmt", `{"network": "udp", "address": "10.1.0.1:1900"}`))
	if !c.HasOverride("listeners.radius.mgmt") {
		t.Error("listeners.radius.mgmt is not an override")
	}
	var got []string
	for _, l := range ListenersEffective(c.Merged(), "radius") {
		m := l.MetricsAddress
		if m == "" {
			m = "-"
		}
		got = append(got, strings.Join([]string{l.Name, l.Network, l.Address, l.Role, m}, "\t"))
	}
	assertLines(t, got,
		"auth\tudp\t:1812\tauth\t-",
		"acct\tudp\t:1813\tacct\t-",
		"mgmt\tudp\t10.1.0.1:1900\tauth\t-")

	must(t, c.SetJSON("listeners.radius.six", `{"network": "udp6", "address": "[::1]:1901", "role": "acct"}`))

	refused(t, c.SetJSON("listeners.radius.x", `{"network": "tcp", "address": ":1812"}`),
		"the radius backend listens on udp or udp6 only")
	refused(t, c.SetJSON("listeners.radius.x", `{"network": "udp", "address": ":1900", "role": "both"}`),
		"a radius listener has role acct or auth")
	refused(t, c.SetJSON("listeners.radius.x", `{"network": "udp", "address": ":1900", "tls": {"enabled": true}}`),
		"reserved")
	if c.HasOverride("listeners.radius.x") {
		t.Error("a refused listener was written")
	}
}
