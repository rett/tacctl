package devconf

import (
	"strconv"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// The device's own settings of the aaa section: a leaf of the server block
// tacctl renders that the rendering says nothing of, and the options of the
// client that do not decide who can log in, are unmanaged (the section reads
// ok with their number). A leaf the rendering states with another value, a
// TACACS+ port the rendering does not state, the options that change the
// service asked for or how a password is checked, another server or server
// block, a group's leaf and the login leaf of a line stay differences.
func TestAAAOwnSettings(t *testing.T) {
	junosTAC := devices.Section{Name: SectionAAA, Secret: []bool{false, true, false},
		Lines: []string{"set system authentication-order [ password tacplus ]", "set system tacplus-server 192.0.2.10 secret key", "set system tacplus-server 192.0.2.10 single-connection"}}
	junosTAC4949 := devices.Section{Name: SectionAAA, Secret: []bool{false, true, false, false},
		Lines: []string{"set system authentication-order [ password tacplus ]", "set system tacplus-server 192.0.2.10 secret key", "set system tacplus-server 192.0.2.10 single-connection", "set system tacplus-server 192.0.2.10 port 4949"}}
	junosRAD := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true},
		Lines: []string{"set system authentication-order [ password radius ]", "set system radius-server 192.0.2.10 port 1812", "set system radius-server 192.0.2.10 accounting-port 1813", "set system radius-server 192.0.2.10 secret key"}}
	iosTAC := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true, false, false, false, false, false, false, false},
		Lines: []string{"aaa new-model", "tacacs server TACACS", "  address ipv4 192.0.2.10", "  key key", "  single-connection", "  timeout 5",
			"aaa group server tacacs+ LAB", "  server name TACACS", "aaa authentication login default local group LAB", "line vty 0 15", "  login authentication default"}}
	iosRAD := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true, false, false, false, false, false},
		Lines: []string{"aaa new-model", "radius server RADIUS", "  address ipv4 192.0.2.10 auth-port 1812 acct-port 1813", "  key key", "  timeout 5", "  retransmit 2",
			"aaa group server radius LAB", "  server name RADIUS", "aaa authentication login default local group LAB"}}

	// the device that agrees with the rendering
	junosTACDev := []string{"set system authentication-order [ password tacplus ]", `set system tacplus-server 192.0.2.10 secret "$9$abc"`, "set system tacplus-server 192.0.2.10 single-connection"}
	junosRADDev := []string{"set system authentication-order [ password radius ]", "set system radius-server 192.0.2.10 port 1812",
		"set system radius-server 192.0.2.10 accounting-port 1813", `set system radius-server 192.0.2.10 secret "$9$abc"`}
	iosTACDev := []string{"aaa new-model", "tacacs server TACACS", " address ipv4 192.0.2.10", " key 7 0822455D0A16", " single-connection", " timeout 5",
		"aaa group server tacacs+ LAB", " server name TACACS", "aaa authentication login default local group LAB", "line vty 0 15", " login authentication default"}
	iosRADDev := []string{"aaa new-model", "radius server RADIUS", " address ipv4 192.0.2.10 auth-port 1812 acct-port 1813", " key 7 0822455D0A16", " timeout 5", " retransmit 2",
		"aaa group server radius LAB", " server name RADIUS", "aaa authentication login default local group LAB"}

	with := func(dev []string, extra ...string) []string { return append(append([]string(nil), dev...), extra...) }
	swap := func(dev []string, from, to string) []string {
		out := append([]string(nil), dev...)
		for i, l := range out {
			if l == from {
				out[i] = to
				return out
			}
		}
		t.Fatalf("no %q in %q", from, dev)
		return nil
	}

	for _, tc := range []struct {
		name      string
		vendor    string
		exp       devices.Section
		dev       []string
		state     State
		unmanaged int
	}{
		// Junos TACACS+
		{"junos tacplus as rendered", "junos", junosTAC, junosTACDev, StateOK, 0},
		{"junos tacplus source address", "junos", junosTAC, with(junosTACDev, "set system tacplus-server 192.0.2.10 source-address 192.0.2.1"), StateOK, 1},
		{"junos tacplus timeout, retry, routing instance", "junos", junosTAC, with(junosTACDev, "set system tacplus-server 192.0.2.10 timeout 10",
			"set system tacplus-server 192.0.2.10 routing-instance mgmt", "set system tacplus-server 192.0.2.10 retry 3"), StateOK, 3},
		{"junos tacplus a port the rendering does not state", "junos", junosTAC, with(junosTACDev, "set system tacplus-server 192.0.2.10 port 4949"), StateDiffers, 0},
		{"junos tacplus the port the rendering states", "junos", junosTAC4949, with(junosTACDev, "set system tacplus-server 192.0.2.10 port 4949"), StateOK, 0},
		{"junos tacplus another port than the rendered one", "junos", junosTAC4949, with(junosTACDev, "set system tacplus-server 192.0.2.10 port 4950"), StateDiffers, 0},
		{"junos tacplus options that do not decide who logs in", "junos", junosTAC, with(junosTACDev, "set system tacplus-options timestamp-and-timezone",
			"set system tacplus-options enhanced-accounting", "set system tacplus-options no-cmd-attribute-value", "set system tacplus-options exclude-cmd-attribute priv-lvl",
			"set system tacplus-options authorization-time-interval 5", "set system tacplus-options service-name junos-exec"), StateOK, 6},
		{"junos tacplus another service name", "junos", junosTAC, with(junosTACDev, "set system tacplus-options service-name other-exec"), StateDiffers, 0},
		{"junos tacplus strict authorization", "junos", junosTAC, with(junosTACDev, "set system tacplus-options strict-authorization"), StateDiffers, 0},
		{"junos tacplus option beside a finding is still counted apart", "junos", junosTAC, with(junosTACDev, "set system tacplus-options enhanced-accounting",
			"set system tacplus-options strict-authorization"), StateDiffers, 1},
		{"junos tacplus own leaf beside a missing rendered one", "junos", junosTAC,
			[]string{"set system authentication-order [ password tacplus ]", `set system tacplus-server 192.0.2.10 secret "$9$abc"`, "set system tacplus-server 192.0.2.10 source-address 192.0.2.1"}, StateDiffers, 1},
		{"junos tacplus another server", "junos", junosTAC, with(junosTACDev, "set system tacplus-server 192.0.2.98 source-address 192.0.2.1"), StateDiffers, 0},
		{"junos tacplus another server with its key", "junos", junosTAC, with(junosTACDev, `set system tacplus-server 192.0.2.98 secret "$9$abc"`), StateDiffers, 0},
		{"junos tacplus a deactivated leaf", "junos", junosTAC, with(junosTACDev, "deactivate system tacplus-server 192.0.2.10 source-address"), StateDiffers, 0},
		{"junos another authentication order", "junos", junosTAC, swap(junosTACDev, "set system authentication-order [ password tacplus ]", "set system authentication-order [ tacplus password ]"), StateDiffers, 0},
		{"junos accounting to another server", "junos", junosTAC, with(junosTACDev, "set system accounting destination tacplus server 192.0.2.98 port 49"), StateDiffers, 0},
		// Junos RADIUS
		{"junos radius as rendered", "junos", junosRAD, junosRADDev, StateOK, 0},
		{"junos radius source address, retry, timeout", "junos", junosRAD, with(junosRADDev, "set system radius-server 192.0.2.10 source-address 192.0.2.1",
			"set system radius-server 192.0.2.10 retry 3", "set system radius-server 192.0.2.10 timeout 4"), StateOK, 3},
		{"junos radius options that do not decide who logs in", "junos", junosRAD, with(junosRADDev, "set system radius-options attributes nas-ip-address 192.0.2.1",
			"set system radius-options revert-interval 60", "set system radius-options request-rate 20"), StateOK, 3},
		{"junos radius password protocol", "junos", junosRAD, with(junosRADDev, "set system radius-options password-protocol mschap-v2"), StateDiffers, 0},
		{"junos radius another port", "junos", junosRAD, swap(junosRADDev, "set system radius-server 192.0.2.10 port 1812", "set system radius-server 192.0.2.10 port 1700"), StateDiffers, 0},
		{"junos radius another accounting port", "junos", junosRAD, swap(junosRADDev, "set system radius-server 192.0.2.10 accounting-port 1813", "set system radius-server 192.0.2.10 accounting-port 1700"), StateDiffers, 0},
		{"junos radius another server", "junos", junosRAD, with(junosRADDev, "set system radius-server 192.0.2.98 source-address 192.0.2.1"), StateDiffers, 0},
		{"junos tacplus server of a radius scope", "junos", junosRAD, with(junosRADDev, "set system tacplus-server 192.0.2.10 source-address 192.0.2.1"), StateDiffers, 0},
		// IOS TACACS+
		{"ios tacacs as rendered", "ios", iosTAC, iosTACDev, StateOK, 0},
		{"ios tacacs nat address", "ios", iosTAC, with(iosTACDev, "tacacs server TACACS", " send-nat-address"), StateOK, 1},
		{"ios tacacs a port the rendering does not state", "ios", iosTAC, with(iosTACDev, "tacacs server TACACS", " port 4949"), StateDiffers, 0},
		{"ios tacacs another timeout", "ios", iosTAC, swap(iosTACDev, " timeout 5", " timeout 9"), StateDiffers, 0},
		{"ios tacacs another address form", "ios", iosTAC, with(iosTACDev, "tacacs server TACACS", " address ipv6 2001:db8::10"), StateDiffers, 0},
		{"ios tacacs another server block", "ios", iosTAC, with(iosTACDev, "tacacs server OTHER", " address ipv4 192.0.2.98"), StateDiffers, 0},
		{"ios tacacs another server block's port", "ios", iosTAC, with(iosTACDev, "tacacs server OTHER", " port 4949"), StateDiffers, 0},
		{"ios tacacs the legacy host line", "ios", iosTAC, with(iosTACDev, "tacacs-server host 192.0.2.98"), StateDiffers, 0},
		{"ios tacacs another group", "ios", iosTAC, with(iosTACDev, "aaa group server tacacs+ OTHER", " server name TACACS"), StateDiffers, 0},
		{"ios tacacs a server of tacacs's group", "ios", iosTAC, with(iosTACDev, "aaa group server tacacs+ LAB", " server name OTHER"), StateDiffers, 0},
		{"ios tacacs another method list", "ios", iosTAC, with(iosTACDev, "aaa authentication login OTHER local"), StateDiffers, 0},
		{"ios tacacs another login on the vty lines", "ios", iosTAC, swap(iosTACDev, " login authentication default", " login local"), StateDiffers, 0},
		// IOS RADIUS
		{"ios radius as rendered", "ios", iosRAD, iosRADDev, StateOK, 0},
		{"ios radius test probe and dead criteria", "ios", iosRAD, with(iosRADDev, "radius server RADIUS", " automate-tester username probe", "radius server RADIUS", " dead-criteria time 10 tries 3"), StateOK, 2},
		{"ios radius another retransmit", "ios", iosRAD, swap(iosRADDev, " retransmit 2", " retransmit 5"), StateDiffers, 0},
		{"ios radius another server block", "ios", iosRAD, with(iosRADDev, "radius server OTHER", " address ipv4 192.0.2.98 auth-port 1812 acct-port 1813"), StateDiffers, 0},
		{"ios radius another group", "ios", iosRAD, with(iosRADDev, "aaa group server radius OTHER", " server name OTHER"), StateDiffers, 0},
		{"ios radius the old host line", "ios", iosRAD, with(iosRADDev, "radius-server host 192.0.2.98"), StateDiffers, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := devices.Section{Name: SectionAAA, Lines: tc.dev}
			r, err := Compare(tc.vendor, tc.exp, dev, true)
			if err != nil {
				t.Fatal(err)
			}
			if r.State != tc.state || r.Unmanaged != tc.unmanaged {
				t.Errorf("%s with %d unmanaged, want %s with %d:\n%v", r.State, r.Unmanaged, tc.state, tc.unmanaged, r.Lines)
			}
			if want := "ok (+" + strconv.Itoa(tc.unmanaged) + " unmanaged)"; r.State == StateOK && tc.unmanaged > 0 && r.StateText() != want {
				t.Errorf("state text %q, want %q", r.StateText(), want)
			}
		})
	}
}
