package hosts

import (
	"net/netip"
	"strings"
	"testing"
)

const routeHeader = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"

func addrs(list ...string) []netip.Addr {
	var out []netip.Addr
	for _, a := range list {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

// The detection: the interface of the default route first, then the first
// usable IPv4 address by interface index, IPv6 only without any IPv4, never
// loopback or link-local; nothing usable is an error that names --server.
func TestDetectServerAddress(t *testing.T) {
	ifaces := []Iface{
		{Name: "lo", Index: 1, Up: true, Addrs: addrs("127.0.0.1", "::1")},
		{Name: "eth0", Index: 2, Up: true, Addrs: addrs("fe80::1", "169.254.3.3", "192.0.2.10")},
		{Name: "eth1", Index: 3, Up: true, Addrs: addrs("198.51.100.20")},
		{Name: "br0", Index: 4, Up: true, Addrs: addrs("203.0.113.1")},
	}
	for _, c := range []struct {
		name, route, addr, iface string
		ifaces                   []Iface
	}{
		{"default route", routeHeader + "eth1\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n", "198.51.100.20", "eth1", ifaces},
		{"no default route", routeHeader + "eth1\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n", "192.0.2.10", "eth0", ifaces},
		{"no route file", "", "192.0.2.10", "eth0", ifaces},
		{"a down interface is skipped", "", "198.51.100.20", "eth1", []Iface{{Name: "eth0", Index: 2, Addrs: addrs("192.0.2.10")}, ifaces[2]}},
		{"IPv6 only", "", "2001:db8::10", "eth0", []Iface{ifaces[0], {Name: "eth0", Index: 2, Up: true, Addrs: addrs("fe80::1", "2001:db8::10")}}},
	} {
		addr, iface, err := DetectServerAddress([]byte(c.route), c.ifaces)
		if err != nil || addr != c.addr || iface != c.iface {
			t.Errorf("%s: %q %q %v", c.name, addr, iface, err)
		}
	}
	for _, none := range [][]Iface{nil, {ifaces[0]}, {{Name: "eth0", Index: 2, Up: true, Addrs: addrs("169.254.3.3", "fe80::1")}}} {
		if _, _, err := DetectServerAddress(nil, none); err == nil || !strings.Contains(err.Error(), "give --server <address>") {
			t.Errorf("%v: %v", none, err)
		}
	}
}

func TestCheckServerAddress(t *testing.T) {
	for _, ok := range []string{"192.0.2.10", "203.0.113.9", "2001:db8::10"} {
		if err := CheckServerAddress(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "authsrv.example.net", "0.0.0.0", "::", "127.0.0.1", "::1", "169.254.1.1", "fe80::1", "224.0.0.1", "192.0.2.0/24"} {
		if err := CheckServerAddress(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
