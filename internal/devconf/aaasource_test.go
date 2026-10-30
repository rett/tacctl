package devconf

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// The source of the AAA client must be on the device (D314): the device's
// own source address (Junos) or source interface (IOS) that names nothing
// the pull recorded is a difference, an access irregularity of the plan;
// one it holds is the device's own as before; and a record that cannot say
// (no facts, an unseen interface list) leaves it the device's own and says
// so in a note.

var (
	junosFacts = &InterfaceFacts{Visible: true, Addresses: map[string][]string{
		"lo0.0":      {"192.0.2.250", "2001:db8::250"},
		"ge-0/0/0.0": {"198.51.100.1", "198.51.100.254"},
	}}
	iosFacts = &InterfaceFacts{Visible: true, Addresses: map[string][]string{
		"loopback0":          {"192.0.2.250"},
		"gigabitethernet0/0": {"198.51.100.1", "2001:db8::1"},
		"gigabitethernet0/2": {dynamicAddress},
	}}
	noInterfaces = &InterfaceFacts{}
)

func withSources(f *InterfaceFacts, kv ...string) *InterfaceFacts {
	c := f.Clone()
	c.Sources = map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		c.Sources[kv[i]] = kv[i+1]
	}
	return c
}

func TestAAASourceMustBeOnTheDevice(t *testing.T) {
	junosTAC := devices.Section{Name: SectionAAA, Secret: []bool{false, true, false},
		Lines: []string{"set system authentication-order [ password tacplus ]", "set system tacplus-server 192.0.2.10 secret key", "set system tacplus-server 192.0.2.10 single-connection"}}
	junosRAD := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true},
		Lines: []string{"set system authentication-order [ password radius ]", "set system radius-server 192.0.2.10 port 1812", "set system radius-server 192.0.2.10 accounting-port 1813", "set system radius-server 192.0.2.10 secret key"}}
	iosTAC := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true, false, false, false, false, false, false, false},
		Lines: []string{"aaa new-model", "tacacs server TACACS", "  address ipv4 192.0.2.10", "  key key", "  single-connection", "  timeout 5",
			"aaa group server tacacs+ LAB", "  server name TACACS", "aaa authentication login default local group LAB", "line vty 0 15", "  login authentication default"}}
	iosTACSrc := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true, false, false, false, false, false, false, false, false},
		Lines: append(slices.Clone(iosTAC.Lines), "ip tacacs source-interface Loopback0")}
	iosRAD := devices.Section{Name: SectionAAA, Secret: []bool{false, false, false, true, false, false, false, false, false},
		Lines: []string{"aaa new-model", "radius server RADIUS", "  address ipv4 192.0.2.10 auth-port 1812 acct-port 1813", "  key key", "  timeout 5", "  retransmit 2",
			"aaa group server radius LAB", "  server name RADIUS", "aaa authentication login default local group LAB"}}

	junosTACDev := []string{"set system authentication-order [ password tacplus ]", `set system tacplus-server 192.0.2.10 secret "$9$abc"`, "set system tacplus-server 192.0.2.10 single-connection"}
	junosRADDev := []string{"set system authentication-order [ password radius ]", "set system radius-server 192.0.2.10 port 1812",
		"set system radius-server 192.0.2.10 accounting-port 1813", `set system radius-server 192.0.2.10 secret "$9$abc"`}
	iosTACDev := []string{"aaa new-model", "tacacs server TACACS", " address ipv4 192.0.2.10", " key 7 0822455D0A16", " single-connection", " timeout 5",
		"aaa group server tacacs+ LAB", " server name TACACS", "aaa authentication login default local group LAB", "line vty 0 15", " login authentication default"}
	iosRADDev := []string{"aaa new-model", "radius server RADIUS", " address ipv4 192.0.2.10 auth-port 1812 acct-port 1813", " key 7 0822455D0A16", " timeout 5", " retransmit 2",
		"aaa group server radius LAB", " server name RADIUS", "aaa authentication login default local group LAB"}
	with := func(dev []string, extra ...string) []string { return append(slices.Clone(dev), extra...) }

	type want struct {
		state State
		own   int
		// why is a part of the reason of the one extra line that is a
		// finding ("" for none), note a part of a note ("" for none)
		why, note string
	}
	tacSrc := func(a string) string { return "set system tacplus-server 192.0.2.10 source-address " + a }
	radSrc := func(a string) string { return "set system radius-server 192.0.2.10 source-address " + a }
	tacGrp := func(ifc string) []string {
		return []string{"aaa group server tacacs+ LAB", " ip tacacs source-interface " + ifc}
	}

	// the facts of a pulled text with subinterfaces whose lines end in their type
	pulled := func(src string) *InterfaceFacts {
		ext, err := Extract("cisco", iosInterfacesText)
		if err != nil {
			t.Fatal(err)
		}
		f := ext.Interfaces
		f.Sources = map[string]string{"tacacs": src}
		return f
	}

	for _, tc := range []struct {
		name   string
		vendor string
		exp    devices.Section
		dev    []string
		facts  *InterfaceFacts
		want   want
	}{
		// Junos
		{"junos tacplus source on an interface", "junos", junosTAC, with(junosTACDev, tacSrc("192.0.2.250")), junosFacts, want{StateOK, 1, "", ""}},
		{"junos tacplus source of a virtual address", "junos", junosTAC, with(junosTACDev, tacSrc("198.51.100.254")), junosFacts, want{StateOK, 1, "", ""}},
		{"junos tacplus source on no interface", "junos", junosTAC, with(junosTACDev, tacSrc("192.0.2.99")), junosFacts,
			want{StateDiffers, 0, "source-address 192.0.2.99 is not an address of any interface this login can see", ""}},
		{"junos tacplus ipv6 source on an interface, as another text", "junos", junosTAC, with(junosTACDev, tacSrc("2001:DB8:0:0:0:0:0:250")), junosFacts, want{StateOK, 1, "", ""}},
		{"junos tacplus ipv6 source on no interface", "junos", junosTAC, with(junosTACDev, tacSrc("2001:db8::99")), junosFacts,
			want{StateDiffers, 0, "source-address 2001:db8::99 is not an address", ""}},
		{"junos tacplus an address that is a prefix of one", "junos", junosTAC, with(junosTACDev, tacSrc("192.0.2.25")), junosFacts,
			want{StateDiffers, 0, "source-address 192.0.2.25 is not an address", ""}},
		{"junos tacplus the device takes an address by itself", "junos", junosTAC, with(junosTACDev, tacSrc("192.0.2.99")),
			&InterfaceFacts{Visible: true, Addresses: map[string][]string{"ge-0/0/0.0": {dynamicAddress}}}, want{StateOK, 1, "", ""}},
		{"junos tacplus no facts", "junos", junosTAC, with(junosTACDev, tacSrc("192.0.2.99")), nil,
			want{StateOK, 1, "", "their addresses are not recorded (pull the device again)"}},
		{"junos tacplus interfaces not visible", "junos", junosTAC, with(junosTACDev, tacSrc("192.0.2.99")), noInterfaces,
			want{StateOK, 1, "", "this login cannot see the interfaces"}},
		{"junos tacplus no source, no note", "junos", junosTAC, junosTACDev, nil, want{StateOK, 0, "", ""}},
		{"junos tacplus another leaf is not a source", "junos", junosTAC, with(junosTACDev, "set system tacplus-server 192.0.2.10 timeout 10"), junosFacts, want{StateOK, 1, "", ""}},
		{"junos tacplus source of another server stays a finding of its own kind", "junos", junosTAC, with(junosTACDev, "set system tacplus-server 192.0.2.98 source-address 192.0.2.250"), junosFacts,
			want{StateDiffers, 0, "", ""}},
		{"junos radius source on an interface", "junos", junosRAD, with(junosRADDev, radSrc("192.0.2.250")), junosFacts, want{StateOK, 1, "", ""}},
		{"junos radius source on no interface", "junos", junosRAD, with(junosRADDev, radSrc("192.0.2.99")), junosFacts,
			want{StateDiffers, 0, "source-address 192.0.2.99 is not an address of any interface this login can see", ""}},
		{"junos radius no facts", "junos", junosRAD, with(junosRADDev, radSrc("192.0.2.99")), nil, want{StateOK, 1, "", "not recorded"}},
		// IOS, the device's own source interface (the rendering sets none)
		{"ios tacacs global source interface that exists", "ios", iosTAC, iosTACDev, withSources(iosFacts, "tacacs", "Loopback0"), want{StateOK, 0, "", ""}},
		{"ios tacacs global source interface in other case", "ios", iosTAC, iosTACDev, withSources(iosFacts, "tacacs", "LOOPBACK0"), want{StateOK, 0, "", ""}},
		{"ios tacacs global source interface that does not exist", "ios", iosTAC, iosTACDev, withSources(iosFacts, "tacacs", "Loopback9"),
			want{StateDiffers, 0, "source-interface Loopback9: no such interface with an address that this login can see", ""}},
		{"ios tacacs global source interface without an address", "ios", iosTAC, iosTACDev,
			withSources(&InterfaceFacts{Visible: true, Addresses: map[string][]string{"loopback0": {"192.0.2.250"}}}, "tacacs", "Loopback1"),
			want{StateDiffers, 0, "no such interface with an address that this login can see", ""}},
		{"ios tacacs global source interface that takes its address by itself", "ios", iosTAC, iosTACDev, withSources(iosFacts, "tacacs", "GigabitEthernet0/2"), want{StateOK, 0, "", ""}},
		{"ios tacacs global source interface, no facts", "ios", iosTAC, iosTACDev, nil, want{StateOK, 0, "", ""}},
		{"ios tacacs global source interface, interfaces not visible", "ios", iosTAC, iosTACDev, withSources(noInterfaces, "tacacs", "Loopback9"),
			want{StateOK, 0, "", "this login cannot see the interfaces"}},
		{"ios tacacs radius source interface of a tacacs scope is nobody's business", "ios", iosTAC, iosTACDev, withSources(iosFacts, "radius", "Loopback9"), want{StateOK, 0, "", ""}},
		{"ios tacacs source interface that is a point-to-point subinterface", "ios", iosTAC, iosTACDev, pulled("Serial0/0.1"), want{StateOK, 0, "", ""}},
		{"ios tacacs source interface that is a multipoint subinterface", "ios", iosTAC, iosTACDev, pulled("ATM0/0.1"), want{StateOK, 0, "", ""}},
		// a source interface of tacctl's own group overrides the global one: a
		// wrong global one is not what the requests use
		{"ios tacacs wrong global source, group source that exists", "ios", iosTAC, with(iosTACDev, tacGrp("Loopback0")...), withSources(iosFacts, "tacacs", "Loopback9"), want{StateOK, 1, "", ""}},
		{"ios tacacs wrong global source, wrong group source is the one finding", "ios", iosTAC, with(iosTACDev, tacGrp("Loopback7")...), withSources(iosFacts, "tacacs", "Loopback9"),
			want{StateDiffers, 0, "source-interface Loopback7: no such interface", ""}},
		{"ios tacacs wrong global source, a group source of another group", "ios", iosTAC, with(iosTACDev, "aaa group server tacacs+ OTHER", " ip tacacs source-interface Loopback0"), withSources(iosFacts, "tacacs", "Loopback9"),
			want{StateDiffers, 0, "source-interface Loopback9: no such interface", ""}},
		{"ios radius wrong global source, group source of the radius group", "ios", iosRAD, with(iosRADDev, "aaa group server radius LAB", " ip radius source-interface Loopback0"), withSources(iosFacts, "radius", "Loopback9"), want{StateOK, 1, "", ""}},
		// IOS, the source interface the rendering sets
		{"ios tacacs rendered source interface that exists", "ios", iosTACSrc, with(iosTACDev, "ip tacacs source-interface Loopback0"),
			withSources(iosFacts, "tacacs", "Loopback0"), want{StateOK, 0, "", ""}},
		{"ios tacacs rendered source interface that does not exist", "ios", iosTACSrc, with(iosTACDev, "ip tacacs source-interface Loopback0"),
			withSources(&InterfaceFacts{Visible: true, Addresses: map[string][]string{"vlan10": {"10.0.10.1"}}}, "tacacs", "Loopback0"),
			want{StateDiffers, 0, "source-interface Loopback0: no such interface with an address that this login can see", ""}},
		{"ios tacacs another source interface than the rendered one is the difference it was", "ios", iosTACSrc, with(iosTACDev, "ip tacacs source-interface Loopback5"),
			withSources(iosFacts, "tacacs", "Loopback5"), want{StateDiffers, 0, "", ""}},
		// IOS, the source interface of the server group
		{"ios tacacs group source interface that exists", "ios", iosTAC, with(iosTACDev, tacGrp("Loopback0")...), iosFacts, want{StateOK, 1, "", ""}},
		{"ios tacacs group source interface that does not exist", "ios", iosTAC, with(iosTACDev, tacGrp("Loopback9")...), iosFacts,
			want{StateDiffers, 0, "source-interface Loopback9: no such interface with an address that this login can see", ""}},
		{"ios tacacs group source interface, no facts", "ios", iosTAC, with(iosTACDev, tacGrp("Loopback9")...), nil, want{StateOK, 1, "", "not recorded"}},
		{"ios radius group source interface that does not exist", "ios", iosRAD, with(iosRADDev, "aaa group server radius LAB", " ip radius source-interface Loopback9"), iosFacts,
			want{StateDiffers, 0, "source-interface Loopback9: no such interface with an address that this login can see", ""}},
		{"ios radius group source interface that exists", "ios", iosRAD, with(iosRADDev, "aaa group server radius LAB", " ip radius source-interface Loopback0"), iosFacts, want{StateOK, 1, "", ""}},
		{"ios radius global source interface that does not exist", "ios", iosRAD, iosRADDev, withSources(iosFacts, "radius", "Loopback9"),
			want{StateDiffers, 0, "source-interface Loopback9", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dev := devices.Section{Name: SectionAAA, Lines: tc.dev}
			r, err := CompareWith(tc.vendor, tc.exp, dev, true, tc.facts)
			if err != nil {
				t.Fatal(err)
			}
			if r.State != tc.want.state || r.Unmanaged != tc.want.own {
				t.Fatalf("%s with %d unmanaged, want %s with %d:\n%v", r.State, r.Unmanaged, tc.want.state, tc.want.own, r.Lines)
			}
			var whys []string
			for _, l := range r.Lines {
				if l.Why != "" {
					if l.Op != OpExtra || l.Unmanaged {
						t.Errorf("a source finding is an extra that is not the device's own: %+v", l)
					}
					whys = append(whys, l.Why)
				}
			}
			switch {
			case tc.want.why == "" && len(whys) > 0:
				t.Errorf("unexpected finding %v", whys)
			case tc.want.why != "" && (len(whys) != 1 || !strings.Contains(whys[0], tc.want.why)):
				t.Errorf("findings %v, want one with %q\n%v", whys, tc.want.why, r.Lines)
			}
			var notes []string
			for _, n := range r.Notes {
				if strings.Contains(n, "AAA server is not checked") {
					notes = append(notes, n)
				}
			}
			switch {
			case tc.want.note == "" && len(notes) > 0:
				t.Errorf("unexpected note %v", notes)
			case tc.want.note != "" && (len(notes) != 1 || !strings.Contains(notes[0], tc.want.note)):
				t.Errorf("notes %v, want one with %q", r.Notes, tc.want.note)
			}
		})
	}
}

// The facts the pull extracts are the ones the check reads: a device text
// with a deactivated interface, a virtual address and a source on each.
func TestAAASourceFromAPullText(t *testing.T) {
	exp := []devices.Section{{Name: SectionAAA, Secret: []bool{false, true, false},
		Lines: []string{"set system authentication-order [ password tacplus ]", "set system tacplus-server 192.0.2.10 secret key", "set system tacplus-server 192.0.2.10 single-connection"}}}
	// (a family that takes its address from DHCP makes every source possible:
	// the table above has that case)
	base := strings.Replace(junosInterfacesText, "set interfaces ge-0/0/2 unit 0 family inet dhcp\n", "", 1) + `set system authentication-order [ password tacplus ]
set system tacplus-server 192.0.2.10 single-connection
`
	check := func(source string) SectionResult {
		t.Helper()
		ext, err := Extract("juniper", base+"set system tacplus-server 192.0.2.10 source-address "+source+"\n", exp...)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := CompareAll(exp, ext)
		if err != nil {
			t.Fatal(err)
		}
		return rs[0]
	}
	for _, tc := range []struct {
		source string
		state  State
	}{
		{"192.0.2.250", StateOK},
		{"198.51.100.254", StateOK}, // a VRRP virtual address
		{"2001:db8:0:1::fe", StateOK},
		{"10.0.0.5", StateOK},
		{"203.0.113.1", StateDiffers}, // the address is deactivated
		{"10.0.4.1", StateDiffers},    // the unit is deactivated
		{"10.0.5.1", StateDiffers},    // the interface is deactivated
		{"10.0.6.1", StateDiffers},    // the family is deactivated
		{"10.0.7.254", StateDiffers},  // the group of the virtual address is deactivated
		{"10.0.7.1", StateOK},         // while the address of the interface is not
	} {
		if r := check(tc.source); r.State != tc.state {
			t.Errorf("source %s: %s, want %s:\n%v", tc.source, r.State, tc.state, r.Lines)
		}
	}
}
