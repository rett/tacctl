package devconf

import (
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// The addresses the opt-in test of the AAA sources connects to (D315): read
// from the aaa section of the pull and the interface facts, deduplicated, in
// address order, with the reason for each source that is left out.

func aaaLines(lines ...string) devices.Section {
	return devices.Section{Name: SectionAAA, Lines: lines, Secret: make([]bool, len(lines))}
}

func TestAAASourceAddressesJunos(t *testing.T) {
	sec := aaaLines(
		"set system authentication-order [ password tacplus ]",
		"set system tacplus-server 192.0.2.10 source-address 198.51.100.9",
		"set system radius-server 192.0.2.10 source-address 192.0.2.250",
		"set system radius-server 192.0.2.11 source-address 198.51.100.9",
		"set system tacplus-server 192.0.2.12 source-address 2001:db8::9",
		"set system tacplus-server 192.0.2.13 source-address 127.0.0.1",
		"set system tacplus-server 192.0.2.14 source-address fe80::1",
		"set system tacplus-server 192.0.2.17 source-address 255.255.255.255",
		"set system tacplus-server 192.0.2.18 source-address 224.0.0.9",
		"set system tacplus-server 192.0.2.15 source-address not-an-address",
		"set system tacplus-server 192.0.2.16 source-address 203.0.113.77",
		"deactivate system tacplus-server 192.0.2.16",
	)
	got := AAASourceAddresses("juniper", sec, nil)
	var addrs []string
	for _, a := range got.Addrs {
		addrs = append(addrs, a.Address)
		if a.Via != "" {
			t.Errorf("%s: via %q for a source-address", a.Address, a.Via)
		}
	}
	if want := []string{"192.0.2.250", "198.51.100.9", "2001:db8::9"}; !slices.Equal(addrs, want) {
		t.Errorf("addresses %v, want %v (deduplicated, in address order, the deactivated one left out)", addrs, want)
	}
	want := []SourceSkip{
		{"source-address 127.0.0.1", SkipLocal},
		{"source-address fe80::1", SkipLocal},
		{"source-address 255.255.255.255", SkipLocal},
		{"source-address 224.0.0.9", SkipLocal},
		{"source-address not-an-address", SkipNotAddress},
	}
	if !slices.Equal(got.Skipped, want) {
		t.Errorf("skipped %v, want %v", got.Skipped, want)
	}
	// the facts are not needed for an address the device states
	if g2 := AAASourceAddresses("juniper", sec, junosFacts); !slices.Equal(g2.Addrs, got.Addrs) {
		t.Errorf("with facts: %v", g2.Addrs)
	}
}

func TestAAASourceAddressesIOS(t *testing.T) {
	facts := withSources(iosFacts, "radius", "GigabitEthernet0/2")
	sec := aaaLines(
		"aaa new-model",
		"aaa group server tacacs+ LAB",
		"  ip tacacs source-interface Loopback0",
		"aaa group server radius LAB2",
		"  ip radius source-interface GigabitEthernet0/0",
		"ip tacacs source-interface Loopback0",
	)
	got := AAASourceAddresses("cisco", sec, facts)
	var addrs, via []string
	for _, a := range got.Addrs {
		addrs = append(addrs, a.Address)
		via = append(via, a.Via)
	}
	if want := []string{"192.0.2.250", "198.51.100.1", "2001:db8::1"}; !slices.Equal(addrs, want) {
		t.Errorf("addresses %v, want %v (an interface with several addresses gives each, the group level counts)", addrs, want)
	}
	if want := []string{"loopback0", "gigabitethernet0/0", "gigabitethernet0/0"}; !slices.Equal(via, want) {
		t.Errorf("via %v, want %v", via, want)
	}
	// the radius global source (the section leaves it out) is on an
	// interface with a learned address
	if want := []SourceSkip{{"source-interface gigabitethernet0/2", SkipDynamic}}; !slices.Equal(got.Skipped, want) {
		t.Errorf("skipped %v, want %v", got.Skipped, want)
	}
}

func TestAAASourceAddressesIOSNotRecorded(t *testing.T) {
	sec := aaaLines("aaa new-model", "ip tacacs source-interface Loopback0")
	for name, c := range map[string]struct {
		facts  *InterfaceFacts
		reason string
	}{"none": {nil, SkipNotRecorded}, "invisible": {noInterfaces, SkipNotVisible}} {
		got := AAASourceAddresses("cisco", sec, c.facts)
		if len(got.Addrs) != 0 || !slices.Equal(got.Skipped, []SourceSkip{{"source-interface loopback0", c.reason}}) {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if SkipNotVisible != "this login cannot see the interfaces" || SkipNotRecorded == SkipNotVisible {
		t.Error("the two reasons must differ")
	}
	// an interface the record does not hold at all
	got := AAASourceAddresses("cisco", sec, iosFacts.Clone())
	if len(got.Addrs) != 1 {
		t.Fatalf("known interface: %+v", got)
	}
	sec = aaaLines("ip tacacs source-interface Loopback9")
	got = AAASourceAddresses("cisco", sec, iosFacts)
	if len(got.Addrs) != 0 || !slices.Equal(got.Skipped, []SourceSkip{{"source-interface loopback9", SkipNoAddress}}) {
		t.Errorf("unknown interface: %+v", got)
	}
}

func TestAAASourceAddressesOtherVendors(t *testing.T) {
	sec := aaaLines("set system tacplus-server 192.0.2.10 source-address 198.51.100.9")
	for _, v := range []string{"wti", "other", ""} {
		if got := AAASourceAddresses(v, sec, nil); !got.Empty() {
			t.Errorf("%q: %+v", v, got)
		}
	}
	if got := AAASourceAddresses("juniper", aaaLines("set system authentication-order [ password tacplus ]"), nil); !got.Empty() {
		t.Errorf("no source: %+v", got)
	}
}
