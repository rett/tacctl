package devconf

// The addresses an AAA client sends from (0.2.23, D315): what the opt-in test
// of 'device check --sources' and 'device scan --sources' connects to. They
// come from the aaa section of the device's last pull (the Junos
// 'system tacplus-server|radius-server <addr> source-address <ip>', the IOS
// 'ip tacacs|radius source-interface <name>' of the section or, for the one the
// section leaves out, of the facts) and, for an interface, from the addresses
// the pull recorded (Record.Interfaces). Nothing here connects anywhere.

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// The reasons a source is not tested.
const (
	SkipNotRecorded = "addresses are not recorded: pull the device again"
	SkipNotVisible  = "this login cannot see the interfaces"
	SkipDynamic     = "the address is learned dynamically"
	SkipNoAddress   = "no address of this interface is recorded"
	SkipNotAddress  = "is not an address"
	SkipLocal       = "a loopback, link-local, unspecified, multicast or broadcast address cannot be tested from this server"
)

// SourceAddr is one address to test: Address in canonical form, Via the name
// of the source interface it belongs to ("" for a source-address).
type SourceAddr struct {
	Address string
	Via     string
}

// SourceSkip is a source that is not tested: Source as the device states it
// ('source-address 192.0.2.7', 'source-interface Loopback0'), Reason why.
type SourceSkip struct {
	Source string
	Reason string
}

// SourceAddresses are the sources of one device's AAA clients: the addresses
// to test, deduplicated and in address order, and the sources left out.
type SourceAddresses struct {
	Addrs   []SourceAddr
	Skipped []SourceSkip
}

// Empty reports whether the device states no source at all.
func (s SourceAddresses) Empty() bool { return len(s.Addrs) == 0 && len(s.Skipped) == 0 }

// AAASourceAddresses are the sources of the AAA client of a device's pull:
// aaa is its stored aaa section, facts the interface addresses of the pull
// (nil for a record made before 0.2.23). A Junos or IOS device only; another
// vendor, and a section that states no source, have none.
func AAASourceAddresses(vendor string, aaa devices.Section, facts *InterfaceFacts) SourceAddresses {
	fam, err := Family(vendor)
	if err != nil || (fam != FamilyJunos && fam != FamilyIOS) {
		return SourceAddresses{}
	}
	stmts := canonFor(fam)(aaa.Lines, aaa.Secret, nil)
	var off [][]string
	for _, x := range stmts {
		if fam == FamilyJunos && strings.HasPrefix(x.text, "deactivate ") {
			off = append(off, x.path)
		}
	}
	type src struct{ kind, value string }
	var found []src
	add := func(kind, value string) {
		s := src{kind, value}
		if kind == sourceInterface {
			s.value = strings.ToLower(value)
		}
		if !slices.Contains(found, s) {
			found = append(found, s)
		}
	}
	for _, x := range stmts {
		if fam == FamilyJunos && (!strings.HasPrefix(x.text, "set ") ||
			slices.ContainsFunc(off, func(d []string) bool { return len(d) <= len(x.path) && slices.Equal(d, x.path[:len(d)]) })) {
			continue
		}
		if kind, value, ok := aaaSource(fam, stmtWords(fam, x)); ok {
			add(kind, value)
		}
	}
	if fam == FamilyIOS && facts != nil {
		// the global statement of a protocol the rendering sets no server
		// for is not in the section: the pull kept it
		for _, proto := range []string{"tacacs", "radius"} {
			if v := facts.Sources[proto]; v != "" {
				add(sourceInterface, v)
			}
		}
	}

	var out SourceAddresses
	seen := map[string]bool{}
	skip := func(source, reason string) {
		if !slices.Contains(out.Skipped, SourceSkip{source, reason}) {
			out.Skipped = append(out.Skipped, SourceSkip{source, reason})
		}
	}
	keep := func(addr, via string) {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return
		}
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsUnspecified() || a.IsMulticast() ||
			a == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			skip("source-address "+addr, SkipLocal)
			return
		}
		if !seen[addr] {
			seen[addr] = true
			out.Addrs = append(out.Addrs, SourceAddr{Address: addr, Via: via})
		}
	}
	for _, s := range found {
		switch s.kind {
		case sourceAddress:
			a, ok := canonAddr(s.value)
			if !ok {
				skip("source-address "+s.value, SkipNotAddress)
				continue
			}
			keep(a, "")
		case sourceInterface:
			name := "source-interface " + s.value
			if !facts.checkable() {
				if facts == nil {
					skip(name, SkipNotRecorded)
				} else {
					skip(name, SkipNotVisible)
				}
				continue
			}
			var real, dynamic bool
			for _, a := range facts.Addresses[s.value] {
				if a == dynamicAddress {
					dynamic = true
					continue
				}
				real = true
				keep(a, s.value)
			}
			switch {
			case real:
			case dynamic:
				skip(name, SkipDynamic)
			default:
				skip(name, SkipNoAddress)
			}
		}
	}
	slices.SortFunc(out.Addrs, func(a, b SourceAddr) int {
		x, _ := netip.ParseAddr(a.Address)
		y, _ := netip.ParseAddr(b.Address)
		return x.Compare(y)
	})
	return out
}
