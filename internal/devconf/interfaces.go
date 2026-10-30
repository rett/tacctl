package devconf

// The addresses of the device's interfaces (0.2.23, D314): what the pull
// reads of the configuration it already reads, so that the source of the
// AAA client (a Junos 'source-address' under the server, an IOS
// 'source-interface') can be told from one that names nothing the device
// has. They are derived data kept in the record (Record.Interfaces), not in
// the sections file: they are no section and are never compared as
// statements. An older release reads the record with a decoder that ignores
// the key, so the rollback has nothing to undo (the pull repeats it).

import (
	"net/netip"
	"slices"
	"strings"
)

// dynamicAddress stands in an interface's list for an address the device
// obtains by itself or derives (DHCP, negotiation, an EUI-64 prefix, an
// unnumbered interface): the interface carries an address, which is not
// known.
const dynamicAddress = "dynamic"

// InterfaceFacts are the interface addresses of one pull.
type InterfaceFacts struct {
	// Visible is false when the text holds no interface address at all: a
	// login class that hides the interfaces shows none. Nothing is then
	// checked against them.
	Visible bool `json:"visible"`
	// Addresses are the addresses of each interface that carries one, in
	// canonical form without a prefix length (an IPv6 address in the short
	// form), sorted. Junos keys are the logical interfaces ('lo0.0',
	// 'ge-0/0/0.0') and hold the addresses of the VRRP groups as well; IOS
	// keys are the interface names in lower case. An address the device
	// obtains by itself is listed as "dynamic".
	Addresses map[string][]string `json:"addresses,omitempty"`
	// Sources are the interfaces the device names as the source of its
	// TACACS+ and RADIUS requests ('ip tacacs|radius source-interface'; IOS
	// only), by protocol ("tacacs", "radius"), as the device prints them.
	// The statement reaches the aaa section only where the rendering sets
	// one, so the pull keeps it here.
	Sources map[string]string `json:"sources,omitempty"`
}

// Clone is a deep copy (nil stays nil).
func (f *InterfaceFacts) Clone() *InterfaceFacts {
	if f == nil {
		return nil
	}
	c := *f
	if f.Addresses != nil {
		c.Addresses = make(map[string][]string, len(f.Addresses))
		for k, v := range f.Addresses {
			c.Addresses[k] = slices.Clone(v)
		}
	}
	if f.Sources != nil {
		c.Sources = make(map[string]string, len(f.Sources))
		for k, v := range f.Sources {
			c.Sources[k] = v
		}
	}
	return &c
}

// canonAddr parses an address with or without a prefix length and returns
// it in canonical form.
func canonAddr(s string) (string, bool) {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "/")
	a, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	return a.Unmap().String(), true
}

// add keeps an address (or the dynamic marker) of an interface.
func (f *InterfaceFacts) add(ifc, addr string) {
	if f.Addresses == nil {
		f.Addresses = map[string][]string{}
	}
	if !slices.Contains(f.Addresses[ifc], addr) {
		f.Addresses[ifc] = append(f.Addresses[ifc], addr)
		slices.Sort(f.Addresses[ifc])
	}
}

// finish sets Visible: at least one interface carries an address.
func (f *InterfaceFacts) finish() *InterfaceFacts {
	f.Visible = len(f.Addresses) > 0
	return f
}

// junosInterfaces reads the addresses of the interfaces out of the
// canonical statements of 'display set': 'interfaces <name> unit <n>
// family inet|inet6 address <ip>/<len>', the virtual addresses of a VRRP
// group under it, and a family that takes its address from DHCP. A
// statement that is deactivated, or that sits under a deactivated
// interface, unit, family or address, is not in effect and is not an
// address of the device.
func junosInterfaces(got []stmt) *InterfaceFacts {
	f := &InterfaceFacts{}
	var off [][]string
	for _, x := range got {
		if strings.HasPrefix(x.text, "deactivate ") && len(x.path) > 0 && x.path[0] == "interfaces" {
			off = append(off, x.path)
		}
	}
	// live reports whether no deactivated statement covers the first n words
	// of p.
	live := func(p []string, n int) bool {
		return !slices.ContainsFunc(off, func(d []string) bool { return len(d) <= n && slices.Equal(d, p[:len(d)]) })
	}
	for _, x := range got {
		p := x.path
		if !strings.HasPrefix(x.text, "set ") || len(p) < 7 || p[0] != "interfaces" || p[2] != "unit" || p[4] != "family" ||
			p[5] != "inet" && p[5] != "inet6" {
			continue
		}
		ifc := p[1] + "." + p[3]
		switch p[6] {
		case "dhcp", "dhcp-client", "dhcpv6-client", "negotiate-address":
			if live(p, 7) {
				f.add(ifc, dynamicAddress)
			}
		case "address":
			if len(p) < 8 || !live(p, 8) {
				continue
			}
			if slices.Contains(p[8:], "eui-64") {
				// the address is derived from the prefix and the interface:
				// the prefix is not an address of the device
				f.add(ifc, dynamicAddress)
			} else if a, ok := canonAddr(p[7]); ok {
				f.add(ifc, a)
			}
			// the virtual addresses of a VRRP group ride on the address
			for i := 8; i+1 < len(p); i++ {
				if (p[i] == "virtual-address" || p[i] == "virtual-inet6-address") && live(p, i+2) {
					if a, ok := canonAddr(p[i+1]); ok {
						f.add(ifc, a)
					}
				}
			}
		}
	}
	return f.finish()
}

// iosInterfaces reads the addresses of the interfaces out of the canonical
// statements of 'show running-config' ('interface <name>' with 'ip address
// <ip> <mask>' and 'ipv6 address <ip>/<len>'), and the source interfaces of
// the TACACS+ and RADIUS clients.
func iosInterfaces(got []stmt) *InterfaceFacts {
	f := &InterfaceFacts{}
	for _, x := range got {
		p := x.path
		switch {
		case len(p) == 1:
			w := strings.Fields(p[0])
			if len(w) >= 4 && w[0] == "ip" && (w[1] == "tacacs" || w[1] == "radius") && w[2] == "source-interface" {
				if f.Sources == nil {
					f.Sources = map[string]string{}
				}
				f.Sources[w[1]] = w[3]
			}
		case len(p) == 2 && strings.HasPrefix(p[0], "interface "):
			// the name is the first word: a subinterface line goes on with
			// 'point-to-point' or 'multipoint', which is no part of it
			name := strings.Fields(strings.TrimPrefix(p[0], "interface "))
			if len(name) == 0 {
				continue
			}
			ifc := strings.ToLower(name[0])
			w := strings.Fields(p[1])
			switch {
			case len(w) >= 3 && w[0] == "ip" && w[1] == "address":
				if a, ok := canonAddr(w[2]); ok {
					f.add(ifc, a)
				} else if w[2] == "dhcp" || w[2] == "negotiated" || w[2] == "pool" {
					f.add(ifc, dynamicAddress)
				}
			case len(w) >= 3 && w[0] == "ipv6" && w[1] == "address":
				if slices.Contains(w[3:], "eui-64") {
					f.add(ifc, dynamicAddress)
				} else if a, ok := canonAddr(w[2]); ok {
					f.add(ifc, a)
				} else if w[2] == "dhcp" || w[2] == "autoconfig" {
					f.add(ifc, dynamicAddress)
				}
			case len(w) >= 2 && w[0] == "ip" && w[1] == "unnumbered":
				f.add(ifc, dynamicAddress)
			}
		}
	}
	return f.finish()
}
