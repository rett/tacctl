package store

import (
	"sort"

	"github.com/rett/tacctl/internal/cidr"
)

// CanonicalCIDR is canonical_cidr: the canonical string of a CIDR (the
// value is stripped first), or "" and false when v is not a string or does
// not parse.
func CanonicalCIDR(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	c := cidr.Canonical(pyStrip(s))
	return c, c != ""
}

// Net is a parsed network with the comparisons ipaddress offers.
type Net struct {
	n cidr.Network
	k cidr.Key
}

// ParseNet is ipaddress.ip_network(s, strict=False) (no stripping).
func ParseNet(s string) (Net, bool) {
	n, err := cidr.Parse(s)
	if err != nil {
		return Net{}, false
	}
	return Net{n: n, k: n.SortKey()}, true
}

// String is str(network), the canonical form.
func (a Net) String() string { return a.n.String() }

// Version is 4 or 6.
func (a Net) Version() int { return a.n.Version() }

// PrefixLen is the prefix length.
func (a Net) PrefixLen() int { return a.n.PrefixLen() }

// MaxPrefixLen is 32 or 128.
func (a Net) MaxPrefixLen() int {
	if a.n.IsIPv6() {
		return 128
	}
	return 32
}

// IsHost reports whether the network is a single address.
func (a Net) IsHost() bool { return a.PrefixLen() == a.MaxPrefixLen() }

// Key is cidr_key: (version, broadcast, network).
func (a Net) Key() cidr.Key { return a.k }

// Equal is ==: same version, address and prefix length.
func (a Net) Equal(b Net) bool { return a.k == b.k && a.PrefixLen() == b.PrefixLen() }

// SubnetOf is a.subnet_of(b) for networks of the same version.
func (a Net) SubnetOf(b Net) bool {
	if a.Version() != b.Version() {
		return false
	}
	return !lessU(a.k.Network, b.k.Network) && !lessU(b.k.Broadcast, a.k.Broadcast)
}

// Contains is 'address in network' for a host address given as a /32 or
// /128 network.
func (a Net) Contains(host Net) bool { return host.SubnetOf(a) }

func lessU(a, b [2]uint64) bool {
	if a[0] != b[0] {
		return a[0] < b[0]
	}
	return a[1] < b[1]
}

// DisplayKey is model.sh's display_key: longest prefix first, IPv4 before
// IPv6, then by address; a string that does not parse sorts after all.
type DisplayKey struct {
	bad     bool
	negLen  int
	version int
	network [2]uint64
}

// DisplayKeyOf returns the display key of a CIDR string.
func DisplayKeyOf(c string) DisplayKey {
	n, ok := ParseNet(c)
	if !ok {
		return DisplayKey{bad: true}
	}
	return DisplayKey{negLen: -n.PrefixLen(), version: n.Version(), network: n.k.Network}
}

// Less orders display keys as Python orders the tuples ((1, 0, 0) for a
// bad one, which is after every real key).
func (k DisplayKey) Less(o DisplayKey) bool {
	if k.bad != o.bad {
		return !k.bad
	}
	if k.bad {
		return false
	}
	if k.negLen != o.negLen {
		return k.negLen < o.negLen
	}
	if k.version != o.version {
		return k.version < o.version
	}
	return lessU(k.network, o.network)
}

// SortDisplay sorts CIDR strings by display key, stably (the order every
// listing uses).
func SortDisplay(cidrs []string) []string {
	out := append([]string(nil), cidrs...)
	keys := make(map[string]DisplayKey, len(out))
	for _, c := range out {
		keys[c] = DisplayKeyOf(c)
	}
	sort.SliceStable(out, func(i, j int) bool { return keys[out[i]].Less(keys[out[j]]) })
	return out
}

// cidrKeyOf is cidr_key of a canonical string (which always parses).
func cidrKeyOf(c string) cidr.Key {
	n, _ := ParseNet(c)
	return n.k
}

// canonicalCIDRList is canonical_cidr_list: canonicalise, dedupe and sort
// (render order) a list whose entries all parse; anything else comes back
// untouched for the validator.
func canonicalCIDRList(v any) any {
	items, ok := v.([]any)
	if !ok {
		return v
	}
	var out []string
	for _, c := range items {
		canon, ok := CanonicalCIDR(c)
		if !ok {
			return v
		}
		if !inList(out, canon) {
			out = append(out, canon)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return cidrKeyOf(out[i]).Less(cidrKeyOf(out[j])) })
	res := make([]any, len(out))
	for i, c := range out {
		res[i] = c
	}
	return res
}

// DeviceScope is what device_problems looks at in one scope.
type DeviceScope struct {
	Name string
	// Prefixes are the entries of the scope's prefix list (nil when it has
	// none or it is not a list); entries that are not CIDRs are skipped.
	Prefixes []any
	// Devices are the keys of the scope's devices mapping, in stored
	// order (nil when it has none or it is not a mapping).
	Devices []string
}

// DeviceProblem is one tagged address that cannot stand.
type DeviceProblem struct {
	Scope string
	CIDR  string // the devices key as stored
	Msg   string
}

// DeviceProblems is device_problems: the tagged addresses ('devices') that
// are not inside a prefix of their scope, or are inside a more specific
// prefix of another scope. Scopes are taken in the order given.
func DeviceProblems(scopes []DeviceScope) []DeviceProblem {
	type owned struct {
		net  Net
		name string
	}
	var nets []owned
	for _, s := range scopes {
		for _, c := range s.Prefixes {
			if canon, ok := CanonicalCIDR(c); ok {
				n, _ := ParseNet(canon)
				nets = append(nets, owned{n, s.Name})
			}
		}
	}
	var out []DeviceProblem
	for _, s := range scopes {
		for _, c := range s.Devices {
			canon, ok := CanonicalCIDR(c)
			if !ok {
				continue
			}
			net, _ := ParseNet(canon)
			var covering []owned
			mine := false
			for _, o := range nets {
				if o.net.Version() == net.Version() && net.SubnetOf(o.net) {
					covering = append(covering, o)
					if o.name == s.Name {
						mine = true
					}
				}
			}
			if !mine {
				out = append(out, DeviceProblem{s.Name, c,
					sprintf("scope '%s': devices: %s is not inside a prefix of the scope", s.Name, canon)})
				continue
			}
			// max() keeps the first of equal keys.
			best := covering[0]
			for _, o := range covering[1:] {
				if o.net.PrefixLen() > best.net.PrefixLen() {
					best = o
				}
			}
			if best.name != s.Name {
				out = append(out, DeviceProblem{s.Name, c,
					sprintf("scope '%s': devices: %s belongs to scope '%s' (its prefix %s is the most specific one that contains it)",
						s.Name, canon, best.name, best.net.String())})
			}
		}
	}
	return out
}
