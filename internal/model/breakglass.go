package model

// The model with the addresses of a break-glass hold carved out of it
// (docs/plans/0.2.5-plan.md D123). Both renderers and the read-back of the
// rendered file use this copy; the store is never changed.

import (
	"sort"

	"github.com/rett/tacctl/internal/cidr"
)

// piece is a prefix or a tagged address after the carve with the stored
// entry it came from.
type piece struct {
	cidr, origin string
}

// PrefixOrigin is the stored prefix that Prefixes[i] was carved from: the
// prefix itself for a scope nothing was carved out of. A carved piece takes
// the place of its origin in the routing order (it sorts where the origin
// did), so an address that is not held resolves to the scope it did before.
func (s *Scope) PrefixOrigin(i int) string {
	if i < len(s.prefixFrom) {
		return s.prefixFrom[i]
	}
	return s.Prefixes[i]
}

// DeviceOrigin is the stored tagged address that Devices[i] was carved
// from.
func (s *Scope) DeviceOrigin(i int) string {
	if i < len(s.deviceFrom) {
		return s.deviceFrom[i]
	}
	return s.Devices[i].CIDR
}

// WithoutAddresses returns the model with every prefix and every tagged
// address of every scope replaced by itself minus the addresses
// (cidr.Subtract): an entry that holds none of them stays as it is, one
// equal to an address is gone, one that holds one is its covering pieces,
// each of which remembers the entry it came from (PrefixOrigin,
// DeviceOrigin). A piece that two entries of a scope both produce is
// listed twice, once for each origin: the renderers keep the one the
// order or the longer prefix of the origins decides. The receiver is not
// changed; with no addresses it is returned as it is.
func (m *Model) WithoutAddresses(addrs []string) *Model {
	if len(addrs) == 0 {
		return m
	}
	out := *m
	out.Scopes = make([]*Scope, 0, len(m.Scopes))
	out.scopes = make(map[string]*Scope, len(m.Scopes))
	for _, s := range m.Scopes {
		ns := *s
		changed := false

		var ps []piece
		for _, p := range s.Prefixes {
			for _, c := range cidr.Subtract([]string{p}, addrs) {
				if c != p {
					changed = true
				}
				ps = append(ps, piece{c, p})
			}
		}
		if len(ps) != len(s.Prefixes) {
			changed = true
		}
		ns.Prefixes, ns.prefixFrom = nil, nil
		for _, p := range ps {
			ns.Prefixes = append(ns.Prefixes, p.cidr)
			ns.prefixFrom = append(ns.prefixFrom, p.origin)
		}

		type dev struct {
			d      Device
			origin string
		}
		var ds []dev
		for _, d := range s.Devices {
			for _, c := range cidr.Subtract([]string{d.CIDR}, addrs) {
				if c != d.CIDR {
					changed = true
				}
				ds = append(ds, dev{Device{CIDR: c, Vendor: d.Vendor}, d.CIDR})
			}
		}
		sort.SliceStable(ds, func(i, j int) bool { return ds[i].d.CIDR < ds[j].d.CIDR })
		ns.Devices, ns.deviceFrom = nil, nil
		for _, d := range ds {
			ns.Devices = append(ns.Devices, d.d)
			ns.deviceFrom = append(ns.deviceFrom, d.origin)
		}
		if len(ds) != len(s.Devices) {
			changed = true
		}

		if !changed {
			ns = *s
		}
		cp := ns
		out.Scopes = append(out.Scopes, &cp)
		out.scopes[cp.Name] = &cp
	}
	return &out
}

// Carve says where a held address is taken out of: one stored prefix or
// tagged address of a scope that holds it.
type Carve struct {
	Scope, CIDR string
	// Tagged is true for an entry of 'scope devices', false for a prefix.
	Tagged bool
}

// CarvedFrom lists the stored prefixes (and, with tagged, the tagged
// addresses: only RADIUS renders those) of the scopes that serve protocol
// ("" for every scope) which hold addr, by scope name and then in stored
// order: what a hold of addr is carved out of.
func (m *Model) CarvedFrom(addr, protocol string, tagged bool) []Carve {
	var out []Carve
	scopes := append([]*Scope(nil), m.Scopes...)
	sort.SliceStable(scopes, func(i, j int) bool { return scopes[i].Name < scopes[j].Name })
	for _, s := range scopes {
		if protocol != "" && !s.ServedBy(protocol) {
			continue
		}
		for _, p := range s.Prefixes {
			if cidr.ContainsAddr(p, addr) {
				out = append(out, Carve{s.Name, p, false})
			}
		}
		for _, d := range s.Devices {
			if tagged && cidr.ContainsAddr(d.CIDR, addr) {
				out = append(out, Carve{s.Name, d.CIDR, true})
			}
		}
	}
	return out
}
