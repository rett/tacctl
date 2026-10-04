package model

import (
	"github.com/rett/tacctl/internal/store"
)

// AddrInfo is what ScopeLookup tells of an address, as data: the scope
// tacquito would pick, the prefix that routes to it, the vendor tag that
// covers the address in that scope (the most specific 'devices' entry) and
// the scopes whose prefixes also hold it but lose to the first.
type AddrInfo struct {
	Scope, Prefix string
	// Tag is the vendor of the covering tag ('' when none) and TagCIDR the
	// entry that carries it.
	Tag, TagCIDR string
	// Shadowed are the other scopes that cover the address, in routing order.
	Shadowed []string
}

// LookupAddr is ScopeLookup for one address, as a value: ok is false when
// the address is not valid or no scope owns it.
func (m *Model) LookupAddr(address string) (info AddrInfo, ok bool) {
	q, valid := store.ParseNet(address)
	if !valid {
		return AddrInfo{}, false
	}
	seen := map[string]bool{}
	for _, p := range m.routingPairs() {
		pnet, valid := store.ParseNet(p.cidr)
		if !valid || pnet.Version() != q.Version() || !pnet.Contains(q) {
			continue
		}
		if info.Scope == "" {
			info.Scope, info.Prefix = p.scope, pnet.String()
			seen[p.scope] = true
			continue
		}
		if !seen[p.scope] {
			seen[p.scope] = true
			info.Shadowed = append(info.Shadowed, p.scope)
		}
	}
	if info.Scope == "" {
		return AddrInfo{}, false
	}
	var best *store.Net
	for _, d := range m.scopes[info.Scope].Devices {
		tnet, valid := store.ParseNet(d.CIDR)
		if !valid || tnet.Version() != q.Version() {
			continue
		}
		if q.SubnetOf(tnet) && (best == nil || tnet.PrefixLen() > best.PrefixLen()) {
			t := tnet
			best, info.Tag, info.TagCIDR = &t, d.Vendor, d.CIDR
		}
	}
	return info, true
}
