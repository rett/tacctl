package cli

// 'device list' selection: the rows are sorted by name and may be narrowed
// by name, address, vendor and scope. Each option takes one value or a
// comma-separated list (any of them matches); different options must all
// match; the optional word matches the name, the address, the vendor or the
// scope. Nothing here reads state: it is a pure function of the entries.

import (
	"net/netip"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
)

// deviceListFilter is what a 'device list' was narrowed by.
type deviceListFilter struct {
	names, addrs, vendors, scopes []string
	word                          string
}

// empty reports a filter that selects everything.
func (f deviceListFilter) empty() bool {
	return len(f.names)+len(f.addrs)+len(f.vendors)+len(f.scopes) == 0 && f.word == ""
}

// splitList is the non-empty, trimmed, lower-cased items of a
// comma-separated option value.
func splitList(values []string) []string {
	var out []string
	for _, v := range values {
		for _, s := range strings.Split(v, ",") {
			if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

// newDeviceListFilter builds the filter of one invocation.
func newDeviceListFilter(p Parsed) deviceListFilter {
	f := deviceListFilter{
		names:   splitList(p.Values("--name")),
		addrs:   splitList(p.Values("--ip")),
		vendors: splitList(p.Values("--vendor")),
		scopes:  splitList(p.Values("--scope")),
	}
	if len(p.Args) > 0 {
		f.word = strings.ToLower(strings.TrimSpace(p.Args[0]))
	}
	return f
}

// addrMatches says whether an address (as registered) fits one address
// pattern: a CIDR it lies in, an address it equals, or else a text it
// contains ('10.20.' selects a range of dotted addresses).
func addrMatches(addr, pattern string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if pr, err := netip.ParsePrefix(pattern); err == nil {
		a, aerr := netip.ParseAddr(addr)
		return aerr == nil && pr.Contains(a.Unmap())
	}
	if pa, err := netip.ParseAddr(pattern); err == nil {
		a, aerr := netip.ParseAddr(addr)
		return aerr == nil && a.Unmap() == pa.Unmap()
	}
	return strings.Contains(addr, pattern)
}

func anyContains(hay string, needles []string) bool {
	hay = strings.ToLower(hay)
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

func anyEquals(v string, wants []string) bool {
	v = strings.ToLower(v)
	for _, w := range wants {
		if v == w {
			return true
		}
	}
	return false
}

// match says whether the entry passes every option that was given.
func (f deviceListFilter) match(e devreg.Entry) bool {
	if len(f.names) > 0 && !anyContains(e.Name, f.names) {
		return false
	}
	if len(f.addrs) > 0 {
		ok := false
		for _, a := range f.addrs {
			if addrMatches(e.Address, a) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.vendors) > 0 && !anyEquals(e.Vendor, f.vendors) {
		return false
	}
	if len(f.scopes) > 0 && !anyEquals(e.Scope, f.scopes) {
		return false
	}
	if f.word != "" {
		if !strings.Contains(strings.ToLower(e.Name), f.word) && !strings.Contains(strings.ToLower(e.Address), f.word) &&
			!strings.EqualFold(e.Vendor, f.word) && !strings.EqualFold(e.Scope, f.word) {
			return false
		}
	}
	return true
}

// sortEntriesByName orders the rows by name (case-insensitively), then by
// address, so the table and its JSON are in one stable order.
func sortEntriesByName(es []devreg.Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := strings.ToLower(es[i].Name), strings.ToLower(es[j].Name)
		if a != b {
			return a < b
		}
		return es[i].Address < es[j].Address
	})
}
