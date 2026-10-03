// Package cidr is tacctl's view of Python's ipaddress.ip_network(s,
// strict=False): validation, the canonical string, the sort key of
// 'sort_cidrs_by_specificity', the Cisco wildcard form and the
// comma-separated list parser of lib/core.sh (validate_cidr,
// canonicalize_cidr, sort_cidrs_by_specificity, parse_cidr_list) and
// lib/render_devices.sh (cidr_to_cisco_wildcard). The parsing is a port of
// CPython 3.12's ipaddress module (see parse.go), so what bash accepted is
// accepted here and renders to the same string.
package cidr

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/shellquote"
)

// InvalidError is "Invalid CIDR: '<value>'", the message validate_cidr
// prints before exiting 1.
type InvalidError struct{ Value string }

func (e *InvalidError) Error() string { return fmt.Sprintf("Invalid CIDR: '%s'", e.Value) }

// Network is a parsed IPv4 or IPv6 network, host bits cleared.
type Network struct {
	v6     bool
	ip     u128 // network address
	prefix int
	scope  string // IPv6 scope id kept by Python when no host bits were set
}

// Parse is ipaddress.ip_network(s, strict=False): 'a.b.c.d[/len|/netmask|
// /hostmask]' or an IPv6 address with an optional '/len' (and a scope id);
// a missing mask is the host mask (/32, /128). IPv4 is tried first. The
// input is not trimmed. It returns *InvalidError.
func Parse(s string) (Network, error) {
	addr, mask, hasMask := s, "", false
	if i := strings.IndexByte(s, '/'); i >= 0 {
		addr, mask, hasMask = s[:i], s[i+1:], true
		if strings.IndexByte(mask, '/') >= 0 {
			return Network{}, &InvalidError{s} // only one '/' permitted
		}
	}
	if n, ok := parse4(addr, mask, hasMask); ok {
		return n, nil
	}
	if n, ok := parse6(addr, mask, hasMask); ok {
		return n, nil
	}
	return Network{}, &InvalidError{s}
}

// IsIPv6 reports the address family.
func (n Network) IsIPv6() bool { return n.v6 }

// Version is 4 or 6, the first element of the sort key.
func (n Network) Version() int {
	if n.v6 {
		return 6
	}
	return 4
}

// PrefixLen is the prefix length.
func (n Network) PrefixLen() int { return n.prefix }

// String is str(ip_network): dotted quad or the compressed lower-case IPv6
// form (CPython 3.12: an IPv4-mapped address prints as hextets), then
// '/<prefixlen>'.
func (n Network) String() string {
	if !n.v6 {
		a := uint32(n.ip.lo)
		return fmt.Sprintf("%d.%d.%d.%d/%d", a>>24, a>>16&0xff, a>>8&0xff, a&0xff, n.prefix)
	}
	var h [8]string
	var raw [8]uint64
	for i := 0; i < 4; i++ {
		raw[i] = n.ip.hi >> (48 - 16*uint(i)) & 0xffff
		raw[i+4] = n.ip.lo >> (48 - 16*uint(i)) & 0xffff
	}
	for i, v := range raw {
		h[i] = formatHex(v)
	}
	// Replace the longest run of "0" (length > 1, first on a tie) with "::".
	bestStart, bestLen, start, run := -1, 0, -1, 0
	for i, s := range h {
		if s == "0" {
			run++
			if start == -1 {
				start = i
			}
			if run > bestLen {
				bestLen, bestStart = run, start
			}
		} else {
			run, start = 0, -1
		}
	}
	var out string
	if bestLen > 1 {
		out = strings.Join(h[:bestStart], ":") + "::" + strings.Join(h[bestStart+bestLen:], ":")
	} else {
		out = strings.Join(h[:], ":")
	}
	if n.scope != "" {
		out += "%" + n.scope
	}
	return fmt.Sprintf("%s/%d", out, n.prefix)
}

// Key is the sort key of sort_cidrs_by_specificity: (version, broadcast
// address, network address).
type Key struct {
	Version   int
	Broadcast [2]uint64 // hi, lo
	Network   [2]uint64
}

// SortKey is (version, int(broadcast_address), int(network_address)).
func (n Network) SortKey() Key {
	width := 32
	if n.v6 {
		width = 128
	}
	bc := n.ip.or(ones(width, n.prefix).not().and(allOnes(width)))
	return Key{Version: n.Version(), Broadcast: [2]uint64{bc.hi, bc.lo}, Network: [2]uint64{n.ip.hi, n.ip.lo}}
}

// Less orders keys as Python orders the tuples.
func (k Key) Less(o Key) bool {
	if k.Version != o.Version {
		return k.Version < o.Version
	}
	if k.Broadcast != o.Broadcast {
		return u128{k.Broadcast[0], k.Broadcast[1]}.cmp(u128{o.Broadcast[0], o.Broadcast[1]}) < 0
	}
	return u128{k.Network[0], k.Network[1]}.cmp(u128{o.Network[0], o.Network[1]}) < 0
}

// Validate is validate_cidr: nil when s parses, else *InvalidError.
func Validate(s string) error {
	_, err := Parse(s)
	return err
}

// Canonical is canonicalize_cidr: the canonical string, or "" for input
// that does not parse.
func Canonical(s string) string {
	n, err := Parse(s)
	if err != nil {
		return ""
	}
	return n.String()
}

// SortKey is the key of one CIDR string; false when it does not parse.
func SortKey(s string) (Key, bool) {
	n, err := Parse(s)
	if err != nil {
		return Key{}, false
	}
	return n.SortKey(), true
}

// SortBySpecificity is sort_cidrs_by_specificity: each entry is trimmed,
// empty and unparsable entries are dropped silently, and the rest are
// ordered by (version, broadcast, network) ascending - most specific first,
// IPv4 before IPv6 - keeping each entry's own text and the input order of
// equal keys (Python's sort is stable). Callers that need a clean list
// validate first.
func SortBySpecificity(cidrs []string) []string {
	type item struct {
		s string
		k Key
	}
	var items []item
	for _, c := range cidrs {
		s := strings.TrimSpace(c)
		if s == "" {
			continue
		}
		if k, ok := SortKey(s); ok {
			items = append(items, item{s, k})
		}
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].k.Less(items[j].k) })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.s
	}
	return out
}

// CiscoWildcard is cidr_to_cisco_wildcard: '10.1.0.0/16' becomes
// '10.1.0.0 0.0.255.255'. IPv6 and unparsable input give "" (the callers
// decide whether to skip or warn).
func CiscoWildcard(s string) string {
	n, err := Parse(s)
	if err != nil || n.v6 {
		return ""
	}
	a := uint32(n.ip.lo)
	host := ^uint32(ones(32, n.prefix).lo)
	return fmt.Sprintf("%d.%d.%d.%d %d.%d.%d.%d",
		a>>24, a>>16&0xff, a>>8&0xff, a&0xff, host>>24, host>>16&0xff, host>>8&0xff, host&0xff)
}

// ErrUnmatchedQuote is what xargs reports for an entry with an unbalanced
// quote (see ParseList).
var ErrUnmatchedQuote = errors.New("unmatched quote in CIDR list entry")

// ParseList is parse_cidr_list: split on commas, trim, validate every entry
// (the first invalid one is returned as *InvalidError, naming the entry as
// the shell saw it), canonicalise and drop repeats of an earlier entry's
// canonical form. Empty entries are skipped; empty input gives an empty
// list. The order is the input order.
//
// Faithful quirks of the bash: only the first line of input is read ('read
// -ra' on a here-string); each entry goes through 'echo | xargs', which
// trims it, collapses inner blanks to one space and consumes quotes and
// backslashes (an unbalanced quote is ErrUnmatchedQuote, where bash made
// xargs fail). Not reproduced: an entry that is a word starting '-n' or '-e'
// is swallowed by xargs's echo and a trailing backslash joins a newline; both
// only change which message a malformed entry gets.
func ParseList(input string) ([]string, error) {
	if i := strings.IndexByte(input, '\n'); i >= 0 {
		input = input[:i]
	}
	var out []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(input, ",") {
		entry, err := shellquote.XargsEcho(raw)
		if err != nil {
			return nil, ErrUnmatchedQuote
		}
		if entry == "" {
			continue
		}
		n, err := Parse(entry)
		if err != nil {
			return nil, err
		}
		c := n.String()
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}
