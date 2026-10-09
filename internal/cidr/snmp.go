package cidr

import (
	"fmt"
	"strings"
)

// MaxSNMPClients is the most allowed-client ranges a scope's SNMP list may
// hold (D41): a device's access list is read by people, and a list longer
// than this is a sign that a wider range was meant.
const MaxSNMPClients = 32

// ClientProblem is "" when s can be one entry of a scope's SNMP client list
// as it is stored, else why not: an IPv4 network in its canonical form
// (a.b.c.d/len), not 0.0.0.0/0. The list's final 0.0.0.0/0 restrict is
// always rendered and never stored, so a stored one could only be a
// permit-everything.
func ClientProblem(s string) string {
	n, err := Parse(s)
	switch {
	case err != nil:
		return "is not a valid CIDR"
	case n.IsIPv6():
		return "is an IPv6 network (the SNMP client list is IPv4 only)"
	case n.PrefixLen() == 0:
		return "would allow every address: 0.0.0.0/0 is the restrict tacctl always renders last, and is never stored"
	case n.String() != s:
		return "is not in its canonical form (" + n.String() + ")"
	}
	return ""
}

// ContainsNet reports whether the IPv4 network outer holds every address
// of inner (equal networks contain each other); false for an input that
// does not parse or is not IPv4.
func ContainsNet(outer, inner string) bool {
	o, err := Parse(outer)
	if err != nil || o.v6 {
		return false
	}
	i, err := Parse(inner)
	if err != nil || i.v6 {
		return false
	}
	return o.prefix <= i.prefix && i.ip.and(ones(32, o.prefix)).cmp(o.ip) == 0
}

// Overlaps reports whether two IPv4 networks share an address: one holds
// the other.
func Overlaps(a, b string) bool { return ContainsNet(a, b) || ContainsNet(b, a) }

// CiscoPermit is the body of a standard access-list entry for an IPv4
// network: 'host <address>' for a /32, else '<address> <wildcard>'; ""
// for IPv6 and unparsable input.
func CiscoPermit(s string) string {
	wc := CiscoWildcard(s)
	if wc == "" {
		return ""
	}
	n, _ := Parse(s)
	if n.prefix == 32 {
		return "host " + strings.TrimSuffix(n.String(), "/32")
	}
	return wc
}

// Host32 is the /32 network of an IPv4 address ("" for anything that is
// not one).
func Host32(addr string) string {
	if strings.ContainsAny(addr, "/ ") {
		return ""
	}
	n, err := Parse(addr)
	if err != nil || n.v6 || n.prefix != 32 {
		return ""
	}
	return n.String()
}

// OverlapWarnings are the notes on a list of IPv4 networks that overlap
// each other: one line per pair, the wider network first. Overlap is no
// error (an access list takes both), only worth saying.
func OverlapWarnings(list []string) []string {
	var out []string
	for i, a := range list {
		for _, b := range list[i+1:] {
			switch {
			case a == b:
			case ContainsNet(a, b):
				out = append(out, fmt.Sprintf("%s already contains %s", a, b))
			case ContainsNet(b, a):
				out = append(out, fmt.Sprintf("%s already contains %s", b, a))
			}
		}
	}
	return out
}
