// Package mgmtacl is the grammar of one entry of the management ACL (the
// lists mgmt_acl.permits and scope_mgmt_acl.permits.<scope>, 0.2.7):
//
//	<cidr>[:<service>[,<service>...]]
//	<service> = tcp/<ports> | udp/<ports> | icmp
//	<ports>   = N | N-M | *          (* is every port of the protocol)
//
// A plain <cidr> (no services) permits every protocol and port from that
// source. The CIDR is split from the services at the first ':' that is
// followed by tcp/, udp/, icmp or '*' (an IPv6 CIDR holds colons, and none
// of them is followed by one of those words). The stored form is canonical:
// the canonical CIDR, then ':' and the services in lower case, de-duplicated,
// in the order tcp, udp, icmp and ports ascending; 'tcp/*' takes the other
// tcp services of the entry, and every protocol of the whole set is the plain
// CIDR.
//
// The package is pure: it reads nothing and writes nothing.
package mgmtacl

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
)

// MaxServices is the most services one entry may hold (after the canonical
// form took the repeats and the covered ports away).
const MaxServices = 8

// Protocols of a service.
const (
	TCP  = "tcp"
	UDP  = "udp"
	ICMP = "icmp"
)

// SSHPort is the port a Cisco VTY access list and a Junos management filter
// stand for: an entry is listed there only when it permits it.
const SSHPort = 22

// Service is one protocol and its ports.
type Service struct {
	Proto string // TCP, UDP or ICMP
	// Lo and Hi are the ports of a tcp or udp service (Lo == Hi for one
	// port); Any says every port, and icmp has none.
	Lo, Hi int
	Any    bool
}

// String is the service as it is written: tcp/22, udp/161-162, tcp/*, icmp.
func (s Service) String() string {
	switch {
	case s.Proto == ICMP:
		return ICMP
	case s.Any:
		return s.Proto + "/*"
	case s.Lo == s.Hi:
		return s.Proto + "/" + strconv.Itoa(s.Lo)
	}
	return s.Proto + "/" + strconv.Itoa(s.Lo) + "-" + strconv.Itoa(s.Hi)
}

// Ports is the service's ports as iptables' --dport takes them: "22",
// "161:162", and "" for every port (and for icmp).
func (s Service) Ports() string {
	switch {
	case s.Proto == ICMP, s.Any:
		return ""
	case s.Lo == s.Hi:
		return strconv.Itoa(s.Lo)
	}
	return strconv.Itoa(s.Lo) + ":" + strconv.Itoa(s.Hi)
}

// Covers reports whether the service lets proto's port through (icmp has no
// port: pass 0).
func (s Service) Covers(proto string, port int) bool {
	switch {
	case s.Proto != proto:
		return false
	case s.Proto == ICMP, s.Any:
		return true
	}
	return port >= s.Lo && port <= s.Hi
}

func protoRank(p string) int {
	switch p {
	case TCP:
		return 0
	case UDP:
		return 1
	}
	return 2
}

// cmp orders services as the canonical form lists them.
func (s Service) cmp(o Service) int {
	switch {
	case protoRank(s.Proto) != protoRank(o.Proto):
		return protoRank(s.Proto) - protoRank(o.Proto)
	case s.Any != o.Any:
		if s.Any {
			return -1
		}
		return 1
	case s.Lo != o.Lo:
		return s.Lo - o.Lo
	}
	return s.Hi - o.Hi
}

// Entry is one parsed entry: the canonical CIDR and its services (none for a
// plain entry).
type Entry struct {
	Net      string
	Services []Service
}

// Plain reports an entry with no services: every protocol and port.
func (e Entry) Plain() bool { return len(e.Services) == 0 }

// IPv6 reports an IPv6 network.
func (e Entry) IPv6() bool {
	n, err := cidr.Parse(e.Net)
	return err == nil && n.IsIPv6()
}

// String is the canonical stored form.
func (e Entry) String() string {
	if e.Plain() {
		return e.Net
	}
	return e.Net + ":" + ServicesText(e.Services, ",")
}

// ServicesText joins the services' spellings with sep (",", or ", " for a
// person).
func ServicesText(s []Service, sep string) string {
	parts := make([]string, len(s))
	for i, x := range s {
		parts[i] = x.String()
	}
	return strings.Join(parts, sep)
}

// Permits reports whether the entry lets proto's port through: a plain
// entry lets everything through.
func (e Entry) Permits(proto string, port int) bool {
	if e.Plain() {
		return true
	}
	for _, s := range e.Services {
		if s.Covers(proto, port) {
			return true
		}
	}
	return false
}

// AllowsSSH reports a plain entry, or one that has tcp/22 (alone, in a range
// or as tcp/*): the entries a standard access list and the Junos permit-mgmt
// term, which have no per-source services, stand for.
func (e Entry) AllowsSSH() bool { return e.Permits(TCP, SSHPort) }

// AllowsICMP reports a plain entry, or one that has the icmp service.
func (e Entry) AllowsICMP() bool { return e.Permits(ICMP, 0) }

// Error is a problem with the services of an entry (a bad CIDR is the
// *cidr.InvalidError of the cidr package).
type Error struct {
	Entry string
	Msg   string
}

func (e *Error) Error() string {
	return fmt.Sprintf("Invalid management ACL entry '%s': %s", e.Entry, e.Msg)
}

// isServiceStart reports the text a service begins with: the colon that
// splits an entry is the first one followed by it.
func isServiceStart(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, "tcp/") || strings.HasPrefix(l, "udp/") || strings.HasPrefix(l, "icmp") || strings.HasPrefix(l, "*")
}

// split cuts an entry into its CIDR and its services text; has says the
// entry carried a ':' that starts services.
func split(s string) (net, services string, has bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && isServiceStart(s[i+1:]) {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// ParseEntry parses one entry as it is stored or typed: a plain CIDR (any
// spelling the cidr package takes), or '<cidr>:<services>' with the services
// comma separated. The result is canonical. A bad CIDR is a
// *cidr.InvalidError, anything else a *Error. The text is not trimmed: a
// blank around it is no CIDR, as it never was.
func ParseEntry(s string) (Entry, error) {
	if s != strings.TrimSpace(s) {
		return Entry{}, &cidr.InvalidError{Value: s}
	}
	net, services, has := split(s)
	n, err := cidr.Parse(net)
	if err != nil {
		if !has {
			// '10.0.0.0/8:ssh': a CIDR, a colon and something that is no
			// service says so, instead of that the whole is no CIDR
			for i := 0; i < len(s); i++ {
				if s[i] != ':' {
					continue
				}
				if _, e := cidr.Parse(s[:i]); e != nil {
					continue
				}
				rest := strings.TrimSpace(s[i+1:])
				if rest == "" {
					return Entry{}, &Error{s, "no service after ':' (services are tcp/<ports>, udp/<ports> and icmp)"}
				}
				return Entry{}, &Error{s, "'" + rest + "' is not a service (services are tcp/<ports>, udp/<ports> and icmp; <ports> is N, N-M or *)"}
			}
		}
		return Entry{}, &cidr.InvalidError{Value: net}
	}
	e := Entry{Net: n.String()}
	if !has {
		return e, nil
	}
	svcs, all, err := parseServices(s, services)
	if err != nil {
		return Entry{}, err
	}
	if all {
		return e, nil
	}
	e.Services = svcs
	if len(e.Services) > MaxServices {
		return Entry{}, &Error{s, fmt.Sprintf("%d services; an entry holds at most %d (use tcp/* or udp/* for a protocol's every port, or a range)", len(e.Services), MaxServices)}
	}
	return e, nil
}

// parseServices reads the comma separated services of entry; all is set when
// the set is every protocol and port (the plain CIDR).
func parseServices(entry, text string) (out []Service, all bool, err error) {
	bad := func(format string, a ...any) error { return &Error{entry, fmt.Sprintf(format, a...)} }
	for _, tok := range strings.Split(text, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		switch {
		case tok == "":
			return nil, false, bad("an empty service (services are tcp/<ports>, udp/<ports> and icmp)")
		case tok == "*":
			all = true
			continue
		case tok == ICMP:
			out = append(out, Service{Proto: ICMP})
			continue
		case strings.HasPrefix(tok, "icmp/"):
			return nil, false, bad("'%s': icmp takes no port", tok)
		}
		proto, ports, ok := strings.Cut(tok, "/")
		if !ok || (proto != TCP && proto != UDP) {
			return nil, false, bad("'%s' is not a service (services are tcp/<ports>, udp/<ports> and icmp; <ports> is N, N-M or *)", tok)
		}
		s := Service{Proto: proto}
		if ports == "*" {
			s.Any = true
			out = append(out, s)
			continue
		}
		lo, hi, rangeForm := ports, "", false
		if i := strings.IndexByte(ports, '-'); i >= 0 {
			lo, hi, rangeForm = ports[:i], ports[i+1:], true
		}
		l, ok := port(lo)
		if !ok {
			return nil, false, bad("'%s': %s is not a port (1 to 65535)", tok, quoteOr(lo))
		}
		s.Lo, s.Hi = l, l
		if rangeForm {
			h, ok := port(hi)
			if !ok {
				return nil, false, bad("'%s': %s is not a port (1 to 65535)", tok, quoteOr(hi))
			}
			if l >= h {
				return nil, false, bad("'%s': the range's first port must be lower than its last (use %s/%d for one port)", tok, proto, l)
			}
			s.Hi = h
		}
		out = append(out, s)
	}
	if all {
		return nil, true, nil
	}
	out = canonicalServices(out)
	// tcp/*, udp/* and icmp together are everything: the plain CIDR
	if len(out) == 3 && out[0].Proto == TCP && out[0].Any && out[1].Proto == UDP && out[1].Any && out[2].Proto == ICMP {
		return nil, true, nil
	}
	return out, false, nil
}

func quoteOr(s string) string {
	if s == "" {
		return "an empty value"
	}
	return "'" + s + "'"
}

// port reads a decimal port 1 to 65535 (digits only).
func port(s string) (int, bool) {
	if s == "" || len(s) > 5 {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	n, _ := strconv.Atoi(s)
	return n, n >= 1 && n <= 65535
}

// canonicalServices sorts the services (tcp, udp, icmp; ports ascending),
// drops the repeats and lets a protocol's '*' take the rest of its entries.
func canonicalServices(in []Service) []Service {
	any := map[string]bool{}
	for _, s := range in {
		if s.Any {
			any[s.Proto] = true
		}
	}
	var out []Service
	for _, s := range in {
		if s.Proto != ICMP && any[s.Proto] && !s.Any {
			continue
		}
		dup := false
		for _, o := range out {
			if o == s {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].cmp(out[j]) < 0 })
	return out
}

// Canonical is the stored form of an entry, and false when it is no entry.
func Canonical(s string) (string, bool) {
	e, err := ParseEntry(s)
	if err != nil {
		return "", false
	}
	return e.String(), true
}

// Problem is "" when s can be an element of the lists, else why not
// (the schema's message): '<cidr>' keeps its message of before.
func Problem(s string) string {
	_, err := ParseEntry(s)
	switch e := err.(type) {
	case nil:
		return ""
	case *cidr.InvalidError:
		return "is not a valid CIDR"
	case *Error:
		return e.Msg
	}
	return err.Error()
}

// Group attaches each service token (one that starts with tcp/, udp/ or
// icmp, in any case) to the entry before it, so that the commas of a service
// list and the commas between entries read as one list: 'a,b:tcp/22,udp/161,c'
// is a, b:tcp/22,udp/161 and c. Tokens are trimmed and empty ones dropped.
// A service before any CIDR is an *Error.
func Group(tokens []string) ([]string, error) {
	var out []string
	for _, raw := range tokens {
		t := strings.TrimSpace(raw)
		if t == "" {
			continue
		}
		l := strings.ToLower(t)
		if strings.HasPrefix(l, "tcp/") || strings.HasPrefix(l, "udp/") || strings.HasPrefix(l, "icmp") {
			if len(out) == 0 {
				return nil, &Error{t, "a service comes after a CIDR (<cidr>:tcp/22,udp/161)"}
			}
			if _, _, has := split(out[len(out)-1]); !has {
				// 'a,tcp/22': the service has no ':' to follow
				return nil, &Error{out[len(out)-1] + "," + t, "write the services after a ':' (<cidr>:tcp/22,udp/161)"}
			}
			out[len(out)-1] += "," + t
			continue
		}
		out = append(out, t)
	}
	return out, nil
}

// ParseList reads a comma separated list of entries (Group's rule) and
// returns the canonical entries, in input order, each once. The first bad
// entry is the error.
func ParseList(input string) ([]Entry, error) {
	tokens, err := Group(strings.Split(input, ","))
	if err != nil {
		return nil, err
	}
	var out []Entry
	seen := map[string]bool{}
	for _, t := range tokens {
		e, err := ParseEntry(t)
		if err != nil {
			return nil, err
		}
		if s := e.String(); !seen[s] {
			seen[s] = true
			out = append(out, e)
		}
	}
	return out, nil
}

// Sort canonicalises stored entries, drops the repeats and what is no entry,
// and orders them as the lists always were: by the CIDR's version, broadcast
// address and network address (most specific first, IPv4 before IPv6), and
// then by services (the plain entry first).
func Sort(list []string) []string {
	type item struct {
		s string
		e Entry
		k cidr.Key
	}
	var items []item
	seen := map[string]bool{}
	for _, l := range list {
		e, err := ParseEntry(strings.TrimSpace(l))
		if err != nil || seen[e.String()] {
			continue
		}
		seen[e.String()] = true
		k, _ := cidr.SortKey(e.Net)
		items = append(items, item{e.String(), e, k})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		switch {
		case a.k.Less(b.k):
			return true
		case b.k.Less(a.k):
			return false
		}
		return compareServices(a.e.Services, b.e.Services) < 0
	})
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.s
	}
	return out
}

// compareServices orders two service lists: the shorter prefix first, the
// plain (empty) list before any.
func compareServices(a, b []Service) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if c := a[i].cmp(b[i]); c != 0 {
			return c
		}
	}
	return len(a) - len(b)
}

// Display is an entry as 'list' prints it: the CIDR, then (for an entry with
// services) the services for a person, the CIDR padded to width.
func Display(e Entry, width int) string {
	if e.Plain() {
		return e.Net
	}
	return fmt.Sprintf("%-*s   %s", width, e.Net, ServicesText(e.Services, ", "))
}
