package devices

// The strict (deny-by-default) mode of the Junos management filter (0.2.20,
// 'tacctl scope mgmt-acl <scope> mode strict'). The ssh-only filter
// (juniper.go) matches ssh and NETCONF from the permit list and ends in a
// default-accept term; the strict filter accepts every protocol from the
// permit list and has no default-accept term, so the implicit discard of a
// Junos filter drops the rest.
//
// What the permit list says of an entry is kept (mgmtacl): a plain entry
// accepts everything from that source, an entry with services only those
// services. The terms:
//
//	permit-mgmt        the sources of every plain entry, the server's /32
//	                   first; then accept
//	permit-<service>   one term per distinct service of the entries that
//	                   have services (permit-tcp-22, permit-udp-161-162,
//	                   permit-tcp-any, permit-icmp), with the sources that
//	                   name it, protocol and destination port; then accept
//
// then the permit-snmp and deny-snmp terms of the SNMP clients, as in the
// ssh-only filter, and last permit-auth-replies, the replies of the server
// the device authenticates against, when its address is not a plain source
// above. It follows the SNMP terms so that deny-snmp decides udp port 161
// first. A service term is named after its service, not its
// position, so a list that gains an entry changes the terms it names and no
// other.

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/mgmtacl"
)

// strictTerm is one service term of the strict filter.
type strictTerm struct {
	name    string
	svc     mgmtacl.Service
	sources []string
}

// authReply is the term of the strict filter that accepts the replies of the
// server the device authenticates against, from an address that is not a
// source of the permit list.
type authReply struct {
	source  string   // the server's /32
	proto   string   // tcp (TACACS+) or udp (RADIUS)
	ports   []string // the source ports of the replies, as the statement writes them
	entries []string // the entries with services of the permit list that hold the address
	ssh     bool     // one of them permits ssh
}

// authReplyTerm is the name of the term that holds the replies of the
// authentication server.
const authReplyTerm = "permit-auth-replies"

// mgmtStrict are the permits of the strict filter: the sources of the
// permit-mgmt term (the IPv4 entries without services, headed by the server's
// /32 as mgmtPermits does: --source, else the detected address) and the
// service terms (the entries that have services, grouped by service in the
// order the canonical entry lists them). Nothing when the ACL has no IPv4
// entry, or none that permits ssh (a plain entry, or one with tcp/22): no
// block is rendered then, as in the ssh-only mode (mgmtPermits), because the
// server's address alone would be one that locks everybody else out. An entry
// whose network is already a source of permit-mgmt (the server's /32 or a
// plain entry of the same network) adds nothing: that source accepts
// everything.
//
// auth is the address the device is told to authenticate against: --server,
// else the bound RADIUS address, else the detected one. When it is another
// address than the sources of permit-mgmt, the replies of the TACACS+ or
// RADIUS server come from it, and a filter that ends in the discard must
// accept them; reply says so. It is no source of permit-mgmt: the device
// starts those sessions, so only the packets of the replies are accepted from
// it (a TACACS+ connection already established from port 49, RADIUS udp from
// the listener's ports). No reply when a plain source (the server's /32, a
// plain entry, or a range of one) holds the address already: it is accepted
// for everything.
func (d Data) mgmtStrict(auth, protocol string) (plain []string, terms []strictTerm, reply *authReply) {
	var entries []mgmtacl.Entry
	for _, raw := range d.ACL.CIDRs {
		e, err := mgmtacl.ParseEntry(raw)
		if err != nil || e.IPv6() {
			continue
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 || !slices.ContainsFunc(entries, mgmtacl.Entry.AllowsSSH) {
		return nil, nil, nil
	}
	if srv := cidr.Host32(d.source()); srv != "" {
		plain = append(plain, srv)
	}
	for _, e := range entries {
		if e.Plain() && !slices.Contains(plain, e.Net) {
			plain = append(plain, e.Net)
		}
	}
	if a := cidr.Host32(auth); a != "" && !prefixesHold(plain, a) {
		reply = d.authReplies(a, protocol)
		for _, e := range entries {
			if !e.Plain() && prefixesHold([]string{e.Net}, a) {
				reply.entries = append(reply.entries, e.String())
				reply.ssh = reply.ssh || e.AllowsSSH()
			}
		}
	}
	for _, e := range entries {
		if e.Plain() || slices.Contains(plain, e.Net) {
			continue
		}
		for _, s := range e.Services {
			i := slices.IndexFunc(terms, func(t strictTerm) bool { return t.svc == s })
			if i < 0 {
				terms = append(terms, strictTerm{name: serviceTermName(s), svc: s})
				i = len(terms) - 1
			}
			if !slices.Contains(terms[i].sources, e.Net) {
				terms[i].sources = append(terms[i].sources, e.Net)
			}
		}
	}
	slices.SortStableFunc(terms, func(a, b strictTerm) int { return serviceRank(a.svc) - serviceRank(b.svc) })
	return plain, terms, reply
}

// prefixesHold reports whether one of the prefixes holds the /32 address a.
func prefixesHold(prefixes []string, a string) bool {
	ap, err := netip.ParsePrefix(a)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if pp, err := netip.ParsePrefix(p); err == nil && pp.Contains(ap.Addr()) {
			return true
		}
	}
	return false
}

// authReplies are the replies of the server at a (its /32) in the walkthrough
// of protocol: TACACS+ answers over tcp from port 49 (the walkthrough sets no
// other), in a connection the device opened; RADIUS answers over udp from the listener's authentication and
// accounting ports (1812 and 1813 unless the listener is configured with
// others), the ports the walkthrough sets on the device.
func (d Data) authReplies(a, protocol string) *authReply {
	if protocol != RADIUS {
		return &authReply{source: a, proto: "tcp", ports: []string{junosPortOf(49)}}
	}
	auth, acct := "1812", "1813"
	if d.Radius != nil {
		auth, acct = d.Radius.AuthPort, d.Radius.AcctPort
	}
	r := &authReply{source: a, proto: "udp"}
	for _, p := range []string{auth, acct} {
		if n, err := strconv.Atoi(p); err == nil {
			p = junosPortOf(n)
		}
		if !slices.Contains(r.ports, p) {
			r.ports = append(r.ports, p)
		}
	}
	return r
}

// serviceRank orders the service terms as the canonical entry lists its
// services: tcp, udp, icmp; every port before a port; ports ascending.
func serviceRank(s mgmtacl.Service) int {
	r := 0
	switch s.Proto {
	case mgmtacl.UDP:
		r = 1 << 30
	case mgmtacl.ICMP:
		r = 2 << 30
	}
	if s.Any || s.Proto == mgmtacl.ICMP {
		return r
	}
	return r + 1 + s.Lo*65536 + s.Hi
}

// serviceTermName is the term of a service: permit-tcp-22, permit-udp-161-162,
// permit-tcp-any, permit-icmp.
func serviceTermName(s mgmtacl.Service) string {
	switch {
	case s.Proto == mgmtacl.ICMP:
		return "permit-icmp"
	case s.Any:
		return "permit-" + s.Proto + "-any"
	case s.Lo == s.Hi:
		return "permit-" + s.Proto + "-" + strconv.Itoa(s.Lo)
	}
	return "permit-" + s.Proto + "-" + strconv.Itoa(s.Lo) + "-" + strconv.Itoa(s.Hi)
}

// junosPortNames are the ports whose names 'show configuration' prints in
// place of the number; the statement is written with the name so that what a
// device prints compares equal to what is rendered. A port that is not here
// has no name (or more than one) and is written as a number.
var junosPortNames = map[int]string{
	22: "ssh", 23: "telnet", 49: "tacacs", 53: "domain", 69: "tftp", 80: "http", 123: "ntp", 161: "snmp", 162: "snmptrap",
	179: "bgp", 443: "https", 646: "ldp", 1812: "radius", 1813: "radacct",
}

// junosPortOf is a port as the statement writes it: its name, else its number.
func junosPortOf(n int) string {
	if name, ok := junosPortNames[n]; ok {
		return name
	}
	return strconv.Itoa(n)
}

// junosPort is a destination port as the statement writes it.
func junosPort(s mgmtacl.Service) string {
	if s.Lo == s.Hi {
		return junosPortOf(s.Lo)
	}
	return strconv.Itoa(s.Lo) + "-" + strconv.Itoa(s.Hi)
}

// strictStatements are the 'set' lines of the strict filter's permit terms
// (prefix is "set firewall family inet filter <name> term "): permit-mgmt,
// then one term per service. A term holds only what its entry says: a
// service term with a protocol and no port is every port of the protocol.
func strictStatements(prefix string, plain []string, terms []strictTerm) string {
	var b strings.Builder
	if len(plain) > 0 {
		for _, e := range plain {
			b.WriteString(prefix + "permit-mgmt from source-address " + e + "\n")
		}
		b.WriteString(prefix + "permit-mgmt then accept\n")
	}
	for _, t := range terms {
		for _, e := range t.sources {
			b.WriteString(prefix + t.name + " from source-address " + e + "\n")
		}
		b.WriteString(prefix + t.name + " from protocol " + t.svc.Proto + "\n")
		if t.svc.Proto != mgmtacl.ICMP && !t.svc.Any {
			b.WriteString(prefix + t.name + " from destination-port " + junosPort(t.svc) + "\n")
		}
		b.WriteString(prefix + t.name + " then accept\n")
	}
	return b.String()
}

// authReplyStatements are the 'set' lines of the term of the authentication
// server's replies (nothing without one). The filter is stateless: the term
// matches by source address, protocol and source port. For TACACS+ it adds
// tcp-established (every tcp packet but the first of a connection: a SYN-ACK
// and what follows), so that a new connection from port 49 is not accepted;
// udp has no such flag.
func authReplyStatements(prefix string, reply *authReply) string {
	if reply == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString(prefix + authReplyTerm + " from source-address " + reply.source + "\n")
	b.WriteString(prefix + authReplyTerm + " from protocol " + reply.proto + "\n")
	ports := reply.ports[0]
	if len(reply.ports) > 1 {
		ports = "[ " + strings.Join(reply.ports, " ") + " ]"
	}
	b.WriteString(prefix + authReplyTerm + " from source-port " + ports + "\n")
	if reply.proto == "tcp" {
		b.WriteString(prefix + authReplyTerm + " from tcp-established\n")
	}
	b.WriteString(prefix + authReplyTerm + " then accept\n")
	return b.String()
}

// strictHeader is the comment block above the strict filter: what the mode
// is, what stops once the filter is on lo0, and how to apply it.
func strictHeader(scope string) string {
	return "# Deny-by-default management filter (mgmt-acl mode strict; Junos only).\n" +
		"# The filter accepts every protocol from the sources of the mgmt-acl list (an entry with\n" +
		"# services keeps only those) and has no default-accept term: the implicit discard at the\n" +
		"# end of a Junos filter drops the rest.\n" +
		"# Once the filter is applied to lo0, these stop reaching the routing engine:\n" +
		"#   - routing protocols carried over IP from neighbours that are not in the list: BGP, OSPF, LDP, VRRP, BFD\n" +
		"#     (IS-IS is not carried over IP: a family inet filter on lo0 does not see it, so it is neither stopped nor permitted)\n" +
		"#   - replies from servers that are not in the list: TACACS+ and RADIUS (the replies of the server this\n" +
		"#     walkthrough names are accepted), NTP, DNS\n" +
		"#   - NTP, syslog and DHCP from hosts that are not in the list\n" +
		"#   - SNMP from sources outside the list (the SNMP clients of Step 5 still poll)\n" +
		"#   - every other protocol (ping, traceroute) from sources outside the list\n" +
		"# permit-mgmt starts with the address tacctl reaches the device from.\n" +
		"# Add each neighbour and server the device needs to the permit list this scope renders from first\n" +
		"# ('tacctl scope mgmt-acl " + scope + " list' says which): the first entry of the scope's own list replaces\n" +
		"# the global list for this scope, so add the global entries to it too.\n" +
		"# Keep a console session open while you apply it, and commit with 'commit confirmed'.\n" +
		"# These 'set firewall' lines define the filter in the candidate config.\n" +
		"# Activate it by uncommenting the 'set interfaces lo0 …' line below\n" +
		"# after reviewing.\n"
}

// authReplyNote is the comment of the term that accepts the replies of the
// authentication server: why it is a term of its own, what it matches and
// what it cannot tell (the filter is stateless). snmpTerms says the filter
// has the deny-snmp term, which comes before the term and decides udp port 161.
func authReplyNote(r *authReply, snmpTerms bool) string {
	if r == nil {
		return ""
	}
	a := strings.TrimSuffix(r.source, "/32")
	var b strings.Builder
	b.WriteString("#\n# " + authReplyTerm + ": " + a + " is the address the device authenticates against (--server, a RADIUS listener bound to\n" +
		"# another address, or the detected address when --source is another) and is not a source of permit-mgmt. The device\n" +
		"# starts those sessions, so the term accepts only the packets of the server's answers:\n")
	if r.proto == "tcp" {
		b.WriteString("#   - tcp from source port " + r.ports[0] + " that are not the first packet of a connection (tcp-established): a new connection\n" +
			"#     from " + a + ", even from that port, is not accepted. The filter keeps no state, so a packet of an\n" +
			"#     established connection from that port is accepted whatever its destination port.\n")
	} else {
		b.WriteString("#   - udp from source port " + strings.Join(r.ports, " and ") + ". The filter keeps no state and udp has no connection flag:\n" +
			"#     it cannot tell a reply from another udp packet sent from those ports.\n")
		if snmpTerms {
			b.WriteString("#     The permit-snmp and deny-snmp terms come first, so udp port 161 (SNMP) is decided by them.\n")
		} else {
			b.WriteString("#     The scope has no SNMP clients, so there is no deny-snmp term: udp port 161 from it is accepted too.\n")
		}
	}
	if len(r.entries) > 0 {
		b.WriteString("# The permit list holds " + strings.Join(r.entries, ", ") + " for this address: it is accepted for those services only")
		if r.ssh {
			b.WriteString(" (ssh among them)")
		}
		b.WriteString(",\n# and this term adds the answers above.\n")
	} else {
		b.WriteString("# Nothing is accepted from " + a + " beyond that. Add the address to the permit list this scope renders from to accept more.\n")
	}
	return b.String()
}

// strictNoSSH is the comment of the strict mode when the list has IPv4 entries
// and none of them permits ssh: what each permits, and why no filter is
// rendered.
func (d Data) strictNoSSH(scope string) string {
	var b strings.Builder
	for _, e := range d.mgmtEntries() {
		b.WriteString("# entry " + e.text + " permits " + e.why + " only\n")
	}
	return b.String() + "# no entry of the mgmt-acl list permits ssh (tcp/22): the strict filter would let only the tacctl server in,\n" +
		"# so none is rendered. Add an entry that permits ssh to the permit list this scope renders from\n" +
		"# ('tacctl scope mgmt-acl " + scope + " list' says which; the first entry of the scope's own list replaces the\n" +
		"# global list for this scope) to emit a deny-by-default lo0 firewall filter here (mgmt-acl mode strict)."
}

// strictEmpty is the comment of the strict mode when the list has no entry
// to build a filter from.
func strictEmpty() string {
	return "# mgmt-acl empty — configure with 'tacctl config mgmt-acl add <cidr>' on the tacctl server\n" +
		"# to emit a deny-by-default lo0 firewall filter here (mgmt-acl mode strict)."
}
