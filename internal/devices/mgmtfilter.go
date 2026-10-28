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
// ssh-only filter. A service term is named after its service, not its
// position, so a list that gains an entry changes the terms it names and no
// other.

import (
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

// mgmtStrict are the permits of the strict filter: the sources of the
// permit-mgmt term (the IPv4 entries without services, headed by the server's
// /32 as mgmtPermits does: --source, else the detected address, and then, when
// it is another address, the /32 the device authenticates against: auth is
// --server, else the bound RADIUS address, else the detected one. The replies
// of the TACACS+ or RADIUS server come from it, and a filter that ends in the
// discard must accept them) and the
// service terms (the entries that have services, grouped by service in the
// order the canonical entry lists them). Nothing when the ACL has no IPv4
// entry, or none that permits ssh (a plain entry, or one with tcp/22): no
// block is rendered then, as in the ssh-only mode (mgmtPermits), because the
// server's address alone would be one that locks everybody else out. An entry whose network is already a
// source of permit-mgmt (the server's /32 or a plain entry of the same
// network) adds nothing: that source accepts everything.
func (d Data) mgmtStrict(auth string) (plain []string, terms []strictTerm) {
	var entries []mgmtacl.Entry
	for _, raw := range d.ACL.CIDRs {
		e, err := mgmtacl.ParseEntry(raw)
		if err != nil || e.IPv6() {
			continue
		}
		entries = append(entries, e)
	}
	if len(entries) == 0 || !slices.ContainsFunc(entries, mgmtacl.Entry.AllowsSSH) {
		return nil, nil
	}
	if srv := cidr.Host32(d.source()); srv != "" {
		plain = append(plain, srv)
	}
	if a := cidr.Host32(auth); a != "" && !slices.Contains(plain, a) {
		plain = append(plain, a)
	}
	for _, e := range entries {
		if e.Plain() && !slices.Contains(plain, e.Net) {
			plain = append(plain, e.Net)
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
	return plain, terms
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
	22: "ssh", 23: "telnet", 53: "domain", 69: "tftp", 80: "http", 123: "ntp", 161: "snmp", 162: "snmptrap",
	179: "bgp", 443: "https", 646: "ldp", 1812: "radius", 1813: "radacct",
}

// junosPort is a destination port as the statement writes it.
func junosPort(s mgmtacl.Service) string {
	if s.Lo == s.Hi {
		if n, ok := junosPortNames[s.Lo]; ok {
			return n
		}
		return strconv.Itoa(s.Lo)
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

// strictHeader is the comment block above the strict filter: what the mode
// is, what stops once the filter is on lo0, and how to apply it.
func strictHeader(scope string) string {
	return "# Deny-by-default management filter (mgmt-acl mode strict; Junos only).\n" +
		"# The filter accepts every protocol from the sources of the mgmt-acl list (an entry with\n" +
		"# services keeps only those) and has no default-accept term: the implicit discard at the\n" +
		"# end of a Junos filter drops the rest.\n" +
		"# Once the filter is applied to lo0, these stop reaching the routing engine:\n" +
		"#   - routing protocols from neighbours that are not in the list: BGP, OSPF, IS-IS, VRRP, LDP, BFD\n" +
		"#   - replies from servers that are not in the list: TACACS+ and RADIUS (the server this walkthrough\n" +
		"#     names is in it), NTP, DNS\n" +
		"#   - NTP, syslog and DHCP from hosts that are not in the list\n" +
		"#   - SNMP from sources outside the list (the SNMP clients of Step 5 still poll)\n" +
		"#   - every other protocol (ping, traceroute) from sources outside the list\n" +
		"# permit-mgmt starts with the address tacctl reaches the device from and, when it is another one\n" +
		"# (--server, a RADIUS listener bound to another address), the address the device authenticates against.\n" +
		"# Add each neighbour and server the device needs first ('tacctl scope mgmt-acl " + scope + " add <cidr>').\n" +
		"# Keep a console session open while you apply it, and commit with 'commit confirmed'.\n" +
		"# These 'set firewall' lines define the filter in the candidate config.\n" +
		"# Activate it by uncommenting the 'set interfaces lo0 …' line below\n" +
		"# after reviewing.\n"
}

// strictNoSSH is the comment of the strict mode when the list has IPv4 entries
// and none of them permits ssh: what each permits, and why no filter is
// rendered.
func (d Data) strictNoSSH() string {
	var b strings.Builder
	for _, e := range d.mgmtEntries() {
		b.WriteString("# entry " + e.text + " permits " + e.why + " only\n")
	}
	return b.String() + "# no entry of the mgmt-acl list permits ssh (tcp/22): the strict filter would let only the tacctl server in,\n" +
		"# so none is rendered. Configure with 'tacctl config mgmt-acl add <cidr>' on the tacctl server\n" +
		"# to emit a deny-by-default lo0 firewall filter here (mgmt-acl mode strict)."
}

// strictEmpty is the comment of the strict mode when the list has no entry
// to build a filter from.
func strictEmpty() string {
	return "# mgmt-acl empty — configure with 'tacctl config mgmt-acl add <cidr>' on the tacctl server\n" +
		"# to emit a deny-by-default lo0 firewall filter here (mgmt-acl mode strict)."
}
