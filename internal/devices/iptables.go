package devices

// The WTI IP Tables list of the walkthroughs (D42 of docs/plans/0.2.3-plan.md):
// the unit's firewall list for the device's scope, built from data tacctl
// already holds and nothing new: the scope's management permit list
// ('scope mgmt-acl', with its global fallback, as the Cisco VTY-ACL and the
// Junos filter read it), the tacctl server's own address (the address the
// unit must permit for tacctl's queries: --source, else the detected one,
// D43) and the scope's SNMP clients (D41). The builder reads nothing but
// its input: no terminal, no tacctl.yaml, no state files, no clock.
//
// Two texts come out of it: the rules (Step 5 of the walkthrough) and the
// final DROP (the last step), which the walkthrough never applies and which
// is a comment when it would lock every other administrator out.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
)

// iptablesPorts are the unit's services the list opens to the permitted
// ranges: its ssh and its https. Telnet (23) and http (80) are left out on
// purpose; the notes say how to add them by hand.
var iptablesPorts = []struct {
	Port int
	Name string
}{{22, "ssh"}, {443, "https"}}

// snmpUDPPort is the port of the unit's SNMP agent.
const snmpUDPPort = 161

// IPTablesInput is everything the IP Tables list is built from.
type IPTablesInput struct {
	// Scope is the scope the walkthrough is for.
	Scope string
	// Server is the address the unit must permit for tacctl's own queries
	// (--source, else the detected address); anything that is not an IPv4
	// address is "not known".
	Server string
	// Permits is the scope's effective management permit list, as the
	// Cisco and Junos blocks read it (the scope's own, else the global
	// one), in the order stored.
	Permits []string
	// SNMPRanges are the scope's SNMP clients (snmp_scope.<scope>.clients);
	// the server's /32 is the first client and not part of this list.
	SNMPRanges []string
}

// IPTablesBlock is the IP Tables part of a WTI walkthrough.
type IPTablesBlock struct {
	// Rules is the text of Step 5 below the caution: the numbered list.
	Rules string
	// Drop is the text of the last step: the numbered DROP, or the commented
	// one and the reason it is not rendered as a paste.
	Drop string
	// Lines is how many lines of the list Rules numbers (the DROP is the
	// next one).
	Lines int
	// DropRendered says that Drop carries the DROP as a paste.
	DropRendered bool
	// Unfilled is the value the list could not fill (the server's address).
	Unfilled []Unfilled
}

// iptablesInput is the IP Tables input for scope.
func (d Data) iptablesInput(scope string) IPTablesInput {
	return IPTablesInput{Scope: scope, Server: d.source(), Permits: d.ACL.CIDRs, SNMPRanges: d.SNMP.Ranges}
}

// iptablesNets splits a list of CIDRs into the IPv4 networks (canonical, no
// duplicates) and the entries that cannot be rendered, each with its reason.
func iptablesNets(list []string, skip string) (nets, skipped []string) {
	seen := map[string]bool{skip: skip != ""}
	for _, e := range list {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		n, err := cidr.Parse(e)
		switch {
		case err != nil:
			skipped = append(skipped, e+" (not a CIDR)")
		case n.IsIPv6():
			skipped = append(skipped, e+" (IPv6; the list is IPv4 only)")
		default:
			if s := n.String(); !seen[s] {
				seen[s] = true
				nets = append(nets, s)
			}
		}
	}
	return nets, skipped
}

// WTIIPTables builds the IP Tables list of the unit for the scope: the
// loopback and the replies to the unit's own connections, ssh and https for
// the tacctl server and each permitted range, udp 161 for the SNMP clients
// (the server first, then the scope's ranges in order). The final DROP is
// not part of it.
func WTIIPTables(in IPTablesInput) IPTablesBlock {
	const pre = "        "
	server := cidr.Host32(in.Server)
	permits, skippedPermits := iptablesNets(in.Permits, server)
	clients, skippedClients := iptablesNets(in.SNMPRanges, server)

	// The lines in the unit's order; a note has no number.
	type line struct {
		note bool
		text string
	}
	var ls []line
	rule := func(s string) { ls = append(ls, line{false, "iptables -A INPUT " + s + " -j ACCEPT"}) }
	note := func(s string) { ls = append(ls, line{true, "# " + s}) }

	note("the unit's own traffic: loopback, and the replies to its own connections")
	rule("-i lo")
	rule("-m conntrack --ctstate ESTABLISHED,RELATED")
	tcp := func(net string) {
		for _, p := range iptablesPorts {
			rule("-p tcp -s " + net + " --dport " + strconv.Itoa(p.Port))
		}
	}
	if server != "" {
		note("the tacctl server " + server + ": ssh and https")
		tcp(server)
	} else {
		note("the tacctl server's address is not known: add its ssh, https and udp 161 lines by hand (or pass --source <address>)")
	}
	if len(permits) == 0 {
		who := ""
		if server != "" {
			who = ": only the tacctl server is permitted for ssh and https"
		}
		note("no management permit list for scope '" + in.Scope + "'" + who)
	}
	for _, n := range permits {
		note("permitted range " + n + ": ssh and https")
		tcp(n)
	}
	for _, s := range skippedPermits {
		note("skipped, not rendered: " + s)
	}
	if server != "" || len(clients) > 0 {
		note("SNMP (udp " + strconv.Itoa(snmpUDPPort) + "): the tacctl server, then the scope's SNMP clients")
	}
	snmp := func(net string) { rule("-p udp -s " + net + " --dport " + strconv.Itoa(snmpUDPPort)) }
	if server != "" {
		snmp(server)
	}
	for _, n := range clients {
		snmp(n)
	}
	for _, s := range skippedClients {
		note("skipped, not rendered: SNMP client " + s)
	}

	count := 0
	for _, l := range ls {
		if !l.note {
			count++
		}
	}
	w := len(strconv.Itoa(count + 1)) // room for the DROP's number
	var b []string
	add := func(l ...string) {
		for _, x := range l {
			b = append(b, strings.TrimRight(pre+x, " "))
		}
	}
	add("Generated for scope '"+in.Scope+"'. Not verified on a unit. It is the unit's whole IP Tables list, in the",
		"unit's order, from the scope's management permit list (tacctl scope mgmt-acl "+in.Scope+" list; the global",
		"tacctl config mgmt-acl list when the scope has none), the tacctl server's address and the scope's",
		"SNMP clients (tacctl scope snmp "+in.Scope+" clients list). Add one line per entry under /N, IP Tables,",
		"in this order. The number is the line's place in the list, not part of the command; a line that",
		"starts with # is a note for you. The final DROP is not in this list: it is the last step, below.",
		"")
	n := 0
	for _, l := range ls {
		if l.note {
			add("  " + strings.Repeat(" ", w+2) + l.text)
			continue
		}
		n++
		num := strconv.Itoa(n) + "."
		add("  " + strings.Repeat(" ", w+1-len(num)) + num + " " + l.text)
	}
	add("",
		"Notes on the list:",
		"  - Line 2: older builds take '-m state --state ESTABLISHED,RELATED' in place of",
		"    '-m conntrack --ctstate ESTABLISHED,RELATED'. It covers the replies of the unit's own TACACS+,",
		"    RADIUS, DNS and NTP queries.",
		"  - Only ssh (22) and https (443) are permitted. Telnet and http are not: to allow them, add the same",
		"    line with '--dport 23' or '--dport 80' for each address above, before the DROP.",
		"  - The udp "+strconv.Itoa(snmpUDPPort)+" lines are the SNMP client restriction of Step 6, unless the unit has an SNMP",
		"    access menu of its own (then enter the same clients there).",
		"  - IPv4 only: the unit's 'iptables', not 'ip6tables'. An IPv6 entry of the lists is skipped, with a note.")

	out := IPTablesBlock{Rules: strings.Join(b, "\n"), Lines: count}
	if server == "" {
		out.Unfilled = []Unfilled{{"tacctl server address", "pass --source <address>"}}
	}
	out.Drop, out.DropRendered = in.drop(len(permits) > 0, server != "", count+1, w)
	return out
}

// drop is the text of the last step: the DROP as a numbered paste when the
// list has a permit list and the tacctl server's address, else the DROP as a
// comment and why (an empty list would lock every other administrator out,
// and a list without the server would lock tacctl out).
func (in IPTablesInput) drop(hasPermits, hasServer bool, n, w int) (string, bool) {
	const pre = "        "
	var b []string
	add := func(l ...string) {
		for _, x := range l {
			b = append(b, strings.TrimRight(pre+x, " "))
		}
	}
	num := strconv.Itoa(n)
	switch {
	case hasPermits && hasServer:
		add("This line turns the list into a restriction, and it is the one that can lock you out. The",
			"walkthrough does not apply it: you paste it, last, yourself, once the steps above work.",
			"  a) Keep the serial session of Step 1 open (and a second session ready). It is the way back.",
			"  b) Add the DROP as the LAST line of the IP Tables list (after line "+strconv.Itoa(n-1)+"):",
			"       "+strings.Repeat(" ", w-len(num))+num+". iptables -A INPUT -j DROP",
			"  c) Before saving, test a login from a permitted address (repeat Step 8, and from the tacctl",
			"     server: tacctl scope snmp "+in.Scope+" test <unit-address>). A login from an address",
			"     outside the list must now be refused.",
			"  d) Save only when the test works. If it fails, delete line "+num+" on the serial session first.",
			"Not verified on a unit: whether the unit applies a changed list on entry or on save. If on entry,",
			"the test above runs with the DROP already in force; the serial session is the way back.")
		return strings.Join(b, "\n"), true
	}
	add("# iptables -A INPUT -j DROP")
	if !hasPermits {
		add("NOT rendered as a paste: scope '"+in.Scope+"' has no management permit list (tacctl scope mgmt-acl "+in.Scope+" list,",
			"and the global tacctl config mgmt-acl list, give no IPv4 range), so the DROP would lock out every",
			"administrator but the tacctl server. Add the permitted ranges (tacctl scope mgmt-acl "+in.Scope+" add <cidr>),",
			"then run this command again.")
	}
	if !hasServer {
		add("NOT rendered as a paste: the tacctl server's address is not known, so the DROP would lock tacctl out.",
			"Run this command again with --source <address>.")
	}
	add("The walkthrough applies no DROP in any case; the list above is safe to paste without one.")
	return strings.Join(b, "\n"), false
}

// iptablesGaps are the values of the IP Tables list left unfilled, or none
// when the template (an operator's copy may lack the step) does not carry it.
func (t Template) iptablesGaps(b IPTablesBlock) []Unfilled {
	if !strings.Contains(t.Text, "IPTABLES_BLOCK") {
		return nil
	}
	return b.Unfilled
}

// mergeUnfilled joins gap lists, a value named by an earlier one not twice.
func mergeUnfilled(lists ...[]Unfilled) []Unfilled {
	var out []Unfilled
	seen := map[string]bool{}
	for _, l := range lists {
		for _, u := range l {
			if !seen[u.What] {
				seen[u.What] = true
				out = append(out, u)
			}
		}
	}
	return out
}
