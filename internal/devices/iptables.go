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
// is a comment when it would lock every other administrator out. Each of
// them carries its list twice: numbered, one line per entry of the unit's
// IP Tables page, and as the one <iptables> block the unit takes at that
// page's prompt (a lab unit, command menu 8.10: the paste replaces every
// entry, 256 characters per command, 48 entries in all).

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/ui"
)

// iptablesPorts are the unit's services the list opens to the permitted
// ranges: its ssh. Telnet (23), http (80) and https (443) are left out on
// purpose (web access is off, and the REST API is not used); the notes say
// how to add them by hand.
var iptablesPorts = []struct {
	Port int
	Name string
}{{22, "ssh"}}

// snmpUDPPort is the port of the unit's SNMP agent.
const snmpUDPPort = 161

// iptablesLimit is the number of entries the unit's IP Tables page holds
// (4 pages of 12, the RESTful API's `iptables` list too).
const iptablesLimit = 48

// iptablesLen is the longest command the unit takes ("256 char max per
// command", its own upload text).
const iptablesLen = 256

// iptablesTail is what the list of the last step adds to the rules: the
// final DROP, the unit's own traffic out, and the three policies, LAST (the
// order a lab unit took without cutting the pasting session off).
var iptablesTail = []string{
	"iptables -A INPUT -j DROP",
	"iptables -A OUTPUT -j ACCEPT",
	"iptables -P INPUT DROP",
	"iptables -P OUTPUT DROP",
	"iptables -P FORWARD DROP",
}

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
	// Commands are the commands of Rules, in order, as the <iptables> block
	// of Step 5 pastes them: no numbers, no comments, no DROP.
	Commands []string
	// Final is the whole list of the last step (Commands, then the DROP, the
	// OUTPUT ACCEPT and the three policies), as the block of that step pastes
	// it. It is empty when the DROP is not rendered.
	Final []string
	// Warning is set when a list would not fit the unit's 48 entries: how
	// many it holds and what to reduce. Nothing is cut from the text.
	Warning string
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
// loopback and the replies to the unit's own connections, ssh for
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
	var cmds []string
	rule := func(s string) {
		c := "iptables -A INPUT " + s + " -j ACCEPT"
		ls = append(ls, line{false, c})
		cmds = append(cmds, c)
	}
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
		note("the tacctl server " + server + ": ssh")
		tcp(server)
	} else {
		note("the tacctl server's address is not known: add its ssh and udp 161 lines by hand (or pass --source <address>)")
	}
	if len(permits) == 0 {
		who := ""
		if server != "" {
			who = ": only the tacctl server is permitted for ssh"
		}
		note("no management permit list for scope '" + in.Scope + "'" + who)
	}
	for _, n := range permits {
		note("permitted range " + n + ": ssh")
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
	// ICMP (ping), on the unit's own interface, from the networks above: the
	// server, the permits and the SNMP clients, each once. The unit's own
	// 'Ping Access' item is separate.
	var pingers []string
	seenPing := map[string]bool{}
	for _, n := range append(append([]string{server}, permits...), clients...) {
		if n != "" && !seenPing[n] {
			seenPing[n] = true
			pingers = append(pingers, n)
		}
	}
	if len(pingers) > 0 {
		note("ICMP (ping) from the same networks, on eth0")
	}
	for _, n := range pingers {
		rule("-i eth0 -s " + n + " -p icmp")
	}

	count := len(cmds)
	w := len(strconv.Itoa(count + 1)) // room for the DROP's number
	var b []string
	add := func(l ...string) {
		for _, x := range l {
			b = append(b, strings.TrimRight(pre+x, " "))
		}
	}
	add("Generated for scope '"+in.Scope+"'. Verified on a lab unit (8.10, 2026-10-12). It is the unit's whole IP Tables list, in the",
		"unit's order, from the scope's management permit list (tacctl scope mgmt-acl "+in.Scope+" list; the global",
		"tacctl config mgmt-acl list when the scope has none), the tacctl server's address and the scope's",
		"SNMP clients (tacctl scope snmp "+in.Scope+" clients list). Add one line per entry under /N, IP Tables,",
		"in this order. The number is the line's place in the list, not part of the command; a line that",
		"starts with # is a note for you. The final DROP is not in this list: it is the last step, below.",
		"")
	final := iptablesFinal(cmds)
	warning := iptablesWarning(in.Scope, count, len(final))
	if warning != "" {
		add(wrapText("WARNING: "+warning, 100)...)
		add("")
	}
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
		"The same rules in one paste, for the IP Tables prompt (/N, item 5): no comments, no DROP. The paste",
		"replaces every entry the unit holds, so read its list first ('>' and '<' page through it): what this",
		"list lacks is gone afterwards. The unit takes the block in one go (\"Configuring iptables - Please",
		"wait...\"), applies the rules at once and shows 'IP Tables: On' on the /N menu; any session that",
		"leaves a top-level menu saves the configuration, this paste included. The block is at the left",
		"margin on purpose: paste it as it is.",
		"")
	b = append(b, iptablesBlock(cmds)...)
	add("",
		"Notes on the list:",
		"  - Line 2: older builds take '-m state --state ESTABLISHED,RELATED' in place of",
		"    '-m conntrack --ctstate ESTABLISHED,RELATED'. It covers the replies of the unit's own TACACS+,",
		"    RADIUS, DNS and NTP queries.",
		"  - Only ssh (22) is permitted. Telnet, http and https are not: to allow one, add the same line with",
		"    '--dport 23', '--dport 80' or '--dport 443' for each address above, before the DROP.",
		"  - The udp "+strconv.Itoa(snmpUDPPort)+" lines are the SNMP client restriction of Step 6, unless the unit has an SNMP",
		"    access menu of its own (then enter the same clients there).",
		"  - ICMP (ping): the last lines accept it from the same networks, on eth0 only. The unit's own",
		"    'Ping Access' item (/N, item 30; Limited by default) is separate and not changed by this list.",
		"  - IPv4 only: the unit's 'iptables', not 'ip6tables'. An IPv6 entry of the lists is skipped, with a note.",
		"  - The unit holds "+strconv.Itoa(iptablesLimit)+" entries (12 to a page): this list has "+strconv.Itoa(count)+"; with the DROP, the",
		"    OUTPUT ACCEPT and the three policies of the last step, "+strconv.Itoa(len(final))+". A command is "+strconv.Itoa(iptablesLen)+" characters at most.")

	out := IPTablesBlock{Rules: strings.Join(b, "\n"), Lines: count, Commands: cmds, Warning: warning}
	if server == "" {
		out.Unfilled = []Unfilled{{"tacctl server address", "pass --source <address>"}}
	}
	out.Drop, out.DropRendered = in.drop(len(permits) > 0, server != "", count+1, w, cmds, warning)
	if out.DropRendered {
		out.Final = final
	}
	return out
}

// iptablesFinal is the list of the last step: the rules, then the tail.
func iptablesFinal(cmds []string) []string {
	return append(append([]string{}, cmds...), iptablesTail...)
}

// iptablesBlock is the <iptables> block the unit takes at its IP Tables
// prompt: the commands one per line, no comments, at the left margin.
func iptablesBlock(cmds []string) []string {
	return append(append([]string{"<iptables>"}, cmds...), "</iptables>")
}

// iptablesWarning says that a list would not fit the unit's page: the rules
// of Step 5 (rules entries) or the whole list of the last step (final
// entries); "" when both fit.
func iptablesWarning(scope string, rules, final int) string {
	limit := strconv.Itoa(iptablesLimit)
	fix := " Reduce the scope's management permit list (tacctl scope mgmt-acl " + scope + " list) or its SNMP clients" +
		" (tacctl scope snmp " + scope + " clients list), or use wider networks. Nothing is cut from the list below."
	switch {
	case rules > iptablesLimit:
		return "this list has " + strconv.Itoa(rules) + " entries; the unit holds " + limit + "." + fix
	case final > iptablesLimit:
		return "this list has " + strconv.Itoa(rules) + " entries and fits, but the list of the last step (the DROP, the OUTPUT" +
			" ACCEPT and the three policies added) has " + strconv.Itoa(final) + "; the unit holds " + limit + "." + fix
	}
	return ""
}

// wrapText breaks s at spaces into lines of at most width characters.
func wrapText(s string, width int) []string {
	var out []string
	line := ""
	for _, w := range strings.Fields(s) {
		if line != "" && len(line)+1+len(w) > width {
			out = append(out, line)
			line = w
			continue
		}
		if line != "" {
			line += " "
		}
		line += w
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// drop is the text of the last step: the DROP as a numbered paste when the
// list has a permit list and the tacctl server's address, else the DROP as a
// comment and why (an empty list would lock every other administrator out,
// and a list without the server would lock tacctl out).
func (in IPTablesInput) drop(hasPermits, hasServer bool, n, w int, cmds []string, warning string) (string, bool) {
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
		final := iptablesFinal(cmds)
		add("This line turns the list into a restriction, and it is the one that can lock you out. The",
			"walkthrough does not apply it: you paste it, last, yourself, once the steps above work.",
			"  a) Keep the serial session of Step 1 open (and a second session ready). It is the way back.",
			"  b) Add the DROP as the LAST line of the IP Tables list (after line "+strconv.Itoa(n-1)+"):",
			"       "+strings.Repeat(" ", w-len(num))+num+". iptables -A INPUT -j DROP",
			"     or paste the whole list again, with the DROP in it, in one go. The block below is the rules of",
			"     Step 5, then the DROP, the OUTPUT ACCEPT and the three policies, LAST (the order a lab unit",
			"     took without cutting the pasting session off). The paste replaces every entry, and the unit",
			"     applies it at once, so the test of c) runs with the DROP already in force.")
		if warning != "" {
			add("     WARNING: the block has "+strconv.Itoa(len(final))+" entries and the unit holds "+strconv.Itoa(iptablesLimit)+". Reduce the lists of",
				"     Step 5 first (see its warning) or use wider networks; nothing is cut from the block.")
		}
		add("")
		b = append(b, iptablesBlock(final)...)
		add("",
			"  c) Before saving, test a login from a permitted address (repeat Step 8, and from the tacctl",
			"     server: tacctl scope snmp "+in.Scope+" test <unit-address>). A login from an address",
			"     outside the list must now be refused.",
			"  d) Save only when the test works (any session that leaves a top-level menu saves the whole",
			"     configuration). If it fails, delete line "+num+" on the serial session first; after the paste of",
			"     the block, clear the three policies as well (below).",
			"The unit has no commit-confirm and no rollback: the way back is clearing the slots (<SPACE><CR> at a",
			"slot's prompt; after the paste of the block the DROP is entry "+num+" and the three policies are",
			"entries "+strconv.Itoa(n+2)+" to "+strconv.Itoa(n+4)+"), or pasting the block of Step 5 again, from the serial session.")
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

// iptablesWarning ends a walkthrough whose IP Tables list would not fit the
// unit: the same warning the step carries, so it is not missed.
func (o *out) iptablesWarning(t Template, b IPTablesBlock) {
	if b.Warning == "" || !strings.Contains(t.Text, "IPTABLES_BLOCK") {
		return
	}
	lines := wrapText("IP Tables list too long (Step 5): "+b.Warning, 100)
	o.heading(ui.Yellow, lines[0])
	for _, l := range lines[1:] {
		o.echo("  " + l)
	}
	o.echo("")
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
