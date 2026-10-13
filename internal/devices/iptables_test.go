package devices

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// iptablesCase is one input of the matrix the IP Tables list is built over.
type iptablesCase struct {
	name string
	in   IPTablesInput
}

func iptablesCases() []iptablesCase {
	base := IPTablesInput{Scope: "lab", Server: "10.0.0.42"}
	with := func(f func(*IPTablesInput)) IPTablesInput { in := base; f(&in); return in }
	return []iptablesCase{
		{"nolist", base},
		{"one", with(func(i *IPTablesInput) { i.Permits = []string{"192.0.2.0/24"} })},
		{"several", with(func(i *IPTablesInput) {
			i.Permits = []string{"192.0.2.0/24", "198.51.100.0/25", "10.0.0.0/8"}
		})},
		{"snmp", with(func(i *IPTablesInput) {
			i.Permits = []string{"192.0.2.0/24"}
			i.SNMPRanges = []string{"203.0.113.0/24", "198.51.100.7/32"}
		})},
		{"snmp-nolist", with(func(i *IPTablesInput) { i.SNMPRanges = []string{"203.0.113.0/24"} })},
		{"server-listed", with(func(i *IPTablesInput) {
			i.Permits = []string{"10.0.0.42/32", "192.0.2.0/24"}
			i.SNMPRanges = []string{"10.0.0.42/32", "203.0.113.0/24"}
		})},
		{"host", with(func(i *IPTablesInput) { i.Permits = []string{"192.0.2.7/32", "192.0.2.9"} })},
		{"v6", with(func(i *IPTablesInput) {
			i.Permits = []string{"fd00::/64", "192.0.2.0/24", "bogus"}
			i.SNMPRanges = []string{"fd00:1::/48"}
		})},
		{"only-v6", with(func(i *IPTablesInput) { i.Permits = []string{"fd00::/64"} })},
		{"unknown-server", with(func(i *IPTablesInput) { i.Server = UnknownServer; i.Permits = []string{"192.0.2.0/24"} })},
		{"unknown-server-nolist", with(func(i *IPTablesInput) { i.Server = UnknownServer })},
		// 0.2.7: entries with services (a plain entry is every protocol and port)
		{"services", with(func(i *IPTablesInput) {
			i.Permits = []string{"172.16.100.0/23:tcp/22,udp/161,udp/162", "10.0.0.0/8"}
		})},
		{"services-forms", with(func(i *IPTablesInput) {
			i.Permits = []string{"192.0.2.0/25:tcp/22", "192.0.2.128/25:tcp/*,udp/161-162", "198.51.100.0/24:tcp/22,tcp/443,icmp",
				"203.0.113.0/24:udp/*", "203.0.113.0/24:tcp/22-23"}
			i.SNMPRanges = []string{"198.51.100.0/24", "203.0.113.0/24", "192.0.2.64/26"}
		})},
		{"services-no-ssh", with(func(i *IPTablesInput) { i.Permits = []string{"192.0.2.0/24:udp/161,icmp"} })},
		{"services-server", with(func(i *IPTablesInput) {
			i.Permits = []string{"10.0.0.42/32:tcp/443,udp/161,icmp", "192.0.2.0/24:tcp/22"}
		})},
		{"plain-server", with(func(i *IPTablesInput) { i.Permits = []string{"10.0.0.42/32", "192.0.2.0/24:tcp/22"} })},
	}
}

// The step of each case, whole: the numbered list, then the last step.
func TestIPTablesBlockGoldens(t *testing.T) {
	for _, c := range iptablesCases() {
		b := WTIIPTables(c.in)
		text := b.Rules + "\n\n" + b.Drop + "\n"
		if line := UnfilledLine(b.Unfilled); line != "" {
			text += "\n" + line + "\n"
		}
		checkGolden(t, "iptables/block-"+c.name+".txt", text)
	}
}

var reRuleLine = regexp.MustCompile(`^\s+(\d+)\. (iptables .*)$`)

// ruleLines are the numbered lines of a text, with their numbers.
func ruleLines(t *testing.T, text string) (nums []int, cmds []string) {
	t.Helper()
	for _, l := range strings.Split(text, "\n") {
		if m := reRuleLine.FindStringSubmatch(l); m != nil {
			n, _ := strconv.Atoi(m[1])
			nums, cmds = append(nums, n), append(cmds, m[2])
		}
	}
	return nums, cmds
}

// The rules come in the unit's order, numbered from 1 without gaps, and
// the DROP is never one of them.
func TestIPTablesOrder(t *testing.T) {
	in := IPTablesInput{Scope: "lab", Server: "10.0.0.42",
		Permits:    []string{"192.0.2.0/24:tcp/22", "198.51.100.0/25:tcp/22"},
		SNMPRanges: []string{"203.0.113.0/24", "10.8.0.0/16"}}
	b := WTIIPTables(in)
	nums, cmds := ruleLines(t, b.Rules)
	want := []string{
		"iptables -A INPUT -i lo -j ACCEPT",
		"iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"iptables -A INPUT -p tcp -s 10.0.0.42/32 --dport 22 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 192.0.2.0/24 --dport 22 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 198.51.100.0/25 --dport 22 -j ACCEPT",
		"iptables -A INPUT -p udp -s 10.0.0.42/32 --dport 161 -j ACCEPT",
		"iptables -A INPUT -p udp -s 203.0.113.0/24 --dport 161 -j ACCEPT",
		"iptables -A INPUT -p udp -s 10.8.0.0/16 --dport 161 -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 10.0.0.42/32 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 192.0.2.0/24 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 198.51.100.0/25 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 203.0.113.0/24 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 10.8.0.0/16 -p icmp -j ACCEPT",
	}
	if strings.Join(cmds, "\n") != strings.Join(want, "\n") {
		t.Errorf("rules:\n%s\nwant:\n%s", strings.Join(cmds, "\n"), strings.Join(want, "\n"))
	}
	for i, n := range nums {
		if n != i+1 {
			t.Errorf("line %d is numbered %d", i+1, n)
		}
	}
	if b.Lines != len(want) {
		t.Errorf("Lines = %d", b.Lines)
	}
	if strings.Contains(b.Rules, "-j DROP") {
		t.Errorf("the list carries the DROP:\n%s", b.Rules)
	}
	// The DROP is the next number, in the last step, and nothing follows it.
	dn, dc := ruleLines(t, b.Drop)
	if len(dn) != 1 || dn[0] != len(want)+1 || dc[0] != "iptables -A INPUT -j DROP" || !b.DropRendered {
		t.Errorf("drop: %v %v\n%s", dn, dc, b.Drop)
	}
	if !strings.Contains(b.Drop, "does not apply it") || !strings.Contains(b.Drop, "serial session") ||
		!strings.Contains(b.Drop, "test a login from a permitted address") || !strings.Contains(b.Drop, "LAST line") {
		t.Errorf("the last step lacks its warnings:\n%s", b.Drop)
	}
}

// Numbers of two digits stay aligned and the DROP follows the last line.
func TestIPTablesLongList(t *testing.T) {
	in := IPTablesInput{Scope: "lab", Server: "10.0.0.42"}
	for i := 1; i <= 6; i++ {
		in.Permits = append(in.Permits, "192.0.2."+strconv.Itoa(i*16)+"/28:tcp/22")
	}
	b := WTIIPTables(in)
	nums, _ := ruleLines(t, b.Rules)
	if len(nums) != 17 || nums[16] != 17 {
		t.Fatalf("nums = %v", nums)
	}
	if dn, _ := ruleLines(t, b.Drop); len(dn) != 1 || dn[0] != 18 {
		t.Errorf("drop number %v", dn)
	}
	col := func(prefix string) int {
		for _, l := range strings.Split(b.Rules, "\n") {
			if strings.HasPrefix(strings.TrimLeft(l, " "), prefix) {
				return strings.Index(l, ". iptables")
			}
		}
		return -1
	}
	if c1, c17 := col("1. iptables"), col("17. iptables"); c1 < 0 || c1 != c17 {
		t.Errorf("alignment (%d, %d):\n%s", c1, c17, b.Rules)
	}
}

// A scope with no permit list: loopback, established and the server's rules,
// and a commented DROP with the reason.
func TestIPTablesLockoutGuard(t *testing.T) {
	for _, in := range []IPTablesInput{
		{Scope: "lab", Server: "10.0.0.42"},
		{Scope: "lab", Server: "10.0.0.42", Permits: []string{"fd00::/64", "bogus"}},
	} {
		b := WTIIPTables(in)
		_, cmds := ruleLines(t, b.Rules)
		if len(cmds) != 5 || !strings.Contains(cmds[2], "-s 10.0.0.42/32 --dport 22") || !strings.Contains(cmds[3], "-p udp -s 10.0.0.42/32 --dport 161") ||
			cmds[4] != "iptables -A INPUT -i eth0 -s 10.0.0.42/32 -p icmp -j ACCEPT" {
			t.Errorf("rules without a list: %v", cmds)
		}
		if b.DropRendered {
			t.Error("the DROP is rendered without a permit list")
		}
		if nums, _ := ruleLines(t, b.Drop); len(nums) != 0 {
			t.Errorf("a numbered paste in the guard:\n%s", b.Drop)
		}
		for _, want := range []string{"# iptables -A INPUT -j DROP\n", "NOT rendered as a paste", "lock out every", "scope mgmt-acl lab add <cidr>", "applies no DROP"} {
			if !strings.Contains(b.Drop, want) {
				t.Errorf("guard lacks %q:\n%s", want, b.Drop)
			}
		}
	}
	// No server address: the DROP would lock tacctl out, and the gap is named.
	b := WTIIPTables(IPTablesInput{Scope: "lab", Server: UnknownServer, Permits: []string{"192.0.2.0/24"}})
	if b.DropRendered || !strings.Contains(b.Drop, "lock tacctl out") || !strings.Contains(b.Drop, "--source <address>") {
		t.Errorf("unknown server:\n%s", b.Drop)
	}
	if UnfilledLine(b.Unfilled) != "Unfilled SNMP values: tacctl server address (pass --source <address>)" {
		t.Errorf("unfilled: %q", UnfilledLine(b.Unfilled))
	}
	if strings.Contains(b.Rules, "10.0.0.42") || strings.Contains(b.Rules, UnknownServer) {
		t.Errorf("the placeholder is a rule:\n%s", b.Rules)
	}
}

// A /32 renders as it is, a bare address as a /32, and IPv6 or junk is
// skipped with a note, never rendered.
func TestIPTablesAddresses(t *testing.T) {
	b := WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42",
		Permits: []string{"192.0.2.7/32:tcp/22", "192.0.2.9:tcp/22", "fd00::/64", "fd00::/64:tcp/22", "bogus"}, SNMPRanges: []string{"fd00:1::/48"}})
	_, cmds := ruleLines(t, b.Rules)
	text := strings.Join(cmds, "\n")
	for _, want := range []string{"-s 192.0.2.7/32 --dport 22", "-s 192.0.2.9/32 --dport 22"} {
		if !strings.Contains(text, want) {
			t.Errorf("lacks %q:\n%s", want, text)
		}
	}
	for _, bad := range []string{"fd00", "bogus", "/ ", "-s 192.0.2.9 "} {
		if strings.Contains(text, bad) {
			t.Errorf("rendered %q:\n%s", bad, text)
		}
	}
	for _, want := range []string{"# skipped, not rendered: fd00::/64 (IPv6; the list is IPv4 only)",
		"# skipped, not rendered: fd00::/64:tcp/22 (IPv6; the list is IPv4 only)",
		"# skipped, not rendered: bogus (not a CIDR)", "# skipped, not rendered: SNMP client fd00:1::/48"} {
		if !strings.Contains(b.Rules, want) {
			t.Errorf("lacks the note %q:\n%s", want, b.Rules)
		}
	}
	// The mask of every rendered source is a prefix length of 0..32.
	re := regexp.MustCompile(` -s (\d+\.\d+\.\d+\.\d+)/(\d+) `)
	for _, c := range cmds {
		if m := re.FindStringSubmatch(c); strings.Contains(c, " -s ") && (m == nil || len(m[2]) > 2) {
			t.Errorf("source without a prefix length: %s", c)
		}
	}
}

// The older-build note and the notes on ports, SNMP and IPv4 are in the list.
func TestIPTablesNotes(t *testing.T) {
	b := WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42"})
	for _, want := range []string{
		"Only ssh (22) is permitted. Telnet, http and https are not", "'--dport 23', '--dport 80' or '--dport 443'",
	} {
		if !strings.Contains(b.Rules, want) {
			t.Errorf("a list with no permits lacks %q:\n%s", want, b.Rules)
		}
	}
	// a permitted range with services: the entry says what it may reach
	b = WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42", Permits: []string{"192.0.2.0/24:tcp/22"}})
	flat := func(s string) string { return strings.Join(strings.Fields(s), " ") }
	for _, want := range []string{
		"A permitted range may reach what its entry lists: ssh (tcp/22) and the other services as written, or every protocol and port when the entry is plain.",
		"Telnet, http and https are not permitted unless an entry lists them (tacctl scope mgmt-acl lab add <cidr>:tcp/22,tcp/443) or is plain.",
	} {
		if !strings.Contains(flat(b.Rules), want) {
			t.Errorf("a list with services lacks %q:\n%s", want, b.Rules)
		}
	}
	for _, bad := range []string{"Plain entries permit", "Only ssh (22) is permitted", "has no ICMP line of its own"} {
		if strings.Contains(b.Rules, bad) {
			t.Errorf("a list with services only says %q:\n%s", bad, b.Rules)
		}
	}
	// a plain entry is named, with how to restrict it
	b = WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42", Permits: []string{"192.0.2.0/24:tcp/22", "10.0.0.0/8", "198.51.100.0/24"}})
	for _, want := range []string{
		"Plain entries permit every protocol and port from their source, the unit's telnet and web pages included:",
		"10.0.0.0/8, 198.51.100.0/24.",
		"Use <cidr>:tcp/22 to restrict one to ssh (<cidr>:tcp/22,udp/161 to add SNMP):",
		"has no ICMP line of its own in the last lines",
	} {
		if !strings.Contains(strings.Join(strings.Fields(b.Rules), " "), strings.Join(strings.Fields(want), " ")) {
			t.Errorf("a list with plain entries lacks %q:\n%s", want, b.Rules)
		}
	}
	b = WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42", Permits: []string{"192.0.2.0/24:tcp/22"}})
	for _, want := range []string{
		"'-m state --state ESTABLISHED,RELATED' in place of",
		"'-m conntrack --ctstate ESTABLISHED,RELATED'",
		"TACACS+,", "RADIUS, DNS and NTP queries",
		"SNMP client restriction of Step 6",
		"Verified on a lab unit (8.10, 2026-10-12).",
		"IPv4 only",
		"tacctl scope mgmt-acl lab list", "tacctl scope snmp lab clients list",
	} {
		if !strings.Contains(b.Rules, want) {
			t.Errorf("lacks %q:\n%s", want, b.Rules)
		}
	}
	for _, bad := range []string{"--dport 23 -j", "--dport 80 -j", "--dport 443 -j"} {
		if strings.Contains(b.Rules, bad) {
			t.Errorf("rendered %q", bad)
		}
	}
}

// The builder reads nothing but its input.
func TestIPTablesBuilderIsPure(t *testing.T) {
	for _, c := range iptablesCases() {
		a, b := WTIIPTables(c.in), WTIIPTables(c.in)
		if a.Rules != b.Rules || a.Drop != b.Drop || a.Lines != b.Lines {
			t.Errorf("%s differs between runs", c.name)
		}
	}
}

// The caution Step 5 had before the list is the list's introduction, word
// for word, in both walkthroughs.
func TestIPTablesKeepsStep5Caution(t *testing.T) {
	for _, c := range []struct {
		protocol string
		caution  string
	}{
		{TACACS, "Step 5: Check the unit's firewall (IP Tables under /N)\n" +
			"        If the IP Tables list sets 'iptables -P INPUT DROP' or ends in\n" +
			"        'iptables -A INPUT -j DROP', it must also accept loopback and replies\n" +
			"        to the unit's own connections, BEFORE the final DROP:\n" +
			"          iptables -A INPUT -i lo -j ACCEPT\n" +
			"          iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
			"        (older builds: -m state --state ESTABLISHED,RELATED). Without them the\n" +
			"        unit's TACACS+ SYN leaves but tacquito's SYN-ACK is dropped: every\n" +
			"        login waits out the Fallback Timer and tacquito logs nothing.\n"},
		{RADIUS, "Step 5: Check the unit's firewall (IP Tables under /N)\n" +
			"        If the IP Tables list sets 'iptables -P INPUT DROP' or ends in\n" +
			"        'iptables -A INPUT -j DROP', it must also accept loopback and the\n" +
			"        replies to the unit's own requests, BEFORE the final DROP:\n" +
			"          iptables -A INPUT -i lo -j ACCEPT\n" +
			"          iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n" +
			"        (older builds: -m state --state ESTABLISHED,RELATED). The server\n" +
			"        answers over UDP from 10.0.0.42 port 1812 (and 1813).\n" +
			"        Without the rule the unit's requests leave, the answers are dropped,\n" +
			"        and every login waits out the Fallback Timer while the server's auth\n" +
			"        log shows it answered.\n"},
	} {
		out := snmpRender(t, "wti", "lab", false, c.protocol, func(d *Data) { d.ACL.CIDRs = []string{"192.0.2.0/24"} })
		i := strings.Index(out, c.caution)
		if i < 0 {
			t.Fatalf("%s: the Step 5 caution is not kept:\n%s", c.protocol, out)
		}
		rest := out[i+len(c.caution):]
		if !strings.HasPrefix(rest, "\n        Generated for scope 'lab'.") {
			t.Errorf("%s: the list does not follow the caution:\n%.300s", c.protocol, rest)
		}
		if !strings.Contains(rest, "\nStep 6: SNMP") {
			t.Errorf("%s: Step 6 does not follow the list", c.protocol)
		}
	}
}

// Whole walkthroughs: the step order, the DROP only in the last step, and
// the goldens for the cases that matter.
func TestIPTablesWalkthroughs(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Data)
	}{
		{"nolist", func(d *Data) { d.SNMP = v2cAll }},
		{"one", func(d *Data) { d.SNMP = v2cAll; d.ACL.CIDRs = []string{"192.0.2.0/24"}; d.SNMP.Ranges = nil }},
		{"several", func(d *Data) {
			d.SNMP = v2cAll
			d.ACL.CIDRs = []string{"192.0.2.0/24", "198.51.100.0/25", "10.0.0.0/8"}
		}},
		{"noclients", func(d *Data) { d.SNMP = v2cAll; d.SNMP.Ranges = nil; d.ACL.CIDRs = []string{"192.0.2.0/24"} }},
		{"v6", func(d *Data) { d.ACL.CIDRs = []string{"fd00::/64", "192.0.2.0/24"} }},
		{"source", func(d *Data) {
			d.SNMP = v2cAll
			d.ACL.CIDRs = []string{"192.0.2.0/24"}
			d.AuthServer, d.SourceIP = "203.0.113.9", "198.51.100.77"
		}},
		{"unknown-server", func(d *Data) { d.ServerIP = UnknownServer; d.ACL.CIDRs = []string{"192.0.2.0/24"} }},
	}
	for _, v := range []variant{variants[5], variants[6]} {
		for _, c := range cases {
			out := snmpRender(t, "wti", "lab", false, v.protocol, c.mod)
			checkGolden(t, "iptables/full-"+v.name+"-"+c.name+".conf", out)

			// The steps are in order, and Step 11 is last.
			last := -1
			for _, s := range []string{"\nStep 5: ", "\nStep 6: SNMP", "\nStep 7: Save", "\nStep 8: Test", "\nStep 9: Only if Step 8 fails",
				"\nStep 10: Break-glass", "\nStep 11: The final DROP"} {
				i := strings.Index(out, s)
				if i <= last {
					t.Errorf("%s/%s: %q out of order", v.name, c.name, s)
				}
				last = i
			}
			// The DROP as a command exists only in Step 11: once as the
			// numbered line and once in the block (once as the comment of the
			// guard). Step 5 has no DROP, no OUTPUT ACCEPT and no policy.
			step11 := out[strings.Index(out, "\nStep 11:"):]
			before := out[:strings.Index(out, "\nStep 11:")]
			for _, l := range strings.Split(before, "\n") {
				cmd := strings.TrimSpace(l)
				if (reRuleLine.MatchString(l) && strings.HasSuffix(l, "-j DROP")) || cmd == "iptables -A INPUT -j DROP" ||
					strings.HasPrefix(cmd, "iptables -P ") || cmd == "iptables -A OUTPUT -j ACCEPT" {
					t.Errorf("%s/%s: Step 5 carries a command of the last step: %s", v.name, c.name, l)
				}
			}
			want := 2
			if strings.Contains(step11, "NOT rendered as a paste") {
				want = 1
			}
			if n := strings.Count(step11, "iptables -A INPUT -j DROP"); n != want {
				t.Errorf("%s/%s: %d DROP lines in Step 11, want %d", v.name, c.name, n, want)
			}
			// Step 6 no longer says the restriction is unverified-dependent.
			if strings.Contains(out, "depends on the IP Tables") {
				t.Errorf("%s/%s: stale SNMP text", v.name, c.name)
			}
		}
	}
}

// --server is where the unit authenticates; the permits and the udp 161
// lines name --source, else the detected address.
func TestIPTablesServerAndSource(t *testing.T) {
	for _, c := range []struct {
		name, want string
		mod        func(*Data)
	}{
		{"detected", "10.0.0.42", func(d *Data) {}},
		{"server", "10.0.0.42", func(d *Data) { d.AuthServer = "203.0.113.9" }},
		{"source", "198.51.100.77", func(d *Data) { d.SourceIP = "198.51.100.77" }},
		{"both", "198.51.100.77", func(d *Data) { d.AuthServer = "203.0.113.9"; d.SourceIP = "198.51.100.77" }},
	} {
		out := snmpRender(t, "wti", "lab", false, TACACS, func(d *Data) { d.ACL.CIDRs = []string{"192.0.2.0/24"}; c.mod(d) })
		var tcp, udp int
		for _, l := range strings.Split(out, "\n") {
			m := reRuleLine.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			if strings.Contains(m[2], "-s 203.0.113.9") {
				t.Errorf("%s: --server is permitted: %s", c.name, m[2])
			}
			if strings.Contains(m[2], "-s "+c.want+"/32 --dport 22 ") {
				tcp++
			}
			if strings.Contains(m[2], "-s "+c.want+"/32 --dport 161 ") {
				udp++
			}
		}
		if tcp != 1 || udp != 1 {
			t.Errorf("%s: server rules for %s: tcp %d, udp %d", c.name, c.want, tcp, udp)
		}
	}
}

// A template of the operator's without the variables renders as it did, and
// without the Unfilled line for them.
func TestIPTablesOperatorTemplateWithout(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "wti.template"), []byte("MINE ${SERVER_IP}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := snmpRender(t, "wti", "lab", false, TACACS, func(d *Data) { d.ServerIP = UnknownServer; d.TemplateDir = dir })
	if strings.Contains(out, "iptables -A INPUT -p") || strings.Contains(out, "Unfilled") {
		t.Errorf("operator template:\n%s", out)
	}
}

// pasteBlocks are the <iptables> blocks of a text: the commands between the
// delimiter lines, which stand at the left margin.
func pasteBlocks(t *testing.T, text string) [][]string {
	t.Helper()
	var out [][]string
	var cur []string
	in := false
	for _, l := range strings.Split(text, "\n") {
		switch {
		case l == "<iptables>":
			if in {
				t.Fatalf("a block inside a block:\n%s", text)
			}
			in, cur = true, nil
		case l == "</iptables>":
			if !in {
				t.Fatalf("a block end without a start:\n%s", text)
			}
			in = false
			out = append(out, cur)
		case in:
			cur = append(cur, l)
		}
	}
	if in {
		t.Fatalf("an unterminated block:\n%s", text)
	}
	return out
}

// The bulk block of Step 5 holds the numbered list's commands in the same
// order, and the block of the last step the same commands, the DROP, the
// OUTPUT ACCEPT and the three policies, last. No block has a comment, a blank
// line, a number or a command over the unit's 256 characters.
func TestIPTablesBulkBlocks(t *testing.T) {
	for _, c := range iptablesCases() {
		b := WTIIPTables(c.in)
		_, numbered := ruleLines(t, b.Rules)
		bl := pasteBlocks(t, b.Rules)
		if len(bl) != 1 || strings.Join(bl[0], "\n") != strings.Join(numbered, "\n") {
			t.Errorf("%s: the block of Step 5 differs from the numbered list:\n%v\n%v", c.name, bl, numbered)
		}
		if strings.Join(b.Commands, "\n") != strings.Join(numbered, "\n") {
			t.Errorf("%s: Commands differ from the numbered list", c.name)
		}
		fb := pasteBlocks(t, b.Drop)
		if !b.DropRendered {
			if len(fb) != 0 || len(b.Final) != 0 {
				t.Errorf("%s: a block in the guard:\n%s", c.name, b.Drop)
			}
			continue
		}
		if len(fb) != 1 {
			t.Fatalf("%s: %d blocks in the last step", c.name, len(fb))
		}
		want := append(append([]string{}, numbered...), iptablesTail...)
		if strings.Join(fb[0], "\n") != strings.Join(want, "\n") || strings.Join(b.Final, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s: the final block:\n%v\nwant:\n%v", c.name, fb[0], want)
		}
		tail := fb[0][len(fb[0])-5:]
		if tail[0] != "iptables -A INPUT -j DROP" || tail[1] != "iptables -A OUTPUT -j ACCEPT" ||
			tail[2] != "iptables -P INPUT DROP" || tail[3] != "iptables -P OUTPUT DROP" || tail[4] != "iptables -P FORWARD DROP" {
			t.Errorf("%s: the final block does not end with the policies: %v", c.name, tail)
		}
		for _, blk := range append(bl, fb...) {
			for _, cmd := range blk {
				switch {
				case len(cmd) > iptablesLen:
					t.Errorf("%s: %d characters: %s", c.name, len(cmd), cmd)
				case !strings.HasPrefix(cmd, "iptables "):
					t.Errorf("%s: not a command in a block: %q", c.name, cmd)
				case strings.ContainsAny(cmd, "#\r\t") || cmd != strings.TrimSpace(cmd):
					t.Errorf("%s: comment or whitespace in a block: %q", c.name, cmd)
				}
			}
		}
	}
}

// The same holds in a whole walkthrough, whichever protocol, and the block
// of Step 5 has neither the DROP nor a policy.
func TestIPTablesBulkBlocksInWalkthroughs(t *testing.T) {
	for _, v := range []variant{variants[5], variants[6]} {
		out := snmpRender(t, "wti", "lab", false, v.protocol, func(d *Data) {
			d.SNMP = v2cAll
			d.ACL.CIDRs = []string{"192.0.2.0/24", "198.51.100.0/25"}
		})
		bl := pasteBlocks(t, out)
		if len(bl) != 2 {
			t.Fatalf("%s: %d blocks", v.name, len(bl))
		}
		if i, j := strings.Index(out, "<iptables>"), strings.Index(out, "\nStep 11:"); i < 0 || i > j {
			t.Errorf("%s: the first block is not before Step 11", v.name)
		}
		_, numbered := ruleLines(t, out)
		// The numbered lines are Step 5's, then the DROP of Step 11.
		if len(numbered) != len(bl[0])+1 || numbered[len(numbered)-1] != "iptables -A INPUT -j DROP" {
			t.Errorf("%s: %d numbered, %d in the block", v.name, len(numbered), len(bl[0]))
		}
		for _, cmd := range bl[0] {
			if strings.Contains(cmd, "-j DROP") || strings.Contains(cmd, "iptables -P") || strings.HasPrefix(cmd, "iptables -A OUTPUT") {
				t.Errorf("%s: %q in the block of Step 5", v.name, cmd)
			}
		}
		if len(bl[1]) != len(bl[0])+5 || bl[1][len(bl[1])-1] != "iptables -P FORWARD DROP" {
			t.Errorf("%s: the block of Step 11 has %d lines", v.name, len(bl[1]))
		}
	}
}

// ICMP: after the SNMP lines and before any DROP, one line per network of the
// server, the permits and the SNMP clients, each once, IPv4 only.
func TestIPTablesICMP(t *testing.T) {
	b := WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42",
		Permits:    []string{"192.0.2.0/24:tcp/22", "10.0.0.42/32:tcp/22", "fd00::/64", "192.0.2.0/24:tcp/22"},
		SNMPRanges: []string{"192.0.2.0/24", "203.0.113.0/24", "fd00:1::/48", "203.0.113.5", "203.0.113.5/32"}})
	var icmp []string
	last := -1
	for i, c := range b.Commands {
		if strings.Contains(c, "-p icmp") {
			icmp = append(icmp, c)
			if last >= 0 && i != last+1 {
				t.Errorf("the ICMP lines are not together: %v", b.Commands)
			}
			last = i
		}
	}
	want := []string{
		"iptables -A INPUT -i eth0 -s 10.0.0.42/32 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 192.0.2.0/24 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 203.0.113.0/24 -p icmp -j ACCEPT",
		"iptables -A INPUT -i eth0 -s 203.0.113.5/32 -p icmp -j ACCEPT",
	}
	if strings.Join(icmp, "\n") != strings.Join(want, "\n") {
		t.Errorf("icmp:\n%s\nwant:\n%s", strings.Join(icmp, "\n"), strings.Join(want, "\n"))
	}
	if last != len(b.Commands)-1 || !strings.Contains(b.Commands[last-len(icmp)], "--dport 161") {
		t.Errorf("the ICMP lines do not follow the SNMP lines:\n%v", b.Commands)
	}
	for _, want := range []string{"# ICMP (ping) from the same networks, on eth0", "'Ping Access' item (/N, item 30; Limited by default) is separate"} {
		if !strings.Contains(b.Rules, want) {
			t.Errorf("lacks %q", want)
		}
	}
	// Without the server's address and without lists there is nobody to ping from.
	b = WTIIPTables(IPTablesInput{Scope: "lab", Server: UnknownServer})
	if strings.Contains(b.Rules, "icmp") {
		t.Errorf("ICMP without a source:\n%s", b.Rules)
	}
}

// The unit holds 48 entries: a list over it, or a final list over it, says so
// in its step and in Warning, and nothing is cut.
func TestIPTablesEntryLimit(t *testing.T) {
	permits := func(n int) []string {
		var p []string
		for i := 1; i <= n; i++ {
			p = append(p, "192.0.2."+strconv.Itoa(i)+"/32:tcp/22")
		}
		return p
	}
	// Rules: 2 (lo, conntrack) + 1 (server ssh) + 1/permit ssh + 1 (SNMP) + (permits + 1) ICMP = 2*P + 5;
	// the last step's list adds the DROP, the OUTPUT ACCEPT and three policies.
	for _, c := range []struct {
		permits       int
		lines, final  int
		warn, inFinal string
	}{
		{10, 25, 30, "", ""},
		{20, 45, 50, "this list has 45 entries and fits, but the list of the last step", "the block has 50 entries"},
		{22, 49, 54, "this list has 49 entries; the unit holds 48.", "the block has 54 entries"},
	} {
		b := WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42", Permits: permits(c.permits)})
		if b.Lines != c.lines || len(b.Commands) != c.lines {
			t.Fatalf("%d permits: %d lines", c.permits, b.Lines)
		}
		if c.warn == "" {
			if b.Warning != "" || strings.Contains(b.Rules, "WARNING") || strings.Contains(b.Drop, "WARNING") {
				t.Errorf("a warning for %d entries:\n%s", c.lines, b.Warning)
			}
			continue
		}
		if !strings.Contains(b.Warning, c.warn) || !strings.Contains(b.Warning, "the unit holds 48") ||
			!strings.Contains(b.Warning, "tacctl scope mgmt-acl lab list") {
			t.Errorf("%d permits: warning %q", c.permits, b.Warning)
		}
		if !strings.Contains(b.Rules, "WARNING: this list has") && !strings.Contains(b.Rules, "WARNING: "+b.Warning[:20]) {
			t.Errorf("%d permits: Step 5 lacks the warning:\n%.600s", c.permits, b.Rules)
		}
		if !strings.Contains(b.Drop, c.inFinal) {
			t.Errorf("%d permits: the last step lacks %q:\n%s", c.permits, c.inFinal, b.Drop)
		}
		if len(b.Final) != c.final || len(pasteBlocks(t, b.Rules)[0]) != c.lines {
			t.Errorf("%d permits: truncated (%d, %d)", c.permits, len(b.Final), len(pasteBlocks(t, b.Rules)[0]))
		}
	}
}

// The walkthrough ends with the warning when the list does not fit.
func TestIPTablesEntryLimitWalkthrough(t *testing.T) {
	var many []string
	for i := 1; i <= 22; i++ {
		many = append(many, "198.51.100."+strconv.Itoa(i)+"/32:tcp/22")
	}
	out := snmpRender(t, "wti", "lab", false, TACACS, func(d *Data) { d.ACL.CIDRs = many })
	if !strings.Contains(out, "IP Tables list too long (Step 5): this list has 49 entries; the unit holds 48.") {
		t.Errorf("no closing warning:\n%s", out[len(out)-900:])
	}
	ok := snmpRender(t, "wti", "lab", false, TACACS, func(d *Data) { d.ACL.CIDRs = []string{"192.0.2.0/24"} })
	if strings.Contains(ok, "too long") {
		t.Error("a warning for a list that fits")
	}
}
