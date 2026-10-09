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
		Permits:    []string{"192.0.2.0/24", "198.51.100.0/25"},
		SNMPRanges: []string{"203.0.113.0/24", "10.8.0.0/16"}}
	b := WTIIPTables(in)
	nums, cmds := ruleLines(t, b.Rules)
	want := []string{
		"iptables -A INPUT -i lo -j ACCEPT",
		"iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
		"iptables -A INPUT -p tcp -s 10.0.0.42/32 --dport 22 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 10.0.0.42/32 --dport 443 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 192.0.2.0/24 --dport 22 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 192.0.2.0/24 --dport 443 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 198.51.100.0/25 --dport 22 -j ACCEPT",
		"iptables -A INPUT -p tcp -s 198.51.100.0/25 --dport 443 -j ACCEPT",
		"iptables -A INPUT -p udp -s 10.0.0.42/32 --dport 161 -j ACCEPT",
		"iptables -A INPUT -p udp -s 203.0.113.0/24 --dport 161 -j ACCEPT",
		"iptables -A INPUT -p udp -s 10.8.0.0/16 --dport 161 -j ACCEPT",
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
		in.Permits = append(in.Permits, "192.0.2."+strconv.Itoa(i*16)+"/28")
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
		if len(cmds) != 5 || !strings.Contains(cmds[2], "-s 10.0.0.42/32 --dport 22") || !strings.Contains(cmds[4], "-p udp -s 10.0.0.42/32 --dport 161") {
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
		Permits: []string{"192.0.2.7/32", "192.0.2.9", "fd00::/64", "bogus"}, SNMPRanges: []string{"fd00:1::/48"}})
	_, cmds := ruleLines(t, b.Rules)
	text := strings.Join(cmds, "\n")
	for _, want := range []string{"-s 192.0.2.7/32 --dport 22", "-s 192.0.2.9/32 --dport 443"} {
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
	b := WTIIPTables(IPTablesInput{Scope: "lab", Server: "10.0.0.42", Permits: []string{"192.0.2.0/24"}})
	for _, want := range []string{
		"'-m state --state ESTABLISHED,RELATED' in place of",
		"'-m conntrack --ctstate ESTABLISHED,RELATED'",
		"TACACS+,", "RADIUS, DNS and NTP queries",
		"Telnet and http are not", "'--dport 23' or '--dport 80'",
		"SNMP client restriction of Step 6",
		"Not verified on a unit.",
		"IPv4 only",
		"tacctl scope mgmt-acl lab list", "tacctl scope snmp lab clients list",
	} {
		if !strings.Contains(b.Rules, want) {
			t.Errorf("lacks %q:\n%s", want, b.Rules)
		}
	}
	for _, bad := range []string{"--dport 23 -j", "--dport 80 -j"} {
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
			// The DROP as a command exists only in Step 11, at most once, and
			// no step of the list is numbered after it.
			step11 := out[strings.Index(out, "\nStep 11:"):]
			before := out[:strings.Index(out, "\nStep 11:")]
			for _, l := range strings.Split(before, "\n") {
				if reRuleLine.MatchString(l) && strings.HasSuffix(l, "-j DROP") {
					t.Errorf("%s/%s: the list carries a DROP: %s", v.name, c.name, l)
				}
			}
			if n := strings.Count(step11, "iptables -A INPUT -j DROP"); n != 1 {
				t.Errorf("%s/%s: %d DROP lines in Step 11", v.name, c.name, n)
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
