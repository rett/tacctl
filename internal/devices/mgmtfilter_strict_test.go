package devices

// The strict (deny-by-default) mode of the Junos management filter
// (mgmtfilter.go): the rendering against goldens, what it keeps of the
// entries, and that the ssh-only filter is what it always was.

import (
	"slices"
	"strings"
	"testing"
)

func strictData(t *testing.T, server, source string, cidrs []string, snmp SNMPInput) Data {
	t.Helper()
	d := mgmtData(t, server, source, cidrs, snmp)
	d.ACL.Mode = MgmtModeStrict
	return d
}

func mgmtBlock(d Data) string {
	return JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)["MGMT_ACL_BLOCK"]
}

// The strict filter against goldens: plain entries and the server first, the
// SNMP clients' terms, entries with services, an empty list, and the same
// lists in the ssh-only mode beside them.
func TestStrictFilterGoldens(t *testing.T) {
	v2c := SNMPInput{Version: "v2c", Community: "example-ro", Ranges: []string{"198.51.100.0/24"}}
	lists := map[string][]string{
		"plain":    {"10.0.0.0/8", "10.1.0.0/16"},
		"nossh":    {"198.51.100.0/24:udp/161", "203.0.113.0/24:icmp"},
		"services": {"10.0.0.0/8", "198.51.100.0/24:tcp/22,udp/161-162", "203.0.113.0/24:tcp/22,icmp", "192.0.2.64/26:tcp/*,udp/123", "2001:db8::/64"},
	}
	for _, c := range []struct {
		name   string
		list   []string
		snmp   SNMPInput
		strict bool
	}{
		{"strict.plain", lists["plain"], SNMPInput{}, true},
		{"strict.snmp", lists["plain"], v2c, true},
		{"strict.services", lists["services"], SNMPInput{}, true},
		{"strict.services-snmp", lists["services"], v2c, true},
		{"strict.empty", nil, SNMPInput{}, true},
		{"strict.no-ssh", lists["nossh"], SNMPInput{}, true},
		{"sshonly.no-ssh", lists["nossh"], SNMPInput{}, false},
		{"sshonly.services-snmp", lists["services"], v2c, false},
	} {
		d := mgmtData(t, "192.0.2.1", "", c.list, c.snmp)
		if c.strict {
			d.ACL.Mode = MgmtModeStrict
		}
		golden(t, "mgmtfilter."+c.name+".txt", mgmtBlock(d)+"\n")
	}
}

// The device authenticates against authIP (--server, else the bound RADIUS
// address, else the detected one), and the replies of that server reach lo0
// from it. The strict filter, which ends in the discard, accepts them in a
// term of their own, permit-auth-replies, and not as a source of permit-mgmt:
// the device starts those sessions, so the address is accepted for the replies
// of the walkthrough's protocol only, never for ssh. The term is rendered once,
// for TACACS+ and for RADIUS (the listener's ports), and not when the address
// is a source of permit-mgmt already.
func TestStrictFilterAcceptsTheAuthenticationServerRepliesOnly(t *testing.T) {
	const f = "set firewall family inet filter MGMT-ACL term "
	sources := func(block, term string) []string {
		var out []string
		for _, l := range strings.Split(block, "\n") {
			if s, ok := strings.CutPrefix(l, f+term+" from source-address "); ok {
				out = append(out, s)
			}
		}
		return out
	}
	term := func(block string) string {
		var out []string
		for _, l := range strings.Split(block, "\n") {
			if strings.HasPrefix(l, f+"permit-auth-replies ") {
				out = append(out, strings.TrimPrefix(l, f+"permit-auth-replies "))
			}
		}
		return strings.Join(out, "\n")
	}
	list := []string{"10.0.0.0/8"}

	// --server differs from the detected address and from --source: it is no
	// source of permit-mgmt, and its replies (TACACS+: tcp from port 49) have
	// a term, after permit-mgmt
	d := strictData(t, "192.0.2.1", "192.0.2.5", list, SNMPInput{})
	d.AuthServer = "198.51.100.9"
	block := mgmtBlock(d)
	if got := sources(block, "permit-mgmt"); !slices.Equal(got, []string{"192.0.2.5/32", "10.0.0.0/8"}) {
		t.Errorf("--server: permit-mgmt %q\n%s", got, block)
	}
	if got, want := term(block), "from source-address 198.51.100.9/32\nfrom protocol tcp\nfrom source-port tacacs\nthen accept"; got != want {
		t.Errorf("--server: the replies term:\n%s\nwant\n%s", got, want)
	}
	if strings.Index(block, "permit-mgmt then accept") > strings.Index(block, "permit-auth-replies from source-address") {
		t.Errorf("the replies term is not after permit-mgmt:\n%s", block)
	}
	golden(t, "mgmtfilter.strict.server.txt", block+"\n")
	// the walkthrough names that server, and the filter accepts its replies
	if tac := JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)["TACPLUS_CONFIG"]; !strings.Contains(tac, "set system tacplus-server 198.51.100.9 ") {
		t.Errorf("the walkthrough does not authenticate against --server:\n%s", tac)
	}

	// the address is the detected one, or the source (the first source of
	// permit-mgmt), or a plain entry of the list: no term, and still once
	for _, c := range []struct{ server, source, auth string }{{"192.0.2.1", "", ""}, {"192.0.2.1", "192.0.2.5", "192.0.2.5"}, {"192.0.2.1", "", "192.0.2.1"}} {
		d := strictData(t, c.server, c.source, list, SNMPInput{})
		d.AuthServer = c.auth
		block := mgmtBlock(d)
		want := cidrOf(firstNonEmpty(c.source, c.server))
		if got := sources(block, "permit-mgmt"); len(got) != 2 || got[0] != want || got[1] != "10.0.0.0/8" || term(block) != "" {
			t.Errorf("%+v: %q, replies term %q", c, got, term(block))
		}
	}
	d = strictData(t, "192.0.2.1", "", []string{"10.0.0.0/8", "198.51.100.9/32"}, SNMPInput{})
	d.AuthServer = "198.51.100.9"
	if got, block := sources(mgmtBlock(d), "permit-mgmt"), mgmtBlock(d); !slices.Equal(got, []string{"192.0.2.1/32", "10.0.0.0/8", "198.51.100.9/32"}) || term(block) != "" {
		t.Errorf("listed: %q, replies term %q", got, term(block))
	}
	// the address is an entry with services: it is no source of permit-mgmt,
	// so its replies keep their term (and the entry its own)
	d = strictData(t, "192.0.2.1", "", []string{"10.0.0.0/8", "198.51.100.9/32:tcp/22"}, SNMPInput{})
	d.AuthServer = "198.51.100.9"
	if block := mgmtBlock(d); !slices.Equal(sources(block, "permit-auth-replies"), []string{"198.51.100.9/32"}) || !slices.Equal(sources(block, "permit-tcp-22"), []string{"198.51.100.9/32"}) {
		t.Errorf("services entry:\n%s", block)
	}

	// a RADIUS listener bound to another address is the one authenticated
	// against: its replies are udp from the listener's two ports
	d = strictData(t, "192.0.2.1", "", list, SNMPInput{})
	d.Radius = &Radius{AuthPort: "1812", AcctPort: "1813", Secret: "example-secret", ServerAddr: "203.0.113.7", VendorSent: "scope"}
	radius := JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: RADIUS}, d)
	if got := sources(radius["MGMT_ACL_BLOCK"], "permit-mgmt"); !slices.Equal(got, []string{"192.0.2.1/32", "10.0.0.0/8"}) {
		t.Errorf("bound RADIUS address: permit-mgmt %q\n%s", got, radius["MGMT_ACL_BLOCK"])
	}
	if got, want := term(radius["MGMT_ACL_BLOCK"]), "from source-address 203.0.113.7/32\nfrom protocol udp\nfrom source-port [ radius radacct ]\nthen accept"; got != want {
		t.Errorf("bound RADIUS address: the replies term:\n%s\nwant\n%s", got, want)
	}
	if !strings.Contains(radius["RADIUS_CONFIG"], "set system radius-server 203.0.113.7 ") {
		t.Errorf("the walkthrough does not authenticate against the bound address:\n%s", radius["RADIUS_CONFIG"])
	}
	golden(t, "mgmtfilter.strict.radius-bound.txt", radius["MGMT_ACL_BLOCK"]+"\n")
	// a listener on other ports: the ports of the walkthrough, by number
	d.Radius.AuthPort, d.Radius.AcctPort = "11812", "11813"
	if got, want := term(JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: RADIUS}, d)["MGMT_ACL_BLOCK"]), "from source-address 203.0.113.7/32\nfrom protocol udp\nfrom source-port [ 11812 11813 ]\nthen accept"; got != want {
		t.Errorf("other ports:\n%s", got)
	}
	d.Radius.AuthPort, d.Radius.AcctPort = "1812", "1813"
	// --server wins over the bound address, as in the walkthrough
	d.AuthServer = "198.51.100.9"
	radius = JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: RADIUS}, d)
	if got := sources(radius["MGMT_ACL_BLOCK"], "permit-auth-replies"); !slices.Equal(got, []string{"198.51.100.9/32"}) {
		t.Errorf("--server over the bound address: %q", got)
	}
	// ssh-only is untouched: it never named the server's addresses but the
	// first, and has no replies term
	d.ACL.Mode = ""
	if blk := JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: RADIUS}, d)["MGMT_ACL_BLOCK"]; !slices.Equal(sources(blk, "permit-mgmt"), []string{"192.0.2.1/32", "10.0.0.0/8"}) || strings.Contains(blk, "permit-auth-replies") {
		t.Errorf("ssh-only:\n%s", blk)
	}
}

func cidrOf(addr string) string { return addr + "/32" }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ssh-only is the mode of "", of "ssh-only" and of any word that is not
// strict, and renders what it always did.
func TestSSHOnlyModeIsTheDefault(t *testing.T) {
	list := []string{"10.0.0.0/8", "198.51.100.0/24:udp/161"}
	base := mgmtBlock(mgmtData(t, "192.0.2.1", "", list, SNMPInput{}))
	for _, mode := range []string{"", MgmtModeSSHOnly, "other"} {
		d := mgmtData(t, "192.0.2.1", "", list, SNMPInput{})
		d.ACL.Mode = mode
		if got := mgmtBlock(d); got != base {
			t.Errorf("mode %q differs from the default:\n%s\n%s", mode, got, base)
		}
	}
	if !strings.Contains(base, "default-accept then accept") || !strings.Contains(base, "term deny-mgmt then discard") {
		t.Errorf("the ssh-only filter lost its terms:\n%s", base)
	}
}

// What the strict filter says of the entries: permit-mgmt takes the plain
// ones with the server first and once, a service term takes the entries that
// name it, there is no default-accept and no deny-mgmt, the lo0 application
// stays a comment, and the comment says what stops.
func TestStrictFilterShape(t *testing.T) {
	list := []string{"10.0.0.0/8", "192.0.2.1/32:tcp/22", "198.51.100.0/24:tcp/22,udp/161", "203.0.113.0/24:tcp/22,icmp", "2001:db8::/64"}
	got := mgmtBlock(strictData(t, "192.0.2.1", "", list, SNMPInput{}))
	f := "set firewall family inet filter MGMT-ACL term "
	var live []string
	for _, l := range strings.Split(got, "\n") {
		if strings.HasPrefix(l, "set ") {
			live = append(live, l)
		}
	}
	want := []string{
		f + "permit-mgmt from source-address 192.0.2.1/32",
		f + "permit-mgmt from source-address 10.0.0.0/8",
		f + "permit-mgmt then accept",
		f + "permit-tcp-22 from source-address 198.51.100.0/24",
		f + "permit-tcp-22 from source-address 203.0.113.0/24",
		f + "permit-tcp-22 from protocol tcp",
		f + "permit-tcp-22 from destination-port ssh",
		f + "permit-tcp-22 then accept",
		f + "permit-udp-161 from source-address 198.51.100.0/24",
		f + "permit-udp-161 from protocol udp",
		f + "permit-udp-161 from destination-port snmp",
		f + "permit-udp-161 then accept",
		f + "permit-icmp from source-address 203.0.113.0/24",
		f + "permit-icmp from protocol icmp",
		f + "permit-icmp then accept",
	}
	if !slices.Equal(live, want) {
		t.Errorf("statements:\n%s\nwant:\n%s", strings.Join(live, "\n"), strings.Join(want, "\n"))
	}
	for _, no := range []string{"default-accept", "deny-mgmt", "2001:db8"} {
		if strings.Contains(strings.Join(live, "\n"), no) {
			t.Errorf("the strict filter holds %q:\n%s", no, got)
		}
	}
	if !strings.Contains(got, "\n# set interfaces lo0 unit 0 family inet filter input MGMT-ACL") || strings.Contains(got, "\nset interfaces") {
		t.Errorf("the lo0 application is not a comment:\n%s", got)
	}
	for _, say := range []string{"BGP, OSPF, IS-IS, VRRP, LDP, BFD", "(the SNMP clients of Step 5 still poll)", "TACACS+ and RADIUS (the server this walkthrough", "NTP, syslog and DHCP", "SNMP from sources outside the list",
		"Keep a console session open", "commit confirmed"} {
		if !strings.Contains(got, say) {
			t.Errorf("the comment does not say %q:\n%s", say, got)
		}
	}
}

// An unknown server leaves permit-mgmt to the plain entries; no plain entry
// leaves no permit-mgmt term; a list that has no IPv4 entry renders no filter.
func TestStrictFilterWithoutAServerOrPlainEntries(t *testing.T) {
	got := mgmtBlock(strictData(t, UnknownServer, "", []string{"10.0.0.0/8"}, SNMPInput{}))
	if strings.Count(got, "permit-mgmt from source-address") != 1 || !strings.Contains(got, "permit-mgmt from source-address 10.0.0.0/8\n") {
		t.Errorf("no server:\n%s", got)
	}
	got = mgmtBlock(strictData(t, "192.0.2.1", "", []string{"198.51.100.0/24:tcp/22"}, SNMPInput{}))
	if !strings.Contains(got, "permit-mgmt from source-address 192.0.2.1/32\n") || !strings.Contains(got, "permit-tcp-22 from source-address 198.51.100.0/24\n") {
		t.Errorf("services only:\n%s", got)
	}
	// a list none of whose entries permits ssh renders no filter, as in ssh-only:
	// the server's address alone would lock everybody else out
	for _, list := range [][]string{{"198.51.100.0/24:udp/161"}, {"198.51.100.0/24:udp/161", "203.0.113.0/24:icmp,tcp/443"}} {
		got = mgmtBlock(strictData(t, "192.0.2.1", "", list, SNMPInput{}))
		if strings.Contains(got, "\nset ") || strings.HasPrefix(got, "set ") || !strings.Contains(got, "no entry of the mgmt-acl list permits ssh (tcp/22)") ||
			!strings.Contains(got, "# entry 198.51.100.0/24:udp/161 permits udp/161 only") {
			t.Errorf("no ssh in %v:\n%s", list, got)
		}
	}
	// one entry with tcp/22 is enough to render it, and the others stay
	got = mgmtBlock(strictData(t, "192.0.2.1", "", []string{"198.51.100.0/24:udp/161", "203.0.113.0/24:tcp/22"}, SNMPInput{}))
	if !strings.Contains(got, "permit-tcp-22 from source-address 203.0.113.0/24\n") || !strings.Contains(got, "permit-udp-161 from source-address 198.51.100.0/24\n") ||
		strings.Contains(got, "no entry of the mgmt-acl list permits ssh") {
		t.Errorf("one entry with tcp/22:\n%s", got)
	}
	got = mgmtBlock(strictData(t, "192.0.2.1", "", []string{"2001:db8::/64"}, SNMPInput{}))
	if strings.Contains(got, "\nset ") || !strings.Contains(got, "mgmt-acl empty") {
		t.Errorf("IPv6 only:\n%s", got)
	}
	// --source replaces the detected address at the head, as in the ssh-only
	// filter; the detected address is still the one the device authenticates
	// against (no --server), so its replies have their term
	got = mgmtBlock(strictData(t, "192.0.2.1", "198.51.100.7", []string{"10.0.0.0/8"}, SNMPInput{}))
	if !strings.Contains(got, "permit-mgmt from source-address 198.51.100.7/32\n") || strings.Contains(got, "permit-mgmt from source-address 192.0.2.1/32\n") ||
		!strings.Contains(got, "permit-auth-replies from source-address 192.0.2.1/32\n") {
		t.Errorf("--source:\n%s", got)
	}
}

// The managed mgmt-acl section is the live lines of the block, so the strict
// filter is what a pull is compared with; the SNMP terms follow the permit
// terms and nothing follows them.
func TestStrictFilterIsTheManagedSection(t *testing.T) {
	v2c := SNMPInput{Version: "v2c", Community: "example-ro", Ranges: []string{"198.51.100.0/24"}}
	d := strictData(t, "192.0.2.1", "", []string{"10.0.0.0/8", "203.0.113.0/24:tcp/22"}, v2c)
	secs, err := Managed(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS, Source: SourceDefault}, d)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, s := range secs {
		if s.Name == "mgmt-acl" {
			lines = s.Lines
		}
	}
	if len(lines) == 0 || !strings.HasSuffix(lines[len(lines)-1], "term deny-snmp then discard") || !strings.Contains(strings.Join(lines, "\n"), "term permit-tcp-22 from destination-port ssh") {
		t.Errorf("section:\n%s", strings.Join(lines, "\n"))
	}
	for _, l := range lines {
		if strings.Contains(l, "default-accept") || strings.Contains(l, "deny-mgmt") {
			t.Errorf("section holds %q", l)
		}
	}
	// the v3 text says who may poll in the strict mode
	v3 := SNMPInput{Version: "v3", V3User: "monitor", V3Auth: "sha", V3Priv: "aes128", V3AuthPass: "authpass-123", V3PrivPass: "privpass-123",
		Ranges: []string{"198.51.100.0/24"}}
	d = strictData(t, "192.0.2.1", "", []string{"10.0.0.0/8"}, v3)
	got := JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)["SNMP_BLOCK"]
	if !strings.Contains(got, "(strict) does, once you apply it to lo0") || strings.Contains(got, "accept udp port 161 from the\n# clients above only") {
		t.Errorf("v3 text:\n%s", got)
	}
}
