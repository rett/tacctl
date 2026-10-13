package blocks

import (
	"slices"
	"strings"
	"testing"
)

const goodIOSBlock = `# the lab's own pollers
ip access-list standard POLLERS
 permit host 192.0.2.10
 permit 192.0.2.11
 permit 198.51.100.0 0.0.0.255
! another comment
snmp-server community lab-ro-7QxM RO POLLERS
snmp-server community lab-rw-ZpL2 rw WRITERS
snmp-server community open-ro-Zq3 RO
ip access-list standard WRITERS
 permit 192.0.2.99
snmp-server host 192.0.2.50 version 2c traps-Kd93 udp-port 162 config entity
snmp-server host 2001:db8::50 traps-Kd93
snmp-server enable traps
snmp-server enable traps snmp authentication linkdown
snmp-server enable traps config
no snmp-server community old-string
no snmp-server host 192.0.2.77 old-traps
no snmp-server enable traps tty
no ip access-list standard OLD-LIST
`

func TestIOSParseGoodBlock(t *testing.T) {
	b, fs := LintIOSSNMP(goodIOSBlock, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if len(b.Communities) != 3 || b.Communities[0].String != secA || b.Communities[1].Access != AccessRW || b.Communities[2].ACL != "" {
		t.Fatalf("communities: %+v", b.Communities)
	}
	if len(b.ACLs) != 2 || len(b.ACLs[0].Entries) != 3 || b.ACLs[0].Entries[1].Text() != "permit host 192.0.2.11" ||
		b.ACLs[0].Entries[2].Text() != "permit 198.51.100.0 0.0.0.255" {
		t.Fatalf("acls: %+v", b.ACLs)
	}
	if len(b.Hosts) != 2 || b.Hosts[0].UDPPort != 162 || b.Hosts[0].Version != "2c" || !slices.Equal(b.Hosts[0].Types, []string{"config", "entity"}) ||
		b.Hosts[1].Version != "" || b.Hosts[1].Addr.String() != "2001:db8::50" {
		t.Fatalf("hosts: %+v", b.Hosts)
	}
	if len(b.Traps) != 3 || len(b.Traps[0].Words) != 0 || b.Traps[1].key() != "snmp authentication linkdown" {
		t.Fatalf("traps: %+v", b.Traps)
	}
	if len(b.NotManaged) != 4 || b.NotManaged[1].Kind != IOSNoHost || b.NotManaged[1].Addr.String() != "192.0.2.77" || b.NotManaged[3].Name != "OLD-LIST" {
		t.Fatalf("no lines: %+v", b.NotManaged)
	}
	// the statements: lists first, then communities, hosts and traps; the
	// canonical text reads back as the same block
	st := IOSSNMPStatements(b)
	if st[0] != "ip access-list standard POLLERS" || st[1] != " permit host 192.0.2.10" || st[4] != "ip access-list standard WRITERS" {
		t.Errorf("statements: %q", st)
	}
	text := b.String(false)
	b2, fs := ParseIOSSNMP(text)
	if HasErrors(fs) || b2.String(false) != text {
		t.Errorf("round trip:\n%s\n%s", text, dump(fs))
	}
	// the host's lines in the form IOS accepts
	if !strings.Contains(text, "snmp-server host 192.0.2.50 version 2c traps-Kd93 udp-port 162 config entity\n") ||
		!strings.Contains(text, "snmp-server community lab-rw-ZpL2 RW WRITERS\n") {
		t.Errorf("text:\n%s", text)
	}
}

// Every refusal, with the line it is on; none of the texts holds a string.
func TestIOSParseRefusals(t *testing.T) {
	for _, c := range []struct{ name, text, frag string }{
		{"not a statement", "hostname rt1\n", "a block holds 'snmp-server'"},
		{"a numbered list", "access-list 10 permit any\n", "a numbered access list is not accepted"},
		{"an extended list", "ip access-list extended X\n", "only standard access lists"},
		{"an ip statement", "ip route 0.0.0.0 0.0.0.0 192.0.2.1\n", "only 'ip access-list standard"},
		{"a numbered name", "ip access-list standard 10\n permit any\n", "is a number"},
		{"a name off the alphabet", "ip access-list standard A;B\n permit any\n", "holds a character other than"},
		{"tacctl's list", "ip access-list standard TACCTL-SNMP\n permit any\n", "a name tacctl renders itself"},
		{"tacctl's group", "snmp-server community " + secA + " RO TACCTL-GROUP\n", "a name tacctl renders itself"},
		{"a deny entry", "ip access-list standard L\n deny 192.0.2.1\n", "permit entries only"},
		{"a remark", "ip access-list standard L\n remark hello\n", "a remark is not kept"},
		{"an entry outside a list", "permit any\n", "belongs under 'ip access-list standard"},
		{"an entry with a log keyword", "ip access-list standard L\n permit 192.0.2.1 log\n", "log and the other keywords"},
		{"host bits", "ip access-list standard L\n permit 192.0.2.1 0.0.0.255\n", "address bits set where its wildcard says any"},
		{"a bad address", "ip access-list standard L\n permit 192.0.2.300\n", "is not an IPv4 address"},
		{"an entry twice", "ip access-list standard L\n permit 192.0.2.1\n permit host 192.0.2.1\n", "is listed twice"},
		{"a list twice", "ip access-list standard L\n permit any\nip access-list standard L\n permit any\n", "stated twice"},
		{"a community with no access", "snmp-server community " + secA + "\n", "needs RO or RW"},
		{"a view", "snmp-server community " + secA + " view V RO\n", "RO or RW"},
		{"an ipv6 list", "snmp-server community " + secA + " RO ipv6 L\n", "the access list name is the last word"},
		{"a long community", "snmp-server community " + strings.Repeat("x", 33) + " RO\n", "is longer than 32"},
		{"a community twice", "snmp-server community " + secA + " RO\nsnmp-server community " + secA + " RW L\n", "stated twice"},
		{"a placeholder", "snmp-server community <secret:1> RO\n", "a placeholder"},
		{"a quote", "snmp-server community \"a b\" RO\n", "a quote"},
		{"a host with no community", "snmp-server host 192.0.2.5\n", "needs the community"},
		{"a host with v3", "snmp-server host 192.0.2.5 version 3 priv " + secA + "\n", "SNMPv3"},
		{"a host in a vrf", "snmp-server host 192.0.2.5 vrf M " + secA + "\n", "'vrf' is not in the grammar"},
		{"informs", "snmp-server host 192.0.2.5 informs " + secA + "\n", "'informs' is not in the grammar"},
		{"a host port", "snmp-server host 192.0.2.5 " + secA + " udp-port 70000\n", "a number from 1 to 65535"},
		{"a host type", "snmp-server host 192.0.2.5 " + secA + " bogus\n", "a notification type is one of"},
		{"a host twice", "snmp-server host 192.0.2.5 " + secA + "\nsnmp-server host 192.0.2.5 " + secA + " config\n", "is stated twice"},
		{"a name for an address", "snmp-server host nms.example.net " + secA + "\n", "is not an IPv4 or IPv6 address"},
		{"traps type", "snmp-server enable traps bogus\n", "the trap type (word 4) is one of"},
		{"traps subtype", "snmp-server enable traps snmp LINKDOWN\n", "the trap subtype"},
		{"traps twice", "snmp-server enable traps config\nsnmp-server enable traps config\n", "is stated twice"},
		{"contact", "snmp-server contact NOC\n", "never part of a block"},
		{"location", "snmp-server location Rack\n", "never part of a block"},
		{"trap-source none", "snmp-server trap-source\n", "takes one interface name"},
		{"trap-source two", "snmp-server trap-source Loopback0 Loopback1\n", "takes one interface name"},
		{"trap-source abbreviated", "snmp-server trap-source Lo0\n", "has its type abbreviated"},
		{"trap-source no number", "snmp-server trap-source Loopback\n", "has no number"},
		{"trap-source a character", "snmp-server trap-source Loopback0;\n", "is not an interface name"},
		{"trap-source twice", "snmp-server trap-source Loopback0\nsnmp-server trap-source Loopback1\n", "is stated twice"},
		{"source-interface", "snmp-server source-interface traps Loopback0\n", "is not accepted in a block"},
		{"a no of trap-source with words", "no snmp-server trap-source Loopback0 x\n", "takes an interface name, or nothing"},
		{"engineID", "snmp-server engineID local 0123\n", "the device's identity"},
		{"a user", "snmp-server user u g v3\n", "SNMPv3"},
		{"a group", "snmp-server group g v3 priv\n", "SNMPv3"},
		{"a view line", "snmp-server view v iso included\n", "SNMPv3"},
		{"queue length", "snmp-server queue-length 100\n", "word 2 is not one of"},
		{"a tab", "snmp-server community " + secA + "\tRO\n", "a tab at column"},
		{"a control character", "snmp-server community " + secA + " RO\x01\n", "a control character"},
		{"a non-ASCII word", "snmp-server community caf\u00e9 RO\n", "not ASCII"},
		{"a long line", "snmp-server enable traps " + strings.Repeat("a ", 600) + "\n", "longer than"},
		{"a bare no", "no\n", "'no' needs a statement"},
		{"a no of something else", "no ip route 0.0.0.0\n", "a 'no' line takes"},
		{"a no with a port", "no snmp-server host 192.0.2.5 " + secA + " udp-port 162\n", "names the address, the version and the community only"},
		{"a no of tacctl's list", "no ip access-list standard TACCTL-SNMP\n", "a name tacctl renders itself"},
	} {
		_, fs := ParseIOSSNMP(c.text)
		if !HasErrors(fs) || !hasFinding(fs, SevError, -1, c.frag) {
			t.Errorf("%s: no %q:\n%s", c.name, c.frag, dump(fs))
		}
		for _, bad := range []string{secA, "caf", "nms.example.net"} {
			if strings.Contains(dump(fs), bad) {
				t.Errorf("%s: a finding holds %q:\n%s", c.name, bad, dump(fs))
			}
		}
	}
}

// What check says beyond the parse.
func TestIOSCheck(t *testing.T) {
	for _, c := range []struct {
		name, text string
		layer      Layer
		sev        Severity
		frag       string
	}{
		{"rw without a list", "snmp-server community " + secA + " RW\n", LayerScope, SevError, "read-write and names no access list"},
		{"rw with a list that permits any", "ip access-list standard L\n permit any\nsnmp-server community " + secA + " RW L\n", LayerScope, SevError, "its access list permits any"},
		{"rw with the device's own list", "snmp-server community " + secA + " RW OWN\n", LayerScope, SevNote, "tacctl cannot see"},
		{"ro with no list", "snmp-server community " + secA + " RO\n", LayerScope, SevNote, "answers every address"},
		{"ro open", "ip access-list standard L\n permit any\nsnmp-server community " + secA + " RO L\n", LayerScope, SevNote, "open to every client"},
		{"a list the block does not define", "snmp-server community " + secA + " RO OWN\n", LayerScope, SevNote, "names the access list OWN, which this block does not define"},
		{"an empty list", "ip access-list standard L\n", LayerScope, SevError, "has no entry"},
		{"an unreferenced list", "ip access-list standard L\n permit 192.0.2.1\n", LayerScope, SevNote, "named by no community"},
		{"the default names no address", "ip access-list standard L\n permit 192.0.2.1\n", LayerDefault, SevError, "the default block names no address"},
		{"the default names no host", "snmp-server host 192.0.2.5 " + secA + "\n", LayerDefault, SevError, "the default block names no host"},
		{"traps with none", "snmp-server enable traps\n", LayerScope, SevNote, "every notification type"},
		{"owned", "snmp-server community " + secA + " RO L\n", LayerScope, SevNote, "becomes owned by tacctl"},
		{"secret", "snmp-server host 192.0.2.5 " + secA + "\n", LayerScope, SevNote, "carries a community string, a secret, on line 1"},
	} {
		_, fs := LintIOSSNMP(c.text, c.layer)
		if !hasFinding(fs, c.sev, -1, c.frag) {
			t.Errorf("%s: no %s %q:\n%s", c.name, c.sev, c.frag, dump(fs))
		}
		if strings.Contains(dump(fs), secA) {
			t.Errorf("%s: a finding holds the string", c.name)
		}
	}
}

func TestIOSResolveIsPerObject(t *testing.T) {
	scope, _ := LintIOSSNMP(`ip access-list standard P
 permit 192.0.2.10
 permit 192.0.2.11
snmp-server community a-community-1 RO P
snmp-server community b-community-2 RO P
snmp-server host 192.0.2.50 traps-one
snmp-server host 192.0.2.51 traps-two
snmp-server enable traps config
snmp-server enable traps tty
`, LayerScope)
	dev, _ := LintIOSSNMP(`ip access-list standard P
 permit 203.0.113.9
snmp-server community a-community-1 RW P
no snmp-server community b-community-2
snmp-server host 192.0.2.50 version 2c traps-one udp-port 1162
no snmp-server host 192.0.2.51 traps-two
no snmp-server enable traps tty
snmp-server enable traps snmp linkdown
`, LayerDevice)
	r := ResolveIOSSNMP(nil, scope, dev)
	got := IOSSNMPStatements(r)
	want := []string{"ip access-list standard P", " permit host 203.0.113.9", "snmp-server community a-community-1 RW P",
		"snmp-server host 192.0.2.50 version 2c traps-one udp-port 1162", "snmp-server enable traps config", "snmp-server enable traps snmp linkdown"}
	if !slices.Equal(got, want) {
		t.Errorf("resolved:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if len(r.NotManaged) != 3 {
		t.Errorf("no lines: %+v", r.NotManaged)
	}
	// the inputs are not changed
	if len(scope.Communities) != 2 || scope.ACLs[0].Entries[0].Text() != "permit host 192.0.2.10" {
		t.Errorf("the scope's block changed")
	}
	if got := ResolveIOSSNMP(nil, nil, nil); !got.Empty() {
		t.Errorf("nothing: %+v", got)
	}
}

func TestIOSElide(t *testing.T) {
	b, _ := LintIOSSNMP(goodIOSBlock, LayerScope)
	text := b.String(true)
	for _, bad := range []string{secA, secB, secG, "old-string", "old-traps"} {
		if strings.Contains(text, bad) {
			t.Errorf("the elided text holds %q:\n%s", bad, text)
		}
	}
	for _, want := range []string{"snmp-server community <secret:1> RO POLLERS\n", "snmp-server community <secret:2> RW WRITERS\n",
		"snmp-server host 192.0.2.50 version 2c <secret:4> udp-port 162 config entity\n", "no snmp-server community <secret:5>\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("the elided text lacks %q:\n%s", want, text)
		}
	}
	// the same string is the same mark everywhere
	b2, _ := LintIOSSNMP("snmp-server community "+secA+" RO\nsnmp-server host 192.0.2.5 "+secA+"\n", LayerScope)
	if got := b2.String(true); got != "snmp-server community <secret:1> RO\nsnmp-server host 192.0.2.5 <secret:1>\n" {
		t.Errorf("%q", got)
	}
}

func TestIOSLintFor(t *testing.T) {
	d0, fs0, err := LintFor(VendorCisco, BlockSystem, "ip domain name lab.example.net\n", LayerScope)
	if err != nil || HasErrors(fs0) || d0.Empty() || len(StatementsOf(d0)) != 1 {
		t.Errorf("the IOS system block: %v %v", err, fs0)
	}
	if _, ok := d0.(*IOSSystemBlock); !ok {
		t.Errorf("the IOS system block is a %T", d0)
	}
	d, fs, err := LintFor(VendorCisco, BlockSNMP, "snmp-server enable traps config\n", LayerScope)
	if err != nil || HasErrors(fs) || d.Empty() || len(StatementsOf(d)) != 1 {
		t.Errorf("%v %v", err, fs)
	}
	if _, _, err := LintFor("wti", BlockSNMP, "", LayerScope); err == nil {
		t.Error("wti")
	}
}

// The IOS template is comments only and its example, uncommented, is a block
// that passes the check.
func TestIOSTemplate(t *testing.T) {
	for _, layer := range []Layer{LayerScope, LayerDevice} {
		tpl := TemplateFor(VendorCisco, BlockSNMP, layer)
		b, fs := LintIOSSNMP(tpl, layer)
		if HasErrors(fs) || !b.Empty() {
			t.Errorf("template: %v empty=%v", fs, b.Empty())
		}
		_, example, ok := strings.Cut(tpl, "# Example")
		if !ok {
			t.Fatal("no example")
		}
		var lines []string
		for _, l := range strings.Split(example, "\n")[1:] {
			if rest, ok := strings.CutPrefix(l, "# "); ok {
				lines = append(lines, rest)
			}
		}
		b, fs = LintIOSSNMP(strings.Join(lines, "\n")+"\n", layer)
		if HasErrors(fs) || b.Empty() {
			t.Errorf("example: %v\n%s", fs, strings.Join(lines, "\n"))
		}
	}
	if got := TemplateFor(VendorJuniper, BlockSNMP, LayerScope); got != Template(BlockSNMP, LayerScope) {
		t.Error("the Junos template changed")
	}
}

const adoptIOSRaw = `snmp-server community scope-own-string RO TACCTL-SNMP
snmp-server community poller-string RO POLLERS
snmp-server community writer-string RW POLLERS
snmp-server community numbered-string RO 10
snmp-server community view-string view V RO
snmp-server community 7 0822455D0A16 RO
snmp-server community already-string RO POLLERS
snmp-server location Rack 4
snmp-server contact noc@example.net
snmp-server host 192.0.2.61 traps version 2c poller-traps
snmp-server host 192.0.2.62 informs version 2c poller-traps
snmp-server host 192.0.2.63 vrf M poller-traps
snmp-server enable traps config
snmp-server enable traps snmp authentication linkdown linkup
snmp-server user v3user TACCTL-GROUP v3 auth sha secretvalue
snmp-server queue-length 100
ip access-list standard TACCTL-SNMP
 permit host 192.0.2.10
 deny any
ip access-list standard POLLERS
 10 permit 192.0.2.60
 20 permit 198.51.100.0 0.0.0.255
 remark the pollers
ip access-list standard DENYING
 10 permit 192.0.2.70
 20 deny 192.0.2.71
`

func TestAdoptIOSSNMP(t *testing.T) {
	own := AdoptOwn{Community: "scope-own-string"}
	same, _ := LintIOSSNMP("snmp-server community already-string RO POLLERS\nsnmp-server enable traps config\n", LayerScope)
	res := AdoptIOSSNMP(adoptIOSRaw, own, same, nil)
	for _, want := range []string{
		"ip access-list standard POLLERS\n permit host 192.0.2.60\n permit 198.51.100.0 0.0.0.255\n",
		"snmp-server community poller-string RO POLLERS\nsnmp-server community writer-string RW POLLERS\n",
		"snmp-server host 192.0.2.61 version 2c poller-traps\n",
		"snmp-server enable traps snmp authentication linkdown linkup\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	for _, bad := range []string{"scope-own-string", "numbered-string", "view-string", "0822455D0A16", "already-string", "TACCTL", "informs", "vrf",
		"v3user", "DENYING", "snmp-server enable traps config", "Rack", "noc@"} {
		if strings.Contains(res.Text, bad) {
			t.Errorf("the draft holds %q:\n%s", bad, res.Text)
		}
	}
	if _, fs := ParseIOSSNMP(res.Text); HasErrors(fs) {
		t.Errorf("the draft does not parse:\n%s", dump(fs))
	}
	notes := strings.Join(res.Notes, "\n")
	for _, want := range []string{"tacctl's own, rendered from its settings", "2 statements", "identity (contact, location, engine id), never part of a block: 2 statements",
		"stated already", "2 objects"} {
		if !strings.Contains(notes, want) {
			t.Errorf("the notes lack %q:\n%s", want, notes)
		}
	}
	left := strings.Join(res.Left, "\n")
	for _, want := range []string{"names a numbered access list", "names a view or an IPv6 access list", "1 community is shown only as the device's ciphertext",
		"an access list has an entry a block cannot hold"} {
		if !strings.Contains(left, want) {
			t.Errorf("left out lacks %q:\n%s", want, left)
		}
	}
	for _, s := range append(res.Notes, res.Left...) {
		for _, bad := range []string{"poller-string", "writer-string", "poller-traps", "scope-own-string", "numbered-string", "0822455D0A16", "secretvalue"} {
			if strings.Contains(s, bad) {
				t.Errorf("a note holds %q: %q", bad, s)
			}
		}
	}
	// beneath a block that states the same list, the list is not repeated
	up, _ := LintIOSSNMP("ip access-list standard POLLERS\n permit host 192.0.2.60\n permit 198.51.100.0 0.0.0.255\n", LayerScope)
	res = AdoptIOSSNMP(adoptIOSRaw, own, nil, up)
	if strings.Contains(res.Text, "ip access-list standard") {
		t.Errorf("the scope's list is repeated:\n%s", res.Text)
	}
	// nothing to adopt
	if res := AdoptIOSSNMP("", own, nil, nil); res.Text != "" || res.Statements != 0 {
		t.Errorf("empty: %+v", res)
	}
}
