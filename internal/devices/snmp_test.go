package devices

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// updateGolden rewrites the goldens instead of comparing (the Go tests do not
// read the environment; bats's UPDATE_GOLDEN=1 does the same for the CLI's).
var updateGolden = flag.Bool("update", false, "rewrite the golden files of tests/fixtures/golden")

// checkGolden compares got with tests/fixtures/golden/<name>; with -update it
// writes the file instead.
func checkGolden(t *testing.T, name, got string) {
	t.Helper()
	p := filepath.Join("..", "..", "tests", "fixtures", "golden", name)
	if *updateGolden {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("%s: %v (go test -update creates it)", name, err)
	}
	if got != string(want) {
		t.Errorf("%s differs:\n%s", name, firstDiff(got, string(want)))
	}
}

// snmpCase is one SNMP step input of the matrix every vendor is built over.
type snmpCase struct {
	name string
	in   SNMPInput
}

var (
	// fullRanges: a /32, a /24, a /8 and a /12 (the wildcard conversions).
	fullRanges = []string{"192.0.2.7/32", "198.51.100.0/24", "10.0.0.0/8", "172.16.0.0/12"}

	v2cAll = SNMPInput{Scope: "lab", Version: "v2c", Community: "lab-ro-community", CredFrom: "scope", Server: "10.0.0.42",
		Ranges: []string{"198.51.100.0/24"}, Contact: "NOC <noc@example.net>", Location: "Rack 4, DC1", SysName: "core-sw1",
		Description: "Core switch", DeviceName: "core-sw1"}
	v3All = SNMPInput{Scope: "lab", Version: "v3", V3User: "tacctl-ro", V3Auth: "sha", V3Priv: "aes128", V3AuthPass: "auth-pass-0123",
		V3PrivPass: "priv-pass-4567", CredFrom: "default", Server: "10.0.0.42", Ranges: []string{"198.51.100.0/24"},
		Contact: "NOC <noc@example.net>", Location: "Rack 4, DC1", SysName: "core-sw1", Description: "Core switch", DeviceName: "core-sw1"}
)

func snmpCases() []snmpCase {
	with := func(in SNMPInput, f func(*SNMPInput)) SNMPInput { f(&in); return in }
	return []snmpCase{
		{"none", SNMPInput{Scope: "lab", Server: "10.0.0.42"}},
		{"v2c", v2cAll},
		{"v3", v3All},
		{"v3-sha256", with(v3All, func(i *SNMPInput) { i.V3Auth = "sha256"; i.CredFrom = "scope" })},
		{"noclients", with(v2cAll, func(i *SNMPInput) { i.Ranges = nil })},
		{"ranges", with(v2cAll, func(i *SNMPInput) { i.Ranges = fullRanges })},
		{"unset", with(v2cAll, func(i *SNMPInput) { i.Contact, i.Location, i.DeviceName, i.SysName, i.Description = "", "", "", "", "" })},
		{"unset-contact", with(v2cAll, func(i *SNMPInput) { i.Contact = "" })},
		{"unset-location", with(v2cAll, func(i *SNMPInput) { i.Location = "" })},
		{"nocommunity", with(v2cAll, func(i *SNMPInput) { i.Community = "" })},
		{"nov3user", with(v3All, func(i *SNMPInput) { i.V3User = "" })},
		{"unknown-server", with(v2cAll, func(i *SNMPInput) { i.Server = UnknownServer })},
		{"server-listed", with(v2cAll, func(i *SNMPInput) { i.Ranges = []string{"10.0.0.42/32", "198.51.100.0/24"} })},
		{"quoting", with(v2cAll, func(i *SNMPInput) { i.Location = `Rack "4" \ DC1`; i.Description = `say "hi"` })},
	}
}

func snmpBuilders() map[string]func(SNMPInput) SNMPBlock {
	return map[string]func(SNMPInput) SNMPBlock{"cisco": CiscoSNMP, "juniper": JuniperSNMP, "wti": WTISNMP}
}

// The block of every vendor for every case, pinned in goldens.
func TestSNMPBlockGoldens(t *testing.T) {
	for vendor, build := range snmpBuilders() {
		for _, c := range snmpCases() {
			b := build(c.in)
			text := b.Text + "\n"
			if line := UnfilledLine(b.Unfilled); line != "" {
				text += "\n" + line + "\n"
			}
			checkGolden(t, "snmp/block-"+vendor+"-"+c.name+".txt", text)
		}
	}
}

// The client list is the server's /32, the scope's ranges in the order
// given, then the 0.0.0.0/0 restrict, which is always rendered and is
// never one of the ranges.
func TestSNMPClientOrder(t *testing.T) {
	in := v2cAll
	in.Ranges = fullRanges
	cisco := CiscoSNMP(in).Text
	order := []string{"permit host 10.0.0.42", "permit host 192.0.2.7", "permit 198.51.100.0 0.0.0.255", "permit 10.0.0.0 0.255.255.255",
		"permit 172.16.0.0 0.15.255.255", "deny   any"}
	last := -1
	for _, want := range order {
		i := strings.Index(cisco, want+"\n")
		if i <= last {
			t.Errorf("cisco: %q out of order (at %d, after %d):\n%s", want, i, last, cisco)
		}
		last = i
	}
	junos := JuniperSNMP(in).Text
	order = []string{"client-list TACCTL-SNMP 10.0.0.42/32\n", "client-list TACCTL-SNMP 192.0.2.7/32\n", "client-list TACCTL-SNMP 198.51.100.0/24\n",
		"client-list TACCTL-SNMP 10.0.0.0/8\n", "client-list TACCTL-SNMP 172.16.0.0/12\n", "client-list TACCTL-SNMP 0.0.0.0/0 restrict\n"}
	last = -1
	for _, want := range order {
		i := strings.Index(junos, want)
		if i <= last {
			t.Errorf("juniper: %q out of order:\n%s", want, junos)
		}
		last = i
	}
	// A scope with no ranges still has the server and the restrict, and says so.
	in.Ranges = nil
	for _, b := range []SNMPBlock{CiscoSNMP(in), JuniperSNMP(in), WTISNMP(in)} {
		if !strings.Contains(b.Text, "has no client ranges: only the tacctl server may query") {
			t.Errorf("no notice:\n%s", b.Text)
		}
	}
	if !strings.Contains(CiscoSNMP(in).Text, "permit host 10.0.0.42\n") || !strings.Contains(JuniperSNMP(in).Text, "0.0.0.0/0 restrict") {
		t.Error("server or restrict missing without ranges")
	}
	// The server listed in the ranges is not listed twice.
	in.Ranges = []string{"10.0.0.42/32", "198.51.100.0/24"}
	if n := strings.Count(CiscoSNMP(in).Text, "permit host 10.0.0.42\n"); n != 1 {
		t.Errorf("server listed %d times", n)
	}
}

// Nothing unset is ever rendered as text a paste would apply, and the
// Unfilled line names what is missing and the command that sets it.
func TestSNMPUnfilled(t *testing.T) {
	in := v2cAll
	in.Contact, in.Location, in.DeviceName = "", "", ""
	for vendor, build := range snmpBuilders() {
		b := build(in)
		if got := UnfilledLine(b.Unfilled); got != "Unfilled SNMP values: contact (tacctl scope snmp lab contact '<text>')" {
			t.Errorf("%s: %q", vendor, got)
		}
		for _, l := range strings.Split(b.Text, "\n") {
			if strings.Contains(l, "<contact>") || strings.Contains(l, "<location>") {
				if !strings.HasPrefix(strings.TrimSpace(l), "!") && !strings.HasPrefix(strings.TrimSpace(l), "#") && vendor != "wti" {
					t.Errorf("%s: placeholder is not a comment: %q", vendor, l)
				}
			}
		}
	}
	in.DeviceName = "core-sw1"
	// The location is a setting of one device, not a gap of the walkthrough.
	if got := UnfilledLine(CiscoSNMP(in).Unfilled); strings.Contains(got, "location") {
		t.Errorf("named device: %q", got)
	}
	if !strings.Contains(CiscoSNMP(in).Text, "NOT SET: tacctl device location core-sw1 '<text>'") {
		t.Error("the placeholder line does not name the command that sets the location")
	}
	in.Contact, in.Location = "x", "y"
	if len(CiscoSNMP(in).Unfilled) != 0 || UnfilledLine(nil) != "" {
		t.Error("nothing is unfilled")
	}
	// Not configured: nothing to fill.
	if b := CiscoSNMP(SNMPInput{Scope: "lab", Server: "10.0.0.42"}); len(b.Unfilled) != 0 || !strings.Contains(b.Text, "SNMP is not configured in tacctl for scope 'lab'") {
		t.Errorf("not configured: %+v", b)
	}
	// A missing community is unfilled, and the step is a comment.
	in = v2cAll
	in.Community = ""
	b := CiscoSNMP(in)
	if !strings.Contains(UnfilledLine(b.Unfilled), "community (tacctl scope snmp lab community)") || strings.Contains(b.Text, "\nsnmp-server community") {
		t.Errorf("no community: %q\n%s", UnfilledLine(b.Unfilled), b.Text)
	}
}

// The builders read nothing but their input: the same input gives the same
// bytes, however often and in whatever order.
func TestSNMPBuildersArePure(t *testing.T) {
	for vendor, build := range snmpBuilders() {
		for _, c := range snmpCases() {
			a, b := build(c.in), build(c.in)
			if a.Text != b.Text || UnfilledLine(a.Unfilled) != UnfilledLine(b.Unfilled) {
				t.Errorf("%s/%s differs between runs", vendor, c.name)
			}
		}
	}
}

// --- whole walkthroughs -----------------------------------------------------------------

// snmpRender renders a whole walkthrough of the multiscope fixture with
// the SNMP input and the flags of d applied.
func snmpRender(t *testing.T, vendor, scope string, legacy bool, protocol string, mod func(*Data)) string {
	t.Helper()
	m, c := fixture(t, "store.multiscope.yaml", "")
	acl := MgmtACL{Name: "VTY-ACL"}
	if vendor == "juniper" {
		acl.Name = "MGMT-ACL"
	}
	d := Data{Model: m, Conf: c, TemplateDir: t.TempDir(), ServerIP: "10.0.0.42", ACL: acl}
	source := SourceDefault
	if protocol == RADIUS {
		source = SourceFlag
		d.Radius = &Radius{AuthPort: "1812", AcctPort: "1813", Secret: m.Scope(scope).Secret, VendorSent: "scope"}
	}
	if mod != nil {
		mod(&d)
	}
	var buf bytes.Buffer
	if err := Render(&buf, Request{Vendor: vendor, Scope: scope, Legacy: legacy, Protocol: protocol, Source: source}, d); err != nil {
		t.Fatal(err)
	}
	return reANSI.ReplaceAllString(buf.String(), "")
}

type variant struct {
	name, vendor string
	legacy       bool
	protocol     string
}

var variants = []variant{
	{"cisco", "cisco", false, TACACS}, {"cisco-legacy", "cisco", true, TACACS}, {"cisco-radius", "cisco", false, RADIUS},
	{"juniper", "juniper", false, TACACS}, {"juniper-radius", "juniper", false, RADIUS},
	{"wti", "wti", false, TACACS}, {"wti-radius", "wti", false, RADIUS},
}

// Every template renders the step for the cases that matter, whole.
func TestRenderSNMPGoldens(t *testing.T) {
	cases := map[string]SNMPInput{"v2c": v2cAll, "v3": v3All, "unset": snmpCases()[6].in, "ranges": snmpCases()[5].in}
	for _, v := range variants {
		for name, in := range cases {
			out := snmpRender(t, v.vendor, "lab", v.legacy, v.protocol, func(d *Data) { d.SNMP = in })
			checkGolden(t, "snmp/full-"+v.name+"-"+name+".conf", out)
		}
	}
}

// An engineer's walkthrough shows the credentials like a superuser's, and
// the Cisco NETCONF step is a superuser's.
func TestRenderEngineer(t *testing.T) {
	for _, v := range variants[:3] {
		out := snmpRender(t, v.vendor, "lab", v.legacy, v.protocol, func(d *Data) { d.SNMP = v3All; d.Restricted = true })
		if !strings.Contains(out, "auth-pass-0123") || !strings.Contains(out, "priv-pass-4567") {
			t.Errorf("%s: an engineer's walkthrough lacks the credentials", v.name)
		}
		if v.legacy {
			continue
		}
		if !strings.Contains(out, "ask one to run 'tacctl config cisco'") || strings.Contains(out, "netconf-yang\n") {
			t.Errorf("%s: NETCONF for an engineer:\n%s", v.name, out)
		}
		checkGolden(t, "snmp/full-"+v.name+"-engineer.conf", out)
	}
	su := snmpRender(t, "cisco", "lab", false, TACACS, func(d *Data) { d.SNMP = v3All })
	if !strings.Contains(su, "! netconf-yang\n") || strings.Contains(su, "ask one to run") {
		t.Errorf("a superuser's NETCONF step:\n%s", su)
	}
	legacy := snmpRender(t, "cisco", "lab", true, TACACS, nil)
	if !strings.Contains(legacy, "does not exist on IOS 12.x") || strings.Contains(legacy, "! netconf-yang") {
		t.Errorf("legacy NETCONF:\n%s", legacy)
	}
}

// The NETCONF step of the Junos walkthroughs, with and without a
// management filter; WTI says there is none.
func TestRenderNetconf(t *testing.T) {
	with := snmpRender(t, "juniper", "lab", false, TACACS, func(d *Data) { d.ACL.CIDRs = []string{"10.0.0.0/8", "192.0.2.0/24"} })
	without := snmpRender(t, "juniper", "lab", false, TACACS, nil)
	checkGolden(t, "snmp/full-juniper-netconf-filter.conf", with)
	checkGolden(t, "snmp/full-juniper-netconf-nofilter.conf", without)
	if !strings.Contains(with, "#   set system services netconf ssh\n") || !strings.Contains(with, "permits tcp port 830 next to ssh") ||
		!strings.Contains(with, "# tcp port 830 (NETCONF over ssh, Step 6) is permitted by the same terms as ssh.") {
		t.Errorf("with filter:\n%s", with)
	}
	if !strings.Contains(without, "No management filter is rendered") {
		t.Errorf("without filter:\n%s", without)
	}
	for _, line := range strings.Split(with+without, "\n") {
		if strings.Contains(line, "set system services netconf") && !strings.HasPrefix(line, "#") {
			t.Errorf("NETCONF is enabled by the paste: %q", line)
		}
	}
	for _, v := range []variant{variants[5], variants[6]} {
		if out := snmpRender(t, v.vendor, "lab", false, v.protocol, nil); !strings.Contains(out, "NETCONF does not exist on the unit") {
			t.Errorf("%s: no NETCONF line", v.name)
		}
	}
}

// --server and --source (D43): the lines that say where the server is carry
// --server; the SNMP client list keeps the detected address or --source; the
// role note appears when the two differ.
func TestRenderServerAndSource(t *testing.T) {
	both := func(d *Data) { d.SNMP = v2cAll; d.AuthServer = "203.0.113.9"; d.SourceIP = "198.51.100.77" }
	for _, c := range []struct {
		name string
		mod  func(*Data)
	}{
		{"server", func(d *Data) { d.SNMP = v2cAll; d.AuthServer = "203.0.113.9" }},
		{"server-name", func(d *Data) { d.SNMP = v2cAll; d.AuthServer = "203.0.113.9"; d.AuthName = "tacacs.example.net" }},
		{"source", func(d *Data) { d.SNMP = v2cAll; d.SourceIP = "198.51.100.77" }},
		{"both", both},
		{"same", func(d *Data) { d.SNMP = v2cAll; d.AuthServer = "10.0.0.42"; d.SourceIP = "10.0.0.42" }},
	} {
		for _, v := range []variant{variants[0], variants[3], variants[5], variants[2]} {
			out := snmpRender(t, v.vendor, "lab", v.legacy, v.protocol, c.mod)
			if c.name == "server" || c.name == "both" {
				checkGolden(t, "snmp/addr-"+v.name+"-"+c.name+".conf", out)
			}
			var d Data
			c.mod(&d)
			note := strings.Contains(out, "Two server addresses:")
			if note != (c.name != "same") {
				t.Errorf("%s/%s: note %v", v.name, c.name, note)
			}
			if d.AuthServer != "" && !strings.Contains(out, "203.0.113.9") && c.name != "same" {
				t.Errorf("%s/%s: the AAA lines lack --server", v.name, c.name)
			}
			if c.name == "same" && strings.Contains(out, "203.0.113") {
				t.Errorf("%s/same: --server leaked", v.name)
			}
			// The first SNMP client is --source, else the detected address;
			// never --server.
			wantClient := "10.0.0.42"
			if d.SourceIP != "" {
				wantClient = d.SourceIP
			}
			if v.vendor == "cisco" && !strings.Contains(out, "permit host "+wantClient+"\n") {
				t.Errorf("%s/%s: first client is not %s", v.name, c.name, wantClient)
			}
			if v.vendor == "juniper" && !strings.Contains(out, "client-list TACCTL-SNMP "+wantClient+"/32\n") {
				t.Errorf("%s/%s: first client is not %s", v.name, c.name, wantClient)
			}
			if strings.Contains(out, "permit host 203.0.113.9") || strings.Contains(out, "client-list TACCTL-SNMP 203.0.113.9") {
				t.Errorf("%s/%s: --server is an SNMP client", v.name, c.name)
			}
		}
	}
	// --server wins over a RADIUS listener's bound address.
	out := snmpRender(t, "juniper", "lab", false, RADIUS, func(d *Data) {
		d.Radius.ServerAddr = "10.0.0.77"
		d.AuthServer = "203.0.113.9"
	})
	if !strings.Contains(out, "set system radius-server 203.0.113.9 port 1812") || strings.Contains(out, "10.0.0.77") && !strings.Contains(out, "(--server)") {
		t.Errorf("listener vs --server:\n%s", out)
	}
	if out := snmpRender(t, "juniper", "lab", false, RADIUS, func(d *Data) { d.Radius.ServerAddr = "10.0.0.77" }); !strings.Contains(out, "set system radius-server 10.0.0.77 port 1812") {
		t.Errorf("listener alone:\n%s", out)
	}
}

// A template of the operator's without the SNMP variable renders as it did.
func TestOperatorTemplateWithoutSNMP(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cisco.template"), []byte("MINE ${SERVER_IP}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	d := Data{Model: m, Conf: c, TemplateDir: dir, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "VTY-ACL"}, SNMP: v2cAll}
	if err := Render(&buf, Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS, Source: SourceDefault}, d); err != nil {
		t.Fatal(err)
	}
	out := reANSI.ReplaceAllString(buf.String(), "")
	if !strings.Contains(out, "MINE 10.0.0.42\n") || strings.Contains(out, "snmp-server community") {
		t.Errorf("operator template:\n%s", out)
	}
}
