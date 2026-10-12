package devices

// WP10.8a B3, B4, B2: the management ACL names the server, the Junos filter
// restricts udp port 161, and a credential a CLI would misread is not pasted.

import (
	"strings"
	"testing"
)

func mgmtData(t *testing.T, server, source string, cidrs []string, snmp SNMPInput) Data {
	t.Helper()
	m, c := fixture(t, "store.multiscope.yaml", "")
	return Data{Model: m, Conf: c, ServerIP: server, SourceIP: source,
		ACL: MgmtACL{Name: "MGMT-ACL", CIDRs: cidrs}, SNMP: snmp}
}

// B4: the server's /32 (--source, else the detected address) is the first
// permit of the Cisco access list and of the Junos filter whenever the block
// is rendered, once, and the block is not rendered for an empty list.
func TestManagementACLPermitsTheServerFirst(t *testing.T) {
	cisco := func(d Data) string {
		return CiscoVars(Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS}, d)["VTY_ACL_BLOCK"]
	}
	juniper := func(d Data) string {
		return JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)["MGMT_ACL_BLOCK"]
	}
	permitSrc := "set firewall family inet filter MGMT-ACL term permit-mgmt from source-address "

	d := mgmtData(t, "192.0.2.1", "", []string{"10.0.0.0/8", "172.16.0.0/12"}, SNMPInput{})
	if got := cisco(d); !strings.Contains(got, "\n  permit 192.0.2.1 0.0.0.0\n  permit 10.0.0.0 0.255.255.255\n  permit 172.16.0.0 0.15.255.255\n") {
		t.Errorf("cisco, detected address:\n%s", got)
	}
	got := juniper(d)
	if i, j := strings.Index(got, permitSrc+"192.0.2.1/32\n"), strings.Index(got, permitSrc+"10.0.0.0/8\n"); i < 0 || j < 0 || i > j {
		t.Errorf("junos, detected address:\n%s", got)
	}

	// --source wins over the detected address.
	d = mgmtData(t, "192.0.2.1", "198.51.100.7", []string{"10.0.0.0/8"}, SNMPInput{})
	if got := cisco(d); !strings.Contains(got, "  permit 198.51.100.7 0.0.0.0\n  permit 10.0.0.0 0.255.255.255\n") || strings.Contains(got, "192.0.2.1") {
		t.Errorf("cisco, --source:\n%s", got)
	}
	if got := juniper(d); !strings.Contains(got, permitSrc+"198.51.100.7/32\n") || strings.Contains(got, "192.0.2.1") {
		t.Errorf("junos, --source:\n%s", got)
	}

	// The list already holds it: once, first.
	d = mgmtData(t, "192.0.2.1", "", []string{"10.0.0.0/8", "192.0.2.1/32"}, SNMPInput{})
	if got := cisco(d); strings.Count(got, "192.0.2.1 0.0.0.0") != 1 || !strings.Contains(got, "  permit 192.0.2.1 0.0.0.0\n  permit 10.0.0.0 0.255.255.255\n") {
		t.Errorf("cisco, listed already:\n%s", got)
	}
	if got := juniper(d); strings.Count(got, permitSrc+"192.0.2.1/32\n") != 1 || strings.Index(got, "192.0.2.1/32") > strings.Index(got, "10.0.0.0/8") {
		t.Errorf("junos, listed already:\n%s", got)
	}

	// An address that is not known, an empty list: no server entry, and no
	// block for an empty list (the server alone would lock everyone else out).
	d = mgmtData(t, UnknownServer, "", []string{"10.0.0.0/8"}, SNMPInput{})
	if got := cisco(d); strings.Count(got, "permit ") != 1 {
		t.Errorf("cisco, no address:\n%s", got)
	}
	d = mgmtData(t, "192.0.2.1", "", nil, SNMPInput{})
	if got := cisco(d); strings.Contains(got, "permit") || !strings.Contains(got, "not emitted") {
		t.Errorf("cisco, empty list:\n%s", got)
	}
	if got := juniper(d); strings.Contains(got, "permit-mgmt") || !strings.Contains(got, "mgmt-acl empty") {
		t.Errorf("junos, empty list:\n%s", got)
	}
}

// B3: with a management filter and SNMP configured the filter carries a
// udp port 161 term built from the SNMP client list (the server, then the
// scope's ranges), ahead of the default-accept; the v3 text says the filter
// is the restriction. Without SNMP, or without a filter, there is no term
// and the text says v3 is not restricted.
func TestJunosFilterRestrictsUDP161(t *testing.T) {
	v3 := SNMPInput{Version: "v3", V3User: "monitor", V3Auth: "sha", V3Priv: "aes128", V3AuthPass: "authpass-123", V3PrivPass: "privpass-123",
		Ranges: []string{"198.51.100.0/24"}}
	v2c := SNMPInput{Version: "v2c", Community: "public-ro", Ranges: []string{"198.51.100.0/24"}}
	f := "set firewall family inet filter MGMT-ACL term "
	vars := func(d Data) map[string]string {
		return JuniperVars(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, d)
	}
	for name, in := range map[string]SNMPInput{"v3": v3, "v2c": v2c} {
		got := vars(mgmtData(t, "192.0.2.1", "", []string{"10.0.0.0/8"}, in))["MGMT_ACL_BLOCK"]
		for _, want := range []string{
			f + "permit-snmp from source-address 192.0.2.1/32\n",
			f + "permit-snmp from source-address 198.51.100.0/24\n",
			f + "permit-snmp from protocol udp\n", f + "permit-snmp from destination-port snmp\n", f + "permit-snmp then accept\n",
			f + "deny-snmp from protocol udp\n", f + "deny-snmp from destination-port snmp\n", f + "deny-snmp then log\n", f + "deny-snmp then discard\n",
		} {
			if !strings.Contains(got, want) {
				t.Errorf("%s: lacks %q:\n%s", name, want, got)
			}
		}
		// Ahead of the default-accept, after the ssh/830 terms.
		if i, j, k := strings.Index(got, "deny-mgmt then"), strings.Index(got, "permit-snmp from source-address"), strings.Index(got, "default-accept then accept"); i >= j || j >= k {
			t.Errorf("%s: order of the terms (deny-mgmt %d, permit-snmp %d, default-accept %d):\n%s", name, i, j, k, got)
		}
		// Only udp 161 is matched: nothing for the routing protocols.
		for _, l := range strings.Split(got, "\n") {
			if strings.Contains(l, "-snmp ") && !strings.HasPrefix(l, "#") && strings.Contains(l, "destination-port") && !strings.HasSuffix(l, "snmp") {
				t.Errorf("%s: a term that is not snmp: %q", name, l)
			}
		}
	}

	// v3's text: the filter is the restriction, only when it is rendered.
	with := vars(mgmtData(t, "192.0.2.1", "", []string{"10.0.0.0/8"}, v3))["SNMP_BLOCK"]
	if !strings.Contains(with, "permit-snmp and deny-snmp terms accept udp port 161 from the") || strings.Contains(with, "not restricted to the clients above") {
		t.Errorf("v3 with a filter:\n%s", with)
	}
	without := vars(mgmtData(t, "192.0.2.1", "", nil, v3))
	if !strings.Contains(without["SNMP_BLOCK"], "a v3 user is\n# not restricted to the clients above.") || strings.Contains(without["MGMT_ACL_BLOCK"], "permit-snmp") {
		t.Errorf("v3 without a filter:\n%s\n%s", without["SNMP_BLOCK"], without["MGMT_ACL_BLOCK"])
	}
	// SNMP not configured: no term.
	if got := vars(mgmtData(t, "192.0.2.1", "", []string{"10.0.0.0/8"}, SNMPInput{}))["MGMT_ACL_BLOCK"]; strings.Contains(got, "snmp") {
		t.Errorf("an snmp term without SNMP:\n%s", got)
	}
}

// B2: a credential already stored that a CLI would misread (a blank, '?', a
// quote, too long) is rendered as a commented NOT SET line with the command
// that sets it again, never as a line to paste.
func TestSNMPCredentialsAMisreadingCLIIsNeverPasted(t *testing.T) {
	long := strings.Repeat("c", 33)
	for _, c := range []struct{ name, community string }{{"blank", "pub lic"}, {"question mark", "pub?lic"}, {"quote", `pub"lic`}, {"too long", long}, {"control", "pub\tlic"}} {
		in := SNMPInput{Scope: "lab", Version: "v2c", Community: c.community, Server: "192.0.2.1", Contact: "x", Location: "y"}
		for vendor, block := range map[string]SNMPBlock{"cisco": CiscoSNMP(in), "juniper": JuniperSNMP(in), "wti": WTISNMP(in)} {
			if strings.Contains(block.Text, c.community) && !strings.Contains(block.Text, "NOT SET") {
				t.Errorf("%s, %s community pasted:\n%s", vendor, c.name, block.Text)
			}
			for _, l := range strings.Split(block.Text, "\n") {
				if strings.Contains(l, c.community) && !strings.HasPrefix(strings.TrimSpace(l), "#") && !strings.HasPrefix(strings.TrimSpace(l), "!") {
					t.Errorf("%s, %s: a live line holds it: %q", vendor, c.name, l)
				}
			}
			if !strings.Contains(block.Text, "NOT SET: tacctl scope snmp lab community") && vendor != "wti" {
				t.Errorf("%s, %s: no way to set it again:\n%s", vendor, c.name, block.Text)
			}
			if len(block.Unfilled) == 0 || block.Unfilled[len(block.Unfilled)-1].What == "" {
				t.Errorf("%s, %s: not listed as unfilled: %+v", vendor, c.name, block.Unfilled)
			}
		}
	}
	// v3: the user, either passphrase.
	for _, bad := range []SNMPInput{
		{V3User: "mon?tor", V3AuthPass: "authpass-123", V3PrivPass: "privpass-123"},
		{V3User: "monitor", V3AuthPass: "auth pass-123", V3PrivPass: "privpass-123"},
		{V3User: "monitor", V3AuthPass: "authpass-123", V3PrivPass: `priv"pass-123`},
	} {
		bad.Scope, bad.Version, bad.Server = "lab", "v3", "192.0.2.1"
		for vendor, block := range map[string]SNMPBlock{"cisco": CiscoSNMP(bad), "juniper": JuniperSNMP(bad)} {
			if strings.Contains(block.Text, "usm local-engine user") && !strings.Contains(block.Text, "# set snmp v3 usm") ||
				strings.Contains(block.Text, "\nsnmp-server user") {
				t.Errorf("%s: a v3 line is pasted for %+v:\n%s", vendor, bad, block.Text)
			}
			if !strings.Contains(block.Text, "NOT SET: tacctl scope snmp lab v3-user") {
				t.Errorf("%s: no way to set it again:\n%s", vendor, block.Text)
			}
		}
	}
	// A description with '?' (stored before the setters refused it) is
	// commented in the Junos step, whatever else is set.
	in := SNMPInput{Scope: "lab", Version: "v2c", Community: "public-ro", Server: "192.0.2.1", Description: "core? router"}
	if got := JuniperSNMP(in).Text; strings.Contains(got, "\nset snmp description") || !strings.Contains(got, "# set snmp description \"core? router\"   (NOT SET: the description holds '?'") {
		t.Errorf("description with '?':\n%s", got)
	}
}
