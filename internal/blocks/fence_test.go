package blocks

import (
	"strings"
	"testing"
)

// A block holds the statements of its own hierarchy and nothing else: a
// Junos system block only 'set|delete system ...', a Junos snmp block only
// 'set|delete snmp ...', and the IOS blocks only their own families of lines.
// Anything else, on a line of its own or smuggled onto the line of a valid
// statement, is an error finding, so the block is refused at edit and check
// time and never rendered in part (policy.blockFindingsError).
func TestABlockHoldsOnlyItsOwnHierarchy(t *testing.T) {
	type c struct{ vendor, block, text, why string }
	bad := []c{
		{"juniper", "system", "set snmp community public authorization read-only\n", "another hierarchy"},
		{"juniper", "system", "delete snmp community public\n", "another hierarchy, delete"},
		{"juniper", "system", "set interfaces ge-0/0/0 description x\n", "another hierarchy"},
		{"juniper", "system", "delete interfaces\n", "another hierarchy, delete"},
		{"juniper", "system", "set system services ssh\n", "a system child the block does not manage"},
		{"juniper", "system", "set system host-name x\n", "a system child the block does not manage"},
		{"juniper", "system", "set system login user bob class super-user\n", "login beyond the message"},
		{"juniper", "system", "deactivate system ntp\n", "a verb the block does not know"},
		{"juniper", "system", "set system-services ssh\n", "a root that only starts like the block's"},
		{"juniper", "system", "delete system-services\n", "a root that only starts like the block's, delete"},
		{"juniper", "snmp", "set snmp-trap x\n", "a root that only starts like the block's"},
		{"juniper", "snmp", "set snmpv3 x\n", "a root that only starts like the block's"},
		{"juniper", "system", "set system time-zone UTC set interfaces ge-0/0/0\n", "a second statement on the line"},
		{"juniper", "system", "set system time-zone UTC; set interfaces ge-0/0/0\n", "a semicolon"},
		{"juniper", "system", "set system time-zone UTC | run show version\n", "a pipe"},
		{"juniper", "system", "set system name-server 192.0.2.1 set snmp community x\n", "a second statement on the line"},
		{"juniper", "system", "set system ntp server 192.0.2.1 key 1 ; delete interfaces\n", "a semicolon"},
		{"juniper", "system", "set system login message <<'EOF'\nhello\nEOF\nset interfaces x\n", "a statement after the message"},
		{"juniper", "snmp", "set system ntp server 192.0.2.1\n", "another hierarchy"},
		{"juniper", "snmp", "delete system\n", "another hierarchy, delete"},
		{"juniper", "snmp", "set snmp community public authorization read-only\ndelete interfaces\n", "a second line of another hierarchy"},
		{"juniper", "snmp", "deactivate snmp\n", "a verb the block does not know"},
		{"juniper", "snmp", "set snmp trap-group x targets 192.0.2.1\nrun show version\n", "an operational command"},
		{"juniper", "snmp", "set snmp trap-options source-address 192.0.2.7; set system host-name x\n", "a semicolon"},
		{"juniper", "snmp", "set snmp community example-ro authorization read-only set interfaces y\n", "a second statement on the line"},
		{"cisco", "system", "interface Gi0/1\n description x\n", "an interface"},
		{"cisco", "system", "snmp-server community public RO\n", "another block's line"},
		{"cisco", "system", "username bob privilege 15 secret x\n", "a user"},
		{"cisco", "system", "no router bgp 65000\n", "a routing process"},
		{"cisco", "system", "ntp server 192.0.2.1\n!\nhostname evil\n", "a line after a comment"},
		{"cisco", "system", "banner login <<'EOF'\ntext\nEOF\nusername bob secret x\n", "a statement after the banner"},
		{"cisco", "system", "clock timezone UTC 0; hostname x\n", "a semicolon"},
		{"cisco", "snmp", "ntp server 192.0.2.1\n", "another block's line"},
		{"cisco", "snmp", "hostname x\n", "the host name"},
		{"cisco", "snmp", "no interface Gi0/1\n", "an interface"},
		{"cisco", "snmp", "snmp-server community public RO\nrouter bgp 65000\n", "a routing process after a valid line"},
		{"cisco", "snmp", "snmp-server location rack\nexit\ninterface Gi0/1\n", "an interface after a valid line"},
		{"cisco", "snmp", "snmp-server location rack ! ntp server 1.1.1.1\n", "a second statement on the line"},
	}
	for _, x := range bad {
		_, fs, err := LintFor(x.vendor, x.block, x.text, LayerScope)
		if err != nil || !HasErrors(fs) {
			t.Errorf("%s %s block, %s: %q was accepted (err %v)", x.vendor, x.block, x.why, x.text, err)
		}
	}

	// the statements of a valid Junos block stay under the block's own root
	for _, x := range []struct{ block, root, text string }{
		{"system", "system", "set system time-zone UTC\nset system name-server 192.0.2.53\ndelete system ntp server 192.0.2.1\nset system ntp server 192.0.2.123 prefer\nset system domain-name example.net\n"},
		{"snmp", "snmp", "set snmp community example-ro authorization read-only\nset snmp community example-ro clients 192.0.2.0/24\n"},
	} {
		doc, fs, err := LintFor("juniper", x.block, x.text, LayerScope)
		if err != nil || HasErrors(fs) {
			t.Fatalf("%s: %v %v", x.block, err, fs)
		}
		sts := StatementsOf(doc)
		if len(sts) == 0 {
			t.Errorf("%s: no statements from %q", x.block, x.text)
		}
		for _, s := range sts {
			if f := strings.Fields(s); len(f) < 2 || (f[0] != "set" && f[0] != "delete") || f[1] != x.root {
				t.Errorf("%s block produced a statement outside its hierarchy: %q", x.block, s)
			}
		}
	}
}
