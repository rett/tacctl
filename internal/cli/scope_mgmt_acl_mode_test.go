package cli

// 'scope mgmt-acl <scope> mode' (0.2.20): the Junos management filter's
// deny-by-default mode as a per-scope setting.

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

func TestScopeMgmtACLModeShowsAndSets(t *testing.T) {
	sb := newSandbox(t, true)
	mode := func(args ...string) string {
		return plain(sb.run("", append([]string{"scope", "mgmt-acl", "lab", "mode"}, args...)))
	}
	// the default is ssh-only, shown without a write
	out := mode()
	for _, want := range []string{"Scope 'lab' management filter mode: ssh-only", "Source: default",
		"only affects Junos devices", "Usage: tacctl scope mgmt-acl lab mode [ssh-only|strict]"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if sb.code != 0 || strings.Contains(sb.overrides(), "scope_mgmt_acl") {
		t.Errorf("show: exit %d, wrote %q", sb.code, sb.overrides())
	}
	// strict is stored and says what stops, and that it is Junos only
	out = mode("strict")
	for _, want := range []string{"management filter mode set to strict (Junos devices only).", "no default-accept term",
		"BGP, OSPF, LDP, VRRP, BFD", "does not affect IS-IS (it is not carried over IP)", "stops nor permits it", "(the SNMP clients still poll)", "replies from servers not in the list: TACACS+ and RADIUS", "NTP, syslog and DHCP", "SNMP from sources outside the list",
		"The permit list is empty", "Keep a console session open", "commit confirmed", "Cisco VTY-ACL and WTI IP Tables lists are the same"} {
		if !strings.Contains(out, want) {
			t.Errorf("set strict lacks %q:\n%s", want, out)
		}
	}
	if sb.code != 0 || !strings.HasSuffix(sb.overrides(), "\nscope_mgmt_acl:\n  mode:\n    lab: strict\n") {
		t.Errorf("set strict: exit %d, tacctl.yaml %q", sb.code, sb.overrides())
	}
	out = mode()
	if !strings.Contains(out, "mode: strict") || !strings.Contains(out, "Source: set (tacctl.yaml: scope_mgmt_acl.mode.lab)") {
		t.Errorf("show after set:\n%s", out)
	}
	// with a permit list the empty-list line is not said
	sb.run("", []string{"scope", "mgmt-acl", "lab", "add", "10.0.0.0/8"})
	mode("ssh-only")
	out = mode("strict")
	if strings.Contains(out, "The permit list is empty") {
		t.Errorf("empty-list line with a list:\n%s", out)
	}
	// a list none of whose entries permits ssh renders no filter: the setter says so
	sb.run("y\n", []string{"scope", "mgmt-acl", "lab", "clear"})
	sb.run("", []string{"scope", "mgmt-acl", "lab", "add", "198.51.100.0/24:udp/161"})
	mode("ssh-only")
	out = mode("strict")
	if !strings.Contains(out, "No IPv4 entry of the permit list permits ssh") || strings.Contains(out, "The permit list is empty") {
		t.Errorf("no ssh entry:\n%s", out)
	}
	sb.run("", []string{"scope", "mgmt-acl", "lab", "add", "10.0.0.0/8"})
	mode("ssh-only")
	if out = mode("strict"); strings.Contains(out, "No IPv4 entry of the permit list permits ssh") {
		t.Errorf("a plain entry permits ssh:\n%s", out)
	}
	// the same mode again changes nothing
	before := sb.overrides()
	out = mode("strict")
	if sb.code != 0 || !strings.Contains(out, "mode is already strict.") || sb.overrides() != before {
		t.Errorf("strict again: exit %d %q", sb.code, out)
	}
	// ssh-only removes the key (only strict is stored)
	out = mode("ssh-only")
	if sb.code != 0 || !strings.Contains(out, "mode set to ssh-only (Junos devices only).") || !strings.Contains(out, "default-accept term again") ||
		strings.Contains(sb.overrides(), "mode:") {
		t.Errorf("ssh-only: exit %d %q, tacctl.yaml %q", sb.code, out, sb.overrides())
	}
	out = mode("ssh-only")
	if sb.code != 0 || !strings.Contains(out, "mode is already ssh-only.") {
		t.Errorf("ssh-only again: exit %d %q", sb.code, out)
	}
	// one scope's mode is not another's
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "strict"})
	out = plain(sb.run("", []string{"scope", "mgmt-acl", "prod", "mode"}))
	if !strings.Contains(out, "Scope 'prod' management filter mode: ssh-only") {
		t.Errorf("prod:\n%s", out)
	}
}

func TestScopeMgmtACLModeRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "strict"})
	before := sb.overrides()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"scope", "mgmt-acl", "lab", "mode", "lax"}, 1, "Unknown mode 'lax'. Use: ssh-only | strict."},
		{[]string{"scope", "mgmt-acl", "lab", "mode", "STRICT"}, 1, "Unknown mode 'STRICT'"},
		{[]string{"scope", "mgmt-acl", "lab", "mode", "deny"}, 1, "Unknown mode 'deny'"},
		{[]string{"scope", "mgmt-acl", "nosuch", "mode", "strict"}, 1, "nosuch"},
		{[]string{"scope", "mgmt-acl", "lab", "mode", "strict", "extra"}, 1, "Unknown argument: 'extra'"},
		{[]string{"scope", "mgmt-acl", "lab", "mode", "ssh-only", "extra"}, 1, "Usage: tacctl scope mgmt-acl lab mode [ssh-only|strict]"},
		{[]string{"scope", "mgmt-acl", "lab", "mode", "lax", "extra"}, 1, "Unknown argument: 'extra'"},
	} {
		sb.run("", c.args)
		if sb.code != c.code || !strings.Contains(sb.stderr()+plain(sb.out.String()), c.want) {
			t.Errorf("%v: exit %d (want %d), stdout %q stderr %q", c.args, sb.code, c.code, sb.out.String(), sb.stderr())
		}
	}
	if sb.overrides() != before {
		t.Errorf("a refused call wrote tacctl.yaml:\n%s", sb.overrides())
	}
	// the unknown-subcommand answer points at the help of the command
	sb.run("", []string{"scope", "mgmt-acl", "lab", "frob"})
	if !strings.Contains(sb.stderr(), "Unknown subcommand: 'frob'\nRun 'tacctl scope mgmt-acl -h' for usage.") {
		t.Errorf("unknown subcommand: %q", sb.stderr())
	}
	// a mode that is no mode in the file is reported by 'config validate'
	sb.write("state/tacctl.yaml", "scope_mgmt_acl:\n  mode:\n    lab: lax\n", 0o640)
	sb.run("", []string{"config", "validate"})
	if !strings.Contains(plain(sb.out.String()+sb.err.String()), "scope_mgmt_acl.mode.lab: must be one of: ssh-only, strict") {
		t.Errorf("config validate:\n%s%s", sb.out.String(), sb.err.String())
	}
}

// An engineer reads the mode of a scope of their own and nothing else of the
// family: the setter, the permit list and the names are refused with the
// superuser's message, another scope does not exist for them, and nothing is
// written. The tiers below the engineer have no row.
func TestScopeMgmtACLEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "strict"})
	sb.run("", []string{"scope", "mgmt-acl", "lab", "add", "10.0.0.0/8"})
	before := sb.overrides()
	out := sb.asEngineer("", "scope", "mgmt-acl", "lab", "mode")
	if sb.code != 0 || !strings.Contains(out, "Scope 'lab' management filter mode: strict") || !strings.Contains(out, "Setting it is the superuser's.") ||
		strings.Contains(out, "Usage: tacctl scope mgmt-acl") {
		t.Errorf("the engineer's read: exit %d\n%s%s", sb.code, out, sb.stderr())
	}
	if len(centralLines(sb.runner)) != 0 {
		t.Errorf("a read wrote audit lines: %q", centralLines(sb.runner))
	}
	// the other scope is not found, for the read and for everything else
	for _, args := range [][]string{{"mode"}, {"mode", "strict"}, {"list"}, {"add", "10.1.0.0/16"}, {"cisco-name", "X"}} {
		sb.asEngineer("x\n", append([]string{"scope", "mgmt-acl", "prod"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'prod' does not exist.") || strings.Contains(sb.stderr(), "Available") {
			t.Errorf("prod %v: exit %d %q", args, sb.code, sb.stderr())
		}
	}
	sb.asEngineer("", "scope", "mgmt-acl", "nosuch", "mode")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'nosuch' does not exist.") {
		t.Errorf("nosuch: exit %d %q", sb.code, sb.stderr())
	}
	// the setter and every other verb of the family are the superuser's
	for _, args := range [][]string{{"mode", "ssh-only"}, {"mode", "strict"}, {"mode", "lax"}, {"mode", "ssh-only", "extra"}, {"mode", ""},
		{}, {"list"}, {"add", "10.1.0.0/16"}, {"remove", "10.0.0.0/8"}, {"clear"}, {"cisco-name"}, {"juniper-name", "X"}, {"help"}, {"frob"}} {
		sb.asEngineer("y\n", append([]string{"scope", "mgmt-acl", "lab"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads the management filter mode of a scope: tacctl scope mgmt-acl lab mode. "+
			"The permit list, the ACL and filter names and setting the mode are the superuser's. Nothing was changed.") {
			t.Errorf("%v: exit %d %q", args, sb.code, sb.stderr())
		}
		if sb.overrides() != before {
			t.Errorf("%v changed tacctl.yaml:\n%s", args, sb.overrides())
		}
	}
	// the tiers below the engineer have no row; the engineer's has its note
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator} {
		if tier.Permits(tr, "scope", "mgmt-acl") {
			t.Errorf("%s may run scope mgmt-acl", tr)
		}
	}
	if !tier.Permits(tier.Engineer, "scope", "mgmt-acl") || !strings.Contains(tierNotes["scope mgmt-acl"], "an engineer may read the management filter mode of a scope of their own") {
		t.Errorf("the engineer's row or its note: %q", tierNotes["scope mgmt-acl"])
	}
	// the superuser still sets it
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "ssh-only"})
	if sb.code != 0 || strings.Contains(sb.overrides(), "mode:") {
		t.Errorf("the superuser: exit %d\n%s", sb.code, sb.overrides())
	}
}

// The walkthrough follows the mode, for Junos only: the ssh-only output is
// what it was before the setting, the strict one has no default-accept term,
// and Cisco and WTI do not change.
func TestWalkthroughFollowsTheMgmtACLMode(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"config", "mgmt-acl", "add", "10.99.0.0/24,198.51.100.0/24:tcp/22,udp/161"}, route)
	juniper := func() string {
		return plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab"}, route))
	}
	cisco := func() string { return plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route)) }
	wti := func() string { return plain(sb.cfgRun("", []string{"config", "wti", "--scope", "lab"}, route)) }
	sshOnlyJ, sshOnlyC, sshOnlyW := juniper(), cisco(), wti()
	if !strings.Contains(sshOnlyJ, "term default-accept then accept") || !strings.Contains(sshOnlyJ, "term deny-mgmt then discard") {
		t.Fatalf("the ssh-only walkthrough:\n%s", sshOnlyJ)
	}
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "strict"})
	strictJ := juniper()
	for _, want := range []string{"# Deny-by-default management filter (mgmt-acl mode strict; Junos only).",
		"term permit-mgmt from source-address 10.99.0.0/24\n", "term permit-mgmt then accept\n",
		"term permit-tcp-22 from source-address 198.51.100.0/24\n", "term permit-udp-161 from destination-port snmp\n",
		"\n# set interfaces lo0 unit 0 family inet filter input MGMT-ACL\n"} {
		if !strings.Contains(strictJ, want) {
			t.Errorf("the strict walkthrough lacks %q:\n%s", want, strictJ)
		}
	}
	for _, l := range strings.Split(strictJ, "\n") {
		if strings.HasPrefix(l, "set ") && (strings.Contains(l, "default-accept") || strings.Contains(l, "deny-mgmt")) {
			t.Errorf("the strict walkthrough has %q", l)
		}
	}
	if c := cisco(); c != sshOnlyC {
		t.Errorf("the Cisco walkthrough changed with the mode:\n%s", c)
	}
	if w := wti(); w != sshOnlyW {
		t.Errorf("the WTI walkthrough changed with the mode:\n%s", w)
	}
	// --server names the server the device authenticates against: the strict
	// filter, which ends in the discard, accepts its replies, and only those
	withServer := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--server", "198.51.100.9"}, route))
	if !strings.Contains(withServer, "set system tacplus-server 198.51.100.9 ") || !strings.Contains(withServer, "term permit-auth-replies from source-address 198.51.100.9/32\n") ||
		!strings.Contains(withServer, "term permit-auth-replies from source-port tacacs\n") || !strings.Contains(withServer, "term permit-auth-replies from tcp-established\n") || strings.Contains(withServer, "term permit-mgmt from source-address 198.51.100.9/32\n") {
		t.Errorf("--server in the strict walkthrough:\n%s", withServer)
	}
	// another scope keeps its filter
	prod := plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "prod"}, route))
	if !strings.Contains(prod, "term default-accept then accept") {
		t.Errorf("prod is not ssh-only:\n%s", prod)
	}
	// back: byte for byte what it was
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "ssh-only"})
	if got := juniper(); got != sshOnlyJ {
		t.Errorf("ssh-only after strict differs from before:\n%s", got)
	}
}

// 'device config plan' follows the scope's mode end to end: a device that
// holds the ssh-only filter, applied on lo0, is planned to the strict one
// when the scope says strict (with the traffic that stops in the report and
// the lock-out check on --from), and back, and a device that agrees plans
// nothing in either mode.
func TestPlanFollowsTheMgmtACLMode(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.run("scope", "mgmt-acl", "lab", "add", "10.0.0.0/8,198.51.100.0/24:tcp/22,udp/161")
	text := b.expected("lab-j") + "set interfaces lo0 unit 0 family inet filter input MGMT-ACL\n"
	b.serve("juniper", text)
	b.servePlain(text)
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	plan := func(args ...string) string {
		return b.run(append([]string{"device", "config", "plan", "lab-j", "--section", "mgmt-acl"}, args...)...)
	}
	out := plan()
	if b.sb.code != 0 || strings.Contains(out, "PASTE FROM HERE") {
		t.Fatalf("a device that agrees (ssh-only): exit %d\n%s", b.sb.code, out)
	}

	b.run("scope", "mgmt-acl", "lab", "mode", "strict")
	out = plan("--from", "10.0.0.5")
	flat := unwrapPlan(out)
	if b.sb.code != 0 {
		t.Fatalf("the move to strict: exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"##### PASTE FROM HERE: lab-j #####", "delete firewall family inet filter MGMT-ACL term default-accept\n",
		"delete firewall family inet filter MGMT-ACL term deny-mgmt\n", "set firewall family inet filter MGMT-ACL term permit-udp-161 then accept\n",
		"WARNING: the management filter of 'lab' is strict: it has no default-accept term. The device applies it to lo0 already, so from the commit",
		"BGP, OSPF, LDP, VRRP, BFD", "does not affect IS-IS (it is not carried over IP)", "(the SNMP clients still poll)", "TACACS+ and RADIUS replies from servers that are not in the list", "NTP, syslog and DHCP", "SNMP from sources outside the list"} {
		if !strings.Contains(out, want) && !strings.Contains(flat, want) {
			t.Errorf("the plan lacks %q:\n%s", want, out)
		}
	}
	planGolden(t, "junos-mgmt-strict.out", out)
	// the lock-out check: an address inside a term that holds tcp/22 is
	// accepted for ssh, one outside the list is refused
	out = plan("--from", "198.51.100.9")
	if b.sb.code != 0 || !strings.Contains(out, "term permit-tcp-22 then accept") {
		t.Errorf("--from inside the service term: exit %d\n%s", b.sb.code, out)
	}
	out = plan("--from", "203.0.113.5")
	if b.sb.code == 0 || !strings.Contains(unwrapPlan(out+b.sb.stderr()), "is not inside a source of the rendered strict filter that is accepted for ssh") {
		t.Errorf("--from outside: exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}

	// the paste is made: the device holds the strict filter, and nothing is left to plan
	text = b.expected("lab-j") + "set interfaces lo0 unit 0 family inet filter input MGMT-ACL\n"
	b.serve("juniper", text)
	b.servePlain(text)
	b.run("device", "config", "pull", "lab-j")
	if out = plan("--from", "10.0.0.5"); b.sb.code != 0 || strings.Contains(out, "PASTE FROM HERE") || strings.Contains(out, "WARNING: the management filter") {
		t.Errorf("a device that agrees (strict): exit %d\n%s", b.sb.code, out)
	}

	// and back: the scope says ssh-only, the device holds strict
	b.run("scope", "mgmt-acl", "lab", "mode", "ssh-only")
	out = plan("--from", "10.0.0.5")
	if b.sb.code != 0 {
		t.Fatalf("the move back: exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	for _, want := range []string{"set firewall family inet filter MGMT-ACL term default-accept then accept\n",
		"delete firewall family inet filter MGMT-ACL term permit-udp-161\n", "has no default-accept term, so it drops by default",
		"tacctl scope mgmt-acl lab mode strict"} {
		if !strings.Contains(out, want) && !strings.Contains(unwrapPlan(out), want) {
			t.Errorf("the plan back lacks %q:\n%s", want, out)
		}
	}
	planGolden(t, "junos-mgmt-sshonly.out", out)
}

// The setter says which permit list the scope renders from, and that the first
// entry added to the scope's own list replaces the global one for it, so that
// the advice to add a neighbour does not silently cut the global subnets off.
func TestScopeMgmtACLModeSaysWhichListIsUsed(t *testing.T) {
	sb := newSandbox(t, true)
	sb.runFamily("", configMgmtACLCmd, "config", "mgmt-acl", "add", "10.0.0.0/8,192.0.2.0/24")
	out := plain(sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "strict"}))
	for _, want := range []string{"This scope renders from the global permit list (mgmt_acl.permits, 2 entries).",
		"The first entry added with", "'tacctl scope mgmt-acl lab add' replaces it for this scope", "global subnets lose access"} {
		if !strings.Contains(out, want) {
			t.Errorf("global list: lacks %q:\n%s", want, out)
		}
	}
	sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "ssh-only"})
	sb.run("", []string{"scope", "mgmt-acl", "lab", "add", "198.51.100.0/24"})
	out = plain(sb.run("", []string{"scope", "mgmt-acl", "lab", "mode", "strict"}))
	if !strings.Contains(out, "This scope renders from its own permit list (1 entry).") || strings.Contains(out, "replaces it for this scope") {
		t.Errorf("own list:\n%s", out)
	}
}
