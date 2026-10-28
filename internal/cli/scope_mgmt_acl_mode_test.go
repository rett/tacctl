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
		"BGP, OSPF, IS-IS, VRRP, LDP", "NTP, syslog and DHCP", "SNMP from sources outside the list",
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
	// the unknown-subcommand answer names the verb
	sb.run("", []string{"scope", "mgmt-acl", "lab", "frob"})
	if !strings.Contains(sb.stderr(), "Use: list | add | remove | clear | cisco-name | juniper-name | mode.") {
		t.Errorf("unknown subcommand: %q", sb.stderr())
	}
	// a mode that is no mode in the file is reported by 'config validate'
	sb.write("state/tacctl.yaml", "scope_mgmt_acl:\n  mode:\n    lab: lax\n", 0o640)
	sb.run("", []string{"config", "validate"})
	if !strings.Contains(plain(sb.out.String()+sb.err.String()), "scope_mgmt_acl.mode.lab: must be one of: ssh-only, strict") {
		t.Errorf("config validate:\n%s%s", sb.out.String(), sb.err.String())
	}
}

// The setter is the superuser's like every verb of scope mgmt-acl: no tier
// below it has a row for the family.
func TestScopeMgmtACLModeIsTheSuperusers(t *testing.T) {
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer} {
		if tier.Permits(tr, "scope", "mgmt-acl") {
			t.Errorf("%s may run scope mgmt-acl", tr)
		}
	}
	if !tier.Permits(tier.Superuser, "scope", "mgmt-acl") {
		t.Error("the superuser may not run scope mgmt-acl")
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
