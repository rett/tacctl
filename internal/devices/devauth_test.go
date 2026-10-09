package devices

// 0.2.2 (docs/plans/0.2.2-plan.md §6.4-6.6): per-level Cisco authorization
// and accounting with the D16 guard, privilege modes, the server's Junos
// rules per class (D6) and ENG-CLASS (D20), the WTI Service Name and
// per-group levels (D4).

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
)

// fixtureGroups is fixture with store.multiscope.yaml's groups plus extra
// (store lines such as "  helpdesk: {priv_lvl: 5, juniper_class: OP-CLASS}").
func fixtureGroups(t *testing.T, extra []string, overrides string) (*model.Model, *conf.Config) {
	t.Helper()
	b, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Replace(string(b), "groups:\n", "groups:\n"+strings.Join(extra, "\n")+"\n", 1)
	if len(extra) == 0 {
		text = string(b)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "store.yaml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := model.LoadStore(filepath.Join(dir, "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "tacctl.yaml")
	if err := os.WriteFile(p, []byte(overrides), 0o600); err != nil {
		t.Fatal(err)
	}
	return m, conf.Load(p, []string{"tacacs", "radius"})
}

func renderText(t *testing.T, req Request, d Data) string {
	t.Helper()
	if req.Source == "" {
		req.Source = SourceDefault
	}
	var buf bytes.Buffer
	if err := Render(&buf, req, d); err != nil {
		t.Fatal(err)
	}
	return reANSI.ReplaceAllString(buf.String(), "")
}

func TestCiscoLevelsGuardAndAccounting(t *testing.T) {
	m, c := fixtureGroups(t, []string{
		"  helpdesk: {priv_lvl: 5, juniper_class: OP-CLASS}",
		"  noc: {priv_lvl: 5, juniper_class: OP-CLASS}",
		"  netops: {priv_lvl: 12, juniper_class: OP-CLASS}",
	}, "commands:\n  netops:\n  - {name: '*', action: permit}\naaa:\n  order:\n    lab: local-first\n")
	vars := CiscoVars(Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c})
	want := "! Per-command authorization (managed by 'tacctl group commands'): one line per\n" +
		"! privilege level in use; the server decides each command, including configuration\n" +
		"! commands, which IOS sends as ordinary commands.\n" +
		"aaa authorization commands 1 default local group TACACS-GROUP\n" +
		"! aaa authorization commands 5 default local group TACACS-GROUP   ! NOT emitted: groups 'helpdesk', 'noc' have no command rules and would be denied every command; run 'tacctl group commands default <group> permit' for each\n" +
		"aaa authorization commands 7 default local group TACACS-GROUP\n" +
		"aaa authorization commands 12 default local group TACACS-GROUP\n" +
		"aaa authorization commands 15 default local group TACACS-GROUP\n" +
		"aaa authorization config-commands\n" +
		"! aaa authorization console   ! uncomment to have the console line ask the server too"
	if vars["AUTHZ_COMMANDS_BLOCK"] != want {
		t.Errorf("authz:\n%s\nwant:\n%s", vars["AUTHZ_COMMANDS_BLOCK"], want)
	}
	acct := "aaa accounting commands 1 default start-stop group TACACS-GROUP\n" +
		"aaa accounting commands 5 default start-stop group TACACS-GROUP\n" +
		"aaa accounting commands 7 default start-stop group TACACS-GROUP\n" +
		"aaa accounting commands 12 default start-stop group TACACS-GROUP\n" +
		"aaa accounting commands 15 default start-stop group TACACS-GROUP"
	if vars["ACCT_COMMANDS_BLOCK"] != acct {
		t.Errorf("acct:\n%s", vars["ACCT_COMMANDS_BLOCK"])
	}

	// One group without rules: named alone, with its own fix.
	m, c = fixtureGroups(t, []string{"  helpdesk: {priv_lvl: 5, juniper_class: OP-CLASS}"}, "")
	vars = CiscoVars(Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c})
	if !strings.Contains(vars["AUTHZ_COMMANDS_BLOCK"], "! aaa authorization commands 5 default group TACACS-GROUP local   ! NOT emitted: group 'helpdesk' has no command rules and would be denied every command; run 'tacctl group commands default helpdesk permit'\n") {
		t.Error(vars["AUTHZ_COMMANDS_BLOCK"])
	}
	// The templates take the accounting lines from the variable, legacy too;
	// the notes name the priv-15 fallback and the console line.
	for _, legacy := range []bool{false, true} {
		out := renderText(t, Request{Vendor: "cisco", Scope: "lab", Legacy: legacy, Protocol: TACACS}, Data{Model: m, Conf: c, ServerIP: "x"})
		for _, want := range []string{
			"aaa accounting exec default start-stop group TACACS-GROUP\naaa accounting commands 1 default start-stop group TACACS-GROUP\naaa accounting commands 5 ",
			"  - A group at priv-lvl 15 is kept apart from the superusers only by the server's\n",
			"    unless 'aaa authorization console' is uncommented\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("legacy=%v lacks %q", legacy, want)
			}
		}
	}
}

func TestCiscoPrivilegeModes(t *testing.T) {
	m, c := fixtureGroups(t, nil, "privileges:\n  operator:\n  - 'configure: router bgp'\n  - 'exec all: show ip'\n  - show version\n  - 'exec: show version'\n  - 'configure all: interface'\n")
	vars := CiscoVars(Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c})
	// readonly (priv-lvl 1) lowers show running-config to level 1; the
	// block of a group at level 1 is emitted too.
	want := "! --- readonly — Privilege Level 1 Commands ---\n" +
		"privilege exec level 1 show running-config\n!\n" +
		"! --- operator — Privilege Level 7 Commands ---\n" +
		"privilege configure level 7 router bgp\n" +
		"privilege exec all level 7 show ip\n" +
		"privilege exec level 7 show version\n" +
		"privilege configure all level 7 interface\n!\n"
	if vars["PRIVILEGE_COMMANDS"] != want {
		t.Errorf("got:\n%s", vars["PRIVILEGE_COMMANDS"])
	}
}

func TestJuniperServerRulesAndEngineerClass(t *testing.T) {
	m, c := fixtureGroups(t, []string{"  engineer: {priv_lvl: 15, juniper_class: ENG-CLASS}"},
		"junos:\n  operator:\n    deny_commands: ['^(request|start)( .*)?$', '^file']\n    deny_configuration: ['^system login']\n")
	for _, proto := range []string{TACACS, RADIUS} {
		d := Data{Model: m, Conf: c, ServerIP: "x", ACL: MgmtACL{Name: "MGMT-ACL"}}
		if proto == RADIUS {
			d.Radius = &Radius{AuthPort: "1812", AcctPort: "1813", Secret: "s", VendorSent: "scope"}
		}
		out := renderText(t, Request{Vendor: "juniper", Scope: "lab", Protocol: proto, Source: SourceFlag}, d)
		for _, want := range []string{
			"# Step 3: Per-class rules sent by the server at login (read-only summary)\n",
			"# class 'OP-CLASS' (group 'operator')\n" +
				"#   deny-commands       33/241 bytes: (^(request|start)( .*)?$)|(^file)\n" +
				"#   deny-configuration  15/236 bytes: (^system login)\n",
			"# class 'RO-CLASS' (group 'readonly')\n#   none: tacctl group junos readonly deny-commands add '<regex>'\n",
			"set system login class ENG-CLASS permissions [ view view-configuration network clear trace reset configure rollback interface interface-control routing routing-control firewall firewall-control system system-control snmp ]\nset system login user ENG-CLASS class ENG-CLASS\n",
			"  operator: OP-CLASS (local: clear/network/reset/trace/view + view-configuration), junos: deny-commands 33/241, deny-configuration 15/236\n",
			"  engineer: ENG-CLASS (local: operator bits + configure/rollback and interface, routing, firewall, system, snmp)\n",
			"  show configuration system login user ENG-CLASS\n",
			"#   delete system login class OP-CLASS allow-commands\n",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: lacks %q", proto, want)
			}
		}
		if regexp.MustCompile(`(?m)^set system login class \S+ (allow|deny)-commands`).MatchString(out) {
			t.Errorf("%s: class command rules emitted", proto)
		}
		words := map[string][]string{
			TACACS: {"(TACACS+ service junos-exec:", "  show cli authorization    (after a TACACS+ login"},
			RADIUS: {"(Juniper-Deny-Commands and", "  show cli authorization    (after a RADIUS login",
				"  - With it, Juniper-Deny-Commands and Juniper-Deny-Configuration where the group has"},
		}[proto]
		for _, w := range words {
			if !strings.Contains(out, w) {
				t.Errorf("%s: lacks %q", proto, w)
			}
		}
	}
}

func TestWTILevelOverride(t *testing.T) {
	m, c := fixtureGroups(t, []string{"  engineer: {priv_lvl: 15, juniper_class: ENG-CLASS}"}, "wti_level:\n  engineer: superuser\n  readonly: user\n")
	out := renderText(t, Request{Vendor: "wti", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c, ServerIP: "x"})
	for _, want := range []string{
		"11. Service Name               : wti       (factory default; per-group levels need it, see notes)\n",
		"  engineer: priv-lvl 15 → SuperUser (wti-level override; auto: Administrator)\n",
		"  readonly: priv-lvl 1 → User (wti-level override; auto: ViewOnly)\n",
		"  operator: priv-lvl 7 → User\n",
		"    readonly: User\n",
		"client args [service=wti ...]",
		"  - A unit set to Service Name 'shell' by the walkthrough of tacctl 0.2.1 or\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q", want)
		}
	}
	if strings.Contains(out, "No group lands in the SuperUser band") {
		t.Error("SuperUser hint despite the override")
	}
	out = renderText(t, Request{Vendor: "wti", Scope: "lab", Protocol: RADIUS, Source: SourceFlag},
		Data{Model: m, Conf: c, ServerIP: "x", Radius: &Radius{AuthPort: "1812", AcctPort: "1813", Secret: "s", VendorSent: "scope"}})
	for _, want := range []string{
		"  engineer: priv-lvl 15 → WTI-Super 2 (SuperUser; wti-level override, auto: Administrator)\n",
		"  operator: priv-lvl 7 → WTI-Super 1 (User)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("radius lacks %q", want)
		}
	}
}
