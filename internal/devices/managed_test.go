package devices

// devices.Managed (D62, D63, D64 of docs/plans/0.2.4-plan.md): the managed
// sections of a Cisco and a Junos device, built over the walkthrough's own
// builders. The tests pin them in goldens per vendor variant and fixture
// scope, tie every statement to the walkthrough of the same input, mark
// the secrets, and hold Managed to the purity the renderers have.

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
)

// --- the inputs ---------------------------------------------------------------

// managedGroups are the groups the multiscope store gets for these tests: an
// engineer (EN-CLASS, the bracketed permissions line of Junos) and a group
// at level 5 with no command rules (a commented per-command line on Cisco).
var managedGroups = []string{
	"  engineer: {priv_lvl: 15, juniper_class: EN-CLASS}",
	"  helpdesk: {priv_lvl: 5, juniper_class: OP-CLASS}",
}

// managedOverrides is tacctl.yaml: a local-first scope with its own timeout
// and group names, break-glass users in two scopes, and command rules for
// the engineer so its level is authorized.
const managedOverrides = `aaa:
  order:
    lab: local-first
exec_timeout:
  lab: 15
tacacs_group:
  lab: LAB-TACACS
radius_group:
  lab: LAB-RADIUS
breakglass_scope:
  lab:
    users: [lab-admin:admin, lab-ops:operator, lab-ro:readonly]
  dmz:
    users: [dmz-ops:operator]
commands:
  engineer:
  - {name: '*', action: permit}
`

// managedProfile is what a scope of the fixture is given beyond the model:
// the SNMP input, the management ACL, --server and --source.
type managedProfile struct {
	scope                string
	snmp                 SNMPInput
	cidrs                []string
	authServer, sourceIP string
}

// managedProfiles: lab has everything (SNMPv2c, an ACL, three accounts,
// local-first); prod SNMPv3 and an ACL with an IPv6 entry; prod-inner
// nothing, so what is left out shows; dmz an SNMP step with unset values,
// one account, --server and --source.
func managedProfiles() []managedProfile {
	unset := v2cAll
	unset.Contact, unset.Location, unset.Description, unset.DeviceName = "", "", "", ""
	return []managedProfile{
		{scope: "lab", snmp: v2cAll, cidrs: []string{"198.51.100.0/24", "192.0.2.0/24"}},
		{scope: "prod", snmp: v3All, cidrs: []string{"10.0.0.0/8", "2001:db8::/32"}},
		{scope: "prod-inner"},
		{scope: "dmz", snmp: unset, authServer: "203.0.113.9", sourceIP: "198.51.100.77"},
	}
}

// managedVariants are the five variants Managed builds for: Cisco (IOS-XE,
// IOS 12.x, RADIUS) and Junos (TACACS+, RADIUS).
func managedVariants() []variant { return variants[:5] }

func managedWorld(t *testing.T) (*model.Model, *conf.Config) {
	t.Helper()
	return fixtureGroups(t, managedGroups, managedOverrides)
}

// input is the request and data of one device of the profile's scope.
func (p managedProfile) input(m *model.Model, c *conf.Config, v variant) (Request, Data) {
	acl := MgmtACL{Name: "VTY-ACL", CIDRs: p.cidrs}
	if v.vendor == "juniper" {
		acl.Name = "MGMT-ACL"
	}
	d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: acl, SNMP: p.snmp, AuthServer: p.authServer, SourceIP: p.sourceIP}
	source := SourceDefault
	if v.protocol == RADIUS {
		source = SourceFlag
		d.Radius = &Radius{AuthPort: "1812", AcctPort: "1813", Secret: m.Scope(p.scope).Secret, VendorSent: "scope"}
	}
	return Request{Vendor: v.vendor, Scope: p.scope, Legacy: v.legacy, Protocol: v.protocol, Source: source}, d
}

func mustManaged(t *testing.T, req Request, d Data) []Section {
	t.Helper()
	secs, err := Managed(req, d)
	if err != nil {
		t.Fatalf("Managed(%s %s): %v", req.Vendor, req.Scope, err)
	}
	return secs
}

// managedSectionNames is the order Managed returns the sections in.
var managedSectionNames = []string{"aaa", "roles", "mgmt-acl", "snmp", "netconf", "breakglass"}

// managedText is a golden's text of the sections: every section by name,
// '|' before a statement, '*' before one compared by presence.
func managedText(secs []Section) string {
	by := map[string]Section{}
	for _, s := range secs {
		by[s.Name] = s
	}
	var b strings.Builder
	for _, name := range managedSectionNames {
		s, ok := by[name]
		if !ok {
			b.WriteString("[" + name + "] not rendered\n")
			continue
		}
		b.WriteString("[" + name + "]\n")
		for i, l := range s.Lines {
			mark := "| "
			if s.Secret[i] {
				mark = "* "
			}
			b.WriteString(mark + l + "\n")
		}
	}
	return b.String()
}

// writeTemplate puts an operator's copy of a template in dir.
func writeTemplate(t *testing.T, dir, name, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name+".template"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func sectionOf(secs []Section, name string) (Section, bool) {
	for _, s := range secs {
		if s.Name == name {
			return s, true
		}
	}
	return Section{}, false
}

// --- the seed's cases ------------------------------------------------------------

// A vendor with no managed sections: nothing and ErrUnsupported (D71).
func TestManagedUnsupported(t *testing.T) {
	m, c := managedWorld(t)
	for _, vendor := range []string{"wti", "other", ""} {
		secs, err := Managed(Request{Vendor: vendor, Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c})
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("Managed(%q): err = %v, want ErrUnsupported", vendor, err)
		}
		if secs != nil {
			t.Errorf("Managed(%q): sections = %v, want nil", vendor, secs)
		}
	}
}

// A request that cannot be rendered is an error, not a half-built section.
func TestManagedNeedsItsInput(t *testing.T) {
	m, c := managedWorld(t)
	for _, c := range []struct {
		name string
		req  Request
		d    Data
	}{
		{"no model", Request{Vendor: "cisco", Scope: "lab", Protocol: TACACS}, Data{Conf: c}},
		{"no conf", Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, Data{Model: m}},
		{"radius without Prepare", Request{Vendor: "juniper", Scope: "lab", Protocol: RADIUS}, Data{Model: m, Conf: c}},
	} {
		secs, err := Managed(c.req, c.d)
		if err == nil || errors.Is(err, ErrUnsupported) || secs != nil {
			t.Errorf("%s: sections %v, err %v", c.name, secs, err)
		}
	}
}

// A Section carries its statements and a per-line secret mark.
func TestSectionShape(t *testing.T) {
	s := Section{Name: "aaa", Lines: []string{"aaa new-model"}, Secret: []bool{false}}
	if len(s.Lines) != len(s.Secret) {
		t.Fatalf("Lines and Secret differ in length: %d and %d", len(s.Lines), len(s.Secret))
	}
}

// --- goldens --------------------------------------------------------------------

// Every variant for every fixture scope, pinned.
func TestManagedGoldens(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range managedVariants() {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			golden(t, "managed."+v.name+"."+p.scope+".txt", managedText(mustManaged(t, req, d)))
		}
	}
}

// The expected.txt of the real legacy IOS capture (tests/fixtures/devconf/
// ios/real-12.4-7200) is what Managed renders for the legacy Cisco variant
// of a scope with one management ACL entry and one break-glass account, the
// lab server address mapped to a documentation address. The comparison
// tests of internal/devconf read it as the expected side.
func TestManagedRealDeviceFixture(t *testing.T) {
	over := strings.Replace(managedOverrides, "users: [lab-admin:admin, lab-ops:operator, lab-ro:readonly]", "users: [admin:admin]", 1)
	m, c := fixtureGroups(t, managedGroups, over)
	p := managedProfile{scope: "lab", snmp: v2cAll, cidrs: []string{"198.51.100.0/24"}}
	req, d := p.input(m, c, variants[1])
	if !req.Legacy || req.Vendor != "cisco" || req.Protocol != TACACS {
		t.Fatalf("variant %+v is not the legacy Cisco one", req)
	}
	got := strings.ReplaceAll(managedText(mustManaged(t, req, d)), "10.0.0.42", "192.0.2.10")
	data, err := os.ReadFile("../../tests/fixtures/devconf/ios/real-12.4-7200/expected.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, want, ok := strings.Cut(string(data), "\n# ---\n")
	if !ok {
		t.Fatal("expected.txt: no '# ---' line after the header")
	}
	if got != want {
		t.Errorf("real-12.4-7200/expected.txt is not what Managed renders:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// The shape every result has: the sections in order, no section empty,
// Secret as long as Lines, no comment and no blank among the statements,
// and no NETCONF (the step is commented out in every walkthrough).
func TestManagedShape(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range managedVariants() {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			secs := mustManaged(t, req, d)
			last := -1
			for _, s := range secs {
				at := slices.Index(managedSectionNames, s.Name)
				if at <= last {
					t.Errorf("%s/%s: section %q out of order or unknown", v.name, p.scope, s.Name)
				}
				last = at
				if len(s.Lines) == 0 || len(s.Lines) != len(s.Secret) {
					t.Errorf("%s/%s/%s: %d lines, %d marks", v.name, p.scope, s.Name, len(s.Lines), len(s.Secret))
				}
				if s.Name == "netconf" {
					t.Errorf("%s/%s: a NETCONF section, but the step is commented out", v.name, p.scope)
				}
				for _, l := range s.Lines {
					if tl := strings.TrimSpace(l); tl == "" || strings.HasPrefix(tl, "#") || strings.HasPrefix(tl, "!") {
						t.Errorf("%s/%s/%s: %q is no statement", v.name, p.scope, s.Name, l)
					}
				}
			}
			if _, ok := sectionOf(secs, "aaa"); !ok {
				t.Errorf("%s/%s: no aaa section", v.name, p.scope)
			}
		}
	}
	// What a scope without SNMP, ACL and accounts is not told it lacks.
	req, d := managedProfiles()[2].input(m, c, variants[3])
	for _, s := range mustManaged(t, req, d) {
		if s.Name != "aaa" && s.Name != "roles" {
			t.Errorf("prod-inner: unexpected section %q", s.Name)
		}
	}
}

// --- the tie to the walkthrough -------------------------------------------------------

// walkBody is the configuration of a walkthrough: the lines between its
// first and second rule, as live statements (not a comment) and, for the
// commented ones, the statement behind the comment leader.
func walkBody(t *testing.T, text string) (live, commented map[string]bool) {
	t.Helper()
	const rule = "--------------------------------------------"
	var body []string
	in := false
	skip := false
	for _, l := range strings.Split(text, "\n") {
		// The note under --server and --source is prose, not configuration.
		if l == "Two server addresses:" {
			skip = true
		}
		if skip {
			skip = l != ""
			continue
		}
		if l == rule {
			if in {
				break
			}
			in = true
			continue
		}
		if in {
			body = append(body, l)
		}
	}
	if len(body) == 0 {
		t.Fatalf("no configuration between the rules:\n%s", text)
	}
	live, commented = map[string]bool{}, map[string]bool{}
	for _, l := range body {
		tl := strings.TrimLeft(l, " \t")
		switch {
		case tl == "":
		case strings.HasPrefix(tl, "#") || strings.HasPrefix(tl, "!"):
			commented[strings.TrimPrefix(tl[1:], " ")] = true
		default:
			live[l] = true
		}
	}
	return live, commented
}

// The plan's tie between Managed and the walkthrough (D63): every statement
// is a live line of the walkthrough of the same input (the break-glass
// accounts, which the walkthrough renders commented for the operator to
// complete, are its commented lines), for every variant and scope.
func TestManagedStatementsAreInTheWalkthrough(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range managedVariants() {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			live, commented := walkBody(t, renderText(t, req, d))
			for _, s := range mustManaged(t, req, d) {
				for _, l := range s.Lines {
					switch {
					case s.Name == "breakglass" && !commented[l]:
						t.Errorf("%s/%s: %q is not a commented line of the walkthrough", v.name, p.scope, l)
					case s.Name != "breakglass" && !live[l]:
						t.Errorf("%s/%s/%s: %q is not a live line of the walkthrough", v.name, p.scope, s.Name, l)
					}
				}
			}
		}
	}
}

// managedLeftOut are the live statements of a walkthrough that no section
// of D62 names: the commands that are not configuration ('delete', 'commit'),
// the Junos idle timeout, and the Cisco lines outside the AAA lists, the
// access list and the VTY access class.
var managedLeftOut = regexp.MustCompile(`^(` +
	`commit` +
	`|delete .*` +
	`|set system login idle-timeout \d+` +
	`|service password-encryption` +
	`|line (con 0|vty 0 15)` +
	`|  (login authentication default|transport input ssh|exec-timeout \d+ 0)` +
	`)$`)

// The other direction: a live statement of the walkthrough that Managed
// does not return is one of the few left out on purpose, so a statement a
// builder gains cannot go unmanaged unseen.
func TestManagedLeavesOutOnlyWhatItSays(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range managedVariants() {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			live, _ := walkBody(t, renderText(t, req, d))
			managed := map[string]bool{}
			for _, s := range mustManaged(t, req, d) {
				for _, l := range s.Lines {
					managed[l] = true
				}
			}
			for l := range live {
				if !managed[l] && !managedLeftOut.MatchString(l) {
					t.Errorf("%s/%s: live statement %q of the walkthrough is not managed", v.name, p.scope, l)
				}
			}
		}
	}
}

// --- secrets ---------------------------------------------------------------------------

// Statements that carry a key, community, password or hash are marked, and
// only those: a location or a description that says 'secret' is not.
func TestManagedSecretMarks(t *testing.T) {
	for _, c := range []struct {
		vendor, line string
		want         bool
	}{
		{"juniper", "set system tacplus-server 192.0.2.10 secret lab-secret-0123456789abcdef", true},
		{"juniper", "set system tacplus-server 2001:db8::10 secret $9$abc", true},
		{"juniper", "set system radius-server 192.0.2.10 secret lab-secret-0123456789abcdef", true},
		{"juniper", "set system tacplus-server 192.0.2.10 single-connection", false},
		{"juniper", "set system radius-server 192.0.2.10 port 1812", false},
		{"juniper", "set system authentication-order [ password tacplus ]", false},
		{"juniper", "set system accounting destination tacplus", false},
		{"juniper", "set snmp community lab-ro-community authorization read-only", true},
		{"juniper", "set snmp community lab-ro-community client-list-name TACCTL-SNMP", true},
		{"juniper", "set snmp client-list TACCTL-SNMP 192.0.2.7/32", false},
		{"juniper", `set snmp location "secret room, community 7"`, false},
		{"juniper", `set snmp contact "key holder"`, false},
		{"juniper", `set snmp description "authentication-password"`, false},
		{"juniper", `set snmp v3 usm local-engine user tacctl-ro authentication-sha authentication-password "auth-pass-0123"`, true},
		{"juniper", `set snmp v3 usm local-engine user tacctl-ro authentication-sha256 authentication-password "auth-pass-0123"`, true},
		{"juniper", `set snmp v3 usm local-engine user tacctl-ro privacy-aes128 privacy-password "priv-pass-4567"`, true},
		{"juniper", "set snmp v3 vacm security-to-group security-model usm security-name tacctl-ro group TACCTL-GROUP", false},
		{"juniper", "set snmp view TACCTL-VIEW oid .1 include", false},
		{"juniper", "set system login user lab-admin class RW-CLASS authentication encrypted-password '<HASH>'", true},
		{"juniper", "set system login user RW-CLASS class RW-CLASS", false},
		{"juniper", "set system login class RW-CLASS permissions all", false},
		{"juniper", "set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 192.0.2.0/24", false},

		{"cisco", "  key lab-secret-0123456789abcdef", true},
		{"cisco", "tacacs-server host 192.0.2.10 single-connection timeout 5 key lab-secret-0123456789abcdef", true},
		{"cisco", "tacacs-server host 192.0.2.10 single-connection timeout 5", false},
		{"cisco", "tacacs server TACACS", false},
		{"cisco", "  address ipv4 192.0.2.10", false},
		{"cisco", "  timeout 5", false},
		{"cisco", "aaa authentication login default group TACACS-GROUP local", false},
		{"cisco", "aaa group server tacacs+ TACACS-GROUP", false},
		{"cisco", "snmp-server community lab-ro-community RO TACCTL-SNMP", true},
		{"cisco", "snmp-server user tacctl-ro TACCTL-GROUP v3 auth sha auth-pass-0123 priv aes 128 priv-pass-4567", true},
		{"cisco", "snmp-server group TACCTL-GROUP v3 priv read TACCTL-VIEW access TACCTL-SNMP", false},
		{"cisco", "snmp-server view TACCTL-VIEW iso included", false},
		{"cisco", "snmp-server location key room", false},
		{"cisco", "snmp-server contact secret@example.net", false},
		{"cisco", "username lab-admin privilege 15 secret 9 <TYPE9-HASH>", true},
		{"cisco", "username lab-admin privilege 15 secret 5 <HASH>", true},
		{"cisco", "privilege exec level 7 show running-config", false},
		{"cisco", "  permit 192.0.2.0 0.0.0.255", false},
	} {
		secret := ciscoSecret
		if c.vendor == "juniper" {
			secret = juniperSecret
		}
		if got := secret(c.line); got != c.want {
			t.Errorf("%s %q: secret = %v, want %v", c.vendor, c.line, got, c.want)
		}
	}
}

// In the sections themselves: a statement that holds the scope's secret,
// the community or an SNMPv3 passphrase is marked, a mark is on a statement
// that holds one of them or a hash placeholder, and so no secret is
// compared as text by accident.
func TestManagedSecretsAreTheStatementsThatCarryThem(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range managedVariants() {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			values := []string{m.Scope(p.scope).Secret}
			for _, s := range []string{p.snmp.Community, p.snmp.V3AuthPass, p.snmp.V3PrivPass} {
				if s != "" {
					values = append(values, s)
				}
			}
			marked := 0
			for _, s := range mustManaged(t, req, d) {
				for i, l := range s.Lines {
					holds := strings.Contains(l, "<HASH>") || strings.Contains(l, "<TYPE9-HASH>")
					for _, val := range values {
						holds = holds || strings.Contains(l, val)
					}
					if holds != s.Secret[i] {
						t.Errorf("%s/%s/%s: %q: carries a secret %v, marked %v", v.name, p.scope, s.Name, l, holds, s.Secret[i])
					}
					if s.Secret[i] {
						marked++
					}
				}
			}
			if marked == 0 {
				t.Errorf("%s/%s: no statement is marked", v.name, p.scope)
			}
		}
	}
}

// --- what the sections hold --------------------------------------------------------------

func TestManagedCisco(t *testing.T) {
	m, c := managedWorld(t)
	lab := managedProfiles()[0]
	req, d := lab.input(m, c, variants[0])
	secs := mustManaged(t, req, d)

	aaa, _ := sectionOf(secs, "aaa")
	for _, want := range []string{
		"aaa new-model",
		"tacacs server TACACS", "  address ipv4 10.0.0.42", "  key lab-secret-0123456789abcdef", "  single-connection",
		"aaa group server tacacs+ LAB-TACACS", "  server name TACACS",
		"aaa authentication login default local group LAB-TACACS",
		"aaa authorization exec default local group LAB-TACACS if-authenticated",
		"aaa accounting exec default start-stop group LAB-TACACS",
		"aaa accounting commands 5 default start-stop group LAB-TACACS",
		"aaa authorization commands 15 default local group LAB-TACACS",
		"aaa authorization config-commands",
	} {
		if !slices.Contains(aaa.Lines, want) {
			t.Errorf("aaa lacks %q:\n%s", want, strings.Join(aaa.Lines, "\n"))
		}
	}
	// Level 5 has no command rules: its authorization line is commented in
	// the walkthrough, so it is not expected.
	if slices.Contains(aaa.Lines, "aaa authorization commands 5 default local group LAB-TACACS") {
		t.Error("the commented per-command line of level 5 is expected")
	}
	if slices.Contains(aaa.Lines, "aaa authorization console") {
		t.Error("the commented console line is expected")
	}

	roles, _ := sectionOf(secs, "roles")
	if !slices.Contains(roles.Lines, "privilege exec level 1 show running-config") ||
		!slices.Contains(roles.Lines, "privilege exec all level 7 ping") {
		t.Errorf("roles:\n%s", strings.Join(roles.Lines, "\n"))
	}

	acl, _ := sectionOf(secs, "mgmt-acl")
	tail := acl.Lines[len(acl.Lines)-3:]
	if acl.Lines[0] != "ip access-list standard VTY-ACL" || tail[0] != "  deny   any log" ||
		tail[1] != "line vty 0 15" || tail[2] != "  access-class VTY-ACL in" {
		t.Errorf("mgmt-acl:\n%s", strings.Join(acl.Lines, "\n"))
	}

	snmp, _ := sectionOf(secs, "snmp")
	if !slices.Contains(snmp.Lines, "snmp-server community lab-ro-community RO TACCTL-SNMP") ||
		!slices.Contains(snmp.Lines, "snmp-server contact NOC <noc@example.net>") {
		t.Errorf("snmp:\n%s", strings.Join(snmp.Lines, "\n"))
	}

	bg, _ := sectionOf(secs, "breakglass")
	want := []string{
		"username lab-admin privilege 15 secret 9 <TYPE9-HASH>",
		"username lab-ops privilege 7 secret 9 <TYPE9-HASH>",
		"username lab-ro privilege 1 secret 9 <TYPE9-HASH>",
	}
	if !slices.Equal(bg.Lines, want) || !slices.Equal(bg.Secret, []bool{true, true, true}) {
		t.Errorf("breakglass: %q %v", bg.Lines, bg.Secret)
	}

	// IOS 12.x: the global server line, type 5 accounts.
	req, d = lab.input(m, c, variants[1])
	secs = mustManaged(t, req, d)
	aaa, _ = sectionOf(secs, "aaa")
	if !slices.Contains(aaa.Lines, "tacacs-server host 10.0.0.42 single-connection timeout 5 key lab-secret-0123456789abcdef") ||
		!slices.Contains(aaa.Lines, "  server 10.0.0.42") {
		t.Errorf("legacy aaa:\n%s", strings.Join(aaa.Lines, "\n"))
	}
	bg, _ = sectionOf(secs, "breakglass")
	if bg.Lines[0] != "username lab-admin privilege 15 secret 5 <HASH>" {
		t.Errorf("legacy breakglass: %q", bg.Lines)
	}

	// RADIUS: the server block with the listener's ports, no command
	// authorization or accounting, the RADIUS group.
	req, d = lab.input(m, c, variants[2])
	secs = mustManaged(t, req, d)
	aaa, _ = sectionOf(secs, "aaa")
	for _, want := range []string{
		"radius server RADIUS", "  address ipv4 10.0.0.42 auth-port 1812 acct-port 1813", "  retransmit 2",
		"aaa group server radius LAB-RADIUS", "aaa accounting exec default start-stop group LAB-RADIUS",
	} {
		if !slices.Contains(aaa.Lines, want) {
			t.Errorf("radius aaa lacks %q:\n%s", want, strings.Join(aaa.Lines, "\n"))
		}
	}
	for _, l := range aaa.Lines {
		if strings.Contains(l, "commands") || strings.Contains(l, "tacacs") {
			t.Errorf("radius aaa has %q", l)
		}
	}
}

func TestManagedJuniper(t *testing.T) {
	m, c := managedWorld(t)
	lab := managedProfiles()[0]
	req, d := lab.input(m, c, variants[3])
	secs := mustManaged(t, req, d)

	aaa, _ := sectionOf(secs, "aaa")
	want := []string{
		"set system authentication-order [ password tacplus ]",
		"set system tacplus-server 10.0.0.42 secret lab-secret-0123456789abcdef",
		"set system tacplus-server 10.0.0.42 single-connection",
		"set system accounting events [ login change-log ]",
		"set system accounting destination tacplus",
	}
	if !slices.Equal(aaa.Lines, want) || !slices.Equal(aaa.Secret, []bool{false, true, false, false, false}) {
		t.Errorf("aaa: %q %v", aaa.Lines, aaa.Secret)
	}

	roles, _ := sectionOf(secs, "roles")
	for _, want := range []string{
		"set system login class EN-CLASS permissions [ view view-configuration network clear trace reset configure rollback interface interface-control routing routing-control firewall firewall-control system system-control snmp ]",
		"set system login user EN-CLASS class EN-CLASS",
		"set system login class RW-CLASS permissions all",
		"set system login user RO-CLASS class RO-CLASS",
	} {
		if !slices.Contains(roles.Lines, want) {
			t.Errorf("roles lacks %q", want)
		}
	}

	acl, _ := sectionOf(secs, "mgmt-acl")
	for _, want := range []string{
		"set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 10.0.0.42/32",
		"set firewall family inet filter MGMT-ACL term permit-mgmt from source-address 198.51.100.0/24",
		"set firewall family inet filter MGMT-ACL term permit-snmp from destination-port snmp",
		"set firewall family inet filter MGMT-ACL term default-accept then accept",
	} {
		if !slices.Contains(acl.Lines, want) {
			t.Errorf("mgmt-acl lacks %q:\n%s", want, strings.Join(acl.Lines, "\n"))
		}
	}
	// The lo0 line that applies the filter is left to the operator.
	for _, l := range acl.Lines {
		if strings.Contains(l, "interfaces lo0") {
			t.Errorf("the filter is applied: %q", l)
		}
	}

	snmp, _ := sectionOf(secs, "snmp")
	for _, want := range []string{
		"set snmp client-list TACCTL-SNMP 10.0.0.42/32",
		"set snmp client-list TACCTL-SNMP 0.0.0.0/0 restrict",
		"set snmp community lab-ro-community authorization read-only",
		`set snmp location "Rack 4, DC1"`,
		`set snmp description "Core switch"`,
	} {
		if !slices.Contains(snmp.Lines, want) {
			t.Errorf("snmp lacks %q:\n%s", want, strings.Join(snmp.Lines, "\n"))
		}
	}

	bg, _ := sectionOf(secs, "breakglass")
	if len(bg.Lines) != 3 || bg.Lines[0] != "set system login user lab-admin class RW-CLASS authentication encrypted-password '<HASH>'" ||
		!slices.Equal(bg.Secret, []bool{true, true, true}) {
		t.Errorf("breakglass: %q %v", bg.Lines, bg.Secret)
	}

	// RADIUS: the server's ports and secret, accounting to radius; --server
	// is the address the device is told (dmz).
	req, d = managedProfiles()[3].input(m, c, variants[4])
	aaa, _ = sectionOf(mustManaged(t, req, d), "aaa")
	for _, want := range []string{
		"set system radius-server 203.0.113.9 port 1812",
		"set system radius-server 203.0.113.9 accounting-port 1813",
		"set system radius-server 203.0.113.9 secret dmz-secret-0123456789abcdef",
		"set system accounting destination radius",
	} {
		if !slices.Contains(aaa.Lines, want) {
			t.Errorf("radius aaa lacks %q:\n%s", want, strings.Join(aaa.Lines, "\n"))
		}
	}
}

// The sections do not depend on who asks: an engineer's walkthrough (the
// Cisco NETCONF step is a superuser's) has the same statements.
func TestManagedRestrictedIsTheSame(t *testing.T) {
	m, c := managedWorld(t)
	for _, v := range managedVariants() {
		req, d := managedProfiles()[0].input(m, c, v)
		want := mustManaged(t, req, d)
		d.Restricted = true
		if got := mustManaged(t, req, d); !slices.EqualFunc(want, got, sectionEqual) {
			t.Errorf("%s: an engineer's sections differ", v.name)
		}
	}
}

func sectionEqual(a, b Section) bool {
	return a.Name == b.Name && slices.Equal(a.Lines, b.Lines) && slices.Equal(a.Secret, b.Secret)
}

// The statement filters: a step that is uncommented is expected, the
// Junos 'delete' commands and every comment are not.
func TestManagedStatementFilters(t *testing.T) {
	junos := "# NETCONF over ssh\n#   set system services netconf ssh\ndelete system authentication-order\n" +
		"\nset system services netconf ssh\nset system services netconf ssh connection-limit 5\n"
	if got := junosStatements(junos); !slices.Equal(got, []string{"set system services netconf ssh", "set system services netconf ssh connection-limit 5"}) {
		t.Errorf("junos: %q", got)
	}
	cisco := "! --- NETCONF ---\n! netconf-yang\n\n  \nnetconf-yang\nip access-list standard X\n  remark r\n   ! note\n  permit 192.0.2.1 0.0.0.0\n"
	if got := ciscoStatements(cisco); !slices.Equal(got, []string{"netconf-yang", "ip access-list standard X", "  remark r", "  permit 192.0.2.1 0.0.0.0"}) {
		t.Errorf("cisco: %q", got)
	}
	acct := "! username a privilege 15 secret 9 <TYPE9-HASH>\n! tacctl stores no credential\n! username b privilege 7 secret 9 <TYPE9-HASH>"
	if got := uncommented(acct, "! ", "! username "); !slices.Equal(got, []string{"username a privilege 15 secret 9 <TYPE9-HASH>", "username b privilege 7 secret 9 <TYPE9-HASH>"}) {
		t.Errorf("uncommented: %q", got)
	}
}

// --- purity -----------------------------------------------------------------------------

// Managed reads only Request and Data (the renderer-purity tests of 0.2.3
// extended, plan section 7.1): the same input gives the same sections
// however often, in parallel, from another directory and environment, with
// the operator's templates present or absent; it changes nothing it was
// given; its source imports nothing that reaches a file, the terminal or
// the clock.
func TestManagedIsPure(t *testing.T) {
	m, c := managedWorld(t)
	type job struct {
		name string
		req  Request
		d    Data
		want []Section
	}
	var jobs []job
	for _, v := range managedVariants() {
		for _, p := range managedProfiles() {
			req, d := p.input(m, c, v)
			jobs = append(jobs, job{v.name + "/" + p.scope, req, d, mustManaged(t, req, d)})
		}
	}

	// Another directory, another environment, an operator's template that
	// would change the walkthrough: the same sections.
	tpl := t.TempDir()
	for _, name := range []string{"cisco", "cisco-legacy", "cisco-radius", "juniper", "juniper-radius"} {
		writeTemplate(t, tpl, name, "MINE ${SERVER_IP}\n")
	}
	t.Chdir(t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("TZ", "Pacific/Auckland")
	t.Setenv("LC_ALL", "C")
	for _, j := range jobs {
		d := j.d
		d.TemplateDir = tpl
		got := mustManaged(t, j.req, d)
		if !slices.EqualFunc(j.want, got, sectionEqual) {
			t.Errorf("%s: differs with the operator's templates and another environment", j.name)
		}
	}

	// A caller that edits what it got changes nothing the next one gets.
	for _, j := range jobs {
		got := mustManaged(t, j.req, j.d)
		for i := range got {
			for k := range got[i].Lines {
				got[i].Lines[k] = "x"
				got[i].Secret[k] = !got[i].Secret[k]
			}
			got[i].Name = "x"
		}
		if again := mustManaged(t, j.req, j.d); !slices.EqualFunc(j.want, again, sectionEqual) {
			t.Errorf("%s: a caller's edit reached the next result", j.name)
		}
	}

	// The input is left as it was: the walkthrough, the ACL and the SNMP
	// ranges read the same after.
	for _, j := range jobs {
		before := renderText(t, j.req, j.d)
		cidrs, ranges := slices.Clone(j.d.ACL.CIDRs), slices.Clone(j.d.SNMP.Ranges)
		mustManaged(t, j.req, j.d)
		if after := renderText(t, j.req, j.d); after != before ||
			!slices.Equal(cidrs, j.d.ACL.CIDRs) || !slices.Equal(ranges, j.d.SNMP.Ranges) {
			t.Errorf("%s: Managed changed its input", j.name)
		}
	}

	// In parallel over the shared Data (-race).
	var wg sync.WaitGroup
	for range 4 {
		for _, j := range jobs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got, err := Managed(j.req, j.d)
				if err != nil || !slices.EqualFunc(j.want, got, sectionEqual) {
					t.Errorf("%s: differs in parallel (%v)", j.name, err)
				}
			}()
		}
	}
	wg.Wait()
}

// managed.go's imports are the whole of what it can reach: strings and
// patterns, and the error it returns. No os, time, net, exec or io.
func TestManagedImportsNothingImpure(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "managed.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		switch path := strings.Trim(imp.Path.Value, `"`); path {
		case "errors", "regexp", "strings":
		default:
			t.Errorf("managed.go imports %q", path)
		}
	}
}
