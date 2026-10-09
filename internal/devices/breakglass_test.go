package devices

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
)

// The break-glass users of the scope 'lab' in tacctl.yaml: one of each role.
const breakGlassSeveral = "breakglass_scope:\n  lab:\n    users: [lab-admin:admin, lab-ops:operator, lab-ro:readonly]\n"

// stdInput is the input the builders get from the multiscope fixture.
func stdInput(users ...policy.BreakGlassUser) BreakGlassInput {
	return BreakGlassInput{
		Scope:     "lab",
		Users:     users,
		Privilege: map[string]int{"admin": 15, "operator": 7, "readonly": 1},
		Class:     map[string]string{"admin": "RW-CLASS", "operator": "OP-CLASS", "readonly": "RO-CLASS"},
		Level:     map[string]string{"admin": "Administrator", "operator": "User", "readonly": "ViewOnly"},
	}
}

// The builders over their input struct alone (no model, file, terminal or
// clock): none, one and several users, per role and vendor, against one
// golden.
func TestBreakGlassBlocksGolden(t *testing.T) {
	one := []policy.BreakGlassUser{{Name: "lab-admin", Role: "admin"}}
	several := []policy.BreakGlassUser{{Name: "lab-admin", Role: "admin"}, {Name: "lab-ops", Role: "operator"}, {Name: "lab-ro", Role: "readonly"}}
	var b strings.Builder
	for _, users := range []struct {
		name  string
		users []policy.BreakGlassUser
	}{{"none", nil}, {"one admin", one},
		{"operator only", []policy.BreakGlassUser{{Name: "lab-ops", Role: "operator"}}},
		{"readonly only", []policy.BreakGlassUser{{Name: "lab-ro", Role: "readonly"}}},
		{"several", several}} {
		for _, v := range []struct {
			name   string
			legacy bool
			build  func(BreakGlassInput) string
		}{{"cisco", false, ciscoBreakGlass}, {"cisco legacy", true, ciscoBreakGlass},
			{"juniper", false, juniperBreakGlass}, {"wti", false, wtiBreakGlass}} {
			in := stdInput(users.users...)
			in.Legacy = v.legacy
			b.WriteString("=== " + v.name + " / " + users.name + "\n" + v.build(in) + "\n")
		}
		b.WriteString("=== unfilled / " + users.name + "\n" + breakGlassUnfilled(stdInput(users.users...)) + "\n")
	}
	// The scope's aaa-order local-first: the comments say the accounts are
	// tried before the server.
	first := stdInput(one...)
	first.LocalFirst = true
	b.WriteString("=== cisco / local-first\n" + ciscoBreakGlass(first) + "\n=== juniper / local-first\n" + juniperBreakGlass(first) + "\n")
	golden(t, "breakglass-blocks.txt", b.String())
}

// Whole walkthroughs of the scope with three break-glass users, for every
// vendor and protocol variant.
func TestBreakGlassRenderGoldens(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassSeveral)
	for _, g := range []struct {
		golden, vendor string
		legacy         bool
		protocol       string
	}{
		{"breakglass-cisco-lab.conf", "cisco", false, TACACS},
		{"breakglass-cisco-legacy-lab.conf", "cisco", true, TACACS},
		{"breakglass-cisco-radius-lab.conf", "cisco", false, RADIUS},
		{"breakglass-juniper-lab.conf", "juniper", false, TACACS},
		{"breakglass-juniper-radius-lab.conf", "juniper", false, RADIUS},
		{"breakglass-wti-lab.conf", "wti", false, TACACS},
		{"breakglass-wti-radius-lab.conf", "wti", false, RADIUS},
	} {
		acl := MgmtACL{Name: "VTY-ACL"}
		if g.vendor == "juniper" {
			acl.Name = "MGMT-ACL"
		}
		d := Data{Model: m, Conf: c, TemplateDir: t.TempDir(), ServerIP: "10.0.0.42", ACL: acl}
		source := SourceDefault
		if g.protocol == RADIUS {
			source = SourceFlag
			d.Radius = &Radius{AuthPort: "1812", AcctPort: "1813", Secret: m.Scope("lab").Secret, VendorSent: "scope"}
		}
		var buf bytes.Buffer
		if err := Render(&buf, Request{Vendor: g.vendor, Scope: "lab", Legacy: g.legacy, Protocol: g.protocol, Source: source}, d); err != nil {
			t.Fatal(err)
		}
		golden(t, g.golden, reANSI.ReplaceAllString(buf.String(), ""))
	}
}

func renderLab(t *testing.T, m *model.Model, d Data, vendor, scope string) string {
	t.Helper()
	var buf bytes.Buffer
	if err := Render(&buf, Request{Vendor: vendor, Scope: scope, Protocol: TACACS, Source: SourceDefault}, d); err != nil {
		t.Fatal(err)
	}
	return reANSI.ReplaceAllString(buf.String(), "")
}

// Per-scope isolation: the accounts of 'lab' are not rendered for 'prod', and
// a scope with none gets the notice, not an Unfilled line.
func TestBreakGlassPerScope(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml",
		"breakglass_scope:\n  lab:\n    users: [lab-admin:admin]\n  prod:\n    users: [prod-ops:operator]\n")
	for _, v := range []string{"cisco", "juniper", "wti"} {
		d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "X"}}
		lab, prod, dmz := renderLab(t, m, d, v, "lab"), renderLab(t, m, d, v, "prod"), renderLab(t, m, d, v, "dmz")
		if !strings.Contains(lab, "lab-admin") || strings.Contains(lab, "prod-ops") {
			t.Errorf("%s lab:\n%s", v, lab)
		}
		if !strings.Contains(prod, "prod-ops") || strings.Contains(prod, "lab-admin") {
			t.Errorf("%s prod:\n%s", v, prod)
		}
		if strings.Contains(dmz, "lab-admin") || strings.Contains(dmz, "prod-ops") ||
			strings.Contains(dmz, "Unfilled break-glass") ||
			!strings.Contains(dmz, "No break-glass local user is recorded for scope 'dmz'") {
			t.Errorf("%s dmz:\n%s", v, dmz)
		}
		if !strings.Contains(lab, "Unfilled break-glass credentials (tacctl stores none; put in your own): lab-admin (admin)\n") {
			t.Errorf("%s: no Unfilled line:\n%s", v, lab)
		}
	}
}

// No credential is ever rendered as a live line: every account line is a
// comment (Cisco, Junos) or a menu step (WTI) with the placeholder.
func TestBreakGlassPlaceholderNeverApplies(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassSeveral)
	d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "X"}}
	for _, v := range []string{"cisco", "juniper", "wti"} {
		out := renderLab(t, m, d, v, "lab")
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, breakGlassHash) && v != "wti" && !strings.HasPrefix(l, "! ") && !strings.HasPrefix(l, "# ") {
				t.Errorf("%s: a live line holds the placeholder: %q", v, l)
			}
			if strings.HasPrefix(l, "username ") || strings.HasPrefix(l, "set system login user lab-") {
				t.Errorf("%s: a live account line: %q", v, l)
			}
		}
	}
}

// The role's level on each vendor comes from the built-in group the role maps
// to: the model's value, else store.BuiltinGroups'. A class changed on the
// superuser group is the class of an admin.
func TestBreakGlassLevelsFollowTheGroups(t *testing.T) {
	text, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "store.yaml")
	if err := os.WriteFile(p, []byte(strings.Replace(string(text), "juniper_class: RW-CLASS", "juniper_class: ADM-CLASS", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	_, m, err := model.LoadStore(p)
	if err != nil {
		t.Fatal(err)
	}
	_, c := fixture(t, "store.multiscope.yaml", breakGlassSeveral)
	in := BreakGlassFor(Request{Vendor: "juniper", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c})
	if in.Class["admin"] != "ADM-CLASS" || in.Class["operator"] != "OP-CLASS" || in.Class["readonly"] != "RO-CLASS" {
		t.Errorf("classes: %v", in.Class)
	}
	if in.Privilege["admin"] != 15 || in.Privilege["operator"] != 7 || in.Privilege["readonly"] != 1 {
		t.Errorf("privileges: %v", in.Privilege)
	}
	if in.Level["admin"] != "Administrator" || in.Level["operator"] != "User" || in.Level["readonly"] != "ViewOnly" {
		t.Errorf("levels: %v", in.Level)
	}
	if got := juniperBreakGlass(in); !strings.Contains(got, "set system login user lab-admin class ADM-CLASS ") {
		t.Errorf("block:\n%s", got)
	}
	// Legacy applies to Cisco TACACS+ only.
	if BreakGlassFor(Request{Vendor: "cisco", Legacy: true, Protocol: TACACS}, Data{Model: m, Conf: c}).Legacy != true ||
		BreakGlassFor(Request{Vendor: "cisco", Legacy: true, Protocol: RADIUS}, Data{Model: m, Conf: c}).Legacy {
		t.Error("Legacy")
	}
}

// The names a break-glass user may not take: the template users of Step 1
// (every group's class, the built-ins' included) and Junos's own classes.
func TestTemplateUserNames(t *testing.T) {
	m, _ := fixture(t, "store.multiscope.yaml", "")
	got := strings.Join(TemplateUserNames(m), " ")
	for _, want := range []string{"RW-CLASS", "OP-CLASS", "RO-CLASS", "super-user", "read-only", "operator", "unauthorized"} {
		if !strings.Contains(" "+got+" ", " "+want+" ") {
			t.Errorf("%q is not in %q", want, got)
		}
	}
}

// An operator's own template that lacks the step renders without the
// accounts; the Unfilled line still says they are waiting.
func TestBreakGlassCustomTemplateWithoutTheStep(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassSeveral)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cisco.template"), []byte("hostname ${TACACS_GROUP}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := renderLab(t, m, Data{Model: m, Conf: c, TemplateDir: dir, ServerIP: "x", ACL: MgmtACL{Name: "X"}}, "cisco", "lab")
	if strings.Contains(out, "username ") || !strings.Contains(out, "Unfilled break-glass credentials") {
		t.Errorf("\n%s", out)
	}
}

// A group's 'wti-level' override is the level of its break-glass role, the
// one the mapping table of the same output shows.
func TestBreakGlassWTILevelFollowsOverride(t *testing.T) {
	m, c := fixtureGroups(t, nil,
		breakGlassSeveral+"wti_level:\n  readonly: user\n  operator: superuser\n  superuser: superuser\n")
	in := BreakGlassFor(Request{Vendor: "wti", Scope: "lab", Protocol: TACACS}, Data{Model: m, Conf: c})
	if in.Level["admin"] != "SuperUser" || in.Level["operator"] != "SuperUser" || in.Level["readonly"] != "User" {
		t.Errorf("levels: %v", in.Level)
	}
	out := renderLab(t, m, Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "X"}}, "wti", "lab")
	for _, want := range []string{
		"  readonly: priv-lvl 1 → User (wti-level override; auto: ViewOnly)\n",
		"lab-ro  Access Level: User  Password: <PASSWORD>\n",
		"lab-ops  Access Level: SuperUser  Password: <PASSWORD>\n",
		"lab-admin  Access Level: SuperUser  Password: <PASSWORD>\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
}

// 'algorithm-type scrypt secret' takes a plaintext password, so an account
// line for a hash is 'secret 9 <hash>' (type 5 for IOS 12.x): never the
// plaintext form, which would make a pasted hash the password.
func TestBreakGlassCiscoLineIsTheHashForm(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassSeveral)
	d := Data{Model: m, Conf: c, ServerIP: "10.0.0.42", ACL: MgmtACL{Name: "X"}}
	for _, legacy := range []bool{false, true} {
		var buf bytes.Buffer
		if err := Render(&buf, Request{Vendor: "cisco", Scope: "lab", Legacy: legacy, Protocol: TACACS, Source: SourceDefault}, d); err != nil {
			t.Fatal(err)
		}
		out := reANSI.ReplaceAllString(buf.String(), "")
		if strings.Contains(out, "algorithm-type") || strings.Contains(out, "scrypt secret") {
			t.Errorf("legacy=%v: the plaintext form is rendered:\n%s", legacy, out)
		}
		want := "! username lab-admin privilege 15 secret 9 <TYPE9-HASH>\n"
		if legacy {
			want = "! username lab-admin privilege 15 secret 5 <HASH>\n"
		}
		if !strings.Contains(out, want) {
			t.Errorf("legacy=%v: lacks %q:\n%s", legacy, want, out)
		}
	}
}

// The comments say what the scope's aaa-order does: local first, or the
// local accounts only when no server answers.
func TestBreakGlassCommentsFollowTheAAAOrder(t *testing.T) {
	m, c := fixture(t, "store.multiscope.yaml", breakGlassSeveral+"aaa:\n  order:\n    lab: local-first\n")
	if !BreakGlassFor(Request{Vendor: "cisco", Scope: "lab"}, Data{Model: m, Conf: c}).LocalFirst {
		t.Fatal("LocalFirst is not read from aaa.order")
	}
	in := stdInput(policy.BreakGlassUser{Name: "x", Role: "admin"})
	first := in
	first.LocalFirst = true
	for _, b := range []func(BreakGlassInput) string{ciscoBreakGlass, juniperBreakGlass} {
		if got := b(first); !strings.Contains(got, "local-first") || strings.Contains(got, "only when no") {
			t.Errorf("local-first:\n%s", got)
		}
		if got := b(in); strings.Contains(got, "local-first") || !strings.Contains(got, "only when no") {
			t.Errorf("tacacs-first:\n%s", got)
		}
	}
}

// 'remote' is the Junos template account of every remote user without a
// local-user-name.
func TestJunosSystemAccounts(t *testing.T) {
	for _, want := range []string{"root", "remote"} {
		if !slices.Contains(JunosSystemAccounts, want) {
			t.Errorf("%q is not a Junos system account", want)
		}
	}
}

// The docs say what the Cisco line takes: the hash form, never the
// 'algorithm-type scrypt secret <hash>' that would hash it again.
func TestBreakGlassDocsNameTheHashForm(t *testing.T) {
	for _, f := range []string{"../../README.md", "../../man/tacctl.1", "../../CHANGELOG.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		text := string(b)
		if strings.Contains(text, "algorithm-type scrypt secret <") {
			t.Errorf("%s still shows 'algorithm-type scrypt secret <hash>'", f)
		}
		if f != "../../CHANGELOG.md" && !strings.Contains(text, "secret 9 <TYPE9-HASH>") {
			t.Errorf("%s does not show 'secret 9 <TYPE9-HASH>'", f)
		}
	}
}
