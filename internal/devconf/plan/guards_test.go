package plan

// The rules around the tables: secrets (D80, D98), groups (D79), the filter
// and the lock-out guards (D97, D106), the class (lab check L1), the
// selection, and what is never emitted.

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

func hasLineWithValue(d Delta, substr string) bool {
	for _, l := range d.Lines {
		if l.HasValue && strings.Contains(l.Text, substr) {
			return true
		}
	}
	return false
}

func TestSecretsRule(t *testing.T) {
	const serverSecret = "lab-secret-0123456789abcdef"
	// a missing secret is pasted by value
	f := fixtureNamed(t, "juniper.lab-superuser")
	d := planJ(t, f, nil, Options{})
	if !hasLineWithValue(d, "tacplus-server 192.0.2.10 secret "+serverSecret) {
		t.Errorf("a missing server secret is not pasted by value:\n%s", d.Display())
	}
	if !d.HoldsSecret() || !slices.Contains(d.SecretKinds, "TACACS+ SECRET") {
		t.Errorf("the block does not know it holds a secret: %v", d.SecretKinds)
	}
	if strings.Contains(d.Display(), serverSecret) {
		t.Errorf("Display holds the value")
	}

	// a present one is neither printed nor changed
	f = fixtureNamed(t, "juniper.synthetic-lab")
	d = planJ(t, f, nil, Options{})
	if d.HoldsSecret() {
		t.Errorf("a present secret is in the block:\n%s", d.Display())
	}
	if d.Counts.SecretsPresent != 3 {
		t.Errorf("present secrets counted %d, want 3 (server, two communities)", d.Counts.SecretsPresent)
	}
	// --secrets re-pushes it by value
	d = planJ(t, f, nil, Options{Secrets: true})
	if !hasLineWithValue(d, "tacplus-server 192.0.2.10 secret "+serverSecret) || !hasLineWithValue(d, "snmp community lab-ro-community authorization read-only") {
		t.Errorf("--secrets does not re-push:\n%s", d.Display())
	}
	// --no-secrets prints the placeholder, never the value
	f = fixtureNamed(t, "juniper.lab-superuser")
	d = planJ(t, f, nil, Options{NoSecrets: true})
	if d.HoldsSecret() {
		t.Errorf("--no-secrets block holds a value")
	}
	found := false
	for _, l := range d.Lines {
		if l.Text == "set system tacplus-server 192.0.2.10 secret <SECRET>" && l.Secret && !l.HasValue {
			found = true
		}
		if strings.Contains(l.Text, serverSecret) || strings.Contains(l.Text, "lab-ro-community") {
			t.Errorf("a value in a --no-secrets line: %q", l.Text)
		}
	}
	if !found {
		t.Errorf("no placeholder line:\n%s", d.Display())
	}
	if d.Counts.Placeholders == 0 {
		t.Errorf("placeholders not counted")
	}
	// both flags: a usage error
	if _, err := Plan("juniper", nil, devconf.Extracted{}, devconf.Extracted{}, Options{Secrets: true, NoSecrets: true}); !errors.Is(err, ErrUsage) {
		t.Errorf("both flags: %v", err)
	}
	// not visible to the pull's login: left alone unless --secrets
	f = fixtureNamed(t, "juniper.lab-engineer")
	f.class = nil
	d = planJ(t, f, nil, Options{})
	if hasLineWithValue(d, "tacplus-server") {
		t.Errorf("a not-visible secret is pasted:\n%s", d.Display())
	}
	if d.Counts.SecretsNotVisible == 0 {
		t.Errorf("not-visible secrets not counted")
	}
	d = planJ(t, f, nil, Options{Secrets: true})
	if !hasLineWithValue(d, "tacplus-server 192.0.2.10 secret "+serverSecret) {
		t.Errorf("--secrets does not push a not-visible secret:\n%s", d.Display())
	}
}

func TestNeverEmitted(t *testing.T) {
	// the sections that are never planned
	for _, s := range []string{"netconf", "breakglass"} {
		_, err := Plan("juniper", nil, devconf.Extracted{}, devconf.Extracted{}, Options{Sections: []string{s}})
		if !errors.Is(err, ErrNeverEmitted) {
			t.Errorf("--section %s: %v", s, err)
		}
	}
	if _, err := Plan("juniper", nil, devconf.Extracted{}, devconf.Extracted{}, Options{Sections: []string{"bogus"}}); !errors.Is(err, ErrUsage) {
		t.Errorf("an unknown section: %v", err)
	}
	if _, err := Plan("wti", nil, devconf.Extracted{}, devconf.Extracted{}, Options{}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("wti: %v", err)
	}
	// the list: every row matches what it names, and a forward 'no aaa new-model'
	for _, r := range neverEmitted {
		l := Line{Text: r.Prefix + " x"}
		if r.Contains != "" {
			l.Text = r.Prefix + " u" + r.Contains + "y"
		}
		if r.Family == "junos" {
			l.Text = "set " + l.Text
		}
		if id, bad := neverMatch(r.Family, l); !bad || id != r.ID {
			t.Errorf("%s: %q is not matched (%s %v)", r.ID, l.Text, id, bad)
		}
	}
	if _, bad := neverMatch("ios", Line{Op: OpNo, Text: "aaa new-model"}); !bad {
		t.Errorf("a forward 'no aaa new-model' is allowed")
	}
	if _, bad := neverMatch("ios", Line{Op: OpLine, Text: "aaa new-model"}); bad {
		t.Errorf("'aaa new-model' as a line is refused")
	}
	if _, bad := neverMatch("junos", Line{Text: "set system login user RO-CLASS class RO-CLASS"}); bad {
		t.Errorf("a template user's class is on the never list")
	}
	// and no plan of any fixture emits one (Plan returns an error if so)
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		d, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatalf("%s: %v", f.name, err)
		}
		for _, l := range d.Lines {
			for _, w := range []string{"breakglass", "netconf", "lo0", "root-authentication", "username ", "enable secret", "apply-groups", "groups "} {
				if strings.Contains(l.Shown(), w) {
					t.Errorf("%s: %q holds %q", f.name, l.Shown(), w)
				}
			}
		}
	}
}

func TestInheritedStatementsRefuseTheSection(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp := expectedSections(t, f.expected)
	base := ParseJunos(capture(t, f.raw))
	// an owned extra that comes from a group: in the inherited view, not in
	// the plain one
	withExtra := ParseJunos(base.Text())
	withExtra.Add("set system accounting events interactive-commands")
	cur, err := devconf.Extract("juniper", withExtra.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := devconf.Extract("juniper", base.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan("juniper", exp, cur, plain, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Of("aaa"); st.State != StateSkipped || !strings.Contains(st.Why, "inherited from a group") {
		t.Errorf("aaa: %+v", st)
	}
	if len(lines(d, "aaa")) != 0 {
		t.Errorf("a refused section has lines: %v", lines(d, "aaa"))
	}
	if len(d.Inherited) != 1 || !strings.Contains(d.Inherited[0], "interactive-commands") {
		t.Errorf("inherited: %v", d.Inherited)
	}
	if st := d.Of("snmp"); st.State != StatePlanned {
		t.Errorf("the rest of the block must stand: snmp %+v", st)
	}
	if !d.InheritanceChecked {
		t.Errorf("inheritance not checked")
	}
	// without the plain view the check is skipped and says so
	d, err = Plan("juniper", exp, cur, devconf.Extracted{}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if d.InheritanceChecked {
		t.Errorf("checked without a plain view")
	}
	wantLine(t, d, "aaa", "delete system accounting events interactive-commands")
	if !strings.Contains(Block(d, fixtureNamed(t, "juniper.synthetic-lab").header(), Wrapper{}), "no plain view") {
		t.Errorf("the header does not say the inheritance was not checked")
	}
	// a group's statement that is not touched is not in the way
	d, err = Plan("juniper", exp, plain, plain, Options{})
	if err != nil || len(d.Inherited) != 0 {
		t.Errorf("%v %v", err, d.Inherited)
	}
}

func TestManagementFilterOnLo0(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	mut := add("set firewall family inet filter MGMT-ACL term zz-extra then accept")
	// no --from: a warning, the section stays
	d := planJ(t, f, mut, Options{})
	if d.Of("mgmt-acl").State != StatePlanned {
		t.Errorf("mgmt-acl: %+v", d.Of("mgmt-acl"))
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "--from") }) {
		t.Errorf("no warning without --from: %v", d.Warnings)
	}
	// --from inside a permit-mgmt source: the section stays, no warning
	d = planJ(t, f, mut, Options{From: "198.51.100.77"})
	if d.Of("mgmt-acl").State != StatePlanned || len(d.Warnings) != 0 {
		t.Errorf("from inside: %+v %v", d.Of("mgmt-acl"), d.Warnings)
	}
	// --from outside: refused, the rest stands
	d = planJ(t, f, func(c *JunosConfig) {
		mut(c)
		c.Add("set snmp location \"Elsewhere\"")
	}, Options{From: "203.0.113.5"})
	if st := d.Of("mgmt-acl"); st.State != StateSkipped || !strings.Contains(st.Why, "203.0.113.5") {
		t.Errorf("from outside: %+v", st)
	}
	if d.Of("snmp").State != StatePlanned {
		t.Errorf("snmp: %+v", d.Of("snmp"))
	}
	// a filter that is not applied on lo0 has no check
	f = fixtureNamed(t, "juniper.synthetic-lab-nolo0")
	d = planJ(t, f, mut, Options{From: "203.0.113.5"})
	if d.Of("mgmt-acl").State != StatePlanned {
		t.Errorf("not applied on lo0: %+v", d.Of("mgmt-acl"))
	}
}

func TestIOSAAAUnitGuards(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	exp := expectedSections(t, f.expected)
	cur, err := devconf.Extract("cisco", capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	// the current extraction knows the lines' login methods (the console has
	// none and no AAA is on: no leaf; the VTY lines say 'login local')
	leaves, known := LoginLeaves(cur)
	if !known || len(leaves) != 1 || leaves[0] != (LoginLeaf{"line vty 0 4", "login local"}) {
		t.Errorf("login leaves %v known %v", leaves, known)
	}
	// one unit: new-model first, exec directly after authentication, the
	// login method of the lines after the lists
	d, err := Plan("cisco", exp, cur, cur, Options{Device: "rtr-lab-1", Syntax: SyntaxModern})
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Of("aaa"); st.State != StatePlanned {
		t.Fatalf("aaa: %+v", st)
	}
	ls := lines(d, "aaa")
	i := slices.Index(ls, "aaa authentication login default local group LAB-TACACS")
	if i < 0 || i+1 >= len(ls) || !strings.HasPrefix(ls[i+1], "aaa authorization exec default ") {
		t.Errorf("authorization exec is not directly after authentication:\n%s", strings.Join(ls, "\n"))
	}
	if ls[0] != "aaa new-model" {
		t.Errorf("the unit does not start with aaa new-model: %q", ls[0])
	}
	// HIGH 5: command authorization is the last of the whole block, after
	// the login method of the lines
	iv := slices.Index(ls, "line vty 0 4 > login authentication default")
	if iv < 0 {
		t.Errorf("the explicit 'login local' on lines 0 to 4 is not replaced:\n%s", strings.Join(ls, "\n"))
	}
	for _, l := range ls[iv+1:] {
		if !strings.HasPrefix(l, "aaa authorization commands ") && l != "aaa authorization config-commands" {
			t.Errorf("%q after the login leaf, before command authorization", l)
		}
	}
	for _, l := range d.Lines[len(d.Lines)-3:] {
		if !l.Late {
			t.Errorf("the last lines of the block are not the late ones: %q", l.Text)
		}
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "command authorization") }) {
		t.Errorf("no warning about command authorization: %v", d.Warnings)
	}
	noLine(t, d, "aaa", "line con 0")
	if !d.AddsAAA || len(d.Login) != 1 {
		t.Errorf("AddsAAA %v login %v", d.AddsAAA, d.Login)
	}
	// the back-out: no aaa new-model, then the login method of the lines as
	// the device showed it, before anything else
	b := iosBackout(d)
	var got []string
	for _, l := range b[:5] {
		s := l.Text
		if l.Op == OpNo {
			s = "no " + s
		}
		if len(l.Context) > 0 {
			s = l.Context[0] + " > " + s
		}
		got = append(got, s)
	}
	want := []string{"no aaa new-model", "line vty 0 4 > login local"}
	if !slices.Equal(got[:2], want) {
		t.Errorf("the back-out starts %q, want %q", got[:2], want)
	}
	// BLOCKER 2: never 'no line ...'
	for _, l := range b {
		if l.Op == OpNo && strings.HasPrefix(l.Text, "line ") {
			t.Errorf("the back-out removes a line header: %q", l.Text)
		}
	}
	// no enable secret is held ('enable secret 9' is: the fixture has one)
	if slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "no enable secret") }) {
		t.Errorf("an enable secret is on the device: %v", d.Warnings)
	}
	d, err = Plan("cisco", exp, cur, cur, Options{EnableSecret: "absent", Syntax: SyntaxModern})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "no enable secret") }) {
		t.Errorf("no enable-secret warning with the override: %v", d.Warnings)
	}

	// a record of an older tacctl: no leaf and no enable marker. The aaa
	// section is refused with the pull command, the rest stands.
	old := devconf.Extracted{Vendor: "ios", SecretsVisible: true, Sections: map[string]devices.Section{}}
	for n, s := range cur.Sections {
		old.Sections[n] = s
	}
	old.Sections["aaa"] = devices.Section{Name: "aaa", Lines: []string{"aaa authentication login default local"}, Secret: []bool{false}}
	if _, known := LoginLeaves(old); known {
		t.Errorf("an older record is not unknown")
	}
	d, err = Plan("cisco", exp, old, old, Options{Device: "rtr-lab-1", Syntax: SyntaxModern})
	if err != nil {
		t.Fatal(err)
	}
	st := d.Of("aaa")
	if st.State != StateSkipped || !strings.Contains(st.Why, "tacctl device config pull rtr-lab-1") {
		t.Errorf("aaa: %+v", st)
	}
	if len(lines(d, "aaa")) != 0 {
		t.Errorf("a refused aaa section has lines")
	}
	if d.Of("roles").State != StatePlanned {
		t.Errorf("the rest of the block must stand")
	}
	// the record's leaves given as input override: the unit is planned
	d, err = Plan("cisco", exp, old, old, Options{Syntax: SyntaxModern, Login: []LoginLeaf{{"line vty 0 4", "login local"}}})
	if err != nil {
		t.Fatal(err)
	}
	if d.Of("aaa").State != StatePlanned {
		t.Errorf("aaa with the input leaves: %+v", d.Of("aaa"))
	}

	// the rendering without authorization exec: refused, never half a unit
	var cut []devices.Section
	for _, s := range exp {
		if s.Name == "aaa" {
			var ns devices.Section
			ns.Name = s.Name
			for i, l := range s.Lines {
				if strings.HasPrefix(l, "aaa authorization exec") {
					continue
				}
				ns.Lines = append(ns.Lines, l)
				ns.Secret = append(ns.Secret, s.Secret[i])
			}
			s = ns
		}
		cut = append(cut, s)
	}
	d, err = Plan("cisco", cut, cur, cur, Options{Syntax: SyntaxModern})
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Of("aaa"); st.State != StateSkipped || !strings.Contains(st.Why, "privilege 1") {
		t.Errorf("a unit without authorization exec: %+v", st)
	}
	// a device that already has AAA on needs no leaves and no back-out of
	// aaa new-model
	f2 := fixtureNamed(t, "cisco.reference-lab")
	d2 := planI(t, f2, func(c *IOSConfig) { c.noGlobal("aaa accounting commands 15 default start-stop group LAB-TACACS") }, Options{})
	if d2.AddsAAA || d2.Of("aaa").State != StatePlanned {
		t.Errorf("AAA on already: %+v", d2.Of("aaa"))
	}
}

// What the login leaves become in a plan, by the state the device's lines
// are in (WP13.1b): the rendering wants 'login authentication default' on
// the console and on the VTY lines 0 to 15.
func TestIOSLoginLeavesInThePlan(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab") // AAA on, the lines have no leaf: implicit default
	d := planI(t, f, nil, Options{})
	noLine(t, d, "aaa", "login")
	// an explicit 'login local' on a range is replaced; the back-out types it again
	d = planI(t, f, func(c *IOSConfig) {
		blk := c.blockFor("line vty 0 4")
		blk.lines = append(blk.lines, " login local")
	}, Options{})
	// typed under the range the device has, not the rendered header
	wantLine(t, d, "aaa", "line vty 0 4 > login authentication default")
	noLine(t, d, "aaa", "line vty 0 15")
	var undo []string
	for _, l := range d.Lines {
		if l.Section == "aaa" && l.Text == "login authentication default" && len(l.Context) == 1 && l.Context[0] == "line vty 0 4" {
			for _, u := range l.Undo {
				undo = append(undo, strings.Join(u.Context, " > ")+" > "+u.Text)
			}
		}
	}
	if !slices.Equal(undo, []string{"line vty 0 4 > login local"}) {
		t.Errorf("undo: %q", undo)
	}
	// a range wider than the rendering is kept, with its reason
	d = planI(t, f, func(c *IOSConfig) {
		blk := c.blockFor("line vty 5 15")
		blk.lines[0] = "line vty 5 20"
		blk.lines = append(blk.lines, " login local")
	}, Options{})
	var wider bool
	for _, k := range d.Kept {
		if strings.Contains(k.Text, "line vty 5 20 > login local") && strings.Contains(k.Note, "not cover") {
			wider = true
		}
	}
	if !wider {
		t.Errorf("a wider range is not kept: %+v", d.Kept)
	}
	// the record's own marker: no enable secret is a warning for the unit
	f = fixtureNamed(t, "cisco.reference-bare")
	exp := expectedSections(t, f.expected)
	text := strings.Replace(capture(t, f.raw), "enable secret 9 $9$EXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE\n", "", 1)
	cur, err := devconf.Extract("cisco", text, exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err = Plan("cisco", exp, cur, cur, Options{Syntax: SyntaxModern})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.HasPrefix(w, "the device has no enable secret") }) {
		t.Errorf("no warning from the marker: %v", d.Warnings)
	}
	for _, n := range d.Notes {
		if strings.HasPrefix(n, "no enable secret on the device") {
			t.Errorf("the comparison's note stays beside the warning")
		}
	}
}

func TestLoginLeavesAccessor(t *testing.T) {
	ex := devconf.Extracted{Sections: map[string]devices.Section{"aaa": {Name: "aaa", Lines: []string{
		"aaa new-model",
		"line vty 0 4 > login local",
		"line vty 5 15 > login authentication default",
		"line con 0 > login local",
		"line vty 0 15 > access-class VTY-ACL in",
		"no enable secret",
	}}}}
	got, known := LoginLeaves(ex)
	if !known || len(got) != 3 || got[0] != (LoginLeaf{"line vty 0 4", "login local"}) || got[2].Line != "line con 0" {
		t.Errorf("%v %v", got, known)
	}
	if e := enableOf(ex, nil); e != "absent" {
		t.Errorf("enable %q", e)
	}
	ex.Sections["aaa"] = devices.Section{Name: "aaa", Lines: []string{"aaa new-model", "enable secret <secret>"}}
	if e := enableOf(ex, nil); e != "present" {
		t.Errorf("enable %q", e)
	}
	// the marker alone says the record is current: no leaf is known
	if l, known := LoginLeaves(ex); !known || len(l) != 0 {
		t.Errorf("%v %v", l, known)
	}
	// an older record: neither
	ex.Sections["aaa"] = devices.Section{Name: "aaa", Lines: []string{"aaa new-model"}}
	if _, known := LoginLeaves(ex); known {
		t.Errorf("an older record is known")
	}
	if e := enableOf(ex, []string{"no enable secret on the device: with AAA on ..."}); e != "absent" {
		t.Errorf("from the note: %q", e)
	}
	if e := enableOf(ex, []string{"snmp-server user lines are not shown"}); e != "" {
		t.Errorf("%q", e)
	}
}

func TestIOSAccessClassCheck(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	// the ACL is bound on the device's vty lines: a change to its entries
	// without --from warns, with --from outside refuses, inside passes
	change := func(c *IOSConfig) {
		blk := c.blockFor("ip access-list standard VTY-ACL")
		blk.lines = slices.Insert(blk.lines, 1, " permit 203.0.113.9")
	}
	d := planI(t, f, change, Options{})
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "--from") }) {
		t.Errorf("no warning: %v", d.Warnings)
	}
	d = planI(t, f, change, Options{From: "198.51.100.9"})
	if d.Of("mgmt-acl").State != StatePlanned || len(d.Warnings) != 0 {
		t.Errorf("inside: %+v %v", d.Of("mgmt-acl"), d.Warnings)
	}
	d = planI(t, f, change, Options{From: "203.0.113.200"})
	if d.Of("mgmt-acl").State != StateSkipped {
		t.Errorf("outside: %+v", d.Of("mgmt-acl"))
	}
	// the binding itself is never a line
	for _, l := range d.Lines {
		if strings.Contains(l.Text, "access-class") {
			t.Errorf("the binding is emitted: %q", l.Text)
		}
	}
}

func TestClassTable(t *testing.T) {
	if got := Needs("roles"); !slices.Equal(got, []string{"admin-control"}) {
		t.Errorf("roles: %v", got)
	}
	if got := Needs("snmp"); !slices.Equal(got, []string{"snmp-control"}) {
		t.Errorf("snmp: %v", got)
	}
	if got := Needs("mgmt-acl"); !slices.Equal(got, []string{"firewall-control"}) {
		t.Errorf("mgmt-acl: %v", got)
	}
	if got := Needs("aaa"); !slices.Equal(got, []string{"admin-control", "secret-control", "system-control"}) {
		t.Errorf("aaa: %v", got)
	}
	// what the lab check saw for EN-CLASS: the observed column agrees with the bits
	en := enClass(t, expectedSections(t, synthExpected))
	for _, r := range ClassRules() {
		visible := en.allows(r.Bits)
		if visible != (r.Observed == "visible") {
			t.Errorf("%q: the table says %v for EN-CLASS, the lab saw %s", r.Prefix, visible, r.Observed)
		}
	}
	// EN-CLASS: mgmt-acl and the authentication order, nothing else of the
	// rendering's hierarchies
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, func(c *JunosConfig) {
		c.Add("set system accounting events interactive-commands")
		c.Add("set system authentication-order radius")
		c.Add("set firewall family inet filter MGMT-ACL term zz-extra then accept")
		c.Add("set system login class RO-CLASS permissions all")
	}, Options{Class: en})
	for sec, want := range map[string]string{"roles": StateSkipped, "mgmt-acl": StatePlanned, "snmp": StateSkipped, "aaa": StatePlanned} {
		st := d.Of(sec)
		if sec == "snmp" && st.State == StateNoChange {
			continue
		}
		if st.State != want && (sec != "snmp" || st.State != StateSkipped) {
			t.Errorf("%s: %+v, want %s", sec, st, want)
		}
	}
	ls := lines(d, "aaa")
	if len(ls) != 2 || ls[0] != "delete system authentication-order" || !strings.HasPrefix(ls[1], "set system authentication-order") {
		t.Errorf("an engineer's aaa is the authentication order only: %q", ls)
	}
	noLine(t, d, "aaa", "accounting")
	if st := d.Of("roles"); !strings.Contains(st.Why, "not visible to class EN-CLASS") {
		t.Errorf("roles reason: %q", st.Why)
	}
	if len(d.Withheld) == 0 {
		t.Errorf("nothing withheld")
	}
	b := Block(d, f.header(), Wrapper{})
	if !strings.Contains(b, "EN-CLASS cannot change") || !strings.Contains(b, "ask a superuser") {
		t.Errorf("the header does not name the class and the way out:\n%s", b)
	}
	// a class with 'all' (the superuser's) plans everything; no class too
	d = planJ(t, f, func(c *JunosConfig) { c.Add("set system login class RO-CLASS permissions all") }, Options{Class: &Class{Name: "RW-CLASS", Permissions: []string{"all"}}})
	if d.Of("roles").State != StatePlanned {
		t.Errorf("a superuser class: %+v", d.Of("roles"))
	}
}

func TestSectionSelection(t *testing.T) {
	f := fixtureNamed(t, "juniper.lab-superuser")
	d := planJ(t, f, nil, Options{Sections: []string{"snmp"}})
	for _, l := range d.Lines {
		if l.Section != "snmp" {
			t.Errorf("a line outside --section: %s", l.Shown())
		}
	}
	if d.Of("aaa").State != StateNotSelected || d.Of("snmp").State != StatePlanned {
		t.Errorf("%+v %+v", d.Of("aaa"), d.Of("snmp"))
	}
	if !strings.Contains(Block(d, f.header(), Wrapper{}), "Not selected (--section): roles, aaa, mgmt-acl.") {
		t.Errorf("the header does not name the sections left out")
	}
	d = planJ(t, f, nil, Options{Writable: map[string]bool{"snmp": true}})
	if d.Of("aaa").State != StateSkipped || d.Of("snmp").State != StatePlanned {
		t.Errorf("writable: %+v %+v", d.Of("aaa"), d.Of("snmp"))
	}
}

func TestDisplayAndEqual(t *testing.T) {
	f := fixtureNamed(t, "juniper.lab-superuser")
	d := planJ(t, f, nil, Options{})
	e := planJ(t, f, nil, Options{})
	if !d.Equal(e) {
		t.Errorf("the same plan is not equal")
	}
	e.Lines[0].Text += " x"
	if d.Equal(e) {
		t.Errorf("a changed line is equal")
	}
	if !strings.Contains(d.Display(), "[aaa]\n") || strings.Contains(d.Display(), "lab-secret") {
		t.Errorf("Display:\n%s", d.Display())
	}
	if d.Empty() || !(Delta{}).Empty() {
		t.Errorf("Empty")
	}
}

func TestEditors(t *testing.T) {
	c := ParseJunos("set snmp location \"A\"\nset system login user U class X\nset firewall family inet filter F term a then accept\nset firewall family inet filter F term b then accept\nset firewall family inet filter F term c then accept\nset system authentication-order [ password tacplus ]\n")
	err := c.Apply([]Line{
		{Op: OpSet, Text: "set snmp location \"B\""},
		{Op: OpSet, Text: "set system login user U class Y"},
		{Op: OpDelete, Text: "delete system authentication-order"},
		{Op: OpDelete, Text: "delete snmp name"}, // absent: no-op
		{Op: OpInsert, Text: "insert firewall family inet filter F term c before term a"},
		{Op: OpInsert, Text: "insert firewall family inet filter F term a after term b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "set snmp location B\nset system login user U class Y\nset firewall family inet filter F term c then accept\nset firewall family inet filter F term b then accept\nset firewall family inet filter F term a then accept\n"
	if got := c.Text(); got != want {
		t.Errorf("junos editor:\n%s\nwant\n%s", got, want)
	}
	if err := c.Apply([]Line{{Op: OpInsert, Text: "insert firewall family inet filter F term zz after term a"}}); err == nil {
		t.Errorf("insert of an absent term is not an error")
	}

	i := ParseIOS("hostname r\n!\naaa authentication login default local\nip access-list standard A\n 10 permit host 192.0.2.1\n 20 deny   any\n!\nend\n")
	err = i.Apply([]Line{
		{Op: OpLine, Text: "aaa authentication login default group G local"},
		{Op: OpLine, Context: []string{"ip access-list standard A"}, Text: "permit 192.0.2.9"},
		{Op: OpNo, Context: []string{"ip access-list standard A"}, Text: "permit 192.0.2.1"},
		{Op: OpLine, Context: []string{"tacacs server T"}, Text: "address ipv4 192.0.2.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantI := "hostname r\n!\naaa authentication login default group G local\nip access-list standard A\n 20 deny   any\n permit 192.0.2.9\n!\ntacacs server T\n address ipv4 192.0.2.10\nend\n"
	if got := i.Text(); got != wantI {
		t.Errorf("ios editor:\n%s\nwant\n%s", got, wantI)
	}
	_ = i.Apply([]Line{{Op: OpNo, Text: "tacacs server T"}})
	if strings.Contains(i.Text(), "tacacs server T") {
		t.Errorf("no of a block header leaves the block")
	}
}
