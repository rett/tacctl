package plan

// The findings of the second review of the planner (H1-H3, M1-M5, M9 and
// the low ones): each test fails when its finding comes back.

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// H1: copying the whole output, from the region's first banner to the end,
// and typing it must not confirm or save: after the region nothing is a plain
// line.
func TestCopyingTheWholeOutputNeverConfirmsOrSaves(t *testing.T) {
	n := 0
	for _, gc := range goldenCases(t) {
		if gc.d.Empty() {
			continue
		}
		out := Block(gc.d, gc.h, gc.w)
		bc := bannerChar(gc.d.Vendor)
		leader := commentLeader(gc.d.Vendor)
		copied := out[strings.Index(out, bc+" PASTE FROM HERE"):]
		var executed []string
		for _, l := range strings.Split(copied, "\n") {
			if l != "" && !strings.HasPrefix(l, leader) {
				executed = append(executed, l)
			}
		}
		for i, l := range executed {
			last := i == len(executed)-1
			switch {
			case l == "commit" || l == "write memory" || l == "write" || strings.HasPrefix(l, "copy "):
				t.Errorf("%s: a whole copy runs %q", gc.name, l)
			case strings.HasPrefix(l, "commit confirmed ") && !last:
				t.Errorf("%s: a whole copy runs %q before its end", gc.name, l)
			}
		}
		if len(executed) > 0 {
			end := executed[len(executed)-1]
			if gc.d.Vendor == devconf.FamilyIOS && end != "end" || gc.d.Vendor != devconf.FamilyIOS && !strings.HasPrefix(end, "commit confirmed ") {
				t.Errorf("%s: a whole copy ends with %q", gc.name, end)
			}
		}
		// the same for the back-out output
		if bo, err := Backout(gc.d, gc.h, gc.w); err == nil {
			for _, l := range strings.Split(bo[strings.Index(bo, bc+" BACK-OUT FROM HERE"):], "\n") {
				if l == "commit" || l == "write memory" {
					t.Errorf("%s: a whole copy of the back-out runs %q", gc.name, l)
				}
			}
		}
		n++
	}
	if n == 0 {
		t.Fatal("no plan with a region")
	}
}

// H2: the IOS back-out is plain, executable lines in a region of its own;
// the main output holds none of them, and the JSON carries it.
func TestIOSBackoutIsItsOwnRegionOfPlainLines(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	h, w := f.header(), Wrapper{}
	bo, err := Backout(d, h, w)
	if err != nil {
		t.Fatal(err)
	}
	region := between2(t, bo, "!!!!!", "BACK-OUT", h.Device)
	if region[0] != "configure terminal" || region[len(region)-1] != "end" {
		t.Errorf("the back-out region is %q ... %q", region[0], region[len(region)-1])
	}
	typed := nonComments(region, "!")
	for _, want := range []string{"no aaa new-model", "line vty 0 4", " login local", "no tacacs server TACACS"} {
		if !slices.Contains(typed, want) {
			t.Errorf("the back-out does not type %q:\n%s", want, strings.Join(region, "\n"))
		}
	}
	for _, l := range region {
		if strings.HasPrefix(l, "!   no ") {
			t.Errorf("a back-out line that IOS reads as a comment: %q", l)
		}
	}
	// the main output only points at it
	main := Block(d, h, w)
	if strings.Contains(main, "no aaa new-model") || strings.Contains(main, "BACK-OUT FROM") {
		t.Errorf("the main output holds the back-out")
	}
	if !strings.Contains(main, "tacctl device config plan "+h.Device+" --backout") {
		t.Errorf("the main output does not say where the back-out is")
	}
	js, err := JSON(d, h, w)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"backout": [`) || !strings.Contains(string(js), "no aaa new-model") {
		t.Errorf("the JSON has no back-out:\n%s", js)
	}
	// a plan with no statement has none
	e := Delta{Vendor: devconf.FamilyIOS}
	if _, err := Backout(e, h, w); !errors.Is(err, ErrNoBackout) {
		t.Errorf("a back-out of nothing: %v", err)
	}
}

// H2 (Junos): the back-out lines applied to the planned configuration give
// the pulled one back, term order included, for every Junos fixture (the
// property test checks the same on every fuzz case).
func TestJunosBackoutRestoresThePulledConfiguration(t *testing.T) {
	n := 0
	for _, f := range fixtures(t) {
		if f.vendor != "juniper" {
			continue
		}
		for _, secrets := range []bool{false, true} {
			exp, cur, plain := f.load(t)
			opt := f.options()
			opt.Secrets = secrets
			d, err := Plan(f.vendor, exp, cur, plain, opt)
			if err != nil {
				t.Fatal(err)
			}
			if d.Empty() {
				continue
			}
			checkJunosBackout(t, f, capture(t, f.raw), d, "secrets="+map[bool]string{false: "no", true: "yes"}[secrets])
			n++
		}
	}
	if n < 4 {
		t.Fatalf("only %d plans checked", n)
	}
}

// checkJunosBackout applies the plan and then its back-out to the pulled
// text and compares what is left with the pulled text: the statements
// (secrets and community names are not compared: they are elided on the
// device) and the order of the filter's terms.
func checkJunosBackout(t *testing.T, f fixture, raw string, d Delta, label string) {
	t.Helper()
	before, after := ParseJunos(raw), ParseJunos(raw)
	if err := after.Apply(d.Lines); err != nil {
		t.Fatalf("%s %s: %v", f.name, label, err)
	}
	var back []Line
	for _, l := range d.Backout {
		if l.Op != OpComment {
			back = append(back, l)
		}
	}
	if err := after.Apply(back); err != nil {
		t.Fatalf("%s %s: back-out: %v", f.name, label, err)
	}
	keep := func(c *JunosConfig) []string {
		var out []string
		for _, s := range c.stmts {
			j := strings.Join(s.path, " ")
			if s.head != "set" || strings.HasPrefix(j, "snmp community ") || strings.HasPrefix(j, "snmp trap-group ") {
				continue
			}
			if len(s.path) >= 4 && s.path[len(s.path)-2] == "secret" {
				s.path = s.path[:len(s.path)-1]
			}
			if len(s.path) >= 6 && s.path[2] == "authentication-key" && s.path[len(s.path)-2] == "value" {
				// an NTP key's value, a secret too
				s.path = s.path[:len(s.path)-1]
			}
			out = append(out, s.text())
		}
		slices.Sort(out)
		return out
	}
	b, a := keep(before), keep(after)
	if !slices.Equal(b, a) {
		t.Errorf("%s %s: the back-out does not restore the statements\n lost: %v\n left over: %v\nplan:\n%s\nback-out:\n%v",
			f.name, label, diffStrings(b, a), diffStrings(a, b), d.Display(), d.Backout)
	}
	filters := map[string]bool{}
	for _, st := range before.stmts {
		if len(st.path) >= 7 && st.path[0] == "firewall" && st.path[5] == "term" {
			filters[st.path[4]] = true
		}
	}
	for fl := range filters {
		if want, got := termOrder(before.Statements(), fl, true), termOrder(after.Statements(), fl, true); !slices.Equal(want, got) {
			t.Errorf("%s %s: the terms of %s are %v after the back-out, want %v", f.name, label, fl, got, want)
		}
	}
}

func diffStrings(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

// H2: a Junos term that is out of place is put back by an insert of the
// back-out.
func TestJunosBackoutRestoresTermOrder(t *testing.T) {
	f := fixtureNamed(t, "juniper.lab-superuser")
	exp, cur, plain := f.load(t)
	d0, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	// the device after the plan, then with its filter terms reversed
	c := ParseJunos(capture(t, f.raw))
	if err := c.Apply(d0.Lines); err != nil {
		t.Fatal(err)
	}
	var terms []string
	var others []jstmt
	byTerm := map[string][]jstmt{}
	for _, st := range c.stmts {
		if len(st.path) >= 7 && st.path[0] == "firewall" && st.path[5] == "term" {
			if !slices.Contains(terms, st.path[6]) {
				terms = append(terms, st.path[6])
			}
			byTerm[st.path[6]] = append(byTerm[st.path[6]], st)
			continue
		}
		others = append(others, st)
	}
	if len(terms) < 3 {
		t.Fatalf("the planned filter has %d terms", len(terms))
	}
	c.stmts = others
	for i := len(terms) - 1; i >= 0; i-- {
		c.stmts = append(c.stmts, byTerm[terms[i]]...)
	}
	text := c.Text()
	dev, err := devconf.Extract("juniper", text, exp...)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Plan("juniper", exp, dev, dev, f.options())
	if err != nil {
		t.Fatal(err)
	}
	inserts := 0
	for _, l := range d.Lines {
		if l.Op == OpInsert {
			inserts++
		}
	}
	if inserts == 0 {
		t.Fatalf("the plan has no insert for reversed terms:\n%s", d.Display())
	}
	backInserts := 0
	for _, l := range d.Backout {
		if l.Op == OpInsert {
			backInserts++
		}
	}
	if backInserts == 0 {
		t.Errorf("the back-out has no insert to put the terms back:\n%v", d.Backout)
	}
	before, after := ParseJunos(text), ParseJunos(text)
	if err := after.Apply(d.Lines); err != nil {
		t.Fatal(err)
	}
	var back []Line
	for _, l := range d.Backout {
		if l.Op != OpComment {
			back = append(back, l)
		}
	}
	if err := after.Apply(back); err != nil {
		t.Fatal(err)
	}
	if want, got := termOrder(before.Statements(), "MGMT-ACL", true), termOrder(after.Statements(), "MGMT-ACL", true); !slices.Equal(want, got) {
		t.Errorf("terms after the back-out %v, want %v", got, want)
	}
}

// H3: a device with a finding the paste does not fix is never called
// consistent.
func TestStatusIsNeverConsistentWithFindings(t *testing.T) {
	want := map[string]string{
		"juniper.synthetic-lab-engineer": StatusLeftAlone,
		// before the standard block the RADIUS device had only extras: the
		// CONSOLE list and the session id are missing now, and fixed
		"cisco.xe-reference-16": StatusNeedsChange,
		// the device carries the 0.2.5 enable list, which the standard has
		// not: the paste removes it
		"cisco.reference-12x":   StatusNeedsChange,
		"juniper.synthetic-lab": StatusNeedsChange,
	}
	seen := 0
	for _, gc := range goldenCases(t) {
		if gc.opt.Secrets || gc.opt.NoSecrets {
			continue
		}
		st := StatusFor(gc.d, gc.h)
		if len(gc.d.Items) > 0 && st.State == StatusConsistent {
			t.Errorf("%s: %d findings and the state is consistent", gc.name, len(gc.d.Items))
		}
		name := strings.TrimSuffix(gc.name, ".")
		if w, ok := want[name]; ok {
			seen++
			if st.State != w {
				t.Errorf("%s: state %q, want %q", name, st.State, w)
			}
			if js, err := JSON(gc.d, gc.h, gc.w); err != nil || !strings.Contains(string(js), `"status": "`+w+`"`) {
				t.Errorf("%s: the JSON status is not %q", name, w)
			}
		}
		if st.State == StatusLeftAlone && st.Remaining.Total() != st.Left {
			t.Errorf("%s: left %d but the severities add up to %d", name, st.Left, st.Remaining.Total())
		}
	}
	if seen != len(want) {
		t.Errorf("checked %d of %d devices", seen, len(want))
	}
	cover := Cover([]DeviceStatus{{Device: "sw-a", State: StatusLeftAlone, Left: 3, Remaining: LeftCounts{Access: 1, Monitoring: 1, Cosmetic: 1}}})
	if !strings.Contains(cover, "NOT consistent") || !strings.Contains(cover, "1 ACCESS, 1 MONITORING, 1 COSMETIC") ||
		!strings.Contains(cover, "0 consistent") {
		t.Errorf("the cover of a left-alone device:\n%s", cover)
	}
}

// M1: the region check is an allowlist: every line that is not one of the
// shapes the planner emits is refused.
func TestCheckRegionRejects(t *testing.T) {
	ios := func(mid ...string) []string {
		return append(append([]string{"configure terminal"}, mid...), "end")
	}
	junos := func(mid ...string) []string {
		return append(append([]string{"configure exclusive"}, mid...),
			"show | compare | no-more", "commit check", `commit confirmed 5 comment "tacctl plan sw 2026-10-10T14:20Z by alice"`)
	}
	cases := []struct {
		name, vendor string
		lines        []string
	}{
		{"ios do write memory", "ios", ios("aaa new-model", "do write memory")},
		{"ios do reload", "ios", ios("do reload")},
		{"ios write memory", "ios", ios("aaa new-model", "write memory")},
		{"ios end mid-region", "ios", ios("aaa new-model", "end", "snmp-server location X")},
		{"ios later configure terminal", "ios", ios("aaa new-model", "configure terminal", "snmp-server location X")},
		{"ios copy", "ios", ios("copy running-config startup-config")},
		{"ios alias", "ios", ios("alias exec x write memory")},
		{"ios exit", "ios", ios("exit")},
		{"ios delete", "ios", ios("delete flash:config.text")},
		{"ios erase", "ios", ios("erase startup-config")},
		{"ios reload", "ios", ios("reload")},
		{"ios leaf with no header", "ios", ios("aaa new-model", " key abc")},
		{"ios unknown leaf under a header", "ios", ios("tacacs server X", " do reload")},
		{"ios no line header", "ios", ios("no line vty 0 15")},
		{"ios empty line", "ios", ios("aaa new-model", "")},
		{"ios wrong first line", "ios", append([]string{"aaa new-model"}, ios("snmp-server location X")...)},
		{"ios wrong last line", "ios", []string{"configure terminal", "aaa new-model", "write memory"}},
		{"junos commit mid-region", "juniper", junos("set snmp location X", "commit", "set snmp contact Y")},
		{"junos commit confirmed not last", "juniper", junos("set snmp location X", "commit confirmed 5")},
		{"junos run", "juniper", junos("run request system reboot")},
		{"junos bare delete", "juniper", junos("delete")},
		{"junos bare set", "juniper", junos("set")},
		{"junos save", "juniper", junos("save x")},
		{"junos exit", "juniper", junos("exit")},
		{"junos rollback", "juniper", junos("rollback 1")},
		{"junos replace pattern", "juniper", junos("replace pattern a with b")},
		{"junos wildcard delete", "juniper", junos("wildcard delete snmp community *")},
		{"junos load", "juniper", junos("load override x")},
		{"junos pipe", "juniper", junos("set snmp location X | no-more")},
		{"junos semicolon", "juniper", junos("set snmp location X ; commit")},
		{"junos activate", "juniper", junos("activate snmp")},
		{"junos insert without term", "juniper", junos("insert firewall family inet filter F term A")},
		{"junos second configure", "juniper", junos("configure exclusive")},
		{"junos private session", "juniper", append([]string{"configure private"}, junos("set snmp location X")[1:]...)},
		{"junos shared session", "juniper", append([]string{"configure"}, junos("set snmp location X")[1:]...)},
		{"junos no commit check", "juniper", []string{"configure exclusive", "set snmp location X", "show | compare | no-more", `commit confirmed 5`}},
		{"junos plain commit last", "juniper", []string{"configure exclusive", "set snmp location X", "show | compare | no-more", "commit check", "commit"}},
		{"junos indented", "juniper", junos(" set snmp location X")},
		{"junos empty line", "juniper", junos("set snmp location X", "")},
		{"junos wrong first line", "juniper", append([]string{"set snmp location X"}, junos("set snmp contact Y")...)},
	}
	for _, c := range cases {
		if err := CheckRegion(c.vendor, c.lines); err == nil {
			t.Errorf("%s: accepted:\n%s", c.name, strings.Join(c.lines, "\n"))
		}
	}
	// and the shapes it must accept
	good := []struct {
		vendor string
		lines  []string
	}{
		{"juniper", junos("# aaa: the statements", "set snmp location \"Rack 4; DC1\"", "delete system accounting events interactive-commands",
			"insert firewall family inet filter MGMT-ACL term permit-mgmt before term deny-mgmt")},
		{"ios", ios("! aaa: the lines", "aaa new-model", "tacacs server TACACS", " address ipv4 192.0.2.10", " key abc",
			"aaa group server tacacs+ G", " server name TACACS", "line vty 0 4", " login authentication default",
			"ip access-list standard VTY-ACL", " permit 192.0.2.10", " deny   any log", "no privilege exec level 7 ping")},
	}
	for _, g := range good {
		if err := CheckRegion(g.vendor, g.lines); err != nil {
			t.Errorf("%s region refused: %v", g.vendor, err)
		}
	}
}

// M2: the golden check fails on a file nothing produces.
func TestGoldenFilesAreProducedFailsOnUnknown(t *testing.T) {
	dir := t.TempDir()
	// the same listing the real test does, against a directory that has an
	// extra file
	want := map[string]bool{}
	for _, gc := range goldenCases(t) {
		for _, f := range gc.files {
			want["plan."+f.name] = true
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "plan.cisco.nothing.nosecrets.plain.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	var unknown int
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "plan.") && !want[e.Name()] {
			unknown++
		}
	}
	if unknown != 1 {
		t.Errorf("an unknown plan.* file is not detected")
	}
	// and the two orphans of the review are gone from the real directory
	for _, n := range []string{"plan.cisco.reference-bare.nosecrets.plain.txt", "plan.juniper.lab-superuser.nosecrets.plain.txt"} {
		if _, err := os.Stat(filepath.Join(goldenDir, n)); err == nil {
			t.Errorf("%s is back", n)
		}
	}
}

// M3: the 'to remove it later' lines are the exact removal: the whole
// object on Junos, the 'no' line in its context on IOS.
func TestExtrasCarryTheExactRemovalLine(t *testing.T) {
	// Junos: the second server goes whole, not leaf by leaf
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, nil, Options{})
	var found bool
	for _, e := range d.Extras {
		if strings.Contains(e.Text, "tacplus-server 192.0.2.99") {
			found = true
			if len(e.Remove) != 1 || e.Remove[0].Text != "delete system tacplus-server 192.0.2.99" {
				t.Errorf("the removal of the extra server: %+v", e.Remove)
			}
		}
	}
	if !found {
		t.Fatalf("no extra for the second server: %+v", d.Extras)
	}
	for _, it := range d.Items {
		if strings.Contains(it.Statement, "192.0.2.99") && !strings.Contains(it.Action, "To remove it later: delete system tacplus-server 192.0.2.99") {
			t.Errorf("the item says %q", it.Action)
		}
		if strings.Contains(it.Action, "192.0.2.99 secret") {
			t.Errorf("the item removes one leaf: %q", it.Action)
		}
	}
	// a leaf of the rendered server is a leaf, not the server
	f2 := fixtureNamed(t, "juniper.lab-superuser")
	d = planJ(t, f2, func(c *JunosConfig) { c.Add("set system tacplus-server 192.0.2.10 port 4949") }, Options{})
	for _, e := range d.Extras {
		for _, r := range e.Remove {
			if r.Text == "delete system tacplus-server 192.0.2.10" {
				t.Errorf("the rendered server would be removed whole: %+v", e)
			}
		}
	}

	// IOS: a block of another server goes with its header 'no'
	fi := fixtureNamed(t, "cisco.reference-lab")
	di := planI(t, fi, func(c *IOSConfig) {
		c.insertBlock(iosBlk{lines: []string{"tacacs server OTHER", " address ipv4 198.51.100.7", " timeout 3"}})
		c.insertBlock(iosBlk{lines: []string{"aaa group server tacacs+ OTHERGRP", " server name OTHER"}})
	}, Options{})
	wantRemoval(t, di, "tacacs server OTHER", []string{"no tacacs server OTHER"})
	wantRemoval(t, di, "aaa group server tacacs+ OTHERGRP", []string{"no aaa group server tacacs+ OTHERGRP"})
	for _, it := range di.Items {
		if strings.Contains(it.Statement, "tacacs server OTHER") && strings.Contains(it.Action, "To remove it later") &&
			!strings.Contains(it.Action, "no tacacs server OTHER") {
			t.Errorf("the item drops the 'no': %q", it.Action)
		}
	}
	// the legacy host form
	f12 := fixtureNamed(t, "cisco.reference-12x")
	d12 := planI(t, f12, func(c *IOSConfig) { c.typeGlobal("tacacs-server host 192.0.2.77 key 7 0822455D0A16") }, Options{})
	wantRemoval(t, d12, "tacacs-server host 192.0.2.77", []string{"no tacacs-server host 192.0.2.77"})
	// the xe fixture's dynamic-author client: the line keeps its header and its 'no'
	fx := fixtureNamed(t, "cisco.xe-reference-16")
	dx := planI(t, fx, nil, Options{})
	wantRemoval(t, dx, "aaa server radius dynamic-author", []string{"aaa server radius dynamic-author", "no client 192.0.2.7"})
	for _, it := range dx.Items {
		if strings.Contains(it.Statement, "dynamic-author") && !strings.Contains(it.Action, "no client 192.0.2.7") {
			t.Errorf("the item says %q", it.Action)
		}
	}
	// the JSON carries the lines as typed
	js, err := JSON(dx, fx.header(), Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"no client 192.0.2.7"`) {
		t.Errorf("the JSON does not carry the removal lines:\n%s", js)
	}
}

// wantRemoval finds an extra whose text mentions what and checks the lines
// that remove it.
func wantRemoval(t *testing.T, d Delta, what string, lines []string) {
	t.Helper()
	for _, e := range d.Extras {
		if strings.Contains(e.Text, what) {
			if e.Guard != "" {
				t.Errorf("%q has a guard %q, not a removal", what, e.Guard)
				return
			}
			if got := removeLines(e.Remove); !slices.Equal(got, lines) {
				t.Errorf("the removal of %q is %q, want %q", what, got, lines)
			}
			return
		}
	}
	t.Errorf("no extra for %q: %+v", what, d.Extras)
}

// M4, D118 (0): AAA turned on in front of the local database of a device
// with no local user at privilege 15 is refused for the aaa unit (no region
// line of it: add the break-glass user first); a device that already runs
// AAA gets the D106 warning and an ACCESS finding instead.
func TestNoLocalUserAtPrivilege15IsAFinding(t *testing.T) {
	has := func(d Delta) (warn, item bool) {
		for _, w := range d.Warnings {
			if strings.Contains(w, "no local user at privilege 15") {
				warn = true
			}
		}
		for _, it := range d.Items {
			if it.Kind == KindNoLocal {
				item = it.Severity == SevAccess && !it.Fixed
			}
		}
		return
	}
	noUsers := func(c *IOSConfig) {
		for i := range c.blocks {
			if strings.HasPrefix(c.blocks[i].lines[0], "username ") {
				c.blocks[i].lines[0] = "!"
			}
		}
	}
	refused := func(t *testing.T, d Delta, what string) {
		t.Helper()
		st := d.Of("aaa")
		if st.State != StateSkipped || st.Kind != KindRefused ||
			!strings.Contains(st.Why, "add the break-glass user first (walkthrough Step 0), then plan again") {
			t.Errorf("%s: the aaa unit is %+v", what, st)
		}
		if n := len(lines(d, "aaa")); n != 0 {
			t.Errorf("%s: a refused unit has %d lines", what, n)
		}
		if d.Of("roles").State != StatePlanned {
			t.Errorf("%s: the rest of the plan must stand", what)
		}
	}
	// a device with no username at all that would get 'aaa new-model'
	f := fixtureNamed(t, "cisco.reference-bare")
	refused(t, planI(t, f, noUsers, Options{}), "no user")
	// the same device with a user at privilege 1 only
	refused(t, planI(t, f, func(c *IOSConfig) {
		noUsers(c)
		c.typeGlobal("username helper privilege 1 secret 5 $1$exam$EXAMPLEHASHEXAMPLEHASH")
	}, Options{}), "a privilege 1 user")
	// with a privilege 15 user: nothing, planned
	d := planI(t, f, func(c *IOSConfig) {
		noUsers(c)
		c.typeGlobal("username helper privilege 15 secret 5 $1$exam$EXAMPLEHASHEXAMPLEHASH")
	}, Options{})
	if w, i := has(d); w || i || d.Of("aaa").State != StatePlanned {
		t.Errorf("a warning (%v) or finding (%v) with a privilege 15 user: %+v", w, i, d.Of("aaa"))
	}
	// AAA already on and no local user: the warning of D106, the finding, the
	// unit planned
	lab := fixtureNamed(t, "cisco.reference-lab")
	d = planI(t, lab, noUsers, Options{})
	if w, i := has(d); !w || !i || d.Of("aaa").State != StatePlanned {
		t.Errorf("AAA on, no local user: warning %v finding %v unit %+v", w, i, d.Of("aaa"))
	}
	// the fixtures that have one
	for _, name := range []string{"cisco.reference-lab", "cisco.reference-12x", "cisco.real-12.4-7200", "cisco.xe-reference-16", "cisco.reference-bare"} {
		df := planI(t, fixtureNamed(t, name), nil, Options{})
		if w, i := has(df); w || i {
			t.Errorf("%s: a warning (%v) or finding (%v) for a device with a local user", name, w, i)
		}
	}
	// the pull that does not show the users at all: a warning that says so
	exp, cur, _ := f.load(t)
	delete(cur.Sections, devconf.SectionBreakGlass)
	du, err := Plan("cisco", exp, cur, cur, Options{Syntax: SyntaxModern})
	if err != nil {
		t.Fatal(err)
	}
	var unknown bool
	for _, w := range du.Warnings {
		if strings.Contains(w, "could not be checked") {
			unknown = true
		}
	}
	if !unknown {
		t.Errorf("no warning for a record that does not show the users: %v", du.Warnings)
	}
}

// M5: --plain is the statements and nothing else.
func TestPlainIsTheStatementsOnly(t *testing.T) {
	for _, gc := range goldenCases(t) {
		if gc.plainErr != nil || gc.d.Empty() {
			continue
		}
		plainLines := strings.Split(strings.TrimSuffix(gc.plain, "\n"), "\n")
		for i, l := range plainLines {
			if bannerBody(plainLines)[i] {
				continue // the text of a login banner is any text
			}
			switch l {
			case "configure exclusive", "configure terminal", "end", "commit check", "show | compare | no-more":
				t.Errorf("%s: plain holds the wrapper line %q", gc.name, l)
			}
			if strings.HasPrefix(l, "commit ") || strings.HasPrefix(l, "#") || strings.HasPrefix(l, "!") {
				t.Errorf("%s: plain holds %q", gc.name, l)
			}
		}
		if gc.plain == "" {
			t.Errorf("%s: an empty plain form for a plan with statements", gc.name)
		}
	}
	// the count: one plain line per statement of the region
	f := fixtureNamed(t, "juniper.lab-superuser")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	p, err := Plain(d, f.header(), Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(p, "\n"); got != len(d.Lines) {
		t.Errorf("plain has %d lines for %d statements", got, len(d.Lines))
	}
}

// M9: the syntax is an input that cannot be forgotten.
func TestCiscoSyntaxIsRequired(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, Options{Scope: "lab", Device: "rtr-lab-1"})
	if err != nil {
		t.Fatal(err)
	}
	if !d.Empty() {
		t.Errorf("a Cisco plan with no syntax has lines:\n%s", d.Display())
	}
	for _, s := range d.Sections {
		if s.State == StateNever {
			continue
		}
		if s.State != StateSkipped || s.Kind != KindNotPlannable {
			t.Errorf("section %s: %s/%s, want skipped/not-plannable", s.Name, s.State, s.Kind)
		}
		want := "the configuration syntax of this device is not known: run `tacctl device config pull rtr-lab-1` or `tacctl device ios-syntax rtr-lab-1 ios12|modern`"
		if s.Why != want {
			t.Errorf("section %s: %q", s.Name, s.Why)
		}
	}
	if len(d.Skipped) != 4 || d.Skipped[0].Kind != KindNotPlannable {
		t.Errorf("skipped: %+v", d.Skipped)
	}
	// the statements are not pasteable and the state is not 'consistent'
	if st := StatusFor(d, f.header()); st.State == StatusConsistent {
		t.Errorf("a refused plan is consistent")
	}
	if _, err := Plan(f.vendor, exp, cur, plain, Options{Syntax: "ios11"}); !errors.Is(err, ErrUsage) {
		t.Errorf("an unknown syntax: %v", err)
	}
	// each syntax plans, and the box says which
	for syn, want := range map[string]string{SyntaxIOS12: "IOS 12.x syntax", SyntaxModern: "IOS-XE and IOS 15 syntax"} {
		dd, err := Plan(f.vendor, exp, cur, plain, Options{Scope: "lab", Syntax: syn})
		if err != nil || dd.Empty() {
			t.Fatalf("%s: %v", syn, err)
		}
		if out := Block(dd, f.header(), Wrapper{}); !strings.Contains(out, want) {
			t.Errorf("%s: the box lacks %q", syn, want)
		}
	}
	// Junos has no syntax and ignores the field
	fj := fixtureNamed(t, "juniper.lab-superuser")
	jexp, jcur, jplain := fj.load(t)
	dj, err := Plan("juniper", jexp, jcur, jplain, Options{Syntax: "whatever"})
	if err != nil || dj.Empty() {
		t.Errorf("a Junos plan with a syntax: %v", err)
	}
}

// LOW: 'permit host A' is 'permit A' (a false refusal of --from otherwise).
func TestACLHostEntryMatchesTheAddress(t *testing.T) {
	a := netip.MustParseAddr("192.0.2.10")
	for entry, want := range map[string]bool{
		"permit host 192.0.2.10":       true,
		"permit host 192.0.2.10 log":   true,
		"permit 192.0.2.10":            true,
		"permit host 192.0.2.11":       false,
		"permit 192.0.2.0 0.0.0.255":   true,
		"deny host 192.0.2.10":         true,
		"permit any":                   true,
		"permit host 198.51.100.1 log": false,
	} {
		got, _ := aclEntryMatch(entry, a)
		if got != want {
			t.Errorf("%q: %v, want %v", entry, got, want)
		}
	}
	// the xe fixture's list has 'permit host ...' entries: --from one of them is no refusal
	f := fixtureNamed(t, "cisco.xe-reference-16")
	for _, e := range expectedSections(t, f.expected) {
		for _, l := range e.Lines {
			if strings.Contains(l, "permit host ") {
				ip := strings.Fields(l)[2]
				exp, cur, plain := f.load(t)
				d, err := Plan("cisco", exp, cur, plain, Options{From: ip, Syntax: SyntaxModern})
				if err != nil {
					t.Fatal(err)
				}
				for _, w := range d.Skipped {
					if strings.Contains(w.Why, "is not permitted") {
						t.Errorf("--from %s refused: %s", ip, w.Why)
					}
				}
				return
			}
		}
	}
	t.Skip("no 'permit host' entry in the xe rendering")
}
