package plan

// 0.2.7: the objects of a scope's IOS snmp block in the plan. A list the
// block defines is owned whole, a community of it is retyped as it states it,
// a trap host and an 'enable traps' line are only ever added, and the
// device's own communities, hosts and lines are kept.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

func ciscoBlockFixture(t testing.TB) fixture {
	t.Helper()
	return fixtureNamed(t, "cisco.synthetic-block")
}

// ciscoConverges applies the plan to the device's text and compares again:
// the snmp section must read ok.
func ciscoConverges(t *testing.T, f fixture, exp []devices.Section, text string, d Delta) {
	t.Helper()
	c := ParseIOS(text)
	if err := c.Apply(d.Lines); err != nil {
		t.Fatal(err)
	}
	cur, err := devconf.Extract(f.vendor, c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := devconf.CompareAll(exp, cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == devconf.SectionSNMP && r.State != devconf.StateOK {
			t.Errorf("snmp reads %s after the plan:\n%v", r.State, r.Lines)
		}
	}
}

// (a) The device holds the block's objects and others of its own: nothing to
// plan, ok (+N unmanaged), and no mark of the block's is kept.
func TestCiscoBlockPresentIsNothingToDo(t *testing.T) {
	f := ciscoBlockFixture(t)
	d := planI(t, f, nil, Options{Scope: "lab"})
	if got := lines(d, "snmp"); len(got) != 0 {
		t.Errorf("the plan has snmp lines: %q", got)
	}
	if sp := d.Of("snmp"); sp.State != StateNoChange {
		t.Errorf("snmp: %s", sp.State)
	}
	for _, k := range d.Kept {
		if strings.Contains(k.Text, "<secret:2>") || strings.Contains(k.Text, "<secret:3>") {
			t.Errorf("the block's own object is kept: %q", k.Text)
		}
	}
	exp := expectedSections(t, f.expected)
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	rs, _ := devconf.CompareAll(exp, cur)
	for _, r := range rs {
		if r.Name == devconf.SectionSNMP && (r.State != devconf.StateOK || r.Unmanaged != 3 || !strings.HasPrefix(r.StateText(), "ok (+3")) {
			t.Errorf("snmp: %s %d %q\n%v", r.State, r.Unmanaged, r.StateText(), r.Lines)
		}
	}
}

// (b) The device lacks every object of the block: the list first, then the
// community, the host and the trap line; the strings by value; the device's
// own communities and hosts are not touched; the back-out removes what was
// added, the list as one 'no'.
func TestCiscoBlockNewIsSet(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-block-new")
	d := planI(t, f, nil, Options{Scope: "lab"})
	want := []string{
		"ip access-list standard POLLERS > permit host 192.0.2.60",
		"ip access-list standard POLLERS > permit 198.51.100.0 0.0.0.255",
		"snmp-server community <secret:2> RO POLLERS",
		"snmp-server host 192.0.2.61 version 2c <secret:3>",
		"snmp-server enable traps snmp linkdown linkup",
	}
	if got := lines(d, "snmp"); !slices.Equal(got, want) {
		t.Errorf("the snmp lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	typed := realTexts(d)
	for _, w := range []string{"snmp-server community poller-ro RO POLLERS", "snmp-server host 192.0.2.61 version 2c poller-traps"} {
		if !slices.Contains(typed, w) {
			t.Errorf("not typed by value: %q (%q)", w, typed)
		}
	}
	noLine(t, d, "snmp", "no snmp-server")
	var back []string
	for _, l := range iosBackout(d) {
		text := l.Shown()
		if l.Op == OpNo {
			text = "no " + text
		}
		if len(l.Context) == 0 {
			back = append(back, text)
		}
	}
	for _, w := range []string{"no snmp-server enable traps snmp linkdown linkup", "no snmp-server host 192.0.2.61 version 2c <secret:3>",
		"no snmp-server community <secret:2>", "no ip access-list standard POLLERS"} {
		if !slices.Contains(back, w) {
			t.Errorf("the back-out lacks %q:\n%s", w, strings.Join(back, "\n"))
		}
	}
	for _, l := range iosBackout(d) {
		if strings.Contains(l.Text, "lab-ro-community") || strings.Contains(l.Text, "other-example") || strings.Contains(l.Text, "example-trap-community") {
			t.Errorf("the back-out names another community: %q", l.Text)
		}
	}
	// --no-secrets: placeholders, no string
	nd := planI(t, f, nil, Options{Scope: "lab", NoSecrets: true})
	for _, l := range nd.Lines {
		if strings.Contains(l.Text, "poller-") {
			t.Errorf("--no-secrets types a string: %q", l.Text)
		}
	}
	ciscoConverges(t, f, expectedSections(t, f.expected), capture(t, f.raw), d)
}

// The report names the block by its scope and never a string, and says that
// the block's lines were not checked on a device.
func TestCiscoBlockWordsAndNote(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-block-new")
	d := planI(t, f, nil, Options{Scope: "lab"})
	why := d.Of("snmp").Why
	for _, want := range []string{"the SNMP block of scope 'lab' (its communities, access lists, trap hosts and 'enable traps' lines)",
		"the access lists the SNMP block of scope 'lab' defines", "the communities of the SNMP block of scope 'lab'",
		"the trap hosts of the SNMP block of scope 'lab'", "the 'enable traps' lines of the SNMP block of scope 'lab'"} {
		if !strings.Contains(why, want) {
			t.Errorf("the why-line lacks %q: %q", want, why)
		}
	}
	for _, it := range d.Items {
		for _, text := range []string{it.Words, it.Statement, it.Action} {
			for _, bad := range []string{"poller-ro", "poller-traps", "other-example", "lab-ro-community", "example-trap-community"} {
				if strings.Contains(text, bad) {
					t.Errorf("an item names a string: %q", text)
				}
			}
		}
	}
	var words []string
	for _, it := range d.Items {
		words = append(words, it.Words)
	}
	for _, want := range []string{"access list POLLERS of the SNMP block of scope 'lab': 2 statements",
		"a community of the SNMP block of scope 'lab': RO POLLERS",
		"a trap host of the SNMP block of scope 'lab': 192.0.2.61 version 2c <secret:3>",
		"an 'enable traps' line of the SNMP block of scope 'lab': snmp linkdown linkup"} {
		if !slices.Contains(words, want) {
			t.Errorf("the items lack %q:\n%s", want, strings.Join(words, "\n"))
		}
	}
	// the block's lines were pasted and read back: no note says otherwise
	for _, n := range d.Notes {
		if strings.Contains(n, "SNMP block of scope 'lab'") && strings.Contains(n, "not been checked") {
			t.Errorf("a note says the SNMP block is not checked on a device: %q", n)
		}
	}
	// without a block the report does not say so
	g := fixtureNamed(t, "cisco.reference-lab")
	gd := planI(t, g, nil, Options{Scope: "lab"})
	for _, n := range gd.Notes {
		if strings.Contains(n, "SNMP block") {
			t.Errorf("a note about a block that is not in force: %q", n)
		}
	}
}

// (c) The block's objects in other shapes: the stray entry goes under its own
// list, a community of another access and a host with other options are
// retyped in place and never removed; the back-out types the device's lines
// again by value.
func TestCiscoBlockStrayShapes(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-block-stray")
	d := planI(t, f, nil, Options{Scope: "lab"})
	got := lines(d, "snmp")
	for _, w := range []string{"ip access-list standard POLLERS > permit 198.51.100.0 0.0.0.255", "snmp-server community <secret:2> RO POLLERS",
		"snmp-server host 192.0.2.61 version 2c <secret:3>", "snmp-server enable traps snmp linkdown linkup",
		"ip access-list standard POLLERS > no permit 203.0.113.9"} {
		if !slices.Contains(got, w) {
			t.Errorf("the plan lacks %q:\n%s", w, strings.Join(got, "\n"))
		}
	}
	if slices.ContainsFunc(got, func(l string) bool { return strings.HasPrefix(l, "no snmp-server") }) {
		t.Errorf("a community or host was removed:\n%s", strings.Join(got, "\n"))
	}
	var back []string
	for _, l := range iosBackout(d) {
		back = append(back, l.Text)
	}
	for _, w := range []string{"snmp-server community poller-ro RW POLLERS", "snmp-server host 192.0.2.61 version 2c poller-traps udp-port 1162"} {
		if !slices.Contains(back, w) {
			t.Errorf("the back-out lacks %q:\n%s", w, strings.Join(back, "\n"))
		}
	}
	exp := expectedSections(t, f.expected)
	ciscoConverges(t, f, exp, capture(t, f.raw), d)
}

// IOS stores a host in its own form: the default version, kind and port are
// not printed and the types come in IOS's order. A device that holds the
// block's host that way is consistent.
func TestCiscoBlockHostStoredForm(t *testing.T) {
	f := ciscoBlockFixture(t)
	exp := expectedSections(t, f.expected)
	for i := range exp {
		for j, l := range exp[i].Lines {
			if l == "snmp-server host 192.0.2.61 version 2c poller-traps" {
				exp[i].Lines[j] = "snmp-server host 192.0.2.61 version 2c poller-traps udp-port 162 entity config"
			}
		}
	}
	c := ParseIOS(capture(t, f.raw))
	c.typeGlobal("snmp-server host 192.0.2.61 version 2c poller-traps config entity")
	d := planText(t, f, exp, c.Text(), Options{Scope: "lab"})
	noLine(t, d, "snmp", "snmp-server host")
	// a type that is missing is a difference
	c.typeGlobal("snmp-server host 192.0.2.61 version 2c poller-traps config")
	d = planText(t, f, exp, c.Text(), Options{Scope: "lab"})
	wantLine(t, d, "snmp", "snmp-server host 192.0.2.61 version 2c <secret:3> config entity")
}

// A record of an older tacctl (every name the bare mark): nothing is removed
// and nothing under a community is touched.
func TestCiscoBlockOlderRecord(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-block-stray")
	exp, cur, _ := f.load(t)
	old := devconf.Extracted{Vendor: cur.Vendor, SecretsVisible: true, Sections: map[string]devices.Section{}}
	for name, s := range cur.Sections {
		var ls []string
		for _, l := range s.Lines {
			ls = append(ls, reMarks.ReplaceAllString(l, secretMark))
		}
		old.Sections[name] = devices.Section{Name: name, Lines: ls}
	}
	opt := f.options()
	d, err := Plan(f.vendor, exp, old, old, opt)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range d.Lines {
		if l.Op == OpNo && strings.HasPrefix(l.Text, "snmp-server") {
			t.Errorf("an older record's line is removed: %q", l.Text)
		}
	}
}

// --converge never removes the device's own communities, hosts, trap lines or
// lists: they are kept, with the reason.
func TestCiscoBlockConvergeKeepsTheDevicesOwn(t *testing.T) {
	f := ciscoBlockFixture(t)
	exp, cur, plain := f.load(t)
	o := f.options()
	o.Converge = true
	d, err := Plan(f.vendor, exp, cur, plain, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range d.Cleanup.Lines {
		if strings.Contains(l.Text, "snmp-server") || strings.Contains(strings.Join(l.Context, " "), "POLLERS") {
			t.Errorf("the cleanup touches the SNMP block's or the device's own: %q", l.Text)
		}
	}
	for _, l := range d.Lines {
		if l.Op == OpNo && strings.HasPrefix(l.Text, "snmp-server") {
			t.Errorf("the plan removes %q", l.Text)
		}
	}
}
