package plan

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// The source of the AAA client must be on the device (D314). The plan names a
// source that is not (a Junos source-address no interface holds, an IOS
// source-interface that does not exist or has no address) as an access
// irregularity that the paste never fixes and the cleanup never removes; one
// that is on the device is the device's own, as before; a record that cannot
// say (no interface addresses recorded, none seen by the login) leaves the
// source alone and says so once.

const (
	badSourceWords = "is not an address of any interface this login can see"
	badIfaceWords  = "no such interface with an address that this login can see"
)

// planFacts plans a device text with the interface facts of the record given
// (the extraction's own when facts is nil and keep is true).
func planFacts(t *testing.T, f fixture, text string, facts func(devconf.Extracted) *devconf.InterfaceFacts, opt Options) Delta {
	t.Helper()
	return planFactsExp(t, f, expectedSections(t, f.expected), text, facts, opt)
}

// planFactsExp is planFacts against a rendering of its own.
func planFactsExp(t *testing.T, f fixture, exp []devices.Section, text string, facts func(devconf.Extracted) *devconf.InterfaceFacts, opt Options) Delta {
	t.Helper()
	cur, err := devconf.Extract(f.vendor, text, exp...)
	if err != nil {
		t.Fatal(err)
	}
	if facts != nil {
		cur.Interfaces = facts(cur)
	}
	if opt.Class == nil {
		opt.Class = f.class
	}
	if opt.Syntax == "" {
		opt.Syntax = f.syntax()
	}
	d, err := Plan(f.vendor, exp, cur, cur, opt)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// cleanupKeeps plans with --converge a device whose only differences are an
// extra server (which the cleanup does remove) and the wrong source: the
// cleanup must have lines, none of them the source, and the source's item
// must still be left alone. apply puts the device in the state the plan of the
// text leaves it in, then adds the extra server and the source.
func cleanupKeeps(t *testing.T, f fixture, exp []devices.Section, text string, facts func(devconf.Extracted) *devconf.InterfaceFacts, source string) {
	t.Helper()
	d0 := planFactsExp(t, f, exp, text, facts, Options{})
	var out string
	if f.vendor == "juniper" {
		c := ParseJunos(text)
		if err := c.Apply(d0.Lines); err != nil {
			t.Fatal(err)
		}
		out = c.Text()
	} else {
		c := ParseIOS(text)
		if err := c.Apply(append(slices.Clone(d0.Lines), Line{Op: OpLine, Context: []string{"tacacs server SPARESRV"}, Text: "address ipv4 192.0.2.98"})); err != nil {
			t.Fatal(err)
		}
		out = c.Text()
	}
	dc := planFactsExp(t, f, exp, out, facts, Options{Converge: true})
	if len(dc.Cleanup.Lines) == 0 {
		t.Fatalf("the cleanup removes nothing, the extra server stays:\n%+v", dc.Items)
	}
	for _, l := range dc.Cleanup.Lines {
		if strings.Contains(l.Text, source) {
			t.Errorf("the cleanup removes the source: %+v", l)
		}
	}
	items := sourceItems(dc)
	if len(items) != 1 || !strings.HasPrefix(items[0].Action, "Left alone") || strings.Contains(items[0].Action, "cleanup") {
		t.Errorf("the item of the source in a cleanup plan: %+v", dc.Items)
	}
}

func junosText(t *testing.T, f fixture, mut func(*JunosConfig)) string {
	t.Helper()
	c := ParseJunos(capture(t, f.raw))
	mut(c)
	return c.Text()
}

func iosText(t *testing.T, f fixture, mut func(*IOSConfig)) string {
	t.Helper()
	c := ParseIOS(capture(t, f.raw))
	mut(c)
	return c.Text()
}

func sourceItems(d Delta) []Item {
	var out []Item
	for _, it := range d.Items {
		if strings.Contains(it.Words, badSourceWords) || strings.Contains(it.Words, badIfaceWords) {
			out = append(out, it)
		}
	}
	return out
}

// hasNote reports whether the plan carries a note with the text.
func hasNote(d Delta, part string) bool {
	return slices.ContainsFunc(d.Notes, func(n string) bool { return strings.Contains(n, part) })
}

func TestJunosAAASourceAddressIsChecked(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	base := planJ(t, f, nil, Options{})
	// the lab holds 192.0.2.250 on lo0
	ok := junosText(t, f, addMany("set system tacplus-server 192.0.2.10 source-address 192.0.2.250"))
	bad := junosText(t, f, addMany("set system tacplus-server 192.0.2.10 source-address 192.0.2.99"))

	d := planFacts(t, f, ok, nil, Options{})
	if len(d.Items) != len(base.Items) || !slices.Equal(lines(d, ""), lines(base, "")) || len(d.Notes) != len(base.Notes) {
		t.Errorf("a source on an interface changes the plan: %d items, was %d; notes %v", len(d.Items), len(base.Items), d.Notes)
	}
	if o := ownOf(d, devconf.SectionAAA); o.Count != ownOf(base, devconf.SectionAAA).Count+1 {
		t.Errorf("the source is not counted as the device's own: %+v", o)
	}

	d = planFacts(t, f, bad, nil, Options{})
	items := sourceItems(d)
	if len(items) != 1 || len(d.Items) != len(base.Items)+1 {
		t.Fatalf("items %+v", d.Items)
	}
	it := items[0]
	if it.Kind != KindExtra || it.Severity != SevAccess || it.Fixed || it.Section != devconf.SectionAAA ||
		it.Words != "the TACACS+ server 192.0.2.10: source-address 192.0.2.99 "+badSourceWords ||
		it.Action != "Left alone: add the address to an interface, or change the source (not managed by tacctl)." {
		t.Errorf("item %+v", it)
	}
	// the paste does not touch it, and the count of the access findings is one more
	if !slices.Equal(lines(d, ""), lines(base, "")) {
		t.Errorf("the paste changes:\n%v\nwas\n%v", lines(d, ""), lines(base, ""))
	}
	if got, was := leftOf(d).Access, leftOf(base).Access; got != was+1 {
		t.Errorf("%d access findings, was %d", got, was)
	}
	if o := ownOf(d, devconf.SectionAAA); o.Count != ownOf(base, devconf.SectionAAA).Count {
		t.Errorf("a source the device does not hold is counted as its own: %+v", o)
	}
	// the cleanup never removes it, whatever else it removes
	cleanupKeeps(t, f, expectedSections(t, f.expected), bad, nil, "source-address")
	for _, e := range d.Extras {
		if strings.Contains(e.Text, "source-address") && e.Guard == "" {
			t.Errorf("extra %+v", e)
		}
	}
	// and the JSON of the plan says so
	js, err := JSON(d, Header{Device: "jsw1"}, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Items []Item `json:"irregularities"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	if got := sourceItems(Delta{Items: doc.Items}); len(got) != 1 || got[0].Severity != "ACCESS" {
		t.Errorf("JSON items %+v\n%s", doc.Items, js)
	}

	// nothing recorded: the source stays the device's own, and the plan says why
	none := func(devconf.Extracted) *devconf.InterfaceFacts { return nil }
	d = planFacts(t, f, bad, none, Options{})
	if len(d.Items) != len(base.Items) || len(sourceItems(d)) != 0 || !hasNote(d, "their addresses are not recorded (pull the device again)") {
		t.Errorf("not recorded: %d items, notes %v", len(d.Items), d.Notes)
	}
	// a pull that saw no interface
	blind := func(devconf.Extracted) *devconf.InterfaceFacts { return &devconf.InterfaceFacts{} }
	d = planFacts(t, f, bad, blind, Options{})
	if len(d.Items) != len(base.Items) || len(sourceItems(d)) != 0 || !hasNote(d, "this login cannot see the interfaces") {
		t.Errorf("not visible: %d items, notes %v", len(d.Items), d.Notes)
	}
	// with no source on the device there is nothing to say
	d = planFacts(t, f, junosText(t, f, func(*JunosConfig) {}), none, Options{})
	if hasNote(d, "AAA server is not checked") {
		t.Errorf("a note without a source: %v", d.Notes)
	}
}

func TestIOSAAASourceInterfaceIsChecked(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	// a scope that sets the source interface: the rendering has the
	// statement, and the lab holds it
	exp := expectedSections(t, f.expected)
	for i := range exp {
		if exp[i].Name == devconf.SectionAAA {
			exp[i].Lines = append(exp[i].Lines, "ip tacacs source-interface Loopback0")
			exp[i].Secret = append(exp[i].Secret, false)
		}
	}
	facts := func(names ...string) func(devconf.Extracted) *devconf.InterfaceFacts {
		return func(devconf.Extracted) *devconf.InterfaceFacts {
			x := &devconf.InterfaceFacts{Visible: true, Addresses: map[string][]string{}, Sources: map[string]string{"tacacs": "Loopback0"}}
			for _, n := range names {
				x.Addresses[n] = []string{"192.0.2.250"}
			}
			return x
		}
	}
	text := capture(t, f.raw)
	base := planFactsExp(t, f, exp, text, facts("loopback0"), Options{})
	if len(sourceItems(base)) != 0 || hasNote(base, "AAA server is not checked") {
		t.Fatalf("the lab with its interface: %+v %v", base.Items, base.Notes)
	}
	// the rendered source interface is not on the device
	d := planFactsExp(t, f, exp, text, facts("vlan10"), Options{})
	items := sourceItems(d)
	if len(items) != 1 || len(d.Items) != len(base.Items)+1 {
		t.Fatalf("items %+v", d.Items)
	}
	if it := items[0]; it.Severity != SevAccess || it.Kind != KindExtra || it.Fixed || it.Words != "source-interface Loopback0: "+badIfaceWords ||
		!strings.HasPrefix(it.Action, "Left alone: add the address to an interface, or change the source") {
		t.Errorf("item %+v", it)
	}
	if !slices.Equal(lines(d, ""), lines(base, "")) {
		t.Errorf("the paste changes:\n%v\nwas\n%v", lines(d, ""), lines(base, ""))
	}
	// not recorded, not visible
	if d := planFactsExp(t, f, exp, text, func(devconf.Extracted) *devconf.InterfaceFacts { return nil }, Options{}); len(sourceItems(d)) != 0 ||
		!hasNote(d, "their addresses are not recorded") {
		t.Errorf("not recorded: %v", d.Notes)
	}
	if d := planFactsExp(t, f, exp, text, func(devconf.Extracted) *devconf.InterfaceFacts { return &devconf.InterfaceFacts{} }, Options{}); len(sourceItems(d)) != 0 ||
		!hasNote(d, "this login cannot see the interfaces") {
		t.Errorf("not visible: %v", d.Notes)
	}
	// the cleanup keeps the finding
	cleanupKeeps(t, f, exp, text, facts("vlan10"), "source-interface")
}

// The source interface of tacctl's server group, and the device's own that
// the scope does not set (the section does not hold it; the pull recorded it).
func TestIOSAAAGroupAndGlobalSourceInterface(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	facts := func(src string, names ...string) func(devconf.Extracted) *devconf.InterfaceFacts {
		return func(devconf.Extracted) *devconf.InterfaceFacts {
			x := &devconf.InterfaceFacts{Visible: true, Addresses: map[string][]string{}, Sources: map[string]string{}}
			if src != "" {
				x.Sources["tacacs"] = src
			}
			for _, n := range names {
				x.Addresses[n] = []string{"192.0.2.250"}
			}
			return x
		}
	}
	text := capture(t, f.raw)
	base := planFacts(t, f, text, facts("Loopback0", "loopback0"), Options{})
	if len(sourceItems(base)) != 0 || hasNote(base, "AAA server is not checked") {
		t.Fatalf("the lab: %+v %v", base.Items, base.Notes)
	}

	// the device's own, which the rendering does not set: it must exist
	d := planFacts(t, f, text, facts("Loopback9", "loopback0"), Options{})
	if items := sourceItems(d); len(items) != 1 || items[0].Words != "source-interface Loopback9: "+badIfaceWords || items[0].Severity != SevAccess {
		t.Fatalf("global: %+v", d.Items)
	}
	if !slices.Equal(lines(d, ""), lines(base, "")) {
		t.Errorf("the paste changes:\n%v", lines(d, ""))
	}
	if d := planFacts(t, f, text, func(devconf.Extracted) *devconf.InterfaceFacts {
		return &devconf.InterfaceFacts{Sources: map[string]string{"tacacs": "Loopback9"}}
	}, Options{}); len(sourceItems(d)) != 0 || !hasNote(d, "this login cannot see the interfaces") {
		t.Errorf("not visible: %v %+v", d.Notes, d.Items)
	}
	// the RADIUS source of a TACACS+ scope is no business of the AAA it sets up
	if d := planFacts(t, f, text, func(c devconf.Extracted) *devconf.InterfaceFacts {
		x := facts("Loopback0", "loopback0")(c)
		x.Sources["radius"] = "Loopback9"
		return x
	}, Options{}); len(sourceItems(d)) != 0 {
		t.Errorf("a RADIUS source of a TACACS+ scope: %+v", d.Items)
	}

	// the source interface of tacctl's server group
	grp := iosText(t, f, func(c *IOSConfig) {
		_ = c.Apply([]Line{{Op: OpLine, Context: []string{"aaa group server tacacs+ LAB-TACACS"}, Text: "ip tacacs source-interface Loopback7"}})
	})
	d = planFacts(t, f, grp, facts("Loopback0", "loopback0"), Options{})
	items := sourceItems(d)
	if len(items) != 1 || items[0].Words != "the TACACS+ server group LAB-TACACS, source-interface Loopback7: "+badIfaceWords {
		t.Fatalf("group source: %+v", d.Items)
	}
	if !slices.Equal(lines(d, ""), lines(base, "")) {
		t.Errorf("the paste changes with the group source:\n%v", lines(d, ""))
	}
	if d := planFacts(t, f, grp, facts("Loopback0", "loopback0", "loopback7"), Options{}); len(sourceItems(d)) != 0 {
		t.Errorf("a group source on an interface: %+v", d.Items)
	}
	if d := planFacts(t, f, grp, func(devconf.Extracted) *devconf.InterfaceFacts { return nil }, Options{}); len(sourceItems(d)) != 0 ||
		!hasNote(d, "their addresses are not recorded") {
		t.Errorf("group source, nothing recorded: %v", d.Notes)
	}
	cleanupKeeps(t, f, expectedSections(t, f.expected), grp, facts("Loopback0", "loopback0"), "source-interface")
}
