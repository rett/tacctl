package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// 'single-connection' under tacctl's server is a leaf the standard no longer
// renders (0.2.24: the server closes an idle connection, and a device that
// keeps one open for many sessions was left with a dead socket). A device
// that has it gets it removed; it is not the device's own setting.

func TestJunosSingleConnectionIsRemoved(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, addMany(
		"set system tacplus-server 192.0.2.10 single-connection",
		"set system tacplus-server 192.0.2.99 single-connection"), Options{})
	wantLine(t, d, "aaa", "delete system tacplus-server 192.0.2.10 single-connection")
	// another server is not tacctl's
	noLine(t, d, "aaa", "192.0.2.99 single-connection")
	wantKept(t, d, "aaa", "tacplus-server 192.0.2.99 single-connection")
	i := slices.IndexFunc(d.Items, func(it Item) bool {
		return strings.Contains(it.Statement, "tacplus-server 192.0.2.10 single-connection")
	})
	if i < 0 || !d.Items[i].Fixed || d.Items[i].Kind != KindExtra {
		t.Errorf("the leaf is not an extra the paste fixes: %+v", d.Items)
	}
	// the result of the paste needs nothing
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	_ = c.Apply([]Line{{Op: OpSet, Text: "set system tacplus-server 192.0.2.10 single-connection"}})
	if err := c.Apply(d.Lines); err != nil {
		t.Fatal(err)
	}
	if d2 := planText(t, f, exp, c.Text(), Options{}); len(lines(d2, "aaa")) != 0 {
		t.Errorf("a second plan: %v", lines(d2, "aaa"))
	}
}

func TestJunosSingleConnectionOfNoRenderedServerIsKept(t *testing.T) {
	// a server the rendering does not set is not tacctl's: nothing under it goes
	f := fixtureNamed(t, "juniper.synthetic-lab")
	d := planJ(t, f, add("set system tacplus-server 203.0.113.5 single-connection"), Options{})
	noLine(t, d, "aaa", "single-connection")
}

func TestIOSSingleConnectionIsRemoved(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-lab")
	d := planI(t, f, func(c *IOSConfig) {
		typeChild(c.blockFor("tacacs server TACACS"), []string{"tacacs server TACACS"}, "single-connection")
		c.insertBlock(iosBlk{lines: []string{"tacacs server OTHER", " address ipv4 192.0.2.77", " single-connection"}})
	}, Options{})
	wantLine(t, d, "aaa", "tacacs server TACACS > no single-connection")
	noLine(t, d, "aaa", "OTHER")
	wantKept(t, d, "aaa", "tacacs server OTHER > single-connection")
	// the result of the paste needs nothing
	exp := expectedSections(t, f.expected)
	c := ParseIOS(capture(t, f.raw))
	typeChild(c.blockFor("tacacs server TACACS"), []string{"tacacs server TACACS"}, "single-connection")
	if err := c.Apply(d.Lines); err != nil {
		t.Fatal(err)
	}
	if d2 := planText(t, f, exp, c.Text(), Options{}); len(lines(d2, "aaa")) != 0 {
		t.Errorf("a second plan: %v", lines(d2, "aaa"))
	}
}

func TestIOSLegacyHostLineLosesSingleConnection(t *testing.T) {
	// the fixture's legacy host line has the word: the line is retyped as
	// rendered, without it
	f := fixtureNamed(t, "cisco.reference-12x")
	d := planI(t, f, nil, Options{})
	var typed bool
	for _, l := range d.Lines {
		if l.Op == OpLine && strings.HasPrefix(l.Text, "tacacs-server host ") {
			typed = true
			if l.Text != "tacacs-server host 192.0.2.10 timeout 5 key lab-secret-0123456789abcdef" {
				t.Errorf("the host line: %q", l.Text)
			}
		}
	}
	if !typed {
		t.Errorf("the host line is not retyped:\n%s", d.Display())
	}
	// the item names the leaf, and the host line has a comment of its own in
	// the paste region, not the first reason of the section
	i := slices.IndexFunc(d.Items, func(it Item) bool { return it.Kind == KindDifferent })
	if i < 0 || !strings.HasPrefix(d.Items[i].Words, "single-connection on the TACACS+ server 192.0.2.10, no longer rendered") {
		t.Errorf("the item does not name the leaf: %+v", d.Items)
	}
	region := Block(d, f.header(), Wrapper{})
	if !strings.Contains(region, "! aaa: the TACACS+ server line, typed again without single-connection (the standard no longer renders it)\ntacacs-server host 192.0.2.10 timeout 5 key ") {
		t.Errorf("the host line has no comment of its own:\n%s", region)
	}
}

// the items of the leaf name it, whatever the vendor
func TestRetiredLeafItemsNameTheLeaf(t *testing.T) {
	for _, c := range []struct {
		d    Delta
		want string
	}{
		{planJ(t, fixtureNamed(t, "juniper.synthetic-lab"), add("set system tacplus-server 192.0.2.10 single-connection"), Options{}),
			"single-connection on the TACACS+ server 192.0.2.10, no longer rendered"},
		{planI(t, fixtureNamed(t, "cisco.reference-lab"), func(c *IOSConfig) {
			typeChild(c.blockFor("tacacs server TACACS"), []string{"tacacs server TACACS"}, "single-connection")
		}, Options{}), "single-connection on the TACACS+ server TACACS, no longer rendered"},
	} {
		if !slices.ContainsFunc(c.d.Items, func(it Item) bool { return it.Kind == KindExtra && strings.HasPrefix(it.Words, c.want) }) {
			t.Errorf("no item says %q: %+v", c.want, c.d.Items)
		}
	}
}

// the leaf is a difference of the section, not an unmanaged setting of the
// device
func TestSingleConnectionIsADifferenceNotUnmanaged(t *testing.T) {
	for _, c := range []struct{ fixture, stmt string }{
		{"juniper.synthetic-lab", "set system tacplus-server 192.0.2.10 single-connection"},
	} {
		f := fixtureNamed(t, c.fixture)
		exp := expectedSections(t, f.expected)
		cfg := ParseJunos(capture(t, f.raw))
		cfg.Add(c.stmt)
		cur, err := devconf.Extract(f.vendor, cfg.Text(), exp...)
		if err != nil {
			t.Fatal(err)
		}
		res, err := devconf.CompareAll(exp, cur)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range res {
			if r.Name == devconf.SectionAAA && (r.State != devconf.StateDiffers || r.Unmanaged != 0) {
				t.Errorf("aaa: state %s, unmanaged %d", r.State, r.Unmanaged)
			}
		}
	}
}

// A retired leaf that only an apply-group gives cannot be deleted at the top
// level, and it does not refuse the section: the other fixes of aaa stand and
// the leaf is kept, with the word that it is the group's to change.
func TestJunosRetiredLeafOfAGroupIsKeptNotRefused(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-inherit-retired")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	if st := d.Of("aaa"); st.State != StatePlanned {
		t.Fatalf("aaa: %+v", st)
	}
	if len(d.Inherited) != 0 {
		t.Errorf("inherited: %v", d.Inherited)
	}
	// the other fix of the section stands, the leaf is not typed
	wantLine(t, d, "aaa", "delete system accounting events interactive-commands")
	noLine(t, d, "aaa", "single-connection")
	var kept bool
	for _, k := range d.Kept {
		if k.Section == "aaa" && strings.Contains(k.Text, "tacplus-server 192.0.2.10 single-connection") {
			kept = k.Note == retiredFromGroup
		}
	}
	if !kept {
		t.Errorf("the leaf is not kept with the group note: %+v", d.Kept)
	}
	i := slices.IndexFunc(d.Items, func(it Item) bool {
		return strings.Contains(it.Statement, "tacplus-server 192.0.2.10 single-connection")
	})
	if i < 0 || d.Items[i].Fixed || !strings.Contains(d.Items[i].Action, "inherited from a group") {
		t.Errorf("the item: %+v", d.Items)
	}
	// no line removes it later either: a delete at the top level would not
	// find the statement
	for _, e := range d.Extras {
		if strings.Contains(e.Text, "single-connection") && (len(e.Remove) != 0 || e.Guard != retiredFromGroup) {
			t.Errorf("extra: %+v", e)
		}
	}
	// the leaf in the plain view too (at the top level) is deleted, as ever
	d2 := planJ(t, fixtureNamed(t, "juniper.synthetic-lab"), add("set system tacplus-server 192.0.2.10 single-connection"), Options{})
	wantLine(t, d2, "aaa", "delete system tacplus-server 192.0.2.10 single-connection")
}
