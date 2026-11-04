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
