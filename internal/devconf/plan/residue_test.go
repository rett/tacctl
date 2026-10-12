package plan

import (
	"strings"
	"testing"
)

// The lines an IOS 15.x image keeps where a privilege line was removed (the
// lab IOSv 15.6(2)T and CSR1000v 16.7.1, CHANGELOG 61) are the image's own:
// no extra, no irregularity, no 'no', no mention in the output.
func residueFixture() fixture {
	return fixture{name: "cisco.ios15-privilege-residue", vendor: "cisco",
		raw:      "ios/ios15-privilege-residue/running-config.txt",
		expected: "ios/ios15-privilege-residue/expected.txt"}
}

// residueWords are what the fixture's residue lines name.
var residueWords = []string{"monitor", "clear counters", "clear line", "clear ip", "clear arp-cache", "traceroute", "ping", "level 1 clear"}

func TestIOS15PrivilegeResidueIsNoIrregularity(t *testing.T) {
	f, ctl := residueFixture(), fixtureNamed(t, "cisco.reference-lab")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	cexp, ccur, cplain := ctl.load(t)
	dc, err := Plan(ctl.vendor, cexp, ccur, cplain, ctl.options())
	if err != nil {
		t.Fatal(err)
	}
	// the same plan as the control device, which has none of the lines
	if !d.Equal(dc) {
		t.Errorf("the residue changed the plan:\n%s\n--- control\n%s", d.Display(), dc.Display())
	}
	if len(d.Items) != len(dc.Items) || len(d.Kept) != len(dc.Kept) {
		t.Errorf("items %d (control %d), kept %d (control %d)", len(d.Items), len(dc.Items), len(d.Kept), len(dc.Kept))
	}
	for i := range min(len(d.Items), len(dc.Items)) {
		if d.Items[i].Statement != dc.Items[i].Statement || d.Items[i].Kind != dc.Items[i].Kind {
			t.Errorf("item %d: %+v, control %+v", i, d.Items[i], dc.Items[i])
		}
	}
	h, w := f.header(), Wrapper{ConfirmMinutes: 5}
	for _, out := range []string{Report(d, h, w), Block(d, h, w)} {
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "privilege exec level 15") || strings.Contains(l, "privilege exec level 1 ping") ||
				strings.Contains(l, "privilege exec level 1 traceroute") || strings.Contains(l, "privilege exec level 1 clear") {
				if strings.HasPrefix(strings.TrimSpace(l), "! (on IOS 15.x") {
					continue
				}
				t.Errorf("the output names a residue line: %q", l)
			}
		}
	}
	// after the pastes the plan has nothing to say about the roles
	sexp, scur, _ := settledFixture(t, f, f.options())
	sd, err := Plan(f.vendor, sexp, scur, scur, f.options())
	if err != nil {
		t.Fatal(err)
	}
	if got := statusOf(sd); got != statusOf(func() Delta {
		cs, cc, _ := settledFixture(t, ctl, ctl.options())
		x, err := Plan(ctl.vendor, cs, cc, cc, ctl.options())
		if err != nil {
			t.Fatal(err)
		}
		return x
	}()) {
		t.Errorf("settled status %s differs from the control's", got)
	}
	for _, it := range sd.Items {
		if it.Section == "roles" {
			t.Errorf("a roles item after the paste: %+v", it)
		}
	}
	if sd.Of("roles").Why != "" && strings.Contains(sd.Of("roles").Why, "privilege") {
		t.Errorf("the roles why-line names a privilege line: %q", sd.Of("roles").Why)
	}
}

// What stays reported: a line at a level that is not the command's default
// (somebody lowered it), and a rendered line that is not there.
func TestIOS15PrivilegeResidueKeepsTheRealFindings(t *testing.T) {
	f := residueFixture()
	d := planI(t, f, func(c *IOSConfig) {
		c.typeGlobal("privilege exec level 7 clear counters")
		c.typeGlobal("privilege exec level 7 ping")
		c.typeGlobal("privilege exec level 15 debug")
	}, Options{})
	wantLine(t, d, "roles", "no privilege exec level 7 clear counters")
	wantLine(t, d, "roles", "no privilege exec level 7 ping")
	// not in the table, at a level no group has: kept, said so
	wantKept(t, d, "roles", "privilege exec level 15 debug")
	for _, w := range residueWords[:7] {
		noLine(t, d, "roles", "no privilege exec level 15 "+w)
		noLine(t, d, "roles", "no privilege exec level 1 "+w)
	}
	for _, k := range d.Kept {
		if strings.Contains(k.Text, "level 15 clear") || strings.Contains(k.Text, "level 1 ping") || strings.Contains(k.Text, "level 15 monitor") {
			t.Errorf("a residue line is kept with a note: %+v", k)
		}
	}

	// a rendered line that is missing is typed, whatever the residue says
	d = planI(t, f, func(c *IOSConfig) { c.noGlobal("privilege exec level 7 undebug all") }, Options{})
	wantLine(t, d, "roles", "privilege exec level 7 undebug all")
	noLine(t, d, "roles", "no privilege exec level 15")
	noLine(t, d, "roles", "no privilege exec level 1 ping")
}
