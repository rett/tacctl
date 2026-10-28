package plan

// 0.2.20: the device's own statements are no irregularity, for every vendor
// and section the comparison has them in (snmp and system on Junos and IOS,
// the netconf service, a WTI unit's aaa and snmp pages): no item, a count
// that is the comparison's, one Kept line.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// checkOwn holds a plan against the comparison of the same pull: where the
// comparison counts N statements of the device's own, the plan keeps N and
// lists none of them as an item.
func checkOwn(t *testing.T, name string, d Delta, exp []devices.Section, cur devconf.Extracted, sections ...string) int {
	t.Helper()
	rs, err := devconf.CompareAll(exp, cur)
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, r := range rs {
		if len(sections) > 0 && !slices.Contains(sections, r.Name) {
			continue
		}
		if st := d.Of(r.Name).State; st == StateNotSelected || st == StateNA || st == StateNever || st == "" {
			continue
		}
		if got := ownOf(d, r.Name).Count; got != r.Unmanaged {
			t.Errorf("%s [%s]: the plan keeps %d statements of the device's own, the comparison counts %d", name, r.Name, got, r.Unmanaged)
		}
		total += r.Unmanaged
		for _, l := range r.Lines {
			if l.Op != devconf.OpExtra || !l.Unmanaged {
				continue
			}
			for _, it := range d.Items {
				if it.Section == r.Name && strings.TrimPrefix(it.Statement, "e.g. ") == stemOf(l) {
					t.Errorf("%s [%s]: the device's own %q is an item: %+v", name, r.Name, stemOf(l), it)
				}
			}
		}
	}
	return total
}

// Every fixture, as pulled and after the pastes that settle it: the count of
// the device's own is the comparison's and no item stands for one of them.
func TestOwnCountIsTheComparisonsForEveryFixture(t *testing.T) {
	seen := 0
	for _, f := range append(fixtures(t), keptExtrasFixture()) {
		exp, cur, plain := f.load(t)
		d, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatal(err)
		}
		seen += checkOwn(t, f.name, d, exp, cur)
		exp, cur, plain = settledFixtureFull(t, f)
		d, err = Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatal(err)
		}
		seen += checkOwn(t, f.name+" (settled)", d, exp, cur)
	}
	for _, p := range allWTIPlans(t) {
		seen += checkOwn(t, "wti "+p.name, p.d, p.exp, p.cur, devconf.SectionAAA, devconf.SectionSNMP)
	}
	if seen == 0 {
		t.Error("no fixture has a statement of the device's own")
	}
}

// settledFixtureFull is settledFixture with the plain view.
func settledFixtureFull(t testing.TB, f fixture) ([]devices.Section, devconf.Extracted, devconf.Extracted) {
	exp, cur, _ := settledFixture(t, f, f.options())
	return exp, cur, cur
}

// IOS: after the pastes of a plan, a device with the communities, hosts and
// lines of its own is consistent, and the report keeps them in one line per
// section.
func TestIOSOwnStatementsAreNoIrregularity(t *testing.T) {
	for _, name := range []string{"cisco.synthetic-system-stray", "cisco.synthetic-block-stray", "cisco.synthetic-vrf-stray"} {
		f := fixtureNamed(t, name)
		exp, cur, plain := settledFixtureFull(t, f)
		d, err := Plan(f.vendor, exp, cur, plain, f.options())
		if err != nil {
			t.Fatal(err)
		}
		out := flat(Report(d, f.header(), Wrapper{}))
		if !d.Empty() {
			t.Fatalf("%s: not settled:\n%s", name, d.Display())
		}
		// whatever remains is a finding of its own; none is the device's
		for _, it := range d.Items {
			for _, o := range d.Own {
				if it.Section == o.Section && it.Kind == KindExtra && it.Severity == SevCosmetic && strings.Contains(it.Action, "only adds") {
					t.Errorf("%s: an extra of the system block that the comparison keeps: %+v", name, it)
				}
			}
		}
		if len(d.Own) == 0 {
			t.Errorf("%s: nothing kept", name)
		}
		for _, o := range d.Own {
			if want := "Kept: " + o.Section + " "; !strings.Contains(out, want) {
				t.Errorf("%s: no Kept line for %s:\n%s", name, o.Section, out)
			}
			if consistentLine(out, o.Section) == !slices.ContainsFunc(d.Items, func(it Item) bool { return it.Section == o.Section }) {
				continue
			}
			t.Errorf("%s: %s and the Consistent line disagree:\n%s", name, o.Section, out)
		}
	}
}

// consistentLine reports whether the report's Consistent line names the
// section.
func consistentLine(report, section string) bool {
	_, rest, ok := strings.Cut(report, "Consistent: ")
	if !ok {
		return false
	}
	line, _, _ := strings.Cut(rest, ".")
	return slices.Contains(strings.Split(line, ", "), section)
}

// The system and netconf sections: what the device holds beside the block's
// statements is its own, a value that differs is not.
func TestJunosSystemAndNetconfOwnStatements(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-system")
	// the one statement the fixture lacks of the rendering, and three
	// statements the block says nothing of: a search domain, a name server
	// and an NTP threshold
	settle := addMany(`set snmp description "Core switch"`, "set system domain-search example.net",
		"set system name-server 198.51.100.53", "set system ntp threshold 1000 1")
	d := planJ(t, f, settle, Options{})
	own := ownOf(d, devconf.SectionSystem)
	if own.Count != 3 || !slices.Equal(own.Kinds, []string{"search domains", "name servers", "NTP"}) {
		t.Fatalf("the system fixture keeps %+v of the device's own:\n%s", own, d.Display())
	}
	for _, it := range d.Items {
		if it.Section == devconf.SectionSystem && it.Kind == KindExtra {
			t.Errorf("an extra of the system section is an item: %+v", it)
		}
	}
	rs, err := devconf.CompareAll(expectedSections(t, f.expected), extractedOf(t, f, settle))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == devconf.SectionSystem && r.Unmanaged != own.Count {
			t.Errorf("the plan keeps %d, the comparison counts %d", own.Count, r.Unmanaged)
		}
	}
	if text := flat(Report(d, f.header(), Wrapper{ConfirmMinutes: 5})); !strings.Contains(text, "Kept: system ") {
		t.Errorf("no Kept line for system:\n%s", text)
	}
	// a value the block states and the device holds otherwise is a difference
	d = planJ(t, f, func(c *JunosConfig) {
		settle(c)
		c.Remove("set system time-zone UTC")
		c.Add("set system time-zone America/New_York")
	}, Options{})
	if !slices.ContainsFunc(d.Items, func(it Item) bool { return it.Section == devconf.SectionSystem }) {
		t.Errorf("a time zone that differs is no item:\n%s", d.Display())
	}

	// the NETCONF service the scope enables: the device's port and limits
	// are its own
	lab := fixtureNamed(t, "juniper.synthetic-lab")
	exp := slices.DeleteFunc(expectedSections(t, lab.expected), func(s devices.Section) bool { return s.Name == devconf.SectionNetconf })
	exp = append(exp, devices.Section{Name: devconf.SectionNetconf, Lines: []string{"set system services netconf ssh"}, Secret: []bool{false}})
	c := ParseJunos(capture(t, lab.raw))
	c.Add("set system services netconf ssh")
	c.Add("set system services netconf ssh port 830")
	c.Add("set system services netconf ssh connection-limit 7")
	nd := planText(t, lab, exp, c.Text(), Options{})
	if o := ownOf(nd, devconf.SectionNetconf); o.Count != 2 || !slices.Equal(o.Kinds, []string{"NETCONF service"}) {
		t.Errorf("netconf: %+v\n%s", o, nd.Display())
	}
	if slices.ContainsFunc(nd.Items, func(it Item) bool { return it.Section == devconf.SectionNetconf }) {
		t.Errorf("a netconf item for the device's own statements: %+v", nd.Items)
	}
}

func extractedOf(t *testing.T, f fixture, mut func(c *JunosConfig)) devconf.Extracted {
	t.Helper()
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	if mut != nil {
		mut(c)
	}
	cur, err := devconf.Extract(f.vendor, c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	return cur
}

// A WTI unit: the pages it keeps of its own are one Kept line each, not a
// note; a read/write community stays a finding beside them.
func TestWTIOwnStatementsAreNoIrregularity(t *testing.T) {
	p := planWTICase(t, wtiCaseNamed(t, "consistent"), "")
	if len(p.d.Items) != 0 || statusOf(p.d) != StatusConsistent {
		t.Errorf("status %s, items %+v", statusOf(p.d), p.d.Items)
	}
	out := flat(Report(p.d, p.h, Wrapper{}))
	for _, want := range []string{"CONSISTENT: nothing to paste.", "Consistent: snmp, aaa, mgmt-acl.",
		"Kept: aaa 13 statements of the device's own (RADIUS settings): left alone, listed by device config diff.",
		"Kept: snmp 4 statements of the device's own (system name, trap settings): left alone, listed by device config diff."} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "kept on purpose") {
		t.Errorf("the old note is still there:\n%s", out)
	}
	if got := checkOwn(t, "consistent", p.d, p.exp, p.cur, devconf.SectionAAA, devconf.SectionSNMP); got != 17 {
		t.Errorf("the comparison counts %d statements of the unit's own", got)
	}

	q := planWTICase(t, wtiCaseNamed(t, "three-irregularities"), "")
	var rw bool
	for _, it := range q.d.Items {
		rw = rw || it.Section == devconf.SectionSNMP && it.Kind == KindExtra && it.Severity == SevMonitoring && strings.Contains(it.Statement, "rw-community")
	}
	if !rw {
		t.Errorf("the read/write community is no item: %+v", q.d.Items)
	}
	if o := ownOf(q.d, devconf.SectionSNMP); o.Count != 4 {
		t.Errorf("the unit's own beside a finding: %+v", o)
	}
	if text := flat(Report(q.d, q.h, Wrapper{})); consistentLine(text, "snmp") {
		t.Errorf("snmp is consistent beside a read/write community:\n%s", text)
	}
}
