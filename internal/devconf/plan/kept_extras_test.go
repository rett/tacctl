package plan

// 0.2.20: the device's own statements are no irregularity. A device whose
// managed statements are all in place and whose snmp section holds the
// statements of a device that had its own before tacctl (another
// communities with their clients, a trap group per community, the name, trap
// options, a client list, a view, an SNMPv3 user, an interface) is
// consistent: the plan has no item for them, and says how many there are in
// one line. The number is the comparison's (the 'snmp +N unmanaged' of
// 'device config list'), not a count of items.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// keptExtrasFixture is the synthetic lab after everything tacctl manages was
// pasted, with 17 SNMP statements of the device's own.
func keptExtrasFixture() fixture {
	return fixture{name: "juniper.synthetic-kept-extras", vendor: "juniper", raw: "juniper/synthetic-kept-extras/display-set.txt", expected: synthExpected}
}

const keptExtrasCount = 17

// unmanagedOf is the comparison's count of the device's own statements in a
// section of the fixture, after the mutation.
func unmanagedOf(t *testing.T, f fixture, mut func(c *JunosConfig), section string) int {
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
	rs, err := devconf.CompareAll(exp, cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == section {
			if r.State != devconf.StateOK {
				t.Fatalf("%s reads %s: %v", section, r.State, r.Lines)
			}
			return r.Unmanaged
		}
	}
	t.Fatalf("no section %s", section)
	return 0
}

func ownOf(d Delta, section string) Own {
	for _, o := range d.Own {
		if o.Section == section {
			return o
		}
	}
	return Own{}
}

// The device's own SNMP statements are not items: the plan of the lab with
// 17 of them is consistent, says so, and keeps them in one line whose number
// is the comparison's.
func TestOwnStatementsAreNoIrregularity(t *testing.T) {
	f := keptExtrasFixture()
	// the pull labels the other communities and trap groups: the plan's
	// report and the comparison never hold a string
	exp, cur, _ := f.load(t)
	if all := strings.Join(cur.Sections[devconf.SectionSNMP].Lines, "\n"); !strings.Contains(all, "<other:1>") || !strings.Contains(all, "<other:2>") ||
		!strings.Contains(all, "trap-group <other:2> targets 198.51.100.9") {
		t.Fatalf("the fixture has no unattributed communities and trap group:\n%s", all)
	}
	d := planJ(t, f, nil, Options{})
	if len(d.Items) != 0 {
		t.Errorf("the device's own statements are listed as irregular: %+v", d.Items)
	}
	if !d.Empty() || statusOf(d) != StatusConsistent {
		t.Errorf("status %s, lines %d", statusOf(d), len(d.Lines))
	}
	want := unmanagedOf(t, f, nil, devconf.SectionSNMP)
	if want != keptExtrasCount {
		t.Fatalf("the comparison counts %d statements of the device's own, the fixture is made for %d", want, keptExtrasCount)
	}
	if got := ownOf(d, devconf.SectionSNMP); got.Count != want {
		t.Errorf("the plan keeps %d, the comparison counts %d", got.Count, want)
	}
	out := Report(d, f.header(), Wrapper{ConfirmMinutes: 5})
	text := flat(out)
	for _, want := range []string{"CONSISTENT: nothing to paste.",
		"Consistent: roles, aaa, snmp, mgmt-acl.",
		"Kept: snmp 17 statements of the device's own (name, client lists, communities, trap options, trap groups, ...): left alone, listed by device config diff."} {
		if !strings.Contains(text, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	for _, bad := range []string{"What is irregular", "MONITORING", "Left alone (", "<other"} {
		if strings.Contains(out, bad) {
			t.Errorf("the report holds %q:\n%s", bad, out)
		}
	}
	// --json: a count and the kinds, no item; the extras are marked
	raw, err := JSON(d, f.header(), Wrapper{ConfirmMinutes: 5})
	if err != nil {
		t.Fatal(err)
	}
	var j struct {
		Status         string
		Irregularities []jsonItem
		Kept           []Own
		Extras         []jsonExtra
		Left           LeftCounts
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		t.Fatal(err)
	}
	if j.Status != StatusConsistent || len(j.Irregularities) != 0 || j.Left.Total() != 0 {
		t.Errorf("json: %s %d %+v", j.Status, len(j.Irregularities), j.Left)
	}
	if len(j.Kept) != 1 || j.Kept[0].Section != "snmp" || j.Kept[0].Count != keptExtrasCount || !slices.Contains(j.Kept[0].Kinds, "trap groups") {
		t.Errorf("json kept: %+v", j.Kept)
	}
	own := 0
	for _, e := range j.Extras {
		if e.Own {
			own++
		}
	}
	if own != keptExtrasCount {
		t.Errorf("json extras marked as the device's own: %d", own)
	}
	if st := StatusFor(d, f.header()); st.State != StatusConsistent || st.Extras != 0 || st.Left != 0 {
		t.Errorf("cover: %+v", st)
	}
	_ = exp
}

// What is a finding stays one: the device's own statements beside it are
// still not items, and the count is the comparison's all the same.
func TestRealFindingsStayItemsBesideTheDevicesOwn(t *testing.T) {
	f := keptExtrasFixture()
	for name, c := range map[string]struct {
		mut     func(c *JunosConfig)
		section string
		kind    string
		sev     string
	}{
		"a stray leaf of tacctl's community": {add("set snmp community lab-ro-community clients 203.0.113.0/24"), "snmp", KindExtra, SevMonitoring},
		"tacctl's community lacks a leaf": {func(c *JunosConfig) { c.Remove("set snmp community lab-ro-community authorization read-only") },
			"snmp", KindMissing, SevMonitoring},
		"another location": {func(c *JunosConfig) {
			c.Remove(`set snmp location "Rack 4, DC1"`)
			c.Add(`set snmp location "Rack 5"`)
		}, "snmp", KindDifferent, SevCosmetic},
		"a deactivated statement": {func(c *JunosConfig) { c.Add("deactivate snmp trap-group other-example") }, "snmp", KindExtra, SevMonitoring},
		"another server in aaa":   {add("set system tacplus-server 192.0.2.98 secret \"$9$STRAYSTRAYSTRAY\""), "aaa", KindExtra, SevAccess},
		"another filter term":     {add("set firewall family inet filter MGMT-ACL term extra from protocol tcp"), "mgmt-acl", KindExtra, SevAccess},
	} {
		t.Run(name, func(t *testing.T) {
			d := planJ(t, f, c.mut, Options{})
			found := false
			for _, it := range d.Items {
				if it.Section == c.section && it.Kind == c.kind && it.Severity == c.sev {
					found = true
				}
				if it.Section == "snmp" && strings.Contains(it.Statement, "other-") {
					t.Errorf("an item for the device's own: %+v", it)
				}
			}
			if !found {
				t.Errorf("no %s %s item in %s:\n%s", c.kind, c.sev, c.section, Report(d, f.header(), Wrapper{ConfirmMinutes: 5}))
			}
			if statusOf(d) == StatusConsistent {
				t.Errorf("a finding and the status is consistent")
			}
			if text := flat(Report(d, f.header(), Wrapper{ConfirmMinutes: 5})); c.section == "snmp" && strings.Contains(text, "Consistent: ") &&
				strings.Contains(strings.SplitN(strings.SplitN(text, "Consistent: ", 2)[1], ".", 2)[0], "snmp") {
				t.Errorf("snmp is reported as consistent beside a finding of its own:\n%s", text)
			}
		})
	}
}

// A record of an older tacctl cannot tell the communities apart: nothing
// under a community is the device's own by rule, so the plan keeps listing
// them.
func TestOlderRecordKeepsItsItems(t *testing.T) {
	f := keptExtrasFixture()
	exp, cur, _ := f.load(t)
	old := devconf.Extracted{Vendor: cur.Vendor, SecretsVisible: true, Sections: map[string]devices.Section{}}
	for name, s := range cur.Sections {
		var ls []string
		for _, l := range s.Lines {
			ls = append(ls, reMarks.ReplaceAllString(l, secretMark))
		}
		old.Sections[name] = devices.Section{Name: name, Lines: ls}
	}
	d, err := Plan(f.vendor, exp, old, old, f.options())
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Unattributed) == 0 {
		t.Fatal("nothing unattributed")
	}
	snmpItems := 0
	for _, it := range d.Items {
		if it.Section == "snmp" {
			snmpItems++
		}
	}
	if snmpItems == 0 {
		t.Errorf("the statements the comparison cannot attribute are not items")
	}
	rs, err := devconf.CompareAll(exp, old)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == devconf.SectionSNMP && ownOf(d, "snmp").Count != r.Unmanaged {
			t.Errorf("the plan keeps %d, the comparison counts %d", ownOf(d, "snmp").Count, r.Unmanaged)
		}
	}
}
