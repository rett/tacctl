package plan

// 0.2.7: the objects of a scope's snmp configuration block. A community or
// trap group the rendering took from a block is owned whole (an extra leaf
// under it goes, under its real name), tacctl's own structured community is
// owned by the leaves it renders as before, and the device's other
// communities and trap groups are its own.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// blockFixture is the synthetic-communities device after the block of scope
// lab was pasted: tacctl's community lab-ro-community, the block's community
// nms-ro and trap group nms-traps, trap-options agent-address, and the
// device's own other-example community, trap group, trap-options
// source-address and name.
func blockFixture(t testing.TB) fixture {
	t.Helper()
	return fixture{name: "juniper.synthetic-block", vendor: "juniper",
		raw: "juniper/synthetic-block/display-set.txt", expected: "juniper/synthetic-block/expected.txt"}
}

var blockOpt = Options{Scope: "lab"}

// blockStatements are the lines of the block, as the device holds them.
var blockStatements = []string{
	"set snmp community nms-ro authorization read-only",
	"set snmp community nms-ro clients 192.0.2.50/32",
	"set snmp community nms-ro clients 198.51.100.0/24",
	"set snmp trap-group nms-traps version v2",
	"set snmp trap-group nms-traps categories authentication",
	"set snmp trap-group nms-traps categories link",
	"set snmp trap-group nms-traps targets 198.51.100.7",
	"set snmp trap-options agent-address outgoing-interface",
}

func removeAll(ss ...string) func(c *JunosConfig) {
	return func(c *JunosConfig) {
		for _, s := range ss {
			if !c.Remove(s) {
				panic("the fixture lacks " + s)
			}
		}
	}
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return out
}

// realTexts are the texts of the lines of the plan that hold a name by
// value.
func realTexts(d Delta) []string {
	var out []string
	for _, l := range d.Lines {
		if l.HasValue {
			out = append(out, l.Text)
		}
	}
	return out
}

// converges applies the plan to the device's text and compares again: the
// snmp section must read ok.
func converges(t *testing.T, f fixture, exp []devices.Section, text string, d Delta) {
	t.Helper()
	c := ParseJunos(text)
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

// (a) The device holds the block's objects and another community of its own
// with its clients, a trap group, a name and a source address: nothing to
// plan, ok (+N unmanaged).
func TestBlockPresentIsNothingToDo(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, nil, blockOpt)
	if got := lines(d, "snmp"); len(got) != 0 {
		t.Errorf("the plan has snmp lines: %q", got)
	}
	if sp := d.Of("snmp"); sp.State != StateNoChange {
		t.Errorf("snmp: %s", sp.State)
	}
	if len(d.Unattributed) != 0 {
		t.Errorf("unattributed: %v", d.Unattributed)
	}
	for _, k := range []string{"snmp community <other:1> clients 192.0.2.10/32", "snmp community <other:1> clients 0.0.0.0/0 restrict",
		"snmp trap-group <other:1> targets 198.51.100.7", "snmp trap-options source-address 192.0.2.250", "snmp name jsw1.lab.example.net"} {
		wantKept(t, d, "snmp", k)
	}
	for _, k := range d.Kept {
		if strings.Contains(k.Text, "<secret:") {
			t.Errorf("the block's or tacctl's own object is kept: %q", k.Text)
		}
	}
	r := snmpResult(t, f, nil)
	if r.State != devconf.StateOK || r.Unmanaged != 11 || r.StateText() != "ok (+11 unmanaged)" {
		t.Errorf("%s %d %q:\n%v", r.State, r.Unmanaged, r.StateText(), r.Lines)
	}
}

// (b) The device lacks the block's community, trap group and trap option:
// the plan sets every statement of the block, each under its real name, and
// does not touch the device's own community.
func TestBlockMissingIsSet(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, removeAll(blockStatements...), blockOpt)
	want := []string{
		"set snmp community <secret:2> authorization read-only",
		"set snmp community <secret:2> clients 192.0.2.50/32",
		"set snmp community <secret:2> clients 198.51.100.0/24",
		"set snmp trap-group <secret:3> version v2",
		"set snmp trap-group <secret:3> categories authentication",
		"set snmp trap-group <secret:3> categories link",
		"set snmp trap-group <secret:3> targets 198.51.100.7",
		"set snmp trap-options agent-address outgoing-interface",
	}
	if got := lines(d, "snmp"); !slices.Equal(got, want) {
		t.Errorf("the snmp lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	typed := blockStatements[:7]
	if got := realTexts(d); !slices.Equal(got, typed) {
		t.Errorf("by value:\n%s", strings.Join(got, "\n"))
	}
	noLine(t, d, "snmp", "delete")
	// the device's own are kept, and no line names them
	wantKept(t, d, "snmp", "snmp community <other:1> clients 198.51.100.7/32")
	nd := planJ(t, f, removeAll(blockStatements...), Options{Scope: "lab", NoSecrets: true})
	for _, l := range nd.Lines {
		if strings.Contains(l.Text, "nms-") {
			t.Errorf("--no-secrets types a name: %q", l.Text)
		}
	}
	wantLine(t, nd, "snmp", "set snmp community <secret:2> clients 192.0.2.50/32")
	// and the structured community's statements are still its own
	sd := planJ(t, f, func(c *JunosConfig) {
		removeAll(blockStatements...)(c)
		c.Remove("set snmp community lab-ro-community authorization read-only")
	}, blockOpt)
	wantLine(t, sd, "snmp", "set snmp community <secret:1> authorization read-only")
	if got := lines(sd, "snmp"); len(got) != 9 {
		t.Errorf("the snmp lines: %q", got)
	}
}

// The section's reason names the block by its scope, and no string.
func TestBlockWhyNamesTheBlock(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, removeAll(blockStatements...), blockOpt)
	why := d.Of("snmp").Why
	for _, want := range []string{"the communities of the SNMP block of scope 'lab'", "the trap groups of the SNMP block of scope 'lab'", "the trap options of the SNMP block of scope 'lab'"} {
		if !strings.Contains(why, want) {
			t.Errorf("the why-line lacks %q: %q", want, why)
		}
	}
	// the report says the block, never a string: the items and the
	// reasons are free of them (the lines to paste hold them by value)
	for _, it := range d.Items {
		for _, text := range []string{it.Words, it.Statement, it.Action} {
			for _, bad := range []string{"nms-ro", "nms-traps", "other-example", "lab-ro-community"} {
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
	for _, want := range []string{"a community of the SNMP block of scope 'lab': 3 statements", "a trap group of the SNMP block of scope 'lab': 4 statements",
		"a trap option of the SNMP block of scope 'lab': agent-address outgoing-interface"} {
		if !slices.Contains(words, want) {
			t.Errorf("the items lack %q:\n%s", want, strings.Join(words, "\n"))
		}
	}
}

// (c) A stray client entry under the block's community is deleted, exactly
// that leaf, under the community's real name.
func TestBlockStrayClientIsDeleted(t *testing.T) {
	f := blockFixture(t)
	mut := add("set snmp community nms-ro clients 203.0.113.0/24")
	d := planJ(t, f, mut, blockOpt)
	if got := lines(d, "snmp"); len(got) != 1 || got[0] != "delete snmp community <secret:2> clients 203.0.113.0/24" {
		t.Errorf("the snmp lines: %q", got)
	}
	if got := realTexts(d); !slices.Equal(got, []string{"delete snmp community nms-ro clients 203.0.113.0/24"}) {
		t.Errorf("by value: %q", got)
	}
	if r := snmpResult(t, f, mut); r.State != devconf.StateDiffers {
		t.Errorf("the section reads %s", r.State)
	}
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	mut(c)
	converges(t, f, exp, c.Text(), d)
}

// Any other leaf the block does not state goes too: a block's community is
// owned whole. A single-valued one is replaced in place.
func TestBlockCommunityIsOwnedWhole(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, addMany("set snmp community nms-ro client-list-name OTHER-LIST"), blockOpt)
	if got := lines(d, "snmp"); !slices.Equal(got, []string{"delete snmp community <secret:2> client-list-name OTHER-LIST"}) {
		t.Errorf("the snmp lines: %q", got)
	}
	// the authorization the block does not have on the device: the set
	// replaces the device's value, which is then not deleted
	d = planJ(t, f, func(c *JunosConfig) {
		c.Remove("set snmp community nms-ro authorization read-only")
		c.Add("set snmp community nms-ro authorization read-write")
	}, blockOpt)
	if got := lines(d, "snmp"); !slices.Equal(got, []string{"set snmp community <secret:2> authorization read-only"}) {
		t.Errorf("the snmp lines: %q", got)
	}
}

// (d) A trap group of the block with an extra target (or category) on the
// device: deleted; its version is replaced in place.
func TestBlockTrapGroupIsOwnedWhole(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, addMany("set snmp trap-group nms-traps targets 203.0.113.9", "set snmp trap-group nms-traps categories chassis"), blockOpt)
	want := []string{"delete snmp trap-group <secret:3> categories chassis", "delete snmp trap-group <secret:3> targets 203.0.113.9"}
	if got := lines(d, "snmp"); !slices.Equal(sorted(got), want) {
		t.Errorf("the snmp lines: %q", got)
	}
	if got := realTexts(d); !slices.Equal(sorted(got), []string{"delete snmp trap-group nms-traps categories chassis", "delete snmp trap-group nms-traps targets 203.0.113.9"}) {
		t.Errorf("by value: %q", got)
	}
	if r := snmpResult(t, f, addMany("set snmp trap-group nms-traps targets 203.0.113.9")); r.State != devconf.StateDiffers {
		t.Errorf("the section reads %s", r.State)
	}
	d = planJ(t, f, func(c *JunosConfig) {
		c.Remove("set snmp trap-group nms-traps version v2")
		c.Add("set snmp trap-group nms-traps version v1")
	}, blockOpt)
	if got := lines(d, "snmp"); !slices.Equal(got, []string{"set snmp trap-group <secret:3> version v2"}) {
		t.Errorf("the snmp lines: %q", got)
	}
	// the device's other trap group is its own: an extra target is kept
	d = planJ(t, f, add("set snmp trap-group other-example targets 203.0.113.9"), blockOpt)
	noLine(t, d, "snmp", "delete")
	wantKept(t, d, "snmp", "snmp trap-group <other:1> targets 203.0.113.9")
	if r := snmpResult(t, f, add("set snmp trap-group other-example targets 203.0.113.9")); r.State != devconf.StateOK || r.Unmanaged != 12 {
		t.Errorf("%s %d", r.State, r.Unmanaged)
	}
}

// A trap-options leaf the block does not set is the device's own; one it
// sets is replaced.
func TestBlockTrapOptions(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, removeAll("set snmp trap-options agent-address outgoing-interface"), blockOpt)
	if got := lines(d, "snmp"); !slices.Equal(got, []string{"set snmp trap-options agent-address outgoing-interface"}) {
		t.Errorf("the snmp lines: %q", got)
	}
	wantKept(t, d, "snmp", "snmp trap-options source-address 192.0.2.250")
	// the section is ok with the device's source address beside it
	if r := snmpResult(t, f, nil); r.State != devconf.StateOK {
		t.Errorf("snmp reads %s", r.State)
	}
	// the structured settings alone (no block) keep it unmanaged as before
	g := fixtureNamed(t, "juniper.synthetic-communities")
	if r := snmpResult(t, g, nil); r.State != devconf.StateOK || r.Unmanaged != 11 {
		t.Errorf("%s %d", r.State, r.Unmanaged)
	}
}

// A device community whose string is a name the block uses only for a trap
// group is not the block's community: kept, and the device's own.
func TestBlockTrapGroupNameIsNotACommunity(t *testing.T) {
	f := blockFixture(t)
	mut := add("set snmp community nms-traps authorization read-only")
	d := planJ(t, f, mut, blockOpt)
	noLine(t, d, "snmp", "delete")
	wantKept(t, d, "snmp", "snmp community <secret:3> authorization read-only")
	if r := snmpResult(t, f, mut); r.State != devconf.StateOK || r.Unmanaged != 12 {
		t.Errorf("%s %d:\n%v", r.State, r.Unmanaged, r.Lines)
	}
	// and the other way round: a trap group of the name of a block community
	mut = add("set snmp trap-group nms-ro targets 203.0.113.9")
	d = planJ(t, f, mut, blockOpt)
	noLine(t, d, "snmp", "delete")
	if r := snmpResult(t, f, mut); r.State != devconf.StateOK || r.Unmanaged != 12 {
		t.Errorf("%s %d:\n%v", r.State, r.Unmanaged, r.Lines)
	}
}

// (e) A record of an older tacctl (every name the bare mark): nothing under
// a community or trap group is deleted, and the statements are left alone,
// said so.
func TestBlockOlderRecordLeavesObjectsAlone(t *testing.T) {
	f := blockFixture(t)
	exp, cur, _ := f.load(t)
	old := devconf.Extracted{Vendor: cur.Vendor, SecretsVisible: true, Sections: map[string]devices.Section{}}
	for name, s := range cur.Sections {
		var ls []string
		for _, l := range s.Lines {
			ls = append(ls, reMarks.ReplaceAllString(l, secretMark))
		}
		old.Sections[name] = devices.Section{Name: name, Lines: ls}
	}
	// the block's trap group has an extra target, and so has its community an
	// extra client: under the bare mark neither can be told from another's
	add := func(l string) {
		old.Sections["snmp"] = devices.Section{Name: "snmp", Lines: append(old.Sections["snmp"].Lines, l)}
	}
	add("set snmp community <secret> clients 203.0.113.0/24")
	add("set snmp trap-group <secret> targets 203.0.113.9")
	d, err := Plan(f.vendor, exp, old, old, blockOpt)
	if err != nil {
		t.Fatal(err)
	}
	noLine(t, d, "snmp", "delete")
	if len(d.Unattributed) == 0 {
		t.Errorf("nothing is unattributed")
	}
	out := flat(Block(d, f.header(), Wrapper{ConfirmMinutes: 5}))
	if !strings.Contains(out, "Left alone (the community's name is not visible)") {
		t.Errorf("the output does not say it:\n%s", out)
	}
}

// A block's client entry with the restrict flag the device's entry lacks (or
// the other way round) is changed in place: the entry is not deleted after
// it was set.
func TestBlockClientFlag(t *testing.T) {
	f := blockFixture(t)
	for _, c := range []struct {
		name, block, device string
		want                []string
	}{
		{"restrict added", "set snmp community nms-ro clients 0.0.0.0/0 restrict", "set snmp community nms-ro clients 0.0.0.0/0",
			[]string{"set snmp community <secret:2> clients 0.0.0.0/0 restrict"}},
		{"restrict removed", "set snmp community nms-ro clients 0.0.0.0/0", "set snmp community nms-ro clients 0.0.0.0/0 restrict",
			[]string{"set snmp community <secret:2> clients 0.0.0.0/0", "delete snmp community <secret:2> clients 0.0.0.0/0 restrict"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			exp := expectedSections(t, f.expected)
			for i := range exp {
				for j, l := range exp[i].Lines {
					if l == "set snmp community nms-ro clients 198.51.100.0/24" {
						exp[i].Lines[j] = c.block
					}
				}
			}
			cfg := ParseJunos(capture(t, f.raw))
			cfg.Remove("set snmp community nms-ro clients 198.51.100.0/24")
			cfg.Add(c.device)
			text := cfg.Text()
			d := planText(t, f, exp, text, blockOpt)
			if got := lines(d, "snmp"); !slices.Equal(got, c.want) {
				t.Errorf("the snmp lines:\n%s", strings.Join(got, "\n"))
			}
			converges(t, f, exp, text, d)
		})
	}
}

// (g) The back-out of a plan that created the block's objects deletes them
// and nothing else: not tacctl's own community, not the device's.
func TestBlockBackout(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, removeAll(blockStatements...), blockOpt)
	var got, shown []string
	for _, l := range d.Backout {
		got = append(got, l.Text)
		shown = append(shown, l.Shown())
	}
	want := []string{"delete snmp trap-options agent-address outgoing-interface", "delete snmp trap-group nms-traps", "delete snmp community nms-ro"}
	if !slices.Equal(got, want) {
		t.Errorf("the back-out:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if want := []string{"delete snmp trap-options agent-address outgoing-interface", "delete snmp trap-group <secret:3>", "delete snmp community <secret:2>"}; !slices.Equal(shown, want) {
		t.Errorf("the back-out as shown:\n%s", strings.Join(shown, "\n"))
	}
	for _, l := range d.Backout {
		if strings.Contains(l.Text, "lab-ro-community") || strings.Contains(l.Text, "other-example") {
			t.Errorf("the back-out names another community: %q", l.Text)
		}
	}
	// the one that stands in the way: tacctl's own community was there, so a
	// set of the block's must not read as a value of the device's to put back
	for _, l := range d.Backout {
		if l.Op == OpComment {
			t.Errorf("a comment where a delete belongs: %q", l.Text)
		}
	}
	// and applied after the plan it gives the device's statements back
	c := ParseJunos(capture(t, f.raw))
	removeAll(blockStatements...)(c)
	before := slices.Clone(c.Statements())
	slices.Sort(before)
	if err := c.Apply(d.Lines); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(d.Backout); err != nil {
		t.Fatal(err)
	}
	after := c.Statements()
	slices.Sort(after)
	if !slices.Equal(before, after) {
		t.Errorf("the back-out does not restore the device:\n lost: %v\n left over: %v", diffStrings(before, after), diffStrings(after, before))
	}
	// a stray leaf removed by the plan is typed again by name, as a note
	sd := planJ(t, f, add("set snmp community nms-ro clients 203.0.113.0/24"), blockOpt)
	if len(sd.Backout) != 1 || sd.Backout[0].Op != OpComment || !strings.Contains(sd.Backout[0].Text, "set snmp community <secret:2> clients 203.0.113.0/24") {
		t.Errorf("the back-out of a deleted leaf: %+v", sd.Backout)
	}
	// a block's authorization that replaced the device's value goes back
	// as a note, and nothing is deleted
	rd := planJ(t, f, func(c *JunosConfig) {
		c.Remove("set snmp community nms-ro authorization read-only")
		c.Add("set snmp community nms-ro authorization read-write")
	}, blockOpt)
	for _, l := range rd.Backout {
		if l.Op == OpDelete {
			t.Errorf("the back-out deletes: %q", l.Text)
		}
	}
	if len(rd.Backout) != 1 || !strings.Contains(rd.Backout[0].Text, "authorization read-write") {
		t.Errorf("the back-out of a replaced value: %+v", rd.Backout)
	}
}

// With --no-secrets the plan's lines hold placeholders: the back-out still
// tells the block's community from tacctl's own by the labels.
func TestBlockBackoutNoSecrets(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, removeAll(blockStatements...), Options{Scope: "lab", NoSecrets: true})
	var shown []string
	for _, l := range d.Backout {
		shown = append(shown, l.Shown())
	}
	want := []string{"delete snmp trap-options agent-address outgoing-interface", "delete snmp trap-group <secret:3>", "delete snmp community <secret:2>"}
	if !slices.Equal(shown, want) {
		t.Errorf("the back-out:\n%s", strings.Join(shown, "\n"))
	}
}

// The plan with a block converges, and a rendering with no block is not
// changed by one on the device (the block's objects are another community's).
func TestBlockPlanConverges(t *testing.T) {
	f := blockFixture(t)
	exp := expectedSections(t, f.expected)
	c := ParseJunos(capture(t, f.raw))
	removeAll(blockStatements...)(c)
	add("set snmp community nms-ro clients 203.0.113.0/24")(c)
	add("set snmp trap-group nms-traps targets 203.0.113.9")(c)
	text := c.Text()
	d := planText(t, f, exp, text, blockOpt)
	converges(t, f, exp, text, d)
	// the device holds the block's community and the scope has no block now:
	// it is the device's own
	g := fixtureNamed(t, "juniper.synthetic-lab")
	gd := planJ(t, g, add("set snmp community nms-ro clients 192.0.2.50/32"), Options{})
	noLine(t, gd, "snmp", "delete")
}

// The pasted forms: the region and the plain statements hold the block's
// statements by value, the labels never reach a line to paste.
func TestBlockPastedForms(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, removeAll(blockStatements...), blockOpt)
	h, w := f.header(), Wrapper{ConfirmMinutes: 5}
	plain, err := Plain(d, h, w)
	if err != nil {
		t.Fatal(err)
	}
	var typed []string
	for _, l := range strings.Split(plain, "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			typed = append(typed, l)
		}
	}
	if !slices.Equal(typed, blockStatements) {
		t.Errorf("the plain statements:\n%s", strings.Join(typed, "\n"))
	}
	if r := Region(d, h, w); strings.Contains(r, "<secret") || strings.Contains(r, "<other") || strings.Contains(r, "<SECRET") {
		t.Errorf("a label in the region:\n%s", r)
	}
}

// --secrets pushes the block's statements by value too (a community string
// and a trap group's name are secrets), and --converge removes nothing of
// the device's own communities and trap groups.
func TestBlockSecretsAndConverge(t *testing.T) {
	f := blockFixture(t)
	d := planJ(t, f, nil, Options{Scope: "lab", Secrets: true})
	var typed []string
	for _, l := range d.Lines {
		if l.Section == "snmp" && l.HasValue {
			typed = append(typed, l.Text)
		}
	}
	for _, want := range append([]string{"set snmp community lab-ro-community authorization read-only"}, blockStatements[:7]...) {
		if !slices.Contains(typed, want) {
			t.Errorf("--secrets does not type %q:\n%s", want, strings.Join(typed, "\n"))
		}
	}
	noLine(t, d, "snmp", "delete")
	cd := planJ(t, f, add("set snmp community nms-ro clients 203.0.113.0/24"), Options{Scope: "lab", Converge: true})
	for _, l := range cd.Cleanup.Lines {
		if strings.Contains(l.Text, "snmp") {
			t.Errorf("the cleanup region touches snmp: %q", l.Text)
		}
	}
	wantLine(t, cd, "snmp", "delete snmp community <secret:2> clients 203.0.113.0/24")
}
