package plan

// 0.2.7: the system block of a scope (the login message, domain name and
// search list, time zone, name servers and NTP). The section is additive:
// every statement is set when missing, a single value that differs is
// replaced in place, and what the device holds beside the block's statements
// is kept and listed as its own. The message is never in a report, a compared
// line or a stored section: only the pasted statement holds it.

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// systemOpt are the options of the system fixture's plans.
var systemOpt = Options{Scope: "lab"}

// the message of the fixture, as the device prints it and as its body.
const (
	fixtureMessage = `"Authorized use only.\n  *** jsw1.lab.example.net ***\nDisconnect now if you are not authorized.\n  \"quoted\" and a back\\slash"`
	fixtureBody    = "Authorized use only.\n  *** jsw1.lab.example.net ***\nDisconnect now if you are not authorized.\n  \"quoted\" and a back\\slash"
)

func systemFixture(t testing.TB) fixture {
	t.Helper()
	return fixtureNamed(t, "juniper.synthetic-system")
}

// dropPrefix removes every statement of the device whose path starts with one
// of the prefixes (space separated words).
func dropPrefix(prefixes ...string) func(c *JunosConfig) {
	return func(c *JunosConfig) {
		var keep []jstmt
		for _, s := range c.stmts {
			j := strings.Join(s.path, " ")
			drop := false
			for _, p := range prefixes {
				if j == p || strings.HasPrefix(j, p+" ") {
					drop = true
				}
			}
			if !drop {
				keep = append(keep, s)
			}
		}
		c.stmts = keep
	}
}

// systemSectionOf is the system section a block's text renders.
func systemSectionOf(t testing.TB, text string) devices.Section {
	t.Helper()
	b, fs := blocks.LintSystem(text, blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	st := blocks.SystemStatements(blocks.ResolveSystem(nil, b, nil))
	sec := devices.Section{Name: "system", Lines: st, Secret: make([]bool, len(st)), Block: make([]bool, len(st))}
	for i, l := range st {
		sec.Secret[i] = blocks.IsSecretStatement(l)
		sec.Block[i] = true
	}
	return sec
}

// withSystem is the fixture's rendering with its system section replaced.
func withSystem(exp []devices.Section, sec devices.Section) []devices.Section {
	out := slices.Clone(exp)
	for i := range out {
		if out[i].Name == "system" {
			out[i] = sec
			return out
		}
	}
	return append(out, sec)
}

// systemResult is the comparison of the system section of a mutated device.
func systemResult(t testing.TB, f fixture, exp []devices.Section, mut func(c *JunosConfig)) devconf.SectionResult {
	t.Helper()
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
		if r.Name == devconf.SectionSystem {
			return r
		}
	}
	t.Fatalf("no system section in the comparison: %v", rs)
	return devconf.SectionResult{}
}

// systemConverges applies the plan to the device's text and compares again:
// the system section must read ok.
func systemConverges(t *testing.T, f fixture, exp []devices.Section, text string, d Delta) {
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
		if r.Name == devconf.SectionSystem && r.State != devconf.StateOK {
			t.Errorf("system reads %s after the plan:\n%v", r.State, r.Lines)
		}
	}
}

// planSystem plans a mutated device against the fixture's rendering, or
// against another one.
func planSystem(t *testing.T, mutDev func(c *JunosConfig), exp []devices.Section, opt Options) (Delta, string) {
	t.Helper()
	f := systemFixture(t)
	if exp == nil {
		exp = expectedSections(t, f.expected)
	}
	c := ParseJunos(capture(t, f.raw))
	if mutDev != nil {
		mutDev(c)
	}
	return planText(t, f, exp, c.Text(), opt), c.Text()
}

// (a) The device holds everything the block says: nothing to plan, ok. The
// key is a secret the device holds: present, not compared.
func TestSystemPresentIsNothingToDo(t *testing.T) {
	d, _ := planSystem(t, nil, nil, systemOpt)
	if got := lines(d, "system"); len(got) != 0 {
		t.Errorf("the plan has system lines: %q", got)
	}
	if sp := d.Of("system"); sp.State != StateNoChange {
		t.Errorf("system: %+v", sp)
	}
	// the key is one more secret the device holds than a scope with no block
	// has to be asked about
	f := systemFixture(t)
	var without []devices.Section
	for _, s := range expectedSections(t, f.expected) {
		if s.Name != "system" {
			without = append(without, s)
		}
	}
	d0 := planText(t, f, without, capture(t, f.raw), systemOpt)
	if d.Counts.SecretsPresent != d0.Counts.SecretsPresent+1 {
		t.Errorf("secrets present: %d, with no block %d", d.Counts.SecretsPresent, d0.Counts.SecretsPresent)
	}
	r := systemResult(t, f, expectedSections(t, f.expected), nil)
	if r.State != devconf.StateOK || r.Unmanaged != 0 || r.StateText() != "ok" {
		t.Errorf("%s %d %q:\n%v", r.State, r.Unmanaged, r.StateText(), r.Lines)
	}
	// the section sits after snmp and before mgmt-acl, which stays last
	var order []string
	for _, s := range d.Sections {
		order = append(order, s.Name)
	}
	want := []string{"roles", "aaa", "snmp", "system", "mgmt-acl", "netconf", "breakglass"}
	if !slices.Equal(order, want) {
		t.Errorf("sections %v, want %v", order, want)
	}
}

// the statements the fixture's block renders, as the plan types them.
var systemPlanLines = []string{
	`set system login message ` + fixtureMessage,
	"set system domain-name lab.example.net",
	"set system domain-search lab.example.net",
	"set system time-zone UTC",
	"set system name-server 192.0.2.53",
	"set system ntp server 192.0.2.123 prefer",
	"set system ntp server 192.0.2.123 version 4",
	"set system ntp server 192.0.2.123 key 1",
	"set system ntp boot-server 192.0.2.123",
	"set system ntp source-address 192.0.2.250",
	"set system ntp authentication-key 1 value <secret>",
	"set system ntp trusted-key 1",
}

var systemHierarchies = []string{"system login message", "system domain-name", "system domain-search", "system time-zone",
	"system name-server", "system ntp"}

// (b) The device lacks all of it: the plan sets every statement, the message
// as the one line, and the key by value, and deletes nothing. The bare server
// statement is not typed beside its options.
func TestSystemMissingIsSet(t *testing.T) {
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	d, text := planSystem(t, dropPrefix(systemHierarchies...), nil, systemOpt)
	if got := lines(d, "system"); !slices.Equal(got, systemPlanLines) {
		t.Errorf("system lines:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(systemPlanLines, "\n"))
	}
	for _, l := range d.Lines {
		if l.Section != "system" {
			continue
		}
		if l.Op != OpSet {
			t.Errorf("a %s line: %q", l.Op, l.Text)
		}
		if strings.HasPrefix(l.Text, "set system ntp authentication-key") {
			if !l.Secret || !l.HasValue || l.Text != "set system ntp authentication-key 1 type md5 value ntp-key-0123456789" {
				t.Errorf("the key line: %+v", l)
			}
		}
	}
	if sp := d.Of("system"); sp.State != StatePlanned || sp.Statements != len(systemPlanLines) {
		t.Errorf("system: %+v", sp)
	}
	if !slices.Contains(d.SecretKinds, "NTP KEY") {
		t.Errorf("secret kinds: %v", d.SecretKinds)
	}
	systemConverges(t, f, exp, text, d)

	// under --no-secrets the key is a placeholder
	d, _ = planSystem(t, dropPrefix(systemHierarchies...), nil, Options{Scope: "lab", NoSecrets: true})
	var key string
	for _, l := range d.Lines {
		if strings.HasPrefix(l.Text, "set system ntp authentication-key") {
			key = l.Text
		}
	}
	if key != "set system ntp authentication-key 1 value <SECRET>" && key != "set system ntp authentication-key 1 type md5 value <SECRET>" {
		t.Errorf("the placeholder line: %q", key)
	}

	// the report words the findings and holds no word of the message or the key
	rep := Report(d, f.header(), Wrapper{})
	for _, bad := range []string{"Authorized", "jsw1.lab", "Disconnect", "ntp-key-0123456789", "quoted"} {
		if strings.Contains(rep, bad) {
			t.Errorf("the report holds %q:\n%s", bad, rep)
		}
	}
	for _, want := range []string{"the login message", "the time zone is UTC", "the name server 192.0.2.53", "NTP key 1 is set"} {
		if !strings.Contains(rep, want) {
			t.Errorf("the report lacks %q:\n%s", want, rep)
		}
	}
}

// (c) The device has another name server, another NTP server, another search
// domain, an option of the block's server the block does not state, another
// key and trusted key and an NTP leaf of its own: ok (+N unmanaged), and the
// plan deletes nothing.
func TestSystemExtrasAreUnmanaged(t *testing.T) {
	extras := []string{
		"set system name-server 198.51.100.53",
		"set system domain-search example.net",
		"set system ntp server ntp.example.net",
		"set system ntp server 192.0.2.123 routing-instance mgmt",
		"set system ntp threshold 10 action accept",
		`set system ntp authentication-key 9 value "$9$OTHEROTHEROTHER"`,
		"set system ntp trusted-key 9",
	}
	mut := addMany(extras...)
	d, text := planSystem(t, mut, nil, systemOpt)
	if got := lines(d, "system"); len(got) != 0 {
		t.Errorf("the plan has system lines: %q", got)
	}
	if sp := d.Of("system"); sp.State != StateNoChange {
		t.Errorf("system: %+v", sp)
	}
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	r := systemResult(t, f, exp, mut)
	if r.State != devconf.StateOK || r.Unmanaged != 7 || r.StateText() != "ok (+7 unmanaged)" {
		t.Errorf("%s %d %q:\n%v", r.State, r.Unmanaged, r.StateText(), r.Lines)
	}
	for _, k := range []string{"system name-server 198.51.100.53", "system domain-search example.net", "system ntp server ntp.example.net",
		"system ntp server 192.0.2.123 routing-instance mgmt", "system ntp threshold 10 action accept",
		"system ntp authentication-key 9 value", "system ntp trusted-key 9"} {
		wantKept(t, d, "system", k)
	}
	// the cleanup never offers to remove what the plan keeps (the allow-list
	// is closed), and nothing here is a delete
	for _, l := range d.Lines {
		if l.Op == OpDelete {
			t.Errorf("a delete: %q", l.Text)
		}
	}
	systemConverges(t, f, exp, text, d)
	// an extra of a server's option that the block states is a difference, not
	// the device's own
	r = systemResult(t, f, exp, addMany("set system ntp server 192.0.2.123 version 3"))
	if r.State != devconf.StateDiffers {
		t.Errorf("a different version: %s", r.State)
	}
}

// (d) A different time zone, domain name and message: the plan sets the new
// value in place and never deletes the device's. The report words the
// difference without the message.
func TestSystemDifferingValuesAreReplaced(t *testing.T) {
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	mut := func(c *JunosConfig) {
		dropPrefix("system time-zone", "system domain-name", "system login message", "system ntp server 192.0.2.123 version", "system ntp boot-server")(c)
		for _, s := range []string{
			"set system time-zone America/New_York",
			"set system domain-name other.example.net",
			`set system login message "Welcome\nto the old switch"`,
			"set system ntp server 192.0.2.123 version 3",
			"set system ntp boot-server 192.0.2.99",
		} {
			c.Add(s)
		}
	}
	r := systemResult(t, f, exp, mut)
	if r.State != devconf.StateDiffers {
		t.Fatalf("state %s:\n%v", r.State, r.Lines)
	}
	d, text := planSystem(t, mut, nil, systemOpt)
	want := []string{
		`set system login message ` + fixtureMessage,
		"set system domain-name lab.example.net",
		"set system time-zone UTC",
		"set system ntp server 192.0.2.123 version 4",
		"set system ntp boot-server 192.0.2.123",
	}
	if got := lines(d, "system"); !slices.Equal(got, want) {
		t.Errorf("system lines:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	noLine(t, d, "system", "delete")
	systemConverges(t, f, exp, text, d)
	rep := Report(d, f.header(), Wrapper{})
	for _, bad := range []string{"Authorized", "Welcome", "old switch", "Disconnect"} {
		if strings.Contains(rep, bad) {
			t.Errorf("the report holds %q:\n%s", bad, rep)
		}
	}
	if flat := strings.Join(strings.Fields(strings.ReplaceAll(rep, "\n#", " ")), " "); !strings.Contains(flat, "the login message of 4 lines, 121 characters (the device has: the login message of 2 lines, 25 characters)") ||
		!strings.Contains(flat, "the time zone is UTC (the device has: the time zone is America/New_York)") {
		t.Errorf("the report:\n%s", rep)
	}
	// the device's other values are not kept as extras: they are replaced
	for _, k := range d.Kept {
		if k.Section == "system" {
			t.Errorf("a kept statement: %+v", k)
		}
	}
	// the cover page: the device needs a change, three of whose findings the
	// paste fixes
	if st := StatusFor(d, f.header()); st.State != StatusNeedsChange {
		t.Errorf("status %+v", st)
	}
}

// (f) A 22-line message of 1,300 characters: the statement is whole in the
// plan and in the plain file, and the report carries the warning about a
// line over 1,023 characters, with its size and no word of the text.
func TestSystemLongMessage(t *testing.T) {
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	var ls []string
	for i := 0; i < 22; i++ {
		ls = append(ls, fmt.Sprintf("%02d  %s", i, strings.Repeat("=", 54)))
	}
	body := strings.Join(ls, "\n")
	if len(body) < 1250 || len(body) > 1350 {
		t.Fatalf("the body is %d characters", len(body))
	}
	text := "set system login message <<'EOF'\n" + body + "\nEOF\nset system time-zone UTC\n"
	sec := systemSectionOf(t, text)
	stmt := blocks.MessageStatement + blocks.DeviceMessage(body)
	if sec.Lines[0] != stmt {
		t.Fatal("the rendering holds another statement")
	}
	rendering := withSystem(exp, sec)
	d, _ := planSystem(t, dropPrefix(systemHierarchies...), rendering, systemOpt)
	got := lines(d, "system")
	if len(got) != 2 || got[0] != stmt {
		t.Fatalf("system lines: %q", got)
	}
	if len(stmt) <= 1023 {
		t.Fatalf("the statement is %d characters", len(stmt))
	}
	n := fmt.Sprint(len(stmt))
	found := false
	for _, w := range d.Warnings {
		if strings.Contains(w, "1,023 characters") && strings.Contains(w, n) && strings.Contains(w, "--plain") {
			found = true
		}
		if strings.Contains(w, "====") {
			t.Errorf("a warning holds the text: %q", w)
		}
	}
	if !found {
		t.Errorf("no warning: %q", d.Warnings)
	}
	h := f.header()
	rep := Report(d, h, Wrapper{})
	if !strings.Contains(rep, "WARNING: the login message statement is "+n+" characters on one line") || strings.Contains(rep, "====") {
		t.Errorf("the report:\n%s", rep)
	}
	plain, err := Plain(d, h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain, stmt+"\n") {
		t.Errorf("the plain file lacks the whole statement")
	}
	// a short message has no such warning
	d, _ = planSystem(t, dropPrefix(systemHierarchies...), nil, systemOpt)
	for _, w := range d.Warnings {
		if strings.Contains(w, "1,023") {
			t.Errorf("a warning for a short message: %q", w)
		}
	}
}

// (g) A record made before the block was set holds no system section: it is
// not compared, the plan names the pull to make, and nothing else about the
// plan changes.
func TestSystemOlderRecordIsNotCompared(t *testing.T) {
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	// the pull as an older tacctl read it: against a rendering with no system
	var without []devices.Section
	for _, s := range exp {
		if s.Name != "system" {
			without = append(without, s)
		}
	}
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), without...)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cur.Sections["system"]; ok {
		t.Fatalf("an extraction with no system section has one: %v", cur.Sections["system"])
	}
	// no statement of the device's own system hierarchies is in any section
	for n, s := range cur.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, "ntp") || strings.Contains(l, "name-server") || strings.Contains(l, "login message") || strings.Contains(l, "domain-") {
				t.Errorf("[%s] holds %q", n, l)
			}
		}
	}
	d, err := Plan(f.vendor, exp, cur, cur, Options{Scope: "lab", Device: "jsw1"})
	if err != nil {
		t.Fatal(err)
	}
	sp := d.Of("system")
	if sp.State != StateSkipped || sp.Kind != KindNotPlannable || !strings.Contains(sp.Why, "tacctl device config pull jsw1") {
		t.Errorf("system: %+v", sp)
	}
	if !slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "newer than the pull") }) {
		t.Errorf("warnings: %q", d.Warnings)
	}
	// the other sections plan as they do with no block
	dNone, err := Plan(f.vendor, without, cur, cur, Options{Scope: "lab", Device: "jsw1"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(lines(d, ""), lines(dNone, "")) {
		t.Errorf("the other sections changed:\n%s\nwant\n%s", strings.Join(lines(d, ""), "\n"), strings.Join(lines(dNone, ""), "\n"))
	}
	// the comparison names it, and is neither a difference nor a stale device
	rs, err := devconf.CompareAll(exp, cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == "system" && (r.State != devconf.StateNA || len(r.Notes) != 1) {
			t.Errorf("system result: %+v", r)
		}
	}
}

// (h) The back-out: a replaced value is typed back, what the plan added is
// deleted, and a replaced message (of which the pull holds a digest, not the
// text) is a note, never a statement with the mark.
func TestSystemBackout(t *testing.T) {
	f := systemFixture(t)
	mut := func(c *JunosConfig) {
		dropPrefix("system time-zone", "system login message", "system name-server", "system ntp")(c)
		for _, s := range []string{
			"set system time-zone America/New_York",
			`set system login message "Old banner"`,
			"set system ntp server 192.0.2.7",
			"set system ntp trusted-key 7",
		} {
			c.Add(s)
		}
	}
	d, text := planSystem(t, mut, nil, systemOpt)
	if len(d.Backout) == 0 {
		t.Fatal("no back-out")
	}
	var typed, notes []string
	for _, l := range d.Backout {
		if l.Op == OpComment {
			notes = append(notes, l.Text)
			continue
		}
		typed = append(typed, l.Text)
	}
	for _, want := range []string{
		"set system time-zone America/New_York",
		"delete system name-server 192.0.2.53",
		"delete system ntp authentication-key 1",
		"delete system ntp boot-server",
		"delete system ntp source-address",
		"delete system ntp server 192.0.2.123",
	} {
		if !slices.Contains(typed, want) {
			t.Errorf("the back-out lacks %q:\n%v", want, typed)
		}
	}
	for _, l := range typed {
		if strings.Contains(l, "<message:") || strings.Contains(l, "ntp-key-0123456789") {
			t.Errorf("the back-out types %q", l)
		}
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "login message") || !strings.Contains(notes[0], "<message: 1 lines, 10 characters, id ") {
		t.Errorf("notes: %q", notes)
	}
	// applied to the planned configuration it gives the device's own statements
	// back (the check of the whole-device back-out tests)
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
	keep := func(c *JunosConfig) []string {
		var out []string
		for _, s := range c.stmts {
			if j := strings.Join(s.path, " "); strings.HasPrefix(j, "system ntp") || strings.HasPrefix(j, "system time-zone") ||
				strings.HasPrefix(j, "system name-server") {
				out = append(out, s.text())
			}
		}
		slices.Sort(out)
		return out
	}
	if b, a := keep(before), keep(after); !slices.Equal(b, a) {
		t.Errorf("the back-out does not restore the statements\nbefore %v\nafter  %v", b, a)
	}
	// the stored form of the back-out holds neither the message nor the key
	out, err := Backout(d, f.header(), Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"Authorized", "ntp-key-0123456789"} {
		if strings.Contains(out, bad) {
			t.Errorf("the back-out holds %q", bad)
		}
	}
}

// (i) A scope with no system block has no system section at all: the device's
// own login message, domain and NTP are not compared, listed or kept.
func TestSystemNoBlockNoSection(t *testing.T) {
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	var without []devices.Section
	for _, s := range exp {
		if s.Name != "system" {
			without = append(without, s)
		}
	}
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), without...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := devconf.CompareAll(without, cur)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == "system" {
			t.Errorf("a system result with no block: %+v", r)
		}
	}
	d, err := Plan(f.vendor, without, cur, cur, Options{Scope: "lab"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d.Sections {
		if s.Name == "system" {
			t.Errorf("a system section in the plan: %+v", s)
		}
	}
	for _, k := range d.Kept {
		if k.Section == "system" {
			t.Errorf("kept: %+v", k)
		}
	}
	rep := Report(d, f.header(), Wrapper{})
	for _, l := range strings.Split(rep, "\n") {
		for _, lead := range []string{"# Consistent:", "# The standard has nothing for:", "# Not selected", "# Not visible"} {
			if strings.HasPrefix(l, lead) && strings.Contains(l, "system") {
				t.Errorf("the report names the section: %q", l)
			}
		}
	}
	// the other Junos fixture, which holds no such statement, is the same
	g := fixtureNamed(t, "juniper.synthetic-lab")
	exp2, cur2, plain2 := g.load(t)
	d2, err := Plan(g.vendor, exp2, cur2, plain2, g.options())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range d2.Sections {
		if s.Name == "system" {
			t.Errorf("a system section in the synthetic lab plan: %+v", s)
		}
	}
}

// The mark of a message never holds a word of it, and a stem read again is
// the same stem.
func TestSystemMessageIsOnlyAMarkInTheComparison(t *testing.T) {
	f := systemFixture(t)
	exp := expectedSections(t, f.expected)
	cur, err := devconf.Extract(f.vendor, capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	sec := cur.Sections["system"]
	var mark string
	for _, l := range sec.Lines {
		if strings.HasPrefix(l, "set system login message ") {
			mark = l
		}
		if strings.Contains(l, "Authorized") || strings.Contains(l, "Disconnect") || strings.Contains(l, "ntp-key") || strings.Contains(l, "EXAMPLEKEY") {
			t.Errorf("the extraction holds %q", l)
		}
	}
	want := `set system login message "` + devconf.MessageMark(fixtureBody) + `"`
	if mark != want {
		t.Errorf("the mark %q, want %q", mark, want)
	}
	again, err := devconf.Normalise(f.vendor, sec)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again.Lines, sec.Lines) || !slices.Equal(again.Secret, sec.Secret) {
		t.Errorf("a stem read again changed:\n%v\n%v", again.Lines, sec.Lines)
	}
}
