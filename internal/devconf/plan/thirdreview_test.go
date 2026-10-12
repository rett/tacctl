package plan

// The second review of WP13.2 (Opus, no blockers): the Junos cleanup follows
// the scope's protocol (S2), the report agrees with the region it prints
// (S6), the Junos cleanup asks for the pending commit to be settled (S7), a
// kept back-out never holds a value whatever its elided form (the note of
// kept()), and a group entry names the host line the device stores
// (iosGroupEntryServer).

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// settledFrom pastes the plans of a text until the first region is empty and
// returns the pull that verifies them.
func settledFrom(t *testing.T, f fixture, exp []devices.Section, text string, opt Options) (devconf.Extracted, string) {
	t.Helper()
	opt.Converge = false
	cur, err := devconf.Extract(f.vendor, text, exp...)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 6; n++ {
		d, err := Plan(f.vendor, exp, cur, cur, opt)
		if err != nil {
			t.Fatal(err)
		}
		if d.Empty() {
			return cur, text
		}
		text, cur = pasteAll(t, f, exp, text, d)
	}
	t.Fatal("the plans do not settle")
	return cur, text
}

// S2: on a TACACS+ scope the cleanup never removes a RADIUS server (it may
// serve accounting or another login method), and a TACACS+ server that a
// staying accounting destination names stays; on a RADIUS scope the other way
// round.
func TestJunosCleanupFollowsTheScopesProtocol(t *testing.T) {
	f := fixtureByName(t, "juniper.synthetic-lab")
	exp := expectedSections(t, f.expected)
	text := capture(t, f.raw) + "\n" +
		"set system radius-server 203.0.113.9 secret \"$9$ZZZZZZZZ\"\n" +
		"set system accounting destination radius server 203.0.113.9\n" +
		"set system tacplus-server 203.0.113.5 secret \"$9$ZZZZZZZZ\"\n" +
		"set system tacplus-server 203.0.113.6 secret \"$9$ZZZZZZZZ\"\n" +
		"set system accounting destination tacplus server 203.0.113.6\n"
	o := f.options()
	cur, _ := settledFrom(t, f, exp, text, o)
	o.Converge = true
	d, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range d.Cleanup.Lines {
		got = append(got, l.Text)
	}
	// the stray server of the fixture and the one nobody names go; the RADIUS
	// server and the one an accounting destination names stay
	for _, want := range []string{"delete system tacplus-server 192.0.2.99", "delete system tacplus-server 203.0.113.5"} {
		if !slices.Contains(got, want) {
			t.Errorf("cleanup lacks %q: %q", want, got)
		}
	}
	for _, bad := range []string{"203.0.113.9", "203.0.113.6"} {
		for _, g := range got {
			if strings.Contains(g, bad) {
				t.Errorf("the cleanup removes %q: %q", bad, g)
			}
		}
	}
	why := map[string]string{}
	for _, l := range d.Cleanup.Left {
		why[l.Text] = l.Why
	}
	var radius, named string
	for text, w := range why {
		switch {
		case strings.HasPrefix(text, "set system radius-server 203.0.113.9"):
			radius = w
		case strings.HasPrefix(text, "set system tacplus-server 203.0.113.6"):
			named = w
		}
	}
	if !strings.Contains(radius, "it is a RADIUS server and the scope's protocol is the other") {
		t.Errorf("the RADIUS server's reason: %q (%v)", radius, why)
	}
	if !strings.Contains(named, "a statement that stays names it: system accounting destination tacplus server 203.0.113.6") {
		t.Errorf("the named server's reason: %q (%v)", named, why)
	}
	checkCleanupWhole(t, f.name+" (S2)", d, f.header(), Wrapper{ConfirmMinutes: 5})

	// a RADIUS scope: the rendering has a radius-server and the radius
	// destination; the TACACS+ servers are the other protocol's
	var rexp []devices.Section
	for _, s := range exp {
		s.Lines = slices.Clone(s.Lines)
		s.Secret = slices.Clone(s.Secret)
		for i, l := range s.Lines {
			l = strings.ReplaceAll(l, "set system tacplus-server 192.0.2.10 single-connection", "set system radius-server 192.0.2.10 port 1812")
			l = strings.ReplaceAll(l, "tacplus-server", "radius-server")
			l = strings.ReplaceAll(l, "destination tacplus", "destination radius")
			s.Lines[i] = l
		}
		rexp = append(rexp, s)
	}
	rtext := strings.ReplaceAll(strings.ReplaceAll(capture(t, f.raw), "tacplus-server", "radius-server"), "destination tacplus", "destination radius") + "\n" +
		"set system tacplus-server 203.0.113.7 secret \"$9$ZZZZZZZZ\"\n" +
		"set system radius-server 203.0.113.8 secret \"$9$ZZZZZZZZ\"\n"
	rcur, _ := settledFrom(t, f, rexp, rtext, o)
	rd, err := Plan(f.vendor, rexp, rcur, rcur, o)
	if err != nil {
		t.Fatal(err)
	}
	var rgot []string
	for _, l := range rd.Cleanup.Lines {
		rgot = append(rgot, l.Text)
	}
	if slices.Contains(rgot, "delete system tacplus-server 203.0.113.7") {
		t.Errorf("a RADIUS scope removes a TACACS+ server: %q", rgot)
	}
	if !slices.Contains(rgot, "delete system radius-server 203.0.113.8") {
		t.Errorf("a RADIUS scope keeps its own other server: %q (left %v)", rgot, rd.Cleanup.Left)
	}
}

// S6: a first region that is empty with a refused section and a cleanup: the
// report names the cleanup region as the paste and the refused section as
// left, not "CANNOT BE PLANNED ... Nothing is pasted".
func TestReportNamesTheCleanupWhenASectionIsRefused(t *testing.T) {
	f := fixtureByName(t, "cisco.reference-lab")
	exp := expectedSections(t, f.expected)
	o := f.options()
	// the standard is in place, the old server forms are extras the cleanup
	// removes, and the management list lacks an entry the plan would type:
	// with --from an address the list does not permit the section is refused
	extra := iosExtraText + iosDot1xText
	text := strings.Replace(capture(t, f.raw), "\nend", "\n"+extra+"end", 1)
	_, settled := settledFrom(t, f, exp, text, o)
	lines := strings.Split(settled, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "permit 198.51.100.0 0.0.0.255" {
			lines = append(lines[:i:i], lines[i+1:]...)
			break
		}
	}
	cur, err := devconf.Extract(f.vendor, strings.Join(lines, "\n"), exp...)
	if err != nil {
		t.Fatal(err)
	}
	o.Converge = true
	o.From = "203.0.113.77"
	d, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Empty() || d.Cleanup.Empty() || d.Of("mgmt-acl").State != StateSkipped {
		t.Fatalf("the scenario: empty=%v cleanup=%d mgmt-acl=%+v", d.Empty(), len(d.Cleanup.Lines), d.Of("mgmt-acl"))
	}
	out := flat(Report(d, f.header(), Wrapper{}))
	if strings.Contains(out, "CANNOT BE PLANNED") || strings.Contains(out, "Nothing is pasted for this device") {
		t.Errorf("the report says nothing is pasted beside a cleanup region:\n%s", out)
	}
	if !strings.Contains(out, "No fix to paste: the cleanup region below is the only paste. The section mgmt-acl is not planned and stays as it is (refused: ") {
		t.Errorf("the report does not name the refused section as left:\n%s", out)
	}
	if st := statusOf(d); st != StatusNeedsChange {
		t.Errorf("status %q", st)
	}
	// with no cleanup the refusal is the report, as ever
	o.Converge = false
	nd, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	if got := flat(Report(nd, f.header(), Wrapper{})); !strings.Contains(got, "CANNOT BE PLANNED: refused: mgmt-acl") {
		t.Errorf("no refusal without the cleanup:\n%s", got)
	}
}

// S7: a Junos cleanup asks for the pending 'commit confirmed' to be settled:
// the check pull of the first region is taken before its 'commit'.
func TestJunosCleanupAsksForNoPendingCommit(t *testing.T) {
	f := fixtureByName(t, "juniper.synthetic-lab")
	o := f.options()
	exp, cur, _ := settledFixture(t, f, o)
	o.Converge = true
	d, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	if d.Cleanup.Empty() {
		t.Fatal("no cleanup")
	}
	const want = "that 'show system commit' shows no pending 'commit confirmed' (type the plan's 'commit' first)"
	out := flat(Block(d, f.header(), Wrapper{ConfirmMinutes: 5}))
	if strings.Count(out, want) != 2 {
		t.Errorf("the report and the after-steps should each say it (%d):\n%s", strings.Count(out, want), out)
	}
	if !strings.Contains(flat(CleanupAfter(d, f.header(), Wrapper{ConfirmMinutes: 5})), want) {
		t.Errorf("CleanupAfter does not say it")
	}
	// ASCII, as every paste
	for _, l := range strings.Split(Block(d, f.header(), Wrapper{ConfirmMinutes: 5}), "\n") {
		for i := 0; i < len(l); i++ {
			if l[i] < 0x20 || l[i] > 0x7e {
				t.Errorf("a byte outside printable ASCII in %q", l)
			}
		}
	}
	// the IOS cleanup has no pending revert: it does not say it
	fi := fixtureByName(t, "cisco.reference-lab")
	io := fi.options()
	iexp, icur, _ := settledFixture(t, fi, io)
	io.Converge = true
	id, err := Plan(fi.vendor, iexp, icur, icur, io)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(Block(id, fi.header(), Wrapper{}), "show system commit") {
		t.Errorf("an IOS cleanup mentions 'show system commit'")
	}
}

// kept(): a line that holds a value is a note whether or not its elided form
// is known, in the back-out and in the undo of a line; never the value.
func TestKeptNotesALineWithAValueWhateverItsElidedForm(t *testing.T) {
	const val = "value-not-for-the-store"
	d := Delta{Vendor: devconf.FamilyJunos,
		Lines: []Line{{Op: OpSet, Section: "aaa", Text: `set system tacplus-server 192.0.2.1 secret "` + val + `"`, Secret: true, HasValue: true,
			Undo: []Line{{Op: OpLine, Section: "aaa", Text: "key " + val, Secret: true, HasValue: true}}}},
		Backout: []Line{{Op: OpSet, Section: "aaa", Text: `set system tacplus-server 192.0.2.1 secret "` + val + `"`, Secret: true, HasValue: true},
			{Op: OpSet, Section: "aaa", Text: `set system tacplus-server 192.0.2.2 secret "` + val + `"`, Secret: true, HasValue: true,
				Elided: `set system tacplus-server 192.0.2.2 secret <secret>`}}}
	k := d.kept()
	for _, l := range slices.Concat(k.Backout, k.Lines[0].Undo) {
		if l.Op != OpComment || strings.Contains(l.Text, val) {
			t.Errorf("a kept line is not a note or holds the value: %+v", l)
		}
	}
	if !strings.Contains(k.Backout[1].Text, "type yourself, with its own value: set system tacplus-server 192.0.2.2 secret <secret>") {
		t.Errorf("the note of a line with an elided form: %q", k.Backout[1].Text)
	}
	if !strings.Contains(k.Backout[0].Text, "a statement of aaa that holds a secret") {
		t.Errorf("the note of a line with none: %q", k.Backout[0].Text)
	}
}

// A group entry 'server 192.0.2.5' names the host line the device stores with
// its ports, on RADIUS: the cleanup that removes the host removes the entry
// with it, and a host line that a staying entry names stays.
func TestGroupEntryNamesTheHostLineWithItsPorts(t *testing.T) {
	for _, tc := range []struct{ header, leaf, want string }{
		{"aaa group server radius G", "server 192.0.2.5", "radius-server host 192.0.2.5"},
		{"aaa group server tacacs+ G", "server 192.0.2.5", "tacacs-server host 192.0.2.5"},
		{"aaa group server radius G", "server 192.0.2.5 auth-port 1645 acct-port 1646", "radius-server host 192.0.2.5 auth-port 1645 acct-port 1646"},
	} {
		if got := iosGroupEntryServer(tc.header, tc.leaf); got != tc.want {
			t.Errorf("iosGroupEntryServer(%q, %q) = %q, want %q", tc.header, tc.leaf, got, tc.want)
		}
	}
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"radius-server host 192.0.2.5", "radius-server host 192.0.2.5 auth-port 1812 acct-port 1813", true},
		{"radius-server host 192.0.2.5 auth-port 1812 acct-port 1813", "radius-server host 192.0.2.5 auth-port 1812 acct-port 1813", true},
		{"radius-server host 192.0.2.5 auth-port 1645 acct-port 1646", "radius-server host 192.0.2.5 auth-port 1812 acct-port 1813", false},
		{"radius-server host 192.0.2.5", "radius-server host 192.0.2.6", false},
		{"radius-server host 192.0.2.5", "tacacs-server host 192.0.2.5", false},
		{"radius server X", "radius server X", true},
		{"radius server X", "radius server Y", false},
	} {
		if got := sameServerEntry(tc.a, tc.b); got != tc.want {
			t.Errorf("sameServerEntry(%q, %q) = %v", tc.a, tc.b, got)
		}
	}
}
