package plan

// The cleanup region of --converge (plan D111): its invariants, its guards
// and the property that it never changes the first region, and (D111,
// amended) that it is never beside one: a device with something to paste
// gets only that region and the sentence that the cleanup comes after it.

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// checkCleanupWhole is the whole-paste invariant on the output of a
// --converge plan. With a first region the output is that region as ever
// and the one sentence about the cleanup: no cleanup banner, no cleanup
// line, and nothing after the region's end banner that is a plain line. With
// no first region the cleanup is the only region, between its own banner
// pair (the end banner is not the first region's), safe pasted whole, with
// nothing before the first banner or after the last that is a plain line.
func checkCleanupWhole(t *testing.T, name string, d Delta, h Header, w Wrapper) {
	t.Helper()
	full := Block(d, h, w)
	leader := commentLeader(d.Vendor)
	bc := bannerChar(d.Vendor)
	pasteFrom := bc + " PASTE FROM HERE: " + h.Device + " " + bc
	pasteTo := bc + " PASTE TO HERE: " + h.Device + " " + bc
	from, to := cleanupFromBanner(d, h), cleanupToBanner(d, h)
	if from == pasteFrom || to == pasteTo {
		t.Fatalf("%s: the cleanup banners are the first region's", name)
	}
	checkWholePaste(t, name, d, h, w)
	if !d.Empty() {
		// B1: one output, one region
		if !d.Cleanup.Empty() || d.Cleanup.Whole != "" || len(d.Cleanup.Left) > 0 {
			t.Errorf("%s: a cleanup beside a first region: %+v", name, d.Cleanup)
		}
		if strings.Contains(full, "CLEANUP FROM HERE") || strings.Contains(full, "CLEANUP TO HERE") {
			t.Errorf("%s: a cleanup banner beside a first region", name)
		}
		if !strings.Contains(flat(full), CleanupDeferred) {
			t.Errorf("%s: the report does not say that the cleanup comes after the first region", name)
		}
		return
	}
	if strings.Contains(full, pasteFrom) || strings.Contains(full, pasteTo) {
		t.Errorf("%s: a first-region banner for an empty first region", name)
	}
	if d.Cleanup.Empty() {
		if strings.Contains(full, "CLEANUP FROM HERE") || strings.Contains(full, "CLEANUP TO HERE") {
			t.Errorf("%s: a cleanup banner with no cleanup", name)
		}
		if !strings.Contains(full, "Cleanup (--converge)") {
			t.Errorf("%s: the report does not say what --converge did", name)
		}
		return
	}
	if strings.Count(full, from) != 1 || strings.Count(full, to) != 1 || strings.Index(full, from) > strings.Index(full, to) {
		t.Errorf("%s: %q and %q are not one pair in the output", name, from, to)
		return
	}
	var lines []string
	for _, l := range CleanupLines(d, h, w) {
		lines = append(lines, l.Text)
	}
	if err := CheckRegion(d.Vendor, lines); err != nil {
		t.Errorf("%s: the cleanup region is not safe to paste whole: %v\n%s", name, err, strings.Join(lines, "\n"))
	}
	i := strings.Index(full, from)
	rest := full[i+len(from)+1:]
	j := strings.Index(rest, to)
	if strings.TrimSuffix(rest[:j], "\n") != strings.Join(lines, "\n") {
		t.Errorf("%s: the text between the cleanup banners is not the cleanup region", name)
	}
	// nothing before the region and nothing after it is a plain line
	if typed := onlyComments(withoutRestoreBlock(t, name, d, h, full, full[:i], from), leader); len(typed) != 0 {
		t.Errorf("%s: plain lines before the cleanup region: %q", name, typed)
	}
	if typed := onlyComments(rest[j+len(to)+1:], leader); len(typed) != 0 {
		t.Errorf("%s: plain lines after the cleanup region: %q", name, typed)
	}
	// the follow-up is said, as a comment
	want := "write memory"
	if d.Vendor == devconf.FamilyJunos {
		want = "commit"
	}
	if !strings.Contains(rest[j:], "yourself:  "+want) {
		t.Errorf("%s: the follow-up %q is not said after the cleanup", name, want)
	}
	// only removals: no 'set', no 'insert' on Junos, no line without 'no' on IOS
	for _, l := range d.Cleanup.Lines {
		switch {
		case d.Vendor == devconf.FamilyJunos && l.Op != OpDelete, d.Vendor == devconf.FamilyIOS && l.Op != OpNo:
			t.Errorf("%s: a cleanup line that is not a removal: %q", name, l.Shown())
		}
		if id, bad := neverMatch(d.Vendor, l); bad {
			t.Errorf("%s: %q is on the never list (%s)", name, l.Shown(), id)
		}
		if l.Secret || l.HasValue {
			t.Errorf("%s: a cleanup line holds a secret: %q", name, l.Shown())
		}
		// never the lists the session and the standard stand on, and no list
		// at all (B2: a named list's use on a line is not read)
		if d.Vendor == devconf.FamilyIOS && len(l.Context) == 0 && strings.HasPrefix(l.Text, "aaa ") && !strings.HasPrefix(l.Text, "aaa group server ") {
			t.Errorf("%s: an aaa list is removed: %q", name, l.Text)
		}
	}
	// ASCII, as every paste
	for _, l := range lines {
		for k := 0; k < len(l); k++ {
			if l[k] < 0x20 || l[k] > 0x7e {
				t.Errorf("%s: a byte outside printable ASCII in %q", name, l)
			}
		}
	}
}

// flat is an output with its comment leaders removed and its lines joined,
// so a sentence the report wrapped can be looked for.
func flat(out string) string {
	var parts []string
	for _, l := range strings.Split(out, "\n") {
		parts = append(parts, strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(l), "#!")))
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

// pasteAll applies the lines of a plan to the text of a pull, the way the
// technician's paste does, and reads the result as the pull that verifies
// it.
func pasteAll(t testing.TB, f fixture, exp []devices.Section, text string, d Delta) (string, devconf.Extracted) {
	t.Helper()
	var after string
	switch d.Vendor {
	case devconf.FamilyJunos:
		c := ParseJunos(text)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatalf("%s: apply: %v\n%s", f.name, err, d.Display())
		}
		after = c.Text()
	default:
		c := ParseIOS(text)
		if err := c.Apply(d.Lines); err != nil {
			t.Fatalf("%s: apply: %v\n%s", f.name, err, d.Display())
		}
		after = c.Text()
	}
	ex, err := devconf.Extract(f.vendor, after, exp...)
	if err != nil {
		t.Fatalf("%s: extract after the paste: %v", f.name, err)
	}
	ex.SecretsVisible = f.class == nil && !strings.Contains(f.name, "engineer")
	return after, ex
}

// settle pastes the plan of a pull, pulls again, and so on until the first
// region is empty (or stops changing): the pull a technician has before
// asking for the cleanup. It returns that pull and how many pastes it took.
func settle(t testing.TB, f fixture, exp []devices.Section, text string, cur, plain devconf.Extracted, opt Options) (devconf.Extracted, int) {
	t.Helper()
	opt.Converge = false
	var prev Delta
	for n := 0; ; n++ {
		d, err := Plan(f.vendor, exp, cur, plain, opt)
		if err != nil {
			t.Fatal(err)
		}
		if d.Empty() || n == 5 || n > 0 && d.Equal(prev) {
			return cur, n
		}
		text, cur = pasteAll(t, f, exp, text, d)
		plain = cur
		prev = d
	}
}

// settledFixture is a fixture after the pastes that make its first region
// empty.
func settledFixture(t testing.TB, f fixture, opt Options) (exp []devices.Section, cur devconf.Extracted, pastes int) {
	t.Helper()
	exp, cur0, plain0 := f.load(t)
	cur, pastes = settle(t, f, exp, capture(t, f.raw), cur0, plain0, opt)
	return exp, cur, pastes
}

// --converge does not change the first region, the back-out or anything the
// plan alone says about the lines, for every fixture and both secrets
// options; and the output is safe pasted whole.
func TestConvergeLeavesTheFirstRegionAlone(t *testing.T) {
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, secrets := range []bool{false, true} {
			a := f.options()
			a.Secrets = secrets
			b := a
			b.Converge = true
			da, err := Plan(f.vendor, exp, cur, plain, a)
			if err != nil {
				t.Fatal(err)
			}
			db, err := Plan(f.vendor, exp, cur, plain, b)
			if err != nil {
				t.Fatal(err)
			}
			h, w := f.header(), Wrapper{ConfirmMinutes: 5}
			if !da.Equal(db) {
				t.Errorf("%s: --converge changed the plan's lines", f.name)
			}
			if Region(da, h, w) != Region(db, h, w) || After(da, h, w) != After(db, h, w) {
				t.Errorf("%s: --converge changed the region or its after-steps", f.name)
			}
			ba, ea := Backout(da, h, w)
			bb, eb := Backout(db, h, w)
			if ba != bb || (ea == nil) != (eb == nil) {
				t.Errorf("%s: --converge changed the back-out", f.name)
			}
			if strings.Contains(Block(da, h, w), "CLEANUP") {
				t.Errorf("%s: the plan without --converge says CLEANUP", f.name)
			}
			checkCleanupWhole(t, f.name, db, h, w)
		}
	}
}

// B1: a device with something left to paste never yields a cleanup region,
// whatever its extras: the output is the first region, the one sentence, and
// the JSON says the cleanup is deferred.
func TestNoCleanupBesideAFirstRegion(t *testing.T) {
	deferred := 0
	for _, f := range fixtures(t) {
		exp, cur, plain := f.load(t)
		for _, secrets := range []bool{false, true} {
			o := f.options()
			o.Secrets, o.Converge = secrets, true
			d, err := Plan(f.vendor, exp, cur, plain, o)
			if err != nil {
				t.Fatal(err)
			}
			if d.Empty() {
				continue
			}
			deferred++
			h, w := f.header(), Wrapper{ConfirmMinutes: 5}
			if !d.Cleanup.Empty() || d.Cleanup.Deferred != CleanupDeferred || d.Cleanup.Whole != "" {
				t.Errorf("%s: cleanup %+v beside a first region", f.name, d.Cleanup)
			}
			out := Block(d, h, w)
			if strings.Contains(out, "CLEANUP") || strings.Count(out, "PASTE FROM HERE") != 1 {
				t.Errorf("%s: the output has a cleanup banner or not one region", f.name)
			}
			if !strings.Contains(flat(out), "Cleanup (--converge): cleanup comes after this region is pasted and verified: pull the device, then plan --converge again.") {
				t.Errorf("%s: the sentence is missing:\n%s", f.name, out)
			}
			js, err := JSON(d, h, w)
			if err != nil {
				t.Fatal(err)
			}
			var doc jsonDelta
			if err := json.Unmarshal(js, &doc); err != nil {
				t.Fatal(err)
			}
			if len(doc.Cleanup) != 0 || len(doc.CleanupAfter) != 0 || doc.CleanupDeferred != CleanupDeferred || !doc.Converge {
				t.Errorf("%s: the JSON has a cleanup beside a first region: %+v", f.name, doc)
			}
		}
	}
	if deferred == 0 {
		t.Error("no fixture has a first region: the test proves nothing")
	}
}

// With the pastes made, every fixture's cleanup is safe pasted whole and
// every extra is accounted for: removed, or left with a reason.
func TestSettledCleanupAccountsForEveryExtra(t *testing.T) {
	cleaned := 0
	for _, f := range fixtures(t) {
		o := f.options()
		exp, cur, _ := settledFixture(t, f, o)
		o.Converge = true
		d, err := Plan(f.vendor, exp, cur, cur, o)
		if err != nil {
			t.Fatal(err)
		}
		h, w := f.header(), Wrapper{ConfirmMinutes: 5}
		checkCleanupWhole(t, f.name+" (settled)", d, h, w)
		if !d.Cleanup.Empty() {
			cleaned++
		}
		if d.Cleanup.Whole != "" || !d.Empty() {
			continue
		}
		for i, e := range d.Extras {
			if e.Guard != "" || len(e.Remove) == 0 {
				continue
			}
			covered := false
			for _, es := range d.Cleanup.extras {
				if slices.Contains(es, i) {
					covered = true
				}
			}
			left := false
			for _, l := range d.Cleanup.Left {
				if l.Section == e.Section && l.Text == e.Text {
					left = true
				}
			}
			if covered == left {
				t.Errorf("%s: extra %q is covered=%v left=%v", f.name, e.Text, covered, left)
			}
		}
	}
	if cleaned == 0 {
		t.Error("no fixture has a cleanup after its pastes: the test proves nothing")
	}
}

func fixtureByName(t testing.TB, name string) fixture {
	t.Helper()
	for _, f := range fixtures(t) {
		if f.name == name {
			return f
		}
	}
	t.Fatalf("no fixture %s", name)
	return fixture{}
}

// the second TACACS+ server of the synthetic lab switch is the cleanup's
// one line, and --from names the one source that must not go.
func TestCleanupRemovesTheOtherServerAndHonoursFrom(t *testing.T) {
	f := fixtureByName(t, "juniper.synthetic-lab")
	o := f.options()
	exp, cur, _ := settledFixture(t, f, o)
	o.Converge = true
	d, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range d.Cleanup.Lines {
		got = append(got, l.Text)
	}
	if want := []string{"delete system tacplus-server 192.0.2.99"}; !slices.Equal(got, want) {
		t.Fatalf("cleanup lines %q, want %q", got, want)
	}
	reg := CleanupRegion(d, f.header(), Wrapper{ConfirmMinutes: 5})
	for _, want := range []string{"##### CLEANUP FROM HERE: ", "##### CLEANUP TO HERE: ", "configure exclusive", "# aaa: removes the servers", `commit confirmed 5 comment "tacctl cleanup `, "show | compare | no-more"} {
		if !strings.Contains(reg, want) {
			t.Errorf("no %q in\n%s", want, reg)
		}
	}
	// the item says where the removal is
	found := false
	for _, it := range d.Items {
		if it.Kind == KindExtra && strings.Contains(it.Action, "Removed by the cleanup region, line") {
			found = true
		}
	}
	if !found {
		t.Errorf("no item names its cleanup line: %+v", d.Items)
	}

	// the address of --from is never removed
	o.From = "192.0.2.99"
	d, err = Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Cleanup.Empty() {
		t.Errorf("a cleanup that removes the address of --from: %v", d.Cleanup.Lines)
	}
	if len(d.Cleanup.Left) == 0 || !strings.Contains(d.Cleanup.Left[0].Why, "--from") {
		t.Errorf("left: %+v", d.Cleanup.Left)
	}
	// the same address as a /32 inside a prefix of the line, and a prefix
	o.From = "192.0.2.99/32"
	if d, _ = Plan(f.vendor, exp, cur, cur, o); !d.Cleanup.Empty() {
		t.Errorf("--from with a prefix length: %v", d.Cleanup.Lines)
	}
	// another address leaves it alone
	o.From = "192.0.2.77"
	if d, _ = Plan(f.vendor, exp, cur, cur, o); d.Cleanup.Empty() {
		t.Error("--from of another address refused the cleanup")
	}
}

// a login that cannot commit aaa gets no cleanup, as a whole, and says so.
func TestCleanupIsRefusedWhileTheServerIsNotPlanned(t *testing.T) {
	f := fixtureByName(t, "juniper.lab-engineer")
	o := f.options()
	exp, cur, _ := settledFixture(t, f, o)
	o.Converge = true
	d, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Cleanup.Empty() || d.Cleanup.Whole == "" {
		t.Fatalf("cleanup %+v (first region empty: %v)", d.Cleanup, d.Empty())
	}
	rep := Report(d, f.header(), Wrapper{})
	if !strings.Contains(rep, "Cleanup (--converge) is not offered:") {
		t.Errorf("the report does not say it:\n%s", rep)
	}
	if strings.Contains(Block(d, f.header(), Wrapper{}), "CLEANUP FROM HERE") {
		t.Error("a cleanup banner for a refused cleanup")
	}
}

// iosExtraText is what an older walkthrough left on a device beside the
// standard: a legacy host line and a group that names it (and a login list
// and a command list that name the group), a block with no group, an
// unreferenced group with its own block, and, for a TACACS+ scope, the
// RADIUS of 802.1X.
const iosExtraText = "tacacs-server host 192.0.2.77 key 7 0822455D0A16\n" +
	"aaa group server tacacs+ OLD-GROUP\n server 192.0.2.77\n!\n" +
	"tacacs server OLDSRV\n address ipv4 192.0.2.78\n key 7 0822455D0A16\n!\n" +
	"aaa group server tacacs+ SPARE-GROUP\n server name SPARESRV\n!\n" +
	"tacacs server SPARESRV\n address ipv4 192.0.2.79\n key 7 0822455D0A16\n!\n" +
	"aaa authorization commands 15 OTHER group OLD-GROUP local\n" +
	"aaa authentication login VTYLIST group OLD-GROUP local\n"

// iosDot1xText is RADIUS that serves port authentication.
const iosDot1xText = "aaa group server radius ISE\n server name ISE-1\n!\n" +
	"radius server ISE-1\n address ipv4 192.0.2.60 auth-port 1812 acct-port 1813\n key 7 0822455D0A16\n!\n" +
	"aaa authentication dot1x default group ISE\n"

// withIOSExtras is the reference device (or another of the IOS fixtures)
// with extra text before its 'end', planned with --converge after the
// pastes that bring it to the standard. first is the delta as pulled.
func withIOSExtras(t testing.TB, f fixture, extra string) (first, d Delta) {
	t.Helper()
	exp := expectedSections(t, f.expected)
	raw := strings.Replace(capture(t, f.raw), "\nend", "\n"+extra+"end", 1)
	cur, err := devconf.Extract(f.vendor, raw, exp...)
	if err != nil {
		t.Fatal(err)
	}
	o := f.options()
	o.Converge = true
	first, err = Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	settled, _ := settle(t, f, exp, raw, cur, cur, o)
	d, err = Plan(f.vendor, exp, settled, settled, o)
	if err != nil {
		t.Fatal(err)
	}
	return first, d
}

// oldServerForms is the reference IOS device with the forms an older
// walkthrough left (see iosExtraText, and the 802.1X RADIUS the scope does
// not manage), planned with --converge once its first region is empty.
func oldServerForms(t testing.TB) (fixture, Delta) {
	t.Helper()
	f := fixtureByName(t, "cisco.reference-lab")
	_, d := withIOSExtras(t, f, iosExtraText+iosDot1xText)
	return f, d
}

func cleanupTexts(d Delta) []string {
	var got []string
	for _, l := range d.Cleanup.Lines {
		got = append(got, strings.Join(l.Context, " > ")+" | "+string(l.Op)+" "+l.Text)
	}
	return got
}

// the old server forms of an IOS device that nothing names are the
// cleanup's: an unreferenced group before the server it names, a block with
// no group; never the standard's lists, a username or a line, never a group
// or server a staying statement names, never a command list, never the
// RADIUS of the other protocol.
func TestCleanupOfTheOldServerForms(t *testing.T) {
	f, d := oldServerForms(t)
	got := cleanupTexts(d)
	t.Logf("cleanup: %q", got)
	if want := []string{
		" | no aaa group server tacacs+ SPARE-GROUP",
		" | no tacacs server OLDSRV",
		" | no tacacs server SPARESRV",
	}; !slices.Equal(got, want) {
		t.Fatalf("cleanup lines %q, want %q", got, want)
	}
	left := map[string]string{}
	for _, l := range d.Cleanup.Left {
		left[l.Text] = l.Why
	}
	// B2: the group a staying list names is kept, with the reason, and so is
	// the host its entry names
	for text, wantWhy := range map[string]string{
		"aaa group server tacacs+ OLD-GROUP" + pathSep + "server 192.0.2.77": "OLD-GROUP local",
		"tacacs-server host 192.0.2.77 key " + secretMark:                    "group entry that names it stays",
		"aaa authorization commands 15 OTHER group OLD-GROUP local":          "named command authorization list",
	} {
		why, ok := left[text]
		if !ok {
			// the host line shows its key as the elided mark: look it up by prefix
			for k, v := range left {
				if strings.HasPrefix(k, "tacacs-server host 192.0.2.77") && strings.HasPrefix(text, "tacacs-server host 192.0.2.77") {
					why, ok = v, true
				}
			}
		}
		if !ok {
			t.Errorf("%q is not in Left: %+v", text, left)
			continue
		}
		if !strings.Contains(why, wantWhy) {
			t.Errorf("%q is left because %q, want mention of %q", text, why, wantWhy)
		}
	}
	// B3: the other protocol's entries are all left
	for _, g := range got {
		if strings.Contains(g, "radius") || strings.Contains(g, "dot1x") || strings.Contains(g, "ISE") {
			t.Errorf("a RADIUS or 802.1X line is removed: %q", g)
		}
	}
	for _, text := range []string{"radius server ISE-1", "aaa group server radius ISE"} {
		if !slices.ContainsFunc(d.Cleanup.Left, func(l CleanupLeft) bool {
			return strings.HasPrefix(l.Text, text) && strings.Contains(l.Why, "scope's protocol is the other")
		}) {
			t.Errorf("%q is not left for being RADIUS: %+v", text, d.Cleanup.Left)
		}
	}
	// never a list at all
	for _, g := range got {
		if strings.Contains(g, "aaa authentication") || strings.Contains(g, "aaa authorization") {
			t.Errorf("a list is removed: %q", g)
		}
	}
	checkCleanupWhole(t, f.name, d, f.header(), Wrapper{})
	// no secret value in the JSON, nor in the cleanup lines (the golden
	// plan.cisco.old-server-forms.converge-after.json pins the whole)
	js, err := JSON(d, f.header(), Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), "0822455D0A16") {
		t.Errorf("a key's value is in the JSON:\n%s", js)
	}
	var doc jsonDelta
	if err := json.Unmarshal(js, &doc); err != nil || len(doc.Cleanup) == 0 {
		t.Fatalf("cleanup in the JSON: %v %+v", err, doc.Cleanup)
	}
	for _, l := range doc.Cleanup {
		if strings.Contains(l, " key ") {
			t.Errorf("a key line in the cleanup JSON: %q", l)
		}
	}
	reg := CleanupRegion(d, f.header(), Wrapper{})
	if !strings.HasPrefix(reg, "!!!!! CLEANUP FROM HERE: ") || !strings.Contains(reg, "configure terminal\n") ||
		!strings.Contains(reg, "\nend\n!!!!! CLEANUP TO HERE: ") {
		t.Errorf("the IOS cleanup region:\n%s", reg)
	}
	// the lines under a header come before a group, a group before a server
	rank := -1
	for _, l := range d.Cleanup.Lines {
		if r := cleanupRank(l); r < rank {
			t.Errorf("%q is out of order (rank %d after %d)", l.Shown(), r, rank)
		} else {
			rank = r
		}
	}
	// the report says the lists are left, with the exact lines outside
	out := Block(d, f.header(), Wrapper{})
	for _, want := range []string{
		"no aaa authorization commands 15 OTHER group OLD-GROUP local",
		"no aaa authentication login VTYLIST group OLD-GROUP local",
	} {
		if !strings.Contains(flat(out), want) {
			t.Errorf("the output does not give %q:\n%s", want, out)
		}
	}
}

// the old forms as pulled: the first region and the sentence, no cleanup.
func TestOldServerFormsAsPulledHaveNoCleanup(t *testing.T) {
	f := fixtureByName(t, "cisco.reference-lab")
	first, _ := withIOSExtras(t, f, iosExtraText+iosDot1xText)
	if first.Empty() {
		t.Fatal("the reference device has a first region as pulled")
	}
	checkCleanupWhole(t, f.name+" (as pulled)", first, f.header(), Wrapper{})
}

// a RADIUS scope removes its own protocol's old servers and groups, in
// order, and never a TACACS+ entry; and a group a staying list names stays,
// whichever the protocol.
func TestCleanupOfARadiusScopeLeavesTacacsAlone(t *testing.T) {
	f := fixtureByName(t, "cisco.xe-reference-16")
	extra := "aaa group server radius OLDRAD\n server name OLDRADSRV\n!\n" +
		"radius server OLDRADSRV\n address ipv4 192.0.2.81 auth-port 1812 acct-port 1813\n key 7 0822455D0A16\n!\n" +
		"aaa group server radius KEPTRAD\n server name KEPTSRV\n!\n" +
		"radius server KEPTSRV\n address ipv4 192.0.2.82 auth-port 1812 acct-port 1813\n key 7 0822455D0A16\n!\n" +
		"aaa authentication login RADLIST group KEPTRAD local\n" +
		"aaa group server tacacs+ OLDTAC\n server name OLDTACSRV\n!\n" +
		"tacacs server OLDTACSRV\n address ipv4 192.0.2.83\n key 7 0822455D0A16\n!\n" +
		"tacacs-server host 192.0.2.84 key 7 0822455D0A16\n"
	_, d := withIOSExtras(t, f, extra)
	got := cleanupTexts(d)
	if want := []string{
		" | no aaa group server radius OLDRAD",
		" | no radius server OLDRADSRV",
	}; !slices.Equal(got, want) {
		t.Fatalf("cleanup lines %q, want %q", got, want)
	}
	for _, text := range []string{"tacacs server OLDTACSRV", "tacacs-server host 192.0.2.84", "aaa group server tacacs+ OLDTAC"} {
		if !slices.ContainsFunc(d.Cleanup.Left, func(l CleanupLeft) bool {
			return strings.HasPrefix(l.Text, text) && strings.Contains(l.Why, "scope's protocol is the other")
		}) {
			t.Errorf("%q is not left for being TACACS+: %+v", text, d.Cleanup.Left)
		}
	}
	for _, text := range []string{"aaa group server radius KEPTRAD", "radius server KEPTSRV"} {
		if !slices.ContainsFunc(d.Cleanup.Left, func(l CleanupLeft) bool { return strings.HasPrefix(l.Text, text) }) {
			t.Errorf("%q is not left: %+v", text, d.Cleanup.Left)
		}
	}
	checkCleanupWhole(t, f.name, d, f.header(), Wrapper{})
}

// a staying list that uses every server of the protocol ('group tacacs+')
// keeps all the scope's old servers.
func TestCleanupKeepsEveryServerWhileAListUsesThemAll(t *testing.T) {
	f := fixtureByName(t, "cisco.reference-lab")
	extra := "tacacs server OLDSRV\n address ipv4 192.0.2.78\n key 7 0822455D0A16\n!\n" +
		"aaa authentication login VTYLIST group tacacs+ local\n"
	_, d := withIOSExtras(t, f, extra)
	if !d.Cleanup.Empty() {
		t.Fatalf("a server is removed while a list uses all: %q", cleanupTexts(d))
	}
	if !slices.ContainsFunc(d.Cleanup.Left, func(l CleanupLeft) bool {
		return strings.HasPrefix(l.Text, "tacacs server OLDSRV") && strings.Contains(l.Why, "every server")
	}) {
		t.Errorf("the reason is not said: %+v", d.Cleanup.Left)
	}
}

// a RADIUS group's 'server name X' names a RADIUS block, never a TACACS+ one
// (should-fix 4).
func TestIOSGroupEntryServerFollowsTheGroupsProtocol(t *testing.T) {
	for _, c := range []struct{ header, leaf, want string }{
		{"aaa group server tacacs+ G", "server name X", "tacacs server X"},
		{"aaa group server radius G", "server name X", "radius server X"},
		{"aaa group server tacacs+ G", "server 192.0.2.5", "tacacs-server host 192.0.2.5"},
		{"aaa group server radius G", "server 192.0.2.5 auth-port 1812 acct-port 1813", "radius-server host 192.0.2.5 auth-port 1812 acct-port 1813"},
		{"aaa group server ldap G", "server name X", ""},
		{"aaa group server radius G", "server-private 192.0.2.5 key 7 AB", ""},
	} {
		if got := iosGroupEntryServer(c.header, c.leaf); got != c.want {
			t.Errorf("%s / %s: got %q, want %q", c.header, c.leaf, got, c.want)
		}
	}
}

// a cleanup of an IOS device is deferred while its server is not in place
// (the plan adds the standard's block), and after the paste offers the old
// host line.
func TestCleanupAfterTheServerIsPut(t *testing.T) {
	f := fixtureByName(t, "cisco.reference-lab")
	exp := expectedSections(t, f.expected)
	raw := capture(t, f.raw)
	// the server block is gone from the device, an old host line stays
	i := strings.Index(raw, "tacacs server TACACS")
	j := strings.Index(raw[i:], "!\n")
	raw = raw[:i] + "tacacs-server host 192.0.2.77 key 7 0822455D0A16\n" + raw[i+j:]
	cur, err := devconf.Extract(f.vendor, raw, exp...)
	if err != nil {
		t.Fatal(err)
	}
	o := f.options()
	o.Converge = true
	d, err := Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	// the plan adds the standard's block: the cleanup is a second output
	if d.Empty() || !d.Cleanup.Empty() || d.Cleanup.Deferred == "" {
		t.Fatalf("first region empty=%v cleanup %+v", d.Empty(), d.Cleanup)
	}
	// without any way to put the server there (--section skips aaa) the
	// cleanup of aaa is not offered
	o.Sections = []string{"snmp"}
	d, err = Plan(f.vendor, exp, cur, cur, o)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range d.Cleanup.Lines {
		if l.Section == "aaa" {
			t.Errorf("an aaa removal with aaa not selected: %q", l.Shown())
		}
	}
}
