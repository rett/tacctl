package plan

// D118 (12): command authorization waits until the server is proven to the
// device (Opus re-review, SF1).

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// cmdAuthOf are the command-authorization statements among typed texts.
func cmdAuthOf(texts []string) []string {
	var out []string
	for _, s := range texts {
		if s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "no ")); isCmdAuthStem(s) {
			out = append(out, s)
		}
	}
	return out
}

func regionTexts(d Delta, h Header) []string {
	var out []string
	for _, rl := range RegionLines(d, h, Wrapper{}) {
		out = append(out, rl.Text)
	}
	return out
}

// backoutTexts are the lines between the back-out banners.
func backoutTexts(d Delta, h Header) []string {
	var out []string
	for _, rl := range BackoutLines(d, h, Wrapper{}) {
		out = append(out, rl.Text)
	}
	return out
}

// shortCmdAuth is a command-authorization statement without its method list:
// what a back-out 'no' line carries.
func shortCmdAuth(s string) string {
	if f := strings.Fields(s); len(f) >= 5 && f[2] == "commands" {
		return strings.Join(f[:5], " ")
	}
	return s
}

func renderedLines(t *testing.T, f fixture, name string) []string {
	t.Helper()
	for _, s := range expectedSections(t, f.expected) {
		if s.Name == name {
			return s.Lines
		}
	}
	return nil
}

// On a bare device (no AAA, and so no server in use) the pasting session and
// its back-out are local users the server does not know: command
// authorization is not in the region, the plain text, the JSON, the back-out
// or the counts; it stays '+', the section is not consistent, and the report
// says what to do.
func TestCommandAuthorizationHeldBackOnABareDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	d := planI(t, f, nil, Options{Scope: "lab", Device: "sw-lab-1"})
	h := f.header()
	held := []string{
		"aaa authorization commands 1 default local group LAB-TACACS",
		"aaa authorization commands 7 default local group LAB-TACACS",
		"aaa authorization commands 15 default local group LAB-TACACS",
		"aaa authorization config-commands",
	}
	if got := cmdAuthOf(lines(d, "")); len(got) != 0 {
		t.Errorf("the plan has %q", got)
	}
	for _, l := range d.Lines {
		if l.Late {
			t.Errorf("a late line in the plan: %q", l.Text)
		}
	}
	plain, err := Plain(d, h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	js, err := JSON(d, h, Wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Region, Backout, Withheld []string
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Region) == 0 || len(doc.Backout) == 0 {
		t.Fatalf("the JSON has no region or back-out:\n%s", js)
	}
	for name, texts := range map[string][]string{
		"region": regionTexts(d, h), "plain": strings.Split(plain, "\n"), "back-out": backoutTexts(d, h),
		"json region": doc.Region, "json back-out": doc.Backout,
	} {
		if got := cmdAuthOf(texts); len(got) != 0 {
			t.Errorf("the %s has %q", name, got)
		}
	}
	// the held statements are named, in the plan and in the JSON
	for _, s := range held {
		if !slices.Contains(d.Withheld, cmdAuthWithheldPrefix+s) || !slices.Contains(doc.Withheld, cmdAuthWithheldPrefix+s) {
			t.Errorf("%q is not withheld: %q", s, d.Withheld)
		}
	}
	// they stay '+' in the report, unfixed, with the sentence
	n := 0
	for _, it := range d.Items {
		if strings.Contains(it.Statement, "aaa authorization commands") || strings.Contains(it.Statement, "config-commands") {
			n++
			if it.Fixed || it.Action != cmdAuthHeldText+"." || it.Section != "aaa" || it.Kind != KindMissing {
				t.Errorf("the item of command authorization: %+v", it)
			}
		}
	}
	if n == 0 {
		t.Errorf("no item of command authorization:\n%s", Report(d, h, Wrapper{}))
	}
	const want = "command authorization is not in this paste: log in on a new session with your own account and check 'show privilege', then plan again; it is the one group of lines left"
	if cmdAuthHeldText != want {
		t.Errorf("the sentence is %q", cmdAuthHeldText)
	}
	report := Report(d, h, Wrapper{})
	flat := strings.Join(strings.Fields(strings.ReplaceAll(report, "\n!", " ")), " ")
	if !strings.Contains(flat, want) {
		t.Errorf("the report lacks the sentence:\n%s", report)
	}
	// the section is not consistent, and the cover counts the rest as left
	if strings.Contains(flat, "Consistent: aaa") {
		t.Errorf("aaa is called consistent:\n%s", report)
	}
	if st := StatusFor(d, h); st.Left < 1 || st.Remaining.Access < 1 {
		t.Errorf("the cover line: %+v", st)
	}
	if slices.ContainsFunc(d.Warnings, func(w string) bool { return strings.Contains(w, "switches command authorization on") }) {
		t.Errorf("the warning about the lines that switch it on is in a plan without them: %q", d.Warnings)
	}
	// the managed text is unchanged: the held lines are still in the
	// rendering, which is why they stay '+'
	if !slices.Contains(renderedLines(t, f, "aaa"), "aaa authorization config-commands") {
		t.Errorf("the rendering lost the command authorization")
	}
}

// The plan with the held lines left out is what a bare device gets as step
// one; the plan after it (the check done) types the one group of lines left,
// last, its back-out takes exactly those off, and the device is then
// consistent.
func TestCommandAuthorizationTwoStepsOnABareDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.reference-bare")
	exp := expectedSections(t, f.expected)
	opt := Options{Scope: "lab", Device: "sw-lab-1", Syntax: SyntaxModern}
	cur, err := devconf.Extract("cisco", capture(t, f.raw), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d1, err := Plan("cisco", exp, cur, cur, opt)
	if err != nil {
		t.Fatal(err)
	}
	c := ParseIOS(capture(t, f.raw))
	if err := c.Apply(d1.Lines); err != nil {
		t.Fatal(err)
	}
	cur2, err := devconf.Extract("cisco", c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Plan("cisco", exp, cur2, cur2, opt)
	if err != nil {
		t.Fatal(err)
	}
	h := f.header()
	want := []string{
		"aaa authorization commands 1 default local group LAB-TACACS",
		"aaa authorization commands 7 default local group LAB-TACACS",
		"aaa authorization commands 15 default local group LAB-TACACS",
		"aaa authorization config-commands",
	}
	if got := cmdAuthOf(regionTexts(d2, h)); !slices.Equal(got, want) {
		t.Fatalf("the second plan types %q, want %q", got, want)
	}
	for _, l := range d2.Lines {
		if !l.Late {
			t.Errorf("the second plan has more than command authorization: %q", l.Text)
		}
	}
	// the region and the back-out agree
	var undo, wantUndo []string
	for _, tx := range backoutTexts(d2, h) {
		if s := strings.TrimSpace(tx); strings.HasPrefix(s, "no aaa authorization ") {
			undo = append(undo, shortCmdAuth(strings.TrimPrefix(s, "no ")))
		}
	}
	for _, w := range want {
		wantUndo = append(wantUndo, shortCmdAuth(w))
	}
	slices.Sort(undo)
	slices.Sort(wantUndo)
	if !slices.Equal(undo, wantUndo) {
		t.Errorf("the back-out takes off %q, the region types %q", undo, wantUndo)
	}
	// after them the device is consistent
	if err := c.Apply(d2.Lines); err != nil {
		t.Fatal(err)
	}
	cur3, err := devconf.Extract("cisco", c.Text(), exp...)
	if err != nil {
		t.Fatal(err)
	}
	d3, err := Plan("cisco", exp, cur3, cur3, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(d3.Lines) != 0 || slices.ContainsFunc(d3.Withheld, func(w string) bool { return strings.HasPrefix(w, cmdAuthWithheldPrefix) }) {
		t.Errorf("the third plan: %v %q", d3.Lines, d3.Withheld)
	}
}

// The rule's cases, and what is not enough to prove the server.
func TestCommandAuthorizationRule(t *testing.T) {
	dropCmdAuth := func(c *IOSConfig) {
		c.noGlobal("aaa authorization commands")
		c.noGlobal("aaa authorization config-commands")
	}
	for _, x := range []struct {
		name    string
		fixture string
		syntax  string
		mut     func(c *IOSConfig)
		emitted bool
	}{
		{"bare device", "cisco.reference-bare", SyntaxModern, nil, false},
		{"server block and a login list naming a group", "cisco.reference-bare", SyntaxModern, serverInUse, true},
		{"an exec list naming tacacs+ is enough", "cisco.reference-bare", SyntaxModern, func(c *IOSConfig) {
			c.typeGlobal("aaa new-model")
			c.insertBlock(iosBlk{lines: []string{"tacacs server OLDNAME", " address ipv4 192.0.2.10"}})
			c.typeGlobal("aaa authorization exec default group tacacs+ if-authenticated")
		}, true},
		{"the legacy host entry is a server in use too", "cisco.reference-bare", SyntaxModern, func(c *IOSConfig) {
			c.typeGlobal("aaa new-model")
			c.typeGlobal("tacacs-server host 192.0.2.10 single-connection timeout 5 key 7 0822455D0A16")
			c.typeGlobal("aaa authentication login default group LAB-TACACS local")
		}, true},
		{"an aaa authorization commands line already on the device", "cisco.reference-bare", SyntaxModern, func(c *IOSConfig) {
			c.typeGlobal("aaa new-model")
			c.typeGlobal("aaa authorization commands 1 default local")
		}, true},
		{"the server's block and no list that names a group", "cisco.reference-bare", SyntaxModern, func(c *IOSConfig) {
			c.typeGlobal("aaa new-model")
			c.insertBlock(iosBlk{lines: []string{"tacacs server TACACS", " address ipv4 192.0.2.10"}})
			c.typeGlobal("aaa authentication login default local")
		}, false},
		{"a list naming a group and another server's address", "cisco.reference-bare", SyntaxModern, func(c *IOSConfig) {
			c.typeGlobal("aaa new-model")
			c.insertBlock(iosBlk{lines: []string{"tacacs server OTHER", " address ipv4 203.0.113.9"}})
			c.typeGlobal("aaa authentication login default group LAB-TACACS local")
		}, false},
		{"ios12 with the host entry and the lists, command authorization removed", "cisco.reference-12x", SyntaxIOS12, dropCmdAuth, true},
		{"ios12 without the host entry", "cisco.reference-12x", SyntaxIOS12, func(c *IOSConfig) {
			dropCmdAuth(c)
			c.noGlobal("tacacs-server host")
		}, false},
		{"ios12 with no list that names a group", "cisco.reference-12x", SyntaxIOS12, func(c *IOSConfig) {
			dropCmdAuth(c)
			c.typeGlobal("aaa authentication login default local")
			c.typeGlobal("aaa authorization exec default local if-authenticated")
		}, false},
	} {
		t.Run(x.name, func(t *testing.T) {
			f := fixtureNamed(t, x.fixture)
			d := planI(t, f, x.mut, Options{Scope: "lab", Device: "sw-lab-1", Syntax: x.syntax})
			h := f.header()
			inRegion := cmdAuthOf(regionTexts(d, h))
			inBackout := cmdAuthOf(backoutTexts(d, h))
			plain, err := Plain(d, h, Wrapper{})
			if err != nil {
				t.Fatal(err)
			}
			held := slices.ContainsFunc(d.Withheld, func(w string) bool { return strings.HasPrefix(w, cmdAuthWithheldPrefix) })
			if x.emitted {
				if held || len(inRegion) == 0 {
					t.Fatalf("not emitted (held %v, region %q):\n%s", held, inRegion, d.Display())
				}
				// last in the whole block, and each line has its undo
				for i, l := range d.Lines {
					if i >= len(d.Lines)-len(inRegion) && !l.Late {
						t.Errorf("%q is among the last lines and is not late", l.Text)
					}
					if l.Late && len(l.Undo) == 0 {
						t.Errorf("%q has no undo", l.Text)
					}
				}
				if len(inBackout) != len(inRegion) {
					t.Errorf("the region types %q, the back-out takes off %q", inRegion, inBackout)
				}
				return
			}
			if !held {
				t.Fatalf("not held back:\n%s", d.Display())
			}
			if len(inRegion) != 0 || len(inBackout) != 0 || len(cmdAuthOf(strings.Split(plain, "\n"))) != 0 {
				t.Errorf("held lines in the output: region %q, back-out %q", inRegion, inBackout)
			}
		})
	}
}
