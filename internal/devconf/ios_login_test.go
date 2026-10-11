package devconf

// WP13.1b (D106, D107): the login leaves of the console and VTY lines in
// aaa, the presence of the 'enable' secret, and the note for a privilege
// line the device stores shortened.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// loginExpected is the rendering these tests compare with: the legacy
// walkthrough's AAA lines, the console and VTY login leaves, and the VTY
// access class in its own section.
func loginExpected() (aaa, acl devices.Section) {
	aaa = sec(SectionAAA, "aaa new-model", "aaa authentication login default local group G",
		"line con 0", "  login authentication default", "line vty 0 15", "  login authentication default")
	acl = sec(SectionMgmtACL, "ip access-list standard VTY-ACL", "  permit 192.0.2.10", "  deny   any log",
		"line vty 0 15", "  access-class VTY-ACL in")
	return aaa, acl
}

// linesOf is a result's lines as 'op text', sorted.
func linesOf(r SectionResult) []string {
	var out []string
	for _, l := range r.Lines {
		out = append(out, string(l.Op)+" "+l.Text)
	}
	slices.Sort(out)
	return out
}

func TestCiscoLoginLeaves(t *testing.T) {
	const head = "version 12.4\naaa new-model\naaa authentication login default local group G\n"
	for _, tc := range []struct {
		name  string
		lines string
		state State
		want  []string // the 'op text' lines of the leaves only
	}{
		{"login local before the walkthrough", "line con 0\n login local\nline vty 0 4\n login local\nline vty 5 15\n login local\n", StateDiffers,
			[]string{"+ line con 0 > login local", "+ line vty 0 15 > login local",
				"- line con 0 > login authentication default", "- line vty 0 15 > login authentication default"}},
		{"the AAA login method", "line con 0\n login authentication default\nline vty 0 4\n login authentication default\nline vty 5 15\n login authentication default\n", StateOK,
			[]string{"= line con 0 > login authentication default", "= line vty 0 15 > login authentication default"}},
		// IOS does not print 'login authentication default' (the lab 7200:
		// the VTY lines hold the access class only): with 'aaa new-model'
		// a line without a login statement is on the default method list.
		{"implicit on every line, as the real capture", "line con 0\n exec-timeout 0 0\nline vty 0 4\n access-class VTY-ACL in\nline vty 5 15\n access-class VTY-ACL in\n", StateOK,
			[]string{"= line con 0 > login authentication default", "= line vty 0 15 > login authentication default"}},
		{"one range explicit local, the other implicit", "line con 0\n exec-timeout 0 0\nline vty 0 4\n login local\nline vty 5 15\n access-class VTY-ACL in\n", StateDiffers,
			[]string{"= line con 0 > login authentication default", "+ line vty 0 4 > login local", "- line vty 0 15 > login authentication default"}},
		{"one range explicit default, the other implicit", "line con 0\n login authentication default\nline vty 0 4\n login authentication default\nline vty 5 15\n exec-timeout 5 0\n", StateOK,
			[]string{"= line con 0 > login authentication default", "= line vty 0 15 > login authentication default"}},
		{"one range explicit default, the other local", "line con 0\n login authentication default\nline vty 0 4\n login authentication default\nline vty 5 15\n login local\n", StateDiffers,
			[]string{"= line con 0 > login authentication default", "+ line vty 5 15 > login local", "- line vty 0 15 > login authentication default"}},
		{"the console explicit local, the lines implicit", "line con 0\n login local\nline vty 0 15\n transport input ssh\n", StateDiffers,
			[]string{"+ line con 0 > login local", "- line con 0 > login authentication default", "= line vty 0 15 > login authentication default"}},
		{"another list", "line con 0\n login authentication default\nline vty 0 15\n login authentication OTHER\n", StateDiffers,
			[]string{"= line con 0 > login authentication default", "+ line vty 0 15 > login authentication OTHER",
				"- line vty 0 15 > login authentication default"}},
		{"no login", "line con 0\n login authentication default\nline vty 0 15\n no login\n", StateDiffers,
			[]string{"= line con 0 > login authentication default", "+ line vty 0 15 > no login",
				"- line vty 0 15 > login authentication default"}},
		{"plain login", "line con 0\n login authentication default\nline vty 0 15\n login\n", StateDiffers,
			[]string{"= line con 0 > login authentication default", "+ line vty 0 15 > login",
				"- line vty 0 15 > login authentication default"}},
		{"a vty range wider than the rendering", "line con 0\n login authentication default\nline vty 0 20\n login authentication default\n", StateDiffers,
			[]string{"= line con 0 > login authentication default", "+ line vty 0 20 > login authentication default",
				"- line vty 0 15 > login authentication default"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := head + tc.lines
			aaa, acl := loginExpected()
			for _, hinted := range []bool{true, false} {
				var hint []devices.Section
				if hinted {
					hint = []devices.Section{aaa, acl}
				}
				ex, err := Extract("ios", raw, hint...)
				if err != nil {
					t.Fatal(err)
				}
				r := resultOf(t, "ios", aaa, ex.Sections[SectionAAA], true)
				if r.State != tc.state {
					t.Errorf("hinted=%v: %s, want %s\n%v", hinted, r.State, tc.state, linesOf(r))
				}
				var got []string
				for _, l := range linesOf(r) {
					if strings.Contains(l, "line con") || strings.Contains(l, "line vty") {
						got = append(got, l)
					}
				}
				want := slices.Clone(tc.want)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("hinted=%v\n got  %q\n want %q", hinted, got, want)
				}
				// the leaves go to aaa and nowhere else
				for n, s := range ex.Sections {
					if n == SectionAAA {
						continue
					}
					for _, l := range s.Lines {
						if strings.Contains(l, "login") {
							t.Errorf("hinted=%v [%s] holds %q", hinted, n, l)
						}
					}
				}
			}
		})
	}
}

// The binding of an access class and the login method share the VTY
// headers; each goes to its own section.
func TestCiscoLoginLeavesAndAccessClassSplit(t *testing.T) {
	raw := "version 12.4\n" +
		"ip access-list standard VTY-ACL\n permit 192.0.2.10\n deny   any log\n" +
		"line con 0\n exec-timeout 0 0\n login authentication default\n" +
		"line aux 0\n login local\n" +
		"line vty 0 4\n access-class VTY-ACL in\n login local\n transport input ssh\n" +
		"line vty 5 15\n access-class VTY-ACL in\n login local\n transport input ssh\n"
	aaa, acl := loginExpected()
	for _, hint := range [][]devices.Section{{aaa, acl}, nil} {
		ex, err := Extract("ios", raw, hint...)
		if err != nil {
			t.Fatal(err)
		}
		wantAAA := []string{"line con 0 > login authentication default", "line vty 0 15 > login local", enableNone}
		if got := ex.Sections[SectionAAA].Lines; !slices.Equal(got, wantAAA) {
			t.Errorf("aaa = %q, want %q", got, wantAAA)
		}
		wantACL := []string{"ip access-list standard VTY-ACL > permit 192.0.2.10", "ip access-list standard VTY-ACL > deny any log",
			"line vty 0 15 > access-class VTY-ACL in"}
		if got := ex.Sections[SectionMgmtACL].Lines; !slices.Equal(got, wantACL) {
			t.Errorf("mgmt-acl = %q, want %q", got, wantACL)
		}
		// the mgmt-acl comparison does not see the leaves, and is ok
		if r := resultOf(t, "ios", acl, ex.Sections[SectionMgmtACL], true); r.State != StateOK {
			t.Errorf("mgmt-acl %s %v", r.State, linesOf(r))
		}
	}
}

// What the section holds is read back from the sections file the same.
func TestCiscoLoginAndEnableSurviveTheStore(t *testing.T) {
	raw := "version 12.4\nenable secret 5 $1$abcd$HASHHASHHASH\naaa new-model\nline vty 0 4\n login local\n"
	ex, err := Extract("ios", raw)
	if err != nil {
		t.Fatal(err)
	}
	s := newStore(t)
	if err := s.SaveSections("r1", "cisco", ex.Sections); err != nil {
		t.Fatal(err)
	}
	back, err := s.Sections("r1", "cisco")
	if err != nil {
		t.Fatal(err)
	}
	got := back[SectionAAA]
	if want := []string{"aaa new-model", "line vty 0 4 > login local", enableHeld}; !slices.Equal(got.Lines, want) {
		t.Errorf("stored aaa = %q, want %q", got.Lines, want)
	}
	data, _ := os.ReadFile(filepath.Join(s.Dir, "r1.yaml"))
	for _, leak := range []string{"$1$", "HASHHASH"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("the sections file holds %q", leak)
		}
	}
	// compared again from the stored sections, the note and the lines are
	// what the pull showed
	aaa, _ := loginExpected()
	r1 := resultOf(t, "ios", aaa, ex.Sections[SectionAAA], true)
	r2 := resultOf(t, "ios", aaa, got, true)
	if !slices.Equal(linesOf(r1), linesOf(r2)) || !slices.Equal(r1.Notes, r2.Notes) || r1.State != r2.State {
		t.Errorf("pull %v %q\nstore %v %q", linesOf(r1), r1.Notes, linesOf(r2), r2.Notes)
	}
}

func TestCiscoEnableSecretPresence(t *testing.T) {
	const aaaOn = "version 12.4\naaa new-model\n"
	for _, tc := range []struct {
		name, text string
		held       bool
	}{
		{"secret type 9", aaaOn + "enable secret 9 $9$HASHHASHHASHHASH\n", true},
		{"secret clear", aaaOn + "enable secret sekrit-value\n", true},
		{"password", aaaOn + "enable password sekrit-value\n", true},
		{"password 7", aaaOn + "enable password 7 0822455D0A16\n", true},
		{"scrypt", aaaOn + "enable algorithm-type scrypt secret sekrit-value\n", true},
		{"level 15 stated", aaaOn + "enable secret level 15 5 $1$abcd$HASHHASH\n", true},
		{"a secret for level 5 only", aaaOn + "enable secret level 5 5 $1$abcd$HASHHASH\n", false},
		{"enable use-tacacs sets none", aaaOn + "enable use-tacacs\n", false},
		{"enable last-resort password sets none", aaaOn + "enable last-resort password\n", false},
		{"a password under a line is not enable's", aaaOn + "line vty 0 4\n password 7 0822455D0A16\n login\n", false},
		{"none", aaaOn + "hostname r1\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			aaa, _ := loginExpected()
			ex, err := Extract("ios", tc.text, aaa)
			if err != nil {
				t.Fatal(err)
			}
			got := ex.Sections[SectionAAA]
			want := enableNone
			if tc.held {
				want = enableHeld
			}
			if n := countOf(got.Lines, want); n != 1 || countOf(got.Lines, enableHeld)+countOf(got.Lines, enableNone) != 1 {
				t.Errorf("lines %q, want exactly %q", got.Lines, want)
			}
			// only a held secret is marked secret
			for i, l := range got.Lines {
				if got.Secret[i] != (l == enableHeld) {
					t.Errorf("%q secret=%v", l, got.Secret[i])
				}
			}
			r := resultOf(t, "ios", aaa, got, true)
			notes := 0
			for _, n := range r.Notes {
				if strings.Contains(n, "enable secret") {
					notes++
				}
			}
			if wantNotes := map[bool]int{true: 0, false: 1}[tc.held]; notes != wantNotes {
				t.Errorf("%d enable notes %q, want %d", notes, r.Notes, wantNotes)
			}
			// by presence only: no value anywhere
			var all strings.Builder
			all.WriteString(strings.Join(got.Lines, "\n") + strings.Join(r.Notes, "\n"))
			for _, l := range r.Lines {
				all.WriteString(l.Text + "\n")
			}
			for _, leak := range []string{"HASHHASH", "sekrit", "0822455D0A16", "$9$", "$1$"} {
				if strings.Contains(all.String(), leak) {
					t.Errorf("the result holds %q", leak)
				}
			}
			// an extraction without the hint is the same
			ex2, _ := Extract("ios", tc.text)
			if !slices.Equal(ex2.Sections[SectionAAA].Lines, got.Lines) {
				t.Errorf("unhinted %q", ex2.Sections[SectionAAA].Lines)
			}
		})
	}
}

func countOf(lines []string, s string) int {
	n := 0
	for _, l := range lines {
		if l == s {
			n++
		}
	}
	return n
}

// The note needs a rendered 'aaa new-model', and a record that does not
// say (a pull of 0.2.4) gets none.
func TestCiscoEnableNoteConditions(t *testing.T) {
	aaa, _ := loginExpected()
	noAAA := sec(SectionAAA, "line con 0", "  login authentication default")
	none := sec(SectionAAA, "aaa new-model", enableNone)
	none.Secret = []bool{false, false}
	held := sec(SectionAAA, "aaa new-model", enableHeld)
	held.Secret = []bool{false, true}
	unknown := sec(SectionAAA, "aaa new-model") // a 0.2.4 record
	count := func(r SectionResult) int {
		n := 0
		for _, s := range r.Notes {
			if strings.Contains(s, "no enable secret") {
				n++
			}
		}
		return n
	}
	for _, tc := range []struct {
		name     string
		exp, dev devices.Section
		want     int
	}{
		{"none, aaa new-model rendered", aaa, none, 1},
		{"none, no aaa new-model rendered", noAAA, none, 0},
		{"held", aaa, held, 0},
		{"not known (a record of 0.2.4)", aaa, unknown, 0},
	} {
		r := resultOf(t, "ios", tc.exp, tc.dev, true)
		if n := count(r); n != tc.want {
			t.Errorf("%s: %d notes %q, want %d", tc.name, n, r.Notes, tc.want)
		}
		// the marker is never a line of the comparison
		for _, l := range r.Lines {
			if strings.Contains(l.Text, "enable") {
				t.Errorf("%s: %q is in the lines", tc.name, l.Text)
			}
		}
	}
	// a second comparison does not add a second note
	r := resultOf(t, "ios", aaa, none, true)
	if r2 := resultOf(t, "ios", aaa, none, true); count(r2) != count(r) {
		t.Error("the note is not stable")
	}
	// the Junos side has no marker and no note
	if r := resultOf(t, "junos", sec(SectionAAA, "set system host-name a"), sec(SectionAAA, "set system host-name a"), true); len(r.Notes) != 0 {
		t.Errorf("%q", r.Notes)
	}
}

// A device with only 'login local' on its lines and nothing of AAA has no
// AAA section on it, the leaves listed all the same; one that has AAA lines
// beside them differs.
func TestCiscoLoginOnlyIsMissing(t *testing.T) {
	aaa, _ := loginExpected()
	only := sec(SectionAAA, "line vty 0 4 > login local")
	if r := resultOf(t, "ios", aaa, only, true); r.State != StateMissing || !hasLine(r, OpExtra, "line vty 0 4 > login local") {
		t.Errorf("%s %v", r.State, linesOf(r))
	}
	both := sec(SectionAAA, "line vty 0 4 > login local", "aaa new-model")
	if r := resultOf(t, "ios", aaa, both, true); r.State != StateDiffers {
		t.Errorf("%s", r.State)
	}
}

// The real capture: AAA on, no login statement on any line, no 'enable'
// secret. The login lines are satisfied (the default list is in force),
// nothing of aaa differs, and the note about the secret is there once.
func TestCiscoLoginRealCapture(t *testing.T) {
	expected := expectedSections(t, "ios/real-12.4-7200/expected.txt")
	ex, err := Extract("ios", capture(t, "ios/real-12.4-7200/running-config.txt"), expected...)
	if err != nil {
		t.Fatal(err)
	}
	var aaa devices.Section
	for _, s := range expected {
		if s.Name == SectionAAA {
			aaa = s
		}
	}
	r := resultOf(t, "ios", aaa, ex.Sections[SectionAAA], true)
	// The capture is a device configured before the standard block: it has
	// neither the CONSOLE list nor the enable list, and its console is on the
	// default list without saying so (D107: the console is never implicit,
	// the default list is not the CONSOLE list), while the vty lines on the
	// default list are what the standard has.
	if r.State != StateDiffers {
		t.Errorf("%s %v", r.State, linesOf(r))
	}
	for _, l := range []string{
		"- aaa authentication login CONSOLE local",
		"- aaa authentication enable default group LAB-TACACS enable",
		"- line con 0 > login authentication CONSOLE",
		"+ line con 0 > login authentication default",
		"= line vty 0 15 > login authentication default",
		"= aaa session-id common",
	} {
		if !slices.Contains(linesOf(r), l) {
			t.Errorf("no %q in %v", l, linesOf(r))
		}
	}
	if len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "no enable secret") {
		t.Errorf("notes %q", r.Notes)
	}
	// what the pull stores says the same
	got := ex.Sections[SectionAAA].Lines
	for _, w := range []string{"line con 0 > login authentication default", "line vty 0 15 > login authentication default", enableNone} {
		if !slices.Contains(got, w) {
			t.Errorf("the extraction lacks %q: %q", w, got)
		}
	}
}

// With no 'aaa new-model' a line without a login statement has no method:
// nothing is read for it, the rendered line is missing, and the section is
// missing (nothing of AAA is on the device).
func TestCiscoLoginWithoutNewModel(t *testing.T) {
	raw := "version 12.4\nline con 0\n exec-timeout 0 0\nline vty 0 4\n transport input ssh\nline vty 5 15\n login local\n"
	aaa, _ := loginExpected()
	ex, err := Extract("ios", raw, aaa)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := ex.Sections[SectionAAA].Lines, []string{"line vty 5 15 > login local", enableNone}; !slices.Equal(got, want) {
		t.Errorf("aaa = %q, want %q", got, want)
	}
	r := resultOf(t, "ios", aaa, ex.Sections[SectionAAA], true)
	for _, l := range []string{"- line con 0 > login authentication default", "- line vty 0 15 > login authentication default",
		"+ line vty 5 15 > login local"} {
		if !slices.Contains(linesOf(r), l) {
			t.Errorf("no %q in %v", l, linesOf(r))
		}
	}
	if r.State != StateMissing {
		t.Errorf("state %s", r.State)
	}
}

// The implicit state survives the sections file, so a comparison from the
// stored record decides as the pull did; a record without the leaves and
// without the marker (an older tacctl) is not compared on them.
func TestCiscoLoginImplicitSurvivesTheStore(t *testing.T) {
	raw := "version 12.4\naaa new-model\naaa authentication login default local group G\nline con 0\n exec-timeout 0 0\n" +
		"line vty 0 4\n access-class VTY-ACL in\nline vty 5 15\n login local\n"
	aaa, _ := loginExpected()
	ex, err := Extract("ios", raw)
	if err != nil {
		t.Fatal(err)
	}
	s := newStore(t)
	if err := s.SaveSections("r1", "cisco", ex.Sections); err != nil {
		t.Fatal(err)
	}
	back, err := s.Sections("r1", "cisco")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aaa new-model", "aaa authentication login default local group G",
		"line vty 5 15 > login local", "line con 0 > login authentication default", "line vty 0 4 > login authentication default", enableNone}
	if got := back[SectionAAA].Lines; !slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))) {
		t.Errorf("stored aaa = %q, want %q", got, want)
	}
	r1 := resultOf(t, "ios", aaa, ex.Sections[SectionAAA], true)
	r2 := resultOf(t, "ios", aaa, back[SectionAAA], true)
	if !slices.Equal(linesOf(r1), linesOf(r2)) || r1.State != r2.State || r1.State != StateDiffers {
		t.Errorf("pull %s %v\nstore %s %v", r1.State, linesOf(r1), r2.State, linesOf(r2))
	}
	for _, l := range []string{"= line con 0 > login authentication default", "+ line vty 5 15 > login local",
		"- line vty 0 15 > login authentication default"} {
		if !slices.Contains(linesOf(r2), l) {
			t.Errorf("no %q in %v", l, linesOf(r2))
		}
	}
	// an older record: the AAA lines and nothing about the lines or the secret
	old := sec(SectionAAA, "aaa new-model", "aaa authentication login default local group G")
	r := resultOf(t, "ios", aaa, old, true)
	for _, l := range linesOf(r) {
		if strings.Contains(l, "login authentication default") && strings.Contains(l, "line ") {
			t.Errorf("an older record is compared on %q", l)
		}
	}
	if r.State != StateOK || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "older tacctl") {
		t.Errorf("%s %q", r.State, r.Notes)
	}
	// an empty section is not an older record: the lines are missing
	if r := resultOf(t, "ios", aaa, sec(SectionAAA), true); r.State != StateMissing || len(r.Notes) != 0 {
		t.Errorf("%s %q", r.State, r.Notes)
	}
}

// D106: a rendered privilege line the device stores shortened stays
// missing ('equal' would hide a line that was removed and its parent left),
// with a note that says which line the device holds instead; a parent that
// another rendered line explains gets no note.
func TestCiscoTruncatedPrivilegeNote(t *testing.T) {
	const monitorNote = "privilege exec all level 7 monitor capture: not on the device, which holds 'privilege exec level 7 monitor' instead, " +
		"as an image that does not know 'capture' stores it; a device that lost the line looks the same, so it stays missing"
	for _, tc := range []struct {
		name     string
		exp, dev []string
		want     []string
		notes    []string
	}{
		{"the stored form of the 12.4 image",
			[]string{"privilege exec all level 7 monitor capture"},
			[]string{"privilege exec level 7 monitor"},
			[]string{"- privilege exec all level 7 monitor capture"},
			[]string{monitorNote}},
		{"the fixture's lines",
			[]string{"privilege exec all level 7 monitor capture", "privilege exec level 7 clear counters", "privilege exec level 7 clear mac address-table dynamic"},
			[]string{"privilege exec level 7 monitor", "privilege exec level 7 clear counters", "privilege exec level 7 clear"},
			[]string{"- privilege exec all level 7 monitor capture", "= privilege exec level 7 clear counters", "- privilege exec level 7 clear mac address-table dynamic"},
			[]string{monitorNote}},
		{"nothing stored",
			[]string{"privilege exec all level 7 monitor capture"},
			[]string{"privilege exec level 7 show"},
			[]string{"- privilege exec all level 7 monitor capture", "+ privilege exec level 7 show"},
			nil},
		{"the full line is there",
			[]string{"privilege exec all level 7 monitor capture"},
			[]string{"privilege exec all level 7 monitor capture", "privilege exec level 7 monitor"},
			[]string{"= privilege exec all level 7 monitor capture"},
			nil},
		{"an 'all' on the device covers more",
			[]string{"privilege exec all level 7 monitor capture"},
			[]string{"privilege exec all level 7 monitor"},
			[]string{"- privilege exec all level 7 monitor capture", "+ privilege exec all level 7 monitor"},
			nil},
		{"another level",
			[]string{"privilege exec all level 7 monitor capture"},
			[]string{"privilege exec level 15 monitor"},
			[]string{"- privilege exec all level 7 monitor capture", "+ privilege exec level 15 monitor"},
			nil},
		{"the longest stored form is named",
			[]string{"privilege exec level 7 monitor capture start"},
			[]string{"privilege exec level 7 monitor", "privilege exec level 7 monitor capture"},
			[]string{"- privilege exec level 7 monitor capture start"},
			[]string{"privilege exec level 7 monitor capture start: not on the device, which holds 'privilege exec level 7 monitor capture' instead, " +
				"as an image that does not know 'start' stores it; a device that lost the line looks the same, so it stays missing"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := sec(SectionRoles, tc.exp...)
			raw := "version 12.4\n" + strings.Join(tc.dev, "\n") + "\n"
			ex, err := Extract("ios", raw, exp)
			if err != nil {
				t.Fatal(err)
			}
			r := resultOf(t, "ios", exp, ex.Sections[SectionRoles], true)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if got := linesOf(r); !slices.Equal(got, want) {
				t.Errorf("lines\n got  %q\n want %q", got, want)
			}
			if !slices.Equal(r.Notes, tc.notes) {
				t.Errorf("notes\n got  %q\n want %q", r.Notes, tc.notes)
			}
		})
	}
}
