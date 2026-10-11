package plan

// One test per row of the stored-forms table (D106): what the image adds or
// stores by itself is never typed as a 'no', and what it does not store is
// typed again every time. The extractor's comparison already drops the
// parents and the queue length before the planner sees them
// (devconf.Compare); the planner's own guard is tested directly as well.

import (
	"slices"
	"strings"
	"testing"
)

// rolesState is an iosState with the roles of a fixture's rendering.
func rolesState(t *testing.T, name string) *iosState {
	t.Helper()
	f := fixtureNamed(t, name)
	st := &iosState{entries: map[string][]iosEntry{}}
	for _, s := range expectedSections(t, f.expected) {
		st.entries[s.Name] = parseIOSExpected(s)
	}
	return st
}

// planWithRole plans a fixture against its rendering with one roles line
// more: a site's own 'privileges.operator' entry. No default lowers
// 'monitor capture' (the operator may not interrupt service, even
// briefly), but a site may, and the 12.4 image of the real capture stores
// it as 'privilege exec level 7 monitor'.
func planWithRole(t *testing.T, f fixture, line string) Delta {
	t.Helper()
	exp := expectedSections(t, f.expected)
	for i := range exp {
		if exp[i].Name == "roles" {
			exp[i].Lines = append(exp[i].Lines, line)
			exp[i].Secret = append(exp[i].Secret, false)
		}
	}
	return planText(t, f, exp, capture(t, f.raw), Options{})
}

var storedCases = map[string]rowCase{
	"ios.stored.parent": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			// only the parent is left of the level 7 undebug command
			c.noGlobal("privilege exec level 7 undebug all")
			c.typeGlobal("privilege exec level 7 undebug")
		}, Options{})
		noLine(t, d, "roles", "no privilege exec level 7 undebug")
		wantLine(t, d, "roles", "privilege exec level 7 undebug all")
		// the planner's own guard
		st := rolesState(t, "cisco.reference-lab")
		if st.isStoredFormOnly("privilege exec level 7 undebug") == "" || st.isStoredFormOnly("privilege exec level 1 show") == "" {
			t.Errorf("a parent is not recognised")
		}
		if st.isStoredFormOnly("privilege exec level 7 undebug all") != "" || st.isStoredFormOnly("privilege exec level 7 fuzz thing") != "" {
			t.Errorf("a rendered line or an unrelated line is taken for a parent")
		}
		// an 'all' on the device covers more than the rendering says
		if st.isStoredFormOnly("privilege exec all level 7 undebug") != "" {
			t.Errorf("a device 'all' line is taken for a parent")
		}
	},
	"ios.stored.queue-length": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server queue-length 100") }, Options{})
		noLine(t, d, "snmp", "queue-length")
		st := rolesState(t, "cisco.reference-lab")
		if st.isStoredFormOnly("snmp-server queue-length 100") == "" {
			t.Errorf("the queue length is not recognised")
		}
	},
	"ios.stored.chassis-id": func(t *testing.T) {
		// [S: lab IOSv 15.6(2)T] devconf's implicit-lines rule covers the
		// queue length only: the chassis id reaches the planner, which keeps it
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) { c.typeGlobal("snmp-server chassis-id") }, Options{})
		noLine(t, d, "snmp", "chassis-id")
		wantKept(t, d, "snmp", "snmp-server chassis-id")
		var note bool
		for _, k := range d.Kept {
			if k.Text == "snmp-server chassis-id" && strings.Contains(k.Note, "image") {
				note = true
			}
		}
		if !note {
			t.Errorf("no note on the chassis id: %+v", d.Kept)
		}
	},
	"ios.stored.ios15-privilege-default": func(t *testing.T) {
		// [S: lab IOSv 15.6(2)T] what a back-out leaves behind on 15.x: the
		// command's own default level. Never a 'no', listed as kept.
		f := fixtureNamed(t, "cisco.reference-lab")
		d := planI(t, f, func(c *IOSConfig) {
			for _, l := range []string{"privilege exec level 15 clear counters", "privilege exec level 15 undebug all",
				"privilege exec level 15 monitor capture", "privilege exec level 1 ping", "privilege exec level 1 traceroute",
				"privilege exec level 15 clear ip", "privilege exec level 1 show", "privilege exec level 1 undebug"} {
				c.typeGlobal(l)
			}
			// an operator's own line at a rendered level is not a residue
			c.typeGlobal("privilege exec level 7 fuzz thing")
		}, Options{})
		wantLine(t, d, "roles", "no privilege exec level 7 fuzz thing")
		for _, l := range []string{"privilege exec level 1 ping", "privilege exec level 1 traceroute", "privilege exec level 1 show",
			"privilege exec level 1 undebug", "privilege exec level 15 clear counters"} {
			noLine(t, d, "roles", "no "+l)
		}
		var notes int
		for _, k := range d.Kept {
			if strings.HasPrefix(k.Text, "privilege exec level ") && strings.Contains(k.Note, "default level") {
				notes++
			}
		}
		if notes == 0 {
			t.Errorf("the residue lines are not kept with a note: %+v", d.Kept)
		}
		st := rolesState(t, "cisco.reference-lab")
		for _, s := range []string{"privilege exec level 1 ping", "privilege exec level 15 clear counters", "privilege exec level 15 clear ip", "privilege exec level 1 show", "privilege exec level 1 undebug"} {
			if st.isStoredFormOnly(s) == "" {
				t.Errorf("%q is not taken for a residue", s)
			}
		}
		if st.isStoredFormOnly("privilege exec level 7 ping") != "" || st.isStoredFormOnly("privilege exec level 7 clear counters") != "" {
			t.Errorf("a line at another level is taken for a residue")
		}
		// the back-out says so once, after the privilege lines
		d2 := planI(t, fixtureNamed(t, "cisco.reference-bare"), nil, Options{})
		b, err := Backout(d2, fixtureNamed(t, "cisco.reference-bare").header(), Wrapper{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(b, "on IOS 15.x a removed privilege line may stay") != 1 {
			t.Errorf("the back-out does not carry the residue comment once:\n%s", b)
		}
	},
	"ios.stored.truncated": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.real-12.4-7200")
		d := planWithRole(t, f, "privilege exec all level 7 monitor capture")
		// the image stored 'privilege exec level 7 monitor': the rendered
		// 'all ... monitor capture' is typed, the stored prefix is no 'no'
		wantLine(t, d, "roles", "privilege exec all level 7 monitor capture")
		noLine(t, d, "roles", "no privilege exec level 7 monitor")
	},
	"ios.stored.not-stored": func(t *testing.T) {
		f := fixtureNamed(t, "cisco.real-12.4-7200")
		d := planWithRole(t, f, "privilege exec all level 7 monitor capture")
		// the 12.4 image stores no 'capture' (as 'privilege exec level 7
		// monitor'): the line it accepted and did not store is typed again
		wantLine(t, d, "roles", "privilege exec all level 7 monitor capture")
		if !strings.Contains(d.Of("roles").Why, "permanent '-'") {
			t.Errorf("the why-line does not say a permanent '-' is expected: %q", d.Of("roles").Why)
		}
	},
}

func TestStoredForms(t *testing.T) {
	for _, r := range IOSStoredForms() {
		c := storedCases[r.ID]
		if c == nil {
			t.Errorf("stored form %s has no case", r.ID)
			continue
		}
		t.Run(r.ID, c)
	}
	for id := range storedCases {
		if !slices.ContainsFunc(IOSStoredForms(), func(r IOSStoredForm) bool { return r.ID == id }) {
			t.Errorf("case %s names no row", id)
		}
	}
}
