package devconf

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// An IOS 15.x or IOS-XE image keeps 'privilege exec level <default> <cmd>'
// where a privilege line was removed (the lab IOSv 15.6(2)T and CSR1000v
// 16.7.1; CHANGELOG 61). The line is the image's own and harmless: it is no
// extra, whatever else is rendered, and a rendered line that is missing
// stays missing.
const residueFixture = "ios/ios15-privilege-residue/"

func TestCiscoPrivilegeResidueFixture(t *testing.T) {
	expected := expectedSections(t, residueFixture+"expected.txt")
	raw := capture(t, residueFixture+"running-config.txt")
	var roles devices.Section
	for _, s := range expected {
		if s.Name == SectionRoles {
			roles = s
		}
	}
	if len(roles.Lines) != 2 {
		t.Fatalf("the rendering of the fixture changed: %q", roles.Lines)
	}
	want := []string{"= privilege exec level 1 show running-config", "= privilege exec level 7 undebug all"}
	check := func(what string, r SectionResult) {
		t.Helper()
		if got := linesOf(r); !slices.Equal(got, want) || r.State != StateOK || len(r.Notes) != 0 {
			t.Errorf("%s: %s %q, notes %q, want ok %q", what, r.State, got, r.Notes, want)
		}
	}
	// pulled with the rendering, as 'device config pull' does
	ex, err := Extract("ios", raw, expected...)
	if err != nil {
		t.Fatal(err)
	}
	check("pulled", resultOf(t, "ios", roles, ex.Sections[SectionRoles], true))
	// a record an earlier tacctl made keeps the lines: the comparison
	// leaves them out too
	old := sec(SectionRoles)
	for _, l := range strings.Split(raw, "\n") {
		if strings.HasPrefix(l, "privilege ") {
			old.Lines = append(old.Lines, l)
		}
	}
	if len(old.Lines) != 13 {
		t.Fatalf("the fixture's privilege lines: %d", len(old.Lines))
	}
	check("an older record", resultOf(t, "ios", roles, old, true))
	// the whole report reads the roles section ok
	rs, err := CompareAll(expected, ex)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == SectionRoles && r.State != StateOK {
			t.Errorf("roles: %s", r.State)
		}
	}
	// what the stored view of the section holds: no residue
	for _, l := range ex.Sections[SectionRoles].Lines {
		if strings.Contains(l, "level 15") || strings.Contains(l, "level 1 ping") || strings.Contains(l, "level 1 clear") {
			t.Errorf("the extracted roles section holds the residue %q", l)
		}
	}
}

func TestCiscoPrivilegeResidueBoundaries(t *testing.T) {
	std := []string{"privilege exec level 1 show running-config", "privilege exec level 7 undebug all"}
	for _, tc := range []struct {
		name     string
		exp, dev []string
		want     []string
		state    State
	}{
		{"the defaults of the managed commands",
			std,
			slices.Concat(std, []string{
				"privilege exec level 15 clear counters", "privilege exec level 15 clear line", "privilege exec level 15 clear ip arp",
				"privilege exec level 15 clear ip", "privilege exec level 15 clear arp-cache", "privilege exec level 15 monitor capture",
				"privilege exec level 15 monitor", "privilege exec level 1 ping", "privilege exec level 1 traceroute",
				"privilege exec level 1 clear", "privilege exec level 1 show"}),
			[]string{"= " + std[0], "= " + std[1]}, StateOK},
		{"another level than the default is an extra",
			std,
			slices.Concat(std, []string{"privilege exec level 7 clear counters", "privilege exec level 5 ping", "privilege exec level 15 ping",
				"privilege exec level 1 clear counters", "privilege exec level 7 clear"}),
			[]string{"= " + std[0], "= " + std[1], "+ privilege exec level 7 clear counters", "+ privilege exec level 5 ping",
				"+ privilege exec level 15 ping", "+ privilege exec level 1 clear counters", "+ privilege exec level 7 clear"}, StateDiffers},
		{"a command that is not in the table is an extra at any level",
			std,
			slices.Concat(std, []string{"privilege exec level 15 debug", "privilege exec level 1 telnet", "privilege exec level 15 show ip route"}),
			[]string{"= " + std[0], "= " + std[1], "+ privilege exec level 15 debug", "+ privilege exec level 1 telnet",
				"+ privilege exec level 15 show ip route"}, StateDiffers},
		{"a rendered line that is missing stays missing",
			std,
			[]string{std[0], "privilege exec level 15 undebug", "privilege exec level 15 clear counters"},
			[]string{"= " + std[0], "- " + std[1]}, StateDiffers},
		{"the rendering has a line for the command: the device's other one is an extra",
			[]string{"privilege exec level 7 clear counters"},
			[]string{"privilege exec level 15 clear counters"},
			[]string{"- privilege exec level 7 clear counters", "+ privilege exec level 15 clear counters"}, StateDiffers},
		{"an all covers more than the default",
			std,
			slices.Concat(std, []string{"privilege exec all level 1 ping"}),
			[]string{"= " + std[0], "= " + std[1], "+ privilege exec all level 1 ping"}, StateDiffers},
		{"another mode is the operator's",
			std,
			slices.Concat(std, []string{"privilege configure level 15 monitor", "privilege interface level 1 ping"}),
			[]string{"= " + std[0], "= " + std[1], "+ privilege configure level 15 monitor", "+ privilege interface level 1 ping"}, StateDiffers},
		{"a parent of a rendered command at its default level",
			[]string{"privilege exec level 7 clear counters"},
			[]string{"privilege exec level 7 clear counters", "privilege exec level 7 clear", "privilege exec level 1 clear", "privilege exec level 15 clear ip"},
			[]string{"= privilege exec level 7 clear counters"}, StateOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := sec(SectionRoles, tc.exp...)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			// the comparison alone (a record that kept every line)
			r := resultOf(t, "ios", exp, sec(SectionRoles, tc.dev...), true)
			if got := linesOf(r); !slices.Equal(got, want) || r.State != tc.state {
				t.Errorf("compare: %s\n got  %q\n want %q (%s)", r.State, got, want, tc.state)
			}
			if len(r.Notes) != 0 {
				t.Errorf("compare: notes %q", r.Notes)
			}
			// and extracted with the rendering first
			ex, err := Extract("ios", "version 15.6\n"+strings.Join(tc.dev, "\n")+"\n", exp)
			if err != nil {
				t.Fatal(err)
			}
			r = resultOf(t, "ios", exp, ex.Sections[SectionRoles], true)
			if got := linesOf(r); !slices.Equal(got, want) || r.State != tc.state {
				t.Errorf("extract: %s\n got  %q\n want %q (%s)", r.State, got, want, tc.state)
			}
		})
	}
}

// A site that lowers nothing has no rendered privilege line: the residue is
// not listed beside the device's own lines, which still are.
func TestCiscoPrivilegeResidueWithNothingRendered(t *testing.T) {
	exp := sec(SectionRoles)
	r := resultOf(t, "ios", exp, sec(SectionRoles, "privilege exec level 15 clear counters", "privilege exec level 1 ping",
		"privilege exec level 7 fuzz thing"), true)
	if got, want := linesOf(r), []string{"~ privilege exec level 7 fuzz thing"}; !slices.Equal(got, want) {
		t.Errorf("%q, want %q", got, want)
	}
}

// IOSDefaultPrivilege is the one table: the commands of every shipped
// privilege list of the releases that lowered them are in it.
func TestIOSDefaultPrivilegeCoversTheShippedLists(t *testing.T) {
	for _, cmd := range []string{"ping", "traceroute", "monitor capture", "monitor", "clear counters", "clear line", "clear ip arp",
		"clear arp-cache", "clear mac address-table dynamic", "undebug all", "show running-config", "clear ip", "clear", "show"} {
		if _, ok := IOSDefaultPrivilege(cmd); !ok {
			t.Errorf("%q is not in the table", cmd)
		}
	}
	for _, cmd := range []string{"debug", "configure terminal", "show ip route", "reload"} {
		if _, ok := IOSDefaultPrivilege(cmd); ok {
			t.Errorf("%q is in the table", cmd)
		}
	}
}
