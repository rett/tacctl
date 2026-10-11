package devconf

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// A 15.x image and IOS-XE print, beside a command typed with 'all', the
// parent lines of its words ('privilege exec level 7 monitor' for
// 'privilege exec all level 7 monitor capture'), which carry no 'all': they
// are what IOS adds, not extra lines. The parent of a statement that is not
// rendered, of another level or mode, or one that has an 'all' itself, is.
func TestCiscoImplicitParentsOfAllChildren(t *testing.T) {
	typed := []string{
		"privilege exec level 1 show running-config",
		"privilege exec all level 7 ping",
		"privilege exec all level 7 monitor capture",
		"privilege exec level 7 clear counters",
	}
	parents := []string{
		"privilege exec level 7 monitor",
		"privilege exec level 7 clear",
		"privilege exec level 1 show",
	}
	allEqual := []string{
		"= privilege exec all level 7 monitor capture",
		"= privilege exec all level 7 ping",
		"= privilege exec level 1 show running-config",
		"= privilege exec level 7 clear counters",
	}
	const monitorCapture = "privilege exec all level 7 monitor capture"
	for _, tc := range []struct {
		name     string
		exp, dev []string
		want     []string
		state    State
	}{
		{"the implicit parents", typed, slices.Concat(typed, parents), allEqual, StateOK},
		{"the parents first", typed, slices.Concat(parents, typed), allEqual, StateOK},
		{"a longer typed form", []string{"privilege exec all level 7 monitor capture buffer"},
			[]string{"privilege exec all level 7 monitor capture buffer", "privilege exec level 7 monitor", "privilege exec level 7 monitor capture"},
			[]string{"= privilege exec all level 7 monitor capture buffer"}, StateOK},
		{"a parent nothing rendered explains", []string{"privilege exec all level 7 ping"},
			[]string{"privilege exec all level 7 ping", "privilege exec level 7 monitor"},
			[]string{"= privilege exec all level 7 ping", "+ privilege exec level 7 monitor"}, StateDiffers},
		{"another level", []string{monitorCapture},
			[]string{monitorCapture, "privilege exec level 5 monitor"},
			[]string{"= " + monitorCapture, "+ privilege exec level 5 monitor"}, StateDiffers},
		// the command's own default level is the image's, not an extra
		// (CHANGELOG 61)
		{"the command's default level", []string{monitorCapture},
			[]string{monitorCapture, "privilege exec level 15 monitor"},
			[]string{"= " + monitorCapture}, StateOK},
		{"another mode", []string{monitorCapture},
			[]string{monitorCapture, "privilege configure level 7 monitor"},
			[]string{"= " + monitorCapture, "+ privilege configure level 7 monitor"}, StateDiffers},
		{"the interface mode", []string{monitorCapture},
			[]string{monitorCapture, "privilege interface level 7 monitor"},
			[]string{"= " + monitorCapture, "+ privilege interface level 7 monitor"}, StateDiffers},
		{"an all of its own covers more", []string{monitorCapture},
			[]string{"privilege exec all level 7 monitor"},
			[]string{"- " + monitorCapture, "+ privilege exec all level 7 monitor"}, StateDiffers},
		{"another first word", []string{monitorCapture},
			[]string{monitorCapture, "privilege exec level 7 show"},
			[]string{"= " + monitorCapture, "+ privilege exec level 7 show"}, StateDiffers},
		{"the line without its all is not its parent", []string{monitorCapture},
			[]string{monitorCapture, "privilege exec level 7 monitor capture"},
			[]string{"= " + monitorCapture, "+ privilege exec level 7 monitor capture"}, StateDiffers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exp := sec(SectionRoles, tc.exp...)
			raw := "version 15.6\n" + strings.Join(tc.dev, "\n") + "\n"
			want := slices.Clone(tc.want)
			slices.Sort(want)
			check := func(what string, r SectionResult) {
				t.Helper()
				if got := linesOf(r); !slices.Equal(got, want) || r.State != tc.state {
					t.Errorf("%s: %s\n got  %q\n want %q (%s)", what, r.State, got, want, tc.state)
				}
			}
			for _, hinted := range []bool{true, false} {
				var hint []devices.Section
				if hinted {
					hint = []devices.Section{exp}
				}
				ex, err := Extract("ios", raw, hint...)
				if err != nil {
					t.Fatal(err)
				}
				check("pulled", resultOf(t, "ios", exp, ex.Sections[SectionRoles], true))
				// and as the store hands it back to 'device config diff'
				s := newStore(t)
				if err := s.SaveSections("r1", "cisco", ex.Sections); err != nil {
					t.Fatal(err)
				}
				back, err := s.Sections("r1", "cisco")
				if err != nil {
					t.Fatal(err)
				}
				check("stored", resultOf(t, "ios", exp, back[SectionRoles], true))
			}
		})
	}
}
