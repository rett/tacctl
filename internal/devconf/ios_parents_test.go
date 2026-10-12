package devconf

import (
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// A rendering with no 'privilege' line at all (a site whose privileges lists
// are empty, beside the other sections) leaves every privilege line of the
// device an extra, the parents IOS added included: the plan removes them
// with the commands, so a second plan is not needed. A text extracted with
// no rendering has nothing to judge by and drops the parents, as before.
func TestCiscoPrivilegeParentsWithNoRenderedPrivilege(t *testing.T) {
	raw := "version 12.4\naaa new-model\nprivilege exec level 7 clear\nprivilege exec level 7 clear counters\n"
	aaa := devices.Section{Name: SectionAAA, Lines: []string{"aaa new-model"}, Secret: []bool{false}}
	roles := devices.Section{Name: SectionRoles}
	ex, err := Extract("ios", raw, aaa, roles)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compare("ios", roles, ex.Sections[SectionRoles], true)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, l := range r.Lines {
		got = append(got, string(l.Op)+" "+l.Text)
	}
	slices.Sort(got)
	// '~': the section renders nothing, so the device's lines are listed
	// as they are, the parent beside the command
	want := []string{"~ privilege exec level 7 clear", "~ privilege exec level 7 clear counters"}
	if !slices.Equal(got, want) {
		t.Errorf("with a rendering: %q, want %q", got, want)
	}
	bare, err := Extract("ios", raw)
	if err != nil {
		t.Fatal(err)
	}
	if lines := bare.Sections[SectionRoles].Lines; len(lines) != 1 || lines[0] != "privilege exec level 7 clear counters" {
		t.Errorf("without a rendering: %q", lines)
	}
}
