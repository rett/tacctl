package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// The root break-glass access is the person's step: a device that lacks the
// root password or the ssh root-login statement gets neither typed (they are
// on the never lists), and the report names the walkthrough's break-glass
// step, not an account.
func TestPlanNeverTypesRootAccess(t *testing.T) {
	f := fixtureNamed(t, "juniper.synthetic-lab")
	exp := slices.DeleteFunc(slices.Clone(expectedSections(t, f.expected)), func(s devices.Section) bool {
		return s.Name == devconf.SectionBreakGlass
	})
	exp = append(exp, devices.Section{Name: devconf.SectionBreakGlass,
		Lines:  []string{"set system root-authentication encrypted-password '<HASH>'", "set system services ssh root-login allow"},
		Secret: []bool{true, false}})
	// the device has neither: no password and no root-login statement
	text := strings.Join(slices.DeleteFunc(strings.Split(ParseJunos(capture(t, f.raw)).Text(), "\n"), func(l string) bool {
		return strings.Contains(l, "root-authentication") || strings.Contains(l, "root-login")
	}), "\n")
	d := planText(t, f, exp, text, Options{})
	if sp := d.Of(devconf.SectionBreakGlass); sp.State != StateNever {
		t.Errorf("the break-glass section: %+v", sp)
	}
	for _, l := range d.Lines {
		if strings.Contains(l.Text, "root-authentication") || strings.Contains(l.Text, "root-login") {
			t.Errorf("a planned line: %q", l.Text)
		}
	}
	if err := (Allow{Expected: exp}).CheckDelta(d); err != nil {
		t.Errorf("the delta is refused: %v", err)
	}
	// ... and nothing asks for them if a caller types them
	for _, s := range []string{"set system root-authentication encrypted-password x", "set system services ssh root-login allow"} {
		if err := (Allow{Expected: exp}).Check(s); err == nil {
			t.Errorf("%q is allowed", s)
		}
	}
	rep := strings.Join(strings.Fields(strings.ReplaceAll(Report(d, Header{}, Wrapper{}), "\n#", "\n")), " ")
	if !strings.Contains(rep, "Not planned: netconf, breakglass (walkthrough Steps 6 and 7).") &&
		!strings.Contains(rep, "Not planned: breakglass (walkthrough Step 7).") {
		t.Errorf("the report does not name the break-glass step:\n%s", rep)
	}
	for _, leak := range []string{"EXAMPLEHASH", "$6$", "<HASH>", "root-authentication"} {
		if strings.Contains(rep, leak) {
			t.Errorf("the report holds %q:\n%s", leak, rep)
		}
	}
}
