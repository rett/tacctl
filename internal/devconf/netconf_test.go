package devconf

import (
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// The NETCONF service section (D145, D146 of docs/plans/0.2.10-plan.md).

func nsec(lines ...string) devices.Section {
	return devices.Section{Name: SectionNetconf, Lines: lines, Secret: make([]bool, len(lines))}
}

func TestCompareAbsentNetconf(t *testing.T) {
	absent := devices.Section{Name: SectionNetconf, Absent: true}
	res, err := Compare(FamilyJunos, absent, nsec("set system services netconf ssh", "set system services netconf ssh rate-limit 4"), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateDiffers || len(res.Lines) != 2 {
		t.Fatalf("a service that is there: %+v", res)
	}
	for _, l := range res.Lines {
		if l.Op != OpExtra || l.Unmanaged {
			t.Errorf("%q is not an extra that counts: %+v", l.Text, l)
		}
	}
	res, err = Compare(FamilyJunos, absent, nsec(), true)
	if err != nil || res.State != StateOK || len(res.Lines) != 0 {
		t.Errorf("a service that is not there: %+v %v", res, err)
	}
}

func TestCompareEnabledNetconf(t *testing.T) {
	for name, tc := range map[string]struct {
		exp, dev  []string
		state     State
		unmanaged int
		ops       string
	}{
		"bare, as rendered": {[]string{"set system services netconf ssh"}, []string{"set system services netconf ssh"}, StateOK, 0, "="},
		"bare, missing":     {[]string{"set system services netconf ssh"}, nil, StateMissing, 0, "-"},
		// the device prints only the child, never a bare 'ssh'
		"a child satisfies the bare statement": {[]string{"set system services netconf ssh"},
			[]string{"set system services netconf ssh connection-limit 3"}, StateOK, 1, "=+"},
		"the device's own beside it": {[]string{"set system services netconf ssh"},
			[]string{"set system services netconf ssh", "set system services netconf traceoptions flag all"}, StateOK, 1, "=+"},
		"a limit as rendered": {[]string{"set system services netconf ssh connection-limit 5"},
			[]string{"set system services netconf ssh connection-limit 5"}, StateOK, 0, "="},
		"a limit of another value": {[]string{"set system services netconf ssh connection-limit 5"},
			[]string{"set system services netconf ssh connection-limit 9"}, StateDiffers, 0, "-+"},
		"a limit the setting does not state": {[]string{"set system services netconf ssh rate-limit 4"},
			[]string{"set system services netconf ssh rate-limit 4", "set system services netconf ssh connection-limit 9"}, StateOK, 1, "=+"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := Compare(FamilyJunos, nsec(tc.exp...), nsec(tc.dev...), true)
			if err != nil {
				t.Fatal(err)
			}
			var ops string
			for _, l := range res.Lines {
				ops += string(l.Op)
			}
			if res.State != tc.state || res.Unmanaged != tc.unmanaged || ops != tc.ops {
				t.Errorf("state %s unmanaged %d ops %q, want %s %d %q: %+v", res.State, res.Unmanaged, ops, tc.state, tc.unmanaged, tc.ops, res.Lines)
			}
		})
	}
}

// A scope that leaves the service alone compares nothing: the section is
// n/a and the device's statements are information, as in 0.2.9.
func TestCompareLeftAloneNetconf(t *testing.T) {
	res, err := Compare(FamilyJunos, devices.Section{Name: SectionNetconf}, nsec("set system services netconf ssh"), true)
	if err != nil || res.State != StateNA || len(res.Lines) != 1 || res.Lines[0].Op != OpInfo {
		t.Errorf("%+v %v", res, err)
	}
}
