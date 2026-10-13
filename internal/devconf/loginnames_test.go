package devconf

import (
	"strings"
	"testing"
)

// A login user spelled differently in case is the same account for the section
// state, and a note keeps the difference in view.
func TestBreakGlassLoginNamesFoldCase(t *testing.T) {
	const bg = SectionBreakGlass
	junosExp := secrets(bg, []string{
		"set system login user NetEngineer class RW-CLASS authentication encrypted-password '<HASH>'",
	}, true)
	got := sec(bg,
		"set system login user netengineer class RW-CLASS",
		`set system login user netengineer authentication encrypted-password "$6$abc"`)
	r, err := Compare("junos", junosExp, got, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateOK || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "'netengineer' on the device is 'NetEngineer'") {
		t.Errorf("junos case-only: state %v notes %q lines %q", r.State, r.Notes, ops(r))
	}

	// the exact spelling needs no note
	exact := sec(bg,
		"set system login user NetEngineer class RW-CLASS",
		`set system login user NetEngineer authentication encrypted-password "$6$abc"`)
	r, _ = Compare("junos", junosExp, exact, true)
	if r.State != StateOK || len(r.Notes) != 0 {
		t.Errorf("junos exact: state %v notes %q", r.State, r.Notes)
	}

	// another name is still missing and extra
	other := sec(bg,
		"set system login user someoneelse class RW-CLASS",
		`set system login user someoneelse authentication encrypted-password "$6$abc"`)
	r, _ = Compare("junos", junosExp, other, true)
	if r.State != StateDiffers || len(r.Notes) != 0 {
		t.Errorf("junos other name: state %v notes %q", r.State, r.Notes)
	}

	// both spellings on the device: the rendered one is satisfied, the other stays an extra
	both := sec(bg,
		"set system login user NetEngineer class RW-CLASS",
		`set system login user NetEngineer authentication encrypted-password "$6$abc"`,
		"set system login user netengineer class RW-CLASS",
		`set system login user netengineer authentication encrypted-password "$6$abc"`)
	r, _ = Compare("junos", junosExp, both, true)
	if r.State != StateDiffers || len(r.Notes) != 0 {
		t.Errorf("junos both spellings: state %v notes %q lines %q", r.State, r.Notes, ops(r))
	}

	// IOS usernames fold the same way
	iosExp := secrets(bg, []string{"username NetEngineer privilege 15 secret 9 <TYPE9-HASH>"}, true)
	iosGot := sec(bg, "username netengineer privilege 15 secret 9 $9$abcdef")
	r, err = Compare("ios", iosExp, iosGot, true)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateOK || len(r.Notes) != 1 {
		t.Errorf("ios case-only: state %v notes %q lines %q", r.State, r.Notes, ops(r))
	}
}
