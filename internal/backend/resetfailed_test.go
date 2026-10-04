package backend_test

import (
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/backend"
)

// Plan 3.9 item 31: a systemctl command that starts units is preceded by
// 'systemctl reset-failed' of those units (plus what starts with them);
// every other command gets none.
func TestResetFailedArgs(t *testing.T) {
	inst := func(u string) []string {
		if u == "tacquito" {
			return []string{"tacquito@*.service"}
		}
		return nil
	}
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"restart", "tacquito"}, []string{"reset-failed", "tacquito", "tacquito@*.service"}},
		{[]string{"start", "freeradius.service"}, []string{"reset-failed", "freeradius.service"}},
		{[]string{"restart", "tacquito@mgmt.service"}, []string{"reset-failed", "tacquito@mgmt.service"}},
		{[]string{"enable", "--quiet", "--now", "tacquito@mgmt.service"}, []string{"reset-failed", "tacquito@mgmt.service"}},
		{[]string{"enable", "--quiet", "tacquito.service"}, nil},
		{[]string{"stop", "tacquito"}, nil},
		{[]string{"disable", "--quiet", "--now", "tacquito@old.service"}, nil},
		{[]string{"is-active", "--quiet", "tacquito"}, nil},
		{[]string{"daemon-reload"}, nil},
		{[]string{"restart"}, nil},
		{nil, nil},
	}
	for _, c := range cases {
		if got := backend.ResetFailedArgs(c.args, inst); !slices.Equal(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.args, got, c.want)
		}
	}
	if got := backend.ResetFailedArgs([]string{"restart", "tacquito"}, nil); !slices.Equal(got, []string{"reset-failed", "tacquito"}) {
		t.Errorf("no extra: %q", got)
	}
}
