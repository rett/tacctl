package tier

import (
	"strings"
	"testing"
)

// 'user reports-limit' and 'config reports' (0.2.26, D326) set the limits of
// the stored reports: they are the superuser's alone. They have no row, so no
// lower tier may run them and no sudoers rule names them.
func TestReportLimitVerbsAreTheSuperusersAlone(t *testing.T) {
	for _, v := range [][2]string{{"user", "reports-limit"}, {"config", "reports"}} {
		for _, lower := range []Tier{Readonly, Operator, Engineer} {
			if Permits(lower, v[0], v[1]) {
				t.Errorf("%s may run %s %s", lower, v[0], v[1])
			}
		}
		for _, top := range []Tier{Superuser, Unrestricted} {
			if !Permits(top, v[0], v[1]) {
				t.Errorf("%s may not run %s %s", top, v[0], v[1])
			}
		}
	}
	text := Sudoers()
	for _, not := range []string{"user reports-limit", "config reports"} {
		if strings.Contains(text, not) {
			t.Errorf("the per-tier sudoers names %q", not)
		}
	}
	// 'user show' stays open, so a user sees their own limit there
	if !Permits(Readonly, "user", "show") {
		t.Error("the readonly tier may not run user show")
	}
}
