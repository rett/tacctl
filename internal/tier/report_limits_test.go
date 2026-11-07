package tier

import (
	"context"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
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

// The rows of 'device reports' (0.2.26) are in no older text of the per-tier
// drop-in: 0.2.25's is this release's without them, and every older frozen
// text starts from it.
func TestWithoutReportRows(t *testing.T) {
	rs := []Rule{
		{Tier: Readonly, Cmd: "device", Sub: "list", Sudoers: []string{"device list"}},
		{Tier: Readonly, Cmd: "device", Sub: "reports", Sudoers: []string{"device reports list"}},
		{Tier: Engineer, Cmd: "device", Sub: "reports", Sudoers: []string{"device reports generate *"}},
		{Tier: Engineer, Cmd: "user", Sub: "reports", Sudoers: []string{"user reports"}},
		{Tier: Engineer, Cmd: "device", Sub: "config", Sudoers: []string{"device config pull *"}},
	}
	got := withoutReportRows(rs)
	if len(got) != 3 || got[0].Sub != "list" || got[1].Cmd != "user" || got[2].Sub != "config" {
		t.Errorf("rows left: %+v", got)
	}
	if len(rs) != 5 || rs[1].Sub != "reports" {
		t.Error("the input was changed")
	}
	if left := withoutReportRows(nil); len(left) != 0 {
		t.Errorf("nil gives %v", left)
	}
}

func TestSudoers0225HasNoReportRows(t *testing.T) {
	old, cur := Sudoers0225(), Sudoers()
	if strings.Contains(old, "device reports") {
		t.Error("the 0.2.25 text has a row of 'device reports'")
	}
	// while this release has no such row the two texts are one
	if !strings.Contains(cur, "device reports") && old != cur {
		t.Error("the 0.2.25 text differs from this release's with no report row to take out")
	}
	for name, text := range map[string]string{"0.2.23": Sudoers0223(), "0.2.22": Sudoers0222(), "0.2.19": Sudoers0219(), "0.2.18": Sudoers0218(),
		"0.2.17": Sudoers0217(), "0.2.16": Sudoers0216(), "0.2.14": Sudoers0214(), "0.2.13": Sudoers0213(), "0.2.8": Sudoers028(), "0.2.7": Sudoers027()} {
		if strings.Contains(text, "device reports") {
			t.Errorf("the %s text has a row of 'device reports'", name)
		}
	}
}

// Where the 0.2.25 tag is here, Sudoers0225 is that tag's own golden file.
func TestSudoers0225IsTheTextOfTheTag(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.25 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.25^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.25 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.25:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.25 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != Sudoers0225() {
		t.Error("Sudoers0225 differs from the golden file of the 0.2.25 tag")
	}
}

// This release's per-tier text is the one 0.2.26 wrote, which is why the
// rollback to 0.2.26 leaves the drop-in alone. A release that changes a rule
// makes this fail: it freezes the text of the release before it (as
// Sudoers0225 is) and gives the rollback to that release a step for the
// drop-in. Skipped where git or the tag is absent.
func TestSudoersIsTheTextOf0226(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.26 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.26^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.26 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.26:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.26 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != Sudoers() {
		t.Error("the per-tier text differs from the golden file of the 0.2.26 tag: freeze that text for the rollback to 0.2.26 (rollback0226.go leaves the drop-in alone only while they are the same)")
	}
}
