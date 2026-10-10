package tier

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// The frozen text is the golden file copied from the 0.2.3 tag (and, where
// the tag is in the repository, that tag's own file).
func TestSudoers023IsTheTextOfTheTag(t *testing.T) {
	want, err := os.ReadFile("testdata/sudoers.tiers.0.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if got := Sudoers023(); got != string(want) {
		t.Errorf("Sudoers023 differs from testdata/sudoers.tiers.0.2.3:\n%s", got)
	}
	if got := Sudoers023(); got == Sudoers() {
		t.Error("the 0.2.3 text is this release's: nothing to roll back")
	}
	for _, gone := range []string{"TACCTL_ASKPASS", "device config pull", "device config diff", "device config list", "device snmp", "console forget"} {
		if strings.Contains(Sudoers023(), gone) {
			t.Errorf("the 0.2.3 text has %q", gone)
		}
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.3 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.3^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.3 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.3:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.3 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != Sudoers023() {
		t.Error("Sudoers023 differs from the golden file of the 0.2.3 tag")
	}
}

// The group drop-in of 0.2.3 is a text the 0.2.4 classifier calls older (so
// its upgrade replaces it), and not the current one.
func TestGroupSudoers023(t *testing.T) {
	text := GroupSudoers023("tac-admins")
	if g, kind := ClassifyGroupSudoers(text); g != "tac-admins" || kind != GroupOlder {
		t.Errorf("classified %q %v", g, kind)
	}
	if text == GroupSudoers("tac-admins") || strings.Contains(text, AskpassVar) {
		t.Errorf("the 0.2.3 group text is the current one:\n%s", text)
	}
}
