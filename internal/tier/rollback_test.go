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

// The texts 0.2.7 wrote (the env_keep line without the colour variables) are
// the current text with that line, are older ones to the upgrade, and are not
// the current text; where the 0.2.7 tag is in the repository, the per-tier
// text is that tag's golden file.
func TestSudoers027(t *testing.T) {
	old, cur := Sudoers027(), Sudoers()
	// 0.2.8's text with the old env_keep line and without 0.2.8's
	// 'version --long' item
	want := strings.Replace(strings.Replace(Sudoers028(), envKeep028, envKeep027, 1), ", "+Binary+" version --long", "", 1)
	if old == cur || want != old {
		t.Fatalf("Sudoers027 is not the current text with the old env_keep line:\n%s", old)
	}
	if strings.Contains(old, "NO_COLOR") || !strings.Contains(cur, "NO_COLOR TACCTL_COLOR") {
		t.Error("the colour variables are not what tells the two apart")
	}
	text := GroupSudoers027("tac-admins")
	if g, kind := ClassifyGroupSudoers(text); g != "tac-admins" || kind != GroupOlder {
		t.Errorf("classified %q %v", g, kind)
	}
	if strings.Contains(text, "NO_COLOR") || strings.Replace(GroupSudoers028("tac-admins"), envKeep028, envKeep027, 1) != text {
		t.Errorf("the 0.2.7 group text is not the current one with the old env_keep line:\n%s", text)
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.7 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.7^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.7 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.7:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.7 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != old {
		t.Error("Sudoers027 differs from the golden file of the 0.2.7 tag")
	}
}

// The texts 0.2.8 wrote are the current ones without the cache's lines of
// 'device config apply', 'device onboard' and 'device collect' (0.2.9,
// D141); the
// upgrade knows them as older ones, 'rollback 0.2.8' puts them back, and
// where the 0.2.8 tag is in the repository the per-tier text is that tag's
// golden file.
func TestSudoers028(t *testing.T) {
	old, cur := Sudoers028(), Sudoers()
	if old == cur {
		t.Fatal("Sudoers028 is the current text")
	}
	for _, v := range []string{"device config apply *", "device onboard *", "device collect *"} {
		if strings.Contains(old, v) || !strings.Contains(cur, v) {
			t.Errorf("%q: in the 0.2.8 text %v, in the current one %v", v, strings.Contains(old, v), strings.Contains(cur, v))
		}
	}
	// nothing but the cache's alias differs
	if strings.Replace(Sudoers0213(), askpassKeep0216(AskpassAlias), askpassKeep028(AskpassAlias), 1) != old {
		t.Errorf("Sudoers028 differs from the current text in more than the cache's alias:\n%s", old)
	}
	text := GroupSudoers028("tac-admins")
	if g, kind := ClassifyGroupSudoers(text); g != "tac-admins" || kind != GroupOlder {
		t.Errorf("classified %q %v", g, kind)
	}
	if strings.Contains(text, "device config apply") || !strings.Contains(text, "NO_COLOR TACCTL_COLOR") ||
		strings.Replace(GroupSudoers0216("tac-admins"), askpassKeep0216(AskpassGroupAlias), groupAskpass027, 1) != text {
		t.Errorf("the 0.2.8 group text is not the current one without the apply lines:\n%s", text)
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.8 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.8^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.8 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.8:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.8 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != old {
		t.Error("Sudoers028 differs from the golden file of the 0.2.8 tag")
	}
}

// The text 0.2.17 wrote is the current one with the old names of the verbs
// 0.2.18 renamed (D273 to D275) in place of the new ones; where
// the 0.2.17 tag is in the repository the text is that tag's golden file.
func TestSudoers0217(t *testing.T) {
	old, cur := Sudoers0217(), Sudoers()
	for _, c := range []struct{ was, is string }{
		{Binary + " device config-syntax *, ", Binary + " device ios-syntax *, "},
		{Binary + " device notices, " + Binary + " device notices *, ", Binary + " device notice list, " + Binary + " device notice list *, "},
		{Binary + " device ssh-config, ", Binary + " device client-config, "},
	} {
		if old == cur || !strings.Contains(old, c.was) || strings.Contains(old, c.is) || strings.Contains(cur, c.was) || !strings.Contains(cur, c.is) {
			t.Errorf("Sudoers0217 is not the current text with %q for %q:\n%s", c.was, c.is, old)
		}
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.17 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.17^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.17 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.17:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.17 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != old {
		t.Error("Sudoers0217 differs from the golden file of the 0.2.17 tag")
	}
}

// The texts 0.2.9 to 0.2.16 carried the cache's alias without 'device enroll'
// (0.2.17 D269): the per-tier text of 0.2.16 is the current one with that
// alias, the upgrade knows both drop-ins as older ones, 'rollback 0.2.3'
// puts 0.2.3's back over them, and where the 0.2.16 tag is in the repository
// the per-tier text is that tag's golden file.
func TestSudoers0216(t *testing.T) {
	old, cur := Sudoers0216(), Sudoers()
	if old == cur || strings.Contains(old, "device enroll *") || !strings.Contains(cur, Binary+" device enroll *\n") {
		t.Fatalf("Sudoers0216 is not the current text without 'device enroll':\n%s", old)
	}
	text := GroupSudoers0216("tac-admins")
	if g, kind := ClassifyGroupSudoers(text); g != "tac-admins" || kind != GroupOlder {
		t.Errorf("classified %q %v", g, kind)
	}
	if strings.Contains(text, "device enroll") || !strings.Contains(text, "device collect *\n") {
		t.Errorf("the 0.2.16 group text:\n%s", text)
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.16 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.16^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.16 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.16:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.16 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != old {
		t.Error("Sudoers0216 differs from the golden file of the 0.2.16 tag")
	}
}

// The text 0.2.14 wrote is the current one without the operator's
// 'config validate --json' item (0.2.15); the rollback knows it as an older
// one.
func TestSudoers0214(t *testing.T) {
	old, cur := Sudoers0214(), Sudoers()
	if old == cur || strings.Contains(old, "config validate --json") || !strings.Contains(cur, "config validate --json") {
		t.Fatalf("Sudoers0214 is not the current text without 'config validate --json':\n%s", old)
	}
	if !strings.Contains(old, Binary+" config validate,") || !strings.Contains(cur, Binary+" config validate, "+Binary+" config validate --json,") {
		t.Error("the operator's 'config validate' item is not what is added to")
	}
	if !strings.Contains(old, "host list --json") {
		t.Error("Sudoers0214 lacks the engineer's 'host list --json' item that 0.2.14 added")
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.14 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.14^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.14 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.14:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.14 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != old {
		t.Error("Sudoers0214 differs from the golden file of the 0.2.14 tag")
	}
}

// The texts 0.2.9 to 0.2.13 wrote are 0.2.14's without the engineer's
// 'host list --json' item; the rollback knows them as an older one.
func TestSudoers0213(t *testing.T) {
	old, cur := Sudoers0213(), Sudoers0214()
	if old == cur || strings.Contains(old, "host list --json") || !strings.Contains(cur, "host list --json") {
		t.Fatalf("Sudoers0213 is not 0.2.14's text without 'host list --json':\n%s", old)
	}
	if !strings.Contains(old, Binary+" host list,") || !strings.Contains(cur, Binary+" host list, "+Binary+" host list --json,") {
		t.Error("the engineer's 'host list' item is not what is added to")
	}
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.13 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.13^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.13 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.13:internal/tier/testdata/sudoers.tiers"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.13 tag's golden file: %v %s", err, res.Stderr)
	}
	if string(res.Stdout) != old {
		t.Error("Sudoers0213 differs from the golden file of the 0.2.13 tag")
	}
}
