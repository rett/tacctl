package console

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// A console.yaml as 0.2.4 writes it with every setting changed, the password
// cache's included (spaceOff: space completion off, which 0.2.3 writes).
func rollbackFixture(t *testing.T, spaceOff bool) []byte {
	t.Helper()
	f := Defaults()
	f.Idle = 12
	f.AgentForwarding = true
	f.TierOn[tier.Readonly] = false
	f.Users["jdoe"] = true
	f.Users["asmith"] = false
	f.SystemShellTiers = []tier.Tier{tier.Operator, tier.Superuser}
	f.ListMax = 25
	f.SpaceCompletion = !spaceOff
	f.PasswordCacheTiers = []tier.Tier{tier.Engineer, tier.Superuser}
	f.PasswordCacheIdle, f.PasswordCacheMax = 30, 4
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// The file written for 0.2.3 is accepted by the fixture of 0.2.3's parser
// (accepts023, console_test.go), keeps every other setting (the engineer
// tier's switch and space completion included, which are 0.2.3's own), and
// 0.2.4 reads it as it read the file it came from but for the cache, which is
// off again.
func TestRollbackTextIsReadBy023(t *testing.T) {
	for _, off := range []bool{false, true} {
		dir := t.TempDir()
		orig := rollbackFixture(t, off)
		p := write(t, dir, "console.yaml", string(orig), 0o600)
		if err := accepts023(orig); err == nil {
			t.Fatalf("off=%v: the fixture of 0.2.4's file is accepted by the 0.2.3 parser", off)
		}
		plan, err := PlanRollback(p)
		if err != nil {
			t.Fatal(err)
		}
		wantRemove := []string{"settings.password_cache: tiers engineer,superuser, idle 30 min, max 4 h"}
		if !plan.Exists || plan.Text == nil || !reflect.DeepEqual(plan.Remove, wantRemove) {
			t.Fatalf("off=%v: plan %+v, want remove %q", off, plan, wantRemove)
		}
		if err := accepts023(plan.Text); err != nil {
			t.Errorf("off=%v: 0.2.3 rejects the converted file: %v\n%s", off, err, plan.Text)
		}
		if strings.Contains(string(plan.Text), "password_cache") {
			t.Errorf("off=%v: the key is left:\n%s", off, plan.Text)
		}
		for _, keep := range []string{"idle_timeout: 12", "agent_forwarding: true", "readonly: disable", "jdoe: enable", "asmith: disable",
			"system_shell_tiers", "list_max: 25", "version: 1", "superuser: enable", "operator: enable", "engineer: enable"} {
			if !strings.Contains(string(plan.Text), keep) {
				t.Errorf("off=%v: %q is gone:\n%s", off, keep, plan.Text)
			}
		}
		if got := strings.Contains(string(plan.Text), "space_completion: false"); got != off {
			t.Errorf("off=%v: space_completion written: %v\n%s", off, got, plan.Text)
		}
		if _, err := os.Stat(p + ".tmp"); err == nil {
			t.Error("a temporary file was left")
		}
		changed, err := Rollback(p, nil)
		if err != nil || !changed {
			t.Fatalf("off=%v: Rollback: %v %v", off, changed, err)
		}
		got, _ := os.ReadFile(p)
		if string(got) != string(plan.Text) {
			t.Errorf("off=%v: the file is not the planned text:\n%s", off, got)
		}
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("mode %v %v", fi, err)
		}
		f, err := Load(p)
		if err != nil {
			t.Fatal(err)
		}
		if f.Idle != 12 || !f.AgentForwarding || f.TierOn[tier.Readonly] || !f.TierOn[tier.Engineer] || f.SpaceCompletion != !off ||
			f.Users["jdoe"] != true || f.Users["asmith"] != false || f.ListMax != 25 ||
			!reflect.DeepEqual(f.SystemShellTiers, []tier.Tier{tier.Operator, tier.Superuser}) ||
			len(f.PasswordCacheTiers) != 0 || f.PasswordCacheIdle != DefaultPasswordCacheIdle || f.PasswordCacheMax != DefaultPasswordCacheMax {
			t.Errorf("off=%v: read back: %+v", off, f)
		}
		// Idempotent: the converted file needs nothing, and is not rewritten.
		if again, err := Rollback(p, func() error { return errors.New("no snapshot is needed") }); err == nil || again {
			// before runs first by contract: its error stops the write.
			t.Errorf("off=%v: before was not run: %v %v", off, again, err)
		}
		plan2, err := PlanRollback(p)
		if err != nil || plan2.Text != nil || len(plan2.Remove) != 0 || !plan2.Exists {
			t.Errorf("off=%v: second plan %+v %v", off, plan2, err)
		}
		changed, err = Rollback(p, nil)
		if err != nil || changed {
			t.Errorf("off=%v: second Rollback: %v %v", off, changed, err)
		}
		if again, _ := os.ReadFile(p); string(again) != string(plan.Text) {
			t.Errorf("off=%v: the second run changed the file", off)
		}
	}
}

// A cache that only moved a lifetime (the tiers are none) is a key 0.2.3
// rejects as well.
func TestRollbackOfALifetimeOnly(t *testing.T) {
	dir := t.TempDir()
	f := Defaults()
	f.PasswordCacheMax = 12
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	p := write(t, dir, "console.yaml", string(text), 0o600)
	plan, err := PlanRollback(p)
	if err != nil || !reflect.DeepEqual(plan.Remove, []string{"settings.password_cache: tiers none, idle 15 min, max 12 h"}) {
		t.Fatalf("plan %+v %v", plan, err)
	}
	if err := accepts023(plan.Text); err != nil {
		t.Errorf("rejected: %v\n%s", err, plan.Text)
	}
}

// A file 0.2.3 wrote (or a partial one) has nothing to take out and is left
// alone, byte for byte; so is a missing file. The file the defaults write is
// one of them: the cache is written only when it is not the default.
func TestRollbackLeavesWhatIsAlreadyReadable(t *testing.T) {
	dir := t.TempDir()
	defaults, err := Defaults().Text()
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"partial.yaml":  "version: 1\nsettings: {idle_timeout: 5}\n",
		"old.yaml":      "# written by 0.2.3\nversion: 1\ntiers: {readonly: enable, operator: enable, engineer: enable, superuser: disable}\nusers: {}\nsettings: {space_completion: false}\n",
		"empty.yaml":    "",
		"defaults.yaml": string(defaults),
	} {
		p := write(t, dir, name, text, 0o600)
		plan, err := PlanRollback(p)
		if err != nil || plan.Text != nil || len(plan.Remove) != 0 {
			t.Errorf("%s: plan %+v %v", name, plan, err)
		}
		if changed, err := Rollback(p, nil); err != nil || changed {
			t.Errorf("%s: Rollback %v %v", name, changed, err)
		}
		if got, _ := os.ReadFile(p); string(got) != text {
			t.Errorf("%s was rewritten: %q", name, got)
		}
	}
	missing := filepath.Join(dir, "none", "console.yaml")
	plan, err := PlanRollback(missing)
	if err != nil || plan.Exists || plan.Text != nil {
		t.Errorf("missing: %+v %v", plan, err)
	}
	if changed, err := Rollback(missing, nil); err != nil || changed {
		t.Errorf("missing Rollback: %v %v", changed, err)
	}
}

// A file the tool cannot read is an error and stays as it is: the rollback
// refuses before it changes anything.
func TestRollbackRefusesAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	for name, text := range map[string]string{
		"yaml.yaml":    "a: [\n",
		"unknown.yaml": "version: 1\nfoo: 1\n",
		"tier.yaml":    "version: 1\ntiers: {root: enable}\n",
		"cache.yaml":   "version: 1\nsettings: {password_cache: {tiers: [readonly]}}\n",
	} {
		p := write(t, dir, name, text, 0o600)
		if _, err := PlanRollback(p); err == nil {
			t.Errorf("%s: no error", name)
		}
		if changed, err := Rollback(p, nil); err == nil || changed {
			t.Errorf("%s: Rollback %v %v", name, changed, err)
		}
		if got, _ := os.ReadFile(p); string(got) != text {
			t.Errorf("%s was rewritten", name)
		}
	}
	if _, err := PlanRollback(dir); err == nil {
		t.Error("a directory was planned")
	}
}

// before (the snapshot) runs before anything is written, and its error stops
// the write.
func TestRollbackSnapshotsFirst(t *testing.T) {
	dir := t.TempDir()
	orig := rollbackFixture(t, true)
	p := write(t, dir, "console.yaml", string(orig), 0o600)
	boom := errors.New("snapshot failed")
	if changed, err := Rollback(p, func() error { return boom }); !errors.Is(err, boom) || changed {
		t.Fatalf("Rollback: %v %v", changed, err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(orig) {
		t.Error("the file changed although the snapshot failed")
	}
	var order []string
	changed, err := Rollback(p, func() error {
		got, _ := os.ReadFile(p)
		order = append(order, "snapshot sees the original: "+map[bool]string{true: "yes", false: "no"}[string(got) == string(orig)])
		return nil
	})
	if err != nil || !changed || len(order) != 1 || !strings.HasSuffix(order[0], "yes") {
		t.Errorf("order %q %v %v", order, changed, err)
	}
}
