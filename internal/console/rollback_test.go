package console

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// A console.yaml as 0.2.4 writes it with every setting changed, the password
// cache's included (spaceOff: space completion off, which 0.2.3 writes).
func rollbackFixture(t *testing.T, spaceOff bool) []byte {
	t.Helper()
	f := Defaults()
	f.Idle = 12
	f.AgentForwarding = true
	f.IgnoredTiers = map[tier.Tier]bool{tier.Readonly: false, tier.Operator: true, tier.Engineer: true, tier.Superuser: true}
	f.IgnoredUsers["jdoe"] = true
	f.IgnoredUsers["asmith"] = false
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
		if f.Idle != 12 || !f.AgentForwarding || f.IgnoredTiers[tier.Readonly] || !f.IgnoredTiers[tier.Engineer] || f.SpaceCompletion != !off ||
			f.IgnoredUsers["jdoe"] != true || f.IgnoredUsers["asmith"] != false || f.ListMax != 25 ||
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

// accepts0227 is the part of 0.2.27's console.yaml parser that matters for a
// rollback to it, as a fixture (parse, parseSettings and parsePasswordCache of
// internal/console/config.go at the 0.2.27 tag, which
// TestTheFixtureOf0227IsThe0227Parser reads back): any key of its lists is
// known, any other
// makes it answer "settings: unknown key", and the console falls back to
// the defaults.
func accepts0227(text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	root := v.(*yamlpy.Map)
	for k := range root.All() {
		if !slices.Contains([]string{"version", "tiers", "users", "settings"}, k) {
			return errors.New("unknown key '" + k + "'")
		}
	}
	settings, ok := root.Get("settings")
	if !ok {
		return nil
	}
	for k, sv := range settings.(*yamlpy.Map).All() {
		switch k {
		case "idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion", "color",
			"system_shell", "system_shell_users", "password_cache_users", "system_shell_tiers", "forwarding_tiers":
		case "password_cache":
			for pk := range sv.(*yamlpy.Map).All() {
				if !slices.Contains([]string{"tiers", "idle", "max"}, pk) {
					return errors.New("settings.password_cache: unknown key '" + pk + "'")
				}
			}
		default:
			return errors.New("settings: unknown key '" + k + "'")
		}
	}
	return nil
}

// The fixture of 0.2.27's parser holds what the tag holds: its source reports
// an unknown settings key, has none of the file transfer keys and has every
// settings key the fixture lists. Skipped where git or the tag is absent.
func TestTheFixtureOf0227IsThe0227Parser(t *testing.T) {
	r := execx.Real{}
	if _, err := r.LookPath("git"); err != nil {
		t.Skip("git is not installed, so the 0.2.27 tag cannot be read")
	}
	if res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"rev-parse", "-q", "--verify", "0.2.27^{commit}"}}); err != nil || res.Code != 0 {
		t.Skip("the 0.2.27 tag is not in this repository (CI must fetch tags: git fetch --tags)")
	}
	res, err := r.Run(context.Background(), execx.Cmd{Name: "git", Args: []string{"show", "0.2.27:internal/console/config.go"}})
	if err != nil || res.Code != 0 {
		t.Fatalf("cannot read the 0.2.27 tag's config.go: %v %s", err, res.Stderr)
	}
	src := string(res.Stdout)
	for _, w := range []string{`fail("settings: unknown key '" + k + "'.")`, `fail("unknown key '" + k + "'.")`, `case "system_shell_users":`, `case "password_cache_users":`, `case "color"`} {
		if !strings.Contains(src, w) {
			t.Errorf("0.2.27's config.go lacks %q: the fixture accepts0227 is out of date", w)
		}
	}
	if strings.Contains(src, "file_transfer") {
		t.Error("0.2.27's config.go knows file_transfer: the rollback needs no step for it")
	}
	// the keys of the fixture are the cases of the tag's parseSettings
	for _, k := range []string{"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion", "color",
		"system_shell", "system_shell_users", "password_cache_users", "system_shell_tiers", "forwarding_tiers", "password_cache"} {
		if !strings.Contains(src, `"`+k+`"`) {
			t.Errorf("0.2.27's config.go has no key %q", k)
		}
	}
	// and the file this release writes with every setting is rejected by it
	if err := accepts0227(fileTransferFixture(t)); err == nil || !strings.Contains(err.Error(), "settings: unknown key 'file_transfer'") {
		t.Errorf("the fixture of 0.2.27 reads the file transfer settings: %v", err)
	}
}

// fileTransferFixture is a console.yaml of this release with the file
// transfer settings and every older setting changed.
func fileTransferFixture(t *testing.T) []byte {
	t.Helper()
	f := Defaults()
	f.Idle = 12
	f.AgentForwarding = true
	f.ListMax = ListMaxNever
	f.Color = ColorOn
	f.SpaceCompletion = false
	f.SystemShellTiers = []tier.Tier{tier.Operator, tier.Superuser}
	f.SetSystemShellUser("bob", true, tier.Readonly)
	f.PasswordCacheTiers = []tier.Tier{tier.Engineer, tier.Superuser}
	f.PasswordCacheIdle, f.PasswordCacheMax = 30, 4
	f.PasswordCacheUsers["carol"] = true
	if err := f.SetFileTransfer(tier.Operator, true); err != nil {
		t.Fatal(err)
	}
	f.SetFileTransferUser("bob", true, tier.Readonly)
	f.SetFileTransferQuota(tier.Operator, 1<<30, false)
	f.FileTransferRateUsers["carol"] = 1 << 20
	text, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

// The file written for 0.2.27 is accepted by the fixture of its parser, keeps
// every other setting (0.2.27 has them all: the colour, a list_max that never
// asks, the users' system shell, the password cache and its users), and is
// the file a plan for any older release also gives, as far as the file
// transfer goes.
func TestRollbackTextIsReadBy0227(t *testing.T) {
	orig := fileTransferFixture(t)
	if err := accepts0227(orig); err == nil {
		t.Fatal("the fixture of this release's file is accepted by the 0.2.27 parser")
	}
	p := write(t, t.TempDir(), "console.yaml", string(orig), 0o600)
	plan, err := PlanRollbackSince0228(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"settings.file_transfer: tiers operator,superuser, 1 user switch, 1 quota, 1 rate"}
	if !plan.Exists || plan.Text == nil || !reflect.DeepEqual(plan.Remove, want) || len(plan.Set) != 0 {
		t.Fatalf("plan %+v, want remove %q", plan, want)
	}
	if err := accepts0227(plan.Text); err != nil {
		t.Errorf("0.2.27 rejects the converted file: %v\n%s", err, plan.Text)
	}
	if plan.Summary() != "removed settings.file_transfer" {
		t.Errorf("summary %q", plan.Summary())
	}
	// every other setting is as it was, and this release reads the file with
	// the file transfer at its built-in settings
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	f.FileTransferTiers = Defaults().FileTransferTiers
	f.FileTransferUsers, f.FileTransferUserTiers = map[string]bool{}, map[string]tier.Tier{}
	f.FileTransferQuota, f.FileTransferRateUsers = map[tier.Tier]int64{}, map[string]int64{}
	wantText, err := f.Text()
	if err != nil {
		t.Fatal(err)
	}
	if string(plan.Text) != string(wantText) {
		t.Errorf("the converted file:\n%s\nwant:\n%s", plan.Text, wantText)
	}
	g, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if text, err := g.Text0227(); err != nil || string(text) != string(plan.Text) {
		t.Errorf("Text0227: %v\n%s", err, text)
	}
	changed, err := RollbackSince0228(p, nil)
	if err != nil || !changed {
		t.Fatalf("RollbackSince0228: %v %v", changed, err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(plan.Text) {
		t.Errorf("the file after the rollback:\n%s", got)
	}
	// done: nothing is left to take out, and a second run changes nothing
	if again, err := PlanRollbackSince0228(p); err != nil || again.Text != nil || len(again.Remove) != 0 {
		t.Errorf("second plan: %+v %v", again, err)
	}
	if changed, err := RollbackSince0228(p, nil); err != nil || changed {
		t.Errorf("second RollbackSince0228: %v %v", changed, err)
	}
	// the plans for the older releases take the key out as well, and the
	// other settings 0.2.27 reads go where they must: the colour and the
	// users' settings for the releases before 0.2.20, the password cache for
	// 0.2.3
	for _, c := range []struct {
		name string
		plan func(string) (RollbackPlan, error)
		gone []string
		kept []string
	}{
		{"0.2.19", PlanRollbackSince0220, []string{"file_transfer", "color:", "system_shell_users", "password_cache_users"}, []string{"password_cache:", "space_completion", "list_max: 1000"}},
		{"0.2.3", PlanRollback, []string{"file_transfer", "color:", "system_shell_users", "password_cache_users", "password_cache:"}, []string{"space_completion", "list_max: 1000"}},
	} {
		q := write(t, t.TempDir(), "console.yaml", string(orig), 0o600)
		pl, err := c.plan(q)
		if err != nil || pl.Text == nil {
			t.Fatalf("%s: %+v %v", c.name, pl, err)
		}
		if !slices.ContainsFunc(pl.Remove, func(r string) bool { return strings.HasPrefix(r, "settings.file_transfer: ") }) {
			t.Errorf("%s: the plan does not remove the file transfer: %q", c.name, pl.Remove)
		}
		for _, w := range c.gone {
			if strings.Contains(string(pl.Text), w) {
				t.Errorf("%s: the text keeps %q:\n%s", c.name, w, pl.Text)
			}
		}
		for _, w := range c.kept {
			if !strings.Contains(string(pl.Text), w) {
				t.Errorf("%s: the text lost %q:\n%s", c.name, w, pl.Text)
			}
		}
	}
	// a file without the key is not rewritten, and a missing one is no error
	plain, err := Defaults().Text()
	if err != nil {
		t.Fatal(err)
	}
	r := write(t, t.TempDir(), "console.yaml", string(plain), 0o600)
	if pl, err := PlanRollbackSince0228(r); err != nil || pl.Text != nil || len(pl.Remove) != 0 {
		t.Errorf("a file without the key: %+v %v", pl, err)
	}
	if pl, err := PlanRollbackSince0228(filepath.Join(t.TempDir(), "none.yaml")); err != nil || pl.Exists || pl.Text != nil {
		t.Errorf("a missing file: %+v %v", pl, err)
	}
	// a file this release cannot read refuses the plan
	bad := write(t, t.TempDir(), "console.yaml", "version: 1\nsettings: {file_transfer: {quota: {operator: 0}}}\n", 0o600)
	if _, err := PlanRollbackSince0228(bad); err == nil {
		t.Error("an unreadable file is planned")
	}
}
