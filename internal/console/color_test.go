package console

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// accepts0219 is the part of console.yaml's reader at 0.2.19 (the reader of
// this package before 0.2.20) that the settings of 0.2.20 meet: the settings
// keys it knows (no 'color') and the range of list_max (1 to 1000). Any
// other makes it fail, and the console falls back to the defaults.
func accepts0219(text []byte) error {
	v, err := pyyaml.LoadBytes(text)
	if err != nil {
		return err
	}
	settings, ok := v.(*yamlpy.Map).Get("settings")
	if !ok {
		return nil
	}
	known := []string{"idle_timeout", "list_max", "agent_forwarding", "ssh_escape", "gateway_ports", "space_completion",
		"system_shell", "system_shell_tiers", "forwarding_tiers", "password_cache"}
	for k, val := range settings.(*yamlpy.Map).All() {
		if !slices.Contains(known, k) {
			return errors.New("settings: unknown key '" + k + "'")
		}
		if n, isInt := val.(int); k == "list_max" && (!isInt || n < 1 || n > 1000) {
			return errors.New("settings.list_max must be 1-1000")
		}
	}
	return nil
}

// settings.color is written only when it is on or off, as true or false; a
// file without the key reads as auto, as the file that never chose does.
func TestColorSetting(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error { f.Idle = 5; return nil }); err != nil {
		t.Fatal(err)
	}
	auto, _ := os.ReadFile(p)
	if strings.Contains(string(auto), "color") {
		t.Errorf("the key is written while auto:\n%s", auto)
	}
	if f, err := Load(p); err != nil || f.Color != ColorAuto {
		t.Errorf("a file without the key: %+v %v", f, err)
	}
	for mode, want := range map[string]string{ColorOn: "  color: true\n", ColorOff: "  color: false\n"} {
		if _, err := Mutate(p, nil, func(f *File) error { f.Color = mode; return nil }); err != nil {
			t.Fatal(err)
		}
		got, _ := os.ReadFile(p)
		if string(got) != string(auto)+want {
			t.Errorf("%s:\n%s\nwant\n%s", mode, got, string(auto)+want)
		}
		f, err := Load(p)
		if err != nil || f.Color != mode || f.Idle != 5 {
			t.Errorf("%s round trip: %+v %v", mode, f, err)
		}
		if NewPolicy(f, paths.Paths{}).Color() != mode {
			t.Errorf("%s: the policy says %q", mode, NewPolicy(f, paths.Paths{}).Color())
		}
	}
	// Back to auto: the bytes are those of the file that never had the key.
	if _, err := Mutate(p, nil, func(f *File) error { f.Color = ColorAuto; return nil }); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(p); string(again) != string(auto) {
		t.Errorf("auto again:\n%s\nwant\n%s", again, auto)
	}
	q := write(t, dir, "bad.yaml", "version: 1\nsettings: {color: maybe}\n", 0o600)
	if _, err := Load(q); err == nil || !strings.Contains(err.Error(), "invalid value for 'color'") {
		t.Errorf("a non-boolean: %v", err)
	}
	f := Defaults()
	f.Color = "blue"
	if _, err := f.Text(); err == nil {
		t.Error("an unknown colour word is written")
	}
}

// settings.list_max is 1 to 1000, or -1: never ask.
func TestListMaxNever(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	for _, n := range []int{1, 40, 1000, ListMaxNever} {
		if _, err := Mutate(p, nil, func(f *File) error { f.ListMax = n; return nil }); err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if f, err := Load(p); err != nil || f.ListMax != n {
			t.Errorf("%d: %+v %v", n, f, err)
		}
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "list_max: -1\n") {
		t.Errorf("-1 is not written:\n%s", got)
	}
	for _, n := range []int{0, 1001, -2} {
		f := Defaults()
		f.ListMax = n
		if _, err := f.Text(); err == nil || !strings.Contains(err.Error(), "settings.list_max") {
			t.Errorf("%d is accepted: %v", n, err)
		}
	}
}

// What the rollback has to handle: a file with the colour setting or a
// list_max of -1 is rejected by the reader of 0.2.19 (and so by every older
// one), a file with neither is not, and the rollback writes the second from
// the first, keeping every other setting.
func TestRollbackSince0220(t *testing.T) {
	cases := []struct {
		name   string
		set    func(f *File)
		reject string // what 0.2.19 says of the file; "" accepts it
		remove []string
		sets   []string
	}{
		{"none set", func(*File) {}, "", nil, nil},
		{"color on", func(f *File) { f.Color = ColorOn }, "unknown key 'color'", []string{"settings.color: on"}, nil},
		{"color off", func(f *File) { f.Color = ColorOff }, "unknown key 'color'", []string{"settings.color: off"}, nil},
		{"never ask", func(f *File) { f.ListMax = ListMaxNever }, "list_max must be", nil, []string{"settings.list_max to 1000 (it never asked)"}},
		{"both", func(f *File) { f.Color, f.ListMax = ColorOn, ListMaxNever }, "settings", []string{"settings.color: on"}, []string{"settings.list_max to 1000 (it never asked)"}},
		{"system shell users", func(f *File) {
			f.SetSystemShellUser("carol", false, "")
			f.SetSystemShellUser("bob", true, tier.Operator)
		}, "unknown key 'system_shell_users'",
			[]string{"settings.system_shell_users: bob enable, carol disable"}, nil},
		{"password cache users", func(f *File) { f.PasswordCacheUsers = map[string]bool{"carol": true, "bob": true} }, "unknown key 'password_cache_users'",
			[]string{"settings.password_cache_users: bob, carol (on)"}, nil},
		{"all three", func(f *File) {
			f.Color, f.ListMax = ColorOff, ListMaxNever
			f.SetSystemShellUser("bob", true, tier.Operator)
		}, "settings", []string{"settings.color: off", "settings.system_shell_users: bob enable"}, []string{"settings.list_max to 1000 (it never asked)"}},
	}
	for _, c := range cases {
		dir := t.TempDir()
		f := Defaults()
		f.Idle = 12
		f.ListMax = 25
		f.SpaceCompletion = false
		f.PasswordCacheTiers = Tiers[2:3]
		f.PasswordCacheIdle, f.PasswordCacheMax = 30, 4
		c.set(f)
		text, err := f.Text()
		if err != nil {
			t.Fatal(err)
		}
		err = accepts0219(text)
		if (c.reject == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.reject)) {
			t.Errorf("%s: 0.2.19 says %v of\n%s", c.name, err, text)
		}
		p := write(t, dir, "console.yaml", string(text), 0o600)
		plan, err := PlanRollbackSince0220(p)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(plan.Remove, c.remove) || !slices.Equal(plan.Set, c.sets) {
			t.Errorf("%s: plan remove %q set %q, want %q %q", c.name, plan.Remove, plan.Set, c.remove, c.sets)
		}
		if c.reject == "" {
			if plan.Text != nil {
				t.Errorf("%s: a file that needs nothing is rewritten:\n%s", c.name, plan.Text)
			}
			continue
		}
		if err := accepts0219(plan.Text); err != nil {
			t.Errorf("%s: 0.2.19 rejects the converted file: %v\n%s", c.name, err, plan.Text)
		}
		for _, keep := range []string{"idle_timeout: 12", "space_completion: false", "password_cache:", "tiers: [engineer]", "list_max: "} {
			if !strings.Contains(string(plan.Text), keep) {
				t.Errorf("%s: %q is gone:\n%s", c.name, keep, plan.Text)
			}
		}
		if strings.Contains(string(plan.Text), "color") || strings.Contains(string(plan.Text), "system_shell_users") || strings.Contains(string(plan.Text), "password_cache_users") {
			t.Errorf("%s: a setting of 0.2.20 is left:\n%s", c.name, plan.Text)
		}
		if !strings.Contains(string(plan.Text), "system_shell_tiers: [superuser]") {
			t.Errorf("%s: the tiers' system-shell setting is gone:\n%s", c.name, plan.Text)
		}
		if c.sets != nil && !strings.Contains(string(plan.Text), "list_max: 1000\n") {
			t.Errorf("%s: list_max is not 1000:\n%s", c.name, plan.Text)
		}
		// Written under the lock, once: the second run changes nothing.
		changed, err := RollbackSince0220(p, nil)
		if err != nil || !changed {
			t.Errorf("%s: write: %v %v", c.name, changed, err)
		}
		if again, err := RollbackSince0220(p, nil); err != nil || again {
			t.Errorf("%s: again: %v %v", c.name, again, err)
		}
		if b, _ := os.ReadFile(p); string(b) != string(plan.Text) {
			t.Errorf("%s: the file is not the plan's text:\n%s", c.name, b)
		}
		if !strings.Contains(plan.Summary(), "removed") && !strings.Contains(plan.Summary(), "set settings.list_max") {
			t.Errorf("%s: summary %q", c.name, plan.Summary())
		}
	}
	// The rollback to 0.2.3 takes them out as well, with the cache's.
	f := Defaults()
	f.Color, f.ListMax = ColorOff, ListMaxNever
	f.SetSystemShellUser("bob", true, tier.Operator)
	f.PasswordCacheUsers = map[string]bool{"alice": true}
	f.PasswordCacheTiers = Tiers[3:]
	text, err := f.Text023()
	if err != nil {
		t.Fatal(err)
	}
	if err := accepts023(text); err != nil {
		t.Errorf("0.2.3 rejects its file: %v\n%s", err, text)
	}
	p := write(t, t.TempDir(), "console.yaml", func() string { b, _ := f.Text(); return string(b) }(), 0o600)
	plan, err := PlanRollback(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Remove) != 4 || len(plan.Set) != 1 || !strings.Contains(plan.Summary(), "settings.password_cache, settings.color, settings.system_shell_users, settings.password_cache_users") {
		t.Errorf("0.2.3 plan: %+v %q", plan, plan.Summary())
	}
}
