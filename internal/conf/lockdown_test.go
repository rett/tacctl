package conf

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func lockdownConfig(t *testing.T, text string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	if text != "" {
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Load(p, DefaultBackends)
}

func TestUpdateLockdown(t *testing.T) {
	c := lockdownConfig(t, "")
	set := func(groups ...string) func(*Lockdown) (*Lockdown, error) {
		return func(cur *Lockdown) (*Lockdown, error) {
			l := Lockdown{Groups: groups, Since: "2026-10-25T12:00:00Z", By: "alice", Reason: "leak"}
			if cur != nil {
				l.Since = cur.Since
			}
			return &l, nil
		}
	}
	if err := c.UpdateLockdown("lab", set("operator", "readonly")); err != nil {
		t.Fatal(err)
	}
	got := c.Lockdowns()
	if len(got) != 1 || got[0].Scope != "lab" || !slices.Equal(got[0].Groups, []string{"operator", "readonly"}) || got[0].By != "alice" || got[0].Reason != "leak" {
		t.Fatalf("the record: %+v", got)
	}
	if lg := LockedGroups(c.Merged()); !slices.Equal(lg["lab"], []string{"operator", "readonly"}) || len(lg) != 1 {
		t.Errorf("locked groups: %v", lg)
	}
	// an empty reason is left out; a bad group is refused and nothing is written
	if err := c.UpdateLockdown("dmz", func(*Lockdown) (*Lockdown, error) {
		return &Lockdown{Groups: []string{"Bad Group"}, Since: "2026-10-25T12:00:00Z", By: "alice"}, nil
	}); err == nil || !strings.Contains(err.Error(), "not a group name") {
		t.Errorf("a bad group: %v", err)
	}
	if err := c.UpdateLockdown("dmz", set("readonly")); err != nil {
		t.Fatal(err)
	}
	if n := len(c.Lockdowns()); n != 2 {
		t.Errorf("%d records", n)
	}
	// removed: the mappings it leaves empty go too
	for _, s := range []string{"lab", "dmz"} {
		if err := c.UpdateLockdown(s, func(*Lockdown) (*Lockdown, error) { return nil, nil }); err != nil {
			t.Fatal(err)
		}
	}
	if len(c.Lockdowns()) != 0 || len(c.LockdownKeysOf()) != 0 {
		t.Errorf("left: %v", c.LockdownKeysOf())
	}
	if _, err := os.Stat(c.Path); err == nil {
		b, _ := os.ReadFile(c.Path)
		if strings.Contains(string(b), "emergency") {
			t.Errorf("the file keeps the family:\n%s", b)
		}
	}
}

func TestLockdownDefects(t *testing.T) {
	c := lockdownConfig(t, "emergency:\n  lockdown:\n    lab:\n      by: alice\n    dmz:\n      groups: [readonly]\n")
	if got := c.Lockdowns(); len(got) != 1 || got[0].Scope != "dmz" {
		t.Errorf("usable: %+v", got)
	}
	d := c.LockdownDefects()
	if len(d) != 1 || d[0].Scope != "lab" || !strings.Contains(d[0].Defect, "locks nothing") {
		t.Errorf("defects: %+v", d)
	}
}
