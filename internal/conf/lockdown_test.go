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

// The list of hosts a record waits for (0.2.23, .pending): written with the
// record, a record with no group and a list is a lifted lockdown that locks
// nothing and is no defect, and a list that is not host names is refused.
func TestLockdownPendingHosts(t *testing.T) {
	c := lockdownConfig(t, "")
	since := "2026-10-25T12:00:00Z"
	if err := c.UpdateLockdown("lab", func(*Lockdown) (*Lockdown, error) {
		return &Lockdown{Groups: []string{"operator"}, Since: since, By: "alice", Pending: []string{"web1", "web2"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	got := c.Lockdowns()
	if len(got) != 1 || !slices.Equal(got[0].Pending, []string{"web1", "web2"}) || got[0].Lifted() || len(c.LockdownLifts()) != 0 {
		t.Fatalf("the record: %+v lifts %+v", got, c.LockdownLifts())
	}
	// lifted: no group, the hosts that hold the drop-in; locks nothing
	if err := c.UpdateLockdown("lab", func(cur *Lockdown) (*Lockdown, error) {
		if cur == nil || len(cur.Pending) != 2 {
			t.Fatalf("the record the callback gets: %+v", cur)
		}
		return &Lockdown{Since: since, By: "alice", Pending: []string{"web2"}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(c.Lockdowns()) != 0 || len(LockedGroups(c.Merged())) != 0 {
		t.Errorf("a lifted record locks: %+v", c.Lockdowns())
	}
	lifts := c.LockdownLifts()
	if len(lifts) != 1 || lifts[0].Scope != "lab" || !lifts[0].Lifted() || !slices.Equal(lifts[0].Pending, []string{"web2"}) {
		t.Fatalf("lifts: %+v", lifts)
	}
	if d := c.LockdownDefects(); len(d) != 0 {
		t.Errorf("a lifted record that waits is a defect: %+v", d)
	}
	// the callback gets a lifted record, and one that ends with nothing goes
	if err := c.UpdateLockdown("lab", func(cur *Lockdown) (*Lockdown, error) {
		if cur == nil || !cur.Lifted() {
			t.Fatalf("the lifted record the callback gets: %+v", cur)
		}
		return nil, nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(c.LockdownLifts()) != 0 || strings.Contains(readFileOf(t, c.Path), "emergency") {
		t.Errorf("the record stayed: %s", readFileOf(t, c.Path))
	}
	// a list that is not host names, or is listed twice, is refused
	for _, bad := range [][]string{{"web 1"}, {"1web"}, {"web1", "web1"}} {
		if err := c.UpdateLockdown("lab", func(*Lockdown) (*Lockdown, error) {
			return &Lockdown{Groups: []string{"operator"}, Since: since, By: "alice", Pending: bad}, nil
		}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	// a hand-written record with a list and no group is a lifted one; with
	// neither it is still a defect
	c = lockdownConfig(t, "emergency:\n  lockdown:\n    lab:\n      pending:\n        - web1\n    dmz:\n      reason: drill\n")
	if l := c.LockdownLifts(); len(l) != 1 || l[0].Scope != "lab" {
		t.Errorf("lifts: %+v", l)
	}
	if d := c.LockdownDefects(); len(d) != 1 || d[0].Scope != "dmz" {
		t.Errorf("defects: %+v", d)
	}
}

func readFileOf(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}
