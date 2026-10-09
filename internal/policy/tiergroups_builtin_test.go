package policy

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
)

// B1 (WP10.2i): only the built-in superuser group is exempt from the tier
// invariant. A built-in readonly or operator raised to priv-lvl 15 is as
// ambiguous as any custom group when its tier setting is lost.
func TestNeedsTierExemptsOnlyTheBuiltinSuperuser(t *testing.T) {
	at := func(n int) *int { return &n }
	for _, c := range []struct {
		group string
		lvl   *int
		want  bool
	}{
		{"superuser", at(15), false},
		{"operator", at(15), true},
		{"readonly", at(15), true},
		{"neteng", at(15), true},
		{"neteng", at(16), true},
		{"operator", at(7), false},
		{"readonly", at(1), false},
		{"neteng", at(14), false},
		{"neteng", nil, false},
		{"operator", nil, false},
	} {
		if got := NeedsTier(c.group, c.lvl); got != c.want {
			t.Errorf("NeedsTier(%q, %v) = %v, want %v", c.group, c.lvl, got, c.want)
		}
	}
}

// B1: the reproduction at the model level: operator and readonly at 15, the
// setting of one of them lost: both are listed, the built-in superuser is
// not; pinning (the upgrade's migration) records superuser for both, what
// 0.2.2 gave them.
func TestUnsetTierGroupsListsBuiltinsRaisedTo15(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "store.yaml")
	writeFile(t, store, `version: 1
groups:
  operator: {priv_lvl: 15, juniper_class: OP-CLASS, builtin: true}
  readonly: {priv_lvl: 15, juniper_class: RO-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
users: {}
scopes: {}
filters:
  allow: []
  deny: []
`)
	_, m, _, err := model.Load(model.Paths{Store: store, Config: filepath.Join(dir, "tacquito.yaml"), DatesDir: dir, DisabledDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	c := conf.Load(filepath.Join(dir, "tacctl.yaml"), nil)
	if got := UnsetTierGroups(c, m); !slices.Equal(got, []string{"operator", "readonly"}) {
		t.Fatalf("no file: %v", got)
	}
	// The operator chose a tier for one; the other is still ambiguous.
	if err := WriteGroupTier(c, "operator", "engineer"); err != nil {
		t.Fatal(err)
	}
	if got := UnsetTierGroups(c, m); !slices.Equal(got, []string{"readonly"}) {
		t.Fatalf("operator has one: %v", got)
	}
	// ... and when that setting is lost again (a file without the section).
	writeFile(t, filepath.Join(dir, "tacctl.yaml"), "backends:\n  enabled: [tacacs]\n")
	c = conf.Load(filepath.Join(dir, "tacctl.yaml"), nil)
	done, err := PinUnset(c, m, nil)
	if err != nil || !slices.Equal(done, []string{"operator", "readonly"}) {
		t.Fatalf("pin: %v %v", done, err)
	}
	if GroupTier(c, "operator") != "superuser" || GroupTier(c, "readonly") != "superuser" || GroupTier(c, "superuser") != "" {
		t.Errorf("settings: %q %q %q", GroupTier(c, "operator"), GroupTier(c, "readonly"), GroupTier(c, "superuser"))
	}
}

// PinGroups writes exactly the groups it is given, snapshot first.
func TestPinGroupsWritesOnlyTheGroupsGiven(t *testing.T) {
	m := tierModel(t)
	c := conf.Load(filepath.Join(t.TempDir(), "tacctl.yaml"), nil)
	snaps := 0
	done, err := PinGroups(c, []string{"ops"}, func() error { snaps++; return nil })
	if err != nil || !slices.Equal(done, []string{"ops"}) || snaps != 1 {
		t.Fatalf("pin: %v %v %d", done, err, snaps)
	}
	if got := UnsetTierGroups(c, m); !slices.Equal(got, []string{"neteng"}) {
		t.Errorf("still unset: %v", got)
	}
	if done, err = PinGroups(c, nil, func() error { snaps++; return nil }); err != nil || len(done) != 0 || snaps != 1 {
		t.Errorf("nothing to pin: %v %v %d", done, err, snaps)
	}
}
