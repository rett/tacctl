package policy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
)

func tierModel(t *testing.T) *model.Model {
	t.Helper()
	dir := t.TempDir()
	store := filepath.Join(dir, "store.yaml")
	writeFile(t, store, `version: 1
groups:
  operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
  neteng: {priv_lvl: 15, juniper_class: ENG-CLASS}
  ops: {priv_lvl: 15, juniper_class: OPS-CLASS}
  helpdesk: {priv_lvl: 14, juniper_class: HD-CLASS}
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
	return m
}

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The groups that need a tier setting and have none: not the built-ins
// (their band is the setting), not a group below 15, not a group with any
// setting.
func TestUnsetTierGroupsAndPin(t *testing.T) {
	m := tierModel(t)
	path := filepath.Join(t.TempDir(), "tacctl.yaml")
	c := conf.Load(path, nil)
	if got := UnsetTierGroups(c, m); !slices.Equal(got, []string{"neteng", "ops"}) {
		t.Fatalf("no file: %v", got)
	}
	if err := WriteGroupTier(c, "ops", "engineer"); err != nil {
		t.Fatal(err)
	}
	if got := UnsetTierGroups(c, m); !slices.Equal(got, []string{"neteng"}) {
		t.Fatalf("ops has one: %v", got)
	}
	snaps := 0
	done, err := PinUnset(c, m, func() error { snaps++; return nil })
	if err != nil || !slices.Equal(done, []string{"neteng"}) || snaps != 1 {
		t.Fatalf("pin: %v %v %d", done, err, snaps)
	}
	if GroupTier(c, "neteng") != "superuser" || GroupTier(c, "ops") != "engineer" || GroupTier(c, "helpdesk") != "" || GroupTier(c, "superuser") != "" {
		t.Errorf("settings: %q %q %q %q", GroupTier(c, "neteng"), GroupTier(c, "ops"), GroupTier(c, "helpdesk"), GroupTier(c, "superuser"))
	}
	// Idempotent: nothing to write, no snapshot taken.
	done, err = PinUnset(c, m, func() error { snaps++; return nil })
	if err != nil || len(done) != 0 || snaps != 1 {
		t.Errorf("second pin: %v %v %d", done, err, snaps)
	}
	// A snapshot that fails writes nothing.
	if err := WriteGroupTier(c, "neteng", "auto"); err != nil {
		t.Fatal(err)
	}
	if done, err = PinUnset(c, m, func() error { return errors.New("no space") }); err == nil || len(done) != 0 || GroupTier(c, "neteng") != "" {
		t.Errorf("failed snapshot: %v %v %q", done, err, GroupTier(c, "neteng"))
	}
	// An empty file, and one without a tier section, are the same.
	for _, text := range []string{"", "backends:\n  enabled: [tacacs]\n"} {
		writeFile(t, path, text)
		c = conf.Load(path, nil)
		if got := UnsetTierGroups(c, m); !slices.Equal(got, []string{"neteng", "ops"}) {
			t.Errorf("%q: %v", text, got)
		}
	}
}
