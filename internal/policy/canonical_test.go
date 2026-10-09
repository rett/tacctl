package policy

import (
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/store"
)

// The canonical state of a built-in group is read from the single sources
// (defaults.yaml, store.BuiltinGroups) and carries no setting of its own.
func TestCanonicalBuiltinsAreWhatAFreshInstallGives(t *testing.T) {
	for _, b := range store.BuiltinGroups {
		c, ok := CanonicalGroup(b.Name, false)
		if !ok {
			t.Fatalf("%s: no canonical state", b.Name)
		}
		if !c.Builtin || c.PrivLvl != b.PrivLvl || c.Class != b.JuniperClass {
			t.Errorf("%s: %+v", b.Name, c)
		}
		if c.Tier != "" || c.WTI != "" || len(c.Junos) != 0 {
			t.Errorf("%s carries settings of its own: %+v", b.Name, c)
		}
		if !reflect.DeepEqual(c.Rules, DefaultLines(b.Name)) || c.RulesOverride {
			t.Errorf("%s: rules %q (override %v), shipped %q", b.Name, c.Rules, c.RulesOverride, DefaultLines(b.Name))
		}
		if !reflect.DeepEqual(c.Privileges, DefaultPrivileges(b.Name)) {
			t.Errorf("%s: privileges %q, shipped %q", b.Name, c.Privileges, DefaultPrivileges(b.Name))
		}
		if len(c.Rules) == 0 {
			t.Errorf("%s has no command rules: the lockout guard would not emit its level", b.Name)
		}
	}
}

// With the preset the role's values apply, the shipped class stays where the
// preset names none, and a role with no Cisco rules keeps the shipped ones.
func TestCanonicalWithPresetIsTheRole(t *testing.T) {
	for _, r := range RolePreset() {
		c, ok := CanonicalGroup(r.Group, true)
		if !ok {
			t.Fatalf("%s: no canonical state", r.Group)
		}
		if c.PrivLvl != r.PrivLvl || c.WTI != r.WTI || c.Tier != r.Tier || !reflect.DeepEqual(c.Junos, r.Junos) {
			t.Errorf("%s: %+v, preset %+v", r.Group, c, r)
		}
		wantClass := r.Class
		if b, builtin := builtinGroup(r.Group); builtin && wantClass == "" {
			wantClass = b.JuniperClass
		}
		if c.Class != wantClass {
			t.Errorf("%s: class %q, want %q", r.Group, c.Class, wantClass)
		}
		if r.Commands != nil {
			if !reflect.DeepEqual(c.Rules, r.Commands) || !c.RulesOverride {
				t.Errorf("%s: rules %q (override %v)", r.Group, c.Rules, c.RulesOverride)
			}
		} else if !reflect.DeepEqual(c.Rules, DefaultLines(r.Group)) || c.RulesOverride {
			t.Errorf("%s: rules %q (override %v), want the shipped ones", r.Group, c.Rules, c.RulesOverride)
		}
		// A canonical set fits the Junos limit.
		for _, attr := range conf.JunosAttrs {
			if p := JunosProblem(r.Group, attr, c.JunosItems(attr)); p != nil {
				t.Errorf("%s %s: %q", r.Group, attr, p)
			}
		}
	}
}

// The engineer is not built in: its canonical state is the preset's, with or
// without --preset.
func TestCanonicalEngineerIsThePresetsEngineer(t *testing.T) {
	a, ok := CanonicalGroup("engineer", false)
	if !ok {
		t.Fatal("no canonical engineer")
	}
	b, _ := CanonicalGroup("engineer", true)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("without --preset %+v, with %+v", a, b)
	}
	if a.Builtin || a.PrivLvl != 15 || a.Class != EngineerClass || a.Tier != "engineer" || a.WTI != "superuser" {
		t.Errorf("settings: %+v", a)
	}
	if len(a.Junos[conf.JunosDenyCommands]) != 1 || len(a.JunosItems(conf.JunosDenyConfiguration)) != 0 {
		t.Errorf("junos: %q", a.Junos)
	}
	if !a.RulesOverride || len(a.Rules) != 34 || len(a.Privileges) != 0 {
		t.Errorf("rules %d (override %v), privileges %q", len(a.Rules), a.RulesOverride, a.Privileges)
	}
}

func TestCanonicalRefusesAnyOtherGroup(t *testing.T) {
	for _, g := range []string{"helpdesk", "ENGINEER", "", "admin"} {
		for _, preset := range []bool{false, true} {
			if c, ok := CanonicalGroup(g, preset); ok {
				t.Errorf("%q (preset %v): %+v", g, preset, c)
			}
		}
	}
}

// A group in the superuser band other than superuser always has a tier
// setting: a canonical state that would leave it without writes one.
func TestTierSettingInTheBand(t *testing.T) {
	for _, c := range []struct {
		group string
		priv  int
		tier  string
		want  string
	}{
		{"helpdesk", 15, "", "superuser"},
		{"operator", 15, "", "superuser"},
		{"engineer", 15, "engineer", "engineer"},
		{"superuser", 15, "", ""},
		{"helpdesk", 14, "", ""},
		{"operator", 7, "", ""},
	} {
		if got := tierSetting(c.group, c.priv, c.tier); got != c.want {
			t.Errorf("tierSetting(%s, %d, %q) = %q, want %q", c.group, c.priv, c.tier, got, c.want)
		}
	}
	// Every canonical state, built-in or preset, satisfies the invariant.
	for _, g := range []string{"readonly", "operator", "superuser", "engineer"} {
		for _, preset := range []bool{false, true} {
			c, _ := CanonicalGroup(g, preset)
			if NeedsTier(g, &c.PrivLvl) && c.Tier == "" {
				t.Errorf("%s (preset %v) at priv-lvl %d has no tier", g, preset, c.PrivLvl)
			}
		}
	}
}

func TestDefaultActionOfAndBareSiblings(t *testing.T) {
	for _, c := range []struct {
		lines []string
		want  string
	}{
		{nil, "permit"},
		{[]string{"show|permit|", "*|deny|"}, "deny"},
		{[]string{"*|permit|"}, "permit"},
		{[]string{"show|permit|"}, "deny"},
	} {
		if got := DefaultActionOf(c.lines); got != c.want {
			t.Errorf("DefaultActionOf(%q) = %q, want %q", c.lines, got, c.want)
		}
	}
	cfg := conf.Load(filepath.Join(t.TempDir(), "tacctl.yaml"), conf.DefaultBackends)
	groups := GroupLevels{"operator|7|OP-CLASS", "helpdesk|7|HD", "noc|7|NOC", "readonly|1|RO-CLASS", "superuser|15|RW-CLASS"}
	if err := Write(cfg, "noc", []string{"*|permit|"}); err != nil {
		t.Fatal(err)
	}
	level, bare := BareSiblings(cfg, groups, "operator")
	if level != "7" || !slices.Equal(bare, []string{"helpdesk"}) {
		t.Errorf("BareSiblings: %q %q", level, bare)
	}
	// Nothing was written by asking.
	if len(Lines(cfg, "helpdesk")) != 0 {
		t.Error("BareSiblings wrote")
	}
	level, seeded, err := SeedSiblings(cfg, groups, "operator")
	if err != nil || level != "7" || !slices.Equal(seeded, []string{"helpdesk"}) || DefaultAction(cfg, "helpdesk") != "permit" || len(Lines(cfg, "helpdesk")) != 1 {
		t.Errorf("SeedSiblings: %q %q %v", level, seeded, err)
	}
}
