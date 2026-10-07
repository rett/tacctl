package policy

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

func TestJunosSetRoundTrip(t *testing.T) {
	c, path := newConf(t, "")
	items := []string{"^request( .*)?$", "^file delete .*"}
	if err := WriteJunosSet(c, "operator", conf.JunosDenyCommands, items); err != nil {
		t.Fatal(err)
	}
	if got := JunosSet(c, "operator", conf.JunosDenyCommands); !reflect.DeepEqual(got, items) {
		t.Fatalf("read back %q", got)
	}
	if !strings.Contains(file(t, path), "junos:\n  operator:\n    deny_commands:") {
		t.Fatalf("file:\n%s", file(t, path))
	}
	// An oversized set is refused by the schema and nothing changes.
	big := append(items, strings.Repeat("x", 240))
	if err := WriteJunosSet(c, "operator", conf.JunosDenyCommands, big); err == nil {
		t.Fatal("oversized set written")
	}
	if got := JunosSet(c, "operator", conf.JunosDenyCommands); !reflect.DeepEqual(got, items) {
		t.Fatalf("after refusal %q", got)
	}
	if p := JunosProblem("operator", conf.JunosDenyCommands, big); len(p) != 4 ||
		!strings.HasPrefix(p[0], "Group 'operator': deny-commands would be") || !strings.HasSuffix(p[3], "tacctl group junos operator deny-commands list") {
		t.Fatalf("problem %q", p)
	}
	if JunosProblem("operator", conf.JunosDenyCommands, items) != nil {
		t.Fatal("problem for a set that fits")
	}
	// Empty removes the key and the group's mapping with it.
	if err := WriteJunosSet(c, "operator", conf.JunosDenyCommands, nil); err != nil {
		t.Fatal(err)
	}
	if file(t, path) != "" {
		t.Fatalf("file left:\n%s", file(t, path))
	}
	for word, want := range map[string]bool{"deny-commands": true, "deny_configuration": true, "allow-commands": false, "x": false} {
		if _, ok := JunosAttrOf(word); ok != want {
			t.Errorf("JunosAttrOf(%q) = %v", word, ok)
		}
	}
}

func TestWTILevelAndTier(t *testing.T) {
	c, path := newConf(t, "")
	for privlvl, want := range map[int]string{0: "viewonly", 4: "viewonly", 5: "user", 9: "user", 10: "superuser", 14: "superuser", 15: "administrator"} {
		if l, over := WTILevel(c, "g", privlvl); l != want || over {
			t.Errorf("band %d: %s %v", privlvl, l, over)
		}
	}
	if err := WriteWTILevel(c, "engineer", "superuser"); err != nil {
		t.Fatal(err)
	}
	if l, over := WTILevel(c, "engineer", 15); l != "superuser" || !over {
		t.Fatalf("override: %s %v", l, over)
	}
	if WTIPrivLvl("superuser") != 10 || WTIPrivLvl("viewonly") != 0 || WTIPrivLvl("administrator") != 15 || WTIPrivLvl("user") != 5 {
		t.Fatal("floors")
	}
	if err := WriteWTILevel(c, "engineer", "root"); err == nil {
		t.Fatal("bad level written")
	}
	if err := WriteGroupTier(c, "engineer", "engineer"); err != nil {
		t.Fatal(err)
	}
	if GroupTier(c, "engineer") != "engineer" || GroupTier(c, "operator") != "" {
		t.Fatal("tier")
	}
	if err := WriteJunosSet(c, "engineer", conf.JunosDenyConfiguration, []string{"^snmp"}); err != nil {
		t.Fatal(err)
	}
	// Rename carries everything; forget removes everything.
	if err := RenameGroup(c, "engineer", "eng"); err != nil {
		t.Fatal(err)
	}
	if GroupTier(c, "eng") != "engineer" || GroupTier(c, "engineer") != "" ||
		len(JunosSet(c, "eng", conf.JunosDenyConfiguration)) != 1 || len(JunosSet(c, "engineer", conf.JunosDenyConfiguration)) != 0 {
		t.Fatalf("rename:\n%s", file(t, path))
	}
	if l, over := WTILevel(c, "eng", 15); l != "superuser" || !over {
		t.Fatal("rename wti")
	}
	if err := ForgetGroup(c, "eng"); err != nil {
		t.Fatal(err)
	}
	if file(t, path) != "" {
		t.Fatalf("forget left:\n%s", file(t, path))
	}
	if err := WriteWTILevel(c, "g", "user"); err != nil {
		t.Fatal(err)
	}
	if err := WriteWTILevel(c, "g", "auto"); err != nil {
		t.Fatal(err)
	}
	if _, over := WTILevel(c, "g", 0); over {
		t.Fatal("auto did not clear")
	}
}
