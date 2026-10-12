package policy

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// An install that ran 0.2.3's 'group preset roles' stores the preset's
// 'show' deny in front of the shipped rules of that release: the fix that
// keeps the deny is the preset's reset of the commands (and of the Junos
// sets, in one command), not the shipped rules' (which would lose it).
func TestStaleOperatorPolicyPreset023(t *testing.T) {
	for _, g := range []string{"operator", "readonly"} {
		lines := preset023Lines(g)
		if len(lines) != len(linesOfPrevious(g, 1))+1 || !strings.HasPrefix(lines[0], "show|deny|^(running-config view full|") ||
			lines[1] != "show|deny|^(running-config view full)( .*)?$" {
			t.Fatalf("%s: preset 0.2.3 lines %q", g, lines)
		}
	}
	if r, o := preset023Lines("readonly")[0], preset023Lines("operator")[0]; !strings.Contains(r, "tech-support") || strings.Contains(o, "tech-support") {
		t.Errorf("show denies: %q / %q", r, o)
	}
	c, _ := newConf(t, "")
	for _, g := range []string{"operator", "readonly"} {
		if err := Write(c, g, preset023Lines(g)); err != nil {
			t.Fatal(err)
		}
	}
	got := StaleOperatorPolicy(c)
	if len(got) != 2 || !got[0].Preset || !got[1].Preset ||
		got[0].Fix() != "tacctl group reset operator --preset --only commands" ||
		got[1].Fix() != "tacctl group reset readonly --preset --only commands" ||
		got[0].Restores() != "the role preset's value" {
		t.Fatalf("preset 0.2.3 commands: %v", got)
	}
	// An upgrade leaves a preset value alone: running the preset was a choice.
	if dropped, _ := DropPreviousDefaults(c); len(dropped) != 0 {
		t.Errorf("a preset value dropped: %v", dropped)
	}
	// With the preset's Junos sets as well, one fix per group.
	if err := WriteJunosSet(c, "operator", conf.JunosDenyCommands, []string{operatorDenyCommands023}); err != nil {
		t.Fatal(err)
	}
	if err := WriteJunosSet(c, "readonly", conf.JunosDenyCommands, []string{viewerDenyCommands023}); err != nil {
		t.Fatal(err)
	}
	want := []string{"tacctl group reset operator --preset --only commands,junos", "tacctl group reset readonly --preset --only commands,junos"}
	if fixes := Fixes(StaleOperatorPolicy(c)); !slices.Equal(fixes, want) {
		t.Errorf("fixes %q, want %q", fixes, want)
	}
	// The preset's list with one more rule is the operator's own: the shipped
	// reset names it.
	own := slices.Clone(preset023Lines("operator"))
	own = append(own[:len(own)-1], "debug|permit|", "*|deny|")
	if err := Write(c, "operator", own); err != nil {
		t.Fatal(err)
	}
	for _, s := range StaleOperatorPolicy(c) {
		if s.Setting == "commands.operator" && (s.Preset || s.Fix() != "tacctl group commands reset operator") {
			t.Errorf("customised preset list: %q", s.Fix())
		}
	}
}

// What 0.2.3 shipped (a list 'group commands add' seeded) keeps the shipped
// reset, not the preset's; and one preset-valued setting and one shipped one
// each get their own fix.
func TestStaleOperatorPolicyShipped023IsNotPreset(t *testing.T) {
	c, _ := newConf(t, "")
	if err := Write(c, "operator", linesOfPrevious("operator", 1)); err != nil {
		t.Fatal(err)
	}
	got := StaleOperatorPolicy(c)
	if len(got) != 1 || got[0].Preset || got[0].Fix() != "tacctl group commands reset operator" {
		t.Errorf("0.2.3 shipped: %v", got)
	}
	if err := Write(c, "readonly", preset023Lines("readonly")); err != nil {
		t.Fatal(err)
	}
	want := []string{"tacctl group commands reset operator", "tacctl group reset readonly --preset --only commands"}
	if fixes := Fixes(StaleOperatorPolicy(c)); !slices.Equal(fixes, want) {
		t.Errorf("fixes %q, want %q", fixes, want)
	}
}
