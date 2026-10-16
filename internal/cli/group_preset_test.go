package cli

import (
	"fmt"
	"strings"
	"testing"
)

// 'group preset roles' shows what each setting would change: the value now
// and the preset's, the lines of the rule lists and deny sets that go and
// come, and nothing under a step that is unchanged.
func TestGroupPresetShowsDetail(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.plainRun("", "group", "preset", "roles", "--dry-run")
	for _, want := range []string{
		"WTI level: ViewOnly (auto, from priv-lvl) -> ViewOnly (set)  (same level; now set explicitly)",
		"deny-commands: none -> 136/241 bytes",
		"group does not exist: it is created with Cisco priv-lvl 15 and Juniper class EN-CLASS",
		"+ reload       deny",
		"+ *            permit",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}

	// A value that differs is kept without --force, and the line says what
	// --force would change it from and to.
	sb.must("group", "edit", "readonly", "wti-level", "user")
	out = sb.plainRun("", "group", "preset", "roles", "--dry-run")
	if !strings.Contains(out, fmt.Sprintf("    %-48s kept (pass --force)\n        WTI level: User (set) -> ViewOnly (set)\n", "WTI level viewonly")) {
		t.Errorf("kept step:\n%s", out)
	}

	// Once applied, an unchanged step has no detail at all.
	b := newSandbox(t, true)
	b.run("y\n", []string{"group", "preset", "roles"})
	if b.code != 0 {
		t.Fatalf("preset: %d %s", b.code, b.err.String())
	}
	out = b.plainRun("", "group", "preset", "roles", "--dry-run")
	if strings.Contains(out, " -> ") || strings.Contains(out, "+ ") || !strings.Contains(out, "Nothing to change.") {
		t.Errorf("second run shows detail:\n%s", out)
	}
}
