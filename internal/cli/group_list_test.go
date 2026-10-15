package cli

import (
	"strings"
	"testing"
)

const engineerHint = "No group has the engineer tier; a superuser gives it with 'tacctl group preset roles'"

// 'group list' ends with one line when no group has the engineer tier, and
// has no such line once a group has it or while the tier settings are a hand
// edit problem.
func TestGroupListEngineerHint(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.plainRun("", "group", "list")
	if strings.Count(out, engineerHint) != 1 || !strings.HasSuffix(out, "'tacctl group edit <group> tier engineer'.\n") {
		t.Errorf("no engineer: the hint is not the last line:\n%s", out)
	}
	if strings.Contains(sb.err.String(), "engineer tier") {
		t.Errorf("the hint went to stderr: %q", sb.err.String())
	}

	// The tier setting is what makes an engineer, on any group.
	sb.must("group", "edit", "operator", "tier", "engineer")
	if out := sb.plainRun("", "group", "list"); strings.Contains(out, "engineer tier") || !strings.Contains(out, "GROUP") {
		t.Errorf("tier engineer set:\n%s", out)
	}
	sb.must("group", "edit", "operator", "tier", "auto")
	if out := sb.plainRun("", "group", "list"); !strings.Contains(out, engineerHint) {
		t.Errorf("tier cleared:\n%s", out)
	}

	// A tier setting that is not a string: the existing warnings own it.
	sb.write("state/tacctl.yaml", "tier:\n  operator: 5\n", 0o600)
	if out := sb.plainRun("", "group", "list"); strings.Contains(out, "engineer tier") || !strings.Contains(out, "GROUP") {
		t.Errorf("tier problem:\n%s", out)
	}
}

// An empty privileges list on a built-in group that ships one is a warning
// of 'config validate' (exit code unchanged) and a second line of 'group
// privilege list'; 'group privilege reset' removes both.
func TestEmptyPrivilegesOverrideIsReported(t *testing.T) {
	sb := renderedSandbox(t)
	if out := plain(sb.run("", []string{"config", "validate"})); sb.code != 0 || strings.Contains(out, "empty list") {
		t.Fatalf("clean: %d\n%s", sb.code, out)
	}
	sb.write("state/tacctl.yaml", sb.overrides()+"privileges:\n  operator: []\n  superuser: []\n", 0o640)
	out := plain(sb.run("", []string{"config", "validate"}))
	want := "Group settings:       privileges.operator is an empty list in tacctl.yaml: it hides the shipped default (1 mapping: undebug all); 'tacctl group privilege reset operator' removes it"
	if sb.code != 0 || !strings.Contains(out, want) || strings.Contains(out, "privileges.superuser") {
		t.Errorf("validate: %d\n%s", sb.code, out)
	}
	out = sb.plainRun("", "group", "privilege", "list", "operator")
	if !strings.Contains(out, "(no mappings") || !strings.Contains(out, "  (tacctl.yaml stores an empty list that hides the shipped default; 'tacctl group privilege reset operator' removes it)\n") {
		t.Errorf("privilege list:\n%s", out)
	}
	if out := sb.plainRun("", "group", "privilege", "list", "superuser"); strings.Contains(out, "stores an empty list") {
		t.Errorf("superuser has no shipped list:\n%s", out)
	}
	sb.must("group", "privilege", "reset", "operator", "--yes")
	out = plain(sb.run("", []string{"config", "validate"}))
	if sb.code != 0 || strings.Contains(out, "privileges.operator") {
		t.Errorf("after reset: %d\n%s", sb.code, out)
	}
	if out := sb.plainRun("", "group", "privilege", "list", "operator"); !strings.Contains(out, "undebug all") || strings.Contains(out, "stores an empty list") {
		t.Errorf("privilege list after reset:\n%s", out)
	}
}
