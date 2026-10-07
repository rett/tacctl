package tacacs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
)

// The per-group device settings of 0.2.2 (docs/plans/0.2.2-plan.md §6.1):
// Junos deny sets on junos-exec, a wti service for a group with a WTI
// level. A model without them is covered by the minimal golden, which
// stays as 0.2.1 rendered it.

func devauthView(t *testing.T) string {
	return string(readFile(t, filepath.Join(fixDir, "tacctl.devauth.yaml")))
}

func TestRenderDevauthGolden(t *testing.T) {
	out := render(t, loadStore(t, "store.devauth.yaml"), viewOf(t, devauthView(t)).Merged())
	diffText(t, out, readFile(t, filepath.Join(goldenDir, "tacquito.devauth.rendered.yaml")), "devauth")
}

func TestRenderRefusesAnOversizedJunosSet(t *testing.T) {
	// Written by hand past the schema: the render is the last guard.
	view := "junos:\n  operator:\n    deny_commands: ['" + strings.Repeat("x", 240) + "']\n"
	_, err := Render(loadStore(t, "store.devauth.yaml"), viewOf(t, view).Merged())
	if err == nil {
		t.Fatal("rendered")
	}
	msg := rendered.Report(err)
	for _, want := range []string{"Group 'operator': deny-commands would be 242 bytes; the limit is 241",
		"tacctl group junos operator deny-commands list"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
}

func TestRenderGroupNamedLikeTheWTIService(t *testing.T) {
	if GroupKey("wti_exec_x") != "group_wti_exec_x" {
		t.Fatal(GroupKey("wti_exec_x"))
	}
}

func TestRenderToFileReadsBackDevauth(t *testing.T) {
	if _, err := renderFile(t, loadStore(t, "store.devauth.yaml"), viewOf(t, devauthView(t)).Merged()); err != nil {
		t.Fatal(rendered.Report(err))
	}
}

func TestReadbackCatchesDevauthDifferences(t *testing.T) {
	st := loadStore(t, "store.devauth.yaml")
	text := string(render(t, st, viewOf(t, devauthView(t)).Merged()))
	for _, c := range []struct{ old, new, want string }{
		{"      values: [10]\n", "      values: [5]\n", "wti service of group 'engineer' differs"},
		{"|snmp|", "|snmpx|", "junos values of group 'engineer' differ"},
	} {
		if !strings.Contains(text, c.old) {
			continue
		}
		path := filepath.Join(t.TempDir(), "tacquito.yaml")
		writeFile(t, path, strings.Replace(text, c.old, c.new, 1))
		err := Readback(path, model.FromStore(st), viewOf(t, devauthView(t)).Merged(), DefaultLoader)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v", c.new, err)
		}
	}
	// A view without the settings: the same file now carries extras.
	path := filepath.Join(t.TempDir(), "tacquito.yaml")
	writeFile(t, path, text)
	err := Readback(path, model.FromStore(st), defaultView(t), DefaultLoader)
	if err == nil || !strings.Contains(err.Error(), "junos values of group 'operator' differ") ||
		!strings.Contains(err.Error(), "wti service of group 'engineer' differs") {
		t.Fatalf("%v", err)
	}
}

func TestImporterNotesDevauthAndKeepsExtras(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tacquito.yaml")
	writeFile(t, path, string(render(t, loadStore(t, "store.devauth.yaml"), viewOf(t, devauthView(t)).Merged())))
	_, rep, err := store.LegacyRaw(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Dropped) > 0 || len(rep.Errors) > 0 {
		t.Fatalf("dropped %q errors %q", rep.Dropped, rep.Errors)
	}
	notes := strings.Join(rep.Notes, "\n")
	for _, want := range []string{
		"group 'engineer': service 'wti': the WTI level lives in tacctl.yaml (wti_level.engineer); not stored",
		"group 'operator': service 'junos-exec': set_value 'deny-commands' lives in tacctl.yaml (junos.operator.deny_commands); not stored",
	} {
		if !strings.Contains(notes, want) {
			t.Errorf("missing note %q in:\n%s", want, notes)
		}
	}
	if e := rep.Extras["engineer"]; e == nil || len(e.Junos) != 2 || e.WTI != 10 {
		t.Fatalf("extras %+v", e)
	}
}
