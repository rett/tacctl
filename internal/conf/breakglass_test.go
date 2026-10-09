package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBreakGlassSchema(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, ok := range [][]any{
		{"lab-admin:admin"},
		{"a:admin", "b_2:operator", "C-3:readonly"},
		{strings.Repeat("x", 32) + ":admin"}, // the longest name
	} {
		if msg := s.Validate("breakglass_scope.lab.users", ok, true); msg != "" {
			t.Errorf("%v refused: %s", ok, msg)
		}
	}
	long := make([]any, 17)
	for i := range long {
		long[i] = "u" + string(rune('a'+i)) + ":admin"
	}
	for _, c := range []struct {
		items []any
		want  string
	}{
		{[]any{}, "non-empty list"},
		{[]any{"lab-admin"}, "not 'name:role'"},
		{[]any{"lab-admin:root"}, "the role of 'lab-admin' must be one of: admin, operator, readonly"},
		{[]any{"lab-admin:"}, "must be one of"},
		{[]any{":admin"}, "not a device-safe user name"},
		{[]any{"9lives:admin"}, "not a device-safe user name"},
		{[]any{"has space:admin"}, "not a device-safe user name"},
		{[]any{"bad;name:admin"}, "not a device-safe user name"},
		{[]any{strings.Repeat("x", 33) + ":admin"}, "not a device-safe user name"},
		{[]any{"a:admin", "a:operator"}, "element 1: 'a' is listed twice"},
		{[]any{3}, "element 0: must be a string"},
		{long, "at most 16"},
	} {
		if msg := s.Validate("breakglass_scope.lab.users", c.items, true); !strings.Contains(msg, c.want) {
			t.Errorf("%v: %q, want %q", c.items, msg, c.want)
		}
	}
	if msg := s.Validate("breakglass_scope.lab.users", "lab-admin:admin", false); !strings.Contains(msg, "requires list input") {
		t.Errorf("scalar: %q", msg)
	}
	if msg := s.Validate("breakglass_scope.lab.other", []any{"a:admin"}, true); !strings.Contains(msg, "only field") {
		t.Errorf("other field: %q", msg)
	}
	// The path needs a scope and a field, no more.
	for _, p := range []string{"breakglass_scope.lab", "breakglass_scope.lab.users.x", "breakglass_scope..users"} {
		if msg := s.Validate(p, []any{"a:admin"}, true); !strings.Contains(msg, "unknown config key") {
			t.Errorf("%s: %q", p, msg)
		}
	}
}

func TestBreakGlassSplit(t *testing.T) {
	if n, r, ok := SplitBreakGlass("lab-ops:operator"); !ok || n != "lab-ops" || r != "operator" {
		t.Errorf("%q %q %v", n, r, ok)
	}
	for _, bad := range []string{"", "x", "x:", ":admin", "x:admin:y", "x:Admin", "1x:admin"} {
		if _, _, ok := SplitBreakGlass(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if BreakGlassPath("lab") != "breakglass_scope.lab.users" || BreakGlassEntry("a", "admin") != "a:admin" {
		t.Error("path or entry")
	}
}

// 'config validate' reads the file's own leaves: a hand edit the setters
// would refuse is reported with its path.
func TestBreakGlassValidateFile(t *testing.T) {
	s := NewSchema(DefaultBackends)
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	write := func(text string) {
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("breakglass_scope:\n  lab:\n    users: [lab-admin:admin, lab-ro:readonly]\n")
	if lines := s.ValidateFile(p); len(lines) != 0 {
		t.Errorf("valid file: %v", lines)
	}
	write("breakglass_scope:\n  lab:\n    users: [lab-admin:boss]\n")
	lines := s.ValidateFile(p)
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "breakglass_scope.lab.users: element 0: the role of 'lab-admin' must be one of") {
		t.Errorf("bad role: %v", lines)
	}
}

// The key is written only when set, and a tacctl.yaml without it is not
// touched by setting and clearing it.
func TestBreakGlassWrittenOnlyWhenSet(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tacctl.yaml")
	c := Load(p, DefaultBackends)
	if err := c.Set("exec_timeout.lab", "30"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "breakglass") {
		t.Fatalf("written unset:\n%s", before)
	}
	if err := c.SetList(BreakGlassPath("lab"), []string{"lab-admin:admin"}); err != nil {
		t.Fatal(err)
	}
	set, _ := os.ReadFile(p)
	if !strings.Contains(string(set), "breakglass_scope:\n  lab:\n    users:\n    - lab-admin:admin\n") {
		t.Errorf("set:\n%s", set)
	}
	if err := c.Unset(BreakGlassPath("lab")); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(before) {
		t.Errorf("not byte-identical after clearing:\n%s\nwas:\n%s", after, before)
	}
}
