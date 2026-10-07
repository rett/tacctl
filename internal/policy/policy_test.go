package policy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
)

// newConf is a tacctl.yaml in a temp dir holding text ("" for no file).
func newConf(t *testing.T, text string) (*conf.Config, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tacctl.yaml")
	if text != "" {
		if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return conf.Load(path, conf.DefaultBackends), path
}

func file(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	// Past the header comment block.
	s := string(data)
	if i := strings.Index(s, "\ncommands:"); i >= 0 {
		return s[i+1:]
	}
	if i := strings.Index(s, "\nprivileges:"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func TestLinesAndDefaultAction(t *testing.T) {
	c, _ := newConf(t, "")
	want := []string{"show|permit|", "ping|permit|", "traceroute|permit|", "terminal|permit|", "*|deny|"}
	if got := Lines(c, "operator"); !reflect.DeepEqual(got, want) {
		t.Errorf("operator: %q", got)
	}
	for group, action := range map[string]string{"operator": "deny", "readonly": "deny", "superuser": "permit", "helpdesk": "permit"} {
		if got := DefaultAction(c, group); got != action {
			t.Errorf("%s: default %q, want %q", group, got, action)
		}
	}
	if Lines(c, "helpdesk") != nil {
		t.Error("a group without rules has lines")
	}
	// A group whose last rule is no catch-all is denied the rest.
	c, _ = newConf(t, "commands:\n  helpdesk:\n  - {name: show, match: [a, b]}\n")
	if got := Lines(c, "helpdesk"); !reflect.DeepEqual(got, []string{"show|permit|a,b"}) {
		t.Errorf("helpdesk: %q", got)
	}
	if got := DefaultAction(c, "helpdesk"); got != "deny" {
		t.Errorf("no catch-all: %q", got)
	}
	if Field("a|b|c,d|e", 3) != "c,d" || Field("a", 2) != "" {
		t.Error("Field")
	}
}

func TestInsertUpdateRemove(t *testing.T) {
	c, path := newConf(t, "")
	if err := InsertRule(c, "operator", "configure", "deny", "terminal,x"); err != nil {
		t.Fatal(err)
	}
	want := []string{"show|permit|", "ping|permit|", "traceroute|permit|", "terminal|permit|", "configure|deny|terminal,x", "*|deny|"}
	if got := Lines(c, "operator"); !reflect.DeepEqual(got, want) {
		t.Errorf("after insert: %q", got)
	}
	if got := file(t, path); !strings.Contains(got, "  - name: configure\n    action: deny\n    match:\n    - terminal\n    - x\n") {
		t.Errorf("file:\n%s", got)
	}
	if err := UpdateCatchall(c, "operator", "permit"); err != nil {
		t.Fatal(err)
	}
	if got := Lines(c, "operator"); got[len(got)-1] != "*|permit|" || len(got) != 6 {
		t.Errorf("after update: %q", got)
	}
	if err := RemoveRule(c, "operator", "configure"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateCatchall(c, "operator", "deny"); err != nil {
		t.Fatal(err)
	}
	// Back to the shipped rules: the override is gone, and so is the file.
	if got := file(t, path); got != "" {
		t.Errorf("override left:\n%s", got)
	}
}

func TestInsertRuleAt(t *testing.T) {
	shipped := []string{"show|permit|", "ping|permit|", "traceroute|permit|", "terminal|permit|"}
	for _, tc := range []struct {
		name  string
		where Where
		want  []string
	}{
		{"default", Where{}, append(append([]string{}, shipped...), "x|deny|a", "*|deny|")},
		{"before catch-all", Where{Before: Catchall}, append(append([]string{}, shipped...), "x|deny|a", "*|deny|")},
		{"first", Where{First: true}, append(append([]string{"x|deny|a"}, shipped...), "*|deny|")},
		{"before ping", Where{Before: "ping"}, []string{"show|permit|", "x|deny|a", "ping|permit|", "traceroute|permit|", "terminal|permit|", "*|deny|"}},
	} {
		c, _ := newConf(t, "")
		if err := InsertRuleAt(c, "operator", "x", "deny", "a", tc.where); err != nil {
			t.Fatal(err)
		}
		if got := Lines(c, "operator"); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %q", tc.name, got)
		}
	}
	// Before the first of several rules of the name; a group without a
	// catch-all gains the deny one, as InsertRule does.
	c, path := newConf(t, "commands:\n  helpdesk:\n  - {name: show, match: [a]}\n  - {name: show, match: [b]}\n")
	if err := InsertRuleAt(c, "helpdesk", "show", "deny", "c", Where{Before: "show"}); err != nil {
		t.Fatal(err)
	}
	if got := Lines(c, "helpdesk"); !reflect.DeepEqual(got, []string{"show|deny|c", "show|permit|a", "show|permit|b", "*|deny|"}) {
		t.Errorf("helpdesk: %q", got)
	}
	before := file(t, path)
	err := InsertRuleAt(c, "helpdesk", "x", "permit", "", Where{Before: "missing"})
	var nr *NoRuleError
	if !errors.As(err, &nr) || err.Error() != "No rule named 'missing' in group 'helpdesk'." {
		t.Errorf("missing: %v", err)
	}
	if file(t, path) != before {
		t.Error("a refused insert wrote")
	}
}

func TestRemoveRuleWhere(t *testing.T) {
	const yaml = "commands:\n  operator:\n" +
		"  - {name: show, action: deny, match: ['^crypto( .*)?']}\n" +
		"  - {name: show, action: permit, match: [a, b]}\n" +
		"  - {name: show, action: permit}\n" +
		"  - {name: ping, action: permit}\n" +
		"  - {name: '*', action: deny}\n"
	for _, tc := range []struct {
		name    string
		matches []string
		action  string
		all     bool
		gone    []Numbered
		ambig   int
	}{
		{name: "ambiguous", ambig: 3},
		{name: "ambiguous by action", action: "permit", ambig: 2},
		{name: "by match", matches: []string{"^crypto( .*)?"}, gone: []Numbered{{1, "show|deny|^crypto( .*)?"}}},
		{name: "by match list", matches: []string{"a", "b"}, gone: []Numbered{{2, "show|permit|a,b"}}},
		{name: "match order counts", matches: []string{"b", "a"}},
		{name: "by action", action: "deny", gone: []Numbered{{1, "show|deny|^crypto( .*)?"}}},
		{name: "all", all: true, gone: []Numbered{{1, "show|deny|^crypto( .*)?"}, {2, "show|permit|a,b"}, {3, "show|permit|"}}},
		{name: "all of a selection", action: "permit", all: true, gone: []Numbered{{2, "show|permit|a,b"}, {3, "show|permit|"}}},
		{name: "none", action: "deny", matches: []string{"a", "b"}},
	} {
		c, path := newConf(t, yaml)
		before := file(t, path)
		gone, err := RemoveRuleWhere(c, "operator", "show", tc.matches, tc.action, tc.all)
		var amb *AmbiguousError
		switch {
		case tc.ambig > 0:
			if !errors.As(err, &amb) || amb.Count != tc.ambig {
				t.Errorf("%s: %v", tc.name, err)
			}
		case err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case !reflect.DeepEqual(gone, tc.gone):
			t.Errorf("%s: removed %v, want %v", tc.name, gone, tc.gone)
		}
		if len(tc.gone) == 0 {
			if file(t, path) != before {
				t.Errorf("%s: wrote with nothing removed", tc.name)
			}
			continue
		}
		left := Lines(c, "operator")
		if len(left) != 5-len(tc.gone) || left[len(left)-1] != "*|deny|" {
			t.Errorf("%s: left %q", tc.name, left)
		}
	}
	err := (&AmbiguousError{Group: "operator", Name: "show", Count: 2}).Error()
	if err != "Group 'operator' has 2 rules named 'show'; select one with --match/--action (see 'tacctl group commands list operator'), or pass --all." {
		t.Errorf("message: %s", err)
	}
}

// The line round trip of 0.1.16: a match holding a comma comes back split.
func TestCommaInMatchIsSplitOnWrite(t *testing.T) {
	c, _ := newConf(t, "")
	if err := InsertRule(c, "operator", "show", "permit", "a{1,3}"); err != nil {
		t.Fatal(err)
	}
	if got := Lines(c, "operator"); got[4] != "show|permit|a{1,3}" {
		t.Errorf("lines: %q", got)
	}
	v, _ := c.Value("commands.operator")
	if got := len(v.([]any)); got != 6 {
		t.Fatalf("%d rules", got)
	}
	m, _ := c.GetJSON("commands.operator")
	if !strings.Contains(m, `"match": ["a{1", "3}"]`) {
		t.Errorf("match not split: %s", m)
	}
}

func TestWriteEmptyUnsetsAndSkipsBlankLines(t *testing.T) {
	c, path := newConf(t, "commands:\n  helpdesk:\n  - {name: '*', action: permit}\n")
	if err := Write(c, "helpdesk", []string{"", "  ", "show|deny|", "ping", "*"}); err != nil {
		t.Fatal(err)
	}
	if got := Lines(c, "helpdesk"); !reflect.DeepEqual(got, []string{"show|deny|", "ping|permit|", "*|permit|"}) {
		t.Errorf("lines: %q", got)
	}
	if err := Write(c, "helpdesk", []string{"\n"}); err != nil {
		t.Fatal(err)
	}
	if file(t, path) != "" || Lines(c, "helpdesk") != nil {
		t.Errorf("not unset: %q", file(t, path))
	}
}

func TestSeedSiblings(t *testing.T) {
	c, _ := newConf(t, "")
	groups := GroupLevels{"readonly|1|RO", "operator|7|OP", "superuser|15|RW", "helpdesk|7|HD", "netops|7|NO"}
	lvl, seeded, err := SeedSiblings(c, groups, "netops")
	if err != nil || lvl != "7" || !reflect.DeepEqual(seeded, []string{"helpdesk"}) {
		t.Errorf("netops: %q %q %v", lvl, seeded, err)
	}
	if got := Lines(c, "helpdesk"); !reflect.DeepEqual(got, []string{"*|permit|"}) {
		t.Errorf("helpdesk: %q", got)
	}
	// Again: everyone at 7 has rules now (netops is the one asking).
	if _, seeded, _ := SeedSiblings(c, groups, "netops"); seeded != nil {
		t.Errorf("seeded twice: %q", seeded)
	}
	if lvl, seeded, _ := SeedSiblings(c, groups, "nosuch"); lvl != "" || seeded != nil {
		t.Errorf("unknown group: %q %q", lvl, seeded)
	}
}

func TestDefaultRules(t *testing.T) {
	c, path := newConf(t, "")
	for _, g := range Builtins {
		if ok, err := ApplyDefaultRules(c, g); !ok || err != nil {
			t.Fatalf("%s: %v %v", g, ok, err)
		}
	}
	if got := Lines(c, "superuser"); !reflect.DeepEqual(got, []string{"*|permit|"}) {
		t.Errorf("superuser: %q", got)
	}
	ro := Lines(c, "readonly")
	if len(ro) != 12 || ro[0] != "show|permit|" || ro[11] != "*|deny|" {
		t.Errorf("readonly: %q", ro)
	}
	if !strings.Contains(file(t, path), "  operator:\n  - name: show\n") {
		t.Errorf("file:\n%s", file(t, path))
	}
	if ok, _ := ApplyDefaultRules(c, "helpdesk"); ok {
		t.Error("helpdesk has a seed set")
	}
	if a, p, ok := DefaultRules("operator"); a != "deny" || len(p) != 14 || p[13] != "monitor" || !ok {
		t.Errorf("operator seed: %q %q %v", a, p, ok)
	}
	if _, _, ok := DefaultRules("helpdesk"); ok {
		t.Error("DefaultRules(helpdesk)")
	}
}

func TestPrivileges(t *testing.T) {
	c, path := newConf(t, "")
	def := DefaultPrivileges("operator")
	if len(def) != 6 || def[0] != "show running-config" {
		t.Errorf("defaults: %q", def)
	}
	if DefaultPrivileges("readonly") == nil || len(DefaultPrivileges("readonly")) != 0 {
		t.Error("readonly defaults")
	}
	if got := Privileges(c, "operator"); !reflect.DeepEqual(got, def) {
		t.Errorf("merged: %q", got)
	}
	if err := WritePrivileges(c, "operator", append(def, "", "show version")); err != nil {
		t.Fatal(err)
	}
	if got := Privileges(c, "operator"); len(got) != 7 || got[6] != "show version" || !c.HasOverride("privileges.operator") {
		t.Errorf("after write: %q", got)
	}
	if err := WritePrivileges(c, "operator", def); err != nil {
		t.Fatal(err)
	}
	if file(t, path) != "" {
		t.Errorf("default not pruned:\n%s", file(t, path))
	}
}

func TestHealDeadMatches(t *testing.T) {
	text := `commands:
  operator:
  - {name: show, action: permit, match: ['^show .*$']}
  - {name: ping, action: permit}
  - {name: traceroute, action: permit}
  - {name: terminal, action: permit}
  - {name: '*', action: deny}
  helpdesk:
  - {name: show, action: permit, match: ['^show .*$', 'version']}
  - {name: '*', action: deny}
  readonly:
  - {name: show, action: permit, match: ['running-config']}
  - {name: '*', action: deny}
  other: nope
`
	c, path := newConf(t, text)
	healed, err := HealDeadMatches(c)
	if err != nil {
		t.Fatal(err)
	}
	want := []Healed{{Group: "helpdesk"}, {Group: "operator", Dropped: true}}
	if !reflect.DeepEqual(healed, want) {
		t.Errorf("healed %+v", healed)
	}
	if healed[1].Message() != "Dropped commands.operator override: its match regexes could never fire; shipped defaults now apply" ||
		healed[0].Message() != "Rewrote commands.helpdesk override: removed match regexes that could never fire" {
		t.Error("messages")
	}
	if got := Lines(c, "helpdesk"); !reflect.DeepEqual(got, []string{"show|permit|version", "*|deny|"}) {
		t.Errorf("helpdesk: %q", got)
	}
	if c.HasOverride("commands.operator") || !c.HasOverride("commands.readonly") {
		t.Errorf("file:\n%s", file(t, path))
	}
	// Idempotent.
	if again, err := HealDeadMatches(c); err != nil || again != nil {
		t.Errorf("second run: %+v %v", again, err)
	}
	// An unreadable file is left alone.
	c, _ = newConf(t, "commands: [\n")
	if healed, err := HealDeadMatches(c); healed != nil || err != nil {
		t.Errorf("bad file: %+v %v", healed, err)
	}
}
