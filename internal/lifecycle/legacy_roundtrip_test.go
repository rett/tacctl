package lifecycle_test

// WP10.8a B11/C18: the legacy importer reads back what 0.2.3 writes.

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/lifecycle"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// block is the operator block of a rendered tacquito.yaml.
func operatorBlockOf(t *testing.T, text string) string {
	t.Helper()
	i := strings.Index(text, "operator: &operator\n")
	if i < 0 {
		t.Fatal("no operator block")
	}
	rest := text[i:]
	j := strings.Index(rest, "\n  accounter:")
	if j < 0 {
		t.Fatal("no end of the operator block")
	}
	return rest[:j]
}

// render -> legacy import -> render: a command rule written by the renderer
// (every regex as ^(?:regex)$, in a double-quoted scalar with its escapes)
// comes back from an install without a store byte for byte, compiles, and
// renders to the same block again.
func TestLegacyImportReadsBackWhatTheRendererWrites(t *testing.T) {
	regexes := []string{
		`(?:a)|(?:b)`,             // a bare alternation of groups: the wrapper's ends are not its own
		`^(?:x)$`,                 // already wrapped by the operator
		`a\|b`,                    // an escaped bar
		`[|]x( .*)?`,              // a bar in a class
		`^foo\$`,                  // a trailing escaped dollar
		`say "hi" now`,            // quotes
		`h\x{e9}llo`,              // an escape a regex takes
		"h\u00e9llo \u65e5\u672c", // characters outside Latin-1, written as \u escapes
		`a[]]b`,                   // a bracket in a class
		`^(crypto|trace)( .*)?$`,
		`back\\slash`,
	}
	e := newTenv(t)
	st, err := store.Load("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rule := func(name, action string, match ...string) *yamlpy.Map {
		m := yamlpy.NewMap()
		m.Set("name", name)
		m.Set("action", action)
		if len(match) > 0 {
			l := make([]any, len(match))
			for i, x := range match {
				l[i] = x
			}
			m.Set("match", l)
		}
		return m
	}
	var rules []any
	for _, rx := range regexes {
		rules = append(rules, rule("debug", "permit", rx))
	}
	rules = append(rules, rule("many", "deny", regexes...), rule("*", "deny"))
	if err := e.be.Conf.SetValue("commands.operator", rules); err != nil {
		t.Fatal(err)
	}
	first, err := rtacacs.RenderToFile(st, e.be.Conf.Merged(), e.p.Config, rtacacs.DefaultLoader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(first), `"^(?:(?:a)|(?:b))$"`) {
		t.Fatalf("the renderer does not wrap the alternation as expected:\n%s", operatorBlockOf(t, string(first)))
	}

	// An install without a store, without the override.
	if err := e.be.Conf.Unset("commands.operator"); err != nil {
		t.Fatal(err)
	}
	e.be.Conf.Reload()
	if err := lifecycle.MigrateCommandRules(e.env); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "Migrated tacquito.yaml commands: block for group 'operator' → commands.operator")
	hasNot(t, e.output(), "could not be read")

	var got []struct {
		Name  string   `json:"name"`
		Match []string `json:"match"`
	}
	if err := json.Unmarshal([]byte(e.commandsJSON("operator")), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(regexes)+2 {
		t.Fatalf("%d rules back, want %d:\n%s", len(got), len(regexes)+2, e.commandsJSON("operator"))
	}
	for i, rx := range regexes {
		if len(got[i].Match) != 1 || got[i].Match[0] != rx {
			t.Errorf("rule %d: back %q, stored %q", i, got[i].Match, rx)
		}
		if _, err := regexp.Compile(rx); err != nil {
			t.Fatalf("the test regex %q does not compile: %v", rx, err)
		}
	}
	// One rule with every regex.
	if strings.Join(got[len(regexes)].Match, "\x00") != strings.Join(regexes, "\x00") {
		t.Errorf("the rule with all of them: back %q", got[len(regexes)].Match)
	}

	// Render again from what came back: the same block, byte for byte.
	e.be.Conf.Reload()
	second, err := rtacacs.RenderToFile(st, e.be.Conf.Merged(), e.p.Config+".2", rtacacs.DefaultLoader, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a, b := operatorBlockOf(t, string(first)), operatorBlockOf(t, string(second)); a != b {
		t.Errorf("the second render differs:\n--- first\n%s\n--- second\n%s", a, b)
	}
}

// A file written before 0.2.3 has the operator's regex as it stands between
// ^ and $; taking its ends for the wrapper of 0.2.3 would split a group.
func TestUnwrapMatchOnlyUnwrapsWhatTheWrapperMade(t *testing.T) {
	for in, want := range map[string]string{
		`^(?:a)|(?:b)$`:     `^(?:a)|(?:b)$`, // not a wrapper: a)|(?:b is no regex
		`^(?:a)(?:b)$`:      `^(?:a)(?:b)$`,
		`^(?:a|b)$`:         `a|b`,
		`^(?:^(?:x)$)$`:     `^(?:x)$`,
		`^(?:a\)|b)$`:       `a\)|b`,
		`^(?:[)]|b)$`:       `[)]|b`,
		`^(?:(?:a)|(?:b))$`: `(?:a)|(?:b)`,
		`plain`:             `plain`,
		`^(?:)$`:            ``,
		`^(?:a$`:            `^(?:a$`,
		`^(?:[a)$`:          `^(?:[a)$`,
		`^(?:(unclosed)$`:   `^(?:(unclosed)$`,
		"^(?:h\u00e9llo)$":  "h\u00e9llo",
		`^(?:say "hi")$`:    `say "hi"`,
		`^(?:\)$`:           `^(?:\)$`,
		`^(?:a)b)$`:         `^(?:a)b)$`,
	} {
		if got := rtacacs.UnwrapMatch(in); got != want {
			t.Errorf("UnwrapMatch(%q) = %q, want %q", in, got, want)
		}
	}
}
