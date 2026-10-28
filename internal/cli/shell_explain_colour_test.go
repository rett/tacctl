package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/ui"
)

// plainExplain is shellExplain with the colour taken out: the text the
// tests of the lists compare.
func (inv *invocation) plainExplain(root *cobra.Command) func([]string) (string, bool) {
	explain := inv.shellExplain(root)
	return func(words []string) (string, bool) {
		text, ok := explain(words)
		return regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(text, ""), ok
	}
}

var reColour = regexp.MustCompile("\x1b\\[[0-9;]*m")

// The usage, option and Next: lines are in the palette: the name of a
// command of the top level bright white, sub-commands, fixed words and
// options teal, placeholders and descriptions as they are; with the colour
// taken out the text is the plain one, column for column.
func TestExplainPalette(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	explain := inv.shellExplain(root)
	for _, c := range []struct {
		words []string
		want  []string
	}{
		{[]string{"version"}, []string{
			"  " + ui.BrightWhite + "version" + ui.NC + " " + ui.Teal + "[--long]" + ui.NC + "  Print tacctl version",
			"  " + ui.Teal + "--long" + ui.NC + "  Also the commit",
			"Next: <Enter> to run\n"}},
		{[]string{"user", "add"}, []string{
			"  " + ui.Teal + "add" + ui.NC + " <username> <group> " + ui.Teal + "--hash" + ui.NC + " <hash>  ",
			"  " + ui.Teal + "--hash" + ui.NC + " <hash>  ",
			"Next: <username> <group>\n"}},
		{[]string{"user", "scope"}, []string{
			"  " + ui.Teal + "scope" + ui.NC + " <user> " + ui.Teal + "list|add|remove|replace" + ui.NC + "  Manage",
			"Next: <user> " + ui.Teal + "list|add|remove|replace" + ui.NC + "\n"}},
		{[]string{"group", "edit", "ops"}, []string{"Next: " + ui.Teal + "priv-lvl|"}},
	} {
		got, ok := explain(c.words)
		if !ok {
			t.Errorf("%v: nothing", c.words)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%v: no %q in\n%q", c.words, w, got)
			}
		}
		// The descriptions are plain: no sequence after the two blanks that
		// start one.
		for _, l := range strings.Split(got, "\n") {
			if _, d, ok := splitRow(l); ok && strings.Contains(d, "\x1b[") {
				t.Errorf("%v: the description of %q has colour", c.words, l)
			}
		}
	}
	// Every leaf: the plain text is what the plain renderer gives, and the
	// columns of the colour text are those of the plain text.
	paths, _ := visibleLeaves(root)
	checked := 0
	for _, p := range paths {
		got, ok := explain(p)
		if !ok {
			continue
		}
		checked++
		plain := reColour.ReplaceAllString(got, "")
		for i, l := range strings.Split(got, "\n") {
			pl := strings.Split(plain, "\n")[i]
			if reColour.ReplaceAllString(l, "") != pl {
				t.Errorf("%v: line %d differs", p, i)
			}
		}
		if strings.Count(got, ui.NC) != strings.Count(got, "\x1b[36m")+strings.Count(got, "\x1b[97m") {
			t.Errorf("%v: a style is not closed:\n%q", p, got)
		}
	}
	if checked < 200 {
		t.Errorf("only %d commands checked", checked)
	}
}

// The candidates say what a word is: the top level's commands are command
// names, the rest of the language fixed words, the names of the store live
// names.
func TestCandidateClasses(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	complete := inv.shellCompleter(root)
	top := complete(nil, "")
	if len(top) < 20 {
		t.Fatalf("%d commands", len(top))
	}
	for _, c := range top {
		if !c.Command || c.Live || !c.Fixed {
			t.Errorf("top level %q: %+v", c.Word, c)
		}
	}
	for _, c := range complete([]string{"user"}, "") {
		if c.Command || c.Live || !c.Fixed {
			t.Errorf("user %q: %+v", c.Word, c)
		}
	}
	names := complete([]string{"user", "show"}, "")
	if len(names) != 3 {
		t.Fatalf("user show: %+v", names)
	}
	for _, c := range names {
		if !c.Live || c.Command || c.Fixed {
			t.Errorf("user show %q: %+v", c.Word, c)
		}
	}
	for _, c := range complete([]string{"user", "add", "alice", "ops"}, "-") {
		if c.Live || c.Command || !c.Fixed {
			t.Errorf("flag %q: %+v", c.Word, c)
		}
	}
	for _, c := range complete([]string{"user", "scope", "alice"}, "") {
		if c.Live || c.Command || !c.Fixed {
			t.Errorf("fixed word %q: %+v", c.Word, c)
		}
	}
}

// '--help' prints the palette; piped, with NO_COLOR or TACCTL_COLOR=never,
// the same text without it; the live names '?' lists are bold.
func TestHelpColours(t *testing.T) {
	out := func(env []string, args ...string) string {
		h := newHarness(t, args, env...)
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		h.app.Close()
		return h.out.String()
	}
	coloured := out([]string{"TACCTL_COLOR=always"}, "user", "--help")
	if !strings.Contains(coloured, "  "+ui.Teal+"add"+ui.NC+" <username> <group>") || !strings.Contains(coloured, "Possible completions:\n") {
		t.Errorf("--help:\n%q", coloured)
	}
	for _, env := range [][]string{{"NO_COLOR=1"}, {"TACCTL_COLOR=never"}} {
		if plain := out(env, "user", "--help"); plain != reColour.ReplaceAllString(coloured, "") {
			t.Errorf("%v: plain help differs:\n%q", env, plain)
		}
	}
	// A list of names: bold, with their columns.
	inv, root, _ := shellTestInv(t)
	cands := shell.Candidates(inv.shellCompleter(root), []string{"user", "show"}, "")
	text := shell.HelpText(cands, "", false, true, 80)
	for _, n := range []string{"alice", "albert", "bob"} {
		if !strings.Contains(text, "  "+ui.Bold+n+ui.NC) {
			t.Errorf("%s is not bold:\n%q", n, text)
		}
	}
	if reColour.ReplaceAllString(text, "") != shell.HelpText(cands, "", false, false, 80) {
		t.Error("bold names change the columns")
	}
}
