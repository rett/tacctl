package cli

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/tier"
)

// -h and --help are recognised after the words of a command, and only there.
func TestHelpRequest(t *testing.T) {
	_, root, _ := shellTestInv(t)
	for _, c := range []struct {
		args []string
		want []string // nil: not a help request
	}{
		{[]string{"user", "--help"}, []string{"user"}},
		{[]string{"user", "-h"}, []string{"user"}},
		{[]string{"user", "add", "--help"}, []string{"user", "add"}},
		{[]string{"device", "config", "pull", "-h"}, []string{"device", "config", "pull"}},
		{[]string{"user", "add", "alice", "--help"}, []string{"user", "add", "alice"}},
		{[]string{"shell", "--idle", "5", "-h"}, []string{"shell", "--idle", "5"}},
		// the top level keeps its usage and exit status
		{[]string{"--help"}, nil},
		{[]string{"-h"}, nil},
		{[]string{"-h", "user"}, nil},
		{[]string{"help", "--help"}, nil},
		// not the last word, or after the end of the options
		{[]string{"user", "--help", "add"}, nil},
		{[]string{"log", "search", "--", "-h"}, nil},
		// the value of a flag that waits for one
		{[]string{"shell", "--idle", "--help"}, nil},
		{[]string{"shell", "-c", "--help"}, nil},
		// hidden and underscore commands
		{[]string{"__complete", "user", "--help"}, nil},
		{[]string{"_console-policy", "--help"}, nil},
		{[]string{"nosuchcommand", "--help"}, nil},
	} {
		got, ok := helpRequest(root, c.args)
		if ok != (c.want != nil) || !slices.Equal(got, c.want) {
			t.Errorf("helpRequest(%q) = %q, %v; want %q", c.args, got, ok, c.want)
		}
	}
}

// No flag of any verb is -h or --help, so the words never collide with one.
func TestNoVerbHasAHelpFlag(t *testing.T) {
	_, root, _ := shellTestInv(t)
	paths, _ := visibleLeaves(root)
	for _, p := range paths {
		spec, ok := specFor(p)
		if !ok {
			continue
		}
		for _, f := range spec.Flags {
			for _, n := range f.Names {
				if n == "-h" || n == "--help" {
					t.Errorf("%v has the flag %s", p, n)
				}
			}
		}
	}
}

// 'tacctl <words> --help' prints the help as the user, without sudo, exit 0:
// the sub-commands of a family, the usage of a verb.
func TestHelpPrintsTheList(t *testing.T) {
	for _, c := range []struct {
		args []string
		want []string
		not  []string
	}{
		{[]string{"user", "--help"}, []string{"Possible completions:\n", "  add <username> <group>  ", "  scope <user> list|add|remove|replace  "}, []string{"Usage:", "Next:"}},
		{[]string{"user", "-h"}, []string{"Possible completions:\n", "  list  "}, nil},
		{[]string{"user", "add", "--help"}, []string{"Usage:\n", "Options:\n", "  --hash <hash>  ", "  --scopes <s>[,s...]  ", "Next: <username> <group>\n"}, []string{"Possible completions:"}},
		{[]string{"device", "config", "pull", "--help"}, []string{"Usage:\n", "Options:\n"}, nil},
		// a verb that takes a name: the usage, not the names of the store
		{[]string{"user", "show", "--help"}, []string{"Usage:\n", "  show <username>  "}, []string{"alice", "Possible completions:"}},
	} {
		h := newHarness(t, c.args)
		h.app.Paths.SkipSudo = false // runs as the user: no sudo, no tier gate
		h.app.EUID = 1000
		if err := h.run(); err != nil {
			t.Errorf("%v: %v", c.args, err)
			continue
		}
		if sudo := h.runner.Calls(); len(sudo) > 0 {
			t.Errorf("%v: ran %v", c.args, sudo)
		}
		out := stripSGRString(h.out.String())
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: no %q in\n%s", c.args, w, out)
			}
		}
		for _, w := range c.not {
			if strings.Contains(out, w) {
				t.Errorf("%v: %q in\n%s", c.args, w, out)
			}
		}
	}
}

func stripSGRString(s string) string {
	return regexp.MustCompile("\x1b\\[[0-9;]*m").ReplaceAllString(s, "")
}

// The help is written with its colours, which a pipe, NO_COLOR and
// TACCTL_COLOR=never take out (the stream, as for every other output).
func TestHelpIsPlainWhenPiped(t *testing.T) {
	for _, c := range []struct {
		env  []string
		want bool
	}{
		{nil, true}, // a buffer is taken as a terminal that shows colour
		{[]string{"NO_COLOR=1"}, false},
		{[]string{"TACCTL_COLOR=never"}, false},
		{[]string{"TACCTL_COLOR=always"}, true},
	} {
		h := newHarness(t, []string{"user", "--help"}, c.env...)
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		_ = h.app.Close()
		if got := strings.Contains(h.out.String(), "\x1b["); got != c.want {
			t.Errorf("%v: colour %v, want %v", c.env, got, c.want)
		}
	}
}

// In the shell, '<words> --help' follows the tier's view as '?' does: a
// readonly caller is not offered 'user add', and a family the tier cannot
// run is answered with the tier it needs.
func TestHelpInTheShellFollowsTheView(t *testing.T) {
	inv, root, _ := shellTestInv(t)
	out := inv.app.Out.Stdout.(*bytes.Buffer)
	inv.view = func() tier.Tier { return tier.Readonly }
	inv.helpList(root, []string{"user"})
	got := stripSGRString(out.String())
	if !strings.Contains(got, "  list") || strings.Contains(got, "  add ") {
		t.Errorf("user --help for a readonly caller:\n%s", got)
	}
	out.Reset()
	inv.helpList(root, []string{"config"})
	if got := stripSGRString(out.String()); !strings.HasPrefix(got, "Needs the ") || !strings.Contains(got, "help config describes it.") {
		t.Errorf("config --help for a readonly caller:\n%s", got)
	}
	out.Reset()
	inv.view = func() tier.Tier { return tier.Superuser }
	inv.helpList(root, []string{"user"})
	if got := stripSGRString(out.String()); !strings.Contains(got, "  add <username> <group>") {
		t.Errorf("user --help for a superuser:\n%s", got)
	}
}

// The text of '?' and of '--help' is one text: the same bytes for a family
// and for a verb, in a real shell on a terminal.
func TestPtyHelpIsWhatQuestionMarkPrints(t *testing.T) {
	s := startCLIShell(t, 120, shellPtyViewPrefix+"superuser")
	body := func(out string) string {
		out = strings.ReplaceAll(out, "\r\n", "\n")
		out = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]").ReplaceAllString(out, "")
		for _, mark := range []string{"Possible completions:\n", "Usage:\n"} {
			if _, after, ok := strings.Cut(out, mark); ok {
				text, _, _ := strings.Cut(mark+after, "tacctl> ")
				return text
			}
		}
		return out
	}
	for _, prefix := range []string{"user", "device config", "user add", "console password-cache max", "version"} {
		if err := s.Send("\x15" + prefix + " ?"); err != nil {
			t.Fatal(err)
		}
		q := body(s.Settle(500 * time.Millisecond))
		if err := s.Send("\x15" + prefix + " --help\r"); err != nil {
			t.Fatal(err)
		}
		h := body(s.Settle(500 * time.Millisecond))
		if q == "" || q != h {
			t.Errorf("%s: '?' printed\n%q\n--help printed\n%q", prefix, q, h)
		}
		// -h too
		if err := s.Send(prefix + " -h\r"); err != nil {
			t.Fatal(err)
		}
		if h2 := body(s.Settle(500 * time.Millisecond)); h2 != h {
			t.Errorf("%s: -h printed\n%q\nnot\n%q", prefix, h2, h)
		}
	}
}

// helpOnlyWords are the words '__help' is tried with: verbs that change
// state, flags that wait for a value, '--', hidden commands, the help flags,
// nothing at all.
var helpOnlyWords = [][]string{
	nil, {"user"}, {"user", "add"}, {"user", "remove", "alice", "--yes"},
	{"breakglass", "hold", "sw1", "--reason"}, {"breakglass", "hold", "sw1", "--reason", "why"},
	{"install", "-y", "--branch"}, {"uninstall", "-y"}, {"upgrade"}, {"rollback", "0.2.18", "--apply", "--yes"},
	{"store", "import", "--force"}, {"log", "clear", "--"}, {"log", "search", "--", "--help"},
	{"user", "add", "--help"}, {"--help"}, {"-h"}, {"__help"}, {"__complete", "user"}, {"_console-policy"},
	{"_completion-names", "users"}, {"shell", "-c", "user list"}, {"nosuch", "--x"},
}

// poisonTree replaces the run function of every command of the tree but
// __help by one that fails the test, and counts the calls.
func poisonTree(t *testing.T, root *cobra.Command) *int {
	t.Helper()
	fired := new(int)
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Name() != "__help" {
			name := c.CommandPath()
			c.RunE = func(*cobra.Command, []string) error {
				*fired++
				t.Errorf("__help ran %s", name)
				return nil
			}
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return fired
}

// '__help' is the one thing the bash help key runs: with any words it prints
// and runs nothing else. Every other command of the tree is made to fail the
// test if it runs, and the runner records no call. First straight at the
// command, over every command with every flag as the last word.
func TestHelpOnlyRunsNoVerb(t *testing.T) {
	inv, root, runner := shellTestInv(t)
	fired := poisonTree(t, root)
	help := child(root, "__help")
	if help == nil || !help.Hidden || help.RunE == nil {
		t.Fatalf("__help: %+v", help)
	}
	var out *bytes.Buffer
	run := func(words ...string) string {
		t.Helper()
		out = inv.app.Out.Stdout.(*bytes.Buffer)
		out.Reset()
		before := len(runner.Calls()) + len(runner.Execs())
		if err := help.RunE(help, append([]string{"--"}, words...)); err != nil {
			t.Errorf("__help %q: %v", words, err)
		}
		if after := len(runner.Calls()) + len(runner.Execs()); after != before {
			t.Errorf("__help %q ran %d program(s)", words, after-before)
		}
		return stripSGRString(out.String())
	}
	for _, words := range helpOnlyWords {
		got := run(words...)
		if got == "" {
			t.Errorf("__help %q printed nothing", words)
		}
		if strings.Contains(got, "[ERROR]") {
			t.Errorf("__help %q: %s", words, got)
		}
	}
	// A first '--' is the end of the options, not a word of the path; without
	// one the words are taken as they are.
	out = inv.app.Out.Stdout.(*bytes.Buffer)
	out.Reset()
	if err := help.RunE(help, []string{"user", "add"}); err != nil || !strings.Contains(stripSGRString(out.String()), "Options:") {
		t.Errorf("without --: %v %q", err, out.String())
	}
	// A hidden command has no help to show.
	if got := run("_console-policy"); got != "No valid completions\n" {
		t.Errorf("hidden: %q", got)
	}
	// Every command of the tree, with each of its flags as the last word.
	var all [][]string
	commandPaths(root, nil, &all)
	for _, p := range all {
		if spec, ok := specFor(p); ok {
			for _, f := range spec.Flags {
				run(append(slices.Clone(p), f.Names[0])...)
			}
		}
		run(p...)
	}
	if *fired != 0 {
		t.Errorf("%d command(s) ran", *fired)
	}
}

// The same through the normal path (Run: the re-exec check, the dispatch, the
// audit lines), for the same words: the run functions of the tree the run
// built are replaced (the treeBuilt hook), none fires, the fake runner
// executes nothing, and the words are printed as help.
func TestHelpOnlyRunsNoVerbThroughRun(t *testing.T) {
	for _, words := range helpOnlyWords {
		h := newHarness(t, append([]string{"__help", "--"}, words...))
		h.app.EUID = 1000
		h.app.Paths.SkipSudo = false
		var fired *int
		h.hooks.treeBuilt = func(root *cobra.Command) { fired = poisonTree(t, root) }
		if err := h.run(); err != nil {
			t.Errorf("__help -- %q: %v", words, err)
		}
		if fired == nil || *fired != 0 {
			t.Errorf("__help -- %q: the tree was not seen or a command ran (%v)", words, fired)
		}
		if len(h.runner.Calls()) != 0 || len(h.runner.Execs()) != 0 {
			t.Errorf("__help -- %q ran %v %v", words, h.runner.Calls(), h.runner.Execs())
		}
		if out := stripSGRString(h.out.String()); out == "" || strings.Contains(out, "[ERROR]") || h.err.Len() != 0 {
			t.Errorf("__help -- %q: out %q err %q", words, out, h.err.String())
		}
	}
}

// help_request.go may call only the renderers of the lists, never a verb. The
// two tests above replace the run functions of the tree, which catches a
// dispatch through the tree but not a direct Go call from the help code to a
// verb's method (inv.shell, inv.console ...), which would bypass them. So the
// calls in the file are held to a list of the functions that read the tree
// and the usage blocks and render text; a new call is a decision to be made
// here, by a reviewer, not a side effect.
func TestHelpRequestCallsOnlyRenderers(t *testing.T) {
	allowed := map[string]bool{
		// builtins and the standard library
		"len": true, "append": true, "io.WriteString": true,
		"slices.Contains": true, "slices.ContainsFunc": true, "strings.HasPrefix": true,
		// the tree and the usage text
		"shellCommand": true, "specFor": true, "waitsForValue": true, "hidden": true, "child": true,
		"inv.shellCompleter": true, "inv.shellExplain": true, "cmd.Commands": true, "c.Commands": true,
		"cmd.Root": true, "inv.helpList": true,
		// the renderer and the terminal's width
		"shell.Candidates": true, "shell.HelpText": true, "ui.File": true, "term.IsTerminal": true,
		"term.GetSize": true, "f.Fd": true, "int": true,
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "help_request.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			if x, ok := fn.X.(*ast.Ident); ok {
				name = x.Name + "." + fn.Sel.Name
			} else {
				name = "(expr)." + fn.Sel.Name
			}
		default:
			return true // a function literal, a conversion
		}
		seen[name] = true
		if !allowed[name] {
			t.Errorf("help_request.go calls %s at %s: the help may call only renderers (see the test)", name, fset.Position(call.Pos()))
		}
		return true
	})
	// The list is not a dead one.
	for _, must := range []string{"shell.HelpText", "inv.shellExplain", "shellCommand"} {
		if !seen[must] {
			t.Errorf("help_request.go no longer calls %s: update the test", must)
		}
	}
}

// '__help' is a word of the tree that runs as the user, with no sudo and no
// gate, and prints the list of '?' for the words after it.
func TestHelpOnlyEntryPoint(t *testing.T) {
	h := newHarness(t, []string{"__help", "--", "breakglass", "hold", "sw1", "--reason"})
	h.app.EUID = 1000
	h.app.Paths.SkipSudo = false
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if len(h.runner.Calls()) != 0 || len(h.runner.Execs()) != 0 {
		t.Errorf("ran %v %v", h.runner.Calls(), h.runner.Execs())
	}
	out := stripSGRString(h.out.String())
	if !strings.Contains(out, "Usage:\n") || !strings.Contains(out, "--reason <text>") || strings.Contains(out, "[ERROR]") || h.err.Len() != 0 {
		t.Errorf("out %q err %q", out, h.err.String())
	}
	// The same text '?' prints at that place.
	inv, root, _ := shellTestInv(t)
	want, _ := inv.plainExplain(root)([]string{"breakglass", "hold", "sw1", "--reason"})
	if out != want {
		t.Errorf("__help\n%q\n'?'\n%q", out, want)
	}
}
