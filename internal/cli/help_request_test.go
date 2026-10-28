package cli

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

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
