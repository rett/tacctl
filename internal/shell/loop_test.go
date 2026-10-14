package shell

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/ui"
)

// fakeShell is a shell whose commands are recorded: a command's status is
// the number after 'status' ('status 3'), else 0.
type fakeShell struct {
	sh       *Shell
	ran      [][]string
	stdin    []io.Reader
	out, err bytes.Buffer
}

func newFakeShell(hist *History) *fakeShell {
	f := &fakeShell{}
	f.sh = New(Options{
		Out:     ui.Output{Stdout: &f.out, Stderr: &f.err},
		History: hist,
		Help: func(words []string) (string, bool) {
			if len(words) == 0 || words[0] == "user" {
				return "usage of " + strings.Join(words, " ") + "\n", true
			}
			return "", false
		},
		Exec: func(_ context.Context, words []string, stdin io.Reader) int {
			f.ran = append(f.ran, words)
			f.stdin = append(f.stdin, stdin)
			if len(words) > 1 && words[0] == "status" {
				n := 0
				for _, c := range words[1] {
					n = n*10 + int(c-'0')
				}
				return n
			}
			return 0
		},
	})
	return f
}

func TestBatchStopsAtTheFirstFailure(t *testing.T) {
	cases := []struct {
		script string
		status int
		ran    int
	}{
		{"user list\nbogus\nuser list\n", 0, 3},
		{"user list\nstatus 1\nuser list\n", 1, 2},
		{"status 3\nuser list\n", 3, 1},
		{"user list\n\n   \nuser list", 0, 2},
		{"user list\r\nstatus 0\r\n", 0, 2},
		{"user list\nexit\nuser list\n", 0, 1},
		{"user list\nquit now\nuser list\n", 2, 1},
		{"user 'unterminated\nuser list\n", 2, 0},
		{"help\nhelp user\nuser list\n", 0, 1},
		{"help nothing\nuser list\n", 1, 0},
		{"history\nuser list\n", 0, 1},
		{"user list " + strings.Repeat("x", LineMax) + "\nuser list\n", 2, 0},
		{"user set …(redacted)\n", 2, 0},
	}
	for _, c := range cases {
		f := newFakeShell(nil)
		got := f.sh.Batch(context.Background(), strings.NewReader(c.script))
		if got != c.status || len(f.ran) != c.ran {
			t.Errorf("%q: status %d, ran %q; want %d, %d lines (stderr %q)", c.script, got, f.ran, c.status, c.ran, f.err.String())
		}
		for _, in := range f.stdin {
			if in != nil {
				t.Errorf("%q: a batch command got stdin", c.script)
			}
		}
	}
}

func TestBatchStopsWhenCancelled(t *testing.T) {
	f := newFakeShell(nil)
	ctx, cancel := context.WithCancel(context.Background())
	f.sh.o.Exec = func(context.Context, []string, io.Reader) int { cancel(); return 0 }
	if got := f.sh.Batch(ctx, strings.NewReader("user list\nuser list\n")); got != 130 {
		t.Errorf("status %d, want 130", got)
	}
}

func TestBatchPassesWordsLiterally(t *testing.T) {
	f := newFakeShell(nil)
	f.sh.Batch(context.Background(), strings.NewReader("user show 'a b' $(id) `id` ;|>\n"))
	want := []string{"user", "show", "a b", "$(id)", "`id`", ";|>"}
	if len(f.ran) != 1 || !slices.Equal(f.ran[0], want) {
		t.Errorf("ran %q, want %q", f.ran, want)
	}
}

func TestCommandRecordsTheRedactedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	f := newFakeShell(NewHistory(path, nil))
	in := strings.NewReader("y\n")
	if got := f.sh.Command(context.Background(), "scope secret lab set x", in); got != 0 {
		t.Fatalf("status %d", got)
	}
	if len(f.ran) != 1 || !slices.Equal(f.ran[0], []string{"scope", "secret", "lab", "set", "x"}) || f.stdin[0] != in {
		t.Errorf("ran %q with %v", f.ran, f.stdin)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "scope secret lab set …(redacted)\n" {
		t.Errorf("history %q", b)
	}
	if got := f.sh.Command(context.Background(), "status 4", nil); got != 4 {
		t.Errorf("status %d, want 4", got)
	}
}

func TestBuiltins(t *testing.T) {
	f := newFakeShell(NewHistory("", nil))
	f.sh.o.History.Add("user list")
	f.sh.o.History.Add("scope secret lab set x")
	f.sh.Command(context.Background(), "history", nil)
	if !strings.Contains(f.out.String(), "    1  user list\n") || !strings.Contains(f.out.String(), "scope secret lab set …(redacted)") {
		t.Errorf("history output %q", f.out.String())
	}
	f.out.Reset()
	if got := f.sh.Command(context.Background(), "help user", nil); got != 0 || f.out.String() != "usage of user\n" {
		t.Errorf("help user: %d %q", got, f.out.String())
	}
	if got := f.sh.Command(context.Background(), "help bogus", nil); got != 1 || !strings.Contains(f.err.String(), "no help for 'bogus'") {
		t.Errorf("help bogus: %d %q", got, f.err.String())
	}
	if len(f.ran) != 0 {
		t.Errorf("a builtin ran a command: %q", f.ran)
	}
}

func TestSystemShellWord(t *testing.T) {
	// Without Options.SystemShell the word is a command like any other.
	f := newFakeShell(nil)
	f.sh.Command(context.Background(), "system-shell", nil)
	if len(f.ran) != 1 || f.ran[0][0] != "system-shell" {
		t.Errorf("ran %q", f.ran)
	}
	// With it, the callback runs (not interactive here) and nothing else.
	f = newFakeShell(nil)
	var calls []bool
	f.sh.o.SystemShell = func(_ context.Context, interactive bool) int {
		calls = append(calls, interactive)
		return 126
	}
	if got := f.sh.Command(context.Background(), "system-shell", nil); got != 126 {
		t.Errorf("status %d", got)
	}
	if got := f.sh.Command(context.Background(), "system-shell now", nil); got != 2 || !strings.Contains(f.err.String(), "system-shell takes no arguments") {
		t.Errorf("with an argument: %d %q", got, f.err.String())
	}
	if got := f.sh.Batch(context.Background(), strings.NewReader("user list\nsystem-shell\nuser list\n")); got != 126 {
		t.Errorf("batch status %d", got)
	}
	if !slices.Equal(calls, []bool{false, false}) || len(f.ran) != 1 {
		t.Errorf("calls %v, ran %q", calls, f.ran)
	}
	if reason, lines := f.sh.End(); reason != EndFailed || lines != 4 {
		t.Errorf("End = %s %d", reason, lines)
	}
}

func TestEndReasons(t *testing.T) {
	cases := []struct {
		script, reason string
		lines          int
	}{
		{"user list\n\nuser list\n", EndEOF, 2},
		{"user list\nexit\nuser list\n", EndExit, 2},
		{"status 2\n", EndFailed, 1},
		{"user list " + strings.Repeat("x", LineMax+10) + "\n", EndFailed, 0},
	}
	for _, c := range cases {
		f := newFakeShell(nil)
		f.sh.Batch(context.Background(), strings.NewReader(c.script))
		if reason, lines := f.sh.End(); reason != c.reason || lines != c.lines {
			t.Errorf("%.30q: End = %s %d, want %s %d", c.script, reason, lines, c.reason, c.lines)
		}
	}
	f := newFakeShell(nil)
	ctx, cancel := context.WithCancel(context.Background())
	f.sh.o.Exec = func(context.Context, []string, io.Reader) int { cancel(); return 0 }
	f.sh.Batch(ctx, strings.NewReader("user list\nuser list\n"))
	if reason, _ := f.sh.End(); reason != EndSignal {
		t.Errorf("cancelled batch: %s", reason)
	}
	f = newFakeShell(nil)
	f.sh.Command(context.Background(), "user list", nil)
	if reason, lines := f.sh.End(); reason != EndCommand || lines != 1 {
		t.Errorf("command: %s %d", reason, lines)
	}
}

func TestRows(t *testing.T) {
	if got := Rows(false); !slices.EqualFunc(got, BuiltinRows, func(a, b Row) bool { return a.Left == b.Left }) {
		t.Errorf("Rows(false) = %v", got)
	}
	got := Rows(true)
	var left []string
	for _, r := range got {
		left = append(left, r.Left)
	}
	if !slices.Equal(left, []string{"help [<command>]", "history", "system-shell", "exit | quit"}) {
		t.Errorf("Rows(true) = %q", left)
	}
	if len(BuiltinRows) != 3 {
		t.Error("Rows(true) changed BuiltinRows")
	}
}

// A pasted command line starts with the command the shell implies: it is
// run, and answered, as the line without it.
func TestLeadingBinaryIsNoWord(t *testing.T) {
	cases := []struct {
		script string
		status int
		ran    [][]string
	}{
		{"tacctl user list\n", 0, [][]string{{"user", "list"}}},
		{"sudo tacctl user list\n", 0, [][]string{{"user", "list"}}},
		{"/usr/local/bin/tacctl user show 'a b'\n", 0, [][]string{{"user", "show", "a b"}}},
		{"tacctl status 3\nuser list\n", 3, [][]string{{"status", "3"}}},
		{"tacctl\nsudo tacctl\nuser list\n", 0, [][]string{nil, nil, {"user", "list"}}},
		{"tacctl tacctl user list\n", 0, [][]string{{"tacctl", "user", "list"}}},
		{"user add tacctl\n", 0, [][]string{{"user", "add", "tacctl"}}},
		{"sudo ls\n", 0, [][]string{{"sudo", "ls"}}},
		{"tacctl exit\nuser list\n", 0, nil},
		{"tacctl quit\nuser list\n", 0, nil},
		{"sudo tacctl quit now\n", 2, nil},
		{"tacctl help\nuser list\n", 0, [][]string{{"user", "list"}}},
		{"tacctl help user\n", 0, nil},
		{"tacctl help nothing\n", 1, nil},
		{"tacctl history\nuser list\n", 0, [][]string{{"user", "list"}}},
		{"tacctl 'user\n", 2, nil},
	}
	for _, c := range cases {
		f := newFakeShell(nil)
		got := f.sh.Batch(context.Background(), strings.NewReader(c.script))
		if got != c.status || !slices.EqualFunc(f.ran, c.ran, slices.Equal[[]string]) {
			t.Errorf("%q: status %d, ran %q; want %d, %q (stderr %q)", c.script, got, f.ran, c.status, c.ran, f.err.String())
		}
	}
	// 'tacctl' alone is the command with no arguments: Exec gets no words
	// (and its status stops a batch like any other).
	f := newFakeShell(nil)
	f.sh.o.Exec = func(_ context.Context, words []string, _ io.Reader) int {
		f.ran = append(f.ran, words)
		return 1
	}
	if got := f.sh.Batch(context.Background(), strings.NewReader("sudo tacctl\nuser list\n")); got != 1 || len(f.ran) != 1 || len(f.ran[0]) != 0 {
		t.Errorf("status %d, ran %q", got, f.ran)
	}
	if _, n := f.sh.End(); n != 1 {
		t.Errorf("%d lines counted, want 1", n)
	}
	f = newFakeShell(nil)
	f.sh.Batch(context.Background(), strings.NewReader("tacctl help user\n"))
	if f.out.String() != "usage of user\n" {
		t.Errorf("help output %q", f.out.String())
	}
}

// The history stores what was typed, the leading command included, and
// keeps redacting what follows it.
func TestCommandKeepsTheTypedLineInTheHistory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history")
	f := newFakeShell(NewHistory(path, nil))
	f.sh.Command(context.Background(), "tacctl scope secret lab set x", nil)
	if len(f.ran) != 1 || !slices.Equal(f.ran[0], []string{"scope", "secret", "lab", "set", "x"}) {
		t.Errorf("ran %q", f.ran)
	}
	b, _ := os.ReadFile(path)
	if string(b) != "tacctl scope secret lab set …(redacted)\n" {
		t.Errorf("history %q", b)
	}
}
