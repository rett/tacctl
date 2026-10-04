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
			if words[0] == "status" && len(words) > 1 {
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
