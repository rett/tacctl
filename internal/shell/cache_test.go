package shell

import (
	"context"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/askpass"
)

// fakeCache records what the loop tells the password cache. It uses the
// cache for the lines named ssh, device and pull (a stand-in for
// askpassWords) and mints "env-<n>" per line.
type fakeCache struct {
	held   bool
	open   bool
	n      int
	events []string // begin:<env>, end, forget:<why>
	notes  []string
	lines  [][]string // per Exec: open=, env=
}

func (c *fakeCache) BeginLine(words []string) string {
	if words[0] != "ssh" && words[0] != "pull" {
		return ""
	}
	c.n++
	c.open = true
	env := "env-" + string(rune('0'+c.n))
	c.events = append(c.events, "begin:"+env)
	return env
}

func (c *fakeCache) EndLine() {
	c.open = false
	c.events = append(c.events, "end")
}

func (c *fakeCache) Forget(why string) bool {
	c.events = append(c.events, "forget:"+why)
	was := c.held
	c.held = false
	if was {
		c.notes = append(c.notes, "password forgotten ("+why+")")
	}
	return was
}

func (c *fakeCache) Notices() []string {
	n := c.notes
	c.notes = nil
	return n
}

// withCache puts c on the shell; each Exec records whether the cache was
// open and the line's value of the variable.
func withCache(f *fakeShell, c *fakeCache) {
	f.sh.o.Cache = c
	inner := f.sh.o.Exec
	f.sh.o.Exec = func(ctx context.Context, words []string, stdin io.Reader) int {
		c.lines = append(c.lines, []string{"open=" + map[bool]string{true: "yes", false: "no"}[c.open], "env=" + LineEnv(ctx)})
		return inner(ctx, words, stdin)
	}
}

// Only a line that uses the cache opens it, for the time it runs, with a
// token of its own; every other line, and the shell's own words, leave it
// shut and carry no value.
func TestCacheOpenOnlyForTheLinesThatUseIt(t *testing.T) {
	f := newFakeShell(nil)
	c := &fakeCache{}
	withCache(f, c)
	f.sh.Batch(context.Background(), strings.NewReader("user list\nssh core\nhelp\nhistory\npull all\nssh core\nuser show a\n"))
	if got := strings.Join(c.events, ","); got != "begin:env-1,end,begin:env-2,end,begin:env-3,end" {
		t.Errorf("events %q", got)
	}
	want := [][]string{{"open=no", "env="}, {"open=yes", "env=env-1"}, {"open=yes", "env=env-2"}, {"open=yes", "env=env-3"}, {"open=no", "env="}}
	if !reflect.DeepEqual(c.lines, want) {
		t.Errorf("ran %q, want %q", c.lines, want)
	}
	if c.open {
		t.Error("the cache is left open")
	}
	// A line that fails closes it as well.
	g := newFakeShell(nil)
	c2 := &fakeCache{}
	withCache(g, c2)
	g.sh.Batch(context.Background(), strings.NewReader("ssh status 3\n"))
	if c2.open || strings.Join(c2.events, ",") != "begin:env-1,end" {
		t.Errorf("a failing line: %q open=%v", c2.events, c2.open)
	}
}

// 'console forget' is the shell's: it never reaches Exec, empties the
// cache and says so; with nothing held it says that.
func TestConsoleForget(t *testing.T) {
	f := newFakeShell(nil)
	c := &fakeCache{held: true}
	withCache(f, c)
	f.sh.Batch(context.Background(), strings.NewReader("console forget\nconsole forget\n"))
	if len(f.ran) != 0 || len(c.events) != 2 {
		t.Errorf("console forget reached Exec: %q", f.ran)
	}
	if got := strings.Join(c.events, ","); got != "forget:console forget,forget:console forget" {
		t.Errorf("events %q", got)
	}
	if !strings.Contains(f.err.String(), "password forgotten (console forget)") {
		t.Errorf("stderr %q", f.err.String())
	}
	if !strings.Contains(f.out.String(), "no password is cached") {
		t.Errorf("stdout %q", f.out.String())
	}
	if c.open {
		t.Error("console forget left the cache open")
	}

	// Without a cache the word still answers.
	g := newFakeShell(nil)
	g.sh.Batch(context.Background(), strings.NewReader("console forget\n"))
	if len(g.ran) != 0 || !strings.Contains(g.out.String(), "not on in this session") {
		t.Errorf("no cache: ran %q, stdout %q", g.ran, g.out.String())
	}
	// Arguments are refused.
	h := newFakeShell(nil)
	withCache(h, &fakeCache{})
	if got := h.sh.Batch(context.Background(), strings.NewReader("console forget now\n")); got != 2 {
		t.Errorf("console forget now: status %d", got)
	}
	// Other console words are tacctl commands.
	k := newFakeShell(nil)
	withCache(k, &fakeCache{})
	k.sh.Batch(context.Background(), strings.NewReader("console show\n"))
	if len(k.ran) != 1 || k.ran[0][0] != "console" {
		t.Errorf("console show: ran %q", k.ran)
	}
}

// The password cache is forgotten after 'passwd' and 'user passwd', whether
// or not they succeeded, and only then.
func TestPasswdForgets(t *testing.T) {
	for _, c := range []struct {
		line   string
		forget bool
	}{
		{"passwd", true}, {"user passwd alice", true}, {"user list", false}, {"user show alice", false}, {"device config pull all", false},
	} {
		f := newFakeShell(nil)
		cache := &fakeCache{held: true}
		withCache(f, cache)
		f.sh.Batch(context.Background(), strings.NewReader(c.line+"\n"))
		got := strings.Contains(strings.Join(cache.events, ","), "forget:"+askpass.WhyPasswd)
		if got != c.forget {
			t.Errorf("%q: forgotten %v, want %v (%q)", c.line, got, c.forget, cache.events)
		}
		if c.forget && cache.held {
			t.Errorf("%q: still held", c.line)
		}
	}
}
