package shell

import (
	"context"
	"errors"
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

func (c *fakeCache) Holds() bool { return c.held }

func (c *fakeCache) Stop(why string) {
	c.Forget(why)
	c.events = append(c.events, "stop")
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

// 'console password-cache' with no argument, 'on' or 'off' is a word of the
// shell: the root side (Exec) gets the line to answer or save the person's
// choice, and the shell then starts the cache (on), stops it and forgets the
// password (off) or says whether a password is held (the state). Other
// forms are ordinary commands.
func TestPasswordCacheWord(t *testing.T) {
	ctx := context.Background()
	// on: after the save the cache starts in the running session.
	f := newFakeShell(nil)
	f.sh.interactive = true
	started := &fakeCache{}
	starts := 0
	f.sh.o.CacheStart = func() (PasswordCache, error) { starts++; return started, nil }
	f.sh.Batch(ctx, strings.NewReader("console password-cache on\n"))
	if len(f.ran) != 1 || strings.Join(f.ran[0], " ") != "console password-cache on" || starts != 1 || f.sh.o.Cache != PasswordCache(started) {
		t.Fatalf("on: ran %q, starts %d, cache %v", f.ran, starts, f.sh.o.Cache)
	}
	if !strings.Contains(f.out.String(), "the password cache is on in this session") {
		t.Errorf("stdout %q", f.out.String())
	}
	// ... and the lines that use it open it from then on.
	f.sh.Batch(ctx, strings.NewReader("ssh core\n"))
	if got := strings.Join(started.events, ","); got != "begin:env-1,end" {
		t.Errorf("events after on: %q", got)
	}
	// Already on: nothing is started twice.
	f.sh.Batch(ctx, strings.NewReader("console password-cache on\n"))
	if starts != 1 || strings.Count(f.out.String(), "the password cache is on in this session") != 2 {
		t.Errorf("on again: starts %d, stdout %q", starts, f.out.String())
	}
	// The state, with a password held.
	started.held = true
	f.out.Reset()
	f.sh.Batch(ctx, strings.NewReader("console password-cache\n"))
	if !strings.Contains(f.out.String(), "in this session: the password cache is on and a password is cached now") {
		t.Errorf("state: %q", f.out.String())
	}
	// off: the password is forgotten and said, the cache is stopped and gone.
	f.out.Reset()
	f.sh.Batch(ctx, strings.NewReader("console password-cache off\n"))
	if got := strings.Join(started.events, ","); !strings.HasSuffix(got, "forget:"+askpass.WhyOff+",stop") || started.held || f.sh.o.Cache != nil {
		t.Errorf("off: events %q held %v cache %v", got, started.held, f.sh.o.Cache)
	}
	if !strings.Contains(f.err.String(), "password forgotten ("+askpass.WhyOff+")") || !strings.Contains(f.out.String(), "the password cache is off in this session") {
		t.Errorf("off: stderr %q stdout %q", f.err.String(), f.out.String())
	}
	f.out.Reset()
	f.sh.Batch(ctx, strings.NewReader("console password-cache\n"))
	if !strings.Contains(f.out.String(), "in this session: the password cache is not on") {
		t.Errorf("state after off: %q", f.out.String())
	}
	if len(f.ran) != 6 {
		t.Errorf("the root side got %d lines, want one per line typed: %q", len(f.ran), f.ran)
	}

	// A choice that could not be saved starts nothing; an off always stops.
	g := newFakeShell(nil)
	g.sh.interactive = true
	g.sh.o.CacheStart = func() (PasswordCache, error) { t.Error("started after a refusal"); return nil, nil }
	inner := g.sh.o.Exec
	g.sh.o.Exec = func(c context.Context, words []string, in io.Reader) int {
		inner(c, words, in)
		return 1
	}
	if got := g.sh.Batch(ctx, strings.NewReader("console password-cache on\n")); got != 1 || g.sh.o.Cache != nil {
		t.Errorf("refused on: status %d cache %v", got, g.sh.o.Cache)
	}
	held := &fakeCache{held: true}
	g.sh.o.Cache = held
	g.sh.Batch(ctx, strings.NewReader("console password-cache off\n"))
	if g.sh.o.Cache != nil || held.held {
		t.Errorf("off after a failed save: cache %v held %v", g.sh.o.Cache, held.held)
	}

	// A start that fails is said, with status 1, and the cache stays off.
	h := newFakeShell(nil)
	h.sh.interactive = true
	h.sh.o.CacheStart = func() (PasswordCache, error) {
		return nil, errors.New("password cache unavailable: cannot lock memory")
	}
	if got := h.sh.Batch(ctx, strings.NewReader("console password-cache on\n")); got != 1 || h.sh.o.Cache != nil ||
		!strings.Contains(h.err.String(), "password cache unavailable: cannot lock memory") {
		t.Errorf("failed start: status %d cache %v stderr %q", got, h.sh.o.Cache, h.err.String())
	}

	// Not interactive (-c, a batch) or no way to start: the choice is saved and
	// the cache starts with the next interactive session.
	k := newFakeShell(nil)
	k.sh.o.CacheStart = func() (PasswordCache, error) { t.Error("started in a batch"); return nil, nil }
	k.sh.Batch(ctx, strings.NewReader("console password-cache on\n"))
	if !strings.Contains(k.out.String(), "starts with your next interactive session") {
		t.Errorf("batch: %q", k.out.String())
	}

	// The other forms are ordinary commands, and the word takes no other value.
	m := newFakeShell(nil)
	m.sh.interactive = true
	m.sh.Batch(ctx, strings.NewReader("console password-cache tiers operator\nconsole password-cache user bob clear\nconsole password-cache on now\n"))
	if len(m.ran) != 3 || m.sh.o.Cache != nil {
		t.Errorf("ordinary forms: ran %q", m.ran)
	}
}
