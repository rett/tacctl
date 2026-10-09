package cli

// WP10.4j: the fixes to the review of the shell view (WP10.4g, D56).

import (
	"context"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// clock is a test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// eventually polls until f holds.
func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	for range 400 {
		if f() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A1: the question to the root side never holds the editor up. get answers
// at once with the read-only view while a slow answer is on its way.
func TestPolicyViewDoesNotBlock(t *testing.T) {
	release := make(chan struct{})
	var asked atomic.Int32
	p := &policyView{
		ask: func(ctx context.Context) (tier.Tier, bool) {
			asked.Add(1)
			<-release
			return tier.Operator, true
		},
		ctx: t.Context(), timeout: time.Minute, retry: time.Minute, now: time.Now,
	}
	p.start()
	start := time.Now()
	for range 5 {
		if got := p.get(); got != viewUnread {
			t.Fatalf("while the answer is out: %q, want unread", got)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("get took %v", d)
	}
	close(release)
	eventually(t, "the answer", func() bool { return p.get() == tier.Operator })
	if n := asked.Load(); n != 1 {
		t.Errorf("asked %d times", n)
	}
}

// A1: a question that outlasts the timeout is cut off (the runner gets the
// context with the deadline), the view stays the read-only one, and a later
// use asks again, but not before the retry interval has passed.
func TestPolicyViewTimesOutAndRetries(t *testing.T) {
	clk := &clock{t: time.Unix(1_000_000, 0)}
	var asked atomic.Int32
	var deadlines atomic.Int32
	p := &policyView{
		ask: func(ctx context.Context) (tier.Tier, bool) {
			n := asked.Add(1)
			if _, ok := ctx.Deadline(); ok {
				deadlines.Add(1)
			}
			if n == 1 {
				<-ctx.Done() // sudo waiting out a server timeout
				return "", false
			}
			return tier.Engineer, true
		},
		ctx: t.Context(), timeout: 20 * time.Millisecond, retry: 30 * time.Second, now: clk.now,
	}
	p.start()
	eventually(t, "the first question to fail", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return !p.busy
	})
	if got := p.get(); got != viewUnread {
		t.Fatalf("after the failure: %q", got)
	}
	clk.add(29 * time.Second)
	for range 3 {
		if got := p.get(); got != viewUnread {
			t.Fatalf("before the retry: %q", got)
		}
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("asked again after %d questions, before the retry interval", n)
	}
	clk.add(2 * time.Second)
	p.get() // starts the retry; never waits for it
	eventually(t, "the retry's answer", func() bool { return p.get() == tier.Engineer })
	if n := asked.Load(); n != 2 || deadlines.Load() != 2 {
		t.Errorf("asked %d times, %d with a deadline", n, deadlines.Load())
	}
	// Known: never asked again.
	clk.add(time.Hour)
	p.get()
	if n := asked.Load(); n != 2 {
		t.Errorf("asked again with the answer in: %d", n)
	}
}

// A1: the interactive shell starts the question when it starts, behind a
// runner that is slow; the lists use the read-only view meanwhile and the
// answer once it is in. A failure is not kept for the session.
func TestSetViewInteractiveAsksInTheBackground(t *testing.T) {
	h := newHarness(t, nil)
	release := make(chan struct{})
	var calls atomic.Int32
	h.runner.OnFunc([]string{"sudo", "-n", testExe, "_console-policy"}, func(execx.Cmd) (execx.Result, error) {
		if calls.Add(1) == 1 {
			<-release
			return execx.Result{Code: 1}, nil // the first answer is a failure
		}
		return execx.Result{Stdout: []byte("shell=console tier=operator\n")}, nil
	})
	inv := &invocation{ctx: t.Context(), app: h.app}
	inv.setView(shellRun{exe: testExe, mode: shellInteractive}, true)
	eventually(t, "the question to start", func() bool { return calls.Load() == 1 })
	if got := inv.view(); got != viewUnread {
		t.Fatalf("while sudo waits: %q", got)
	}
	if eff, all, active := inv.currentView(); eff != tier.Readonly || all || !active {
		t.Errorf("the lists use %q all=%v active=%v while the answer is out", eff, all, active)
	}
	// The failed answer is not kept and does not turn into a tier; that the
	// next question waits viewRetry after it is TestPolicyViewTimesOutAndRetries,
	// with a clock (a sleep here would assert nothing: the view is unread
	// whether or not the failure has been recorded yet).
	close(release)
}

// A non-interactive run (-c, a script) asks on first use and waits for the
// answer, so 'help' in a script is not a race.
func TestSetViewBatchWaitsForTheAnswer(t *testing.T) {
	h := newHarness(t, nil)
	h.runner.OnFunc([]string{"sudo", "-n", testExe, "_console-policy"}, func(execx.Cmd) (execx.Result, error) {
		time.Sleep(30 * time.Millisecond)
		return execx.Result{Stdout: []byte("tier=readonly\n")}, nil
	})
	inv := &invocation{ctx: t.Context(), app: h.app}
	inv.setView(shellRun{exe: testExe, mode: shellCommandMode}, true)
	if got := inv.view(); got != tier.Readonly {
		t.Errorf("view = %q", got)
	}
}

// A2: '?' after a family the view hides says which tier the family needs,
// where it is described. Per tier.
func TestViewExplainHiddenFamily(t *testing.T) {
	explain := func(view tier.Tier, w ...string) (string, bool) {
		inv, root := viewInv(t, view)
		return inv.shellExplain(root)(w)
	}
	for _, c := range []struct {
		view   tier.Tier
		family string
		needs  tier.Tier
	}{
		{tier.Readonly, "store", tier.Superuser},
		{tier.Operator, "store", tier.Superuser},
		{tier.Engineer, "store", tier.Superuser},
		{tier.Readonly, "config", tier.Operator},
		{tier.Operator, "host", tier.Engineer},
		{tier.Readonly, "host", tier.Engineer},
		{tier.Readonly, "log", tier.Operator},
		{viewUnread, "store", tier.Superuser},
		{tier.None, "user", tier.Readonly},
		{tier.None, "host", tier.Engineer},
	} {
		want := "Needs the " + string(c.needs) + " tier. help " + c.family + " describes it.\n"
		if got, ok := explain(c.view, c.family); !ok || got != want {
			t.Errorf("%s, %s ?: %q (%v), want %q", c.view, c.family, got, ok, want)
		}
	}
	// A family the tier can run is not answered here (the completer lists
	// its verbs), and a superuser sees everything.
	for _, c := range []struct {
		view   tier.Tier
		family string
	}{{tier.Superuser, "store"}, {tier.Readonly, "user"}, {tier.Operator, "config"}, {tier.Engineer, "host"}, {tier.Unrestricted, "store"}} {
		if got, ok := explain(c.view, c.family); ok {
			t.Errorf("%s, %s ?: %q", c.view, c.family, got)
		}
	}
}

// A3: every verb whose sudoers rows are narrower than '<sub> *' and which
// takes arguments or has sub-verbs of its own has a note in its family's
// help, so a verb the gate lets through but the code refuses is never left
// unexplained. A new split verb fails here until its note is added.
func TestTierNotesCoverTheNarrowRows(t *testing.T) {
	_, root := viewInv(t, tier.Engineer)
	var want []string
	for _, r := range tier.Rules {
		if r.Sub == "" || r.AnySub || len(r.Sudoers) == 0 {
			continue
		}
		broad := r.Cmd + " " + r.Sub + " *"
		if slices.Contains(r.Sudoers, broad) {
			continue
		}
		cmd := child(child(root, r.Cmd), r.Sub)
		if cmd == nil {
			continue
		}
		spec, ok := specFor([]string{r.Cmd, r.Sub})
		if len(visibleChildren(cmd)) > 0 || (ok && spec.MaxArgs != 0) {
			want = append(want, r.Cmd+" "+r.Sub)
		}
	}
	// Verbs whose spec only skips parsing (MaxArgs -1) and that take none.
	noArgs := []string{"config validate"}
	for _, key := range want {
		if slices.Contains(noArgs, key) {
			continue
		}
		if _, ok := tierNotes[key]; !ok {
			t.Errorf("%q has sudoers rows narrower than '%s *' but no entry in tierNotes", key, key)
		}
	}
	for _, key := range []string{"scope staging", "scope secret", "host show", "device import"} {
		if _, ok := tierNotes[key]; !ok {
			t.Errorf("tierNotes lacks %q", key)
		}
	}
	// Every note belongs to a row of the table.
	for key := range tierNotes {
		cmd, sub, _ := strings.Cut(key, " ")
		if !slices.ContainsFunc(tier.Rules, func(r tier.Rule) bool { return r.Cmd == cmd && r.Sub == sub }) {
			t.Errorf("tierNotes[%q] names no row of tier.Rules", key)
		}
	}
}

// A3: the engineer's help for scope says what the code allows of
// 'scope staging'.
func TestViewScopeStagingNote(t *testing.T) {
	inv, root := viewInv(t, tier.Engineer)
	got, _ := inv.shellHelp(root, false)([]string{"scope"})
	if !strings.Contains(got, "scope staging: an engineer may run list for a scope of their own; the other verbs need the superuser tier.") {
		t.Errorf("help scope:\n%s", got)
	}
}

// A4: a caller the root side answered is 'none' lists no verb, in the
// completer and in the explainer; the shell's own words are not the
// completer's to list.
func TestViewNoneListsNoVerb(t *testing.T) {
	inv, root := viewInv(t, tier.None)
	complete := inv.shellCompleter(root)
	if got := words(complete(nil, "")); len(got) != 0 {
		t.Errorf("top level: %q", got)
	}
	for _, fam := range []string{"user", "passwd", "status", "hash", "completion", "version"} {
		if got := words(complete([]string{fam}, "")); len(got) != 0 {
			t.Errorf("%s: %q", fam, got)
		}
	}
	// No answer is not an answer: the read-only verbs remain.
	inv, root = viewInv(t, viewUnread)
	if got := words(inv.shellCompleter(root)([]string{"user"}, "")); !slices.Contains(got, "list") || slices.Contains(got, "add") {
		t.Errorf("unread: %q", got)
	}
}

// Nit: '?' after 'scope staging' does not print the start of an
// alternative as an argument.
func TestExplainNoAlternativePlaceholder(t *testing.T) {
	inv, root := viewInv(t, tier.Superuser)
	got, ok := inv.shellExplain(root)([]string{"scope", "staging"})
	if !ok || strings.Contains(got, "Next: [") || strings.Contains(got, "[list,") {
		t.Errorf("scope staging ?: %q (%v)", got, ok)
	}
}
