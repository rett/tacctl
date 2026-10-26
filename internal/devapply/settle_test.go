package devapply

// The live acceptance of 2026-10-14: a compare with the context lines of a
// device (an added entry beside existing ones) is read, and a pending
// apply is settled from the device's own rollbacks, never from today's
// rendering.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// An apply that adds a community beside an existing one, on a device whose
// compares print the unchanged neighbours as context ('    community <x>
// { ... }'): the check's compare, the landed compare and the cancel's
// inverse all read it.
func TestApplyBesideExistingEntries(t *testing.T) {
	d := newDevice(t, map[string]string{"compare.context": ""})
	before := d.srv.Committed()
	p := &planner{desired: desiredLines()}
	o := apply(t, d, p, nil)
	wantExit(t, o, ExitApplied, ResultApplied)
	if d.srv.Committed() == before {
		t.Fatal("nothing changed")
	}
	// the device's compare holds the context the parser skips
	j := d.dial()
	defer func() { _ = j.Close() }()
	c, err := j.RollbackCompare(context.Background(), 2)
	if err != nil || c.Empty() {
		t.Fatalf("%v %v", c, err)
	}

	// the cancel's inverse check reads it too: a hold refused rolls back
	d2 := newDevice(t, map[string]string{"compare.context": ""})
	before2 := d2.srv.Committed()
	o = apply(t, d2, &planner{desired: desiredLines()}, func(in *Input) {
		in.Hold = func(context.Context, time.Time) (bool, error) { return false, nil }
	})
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if d2.srv.Committed() != before2 || indexOf(o.Log, plan.ApplyCancel(o.ID)) < 0 {
		t.Errorf("not cancelled: %q", o.Log)
	}
}

// The gate's compare with context lines parses, and the reason is the
// stranger's staged change.
func TestGateStagedBesideExisting(t *testing.T) {
	d := newDevice(t, map[string]string{"compare.context": "", "dirty.shared": "user carol\nset snmp community zz-staged authorization read-only\n"})
	j := d.dial()
	defer func() { _ = j.Close() }()
	dirty, err := j.SharedDirty(context.Background())
	if err != nil || !dirty.Staged {
		t.Fatalf("%+v %v", dirty, err)
	}
	o := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitFailed, ResultFailed)
	if o.Reason != "other editors or staged changes" {
		t.Errorf("reason %q", o.Reason)
	}
}

// pendingApply leaves an apply pending on the device: the held session
// closes after the confirmed commit (a dead tacctl).
func pendingApply(t *testing.T) (*device, Outcome) {
	t.Helper()
	d := newDevice(t, map[string]string{"commit.drop": ""})
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitPending, ResultPending)
	d.unknob("commit.drop")
	return d, o
}

// changed is a planner of a rendering that changed since the commit: the
// configuration the device runs is what it wants (no delta) whatever that
// is, or it always wants more (a delta).
func changed(empty bool) func(context.Context, string) (plan.Delta, error) {
	return func(context.Context, string) (plan.Delta, error) {
		if empty {
			return deltaOf(), nil
		}
		return deltaOf(desiredLines()[1]), nil
	}
}

// The reported defect: the device rolled the change back at its window's
// end, and the rendering changed in between so that a read with today's
// rendering finds nothing to do. The settle is rolled back all the same:
// the rollbacks decide, no planner.
func TestSettleExpiryRenderingChanged(t *testing.T) {
	d, o := pendingApply(t)
	before := o
	d.clk.Advance(11 * time.Minute)
	if h := d.srv.History(); h[0].User != textExpiryUser || !ours(CommitEntry{Comment: h[1].Comment}, o.ID) {
		t.Fatalf("history %+v", h)
	}
	for _, facts := range []func(context.Context, string) (plan.Delta, error){changed(true), changed(false), nil} {
		r, _ := d.verify(context.Background())
		rc := ReconcileAt(context.Background(), r, "example-sw1", before.ID, before.Until, d.clk.Now(), facts)
		_ = r.Close()
		wantExit(t, rc, ExitRolledBack, ResultRolledBack)
		if !strings.HasPrefix(rc.Fate, "rolled back by the device at ") || !rc.Until.IsZero() {
			t.Errorf("%q %q", rc.Fate, rc.Reason)
		}
		for _, l := range rc.Log {
			if !plan.IsApplyWord(l) || strings.HasPrefix(l, "configure") {
				t.Errorf("typed %q", l)
			}
		}
	}
}

// A stranger's commit confirmed tacctl's (any commit confirms a pending
// one): applied by someone else, with or without the rendering's say.
func TestSettleForeignCommitConfirmed(t *testing.T) {
	d, o := pendingApply(t)
	runShell(t, d, "configure", "commit comment \"bob's\"")
	if _, p := d.srv.PendingUntil(); p {
		t.Fatal("still pending")
	}
	d.clk.Advance(11 * time.Minute)
	for _, facts := range []func(context.Context, string) (plan.Delta, error){changed(false), nil} {
		r, _ := d.verify(context.Background())
		rc := ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), facts)
		_ = r.Close()
		wantExit(t, rc, ExitAppliedByOther, ResultApplied)
		if !strings.HasPrefix(rc.Fate, "applied (the commit by ") || !strings.Contains(rc.Reason, "the configuration is the one tacctl's commit produced (rollback 1)") {
			t.Errorf("%q %q", rc.Fate, rc.Reason)
		}
	}
}

// A stranger's commit confirmed tacctl's and changed more: the
// configuration is neither tacctl's nor the one before it. Unknown, even
// when today's rendering finds nothing to do.
func TestSettleBothDiffer(t *testing.T) {
	d, o := pendingApply(t)
	runShell(t, d, "configure", "set snmp contact bob", "commit")
	d.clk.Advance(11 * time.Minute)
	r, _ := d.verify(context.Background())
	defer func() { _ = r.Close() }()
	rc := ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), changed(true))
	wantExit(t, rc, ExitUnknown, ResultUnknown)
	if !strings.Contains(rc.Reason, "it changed since") || rc.Fate != "" {
		t.Errorf("%q", rc.Reason)
	}
}

// compareFailR cannot compare the rollbacks; historyMovesR shows another
// entry 0 at the second read of the state.
type compareFailR struct{ Reader }

func (compareFailR) RollbackCompare(context.Context, int) (plan.CompareText, error) {
	return plan.CompareText{}, errors.New("show configuration | compare rollback: the device's answer is not recognised")
}

type historyMovesR struct {
	Reader
	n *int
}

func (h historyMovesR) State(ctx context.Context) (CommitState, error) {
	st, err := h.Reader.State(ctx)
	*h.n++
	if *h.n > 1 && err == nil {
		e := CommitEntry{TimeText: "2026-10-13 15:00:00 UTC", User: "bob", Via: "cli"}
		st.History = append(History{e}, st.History...)
	}
	return st, err
}

// Without the compares the planner is the last fallback, and it only ever
// says unknown; a history that moved between the reads is unknown too.
func TestSettleFallbacksNeverApplied(t *testing.T) {
	d, o := pendingApply(t)
	d.clk.Advance(11 * time.Minute)
	for _, facts := range []func(context.Context, string) (plan.Delta, error){changed(true), changed(false), nil} {
		r, _ := d.verify(context.Background())
		rc := ReconcileAt(context.Background(), compareFailR{r}, "example-sw1", o.ID, o.Until, d.clk.Now(), facts)
		_ = r.Close()
		wantExit(t, rc, ExitUnknown, ResultUnknown)
		if !strings.Contains(rc.Reason, "could not be compared with rollback 1") || strings.Contains(rc.Reason, "the configuration is the one") {
			t.Errorf("%q", rc.Reason)
		}
	}
	r, _ := d.verify(context.Background())
	defer func() { _ = r.Close() }()
	n := 0
	rc := ReconcileAt(context.Background(), historyMovesR{r, &n}, "example-sw1", o.ID, o.Until, d.clk.Now(), changed(true))
	wantExit(t, rc, ExitUnknown, ResultUnknown)
	if !strings.Contains(rc.Reason, "the history changed while the configuration was compared") {
		t.Errorf("%q", rc.Reason)
	}
}

// The compare's text is never quoted: a refusal or a stranger's line gives
// the line number and why.
func TestRollbackCompareNotQuoted(t *testing.T) {
	d := newDevice(t, nil)
	j := d.dial()
	defer func() { _ = j.Close() }()
	if _, err := j.RollbackCompare(context.Background(), 50); !errors.Is(err, ErrNotSent) {
		t.Errorf("rollback 50: %v", err)
	}
	// the fake has one rollback: rollback 5 is the device's refusal
	_, err := j.RollbackCompare(context.Background(), 5)
	if !errors.Is(err, ErrUnrecognised) || !strings.Contains(err.Error(), "(not quoted)") {
		t.Errorf("%v", err)
	}
	c, err := j.RollbackCompare(context.Background(), 0)
	if err != nil || !c.Empty() {
		t.Errorf("rollback 0: %v %v", c, err)
	}
}

// The capture of 2026-10-14: the history of two applies the device rolled
// back, with the rescue line, settles from the rollbacks.
func TestCapturedExpiryHistory(t *testing.T) {
	c := captured(t)
	h, err := parseHistory(c["show system commit (2026-10-14: two applies rolled back by the device at their window's end)"])
	if err != nil || len(h) != 9 {
		t.Fatalf("%v %v", len(h), err)
	}
	s := settle(CommitState{History: h}, "tacctl-20261014T200908Z-664b", CommitEntry{}, testStart, testStart)
	if s.e != ExitUnknown || s.facts != factsRequired {
		t.Errorf("%+v", s)
	}
	s = settle(CommitState{History: h}, "tacctl-20261014T200426Z-00a9", CommitEntry{}, testStart, testStart)
	if s.e != ExitRolledBack || s.fate != "rolled back (cancelled at 2026-10-14 12:04:37 UTC)" {
		t.Errorf("%+v", s)
	}
	for _, k := range []string{"show | compare (2026-10-14: a staged trap group beside an existing one)", "show | compare (2026-10-14: a staged view, nothing beside it)"} {
		body, ok := configAnswer(c[k])
		if !ok {
			t.Fatalf("%s: no location line", k)
		}
		got, err := plan.ParseCompare(strings.Join(body, "\n"))
		if err != nil || len(got.Stmts) != 1 {
			t.Errorf("%s: %v %v", k, got, err)
		}
	}
}
