package devapply

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// apply runs a whole transaction against the device's reviewed delta.
func apply(t *testing.T, d *device, p *planner, mod func(*Input)) Outcome {
	t.Helper()
	rev := d.reviewed(p)
	in := d.input(p)
	if mod != nil {
		mod(&in)
	}
	o := Driver{}.Apply(context.Background(), in, rev)
	assertLog(t, o, rev.Lines)
	assertNoSecret(t, o, d.state)
	return o
}

func check(t *testing.T, d *device, p *planner, mod func(*Input)) Outcome {
	t.Helper()
	in := d.input(p)
	if mod != nil {
		mod(&in)
	}
	o := Driver{}.Check(context.Background(), in)
	assertLog(t, o, desiredLines())
	assertNoSecret(t, o, d.state)
	return o
}

func wantExit(t *testing.T, o Outcome, e Exit, r Result) {
	t.Helper()
	if o.Exit != e || o.Result != r {
		t.Fatalf("exit %s/%s, want %s/%s: %s\nlog: %q", o.Exit, o.Result, e, r, o.Line(), o.Log)
	}
}

// --- APPLIED ---------------------------------------------------------------------------------

func TestApplyApplied(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	p := &planner{desired: desiredLines()}
	o := apply(t, d, p, nil)
	wantExit(t, o, ExitApplied, ResultApplied)
	if o.Commit == nil || !strings.HasPrefix(o.Commit.Comment, "tacctl apply confirm "+o.ID+" by alice") {
		t.Errorf("commit entry %+v", o.Commit)
	}
	if !o.Until.IsZero() || o.Discarded || o.Interrupted || o.LoginRefused {
		t.Errorf("flags %+v", o)
	}
	if o.Counts != (Counts{Set: 3, Delete: 1}) || strings.Join(o.Sections, ",") != "aaa,snmp" {
		t.Errorf("counts %+v sections %v", o.Counts, o.Sections)
	}
	if o.ID != "tacctl-20261013T140000Z-3f2a" {
		t.Errorf("id %q", o.ID)
	}
	after := d.srv.Committed()
	if after == before || !strings.Contains(after, "set system accounting events login") || strings.Contains(after, "example-ro clients") {
		t.Errorf("committed:\n%s", after)
	}
	h := d.srv.History()
	if len(h) < 3 || !strings.HasPrefix(h[0].Comment, "tacctl apply confirm ") || !strings.HasPrefix(h[1].Comment, "tacctl apply "+o.ID+" by alice") || h[1].RollbackIn != 10 {
		t.Errorf("history %+v", h[:2])
	}
	if _, pending := d.srv.PendingUntil(); pending {
		t.Error("still pending")
	}
	if d.srv.ExclusiveHolder() != "" {
		t.Error("the exclusive lock is still held")
	}
	// the confirm is typed in the held session, after the commit
	ic, iconf := indexOf(o.Log, plan.ApplyCommitConfirmed(10, o.ID, "alice")), indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice"))
	if ic < 0 || iconf < ic || indexOf(o.VerifyLog, plan.ApplyConfirm(o.ID, "alice")) >= 0 {
		t.Errorf("commit %d confirm %d; verify log %q", ic, iconf, o.VerifyLog)
	}
	for _, w := range []string{showCommitShell, plan.ApplyShowAuthorization, plan.ApplyLandedCompare} {
		if indexOf(o.VerifyLog, w) < 0 {
			t.Errorf("the verification did not run %q: %q", w, o.VerifyLog)
		}
	}
	// the shape store gained the device
	m, err := OpenShapes(d.state).Load()
	if err != nil || len(m[o.Shape].Confirmed) != 1 || m[o.Shape].Confirmed[0].Device != "example-sw1" || o.StoreErr != nil {
		t.Fatalf("store %+v %v %v", m, err, o.StoreErr)
	}
	if ok, _ := OpenShapes(d.state).Confirmed(o.Shape); !ok {
		t.Error("not confirmed")
	}
	if !strings.Contains(o.Line(), "applied (aaa,snmp: 3 set, 1 delete) [tacctl-") {
		t.Errorf("line %q", o.Line())
	}

	// a second apply has nothing to do
	o2 := apply(t, d, p, nil)
	wantExit(t, o2, ExitNoChange, ResultNoChange)
	if indexOf(o2.Log, plan.ApplyConfigureExclusive) >= 0 {
		t.Errorf("a no-change run opened a session: %q", o2.Log)
	}
}

// --- CHECKED, NO-CHANGE -------------------------------------------------------------------------

func TestCheckChecked(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	o := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitChecked, ResultChecked)
	if !o.Discarded || !endsWith(o.Log, plan.ApplyCommitCheck, plan.ApplyRollback0, plan.ApplyExit) {
		t.Errorf("not discarded: %q", o.Log)
	}
	if o.Shape == "" || len(o.ShapeLines) == 0 || !strings.HasPrefix(o.Line(), "checked: shape "+o.Shape+" (3 set, 1 delete)") {
		t.Errorf("shape %q %q", o.Shape, o.Line())
	}
	if d.srv.Committed() != before || len(d.srv.History()) != 1 {
		t.Error("a check changed the device")
	}
	if d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
		t.Error("the candidate or the lock was left")
	}
	if strings.Contains(strings.Join(o.Log, "\n"), "commit confirmed") {
		t.Error("a check committed")
	}
}

func TestNoChangeAtCompare(t *testing.T) {
	// a delete of an absent statement: the device answers 'statement not
	// found', the compare is empty
	d := newDevice(t, nil)
	p := &planner{desired: []plan.Line{{Section: "snmp", Op: plan.OpDelete, Text: "delete snmp community example-ro clients 192.0.2.0/24"}}}
	in := d.input(p)
	// the planner thinks the device has it; the device removed it meanwhile
	rev := d.reviewed(p)
	runShell(t, d, "configure", "delete snmp community example-ro clients 192.0.2.0/24", "commit")
	p.desired = nil
	in.Plan = func(ctx context.Context, raw string, from netIP) (plan.Delta, error) { return rev, nil }
	o := Driver{}.Check(context.Background(), in)
	wantExit(t, o, ExitNoChange, ResultNoChange)
	if !o.Discarded || o.Counts.NotFound != 1 {
		t.Errorf("discarded %v notfound %d: %q", o.Discarded, o.Counts.NotFound, o.Log)
	}
}

// --- FAILED before OPEN --------------------------------------------------------------------------

func TestFailedBeforeOpen(t *testing.T) {
	cases := []struct {
		name  string
		knobs map[string]string
		mod   func(*Input)
		want  string
	}{
		{"name", nil, func(in *Input) { in.Names = []string{"sw-other"} }, "calls itself 'example-sw1'"},
		{"class", map[string]string{"class": "read-only\n"}, nil, "cannot commit as this login (class read-only)"},
		{"locked", map[string]string{"exclusive.held-by": "bob\n"}, nil, "locked by bob"},
		{"dirty", map[string]string{"dirty.shared": "user carol\nset snmp contact carol\n"}, nil, "other editors or staged changes"},
		{"allow", nil, func(in *Input) {
			in.Plan = func(context.Context, string, netIP) (plan.Delta, error) {
				return deltaOf(plan.Line{Section: "aaa", Op: plan.OpSet, Text: "set system services ssh"}), nil
			}
		}, "statement outside the planner's domain"},
		{"own-login", nil, func(in *Input) {
			in.Plan = func(context.Context, string, netIP) (plan.Delta, error) {
				return deltaOf(plan.Line{Section: "roles", Op: plan.OpSet, Text: "set system login user gotest class super-user"}), nil
			}
		}, "statement outside the planner's domain"},
		{"vendor", nil, func(in *Input) { in.Transport = vendorT{in.Transport} }, "apply is not available for cisco devices"},
		{"input", nil, func(in *Input) { in.Clock = nil }, "no clock"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t, c.knobs)
			before := d.srv.Committed()
			o := check(t, d, &planner{desired: desiredLines()}, c.mod)
			wantExit(t, o, ExitFailed, ResultFailed)
			if !strings.Contains(o.Reason, c.want) {
				t.Errorf("reason %q, want %q", o.Reason, c.want)
			}
			if indexOf(o.Log, plan.ApplyConfigureExclusive) >= 0 && c.name != "locked" {
				t.Errorf("opened: %q", o.Log)
			}
			for _, l := range o.Log {
				if strings.HasPrefix(l, "set ") || strings.HasPrefix(l, "delete ") {
					t.Errorf("a statement was sent: %q", l)
				}
			}
			if d.srv.Committed() != before {
				t.Error("changed")
			}
		})
	}
}

func TestFailedPendingAtPreflight(t *testing.T) {
	d := newDevice(t, map[string]string{"commit.drop": ""})
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitPending, ResultPending)
	d.unknob("commit.drop")
	o2 := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o2, ExitFailed, ResultFailed)
	if !strings.Contains(o2.Reason, "a confirmed commit is pending until 2026-10-13 14:10:00 UTC; nothing was sent") {
		t.Errorf("reason %q", o2.Reason)
	}
	if indexOf(o2.Log, plan.ApplyConfigure) >= 0 || indexOf(o2.Log, plan.ApplyCommitCheck) >= 0 {
		t.Errorf("a pending device was touched: %q", o2.Log)
	}
}

func TestFailedChangedSinceReview(t *testing.T) {
	d := newDevice(t, nil)
	p := &planner{desired: desiredLines()}
	rev := d.reviewed(p)
	runShell(t, d, "configure", "set system accounting events login", "commit")
	o := Driver{}.Apply(context.Background(), d.input(p), rev)
	wantExit(t, o, ExitFailed, ResultFailed)
	if o.Reason != "the device changed since the review" || indexOf(o.Log, plan.ApplyConfigure) >= 0 {
		t.Errorf("%q %q", o.Reason, o.Log)
	}
}

// --- FAILED at LOAD / CHECK ------------------------------------------------------------------------

func TestFailedLoad(t *testing.T) {
	d := newDevice(t, map[string]string{"load.errors": "set system tacplus-server 192.0.2.11 secret => error: could not set " + secretKey + "\n"})
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitFailedLoad, ResultFailed)
	if !strings.HasPrefix(o.Reason, "load: set system tacplus-server 192.0.2.11 secret <secret>: error: could not set <secret>") {
		t.Errorf("reason %q", o.Reason)
	}
	if !o.Discarded || !endsWith(o.Log, "set system tacplus-server 192.0.2.11 secret <secret>", plan.ApplyRollback0, plan.ApplyExit) {
		t.Errorf("not discarded right after the statement: %q", o.Log)
	}
	if d.srv.Committed() != before || d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
		t.Error("the device changed")
	}
}

func TestFailedCheck(t *testing.T) {
	d := newDevice(t, map[string]string{"check.errors": "set system accounting events => error: accounting needs a destination\n"})
	before := d.srv.Committed()
	o := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitFailedCheck, ResultFailed)
	if !strings.Contains(o.Reason, "check: error: accounting needs a destination") {
		t.Errorf("reason %q", o.Reason)
	}
	if !o.Discarded || !endsWith(o.Log, plan.ApplyCommitCheck, plan.ApplyRollback0, plan.ApplyExit) {
		t.Errorf("log %q", o.Log)
	}
	if d.srv.Committed() != before || d.srv.Candidate() != before {
		t.Error("changed")
	}
}

func TestFailedOutsideTheDelta(t *testing.T) {
	// the device turns one statement into more than it says: the compare
	// holds a change no line explains, and nothing is committed
	d := newDevice(t, nil)
	p := &planner{desired: desiredLines()}
	o := check(t, d, p, func(in *Input) {
		in.Transport = &extraT{JunosCLI: in.Transport.(*JunosCLI)}
	})
	wantExit(t, o, ExitFailedLoad, ResultFailed)
	if !strings.Contains(o.Reason, "a change outside the delta") || !o.Discarded {
		t.Errorf("%q %v", o.Reason, o.Discarded)
	}
}

// --- READ-STATE: nothing committed ---------------------------------------------------------------

// showCommitShell is the state read: 'show system commit' in a shell, whose
// prompt carries the banner of a pending commit.
const showCommitShell = plan.ApplyShowCommit + " | no-more"

// The confirmed commit's line closes the connection unanswered, before it is
// applied: the state is read on a fresh login before it is named. (Before
// the spike this exit was reached through the private session's refusal; a
// private session is no longer opened, lab L5.)
func TestNothingCommittedSessionDropped(t *testing.T) {
	d := newDevice(t, map[string]string{"drop": "commit confirmed\n"})
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitNothingCommitted, ResultFailed)
	if !strings.Contains(o.Reason, "nothing was committed (the confirmed commit's answer: ") {
		t.Errorf("reason %q", o.Reason)
	}
	if indexOf(o.VerifyLog, showCommitShell) < 0 {
		t.Errorf("the state was not read on a fresh login: %q", o.VerifyLog)
	}
	if d.srv.Committed() != before || !o.Until.IsZero() || d.srv.ExclusiveHolder() != "" {
		t.Error("changed, pending or locked")
	}
}

// The landed compare and the state read are the lab's commands: 'show
// configuration | compare rollback 1' (L3) and 'configure exclusive' only
// (L5).
func TestNoPrivateSessionAndLandedCompare(t *testing.T) {
	d := newDevice(t, nil)
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitApplied, ResultApplied)
	for _, l := range append(append([]string{}, o.Log...), o.VerifyLog...) {
		if strings.Contains(l, "private") || strings.Contains(l, "system rollback") {
			t.Errorf("typed %q", l)
		}
	}
	if indexOf(o.VerifyLog, "show configuration | compare rollback 1 | no-more") < 0 {
		t.Errorf("verify log %q", o.VerifyLog)
	}
}

// --- ROLLED-BACK ------------------------------------------------------------------------------

func TestRolledBackFreshLoginRefused(t *testing.T) {
	d := newDevice(t, map[string]string{"verify.fail": "deny"})
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !o.LoginRefused || !strings.Contains(o.Reason, "verification failed (the fresh login was refused)") {
		t.Errorf("%v %q", o.LoginRefused, o.Reason)
	}
	if strings.Contains(o.Reason, devssh.ErrAuth.Error()) {
		t.Errorf("the reason reads as a rejected password: %q", o.Reason)
	}
	if !endsWith(o.Log, plan.ApplyRollback1, plan.ApplyCompare, plan.ApplyCancel(o.ID), showCommitShell) {
		t.Errorf("log %q", o.Log)
	}
	if d.srv.Committed() != before {
		t.Errorf("not rolled back:\n%s", d.srv.Committed())
	}
	h := d.srv.History()
	if h[0].Comment != "tacctl apply cancel "+o.ID || !strings.HasPrefix(h[1].Comment, "tacctl apply "+o.ID) {
		t.Errorf("history %+v", h[:2])
	}
	if _, p := d.srv.PendingUntil(); p {
		t.Error("pending")
	}
	if !strings.HasPrefix(o.Line(), "rolled back: verification failed (the fresh login was refused)") {
		t.Errorf("line %q", o.Line())
	}
}

// A fresh login VerifyLogin does not accept (onboard: a local account of
// the person's name, not the rendered template user) fails the
// verification: the change is rolled back.
func TestRolledBackVerifyLoginRefused(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	var seen Login
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.VerifyLogin = func(lg Login) error {
			seen = lg
			return errors.New("'Current user' " + lg.User + " is not the template user EN-CLASS")
		}
	})
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if seen.User == "" || !strings.Contains(o.Reason, "verification failed (the fresh login: 'Current user' "+seen.User+" is not the template user EN-CLASS)") {
		t.Errorf("%+v %q", seen, o.Reason)
	}
	if d.srv.Committed() != before {
		t.Errorf("not rolled back:\n%s", d.srv.Committed())
	}
	// a login it accepts is applied
	d2 := newDevice(t, nil)
	o = apply(t, d2, &planner{desired: desiredLines()}, func(in *Input) {
		in.VerifyLogin = func(Login) error { return nil }
	})
	wantExit(t, o, ExitApplied, ResultApplied)
}

func TestRolledBackStillLacks(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	p := &planner{desired: desiredLines()}
	p.after = func(dl plan.Delta) plan.Delta {
		dl.Lines = append(dl.Lines, plan.Line{Section: "snmp", Op: plan.OpSet, Text: "set snmp contact noc"})
		return dl
	}
	o := apply(t, d, p, nil)
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "verification failed (snmp still lacks set snmp contact noc)") {
		t.Errorf("reason %q", o.Reason)
	}
	if d.srv.Committed() != before {
		t.Error("not rolled back")
	}
}

func TestRolledBackLandedMismatch(t *testing.T) {
	d := newDevice(t, nil)
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Verify = func(ctx context.Context) (Reader, error) {
			r, err := d.verify(ctx)
			if err != nil {
				return nil, err
			}
			return landedT{r}, nil
		}
	})
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "what landed is not the change the check showed") {
		t.Errorf("reason %q", o.Reason)
	}
}

func TestRolledBackHoldRefused(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	var until time.Time
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Hold = func(_ context.Context, u time.Time) (bool, error) { until = u; return false, nil }
	})
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "the hold was not confirmed") || !until.Equal(testStart.Add(10*time.Minute)) {
		t.Errorf("%q %v", o.Reason, until)
	}
	if d.srv.Committed() != before {
		t.Error("not rolled back")
	}
}

// --- PENDING-UNTIL, UNKNOWN, window short --------------------------------------------------------

func TestPendingSessionDropped(t *testing.T) {
	d := newDevice(t, map[string]string{"commit.drop": ""})
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitPending, ResultPending)
	if !o.Until.Equal(testStart.Add(10*time.Minute)) || !strings.Contains(o.Reason, "the held session is lost") {
		t.Errorf("until %v reason %q", o.Until, o.Reason)
	}
	if indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice")) >= 0 || indexOf(o.VerifyLog, plan.ApplyConfirm(o.ID, "alice")) >= 0 {
		t.Error("confirmed from another session")
	}
	if !strings.HasPrefix(o.Line(), "PENDING until 14:10:00: do not type commit or commit check on the device") {
		t.Errorf("line %q", o.Line())
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Fatal("the device is not pending")
	}
	// a dead tacctl's record is reconciled by the next run
	r, err := d.verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	rc := Reconcile(context.Background(), r, "example-sw1", o.ID, o.Until, nil)
	_ = r.Close()
	wantExit(t, rc, ExitPending, ResultPending)
	d.clk.Advance(11 * time.Minute)
	r, _ = d.verify(context.Background())
	defer func() { _ = r.Close() }()
	// 'by root via other' is the device's own rollback or a commit of the
	// system: settled from the configuration, unknown without a planner
	rc = ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), nil)
	wantExit(t, rc, ExitUnknown, ResultUnknown)
	rc = ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), factsOf(&planner{desired: desiredLines()}))
	wantExit(t, rc, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(rc.Reason, "the commit after tacctl's is by root via other at 2026-10-13 14:10:00 UTC") ||
		!strings.Contains(rc.Reason, "the configuration lacks the change") || !rc.Until.IsZero() {
		t.Errorf("reconcile %q", rc.Reason)
	}
}

func TestUnknownStateUnreadable(t *testing.T) {
	d := newDevice(t, map[string]string{"commit.drop": "", "verify.fail": "deny"})
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitUnknown, ResultUnknown)
	if o.Until.IsZero() || !strings.Contains(o.Line(), "unknown: check the device; the window ends at 14:10:00") {
		t.Errorf("%q", o.Line())
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Error("the device should still be pending")
	}
}

func TestWindowShort(t *testing.T) {
	d := newDevice(t, nil)
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Hold = func(context.Context, time.Time) (bool, error) {
			d.clk.Advance(9*time.Minute + 30*time.Second)
			return true, nil
		}
	})
	wantExit(t, o, ExitWindowShort, ResultPending)
	if indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice")) >= 0 || indexOf(o.Log, plan.ApplyRollback1) >= 0 {
		t.Errorf("typed with the window short: %q", o.Log)
	}
	if o.Until.IsZero() || !strings.Contains(o.Reason, "the window ran short") {
		t.Errorf("%+v", o)
	}
	d.clk.Advance(time.Minute)
	if _, p := d.srv.PendingUntil(); p {
		t.Error("the device did not roll back at its window's end")
	}
}

func TestAppliedBySomeoneElse(t *testing.T) {
	d := newDevice(t, map[string]string{"commit.drop": ""})
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitPending, ResultPending)
	d.unknob("commit.drop")
	runShell(t, d, "configure", "commit check")
	// The check leaves no entry: tacctl's commit is still entry 0 with its
	// 'rollback in' label, and no banner stands (lab L2). Before the spike
	// the fake wrote an entry for the check and this needed the facts; the
	// state alone now says it, with or without them.
	if h := d.srv.History(); !ours(CommitEntry{Comment: h[0].Comment}, o.ID) || h[0].RollbackIn != 10 {
		t.Fatalf("history %+v", h[0])
	}
	r, _ := d.verify(context.Background())
	defer func() { _ = r.Close() }()
	p := &planner{desired: desiredLines()}
	// Before the window's end the banner's absence is all there is: a
	// release or a session that prints no banner would roll the change back
	// at the end all the same. The record stays pending.
	for _, facts := range []func(context.Context, string) (plan.Delta, error){factsOf(p), nil} {
		rc := ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), facts)
		wantExit(t, rc, ExitPending, ResultPending)
		if !strings.Contains(rc.Reason, "no confirmed commit's banner stands but tacctl's commit is still entry 0") || !rc.Until.Equal(o.Until) {
			t.Errorf("%q %v", rc.Reason, rc.Until)
		}
	}
	// After it: confirmed, from the configuration when a planner is at hand.
	d.clk.Advance(11 * time.Minute)
	for _, facts := range []func(context.Context, string) (plan.Delta, error){factsOf(p), nil} {
		rc := ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), facts)
		wantExit(t, rc, ExitAppliedByOther, ResultApplied)
		if !strings.Contains(rc.Reason, "a 'commit check' confirmed it") || (facts != nil) != strings.Contains(rc.Reason, "the configuration has the change") {
			t.Errorf("%q", rc.Reason)
		}
	}
	// a configuration that lacks the change says rolled back
	lacks := func(context.Context, string) (plan.Delta, error) { return deltaOf(desiredLines()[1]), nil }
	rc := ReconcileAt(context.Background(), r, "example-sw1", o.ID, o.Until, d.clk.Now(), lacks)
	wantExit(t, rc, ExitRolledBack, ResultRolledBack)
}

// A pending commit's history label is no pending marker: after a 'commit
// check' confirmed a stranger's confirmed commit, entry 0 still reads
// 'commit confirmed, rollback in Nmins', and an apply proceeds (before the
// spike the pre-flight refused it).
func TestPreflightLabelIsNoPendingMarker(t *testing.T) {
	d := newDevice(t, nil)
	runShell(t, d, "configure", "set snmp contact noc", "commit confirmed 5", "commit check")
	if _, p := d.srv.PendingUntil(); p {
		t.Fatal("still pending")
	}
	if h := d.srv.History(); h[0].RollbackIn != 5 {
		t.Fatalf("the label: %+v", h[0])
	}
	o := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitChecked, ResultChecked)
}

// --- interrupts ----------------------------------------------------------------------------------

func TestInterruptBeforeCommit(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := d.input(&planner{desired: desiredLines()})
	in.Transport = &cancelT{JunosCLI: in.Transport.(*JunosCLI), afterLoads: 2, cancel: cancel}
	o := Driver{}.Check(ctx, in)
	assertLog(t, o, desiredLines())
	assertNoSecret(t, o, d.state)
	wantExit(t, o, ExitInterrupted, ResultFailed)
	if !o.Interrupted || !o.Discarded || !endsWith(o.Log, plan.ApplyRollback0, plan.ApplyExit) {
		t.Errorf("%+v", o)
	}
	if d.srv.Committed() != before || d.srv.Candidate() != before {
		t.Error("changed")
	}
}

func TestInterruptAfterCommit(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &planner{desired: desiredLines()}
	rev := d.reviewed(p)
	in := d.input(p)
	in.Hold = func(ctx context.Context, _ time.Time) (bool, error) {
		cancel()
		return false, ctx.Err()
	}
	o := Driver{}.Apply(ctx, in, rev)
	assertLog(t, o, rev.Lines)
	assertNoSecret(t, o, d.state)
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !o.Interrupted || !strings.HasPrefix(o.Reason, "interrupted") {
		t.Errorf("%+v", o)
	}
	if d.srv.Committed() != before {
		t.Error("not rolled back")
	}
}

// --- the transport's guards ---------------------------------------------------------------------

func TestTransportGuards(t *testing.T) {
	d := newDevice(t, nil)
	j := d.dial()
	defer func() { _ = j.Close() }()
	ctx := context.Background()
	if _, err := j.runExec(ctx, "show configuration system"); !errors.Is(err, ErrNotSent) {
		t.Errorf("an exec read outside the words: %v", err)
	}
	line := plan.Line{Op: plan.OpSet, Text: "set snmp contact noc"}
	if _, err := j.Load(ctx, line); !errors.Is(err, ErrNotSent) {
		t.Errorf("a load before Open: %v", err)
	}
	if err := j.Open(ctx, nil); !errors.Is(err, ErrNotSent) {
		t.Errorf("Open without an allow-list: %v", err)
	}
	refuse := func(string) error { return errors.New("no") }
	if err := j.Open(ctx, refuse); err != nil {
		t.Fatal(err)
	}
	if _, err := j.Load(ctx, line); !errors.Is(err, ErrNotSent) {
		t.Errorf("a refused statement: %v", err)
	}
	if _, err := j.Load(ctx, plan.Line{Op: plan.OpSet, Text: "commit"}); !errors.Is(err, ErrNotSent) {
		t.Errorf("a wrapper word as a statement: %v", err)
	}
	if _, err := j.Load(ctx, plan.Line{Op: plan.OpSet, Text: "set system login message \"why?\""}); !errors.Is(err, ErrNotSent) {
		t.Errorf("a '?': %v", err)
	}
	if _, err := j.word(ctx, "commit"); !errors.Is(err, ErrNotSent) {
		t.Errorf("a bare commit: %v", err)
	}
	if err := j.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	for _, l := range j.Log() {
		if strings.HasPrefix(l, "set ") || l == "commit" {
			t.Errorf("sent %q", l)
		}
	}
	if d.srv.ExclusiveHolder() != "" {
		t.Error("lock left")
	}
	_ = fakedev.DefaultUser
}

// Committed is called once, right after 'commit confirmed' was typed and
// before the verification, with the change's id, the window's end and the
// shape: what the caller writes as a pending record. A check never calls it.
func TestApplyCommittedHook(t *testing.T) {
	d := newDevice(t, nil)
	p := &planner{desired: desiredLines()}
	var got []Outcome
	var pendingAtHook bool
	o := apply(t, d, p, func(in *Input) {
		in.Committed = func(c Outcome) {
			_, pendingAtHook = d.srv.PendingUntil()
			got = append(got, c)
		}
	})
	wantExit(t, o, ExitApplied, ResultApplied)
	if len(got) != 1 {
		t.Fatalf("Committed called %d times", len(got))
	}
	c := got[0]
	if c.ID != o.ID || c.Until.IsZero() || c.Shape != o.Shape || c.Shape == "" || c.Exit != "" || !pendingAtHook {
		t.Errorf("at the commit: %+v (pending on the device: %v)", c, pendingAtHook)
	}
	got = nil
	d2 := newDevice(t, nil)
	check(t, d2, &planner{desired: desiredLines()}, func(in *Input) { in.Committed = func(c Outcome) { got = append(got, c) } })
	if len(got) != 0 {
		t.Errorf("a check called Committed: %+v", got)
	}
}
