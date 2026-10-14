package devapply

import (
	"context"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// Reconcile settles a record that says pending, or that a dead tacctl left
// at 'committed, verifying' (D132, D138): it reads the commit state
// through r (the history and the banner of a pending commit, lab L2) and
// names the state of apply id. until is the record's end of
// the window. The exits are ExitPending (still pending: the device must not
// be touched), ExitRolledBack (cancelled, or the device's own rollback),
// ExitApplied (tacctl's confirm), ExitAppliedByOther (the change is in place
// after a commit tacctl does not recognise) and ExitUnknown (the history
// could not be read or no longer shows the commit).
//
// facts is the caller's planner over a read of the device (the delta of
// the read text). An entry after tacctl's commit that is neither its
// confirm, its cancel nor the device's own rollback is settled from it: no
// delta is applied by someone else's commit, a delta is rolled back. With
// facts nil such an entry is ExitUnknown. No banner with tacctl's commit
// still at entry 0 is ExitAppliedByOther (a 'commit check' confirmed it).
// Nothing is typed but 'show system commit' and, for facts, the pull's
// read command.
func Reconcile(ctx context.Context, r Reader, device, id string, until time.Time, facts func(ctx context.Context, read string) (plan.Delta, error)) (o Outcome) {
	o = Outcome{Device: device, ID: id, Step: "reconcile", Until: until}
	defer func() { o.Log = r.Log() }()
	st, err := r.State(ctx)
	if err != nil {
		o.Exit, o.Result = ExitUnknown, ResultUnknown
		o.Reason = "the state could not be read: " + err.Error()
		return o
	}
	e, how, entry, odd := settle(st, id, CommitEntry{})
	if odd {
		if facts == nil {
			how += "; check the device"
		} else if raw, err := r.Read(ctx); err != nil {
			e, how = byFacts(how, plan.Delta{}, err)
		} else {
			d, err := facts(ctx, raw)
			e, how = byFacts(how, d, err)
		}
	}
	o.Exit, o.Result, o.Reason = e, resultOf(e), how
	switch e {
	case ExitApplied:
		o.Commit, o.Until = entry, time.Time{}
	case ExitAppliedByOther, ExitRolledBack:
		o.Until = time.Time{}
	case ExitPending:
		o.Reason = "the confirmed commit is pending " + st.Until() + " by the device's clock"
	}
	return o
}
