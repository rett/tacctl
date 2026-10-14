package devrollout

import (
	"context"
	"time"
)

// Reconcile settles a record that says pending, or that a dead tacctl left
// at 'committed, verifying' (D132, D138): it reads the commit history
// through r and names the state of rollout id. until is the record's end of
// the window. The exits are ExitPending (still pending: the device must not
// be touched), ExitRolledBack (cancelled, or the device's own rollback),
// ExitApplied (tacctl's confirm), ExitAppliedByOther (someone else's commit
// confirmed it) and ExitUnknown (the history could not be read or no longer
// shows the commit). Nothing is typed but 'show system commit'.
func Reconcile(ctx context.Context, r Reader, device, id string, until time.Time) Outcome {
	o := Outcome{Device: device, ID: id, Step: "reconcile", Until: until}
	h, err := r.History(ctx)
	o.Log = r.Log()
	if err != nil {
		o.Exit, o.Result = ExitUnknown, ResultUnknown
		o.Reason = "the state could not be read: " + err.Error()
		return o
	}
	e, how, entry := settle(h, id, CommitEntry{})
	o.Exit, o.Result, o.Reason = e, resultOf(e), how
	switch e {
	case ExitApplied:
		o.Commit, o.Until = entry, time.Time{}
	case ExitAppliedByOther, ExitRolledBack:
		o.Until = time.Time{}
	case ExitPending:
		if p, ok := h.Pending(); ok {
			o.Reason = "the confirmed commit is pending until " + p.Until() + " by the device's clock"
		}
	}
	return o
}
