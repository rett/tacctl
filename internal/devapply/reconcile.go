package devapply

import (
	"context"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// Reconcile is ReconcileAt at this machine's time.
func Reconcile(ctx context.Context, r Reader, device, id string, until time.Time, facts func(ctx context.Context, read string) (plan.Delta, error)) Outcome {
	return ReconcileAt(ctx, r, device, id, until, time.Now(), facts)
}

// ReconcileAt settles a record that says pending, or that a dead tacctl
// left at 'committed, verifying' (D132, D138): it reads the commit state
// through r (the history and the banner of a pending commit, lab L2) and
// names the state of apply id. until is the record's end of the window and
// now this machine's time. The exits are ExitPending (still pending: the
// device must not be touched), ExitRolledBack (cancelled, or the device's
// own rollback), ExitApplied (tacctl's confirm), ExitAppliedByOther (the
// change is in place after a commit tacctl does not recognise, or after a
// 'commit check') and ExitUnknown (the history could not be read or no
// longer shows the commit, or the device's rollbacks do not settle it).
// Outcome.Fate says what became of a settled apply.
//
// An entry after tacctl's commit that is neither its confirm nor its cancel
// (the device's own rollback 'by root via other' among them, which a
// commit of the system shares) is settled from the device's rollbacks
// (byRollbacks): the configuration that tacctl's commit produced is
// applied, the one before it rolled back, any other unknown. No banner with
// tacctl's commit still at entry 0 is ExitPending before until (and a
// minute's slack: a release or a session that prints no banner rolls it
// back at the end all the same), and after it ExitAppliedByOther (a
// 'commit check' confirmed it), proven the same way. A stranger's confirmed
// commit pending over an entry that named tacctl's fate is reported in the
// reason, and Until is then the end of the stranger's window. Everything is
// read on r in operational mode: 'show system commit' and 'show
// configuration | compare rollback N'.
//
// facts is the caller's planner over a read of the device (the delta of
// the read text with today's rendering), the last fallback when the
// rollbacks cannot be compared: it never names the state, it only says in
// the reason of ExitUnknown what the configuration shows. nil: none.
func ReconcileAt(ctx context.Context, r Reader, device, id string, until, now time.Time, facts func(ctx context.Context, read string) (plan.Delta, error)) (o Outcome) {
	o = Outcome{Device: device, ID: id, Step: "reconcile", Until: until}
	defer func() { o.Log = r.Log() }()
	st, err := r.State(ctx)
	if err != nil {
		o.Exit, o.Result = ExitUnknown, ResultUnknown
		o.Reason = "the state could not be read: " + err.Error()
		return o
	}
	s := settle(st, id, CommitEntry{}, now, until)
	if s.facts != factsNo {
		var compared bool
		s, compared = byRollbacks(ctx, r, st, id, s, func(err error) string { return err.Error() })
		switch {
		case compared:
		case facts == nil:
			s.how += "; check the device"
		default:
			if raw, err := r.Read(ctx); err != nil {
				s.e, s.how = byFacts(s.how, plan.Delta{}, err)
			} else {
				d, err := facts(ctx, raw)
				s.e, s.how = byFacts(s.how, d, err)
			}
		}
	}
	o.Exit, o.Result, o.Reason = s.e, resultOf(s.e), s.how
	switch s.e {
	case ExitApplied:
		o.Commit, o.Until, o.Fate = s.entry, time.Time{}, s.fate
	case ExitAppliedByOther, ExitRolledBack:
		o.Until, o.Fate = time.Time{}, s.fate
	case ExitPending:
		if st.Pending {
			o.Reason = "the confirmed commit is pending " + st.Until() + " by the device's clock"
		}
	}
	if s.over {
		o.Until = s.until
	}
	return o
}
