// Package devapply is the transaction that writes a planner-generated
// change to a network device (docs/plans/0.2.9-apply-plan.md D129, D131,
// D132, D138): the transport interface with its first implementation, the
// Junos command line over one held 'configure exclusive' session; the driver
// that takes one device through the state machine of plan §3.1 and ends at
// one of the named exits of §3.2; the reconciliation of a pending confirmed
// commit; the shape store and the per-device lock.
//
// What it guarantees, and what the callers rely on:
//
//   - Nothing but the delta's statements and the apply's own words is ever
//     typed: every line passes plan.Allow (a statement) or plan.IsApplyWord
//     (a wrapper word) in the driver and again in the transport, and a line
//     either refuses is never sent.
//   - Every commit is a confirmed one with tacctl's comment, and the
//     confirming commit is typed only in the session that committed: the
//     verification uses a Reader, which cannot commit.
//   - A failure before the confirmed commit discards the candidate
//     ('rollback 0', 'exit') and says so (Outcome.Discarded); a failed
//     commit's answer is never named before the commit history is read.
//   - A parser that meets a text it does not know fails: no answer is ever
//     taken for success because it was not recognised as a failure.
//   - Nothing the package returns, logs or stores holds a secret value: the
//     statements are logged by plan.Line.Shown and every device text passes
//     the masker. A line of a stranger's staged compare is never quoted.
//   - A pending confirmed commit is told by the device's banner '# commit
//     confirmed will be rolled back in N minutes', which it prints before
//     the prompt of every session while one is pending (lab L2), and never
//     by the history: a 'commit check' confirms a pending commit without a
//     history entry, so entry 0 keeps its 'commit confirmed, rollback in
//     Nmins' label for good. The state is read as a CommitState: 'show
//     system commit' typed in a shell session, and the banner of the prompt
//     after it.
//   - No pending confirmed commit but tacctl's own is ever confirmed: the
//     state is read again right before 'commit check' (which confirms any
//     pending commit, D132), and the held session's own prompt must not
//     show the banner when the check is typed; a pending one fails the
//     transaction after the discard. The cancel commits only a candidate
//     whose compare is exactly the inverse of the committed change, loaded
//     while the banner still stood.
//   - A history entry after tacctl's commit that is not its confirm, its
//     cancel or the device's own rollback is never taken for a confirm: the
//     state is settled from the configuration (the planner's delta of a
//     read), or it is unknown.
//   - A panic in a transaction is a named exit: before the confirmed commit
//     the candidate is discarded (ExitFailed), after it the exit is
//     ExitUnknown with the window's end.
//
// ExitWindowShort is recorded 'pending' with the window's end, not
// 'rolled-back' as plan §3.1 draws it: nothing has shown the device's
// rollback yet, and a record that says pending is settled by the next read
// (Reconcile), which is the safer claim.
//
// It has no terminal, no logging and no package state; the clock, the
// random source and the logins (with their password sources) are inputs.
package devapply

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// Identity is what 'show version' reports.
type Identity struct {
	Hostname string
	Model    string
	Release  string
}

// Login is what 'show cli authorization' reports of this login.
type Login struct {
	// User is the 'Current user' (the local template account of a TACACS+
	// login), Name the 'login' (the person); both "" when the first line
	// does not name them.
	User        string
	Name        string
	Class       string
	Permissions []string
}

// CanCommit reports whether the class may configure and commit every
// hierarchy a plan writes: the 'all' permission. A narrower class (one with
// 'configure' and some of the '*-control' bits) is refused, because which
// bits a plan needs is not known before it is typed [D87's seam].
func (l Login) CanCommit() bool {
	for _, p := range l.Permissions {
		if p == "all" {
			return true
		}
	}
	return false
}

// CommitEntry is one entry of 'show system commit'.
type CommitEntry struct {
	Seq int
	// Time is the device's time of the commit, as it printed it (TimeText)
	// and parsed (the zone abbreviation is the device's; an unknown one
	// parses with a zero offset, so the wall clock is right and the
	// absolute time may not be).
	Time     time.Time
	TimeText string
	User     string
	Via      string
	// RollbackIn is the window of a confirmed commit in minutes (0: not a
	// confirmed commit). It is a label the entry keeps for good, also after
	// a 'commit check' confirmed the commit: never a pending marker
	// (CommitState.Pending is).
	RollbackIn int
	Comment    string
}

// Same reports whether two entries are the same commit.
func (e CommitEntry) Same(o CommitEntry) bool {
	return e.TimeText == o.TimeText && e.User == o.User && e.Via == o.Via && e.Comment == o.Comment && e.RollbackIn == o.RollbackIn
}

// History is 'show system commit', newest first.
type History []CommitEntry

// CommitState is the commit history with the pending marker, both from one
// answer: 'show system commit' typed in a shell session, and the prompt
// area the device printed after it (D132, lab L2).
type CommitState struct {
	History History
	// Pending is set when the prompt area held the banner '# commit
	// confirmed will be rolled back in N minute(s)': a confirmed commit is
	// pending, and it is entry 0 (any later commit would have confirmed
	// it). Minutes is N, the minutes left as the device tells them.
	Pending bool
	Minutes int
}

// Until is the end of a pending commit's window as a phrase: 'until <time>'
// by the device's clock when entry 0 carries its window, else 'for about N
// more minute(s)'; "" when nothing is pending.
func (s CommitState) Until() string {
	if !s.Pending {
		return ""
	}
	if len(s.History) > 0 {
		if u := s.History[0].Until(); u != "" {
			return "until " + u
		}
	}
	unit := "minutes"
	if s.Minutes == 1 {
		unit = "minute"
	}
	return fmt.Sprintf("for about %d more %s", s.Minutes, unit)
}

// Until is the end of a confirmed commit's window in the device's own wall
// clock text: the entry's time and its window ("" for an entry without
// one). It is an end only while the commit is pending (CommitState).
func (e CommitEntry) Until() string {
	if e.RollbackIn == 0 || e.Time.IsZero() {
		return ""
	}
	t := e.Time.Add(time.Duration(e.RollbackIn) * time.Minute)
	for _, layout := range historyTimeLayouts {
		if _, err := time.Parse(layout, e.TimeText); err == nil {
			return t.Format(layout)
		}
	}
	return t.Format(historyTimeLayouts[0])
}

// Dirty is what the gate saw in a throwaway shared session.
type Dirty struct {
	// Editors is set when 'configure' listed other editors; Staged when the
	// shared candidate differs from the committed configuration.
	Editors bool
	Staged  bool
}

// Any reports whether the gate fails.
func (d Dirty) Any() bool { return d.Editors || d.Staged }

// Loaded is the answer to one statement.
type Loaded struct {
	// NotFound is the tolerated 'statement not found' to a delete.
	NotFound bool
}

// Reader is a login that reads: the pre-flight, the verification's fresh
// login, the reconciliation. It cannot change the device.
type Reader interface {
	Vendor() string
	// Identity runs 'show version'.
	Identity(ctx context.Context) (Identity, error)
	// History runs 'show system commit'. It tells nothing of a pending
	// commit (State does).
	History(ctx context.Context) (History, error)
	// State runs 'show system commit' in a shell session and reads the
	// pending marker from the prompt the device printed after it. A prompt
	// area it does not know is an error, never 'not pending'.
	State(ctx context.Context) (CommitState, error)
	// Login runs 'show cli authorization'.
	Login(ctx context.Context) (Login, error)
	// Read runs the pull's read command and returns its text (for the
	// caller's planner; never stored by this package).
	Read(ctx context.Context) (string, error)
	// LandedCompare runs 'show configuration | compare rollback 1',
	// normalised for the delta (plan.ParseCompareFor). A text that did not
	// end as the command ends (an exec channel closed with its exit status)
	// is an error, never a smaller compare.
	LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error)
	// Log is what was typed, a secret's value elided (a copy).
	Log() []string
	Close() error
}

// Transport is the device an apply writes to (D129). The driver uses it in
// the order of plan §3.1 and never against the command line directly, so a
// NETCONF transport can be added without a change to the driver.
type Transport interface {
	Reader
	// Confirms reports whether an apply can commit and confirm through this
	// transport: the device is one the transport can write to and the login's
	// class may commit. False until Login has been read.
	Confirms() bool
	// RollsBackOnClose reports whether closing the transport rolls a pending
	// confirmed commit back (NETCONF) or not (the command line: only the
	// window's end does, D132).
	RollsBackOnClose() bool
	// LocalAddr is the address this machine reaches the device from (the
	// planner's --from, D133).
	LocalAddr() net.IP
	// SharedDirty is the gate (D131 step 3): other editors or a staged
	// change in the shared candidate, read in a throwaway session that types
	// nothing but 'configure' and the compare. Another session's exclusive
	// lock among the editors is a *LockedError.
	SharedDirty(ctx context.Context) (Dirty, error)
	// Open enters configuration mode in the held session with 'configure
	// exclusive' (there is no private mode: a private session refuses
	// 'commit confirmed', lab L5); allow is the allow-list every statement
	// Load is given must pass. A held lock is a *LockedError.
	Open(ctx context.Context, allow func(line string) error) error
	// Held reports whether the held session is open and in configuration
	// mode.
	Held() bool
	// Load types one statement.
	Load(ctx context.Context, l plan.Line) (Loaded, error)
	// Compare runs 'show | compare' in the held session, normalised for
	// the delta (plan.ParseCompareFor). The answer must have ended at the
	// configure prompt with the location line before it; a read that ended
	// any other way is an error, never a smaller compare.
	Compare(ctx context.Context, d plan.Delta) (plan.CompareText, error)
	// Check runs 'commit check', and only when the held session's last
	// prompt showed no pending confirmed commit (ErrPending otherwise).
	Check(ctx context.Context) error
	// CommitConfirmed commits under a window of minutes with tacctl's
	// comment; the held session's prompt must then show the banner.
	CommitConfirmed(ctx context.Context, minutes int, id, user string) error
	// Confirm is the confirming commit, in the held session.
	Confirm(ctx context.Context, id, user string) error
	// Cancel loads the configuration before the confirmed commit and commits
	// it, which ends the window at once (D131 Cancel, lab L2), only when the
	// banner still stood after the load and what it loaded is exactly the
	// inverse of the committed change (the held session's last Compare);
	// otherwise it discards and commits nothing.
	Cancel(ctx context.Context, id string) error
	// Discard drops the candidate and leaves configuration mode ('rollback
	// 0', 'exit'); after a failure it closes the held session instead, which
	// drops an exclusive candidate all the same.
	Discard(ctx context.Context) error
}
