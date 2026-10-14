// Package devrollout is the transaction that writes a planner-generated
// change to a network device (docs/plans/0.2.9-rollout-plan.md D129, D131,
// D132, D138): the transport interface with its first implementation, the
// Junos command line over one held 'configure exclusive' session; the driver
// that takes one device through the state machine of plan §3.1 and ends at
// one of the named exits of §3.2; the reconciliation of a pending confirmed
// commit; the shape store and the per-device lock.
//
// What it guarantees, and what the callers rely on:
//
//   - Nothing but the delta's statements and the rollout's own words is ever
//     typed: every line passes plan.Allow (a statement) or plan.IsRolloutWord
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
//     the masker.
//
// It has no terminal, no logging and no package state; the clock, the
// random source and the logins (with their password sources) are inputs.
package devrollout

import (
	"context"
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
	// confirmed commit). Entry 0 with it is a pending commit.
	RollbackIn int
	Comment    string
}

// Same reports whether two entries are the same commit.
func (e CommitEntry) Same(o CommitEntry) bool {
	return e.TimeText == o.TimeText && e.User == o.User && e.Via == o.Via && e.Comment == o.Comment && e.RollbackIn == o.RollbackIn
}

// History is 'show system commit', newest first.
type History []CommitEntry

// Pending reports whether entry 0 is a confirmed commit waiting for its
// confirm, and when its window ends by the device's clock.
func (h History) Pending() (CommitEntry, bool) {
	if len(h) == 0 || h[0].RollbackIn == 0 {
		return CommitEntry{}, false
	}
	return h[0], true
}

// Until is a pending entry's end in the device's own wall clock text.
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

// OpenMode is how the held session enters configuration mode.
type OpenMode int

// The modes: exclusive (the default, D131) and private (--private).
const (
	OpenExclusive OpenMode = iota
	OpenPrivate
)

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
	// History runs 'show system commit'.
	History(ctx context.Context) (History, error)
	// Login runs 'show cli authorization'.
	Login(ctx context.Context) (Login, error)
	// Read runs the pull's read command and returns its text (for the
	// caller's planner; never stored by this package).
	Read(ctx context.Context) (string, error)
	// LandedCompare runs 'show system rollback compare 1 0', normalised
	// for the delta (plan.ParseCompareFor). A text that did not end as the
	// command ends (an exec channel closed with its exit status) is an
	// error, never a smaller compare.
	LandedCompare(ctx context.Context, d plan.Delta) (plan.CompareText, error)
	// Log is what was typed, a secret's value elided (a copy).
	Log() []string
	Close() error
}

// Transport is the device a rollout writes to (D129). The driver uses it in
// the order of plan §3.1 and never against the command line directly, so a
// NETCONF transport can be added without a change to the driver.
type Transport interface {
	Reader
	// Confirms reports whether a rollout can commit and confirm through this
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
	// nothing but 'configure' and the compare.
	SharedDirty(ctx context.Context) (Dirty, error)
	// Open enters configuration mode in the held session; allow is the
	// allow-list every statement Load is given must pass.
	Open(ctx context.Context, mode OpenMode, allow func(line string) error) error
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
	// Check runs 'commit check'.
	Check(ctx context.Context) error
	// CommitConfirmed commits under a window of minutes with tacctl's
	// comment.
	CommitConfirmed(ctx context.Context, minutes int, id, user string) error
	// Confirm is the confirming commit, in the held session.
	Confirm(ctx context.Context, id, user string) error
	// Cancel loads the configuration before the confirmed commit and commits
	// it, which ends the window at once (D131 Cancel).
	Cancel(ctx context.Context, id string) error
	// Discard drops the candidate and leaves configuration mode ('rollback
	// 0', 'exit'); after a failure it closes the held session instead, which
	// drops an exclusive candidate all the same.
	Discard(ctx context.Context) error
}
