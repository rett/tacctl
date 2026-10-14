package devapply

import (
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"
)

// Exit is the named exit of plan §3.2 a transaction ended at.
type Exit string

// The exits. Each one has its test (driver_test.go).
const (
	// ExitFailed: FAILED before OPEN (the pre-flight, the read, the
	// allow-list, the gate, the open); the device is untouched.
	ExitFailed Exit = "failed"
	// ExitFailedLoad: FAILED at LOAD or at the compare's tripwire; the
	// candidate was discarded.
	ExitFailedLoad Exit = "failed-load"
	// ExitFailedCheck: FAILED at CHECK; the candidate was discarded.
	ExitFailedCheck Exit = "failed-check"
	// ExitNoChange: the device has the plan already.
	ExitNoChange Exit = "no-change"
	// ExitChecked: the check ended (the 'check' verb); the candidate was
	// discarded.
	ExitChecked Exit = "checked"
	// ExitNothingCommitted: READ-STATE after a commit's answer that was not
	// the required one: the history shows nothing committed.
	ExitNothingCommitted Exit = "nothing-committed"
	// ExitRolledBack: the change was committed and is undone (the cancel
	// worked, or the device's window ended and the history says so).
	ExitRolledBack Exit = "rolled-back"
	// ExitPending: PENDING-UNTIL: the device runs the change until Until and
	// then rolls it back by itself, unless someone commits.
	ExitPending Exit = "pending-until"
	// ExitWindowShort: the verification passed with less than the minimum
	// window left; nothing was typed, the device rolls back at Until (the
	// record says pending: the history has not shown the rollback yet).
	ExitWindowShort Exit = "window-short"
	// ExitApplied: confirmed and read back.
	ExitApplied Exit = "applied"
	// ExitAppliedByOther: the history shows tacctl's commit confirmed by
	// someone else's commit (D132).
	ExitAppliedByOther Exit = "applied-by-other"
	// ExitUnknown: the state could not be read after a failure past the
	// confirmed commit.
	ExitUnknown Exit = "unknown"
	// ExitInterrupted: the second interrupt (or the job's deadline) before
	// the confirmed commit; the discard was typed as far as the grace
	// allowed.
	ExitInterrupted Exit = "interrupted"
)

// Result is the record's word (D138 'result').
type Result string

// The results.
const (
	ResultChecked    Result = "checked"
	ResultNoChange   Result = "no-change"
	ResultPending    Result = "pending"
	ResultApplied    Result = "applied"
	ResultRolledBack Result = "rolled-back"
	ResultFailed     Result = "failed"
	ResultUnknown    Result = "unknown"
)

// resultOf is the record's word of an exit.
func resultOf(e Exit) Result {
	switch e {
	case ExitChecked:
		return ResultChecked
	case ExitNoChange:
		return ResultNoChange
	case ExitPending, ExitWindowShort:
		return ResultPending
	case ExitApplied, ExitAppliedByOther:
		return ResultApplied
	case ExitRolledBack:
		return ResultRolledBack
	case ExitUnknown:
		return ResultUnknown
	}
	return ResultFailed
}

// Counts are the delta's statements by verb, and the deletes the device
// answered 'statement not found' (counted, never a failure).
type Counts struct {
	Set, Delete, Insert int
	NotFound            int
}

// Outcome is how one device's transaction ended. Nothing in it holds a
// secret value or raw device output.
type Outcome struct {
	Device string
	// ID is the change identifier in the commit comments.
	ID     string
	Exit   Exit
	Result Result
	// Step is the state of plan §3.1 the transaction ended in.
	Step   string
	Reason string
	// Shape and ShapeLines are plan.Shape of the delta.
	Shape      string
	ShapeLines []string
	Sections   []string
	Counts     Counts
	// Until is the end of a pending window by this machine's clock (the
	// latest the device's own timer can end); zero when nothing is pending.
	Until time.Time
	// Commit is the confirming commit's history entry (applied).
	Commit *CommitEntry
	// Fate is, for a reconciled apply (Reconcile) that settled, what became
	// of it as a phrase after 'was' ('rolled back by the device at <time>');
	// "" otherwise.
	Fate string
	// Identity and Class are the pre-flight's.
	Identity Identity
	Class    string
	// Discarded: the candidate was dropped by 'rollback 0' and 'exit'.
	Discarded bool
	// Interrupted: the job's context was cancelled (the second interrupt).
	Interrupted bool
	// LoginRefused: the verification's fresh login was refused. It is a
	// verification failure, never a rejected password: the caller must not
	// tell its password cache to forget.
	LoginRefused bool
	// Durations are the steps' times.
	Durations map[string]time.Duration
	// Log is what the held login typed and read, VerifyLog what the
	// fresh login read, a secret's value elided.
	Log       []string
	VerifyLog []string
	// StoreErr is a failure to file the shape (the result stands).
	StoreErr error
}

// snapshot is a copy of the outcome so far for Input.Committed: the slices
// cloned, the logs and the step times left out.
func (o *Outcome) snapshot() Outcome {
	c := *o
	c.ShapeLines, c.Sections = slices.Clone(o.ShapeLines), slices.Clone(o.Sections)
	c.Durations, c.Log, c.VerifyLog = nil, nil, nil
	return c
}

// Line is the outcome as the per-device line of plan §3.2.
func (o Outcome) Line() string {
	sec := strings.Join(o.Sections, ",")
	counts := fmt.Sprintf("%d set, %d delete", o.Counts.Set, o.Counts.Delete)
	if o.Counts.Insert > 0 {
		counts += fmt.Sprintf(", %d insert", o.Counts.Insert)
	}
	switch o.Exit {
	case ExitNoChange:
		return "no change"
	case ExitChecked:
		return fmt.Sprintf("checked: shape %s (%s)", o.Shape, counts)
	case ExitApplied:
		return fmt.Sprintf("applied (%s: %s) [%s]", sec, counts, o.ID)
	case ExitAppliedByOther:
		return "applied by someone else's commit: " + o.Reason
	case ExitRolledBack:
		return "rolled back: " + o.Reason
	case ExitPending, ExitWindowShort:
		return fmt.Sprintf("PENDING until %s: do not type commit or commit check on the device; %s", o.Until.Format("15:04:05"), o.Reason)
	case ExitUnknown:
		return fmt.Sprintf("unknown: check the device; the window ends at %s", o.Until.Format("15:04:05"))
	case ExitInterrupted:
		return "interrupted"
	}
	return "failed: " + o.Reason
}

// NewID is a change identifier: 'tacctl-<yyyymmddThhmmssZ>-<4 hex>' (D138).
func NewID(now time.Time, r io.Reader) (string, error) {
	if r == nil {
		return "", fmt.Errorf("devapply: no random source")
	}
	var b [2]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return "", fmt.Errorf("devapply: the random source: %w", err)
	}
	return "tacctl-" + now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:]), nil
}

// NameMatches reports whether the name a device reports is one the registry
// knows it by (backlog §3d): the registry name, its first label, the
// registry's hostname field, its first label; case does not matter.
func NameMatches(reported string, names ...string) bool {
	r := strings.ToLower(strings.TrimSpace(reported))
	if r == "" {
		return false
	}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		first, _, _ := strings.Cut(n, ".")
		if r == n || r == first {
			return true
		}
	}
	return false
}
