package devrollout

// The driver: one device through the state machine of plan §3.1, against
// the Transport interface and never against a command line. Each return is
// one of the named exits of Exit.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
)

// The defaults of the driver's margins.
const (
	// DefaultMinWindow is the window that must be left for the confirm
	// (D131 step 10): with less, nothing is typed.
	DefaultMinWindow = 60 * time.Second
	// DefaultCancelMargin is the window that must be left for the cancel:
	// a 'rollback 1' typed after the device's own rollback would load the
	// change itself, and its commit would keep it, so with less nothing is
	// typed and the device's expiry is the cancel.
	DefaultCancelMargin = 30 * time.Second
	// DefaultGrace bounds what is typed after the job's context ended (the
	// discard, the cancel and the state read).
	DefaultGrace = 15 * time.Second
	// MinConfirmMinutes and MaxConfirmMinutes are the range of
	// device.rollout.confirm_timeout (D140).
	MinConfirmMinutes = 3
	MaxConfirmMinutes = 60
)

// Input is one device's transaction.
type Input struct {
	// Device is the registry name; Names the names the device may report
	// (the registry name and its hostname field, D131 step 1).
	Device string
	Names  []string
	// User is the invoking user, written in the commit comments.
	User string
	// Transport is the held login, dialled by the caller (the password
	// source is the caller's). The driver closes it.
	Transport Transport
	// Verify dials the verification's fresh login (D131 step 9: the
	// invoking user; onboard: the user's TACACS+ login). Nil for Check.
	Verify func(ctx context.Context) (Reader, error)
	// Plan is the caller's planner: the delta for the read text of the
	// device, with the address tacctl connects from (D133's --from). It
	// may refresh the pull record from the text; it must not keep the text.
	Plan func(ctx context.Context, read string, from net.IP) (plan.Delta, error)
	// Allow is the allow-list's input: Expected (the rendering; required,
	// plan.Allow.Ready), Login and LoginClass (the invoking login and its
	// class; LoginClass empty is the pre-flight's class). The driver sets
	// Vendor and Sections from the delta.
	Allow plan.Allow
	// Mode is exclusive (the default) or private.
	Mode OpenMode
	// ConfirmMinutes is the window (device.rollout.confirm_timeout).
	ConfirmMinutes int
	// Hold is the optional --hold (D134 Q2): after the verification, true
	// keeps the change. Nil: none.
	Hold func(ctx context.Context, until time.Time) (bool, error)
	// Clock and Rand are the time and the random source of the change id.
	Clock func() time.Time
	Rand  io.Reader
	// StateDir, when set, holds the device's lock ('<dir>/<device>.lock')
	// for the transaction and the shape store, which an applied rollout
	// files its shape in.
	StateDir string
}

// Driver runs transactions. The zero value has the default margins.
type Driver struct {
	MinWindow    time.Duration
	CancelMargin time.Duration
	Grace        time.Duration
}

// Check is the check phase alone ('device rollout check'): the device loads
// the plan, 'commit check' runs, the candidate is discarded.
func (d Driver) Check(ctx context.Context, in Input) Outcome {
	return d.run(ctx, in, nil)
}

// Apply is the whole transaction against the reviewed delta: a delta
// recomputed from the device that is not the reviewed one fails.
func (d Driver) Apply(ctx context.Context, in Input, reviewed plan.Delta) Outcome {
	return d.run(ctx, in, &reviewed)
}

// run is one transaction.
type run struct {
	d   Driver
	in  Input
	t   Transport
	o   *Outcome
	m   *masker
	ctx context.Context

	stepName  string
	stepStart time.Time

	id        string
	minutes   int
	pre       CommitEntry
	compare   plan.CompareText
	delta     plan.Delta
	windowEnd time.Time
	vr        Reader
}

func (d Driver) margins() Driver {
	if d.MinWindow <= 0 {
		d.MinWindow = DefaultMinWindow
	}
	if d.CancelMargin <= 0 {
		d.CancelMargin = DefaultCancelMargin
	}
	if d.Grace <= 0 {
		d.Grace = DefaultGrace
	}
	return d
}

func (d Driver) run(ctx context.Context, in Input, reviewed *plan.Delta) (out Outcome) {
	r := &run{d: d.margins(), in: in, t: in.Transport, o: &Outcome{Device: in.Device, Durations: map[string]time.Duration{}}, m: &masker{}, ctx: ctx}
	defer func() {
		r.endStep()
		r.finish()
		out = *r.o
	}()
	if err := r.validate(reviewed != nil); err != nil {
		r.fail(ExitFailed, "input", err.Error())
		if r.t != nil {
			_ = r.t.Close()
		}
		return
	}
	defer func() { _ = r.t.Close() }()
	if in.StateDir != "" {
		lk, err := LockDevice(in.StateDir, in.Device)
		if err != nil {
			r.fail(ExitFailed, "lock", err.Error())
			return
		}
		defer lk.Unlock()
	}
	id, err := NewID(r.now(), in.Rand)
	if err != nil {
		r.fail(ExitFailed, "input", err.Error())
		return
	}
	r.id, r.o.ID = id, id
	r.minutes = in.ConfirmMinutes
	if reviewed != nil {
		for _, l := range reviewed.Lines {
			r.m.add(l)
		}
	}
	r.transaction(reviewed)
	return out
}

// validate refuses an input the driver cannot run safely.
func (r *run) validate(apply bool) error {
	in := r.in
	switch {
	case in.Transport == nil:
		return errors.New("no transport")
	case in.Clock == nil:
		return errors.New("no clock")
	case in.Rand == nil:
		return errors.New("no random source")
	case in.Plan == nil:
		return errors.New("no planner")
	case len(in.Names) == 0:
		return errors.New("no name the device may report")
	case in.Device == "":
		return errors.New("no device name")
	case in.Allow.Login == "":
		return errors.New("no invoking login for the allow-list")
	case apply && in.Verify == nil:
		return errors.New("no verification login")
	case apply && (in.ConfirmMinutes < MinConfirmMinutes || in.ConfirmMinutes > MaxConfirmMinutes):
		return fmt.Errorf("the confirm window %d is not %d-%d minutes", in.ConfirmMinutes, MinConfirmMinutes, MaxConfirmMinutes)
	case apply && !plan.IsRolloutWord(plan.RolloutCommitConfirmed(in.ConfirmMinutes, "tacctl-x", in.User)):
		return fmt.Errorf("the user %q cannot be written in a commit comment", in.User)
	}
	return nil
}

func (r *run) now() time.Time { return r.in.Clock() }

// step starts a state of §3.1.
func (r *run) step(name string) {
	r.endStep()
	r.stepName, r.stepStart = name, r.now()
	r.o.Step = name
}

func (r *run) endStep() {
	if r.stepName != "" {
		r.o.Durations[r.stepName] += r.now().Sub(r.stepStart)
		r.stepName = ""
	}
}

// fail ends the transaction at exit with the reason (masked).
func (r *run) fail(e Exit, step, reason string) {
	if step != "" {
		r.o.Step = step
	}
	r.o.Exit, r.o.Result = e, resultOf(e)
	r.o.Reason = r.m.text(reason)
}

// end names the exit.
func (r *run) end(e Exit, reason string) { r.fail(e, "", reason) }

// finish masks what the outcome carries and closes the fresh login.
func (r *run) finish() {
	if r.vr != nil {
		r.o.VerifyLog = r.m.lines(r.vr.Log())
		_ = r.vr.Close()
		r.vr = nil
	}
	if r.t != nil {
		r.o.Log = r.m.lines(r.t.Log())
	}
	r.o.Reason = r.m.text(r.o.Reason)
	if r.o.Exit == "" {
		r.o.Exit, r.o.Result = ExitUnknown, ResultUnknown
		r.o.Reason = "the transaction ended without a named exit"
	}
	r.o.Interrupted = r.o.Interrupted || errors.Is(r.ctx.Err(), context.Canceled)
}

// errText is an error as a reason.
func (r *run) errText(err error) string { return r.m.text(err.Error()) }

// done reports whether the job's context ended (the second interrupt or the
// job's deadline).
func (r *run) done() bool { return r.ctx.Err() != nil }

// grace is the context for what is typed after the job's context ended.
func (r *run) grace() (context.Context, context.CancelFunc) {
	if !r.done() {
		return context.WithCancel(r.ctx)
	}
	return context.WithTimeout(context.WithoutCancel(r.ctx), r.d.Grace)
}

// transaction is plan §3.1 from PREFLIGHT on.
func (r *run) transaction(reviewed *plan.Delta) {
	ctx, t, in := r.ctx, r.t, r.in
	apply := reviewed != nil

	// PREFLIGHT
	r.step("preflight")
	if t.Vendor() != devssh.VendorJuniper {
		r.end(ExitFailed, fmt.Sprintf("rollout is not available for %s devices in this release", t.Vendor()))
		return
	}
	id, err := t.Identity(ctx)
	if err != nil {
		r.end(ExitFailed, "pre-flight: "+r.errText(err))
		return
	}
	r.o.Identity = id
	if !NameMatches(id.Hostname, in.Names...) {
		r.end(ExitFailed, fmt.Sprintf("calls itself '%s'", cut(id.Hostname)))
		return
	}
	h, err := t.History(ctx)
	if err != nil {
		r.end(ExitFailed, "pre-flight: "+r.errText(err))
		return
	}
	if p, ok := h.Pending(); ok {
		r.end(ExitFailed, fmt.Sprintf("a confirmed commit is pending until %s; nothing was sent", p.Until()))
		return
	}
	r.pre = h[0]
	lg, err := t.Login(ctx)
	if err != nil {
		r.end(ExitFailed, "pre-flight: "+r.errText(err))
		return
	}
	r.o.Class = lg.Class
	if !t.Confirms() {
		r.end(ExitFailed, fmt.Sprintf("cannot commit as this login (class %s)", cut(lg.Class)))
		return
	}

	// READ
	r.step("read")
	raw, err := t.Read(ctx)
	if err != nil {
		r.end(ExitFailed, "read: "+r.errText(err))
		return
	}
	delta, err := in.Plan(ctx, raw, t.LocalAddr())
	if err != nil {
		r.end(ExitFailed, "plan: "+r.errText(err))
		return
	}
	for _, l := range delta.Lines {
		r.m.add(l)
	}
	r.delta = delta
	r.o.Sections = delta.Planned()
	r.o.Shape, r.o.ShapeLines = plan.Shape(delta)
	for _, l := range r.o.ShapeLines {
		if r.m.holds(l) {
			// a shape never holds a value; one that does is neither shown
			// nor filed
			r.o.Shape, r.o.ShapeLines = "", nil
			break
		}
	}
	for _, l := range delta.Lines {
		switch l.Op {
		case plan.OpSet:
			r.o.Counts.Set++
		case plan.OpDelete:
			r.o.Counts.Delete++
		case plan.OpInsert:
			r.o.Counts.Insert++
		}
	}
	if fam, _ := devconf.Family(delta.Vendor); fam != devconf.FamilyJunos {
		r.end(ExitFailed, "plan: the delta is not a Junos plan")
		return
	}
	if apply && !delta.Equal(*reviewed) {
		r.end(ExitFailed, "the device changed since the review")
		return
	}
	if delta.Counts.Placeholders > 0 {
		r.end(ExitFailed, "the plan holds placeholders for secrets it could not fill")
		return
	}
	if delta.Empty() {
		r.end(ExitNoChange, "")
		return
	}

	// ALLOW
	r.step("allow")
	allow := in.Allow
	allow.Vendor = delta.Vendor
	allow.Sections = delta.Planned()
	if allow.LoginClass == "" {
		// the held login's own class, from the pre-flight: never changed
		// beyond what the rendering sets
		allow.LoginClass = r.o.Class
	}
	if err := allow.Ready(); err != nil {
		r.end(ExitFailed, "the allow-list is not ready (nothing was sent): "+r.errText(err))
		return
	}
	if err := allow.CheckDelta(delta); err != nil {
		r.end(ExitFailed, "statement outside the planner's domain (nothing was sent): "+r.errText(err))
		return
	}
	check := func(line string) error { return allow.Check(line) }

	// GATE
	r.step("gate")
	dirty, err := t.SharedDirty(ctx)
	if err != nil {
		var le *LockedError
		if errors.As(err, &le) {
			r.end(ExitFailed, le.Error())
		} else {
			r.end(ExitFailed, "gate: "+r.errText(err))
		}
		return
	}
	if dirty.Any() {
		r.end(ExitFailed, "other editors or staged changes")
		return
	}
	if r.done() {
		r.o.Interrupted = errors.Is(ctx.Err(), context.Canceled)
		r.end(ExitInterrupted, "interrupted before the device was changed")
		return
	}

	// OPEN
	r.step("open")
	if err := t.Open(ctx, in.Mode, check); err != nil {
		var le *LockedError
		switch {
		case errors.As(err, &le):
			r.end(ExitFailed, le.Error())
		default:
			r.end(ExitFailed, "open: "+r.errText(err))
		}
		return
	}

	// LOAD: from here every failure before the commit discards
	r.step("load")
	for _, l := range delta.Lines {
		if r.done() {
			r.interruptBeforeCommit()
			return
		}
		if err := check(l.Text); err != nil {
			r.discard(ExitFailedLoad, "load: not sent: "+r.errText(err))
			return
		}
		res, err := t.Load(ctx, l)
		if err != nil {
			if r.done() {
				r.interruptBeforeCommit()
				return
			}
			msg := r.errText(err)
			var ae *AnswerError
			if errors.As(err, &ae) {
				msg = ae.Message()
			}
			r.discard(ExitFailedLoad, fmt.Sprintf("load: %s: %s", l.Shown(), msg))
			return
		}
		if res.NotFound {
			r.o.Counts.NotFound++
		}
	}

	// COMPARE
	r.step("compare")
	c, err := t.Compare(ctx, delta)
	if err != nil {
		if r.done() {
			r.interruptBeforeCommit()
			return
		}
		r.discard(ExitFailedLoad, "compare: "+r.errText(err))
		return
	}
	if c.Empty() {
		r.discard(ExitNoChange, "")
		return
	}
	if un := c.Unexplained(delta); len(un) > 0 {
		r.discard(ExitFailedLoad, "the candidate holds a change outside the delta: "+un[0])
		return
	}
	r.compare = c

	// CHECK
	r.step("check")
	if err := t.Check(ctx); err != nil {
		if r.done() {
			r.interruptBeforeCommit()
			return
		}
		msg := r.errText(err)
		var ae *AnswerError
		if errors.As(err, &ae) {
			msg = ae.Message()
		}
		r.discard(ExitFailedCheck, "check: "+msg)
		return
	}
	if !apply {
		r.discard(ExitChecked, "")
		return
	}
	batch.Progress(ctx, "checked")
	if r.done() {
		r.interruptBeforeCommit()
		return
	}

	// COMMIT-C: entry 0 is read again right before, so that 'nothing was
	// committed' is judged against the history the commit would follow
	r.step("commit")
	h, err = t.History(ctx)
	if err != nil {
		if r.done() {
			r.interruptBeforeCommit()
			return
		}
		r.discard(ExitFailedCheck, "the history before the commit: "+r.errText(err))
		return
	}
	if p, ok := h.Pending(); ok {
		r.discard(ExitFailedCheck, fmt.Sprintf("a confirmed commit is pending until %s", p.Until()))
		return
	}
	r.pre = h[0]
	sent := r.now()
	err = t.CommitConfirmed(ctx, r.minutes, r.id, in.User)
	answered := r.now()
	window := time.Duration(r.minutes) * time.Minute
	// the device's timer starts after the line was sent and before the
	// answer: the window ends no sooner than sent+N (the margins count from
	// it) and no later than answered+N (what the record says)
	r.windowEnd = sent.Add(window)
	r.o.Until = answered.Add(window)
	if err != nil {
		why := "the confirmed commit's answer: " + r.errText(err)
		var ae *AnswerError
		if errors.As(err, &ae) && containsLine(ae.Lines, textNoConfirmedPrivate) {
			why = "this release refuses commit confirmed in a private session; run without --private"
		}
		r.readState(why, true)
		return
	}
	batch.Progress(ctx, "committed, verifying")

	// VERIFY
	r.step("verify")
	if why := r.verify(); why != "" {
		if r.done() {
			why = "interrupted"
		} else {
			why = "verification failed (" + why + ")"
		}
		r.cancel(why)
		return
	}

	// WINDOW
	r.step("window")
	if r.now().After(r.windowEnd.Add(-r.d.MinWindow)) {
		r.end(ExitWindowShort, fmt.Sprintf("the window ran short: not confirmed; the device rolls back at %s", r.o.Until.Format("15:04:05")))
		return
	}
	if r.done() {
		r.cancel("interrupted")
		return
	}

	// CONFIRM
	r.step("confirm")
	batch.Progress(ctx, "confirming")
	if err := t.Confirm(ctx, r.id, in.User); err != nil {
		r.readState(fmt.Sprintf("the confirm's answer: %s", r.errText(err)), false)
		return
	}

	// RECORD
	r.step("record")
	r.record()
}

// interruptBeforeCommit is the second interrupt before the confirmed
// commit: the discard, typed within the grace.
func (r *run) interruptBeforeCommit() {
	r.o.Interrupted = errors.Is(r.ctx.Err(), context.Canceled)
	r.discard(ExitInterrupted, "interrupted before the commit; the candidate was discarded")
	if !r.o.Discarded {
		r.o.Reason = "interrupted before the commit; the held session was closed, which drops its candidate"
	}
}

// discard ends a transaction before the commit: 'rollback 0' and 'exit', or
// the held session closed when they do not answer as they must.
func (r *run) discard(e Exit, reason string) {
	ctx, cancel := r.grace()
	defer cancel()
	err := r.t.Discard(ctx)
	r.o.Discarded = err == nil
	r.end(e, reason)
	if err != nil && e != ExitInterrupted {
		r.o.Reason += "; the discard did not answer as it must (" + r.errText(err) + "): the held session was closed, which drops its candidate"
	}
}

// verify is D131 step 9 on a fresh login; it returns why it failed ("" it
// passed).
func (r *run) verify() string {
	ctx := r.ctx
	vr, err := r.in.Verify(ctx)
	if err != nil {
		if errors.Is(err, devssh.ErrAuth) {
			r.o.LoginRefused = true
			return "the fresh login was refused"
		}
		return "the fresh login failed: " + r.errText(err)
	}
	r.vr = vr
	h, err := vr.History(ctx)
	if err != nil {
		return "show system commit: " + r.errText(err)
	}
	if p, ok := h.Pending(); !ok || !ours(p, r.id) {
		return "entry 0 of the history is not tacctl's pending commit"
	}
	if _, err := vr.Login(ctx); err != nil {
		return "the fresh login's class: " + r.errText(err)
	}
	landed, err := vr.LandedCompare(ctx, r.delta)
	if err != nil {
		return "the landed compare: " + r.errText(err)
	}
	if !landed.Equal(r.compare) {
		return "what landed is not the change the check showed"
	}
	raw, err := vr.Read(ctx)
	if err != nil {
		return "the convergence read: " + r.errText(err)
	}
	after, err := r.in.Plan(ctx, raw, r.t.LocalAddr())
	if err != nil {
		return "the convergence plan: " + r.errText(err)
	}
	for _, l := range after.Lines {
		r.m.add(l)
	}
	for _, l := range after.Lines {
		if !slices.Contains(r.o.Sections, l.Section) {
			continue
		}
		if l.Op == plan.OpDelete {
			return fmt.Sprintf("%s still holds what '%s' removes", l.Section, l.Shown())
		}
		return fmt.Sprintf("%s still lacks %s", l.Section, l.Shown())
	}
	if r.in.Hold != nil {
		ok, err := r.in.Hold(ctx, r.o.Until)
		if err != nil {
			return "the hold: " + r.errText(err)
		}
		if !ok {
			return "the hold was not confirmed"
		}
	}
	return ""
}

// The comments of tacctl's commits, as 'show system commit' shows them.
func commitComment(id string) string  { return "tacctl rollout " + id + " by " }
func confirmComment(id string) string { return "tacctl rollout confirm " + id + " by " }
func cancelComment(id string) string  { return "tacctl rollout cancel " + id }

// ours reports whether the entry is the confirmed commit of the rollout id.
func ours(e CommitEntry, id string) bool { return strings.HasPrefix(e.Comment, commitComment(id)) }

// settle names the state of rollout id from the history (D132). pre is
// entry 0 before the commit (zero: unknown).
func settle(h History, id string, pre CommitEntry) (Exit, string, *CommitEntry) {
	k := slices.IndexFunc(h, func(e CommitEntry) bool { return ours(e, id) })
	switch {
	case k < 0 && pre.TimeText != "" && len(h) > 0 && h[0].Same(pre):
		return ExitNothingCommitted, "nothing was committed", nil
	case k < 0:
		return ExitUnknown, "the history does not show tacctl's commit " + id, nil
	case k == 0 && h[0].RollbackIn > 0:
		return ExitPending, "the confirmed commit is pending", nil
	case k == 0:
		return ExitUnknown, "tacctl's commit is entry 0 without a window", nil
	}
	next := h[k-1]
	switch {
	case strings.HasPrefix(next.Comment, confirmComment(id)) && next.RollbackIn == 0:
		return ExitApplied, "", &next
	case strings.HasPrefix(next.Comment, cancelComment(id)):
		return ExitRolledBack, "cancelled at " + next.TimeText, nil
	case next.User == textExpiryUser && next.Via == textExpiryVia && next.Comment == "":
		return ExitRolledBack, "the device rolled it back at " + next.TimeText, nil
	}
	return ExitAppliedByOther, fmt.Sprintf("confirmed by a commit of %s at %s", cut(next.User), next.TimeText), nil
}

// history reads the commit history after a failure: on the fresh login if
// one is open, on the held login's connection, and on a new fresh login.
func (r *run) history(ctx context.Context) (History, error) {
	if r.vr != nil {
		if h, err := r.vr.History(ctx); err == nil {
			return h, nil
		}
	}
	h, last := r.t.History(ctx)
	if last == nil {
		return h, nil
	}
	if r.in.Verify != nil {
		vr, err := r.in.Verify(ctx)
		if err != nil {
			return nil, err
		}
		if r.vr != nil {
			_ = r.vr.Close()
		}
		r.vr = vr
		return vr.History(ctx)
	}
	return nil, last
}

// readState is READ-STATE (D132): after a failure past the confirmed commit
// the history is read before the state is named. With cancelPending a
// pending commit of this rollout is cancelled first (an answer the
// transport did not know is never taken for a commit to keep).
func (r *run) readState(why string, cancelPending bool) {
	ctx, cancelCtx := r.grace()
	defer cancelCtx()
	h, err := r.history(ctx)
	if err != nil {
		r.end(ExitUnknown, why+"; the state could not be read: "+r.errText(err))
		return
	}
	e, how, entry := settle(h, r.id, r.pre)
	if e == ExitPending && cancelPending {
		r.cancel(why)
		return
	}
	r.named(e, why, how, entry)
}

// named sets the exit settle found.
func (r *run) named(e Exit, why, how string, entry *CommitEntry) {
	switch e {
	case ExitNothingCommitted:
		// the candidate is still loaded: it is discarded as before a commit
		r.o.Until = time.Time{}
		if r.t.Held() {
			ctx, cancel := r.grace()
			r.o.Discarded = r.t.Discard(ctx) == nil
			cancel()
		}
		r.end(e, fmt.Sprintf("nothing was committed (%s)", why))
	case ExitApplied:
		r.o.Commit = entry
		r.end(e, "")
		r.o.Until = time.Time{}
		r.fileShape()
	case ExitAppliedByOther:
		r.o.Until = time.Time{}
		r.end(e, how)
	case ExitRolledBack:
		r.o.Until = time.Time{}
		r.end(e, why+"; "+how)
	default:
		r.end(e, why)
	}
}

// cancel is D131's Cancel after a failure past the confirmed commit: in the
// held session only, only while the window leaves the cancel margin, and
// only when the history shows this rollout's commit pending at entry 0.
// The state is read afterwards and named.
func (r *run) cancel(why string) {
	if r.done() {
		r.o.Interrupted = r.o.Interrupted || errors.Is(r.ctx.Err(), context.Canceled)
	}
	ctx, cancelCtx := r.grace()
	defer cancelCtx()
	r.step("cancel")
	switch {
	case !r.t.Held():
		why += "; the held session is lost, the confirm is never made from another"
	case r.now().After(r.windowEnd.Add(-r.d.CancelMargin)):
		why += "; too little of the window was left to cancel"
	default:
		h, err := r.t.History(ctx)
		if err != nil {
			h, err = r.history(ctx)
		}
		if err != nil {
			r.end(ExitUnknown, why+"; the state could not be read: "+r.errText(err))
			return
		}
		if p, ok := h.Pending(); !ok || !ours(p, r.id) {
			e, how, entry := settle(h, r.id, r.pre)
			r.named(e, why, how, entry)
			return
		}
		if err := r.t.Cancel(ctx, r.id); err != nil {
			why += "; the cancel: " + r.errText(err)
		}
	}
	h, err := r.history(ctx)
	if err != nil {
		r.end(ExitUnknown, why+"; the state could not be read: "+r.errText(err))
		return
	}
	e, how, entry := settle(h, r.id, r.pre)
	r.named(e, why, how, entry)
}

// record is RECORD: the confirm read back on the fresh login.
func (r *run) record() {
	ctx, cancel := r.grace()
	defer cancel()
	h, err := r.history(ctx)
	if err != nil {
		r.end(ExitUnknown, "confirmed (commit complete) but the history could not be read: "+r.errText(err))
		return
	}
	e, how, entry := settle(h, r.id, r.pre)
	if e == ExitPending {
		// the confirm answered 'commit complete' and the commit is still
		// pending: the answer is not what it said; nothing more is typed
		r.end(ExitPending, "the confirm did not end the window")
		return
	}
	r.named(e, "after the confirm", how, entry)
	if e == ExitApplied {
		// leave configuration mode; the candidate is the committed one
		_ = r.t.Discard(ctx)
	}
}

// fileShape files the shape of an applied rollout in the store.
func (r *run) fileShape() {
	if r.in.StateDir == "" || r.o.Shape == "" {
		return
	}
	r.o.StoreErr = OpenShapes(filepath.Clean(r.in.StateDir)).Confirm(r.o.Shape, r.o.ShapeLines, Confirmation{
		Device: r.in.Device, At: r.now(), By: r.in.User, ID: r.id,
	})
}
