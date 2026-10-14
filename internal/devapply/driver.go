package devapply

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
	// device.apply.confirm_timeout (D140).
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
	// ConfirmMinutes is the window (device.apply.confirm_timeout).
	ConfirmMinutes int
	// Hold is the optional --hold (D134 Q2): after the verification, true
	// keeps the change. Nil: none.
	Hold func(ctx context.Context, until time.Time) (bool, error)
	// Committed is optional: it is called once, on the driver's goroutine,
	// as soon as 'commit confirmed' was typed (answered or not), with the
	// outcome so far (ID, Until, Shape, Sections, Counts), so the caller can
	// write a pending record before anything else is typed (D138: a dead
	// tacctl leaves a record the next run reconciles). It must not block for
	// long and its failure is the caller's to report: the transaction goes on.
	Committed func(o Outcome)
	// Clock and Rand are the time and the random source of the change id.
	Clock func() time.Time
	Rand  io.Reader
	// StateDir, when set, holds the device's lock ('<dir>/locks/<device>.lock')
	// for the transaction and the shape store, which an applied apply
	// files its shape in.
	StateDir string
}

// Driver runs transactions. The zero value has the default margins.
type Driver struct {
	MinWindow    time.Duration
	CancelMargin time.Duration
	Grace        time.Duration
}

// Check is the check phase alone ('device apply check'): the device loads
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
	// committing is set right before the confirmed commit is typed: from
	// then on the device may run the change under its timer.
	committing bool
	// noBanner is set when the verification's fresh login saw no banner
	// over tacctl's commit at entry 0: something confirmed it before
	// tacctl's confirm.
	noBanner bool
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
	r.guarded(reviewed)
	return out
}

// guarded is the transaction with a panic turned into a named exit, while
// the transport is still open: before the confirmed commit was typed the
// candidate is discarded and the exit is ExitFailed; from then on nothing
// more is typed and the exit is ExitUnknown with the window's end (the
// record says unknown until a read settles it).
func (r *run) guarded(reviewed *plan.Delta) {
	defer func() {
		v := recover()
		if v == nil {
			return
		}
		why := "internal error: " + cut(r.m.text(fmt.Sprint(v)))
		if r.committing {
			if r.o.Until.IsZero() {
				r.o.Until = r.now().Add(time.Duration(r.minutes) * time.Minute)
			}
			r.end(ExitUnknown, why+"; the confirmed commit may be pending: nothing more was typed")
			return
		}
		r.o.Discarded = false
		func() {
			defer func() { _ = recover() }()
			if r.t.Held() {
				ctx, cancel := r.grace()
				defer cancel()
				r.o.Discarded = r.t.Discard(ctx) == nil
			}
		}()
		if !r.o.Discarded {
			why += "; the held session is closed with the transport, which drops its candidate"
		}
		r.end(ExitFailed, why)
	}()
	r.transaction(reviewed)
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
	case apply && !plan.IsApplyWord(plan.ApplyCommitConfirmed(in.ConfirmMinutes, "tacctl-x", in.User)):
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
		r.end(ExitFailed, fmt.Sprintf("apply is not available for %s devices in this release", t.Vendor()))
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
	// the pending marker is the banner of the prompt, never the history's
	// label (lab L2)
	st, err := t.State(ctx)
	if err != nil {
		r.end(ExitFailed, "pre-flight: "+r.errText(err))
		return
	}
	if st.Pending {
		r.end(ExitFailed, fmt.Sprintf("a confirmed commit is pending %s; nothing was sent", st.Until()))
		return
	}
	r.pre = st.History[0]
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
	if err := t.Open(ctx, check); err != nil {
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

	// CHECK: the state is read once more first, because a 'commit check'
	// confirms any pending confirmed commit (D132, lab L2): a stranger's
	// 'commit confirmed' typed after the pre-flight and before the open
	// would be confirmed by ours. Under the exclusive lock nothing can be
	// committed between this read and the check, and the transport refuses
	// the check when the held session's own prompt shows the banner.
	r.step("check")
	if st, err := t.State(ctx); err != nil {
		if r.done() {
			r.interruptBeforeCommit()
			return
		}
		r.discard(ExitFailedCheck, "the state before the check: "+r.errText(err))
		return
	} else if st.Pending {
		r.discard(ExitFailedCheck, fmt.Sprintf("a confirmed commit of %s became pending %s before the check; nothing was checked or committed, and it was not confirmed",
			cut(st.History[0].User), st.Until()))
		return
	}
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
	st, err = t.State(ctx)
	if err != nil {
		if r.done() {
			r.interruptBeforeCommit()
			return
		}
		r.discard(ExitFailedCheck, "the state before the commit: "+r.errText(err))
		return
	}
	if st.Pending {
		r.discard(ExitFailedCheck, fmt.Sprintf("a confirmed commit is pending %s", st.Until()))
		return
	}
	r.pre = st.History[0]
	sent := r.now()
	r.committing = true
	err = t.CommitConfirmed(ctx, r.minutes, r.id, in.User)
	answered := r.now()
	window := time.Duration(r.minutes) * time.Minute
	// the device's timer starts after the line was sent and before the
	// answer: the window ends no sooner than sent+N (the margins count from
	// it) and no later than answered+N (what the record says)
	r.windowEnd = sent.Add(window)
	r.o.Until = answered.Add(window)
	if in.Committed != nil {
		in.Committed(r.o.snapshot())
	}
	if err != nil {
		r.readState("the confirmed commit's answer: "+r.errText(err), true)
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
	if r.noBanner {
		r.confirmedByOther()
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
	st, err := vr.State(ctx)
	if err != nil {
		return "show system commit: " + r.errText(err)
	}
	switch {
	case !st.Pending && ours(st.History[0], r.id):
		// something confirmed tacctl's commit before its confirm (a
		// stranger's 'commit check'): the verification runs all the same,
		// and only its proof makes the change applied by someone else
		r.noBanner = true
	case !st.Pending:
		return "the fresh login's prompt shows no pending confirmed commit"
	case !ours(st.History[0], r.id):
		return "entry 0 of the history is not tacctl's pending commit"
	}
	if _, err := vr.Login(ctx); err != nil {
		return "the fresh login's class: " + r.errText(err)
	}
	landed, err := vr.LandedCompare(ctx, r.delta)
	if err != nil {
		return "the landed compare: " + r.errText(err)
	}
	// rollback 1 against the committed configuration holds every
	// difference since the commit before tacctl's; one the delta does not
	// explain is not tacctl's and is never quoted (a superuser's compare
	// prints password hashes, lab 2026-10-13): the count only
	if un := landed.Unexplained(r.delta); len(un) > 0 {
		return fmt.Sprintf("the landed compare holds %d statement(s) outside the plan", len(un))
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
func commitComment(id string) string  { return "tacctl apply " + id + " by " }
func confirmComment(id string) string { return "tacctl apply confirm " + id + " by " }
func cancelComment(id string) string  { return "tacctl apply cancel " + id }

// ours reports whether the entry is the confirmed commit of the apply id.
func ours(e CommitEntry, id string) bool { return strings.HasPrefix(e.Comment, commitComment(id)) }

// settleSlack is how long after the record's end of the window a commit
// of tacctl's still at entry 0 without the banner is taken for confirmed:
// the device's own rollback is a commit that takes a moment to stand in
// the history, and the clocks may differ.
const settleSlack = time.Minute

// factsNeed is whether settle's answer is to be settled from the
// configuration (byFacts).
type factsNeed int

const (
	// factsNo: the history says it.
	factsNo factsNeed = iota
	// factsRequired: the history does not say it; without a planner the
	// state is ExitUnknown.
	factsRequired
	// factsPreferred: the history says it, and the configuration says it
	// better when a planner is at hand.
	factsPreferred
)

// settled is what settle found.
type settled struct {
	e     Exit
	how   string
	entry *CommitEntry
	facts factsNeed
	// over is set when a stranger's confirmed commit is pending over the
	// entry that named tacctl's fate; until is then the end of the
	// stranger's window by this machine's clock (now and the banner's
	// minutes, the latest it can be).
	over  bool
	until time.Time
}

// settle names the state of apply id from the commit state (D132, lab L2).
// pre is entry 0 before the commit (zero: unknown); now is this machine's
// time and until the record's end of tacctl's window (zero: unknown). The
// pending marker is the banner, never the history's 'rollback in' label (a
// 'commit check' confirms without an entry, and the label stays):
//
//   - the banner and tacctl's commit at entry 0: pending;
//   - the banner over another entry 0: unknown (someone's later confirmed
//     commit is pending; settle again after its window), unless an entry
//     between the two already named tacctl's fate, which is reported with
//     the stranger's pending commit;
//   - no banner, tacctl's commit at entry 0, before the window's end (and
//     settleSlack): pending. A 'commit check' may have confirmed it, but a
//     release or a session that prints no banner rolls it back at the end
//     all the same, and only a read after the end tells;
//   - no banner, tacctl's commit at entry 0, after the window's end:
//     applied by someone else (a 'commit check' confirmed it), settled
//     from the configuration when a planner is at hand (factsPreferred);
//   - the entry directly above tacctl's: its confirm is applied, its cancel
//     rolled back; one 'by root via other' with no comment is the device's
//     own rollback or a commit of the system that confirmed it, settled
//     from the configuration (factsRequired).
//
// An entry after tacctl's commit that is neither tacctl's confirm nor its
// cancel is never taken for a confirm or a rollback from the history
// alone (a release whose expiry entry reads otherwise would be recorded
// applied): settle returns ExitUnknown with factsRequired, and the caller
// settles it from the configuration (byFacts) when it can read one.
func settle(st CommitState, id string, pre CommitEntry, now, until time.Time) settled {
	h := st.History
	k := slices.IndexFunc(h, func(e CommitEntry) bool { return ours(e, id) })
	if st.Pending {
		switch {
		case k == 0:
			return settled{e: ExitPending, how: "the confirmed commit is pending"}
		case k < 0:
			return settled{e: ExitUnknown, how: "a confirmed commit is pending and the history does not show tacctl's commit " + id}
		}
		stranger := fmt.Sprintf("a later confirmed commit (by %s via %s at %s) is pending %s over tacctl's", cut(h[0].User), cut(h[0].Via), h[0].TimeText, st.Until())
		if k == 1 {
			// the pending commit is itself the one after tacctl's
			return settled{e: ExitUnknown, how: stranger}
		}
		s := fate(h, k, id)
		if s.e == ExitUnknown && !expiry(h[k-1]) {
			return settled{e: ExitUnknown, how: stranger}
		}
		// the entry above tacctl's named its fate: it is reported, and so
		// is the stranger's pending commit, whose window the record keeps
		s.how += "; " + stranger
		s.over = true
		s.until = now.Add(time.Duration(st.Minutes+1) * time.Minute)
		return s
	}
	switch {
	case k < 0 && pre.TimeText != "" && len(h) > 0 && h[0].Same(pre):
		return settled{e: ExitNothingCommitted, how: "nothing was committed"}
	case k < 0:
		return settled{e: ExitUnknown, how: "the history does not show tacctl's commit " + id}
	case k == 0 && until.IsZero():
		return settled{e: ExitUnknown, how: "no confirmed commit's banner stands and tacctl's commit is still entry 0, and the window's end is not known"}
	case k == 0 && now.Before(until.Add(settleSlack)):
		return settled{e: ExitPending, how: "no confirmed commit's banner stands but tacctl's commit is still entry 0: a 'commit check' may have confirmed it, or the device printed no banner; it is settled after the window's end"}
	case k == 0:
		return settled{e: ExitAppliedByOther, how: "no confirmed commit is pending after the window's end and tacctl's commit is still entry 0: a 'commit check' confirmed it", facts: factsPreferred}
	}
	return fate(h, k, id)
}

// expiry reports whether the entry reads as the device's own rollback ('by
// root via other', no comment), which a commit of the system shares.
func expiry(e CommitEntry) bool {
	return e.User == textExpiryUser && e.Via == textExpiryVia && e.Comment == ""
}

// fate is what the entry directly above tacctl's commit (k > 0) says of it.
func fate(h History, k int, id string) settled {
	next := h[k-1]
	switch {
	case strings.HasPrefix(next.Comment, confirmComment(id)) && next.RollbackIn == 0:
		return settled{e: ExitApplied, entry: &next}
	case strings.HasPrefix(next.Comment, cancelComment(id)):
		return settled{e: ExitRolledBack, how: "cancelled at " + next.TimeText}
	case expiry(next):
		return settled{e: ExitUnknown, how: fmt.Sprintf("the commit after tacctl's is by %s via %s at %s (the device's own rollback, or a commit of the system that confirmed it)", textExpiryUser, textExpiryVia, next.TimeText), facts: factsRequired}
	}
	return settled{e: ExitUnknown, how: fmt.Sprintf("the commit after tacctl's (by %s via %s at %s) is not one tacctl recognises", cut(next.User), cut(next.Via), next.TimeText), facts: factsRequired}
}

// byFacts settles an entry after tacctl's commit from the configuration:
// d is the planner's delta of a read made after it. No delta is the change
// in place (someone's commit confirmed it); a delta is the change not in
// place (rolled back).
func byFacts(how string, d plan.Delta, err error) (Exit, string) {
	switch {
	case err != nil:
		return ExitUnknown, how + "; the configuration could not be read: " + err.Error()
	case d.Empty():
		return ExitAppliedByOther, how + "; the configuration has the change"
	}
	return ExitRolledBack, how + "; the configuration lacks the change"
}

// settle is settle with the state settled from the configuration where it
// asks for that, read on the fresh login if one is open, else on the held
// login's connection.
func (r *run) settle(ctx context.Context, st CommitState) settled {
	s := settle(st, r.id, r.pre, r.now(), r.o.Until)
	if s.facts == factsNo {
		return s
	}
	s.entry = nil
	var rd Reader = r.t
	if r.vr != nil {
		rd = r.vr
	}
	raw, err := rd.Read(ctx)
	if err != nil {
		s.e, s.how = byFacts(s.how, plan.Delta{}, errors.New(r.errText(err)))
		return s
	}
	d, err := r.in.Plan(ctx, raw, r.t.LocalAddr())
	for _, l := range d.Lines {
		r.m.add(l)
	}
	if err != nil {
		err = errors.New(r.errText(err))
	}
	s.e, s.how = byFacts(s.how, d, err)
	return s
}

// state reads the commit state after a failure: on the fresh login if one
// is open, on the held login's connection, and on a new fresh login.
func (r *run) state(ctx context.Context) (CommitState, error) {
	if r.vr != nil {
		if st, err := r.vr.State(ctx); err == nil {
			return st, nil
		}
	}
	st, last := r.t.State(ctx)
	if last == nil {
		return st, nil
	}
	if r.in.Verify != nil {
		vr, err := r.in.Verify(ctx)
		if err != nil {
			return CommitState{}, err
		}
		if r.vr != nil {
			_ = r.vr.Close()
		}
		r.vr = vr
		return vr.State(ctx)
	}
	return CommitState{}, last
}

// readState is READ-STATE (D132): after a failure past the confirmed commit
// the state is read before it is named. With cancelPending a pending
// commit of this apply is cancelled first (an answer the transport did not
// know is never taken for a commit to keep): also one whose banner is gone
// while tacctl's commit is still entry 0, which nothing proved.
func (r *run) readState(why string, cancelPending bool) {
	ctx, cancelCtx := r.grace()
	defer cancelCtx()
	st, err := r.state(ctx)
	if err != nil {
		r.end(ExitUnknown, why+"; the state could not be read: "+r.errText(err))
		return
	}
	s := r.settle(ctx, st)
	if s.e == ExitPending && cancelPending {
		r.cancel(why)
		return
	}
	r.named(s, why)
}

// named sets the exit settle found.
func (r *run) named(s settled, why string) {
	e, how := s.e, s.how
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
		r.o.Commit = s.entry
		r.end(e, "")
		if s.over {
			r.o.Reason = how
		}
		r.o.Until = time.Time{}
		r.fileShape()
	case ExitAppliedByOther:
		r.o.Until = time.Time{}
		r.end(e, how)
	case ExitRolledBack:
		r.o.Until = time.Time{}
		r.end(e, why+"; "+how)
	default:
		r.end(e, why+"; "+how)
	}
	if s.over {
		// a stranger's confirmed commit is pending: the record keeps its
		// window
		r.o.Until = s.until
	}
}

// cancel is D131's Cancel after a failure past the confirmed commit: in the
// held session only, only while the window leaves the cancel margin, and
// only when the state read after the failure shows this apply's commit at
// entry 0: under the banner (pending) the cancel, without it (something
// confirmed the commit before tacctl's confirm, and nothing proved the
// change) the revert, each committing only the exact inverse of the
// change. The state is read afterwards and named.
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
		st, err := r.t.State(ctx)
		if err != nil {
			st, err = r.state(ctx)
		}
		if err != nil {
			r.end(ExitUnknown, why+"; the state could not be read: "+r.errText(err))
			return
		}
		switch {
		case !ours(st.History[0], r.id):
			r.named(r.settle(ctx, st), why)
			return
		case st.Pending:
			if err := r.t.Cancel(ctx, r.id); err != nil {
				why += "; the cancel: " + r.errText(err)
			}
		default:
			why += "; no confirmed commit was pending (something confirmed tacctl's before its confirm)"
			if err := r.t.Revert(ctx, r.id); err != nil {
				why += "; the revert: " + r.errText(err)
			}
		}
	}
	st, err := r.state(ctx)
	if err != nil {
		r.end(ExitUnknown, why+"; the state could not be read: "+r.errText(err))
		return
	}
	r.named(r.settle(ctx, st), why)
}

// confirmedByOther ends a transaction whose verification passed while no
// banner stood and tacctl's commit was still entry 0 (a stranger's 'commit
// check' confirmed it before tacctl's confirm): the held login's state is
// read again, and only when it agrees is the change applied by someone
// else, with the verification as its proof; any other state is named from
// the history, a pending commit of tacctl's cancelled.
func (r *run) confirmedByOther() {
	ctx, cancelCtx := r.grace()
	defer cancelCtx()
	st, err := r.t.State(ctx)
	if err != nil {
		r.cancel("the state after the verification: " + r.errText(err))
		return
	}
	switch {
	case st.Pending && ours(st.History[0], r.id):
		// the fresh login's prompt showed no banner and the held login's
		// does: the fresh login's state is not to be trusted
		r.cancel("verification failed (the fresh login's prompt shows no pending confirmed commit)")
		return
	case st.Pending || !ours(st.History[0], r.id):
		r.named(r.settle(ctx, st), "after the verification")
		return
	}
	r.o.Until = time.Time{}
	r.end(ExitAppliedByOther, "no confirmed commit was pending before tacctl's confirm and its commit is still entry 0 (a 'commit check' confirmed it); "+
		"the fresh login's landed compare is the change the check showed and its read has the change")
	// leave configuration mode; the candidate is the committed one
	_ = r.t.Discard(ctx)
}

// record is RECORD: the confirm read back on the fresh login.
func (r *run) record() {
	ctx, cancel := r.grace()
	defer cancel()
	st, err := r.state(ctx)
	if err != nil {
		r.end(ExitUnknown, "confirmed (commit complete) but the state could not be read: "+r.errText(err))
		return
	}
	s := r.settle(ctx, st)
	if s.e == ExitPending {
		// the confirm answered 'commit complete' and the commit is still
		// pending: the answer is not what it said; nothing more is typed
		r.end(ExitPending, "the confirm did not end the window")
		return
	}
	r.named(s, "after the confirm")
	if s.e == ExitApplied {
		// leave configuration mode; the candidate is the committed one
		_ = r.t.Discard(ctx)
	}
}

// fileShape files the shape of an applied apply in the store.
func (r *run) fileShape() {
	if r.in.StateDir == "" || r.o.Shape == "" {
		return
	}
	r.o.StoreErr = OpenShapes(filepath.Clean(r.in.StateDir)).Confirm(r.o.Shape, r.o.ShapeLines, Confirmation{
		Device: r.in.Device, At: r.now(), By: r.in.User, ID: r.id,
	})
}
