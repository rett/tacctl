package cli

// 'device config apply' (docs/plans/0.2.9-rollout-plan.md D129-D135,
// D138-D141): the plan of 0.2.5 typed into Junos devices by tacctl instead of
// pasted by a person. One run is two phases over the same transaction
// driver (internal/devapply), after an optional pull (--pull, 0.2.17 D268):
//
//   - Phase A checks every selected device in the 0.2.4 pool: the device
//     loads the plan in an exclusive session, 'commit check' runs and the
//     candidate is discarded. What it saw is the shape of each device's change.
//   - The review groups the devices by shape, prints each group's statements
//     with every secret elided and asks one question per device, answered by
//     typing that device's name back (D134, 0.2.17 D265); --confirmed --yes
//     answers them in the scripted form (D266); --check stops before it.
//   - Phase B applies the reviewed devices: serial by default, the first
//     device of every shape alone (the canary), each under a confirmed commit,
//     proven by a fresh login and by what landed, then confirmed.
//
// This file is the verb: arguments, the selection, the jobs and the records.
// The progress and the review are device_apply_view.go, 'shapes' is
// device_apply_shapes.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/ui"
)

// applyMaxDefault is the most devices one run applies (D139: a batch is
// watched); --max raises or lowers it.
const (
	applyMaxDefault = 5
	applyMaxLimit   = 1000
)

// applyArgs are the options of an apply, beside the pull's.
type applyArgs struct {
	pull pullArgs
	// check stops after the device's own commit check; confirmed gates the
	// run on shapes another run confirmed (D135); hold is the opt-in human
	// proof of every login class (D134); noCanary starts every device of a
	// shape at once; yes answers the review (only with confirmed);
	// pullFirst is --pull (0.2.17 D268): the devices are pulled before the
	// check and --stale and --differs select from the fresh records.
	check, confirmed, hold, noCanary, yes, exitCode, pullFirst bool
	max                                                        int
	// mode is how the review is answered, for the audit lines (0.2.17
	// D266): "attended" (each device's name typed back) or "scripted"
	// (--confirmed --yes).
	mode string
	// pause is the wait between devices (device.apply.pause, or --pause).
	pause    time.Duration
	pauseSet bool
	sections []string
	// transport is how the run writes: --transport over
	// device.apply.transport (auto, cli or netconf, D150).
	transport devapply.Setting
}

// reviewMode is how the review is answered (mode, or for arguments made
// without applyArgsOf the form --yes gives).
func (a applyArgs) reviewMode() string {
	switch {
	case a.mode != "":
		return a.mode
	case a.yes:
		return "scripted"
	}
	return "attended"
}

// applyArgsOf reads and checks the options that need no device (exit 2).
func (inv *invocation) applyArgsOf(p Parsed) (applyArgs, error) {
	usage := "Usage: tacctl device config " + deviceConfigUse("apply")
	var a applyArgs
	pa, err := inv.pullArgsOf(p, "apply")
	if err != nil {
		return a, err
	}
	a.pull = pa
	a.check, a.confirmed, a.hold = p.Has("--check"), p.Has("--confirmed"), p.Has("--hold")
	a.noCanary, a.yes, a.exitCode = p.Has("--no-canary"), p.Has("-y"), p.Has("--exit-code")
	a.pullFirst = p.Has("--pull")
	a.mode = "attended"
	if a.yes {
		a.mode = "scripted"
	}
	a.max = applyMaxDefault
	_, a.pause = inv.applySettings()
	a.transport = devapply.Setting(inv.applyTransport())
	if p.Has("--transport") {
		t := devapply.Setting(p.Value("--transport"))
		if !t.Valid() {
			return a, inv.argErr("--transport takes auto, cli or netconf: '"+p.Value("--transport")+"'", usage)
		}
		a.transport = t
	}
	if p.Has("--max") {
		n, err := atoiIn(p.Value("--max"), 1, applyMaxLimit)
		if err != nil {
			return a, inv.argErr("--max takes a number of devices, 1 to "+strconv.Itoa(applyMaxLimit)+": '"+p.Value("--max")+"'", usage)
		}
		a.max = n
	}
	if p.Has("--pause") {
		n, err := atoiIn(p.Value("--pause"), 0, applyPauseMax)
		if err != nil {
			return a, inv.argErr("--pause takes seconds, 0 to "+strconv.Itoa(applyPauseMax)+": '"+p.Value("--pause")+"'", usage)
		}
		a.pause, a.pauseSet = time.Duration(n)*time.Second, true
	}
	if p.Has("--section") {
		for _, s := range strings.Split(p.Value("--section"), ",") {
			s = strings.TrimSpace(s)
			switch {
			case s == "breakglass":
				return a, inv.argErr("--section: '"+s+"' is never written (it is a step of the walkthrough); the sections are "+
					strings.Join(planSections, ", ")+".", usage)
			case !slices.Contains(planSections, s):
				return a, inv.argErr("--section takes sections of "+strings.Join(planSections, ", ")+": '"+s+"'", usage)
			case !slices.Contains(a.sections, s):
				a.sections = append(a.sections, s)
			}
		}
	}
	switch {
	case a.check && (a.hold || a.pauseSet || a.noCanary):
		return a, inv.argErr("--hold, --pause and --no-canary are for an apply: --check stops before the commit.", usage)
	case a.exitCode && !a.check:
		return a, inv.argErr("--exit-code is for --check: it makes a check that found a change exit 2.", usage)
	case a.yes && !a.confirmed && !a.check:
		return a, inv.argErr("--yes answers the review only with --confirmed (the shapes another device confirmed): a batch of unreviewed shapes is not run blind.", usage)
	case a.hold && a.pull.concurrency > 1:
		return a, inv.argErr("--hold asks about one device at a time: it takes no --concurrency above 1.", usage)
	case a.hold && a.pull.json:
		return a, inv.argErr("--hold asks on the terminal and --json keeps standard output to the objects: they do not go together.", usage)
	}
	return a, nil
}

// applyOutcome is what one device's phase found, handed from the job to the
// view through batch.Result.Value.
type applyOutcome struct {
	Name, Scope, Vendor string
	// Phase is "check" or "apply".
	Phase string
	// Out is the driver's outcome; nil when no transaction ran.
	Out *devapply.Outcome
	// Delta is the delta of the device's first read of the phase, the one
	// the review shows and Phase B must recompute.
	Delta    plan.Delta
	HasDelta bool
	// Reason is why a device failed before the driver ran.
	Reason string
	// Hint is what to do about it.
	Hint string
	// Status overrides the word of a device refused before any login
	// ("unsupported" for a WTI unit).
	Status string
	// Skipped is why the device was left out of the apply (set by the verb).
	Skipped string
	// Refused is why the plan of the device refuses it (a section the plan
	// refuses, as 'device config plan' exits 1): it is not applied and is a
	// failure.
	Refused string
	// ConfirmedOn is the device that confirmed the shape ("" a new one).
	ConfirmedOn string
	// RecordErr is a record that could not be written; PendingErr the
	// pending record of the moment of the confirmed commit (D138).
	RecordErr, PendingErr string
	Duration              time.Duration
	// Settled is the settle of an earlier apply's pending record, nil when
	// the record was not pending.
	Settled *applySettled
	// Via is the transport the transaction ran through ("" when none ran)
	// and ViaReason why it was not the first choice (the setting's), D150.
	Via       devapply.Via
	ViaReason string
}

// word is the device's state as the summary and the JSON name it.
func (o *applyOutcome) word() string {
	switch {
	case o == nil:
		return "not-started"
	case o.Status != "":
		return o.Status
	case o.Refused != "":
		return "failed"
	case o.Skipped != "":
		return "skipped"
	case o.Out == nil:
		return "failed"
	}
	switch o.Out.Exit {
	case devapply.ExitChecked:
		return "checked"
	case devapply.ExitNoChange:
		return "no-change"
	case devapply.ExitApplied:
		return "applied"
	case devapply.ExitAppliedByOther:
		return "applied-by-other"
	case devapply.ExitRolledBack:
		return "rolled-back"
	case devapply.ExitPending, devapply.ExitWindowShort:
		return "pending"
	case devapply.ExitUnknown:
		return "unknown"
	case devapply.ExitInterrupted:
		return "interrupted"
	}
	return "failed"
}

// batchResult is the outcome as the runner's result: a device that did what
// was asked is OK; a rolled-back, pending or failed one is a failure that the
// summary counts as it is (D130: exit status 1).
func (o *applyOutcome) batchResult() batch.Result {
	r := batch.Result{Value: o}
	switch o.word() {
	case "checked", "no-change", "applied":
		return r
	}
	r.Status = batch.StatusFailed
	r.Reason = o.reason()
	switch o.word() {
	case "rolled-back":
		r.RolledBack = true
	case "pending", "unknown":
		r.Pending = true
	}
	return r
}

// reason is the words after "failed: " in the line.
func (o *applyOutcome) reason() string {
	switch {
	case o.Refused != "":
		return o.Refused
	case o.Reason != "":
		return o.Reason
	case o.Out != nil && o.Out.Reason != "":
		return o.Out.Reason
	case o.Out != nil:
		return string(o.Out.Exit)
	}
	return "failed"
}

// applyRun is what the jobs of one run share. The password, the stores and
// the render are the only shared things, and all are safe for the workers.
type applyRun struct {
	inv      *invocation
	user     string
	render   *managedRender
	store    devconf.Store
	shapes   *devapply.Shapes
	stateDir string
	passwd   devicePasswords
	password string
	sections []string
	minutes  int
	// transport is the run's setting (--transport over
	// device.apply.transport, D150); the zero value is not used by onboard,
	// which writes over the command line only.
	transport devapply.Setting
	driver    devapply.Driver
	// holdOn asks the person for the proof of every login class.
	holdOn bool
	// holdLines are the lines the person types while --hold waits, read by
	// one goroutine the run owns (holdLine) and stopped by holdDone, so no
	// second reader of standard input outlives one device's question.
	// holdAsked counts the questions opened; a line is stamped with it.
	holdOnce  sync.Once
	holdLines chan holdAnswer
	holdDone  chan struct{}
	holdAsked atomic.Int32

	acceptOnce, rejectOnce sync.Once
}

// names are the names a device may report (D131 step 1).
func applyNames(e devreg.Entry) []string {
	out := []string{e.Name}
	if e.Hostname != "" {
		out = append(out, e.Hostname)
	}
	return out
}

// jobOf is the batch job of one device in a phase; reviewed is nil for the
// check and the reviewed delta for the apply.
func (r *applyRun) jobOf(e devreg.Entry, reviewed *plan.Delta, shape string) batch.Job {
	return batch.Job{Name: e.Name, Shape: shape, Do: func(ctx context.Context) batch.Result {
		start := r.inv.app.Knobs.Now()
		o := &applyOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Phase: "check"}
		var res batch.Result
		if reviewed != nil {
			o.Phase = "apply"
			// what the review was given may have changed while it was read
			if why := r.recheck(e); why != "" {
				o.Reason = why
				res = o.batchResult()
			}
		}
		if o.Reason == "" {
			res = r.transact(ctx, e, o, reviewed)
		}
		o.Duration = r.inv.app.Knobs.Now().Sub(start)
		res.Value = o
		return res
	}}
}

// applyState is what one device's planner closure keeps across the reads of
// a transaction: the first (the device as the review saw it), the
// convergence read after the commit.
type applyState struct {
	calls int
	first *readPlan
	after *readPlan
	pre   map[string]string
	// via is the transport of this attempt; serviceChange is set by the
	// planner when a NETCONF attempt's first read plans a statement of the
	// NETCONF service (D148): the attempt ends before anything is opened
	// and the transaction runs again over the command line.
	via           devapply.Via
	serviceChange bool
	// probe is the NETCONF probe the verification of a service change made
	// (D148): what the record's probe becomes once the change is applied.
	probe string
}

// errServiceChange is the planner's answer to a NETCONF attempt whose delta
// changes the NETCONF service: nothing was opened, the caller runs the
// transaction again over the command line.
var errServiceChange = errors.New("the change is to the NETCONF service: it is made over the command line")

// readPlan is one read of a device, extracted, compared and planned.
type readPlan struct {
	ext     devconf.Extracted
	results []devconf.SectionResult
	plain   map[string]devices.Section
	delta   plan.Delta
	raw     string
	// via is the transport the read came through ("" is the command line,
	// as 0.2.9 read); the record's Transport and probe follow it.
	via devapply.Via
	// probe is a NETCONF probe made after the commit (D148); it replaces
	// what the transport of the read implies.
	probe string
}

// planRead makes the delta of a read the way 'device config plan' does from
// a record: the sections in the form the store gives them back, the plain
// view for the groups, from = the address tacctl connects from (D133).
func (r *applyRun) planRead(e devreg.Entry, expected []devices.Section, raw, plainRaw string, from net.IP) (*readPlan, error) {
	ext, err := devconf.ExtractWith(e.Vendor, raw, devconf.Options{Expected: expected})
	if err != nil {
		return nil, err
	}
	results, err := devconf.CompareAll(expected, ext)
	if err != nil {
		return nil, err
	}
	fam, err := devconf.Family(e.Vendor)
	if err != nil {
		return nil, err
	}
	rp := &readPlan{ext: ext, results: results, raw: raw}
	stored, err := devconf.StoredForm(e.Vendor, ext.Sections)
	if err != nil {
		return nil, err
	}
	cur := devconf.Extracted{Vendor: fam, Sections: stored, SecretsVisible: ext.SecretsVisible}
	var plainView devconf.Extracted
	if plainRaw != "" {
		// A view that does not extract is no view (as the pull's): the plan
		// says the inheritance was not checked.
		if pe, perr := devconf.ExtractWith(e.Vendor, plainRaw, devconf.Options{Expected: expected}); perr == nil {
			rp.plain = pe.Sections
			if ps, serr := devconf.StoredForm(e.Vendor, pe.Sections); serr == nil {
				plainView = devconf.Extracted{Vendor: fam, Sections: ps, SecretsVisible: ext.SecretsVisible}
			}
		}
	}
	opt := plan.Options{Sections: r.sections, Scope: e.Scope, Device: e.Name}
	if from != nil {
		opt.From = from.String()
	}
	d, err := plan.Plan(e.Vendor, expected, cur, plainView, opt)
	if err != nil {
		return nil, err
	}
	rp.delta = d
	return rp, nil
}

// fingerprints are the sections the delta plans, as the device had them.
func (rp *readPlan) fingerprints(vendor string) map[string]string {
	out := map[string]string{}
	for _, s := range rp.delta.Planned() {
		if sec, ok := rp.ext.Sections[s]; ok {
			if fp, err := devconf.Fingerprint(vendor, sec); err == nil {
				out[s] = fp
			}
		}
	}
	return out
}

// refresh keeps what a read saw as the pull record of the device (D131 step
// 2, D138): the sections, their comparison and the facts it carried. The
// device's model and serial number are the last pull's own; this read only
// has the release.
func (r *applyRun) refresh(e devreg.Entry, rp *readPlan, dur time.Duration) error {
	facts := devconf.Facts{Release: devconf.JunosRelease(rp.raw)}
	if recs, err := r.store.Load(); err == nil {
		if old, ok := recs.Of(e.Name); ok {
			if facts.Release == "" {
				facts.Release = old.Release
			}
			facts.Model, facts.Serial = old.Model, old.Serial
		}
	}
	pr := &pullRun{inv: r.inv, user: r.user, store: r.store}
	o := &pullOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Transport: transportSSH, Netconf: netconfNotProbed,
		Facts: devconf.CleanFacts(facts), Duration: dur}
	if rp.via == devapply.ViaNetconf {
		// a read that came through the subsystem is a hello
		o.Transport, o.Netconf = transportNetconf, netconfHelloOK
	}
	if rp.probe != "" {
		o.Netconf = rp.probe
	}
	return pr.recordSuccess(o, e, rp.ext, rp.results, rp.plain)
}

// planner is the driver's Plan for one device's transaction. t is the held
// login (its connection reads the plain view). The first read refreshes the
// pull record; the second is the convergence read after the commit, kept only
// in memory until the apply is known to have stuck.
func (r *applyRun) planner(e devreg.Entry, expected []devices.Section, t plainReader, st *applyState) func(context.Context, string, net.IP) (plan.Delta, error) {
	return func(ctx context.Context, raw string, from net.IP) (plan.Delta, error) {
		st.calls++
		n := st.calls
		rp, err := r.planRead(e, expected, raw, t.ReadPlain(ctx), from)
		if err != nil {
			return plan.Delta{}, err
		}
		rp.via = st.via
		if n == 1 && st.via == devapply.ViaNetconf && plan.TouchesNetconf(rp.delta) {
			// nothing has been opened: the command line makes this change
			st.serviceChange = true
			return plan.Delta{}, errServiceChange
		}
		switch n {
		case 1:
			st.first = rp
			st.pre = rp.fingerprints(e.Vendor)
			// best effort: a record that cannot be written is said at the end
			_ = r.refresh(e, rp, 0)
		case 2:
			st.after = rp
		}
		return rp.delta, nil
	}
}

// writeApplied keeps the record of what this run did to the device. The pull
// part of the record is left as the last read made it.
func (r *applyRun) writeApplied(e devreg.Entry, a devconf.Applied) error {
	if err := r.inv.hooks.recordFault(e.Name, a); err != nil {
		return err
	}
	unlock, err := r.store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	recs, _ := r.store.Load()
	var rec devconf.Record
	if old, ok := recs.Of(e.Name); ok {
		rec = *old
	}
	rec.Address = e.Address
	// The stored sections keep the vendor of their pull (D260).
	rec.SetVendorUnlessPulled(e.Vendor)
	rec.Applied = &a
	recs.Put(e.Name, rec)
	recs.Updated = r.inv.app.Knobs.Now()
	return r.store.Save(recs)
}

// appliedOf is the record of a driver outcome (D138).
func (r *applyRun) appliedOf(o devapply.Outcome, kind string, pre map[string]string) devconf.Applied {
	a := devconf.Applied{At: r.inv.app.Knobs.Now(), By: r.user, ID: o.ID, Kind: kind, Result: string(o.Result),
		Reason: cutReason(o.Reason), Until: o.Until, Shape: o.Shape, Sections: o.Sections,
		Set: o.Counts.Set, Delete: o.Counts.Delete, Insert: o.Counts.Insert}
	if o.Exit == devapply.ExitApplied || o.Exit == devapply.ExitAppliedByOther {
		a.Until = time.Time{}
	}
	if o.Commit != nil {
		a.Commit = &devconf.AppliedCommit{Seq: o.Commit.Seq, Time: o.Commit.TimeText}
	}
	if len(pre) > 0 {
		a.Pre = pre
	}
	return a
}

// cutReason keeps a reason to a line the record can hold.
func cutReason(s string) string {
	s = cleanLine(strings.Join(strings.Fields(s), " "))
	if len(s) > 400 {
		s = s[:397] + "..."
	}
	return s
}

// target is the login of the device: the invoking user and the run's
// password, in memory.
func (r *applyRun) target(e devreg.Entry) devssh.Target {
	return r.inv.deviceTarget(e, r.user, func() (string, error) { return r.password, nil })
}

// plainReader is the transport's read of the plain view (the groups).
type plainReader interface {
	ReadPlain(ctx context.Context) string
}

// applyConn is the dialled transport of one attempt.
type applyConn struct {
	t     devapply.Transport
	plain plainReader
	// nc is the NETCONF transport, nil over the command line.
	nc *devapply.JunosNetconf
	// verify dials the fresh login of the verification on the same path
	// the transaction wrote through.
	verify func(ctx context.Context) (devapply.Reader, error)
}

// netconfUnavailable is --transport netconf for a device that does not
// answer or cannot confirm: failed, never written over the command line.
type netconfUnavailable struct{ why string }

func (e *netconfUnavailable) Error() string { return "NETCONF: " + e.why }

// probeOf is the device's last NETCONF probe from its record ("" when it
// has none): what 'auto' chooses from, D150.
func (r *applyRun) probeOf(name string) string {
	recs, err := r.store.Load()
	if err != nil {
		return ""
	}
	if rec, ok := recs.Of(name); ok {
		return rec.Netconf
	}
	return ""
}

// openVia dials the transport of one attempt. It returns the transport
// that was dialled and why it is not the one asked for ("" when it is): under
// auto a NETCONF login that cannot be had, or cannot confirm, is the command
// line with the reason; under netconf it is a *netconfUnavailable. A dial
// that fails is the error as the command line's would be (an authentication
// failure is the run's).
func (r *applyRun) openVia(ctx context.Context, target devssh.Target, via devapply.Via, reason string) (*applyConn, devapply.Via, string, error) {
	if via == devapply.ViaNetconf {
		n, err := devapply.DialJunosNetconf(ctx, target, devapply.ModeAuto)
		if err != nil {
			return nil, via, reason, err
		}
		detail, err := n.Capable(ctx)
		var fallback string
		switch {
		case err != nil && ctx.Err() != nil:
			_ = n.Close()
			return nil, via, reason, err
		case err != nil:
			detail = "login failed: " + shortReason(err)
			fallback = "NETCONF " + detail
		case detail != "":
			fallback = devapply.ReasonCannotConfirm + ": " + detail
		default:
			return &applyConn{t: n, plain: n, nc: n, verify: func(ctx context.Context) (devapply.Reader, error) {
				v, err := devapply.DialJunosNetconf(ctx, target, devapply.ModeAuto)
				if err != nil {
					return nil, err
				}
				return v, nil
			}}, devapply.ViaNetconf, reason, nil
		}
		_ = n.Close()
		if r.transport == devapply.SettingNetconf {
			return nil, via, reason, &netconfUnavailable{why: detail}
		}
		reason = fallback
	}
	j, err := devapply.DialJunos(ctx, target)
	if err != nil {
		return nil, devapply.ViaCLI, reason, err
	}
	return &applyConn{t: j, plain: j, verify: func(ctx context.Context) (devapply.Reader, error) {
		v, err := devapply.DialJunos(ctx, target)
		if err != nil {
			return nil, err
		}
		return v, nil
	}}, devapply.ViaCLI, reason, nil
}

// transact is one device's phase.
func (r *applyRun) transact(ctx context.Context, e devreg.Entry, o *applyOutcome, reviewed *plan.Delta) batch.Result {
	fail := func(reason, hint string) batch.Result {
		o.Reason, o.Hint = reason, hint
		return o.batchResult()
	}
	expected, err := r.render.Expected(e)
	if err != nil {
		return fail("cannot build the expected configuration: "+strings.Join(msgs(err), " "), "")
	}
	target := r.target(e)
	if why := r.settle(ctx, e, expected, target, o); why != "" {
		return fail(why, "")
	}
	// The transport (D150): the setting and the record's last probe choose;
	// what a dialled login or a planned delta shows can change the choice,
	// and then the whole transaction runs again, never the middle of one.
	choice := devapply.Choose(devapply.ChooseInput{Setting: r.transport, Probe: r.probeOf(e.Name)})
	via, viaReason := choice.Via, choice.Reason
	var (
		st  *applyState
		out devapply.Outcome
	)
	for attempt := 0; ; attempt++ {
		c, v, why, err := r.openVia(ctx, target, via, viaReason)
		if err != nil {
			var nu *netconfUnavailable
			if errors.As(err, &nu) {
				return fail(nu.Error(), "use --transport auto or cli, or 'tacctl device config pull "+e.Name+"' to refresh what the device answers")
			}
			_, reason, hint := resultOf(ctx, e.Name, err)
			o.Reason, o.Hint = reason, hint
			if errors.Is(err, devssh.ErrAuth) {
				r.rejectOnce.Do(r.passwd.Rejected)
				res := o.batchResult()
				res.Status = batch.StatusAuthFailed
				return res
			}
			return o.batchResult()
		}
		via, viaReason = v, why
		r.acceptOnce.Do(r.passwd.Accepted)

		st = &applyState{via: via}
		in := devapply.Input{
			Device: e.Name, Names: applyNames(e), User: r.user, Transport: c.t,
			Plan:           r.planner(e, expected, c.plain, st),
			Allow:          plan.Allow{Login: r.user, Expected: expected},
			ConfirmMinutes: r.minutes,
			Clock:          r.inv.app.Knobs.Now, Rand: r.inv.app.Knobs.Rand(), Pause: r.inv.app.Knobs.ApplyPause(),
			StateDir: r.stateDir,
		}
		if reviewed == nil {
			out = r.driver.Check(ctx, in)
		} else {
			in.Verify = c.verify
			in.VerifyService = r.serviceVerifier(e, target, st)
			in.Committed = func(c devapply.Outcome) { r.pending(e, o, c, st) }
			if r.holdOn {
				in.Hold = r.holdFunc(e.Name)
			}
			out = r.driver.Apply(ctx, in, *reviewed)
		}
		switch {
		case st.serviceChange && attempt < 3:
			// a change to the NETCONF service: nothing was opened, and
			// the command line makes it (D148)
			ch := devapply.Choose(devapply.ChooseInput{Setting: r.transport, Probe: r.probeOf(e.Name), ServiceChange: true})
			if ch.Fail != "" {
				return fail(ch.Fail, "")
			}
			via, viaReason = ch.Via, ch.Reason
			continue
		}
		break
	}
	o.Via, o.ViaReason = via, viaReason
	o.Out = &out
	if st.first != nil {
		o.Delta, o.HasDelta = st.first.delta, true
	}
	r.keep(e, o, st, reviewed != nil)
	return o.batchResult()
}

// keep files what the transaction left: the observed shape, the record and,
// after an apply that stuck, the picture the convergence read gave.
func (r *applyRun) keep(e devreg.Entry, o *applyOutcome, st *applyState, apply bool) {
	out := *o.Out
	if out.Shape != "" && out.Exit == devapply.ExitChecked {
		// the lines of a shape nobody has confirmed, for 'shapes' and 'seed'
		if err := r.shapes.Observe(out.Shape, out.ShapeLines); err != nil {
			o.RecordErr = "the shape could not be filed: " + err.Error()
		}
		if m, err := r.shapes.Load(); err == nil {
			if ent, ok := m[out.Shape]; ok && len(ent.Confirmed) > 0 {
				o.ConfirmedOn = ent.Confirmed[0].Device
			}
		}
	}
	if out.StoreErr != nil {
		o.RecordErr = "the shape could not be filed as confirmed: " + out.StoreErr.Error()
	}
	switch out.Exit {
	case devapply.ExitNoChange, devapply.ExitInterrupted:
		// nothing changed and nothing is said: the last record stands
		return
	case devapply.ExitApplied, devapply.ExitAppliedByOther:
		// the read after the commit is what the device runs now
		if st.after != nil {
			st.after.probe = st.probe
			_ = r.refresh(e, st.after, 0)
		}
	}
	kind := devconf.AppliedKindCheck
	if apply {
		kind = devconf.AppliedKindApply
	}
	var pre map[string]string
	if st != nil {
		pre = st.pre
	}
	a := r.appliedOf(out, kind, pre)
	// onboard writes over the command line and sets no transport
	a.Via = string(devapply.ViaCLI)
	if o.Via != "" {
		a.Via = string(o.Via)
	}
	if err := r.writeApplied(e, a); err != nil {
		o.RecordErr = strings.Join(msgs(err), " ")
	}
}

// pending writes the record of a confirmed commit the moment it was typed
// (D138): result pending, the change's id and the window's end, so that a
// tacctl that dies before the end leaves what the next run reconciles. A
// write that fails is said at once, in red, on standard error: the device
// may be pending and nothing records it. The transaction goes on.
func (r *applyRun) pending(e devreg.Entry, o *applyOutcome, c devapply.Outcome, st *applyState) {
	a := r.appliedOf(c, devconf.AppliedKindApply, st.pre)
	a.Via = string(st.via)
	a.Result, a.Reason, a.Until = devconf.AppliedPending, "committed, verifying", c.Until
	if err := r.writeApplied(e, a); err != nil {
		o.PendingErr = strings.Join(msgs(err), " ")
		r.inv.stderrLine(ui.Red + "RECORD " + e.Name + ui.NC + ": the confirmed commit " + c.ID + " was typed and its record could not be written (" +
			cleanLine(o.PendingErr) + "): the device may be PENDING until " + c.Until.Format("15:04:05") +
			"; do not type commit or commit check on it before then.")
	}
}

// recheck is what Phase B asks again at the start of each device's job,
// from the files as they are now (the review was of the devices as they
// were): a break-glass hold placed since, the registry entry (name, address,
// vendor, hostname, port, host keys), the scope that covers it and the
// user's access to that scope. It returns why the device is not applied (""
// when it is); then nothing is sent.
func (r *applyRun) recheck(e devreg.Entry) string {
	inv := r.inv
	const tail = " since the review; nothing was sent"
	for _, h := range conf.Load(inv.app.Paths.Overrides, backend.Default().IDs()).Holds() {
		if strings.EqualFold(h.Device, e.Name) && sameAddress(h.Address, e.Address) {
			return "break-glass was placed on hold for " + e.Name + tail
		}
	}
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return "the device registry could not be read again (" + shortReason(err) + "); nothing was sent"
	}
	reg, err := inv.registry()
	if err != nil {
		return "the host registry could not be read again (" + shortReason(err) + "); nothing was sent"
	}
	m, err := inv.app.LoadModel()
	if err != nil {
		return "the store could not be read again (" + shortReason(err) + "); nothing was sent"
	}
	now, ok := devreg.NewResolver(f, reg, m).Lookup(e.Name, devreg.ScopeFilter{})
	switch {
	case !ok || now.Name != e.Name || now.Source != e.Source:
		return "the device is no longer registered as " + e.Name + tail
	case now.Address != e.Address:
		return "its registered address changed (" + e.Address + " to " + now.Address + ")" + tail
	case now.Vendor != e.Vendor:
		return "its registered vendor changed (" + e.Vendor + " to " + now.Vendor + ")" + tail
	case now.Hostname != e.Hostname || now.Port != e.Port || !slices.Equal(now.HostKeys, e.HostKeys):
		return "its registry entry changed (hostname, port or host keys)" + tail
	case !now.Configured:
		return "no scope covers its address any more" + tail
	case now.Scope != e.Scope:
		return "the scope that covers it changed (" + e.Scope + " to " + now.Scope + ")" + tail
	}
	if msg := loginProblem(m, r.user, now.Scope); msg != "" {
		return msg + tail
	}
	return ""
}

// settle settles a record that says a confirmed commit may be pending (D132)
// before anything is typed: the device's history says which. It returns why
// the device cannot be touched ("" when it can).
func (r *applyRun) settle(ctx context.Context, e devreg.Entry, expected []devices.Section, target devssh.Target, o *applyOutcome) string {
	recs, _ := r.store.Load()
	rec, ok := recs.Of(e.Name)
	if !ok || !rec.Applied.Pending() {
		return ""
	}
	a := rec.Applied.Clone()
	when := "the end of its window"
	if !a.Until.IsZero() {
		when = a.Until.Format("15:04:05")
	}
	forget := "; once the device is checked by hand, 'tacctl device config forget " + e.Name + "' clears the record"
	j, err := devapply.DialJunos(ctx, target)
	if err != nil {
		return "a confirmed commit (" + a.ID + ") may be pending until " + when + " and the device could not be read to settle it (" +
			shortReason(err) + "); nothing was sent"
	}
	defer func() { _ = j.Close() }()
	r.acceptOnce.Do(r.passwd.Accepted)
	facts := func(ctx context.Context, raw string) (plan.Delta, error) {
		rp, err := r.planRead(e, expected, raw, j.ReadPlain(ctx), j.LocalAddr())
		if err != nil {
			return plan.Delta{}, err
		}
		return rp.delta, nil
	}
	out := devapply.Reconcile(ctx, j, e.Name, a.ID, a.Until, facts)
	o.Settled = &applySettled{ID: a.ID, Result: string(out.Result)}
	switch out.Exit {
	case devapply.ExitPending:
		return "a confirmed commit (" + a.ID + ") is pending until " + when + " by this server's clock: do not type commit or commit check on the device before then; nothing was sent"
	case devapply.ExitUnknown:
		return "the state of the confirmed commit " + a.ID + " could not be settled (" + cutReason(out.Reason) + "); nothing was sent" + forget
	}
	a.Result, a.Reason, a.At = string(out.Result), cutReason(out.Reason), r.inv.app.Knobs.Now()
	a.Until = time.Time{}
	if out.Commit != nil {
		a.Commit = &devconf.AppliedCommit{Seq: out.Commit.Seq, Time: out.Commit.TimeText}
	}
	fate := out.Fate
	if fate == "" {
		fate = a.Result
	}
	// the line is made now, from what the settle found: the record it
	// writes is replaced by this run's own when its transaction ends
	o.Settled.Line = "the earlier apply " + a.ID + " by " + a.By + " was " + fate
	if err := r.writeApplied(e, a); err != nil {
		o.Settled.Line += " (the record was not kept: " + strings.Join(msgs(err), " ") + ")"
	}
	return ""
}

// applySettled is what the settle of an earlier apply's pending record
// found: printed above the device's line and audited (apply settle).
type applySettled struct {
	ID, Result string
	// Line is the settled state as a line ("" when it did not settle).
	Line string
}

// realHoldWait is how long --hold waits for the word: until a minute of the
// window is left (DefaultMinWindow), and at least a second. A test shortens it
// (hooks.applyHoldWait).
func realHoldWait(until, now time.Time) time.Duration {
	return max(until.Sub(now)-devapply.DefaultMinWindow, time.Second)
}

// holdAnswer is a line the person typed while --hold waits, with the number
// of questions that were open when it was read.
type holdAnswer struct {
	line  string
	asked int32
}

// holdLine is the run's one reader of the person's lines for --hold: a
// goroutine started at the first question that reads standard input line by
// line and hands each line over, stamped with the question it was read
// under, until the input ends (the channel closes) or the run ends
// (holdDone).
func (r *applyRun) holdLine() <-chan holdAnswer {
	r.holdOnce.Do(func() {
		lines := make(chan holdAnswer)
		r.holdLines = lines
		pr, done := r.inv.app.Prompter(), r.holdDone
		go func() {
			defer close(lines)
			for {
				line, ok := pr.ReadLine()
				if !ok {
					return
				}
				select {
				case lines <- holdAnswer{line, r.holdAsked.Load()}:
				case <-done:
					return
				}
			}
		}()
	})
	return r.holdLines
}

// holdFunc is --hold (D134, Q2): after the verification the change is kept
// only on the typed word, with the window as the limit. A line read under an
// earlier question (an answer that came too late for the device before) is
// dropped, not taken as this device's answer; one read under this question
// is the answer, also when it was typed ahead of the first question (D224).
func (r *applyRun) holdFunc(name string) func(context.Context, time.Time) (bool, error) {
	return func(ctx context.Context, until time.Time) (bool, error) {
		inv := r.inv
		asked := r.holdAsked.Add(1)
		lines := r.holdLine()
		inv.echo("  " + name + "  verified; the change is held until you answer. Log in with one account of each class in another terminal.")
		inv.echo("  " + name + "  it rolls back by itself at " + until.Format("15:04:05") + " unless you answer before then.")
		_, _ = io.WriteString(inv.app.Out.Stderr, "  Type OK to keep the change, anything else rolls it back: ")
		t := time.NewTimer(inv.hooks.holdWait(until, inv.app.Knobs.Now()))
		defer t.Stop()
		for {
			select {
			case a, ok := <-lines:
				if !ok {
					return false, errors.New("no answer: the input ended")
				}
				if a.asked < asked {
					continue
				}
				return a.line == "OK", nil
			case <-ctx.Done():
				return false, errors.New("interrupted")
			case <-t.C:
				return false, errors.New("the window ran short")
			}
		}
	}
}

// --- the verb --------------------------------------------------------------------

// deviceConfigApply is 'device config apply'.
func (inv *invocation) deviceConfigApply(args []string) error {
	p, err := inv.deviceConfigParse("apply", args)
	if err != nil {
		return err
	}
	if err := inv.deviceConfigAllowed("apply"); err != nil {
		return err
	}
	user, err := inv.configLogin("device config apply")
	if err != nil {
		return err
	}
	aa, err := inv.applyArgsOf(p)
	if err != nil {
		return err
	}
	sel, err := inv.parseSelection(p, "apply")
	if err != nil {
		return err
	}
	usage := "Usage: tacctl device config " + deviceConfigUse("apply")
	pr := inv.app.Prompter()
	switch {
	case !aa.check && !aa.yes && !pr.Interactive():
		return inv.argErr("No terminal to confirm on: the review of an apply is answered by typing each device's name back. "+
			"Without a terminal use --confirmed --yes, which applies only shapes another device confirmed. Nothing was changed.", usage)
	case aa.hold && !pr.Interactive():
		return inv.argErr("--hold asks a person to log in and type OK: it needs a terminal. Nothing was changed.", usage)
	}
	// --pull (D268): the selection is made without --stale and --differs,
	// which are applied to the records the pull makes (pullFirst).
	pre := sel
	if aa.pullFirst {
		pre.stale, pre.differs = false, false
	}
	chosen, err := inv.chooseDevices(pre, user, true, "apply", aa.pull.render)
	if err != nil {
		return err
	}
	if len(chosen.entries) == 0 {
		return inv.nothingSelected(chosen, aa.pull.json, false)
	}

	// Only a Junos device is written to (D129): a named Cisco device or WTI
	// unit is a failed row, with its reason, before any login; a selector
	// leaves them out and counts them.
	var junos []devreg.Entry
	var refused []*applyOutcome
	var others []string
	for _, e := range chosen.entries {
		switch {
		case e.Vendor == devssh.VendorJuniper:
			junos = append(junos, e)
		case len(sel.names) > 0:
			o := &applyOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Phase: "check",
				Reason: "apply is not available for Cisco devices in this release"}
			if e.Vendor == "wti" {
				o.Status, o.Reason = "unsupported", "apply is not available for WTI units: a unit has no candidate configuration to check"
			}
			refused = append(refused, o)
		default:
			others = append(others, e.Name)
		}
	}
	if len(others) > 0 {
		chosen.skipped.notJunos = append(chosen.skipped.notJunos, others...)
	}
	ctl := inv.newApplyCtl(user, aa, chosen, inv.hooks.newDevicePasswords(inv), usage)
	run := ctl.run
	defer close(run.holdDone)
	for _, o := range refused {
		ctl.rows = append(ctl.rows, o)
		if aa.pull.json {
			_ = json.NewEncoder(inv.app.Out.Stdout).Encode(o.json(applyJSON{}))
		} else {
			inv.echo(fmt.Sprintf("  %s  %s", o.Name, cleanLine(o.line())))
		}
	}
	if len(junos) == 0 {
		return ctl.finish(batch.Summary{}, false)
	}
	// The password, once, before any connection (D70).
	pw, err := run.passwd.Password(inv.ctx, user)
	if err != nil {
		return err
	}
	run.password = string(pw)
	askpass.Zero(pw)
	defer func() {
		run.password = ""
		if d, ok := run.passwd.(interface{ Done() }); ok {
			d.Done()
		}
	}()
	if aa.pullFirst {
		left, done, err := ctl.pullFirst(junos, sel)
		if done || err != nil {
			return err
		}
		junos = left
	}
	return ctl.run2(junos)
}

// newApplyCtl is the state of one apply over chosen as user, its password
// from passwd (asked by the caller, once, into run.password). The caller
// closes run.holdDone when the run ends.
func (inv *invocation) newApplyCtl(user string, aa applyArgs, chosen *chosenDevices, passwd devicePasswords, usage string) *applyCtl {
	confirm, _ := inv.applySettings()
	run := &applyRun{inv: inv, user: user, render: chosen.render, store: inv.configStore(),
		shapes: devapply.OpenShapes(inv.app.Paths.ApplyDir), stateDir: inv.app.Paths.ApplyDir,
		passwd: passwd, sections: aa.sections, minutes: confirm, holdOn: aa.hold, holdDone: make(chan struct{}),
		transport: aa.transport}
	return &applyCtl{inv: inv, user: user, aa: aa, run: run, settings: inv.deviceConfigSettings(), chosen: chosen, usage: usage}
}

// pullFirst is --pull (0.2.17 D268): the Junos devices are read first as
// 'device config pull' reads them (its view, its audit lines and records,
// the transport of the settings, since --transport is how an apply writes)
// with the run's one password, so it is asked once for the pull, the check
// and the apply. A device whose pull failed is a failed row and is not
// checked: nothing is applied from a record the pull could not renew. Then
// --stale and --differs keep, of the devices read, the ones their fresh
// records select; the others are left out and counted. A pull that stopped
// (interrupted, an authentication failure, --max-failures) ends the run with
// nothing checked. It returns the devices that go on to the check, or done
// with the run's end.
func (c *applyCtl) pullFirst(junos []devreg.Entry, sel selection) ([]devreg.Entry, bool, error) {
	inv, aa, run := c.inv, c.aa, c.run
	view := inv.newPullView(junos, aa.pull.json, c.user, false)
	view.phase = "pull"
	sum, outs, err := inv.runPull(pullBatch{entries: junos, render: c.chosen.render, args: aa.pull, user: c.user, view: view,
		pass: &runPassword{src: run.passwd, password: run.password}})
	if err != nil {
		return nil, true, err
	}
	inv.hooks.pullDone()
	var pulled []devreg.Entry
	for i, e := range junos {
		res := sum.Entries[i].Result
		if res.Status == batch.StatusOK {
			pulled = append(pulled, e)
			continue
		}
		o := &applyOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Phase: "pull"}
		switch {
		case res.Status == batch.StatusNotStarted || res.Status == batch.StatusSkipped:
			o.Status, o.Reason = "not-started", "the pull did not start: "+res.Text()
		case outs[i] != nil && outs[i].Reason != "":
			o.Reason, o.Hint = "the pull failed: "+outs[i].Reason, outs[i].Hint
		default:
			o.Reason = "the pull failed: " + res.Text()
		}
		c.rows = append(c.rows, o)
	}
	if !aa.pull.json {
		inv.echo("")
		inv.echo("  pull: " + sum.Line())
	}
	// A Ctrl-C that cancelled the invocation once the pool had ended (the
	// pool's own context does not carry it) is an interrupted pull too.
	if inv.ctx.Err() != nil {
		sum.Interrupted = true
	}
	if sum.Interrupted || sum.Stop != batch.StopNone {
		return nil, true, c.finish(sum, false)
	}
	// the selection's last step, on the records the pull has just written
	fresh := &chosenDevices{entries: pulled, render: c.chosen.render}
	inv.applyStaleFilters(sel, fresh)
	c.leftAfterPull(pulled, fresh.entries)
	if inv.ctx.Err() != nil {
		return nil, true, c.finish(batch.Summary{Interrupted: true}, false)
	}
	if len(fresh.entries) == 0 {
		return nil, true, c.finish(batch.Summary{}, false)
	}
	if !aa.pull.json {
		inv.echo("")
	}
	return fresh.entries, false, nil
}

// leftAfterPull counts the devices pulled that --stale or --differs left
// out: those whose fresh record agrees with what tacctl renders, and apart
// from them those that could not be compared (the expected configuration
// cannot be rendered, the stored sections cannot be read, the state is not
// known). Neither is checked.
func (c *applyCtl) leftAfterPull(pulled, kept []devreg.Entry) {
	inv := c.inv
	store := inv.configStore()
	recs, _ := store.Load()
	render := c.chosen.render
	for _, e := range pulled {
		if slices.ContainsFunc(kept, func(x devreg.Entry) bool { return x.Name == e.Name }) {
			continue
		}
		st, err := inv.staleness(store, recs, render, e)
		if _, rerr := render.Expected(e); err == nil && rerr == nil && st == devconf.StaleOK {
			c.chosen.skipped.afterPull = append(c.chosen.skipped.afterPull, e.Name)
		} else {
			c.chosen.skipped.notCompared = append(c.chosen.skipped.notCompared, e.Name)
		}
	}
}

// applyCtl is one run's state between the two phases.
type applyCtl struct {
	inv      *invocation
	user     string
	aa       applyArgs
	run      *applyRun
	settings deviceSettings
	chosen   *chosenDevices
	usage    string
	// rows are the devices' final outcomes in the order they were decided.
	rows []*applyOutcome
}

// run2 is Phase A, the review and Phase B over the Junos devices.
func (c *applyCtl) run2(junos []devreg.Entry) error {
	inv, aa, run := c.inv, c.aa, c.run
	// The start line of the audit is written here, on the command's own
	// goroutine: the workers write the records, and audit.strict refuses by
	// a panic that only this goroutine recovers (audit.Writer.Touch).
	inv.app.Audit().Touch()
	// Phase A: the check of every device, in the 0.2.4 pool.
	jobs := make([]batch.Job, len(junos))
	for i, e := range junos {
		jobs[i] = run.jobOf(e, nil, "")
	}
	ctx, interrupts, stop := inv.batchInterrupts()
	view := inv.newApplyView(junos, "check", aa.pull.json, c.user)
	sumA := batch.Run(ctx, batch.Options{
		Concurrency: aa.pull.concurrency, Cap: c.settings.maxConcurrency, Timeout: aa.pull.timeout,
		MaxFailures: aa.pull.maxFailures, StopOnAuthFailure: true, Interrupts: interrupts, Clock: inv.app.Knobs.Now,
	}, jobs, view)
	stop()
	byName := map[string]*applyOutcome{}
	for i, en := range sumA.Entries {
		o, _ := en.Result.Value.(*applyOutcome)
		if o == nil {
			o = &applyOutcome{Name: junos[i].Name, Scope: junos[i].Scope, Vendor: junos[i].Vendor, Phase: "check"}
			if en.Result.Status == batch.StatusNotStarted || en.Result.Status == batch.StatusSkipped {
				o.Reason, o.Status = en.Result.Reason, "not-started"
			}
		}
		byName[strings.ToLower(junos[i].Name)] = o
		c.rows = append(c.rows, o)
	}
	if sumA.Interrupted || aa.check {
		return c.finish(sumA, false)
	}

	// The review: the devices that need a change, grouped by shape.
	groups := c.groupByShape(junos, byName)
	apply := c.selectApply(groups, byName)
	rv := c.review(groups, apply, aa.pull.json)
	if len(apply) == 0 {
		return c.finish(sumA, false)
	}
	if rv.interrupted {
		// Ctrl-C at a question: nothing is applied, approved or not
		sumA.Interrupted = true
		return c.finish(sumA, rv.declined)
	}
	if len(rv.approved) == 0 {
		return c.finish(sumA, true)
	}
	inv.hooks.reviewed()

	// Phase B: the approved devices, one shape's first device at a time; a
	// declined device stays a skipped row (D265).
	entries := make([]devreg.Entry, 0, len(rv.approved))
	jobsB := make([]batch.Job, 0, len(rv.approved))
	for _, o := range rv.approved {
		var e devreg.Entry
		for _, x := range junos {
			if x.Name == o.Name {
				e = x
			}
		}
		d := o.Delta
		entries = append(entries, e)
		jobsB = append(jobsB, run.jobOf(e, &d, o.Out.Shape))
	}
	concurrency := 1
	if aa.pull.concurrency > 1 && !aa.hold {
		concurrency = aa.pull.concurrency
	}
	maxFail := aa.pull.maxFailures
	if maxFail == 0 {
		maxFail = 1
	}
	// Phase B's interrupts are taken first, then the invocation's context is
	// looked at: a Ctrl-C after the last answer and before they were taken
	// cancelled only that context (Phase B's is not cancelled by it), so it
	// ends the run here with nothing applied and no approval line. One that
	// comes later is Phase B's first Ctrl-C.
	ctxB, interruptsB, stopB := inv.batchInterrupts()
	if inv.ctx.Err() != nil {
		stopB()
		c.reviewInterrupted(rv.approved)
		sumA.Interrupted = true
		return c.finish(sumA, rv.declined)
	}
	c.audit(rv.approved)
	viewB := inv.newApplyView(entries, "apply", aa.pull.json, c.user)
	viewB.mode = aa.reviewMode()
	sumB := batch.Run(ctxB, batch.Options{
		Concurrency: concurrency, Cap: c.settings.maxConcurrency, Timeout: time.Duration(run.minutes+2) * time.Minute,
		MaxFailures: maxFail, StopOnAuthFailure: true, Interrupts: interruptsB, Clock: inv.app.Knobs.Now,
		Canary: !aa.noCanary, Pause: aa.pause,
	}, jobsB, viewB)
	stopB()
	// what Phase B did replaces what Phase A said of the same device
	for i, en := range sumB.Entries {
		name := strings.ToLower(entries[i].Name)
		old := byName[name]
		o, _ := en.Result.Value.(*applyOutcome)
		if o == nil {
			// not started in Phase B: the device stays as it was checked, with
			// the reason it did not go on
			switch {
			case old == nil:
			case en.Result.Status == batch.StatusNotStarted:
				old.Skipped = "not started: " + en.Result.Reason
			case en.Result.Status == batch.StatusSkipped:
				old.Skipped = en.Result.Reason
			}
			continue
		}
		o.ConfirmedOn = old.ConfirmedOn
		for j, r := range c.rows {
			if strings.EqualFold(r.Name, o.Name) {
				c.rows[j] = o
			}
		}
	}
	return c.finish(sumB, rv.declined)
}
