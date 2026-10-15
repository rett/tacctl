package devapply

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// both runs a scenario once per transport (D149): the command line and
// NETCONF. The exits that agree are asserted once, in the scenario; what
// differs by design has a test of its own below.
func both(t *testing.T, knobs map[string]string, fn func(t *testing.T, d *device)) {
	t.Helper()
	for _, tr := range []struct {
		name    string
		netconf bool
	}{{"cli", false}, {"netconf", true}} {
		t.Run(tr.name, func(t *testing.T) {
			d := newDevice(t, knobs)
			d.netconf = tr.netconf
			fn(t, d)
		})
	}
}

// netDevice is a device served over NETCONF only.
func netDevice(t *testing.T, knobs map[string]string, mode NetconfMode) *device {
	t.Helper()
	d := newDevice(t, knobs)
	d.netconf, d.mode = true, mode
	return d
}

// --- the exits, once per transport ------------------------------------------------------------

func TestBothApplied(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, nil)
		wantExit(t, o, ExitApplied, ResultApplied)
		if o.Commit == nil || !strings.HasPrefix(o.Commit.Comment, "tacctl apply confirm "+o.ID+" by alice") {
			t.Errorf("commit entry %+v", o.Commit)
		}
		if o.Counts != (Counts{Set: 3, Delete: 1}) || strings.Join(o.Sections, ",") != "aaa,snmp" {
			t.Errorf("counts %+v sections %v", o.Counts, o.Sections)
		}
		after := d.srv.Committed()
		if after == before || !strings.Contains(after, "set system accounting events login") || strings.Contains(after, "example-ro clients") {
			t.Errorf("committed:\n%s", after)
		}
		h := d.srv.History()
		if len(h) < 3 || !strings.HasPrefix(h[0].Comment, "tacctl apply confirm ") ||
			!strings.HasPrefix(h[1].Comment, "tacctl apply "+o.ID+" by alice") || h[1].RollbackIn != 10 {
			t.Errorf("history %+v", h[:2])
		}
		if _, pending := d.srv.PendingUntil(); pending || d.srv.ExclusiveHolder() != "" {
			t.Error("pending or locked")
		}
		if d.srv.Candidate() != after {
			t.Error("the shared candidate is not the committed configuration")
		}
	})
}

func TestBothChecked(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := check(t, d, &planner{desired: desiredLines()}, nil)
		wantExit(t, o, ExitChecked, ResultChecked)
		if !o.Discarded || d.srv.Committed() != before || d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
			t.Errorf("%+v", o)
		}
		if indexOf(o.Log, plan.ApplyCommitCheck) < 0 {
			t.Errorf("no check in the log: %q", o.Log)
		}
	})
}

func TestBothFailedBeforeOpen(t *testing.T) {
	cases := []struct {
		name  string
		knobs map[string]string
		want  string
	}{
		{"class", map[string]string{"class": "read-only\n"}, "cannot commit as this login (class read-only)"},
		{"locked", map[string]string{"exclusive.held-by": "bob\n"}, "locked by bob"},
		{"dirty", map[string]string{"dirty.shared": "user carol\nset snmp contact carol\n"}, "other editors or staged changes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			both(t, c.knobs, func(t *testing.T, d *device) {
				before := d.srv.Committed()
				o := check(t, d, &planner{desired: desiredLines()}, nil)
				wantExit(t, o, ExitFailed, ResultFailed)
				if !strings.Contains(o.Reason, c.want) {
					t.Errorf("reason %q, want %q", o.Reason, c.want)
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
		})
	}
}

func TestBothFailedLoad(t *testing.T) {
	knobs := map[string]string{"load.errors": "set system tacplus-server 192.0.2.11 secret => error: could not set " + secretKey + "\n"}
	both(t, knobs, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, nil)
		wantExit(t, o, ExitFailedLoad, ResultFailed)
		if !strings.HasPrefix(o.Reason, "load: set system tacplus-server 192.0.2.11 secret <secret>: ") ||
			!strings.Contains(o.Reason, "could not set <secret>") {
			t.Errorf("reason %q", o.Reason)
		}
		if !o.Discarded || d.srv.Committed() != before || d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
			t.Errorf("the device changed or the candidate was not discarded: %+v", o)
		}
	})
}

func TestBothFailedCheck(t *testing.T) {
	knobs := map[string]string{"check.errors": "set system accounting events => error: accounting needs a destination\n"}
	both(t, knobs, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := check(t, d, &planner{desired: desiredLines()}, nil)
		wantExit(t, o, ExitFailedCheck, ResultFailed)
		if !strings.Contains(o.Reason, "check: ") || !strings.Contains(o.Reason, "accounting needs a destination") {
			t.Errorf("reason %q", o.Reason)
		}
		if !o.Discarded || d.srv.Committed() != before || d.srv.Candidate() != before {
			t.Errorf("%+v", o)
		}
	})
}

func TestBothRolledBackFreshLoginRefused(t *testing.T) {
	both(t, map[string]string{"verify.fail": "deny"}, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, nil)
		wantExit(t, o, ExitRolledBack, ResultRolledBack)
		if !o.LoginRefused || !strings.Contains(o.Reason, "verification failed (the fresh login was refused)") {
			t.Errorf("%v %q", o.LoginRefused, o.Reason)
		}
		if d.srv.Committed() != before {
			t.Errorf("not rolled back:\n%s", d.srv.Committed())
		}
		if _, p := d.srv.PendingUntil(); p {
			t.Error("pending")
		}
	})
}

func TestBothRolledBackVerifyLoginRefused(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
			in.VerifyLogin = func(lg Login) error { return errors.New("not the template user " + lg.User) }
		})
		wantExit(t, o, ExitRolledBack, ResultRolledBack)
		if !strings.Contains(o.Reason, "verification failed (the fresh login: not the template user") || d.srv.Committed() != before {
			t.Errorf("%q", o.Reason)
		}
	})
}

func TestBothInterruptBeforeCommit(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		in := d.input(&planner{desired: desiredLines()})
		switch tr := in.Transport.(type) {
		case *JunosCLI:
			in.Transport = &cancelT{JunosCLI: tr, afterLoads: 2, cancel: cancel}
		case *JunosNetconf:
			in.Transport = &cancelN{JunosNetconf: tr, afterLoads: 2, cancel: cancel}
		}
		o := Driver{}.Check(ctx, in)
		assertLog(t, o, desiredLines())
		assertNoSecret(t, o, d.state)
		wantExit(t, o, ExitInterrupted, ResultFailed)
		if !o.Interrupted || !o.Discarded {
			t.Errorf("%+v", o)
		}
		if d.srv.Committed() != before || d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
			t.Error("changed")
		}
	})
}

func TestBothInterruptAfterCommit(t *testing.T) {
	both(t, nil, func(t *testing.T, d *device) {
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
		if !o.Interrupted || !strings.HasPrefix(o.Reason, "interrupted") || d.srv.Committed() != before {
			t.Errorf("%+v", o)
		}
		if _, p := d.srv.PendingUntil(); p {
			t.Error("pending")
		}
	})
}

// cancelN is cancelT for the NETCONF transport.
type cancelN struct {
	*JunosNetconf
	afterLoads int
	n          int
	cancel     func()
}

func (c *cancelN) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	r, err := c.JunosNetconf.Load(ctx, l)
	c.n++
	if c.n == c.afterLoads {
		c.cancel()
	}
	return r, err
}

// --- what differs by design ---------------------------------------------------------------------

// A NETCONF session that is lost after the confirmed commit leaves the
// commit pending to the window's end (lab, plan N2), as over the command
// line: the driver cannot cancel from another session and says PENDING
// until the window's end, which the device then rolls back.
func TestNetconfSessionDroppedLeavesTheCommitPending(t *testing.T) {
	for _, knob := range []string{"", "after-output"} {
		t.Run("drop="+knob, func(t *testing.T) {
			d := netDevice(t, map[string]string{"commit.drop": knob}, ModeAuto)
			before := d.srv.Committed()
			o := apply(t, d, &planner{desired: desiredLines()}, nil)
			t.Logf("exit %s: %s", o.Exit, o.Line())
			if o.Exit == ExitApplied {
				t.Fatalf("exit %s: %s\nlog: %q", o.Exit, o.Line(), o.Log)
			}
			if o.Exit != ExitPending && o.Exit != ExitUnknown {
				t.Fatalf("exit %s: %s", o.Exit, o.Line())
			}
			if d.srv.Committed() == before {
				t.Error("rolled back by the lost session")
			}
			if _, p := d.srv.PendingUntil(); !p {
				t.Error("not pending")
			}
			// a dropped session after the answer lets the driver try the
			// confirm (it is in the log, and failed: the commit is pending)
			if knob == "" && indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice")) >= 0 {
				t.Error("confirmed")
			}
			// the window's end is the rollback
			d.clk.Advance(11 * time.Minute)
			if d.srv.Committed() != before {
				t.Errorf("not rolled back at the window's end:\n%s", d.srv.Committed())
			}
		})
	}
}

// A confirmed commit that a command-line session left pending is read as
// pending over NETCONF (from the history's label: no prompt, no banner), and
// nothing is sent to the device.
func TestNetconfPendingAtPreflight(t *testing.T) {
	d := newDevice(t, map[string]string{"commit.drop": ""})
	o := apply(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitPending, ResultPending)
	d.unknob("commit.drop")
	d.netconf, d.mode = true, ModeAuto
	nc := d.dialNetconf(ModeAuto)
	st, err := nc.State(context.Background())
	_ = nc.Close()
	if err != nil || !st.Pending || st.Minutes != 11 {
		t.Errorf("state %+v (%v)", st, err)
	}
	o2 := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o2, ExitFailed, ResultFailed)
	if !strings.Contains(o2.Reason, "a confirmed commit is pending") {
		t.Errorf("reason %q", o2.Reason)
	}
	for _, l := range o2.Log {
		if strings.HasPrefix(l, "netconf: open-configuration") || l == plan.ApplyCommitCheck {
			t.Errorf("a pending device was touched: %q", o2.Log)
		}
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Error("the device is no longer pending")
	}
}

// With the fresh login's state unreadable and the held session gone, the
// outcome is unknown, never applied.
func TestNetconfStateUnreadableIsUnknown(t *testing.T) {
	d := netDevice(t, map[string]string{"commit.drop": ""}, ModeAuto)
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Verify = func(context.Context) (Reader, error) { return nil, errors.New("no login") }
	})
	wantExit(t, o, ExitUnknown, ResultUnknown)
}

// N1 (refuted on the lab switch): the device refuses the confirmed commit
// in a private session, in its own words. An explicit private transport
// gives the typed error and RetryExclusive; nothing is committed and the
// transaction is not switched in the middle. The default mode never tries a
// private session: it takes the candidate's lock at once and applies.
func TestNetconfPrivateConfirmRefused(t *testing.T) {
	d := netDevice(t, nil, ModePrivate)
	before := d.srv.Committed()
	p := &planner{desired: desiredLines()}
	rev := d.reviewed(p)
	in := d.input(p)
	tr := in.Transport.(*JunosNetconf)
	o := Driver{}.Apply(context.Background(), in, rev)
	assertNoSecret(t, o, d.state)
	if o.Exit == ExitApplied || d.srv.Committed() != before {
		t.Fatalf("exit %s: %s\ncommitted:\n%s", o.Exit, o.Line(), d.srv.Committed())
	}
	if !strings.Contains(o.Reason, textNoConfirmedPrivate) {
		t.Errorf("reason %q", o.Reason)
	}
	if !tr.RetryExclusive() {
		t.Error("RetryExclusive is not set")
	}
	if _, pending := d.srv.PendingUntil(); pending || d.srv.ExclusiveHolder() != "" {
		t.Error("pending or locked")
	}
	for _, l := range o.Log {
		if l == "netconf: lock-configuration" {
			t.Errorf("the mode was switched inside the transaction: %q", o.Log)
		}
	}
	// the typed error itself, in the device's words
	d2 := netDevice(t, nil, ModePrivate)
	j := d2.dialNetconf(ModePrivate)
	defer func() { _ = j.Close() }()
	ctx := context.Background()
	if err := j.Open(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	err := j.CommitConfirmed(ctx, 5, "tacctl-20261013T140000Z-3f2a", "alice")
	if !errors.Is(err, ErrPrivateConfirmRefused) || !j.RetryExclusive() {
		t.Errorf("err %v retry %v", err, j.RetryExclusive())
	}
	_ = j.Discard(ctx)
	// the default mode applies on the same kind of device, under the lock,
	// and never opens a private session
	d3 := netDevice(t, nil, ModeAuto)
	o3 := apply(t, d3, &planner{desired: desiredLines()}, nil)
	wantExit(t, o3, ExitApplied, ResultApplied)
	if d3.srv.ExclusiveHolder() != "" {
		t.Error("the lock is still held")
	}
	lockSeen := false
	for _, l := range o3.Log {
		if strings.Contains(l, "open-configuration") {
			t.Errorf("a private session was opened: %q", o3.Log)
		}
		if l == "netconf: lock-configuration" {
			lockSeen = true
		}
	}
	if !lockSeen {
		t.Errorf("the lock was not taken: %q", o3.Log)
	}
}

// The lock mode refuses a candidate that another editor staged (the commit
// would carry it), and leaves no lock behind.
func TestNetconfLockModeRefusesAStagedCandidate(t *testing.T) {
	d := netDevice(t, map[string]string{"dirty.shared": "user carol\nset snmp contact carol\n"}, ModeAuto)
	j := d.dialNetconf(ModeAuto)
	defer func() { _ = j.Close() }()
	err := j.Open(context.Background(), func(string) error { return nil })
	var le *LockedError
	if !errors.As(err, &le) || !le.Modified {
		t.Fatalf("err %v", err)
	}
	if d.srv.ExclusiveHolder() != "" || j.Held() {
		t.Error("the lock or the session is left")
	}
}

// Plan N5: the pending marker is the device's own 'rollback pending' line,
// never the label, which rounds down to 0mins for a one-minute window; the
// 'rollback in' label of a command-line commit still parses as before.
func TestNetconfPendingIsTheDevicesLineNotTheLabel(t *testing.T) {
	h, err := parseHistory("0   2026-10-15 04:09:56 AKDT by admin via netconf commit confirmed, rollback in 0mins\n" +
		"    tacctl lab N1\n    rollback pending\n" +
		"1   2026-10-15 00:41:23 AKDT by admin via junoscript\n")
	if err != nil {
		t.Fatal(err)
	}
	if !h[0].Pending || h[0].RollbackIn != 0 || h[0].Comment != "tacctl lab N1" || h[1].Pending {
		t.Errorf("entries %+v", h)
	}
	h2, err := parseHistory("0   2026-10-15 04:10:45 AKDT by admin via netconf\n    tacctl lab N2 confirm\n" +
		"1   2026-10-15 04:10:43 AKDT by admin via netconf commit confirmed, rollback in 0mins\n    tacctl lab N1\n")
	if err != nil {
		t.Fatal(err)
	}
	if h2[0].Pending || h2[1].Pending {
		t.Errorf("a confirmed commit reads pending: %+v", h2)
	}
}

func TestNetconfExclusiveModeLocksOut(t *testing.T) {
	d := netDevice(t, nil, ModeExclusive)
	j := d.dialNetconf(ModeExclusive)
	defer func() { _ = j.Close() }()
	ctx := context.Background()
	if err := j.Open(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if d.srv.ExclusiveHolder() == "" {
		t.Error("the lock is not held in exclusive mode")
	}
	if err := j.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	if d.srv.ExclusiveHolder() != "" || j.Held() {
		t.Error("the lock or the session is left")
	}
}

// Another session's lock refuses the transaction in every mode, the way the
// command line's configure exclusive is: a LockedError (the lock mode is
// denied; a private session opens with a warning that nothing can be
// committed, which is refused the same way).
func TestNetconfOpenUnderForeignLock(t *testing.T) {
	for _, mode := range []NetconfMode{ModeAuto, ModeExclusive, ModePrivate} {
		d := netDevice(t, map[string]string{"exclusive.held-by": "bob\n"}, mode)
		j := d.dialNetconf(mode)
		err := j.Open(context.Background(), func(string) error { return nil })
		var le *LockedError
		if !errors.As(err, &le) {
			t.Fatalf("mode %d: err %v", mode, err)
		}
		if j.Held() {
			t.Errorf("mode %d: held", mode)
		}
		_ = j.Close()
	}
}

// The driver's cancel is the one used while tacctl's commit is still
// pending: every failure after the confirmed commit is run with a counting
// wrapper, and a rolled-back outcome comes from one Cancel and no Revert
// (the revert branch needs a commit that something else confirmed).
type countRevert struct {
	*JunosNetconf
	reverts, cancels atomic.Int32
}

func (c *countRevert) Revert(ctx context.Context, id string) error {
	c.reverts.Add(1)
	return c.JunosNetconf.Revert(ctx, id)
}

func (c *countRevert) Cancel(ctx context.Context, id string) error {
	c.cancels.Add(1)
	return c.JunosNetconf.Cancel(ctx, id)
}

func TestNetconfCancelIsTheRollbackWhileTheCommitPends(t *testing.T) {
	cases := []struct {
		name  string
		knobs map[string]string
		mod   func(*Input)
	}{
		{"verify.fail", map[string]string{"verify.fail": "deny"}, nil},
		{"verify-login", nil, func(in *Input) { in.VerifyLogin = func(Login) error { return errors.New("no") } }},
		{"landed", nil, func(in *Input) {
			in.Plan = func(ctx context.Context, raw string, from netIP) (plan.Delta, error) {
				return (&planner{desired: desiredLines()}).plan(ctx, raw, from)
			}
			in.Verify = func(ctx context.Context) (Reader, error) { return nil, errors.New("no login") }
		}},
		{"hold", nil, func(in *Input) {
			in.Hold = func(context.Context, time.Time) (bool, error) { return false, errors.New("interrupted") }
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := netDevice(t, c.knobs, ModeAuto)
			p := &planner{desired: desiredLines()}
			rev := d.reviewed(p)
			in := d.input(p)
			cr := &countRevert{JunosNetconf: in.Transport.(*JunosNetconf)}
			in.Transport = cr
			if c.mod != nil {
				c.mod(&in)
			}
			o := Driver{}.Apply(context.Background(), in, rev)
			assertNoSecret(t, o, d.state)
			t.Logf("exit %s: %s (cancels %d)", o.Exit, o.Line(), cr.cancels.Load())
			if cr.reverts.Load() != 0 {
				t.Errorf("Revert was called %d times (exit %s: %s)", cr.reverts.Load(), o.Exit, o.Line())
			}
			if o.Exit == ExitRolledBack && cr.cancels.Load() != 1 {
				t.Errorf("rolled back with %d cancels (exit %s: %s)", cr.cancels.Load(), o.Exit, o.Line())
			}
			if o.Exit == ExitApplied {
				t.Errorf("applied: %s", o.Line())
			}
		})
	}
}

func TestNetconfConfirmsNeedsCapabilitiesAndClass(t *testing.T) {
	hello := func(caps ...string) string {
		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="us-ascii"?><hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities>`)
		b.WriteString("<capability>urn:ietf:params:netconf:base:1.0</capability>")
		for _, c := range caps {
			b.WriteString("<capability>" + c + "</capability>")
		}
		b.WriteString("</capabilities><session-id>1</session-id></hello>")
		return b.String()
	}
	cases := []struct {
		name  string
		knobs map[string]string
		want  bool
	}{
		{"full", nil, true},
		{"no-confirmed", map[string]string{"netconf.hello": hello("urn:ietf:params:netconf:capability:candidate:1.0")}, false},
		{"no-candidate", map[string]string{"netconf.hello": hello("urn:ietf:params:netconf:capability:confirmed-commit:1.0")}, false},
		{"confirmed-1.1", map[string]string{"netconf.hello": hello(
			"urn:ietf:params:netconf:capability:candidate:1.0", "urn:ietf:params:netconf:capability:confirmed-commit:1.1")}, true},
		{"read-only", map[string]string{"class": "read-only\n"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := netDevice(t, c.knobs, ModeAuto)
			j := d.dialNetconf(ModeAuto)
			defer func() { _ = j.Close() }()
			if j.Confirms() {
				t.Error("Confirms before Login")
			}
			if _, err := j.Login(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got := j.Confirms(); got != c.want {
				t.Errorf("Confirms %v, want %v", got, c.want)
			}
		})
	}
}

// The reads yield the same typed values as the command line's.
func TestNetconfReadsAgreeWithTheCommandLine(t *testing.T) {
	d := newDevice(t, nil)
	cli := d.dial()
	defer func() { _ = cli.Close() }()
	nc := d.dialNetconf(ModeAuto)
	defer func() { _ = nc.Close() }()
	ctx := context.Background()
	ci, err := cli.Identity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ni, err := nc.Identity(ctx)
	if err != nil || ni != ci {
		t.Errorf("identity %+v / %+v (%v)", ni, ci, err)
	}
	ch, err := cli.History(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nh, err := nc.History(ctx)
	if err != nil || len(nh) != len(ch) || !nh[0].Same(ch[0]) {
		t.Errorf("history %+v / %+v (%v)", nh, ch, err)
	}
	cl, _ := cli.Login(ctx)
	nl, err := nc.Login(ctx)
	if err != nil || nl.Class != cl.Class || strings.Join(nl.Permissions, ",") != strings.Join(cl.Permissions, ",") {
		t.Errorf("login %+v / %+v (%v)", nl, cl, err)
	}
	cr, _ := cli.Read(ctx)
	nr, err := nc.Read(ctx)
	if err != nil || strings.TrimSpace(nr) != strings.TrimSpace(cr) {
		t.Errorf("read differs (%v):\n%s\n---\n%s", err, nr, cr)
	}
	st, err := nc.State(ctx)
	if err != nil || st.Pending {
		t.Errorf("state %+v (%v)", st, err)
	}
	// the fixture has one version: rollback 1 is refused the same way
	_, cerr := cli.RollbackCompare(ctx, 1)
	_, nerr := nc.RollbackCompare(ctx, 1)
	if !errors.Is(cerr, ErrUnrecognised) || !errors.Is(nerr, ErrUnrecognised) {
		t.Errorf("rollback compare: cli %v, netconf %v", cerr, nerr)
	}
	if c0, err := nc.RollbackCompare(ctx, 0); err != nil || !c0.Empty() {
		t.Errorf("rollback 0: %+v %v", c0, err)
	}
	if _, err := nc.RollbackCompare(ctx, plan.MaxRollback+1); !errors.Is(err, ErrNotSent) {
		t.Errorf("a rollback the device does not keep: %v", err)
	}
	if nc.Vendor() != devssh.VendorJuniper || nc.RollsBackOnClose() {
		t.Error("vendor or RollsBackOnClose")
	}
}

// Nothing the transport sends or logs holds a secret, and the guards refuse
// what the command line's refuse.
func TestNetconfGuardsAndLog(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	j := d.dialNetconf(ModeAuto)
	defer func() { _ = j.Close() }()
	ctx := context.Background()
	line := plan.Line{Op: plan.OpSet, Text: "set snmp contact noc"}
	if _, err := j.Load(ctx, line); !errors.Is(err, ErrNotSent) {
		t.Errorf("a load before Open: %v", err)
	}
	if err := j.Open(ctx, nil); !errors.Is(err, ErrNotSent) {
		t.Errorf("Open without an allow-list: %v", err)
	}
	if _, err := j.runCmd(ctx, "show configuration system"); !errors.Is(err, ErrNotSent) {
		t.Errorf("a read outside the words: %v", err)
	}
	refuse := func(string) error { return errors.New("no") }
	if err := j.Open(ctx, refuse); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []plan.Line{
		line,
		{Op: plan.OpSet, Text: "commit"},
		{Op: plan.OpSet, Text: "set system login message \"why?\""},
	} {
		if _, err := j.Load(ctx, bad); !errors.Is(err, ErrNotSent) {
			t.Errorf("%q: %v", bad.Text, err)
		}
	}
	if err := j.Open(ctx, refuse); !errors.Is(err, ErrNotSent) {
		t.Errorf("a second Open: %v", err)
	}
	// the first transaction ends before another takes the lock
	if err := j.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	secret := desiredLines()[0]
	allow := func(string) error { return nil }
	j2 := d.dialNetconf(ModeAuto)
	defer func() { _ = j2.Close() }()
	if err := j2.Open(ctx, allow); err != nil {
		t.Fatal(err)
	}
	if _, err := j2.Load(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := j2.Discard(ctx); err != nil {
		t.Fatal(err)
	}
	for _, l := range j2.Log() {
		for _, s := range allSecrets {
			if strings.Contains(l, s) {
				t.Errorf("a secret in the log: %q", l)
			}
		}
	}
	if d.srv.ExclusiveHolder() != "" {
		t.Error("lock left")
	}
	_ = fakedev.DefaultUser
}
