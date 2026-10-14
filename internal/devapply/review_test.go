package devapply

// The safety review's findings, each against the fake device.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/devssh/fakedev"
)

// strangerT lets a stranger act on the device right before the held session
// opens: after the pre-flight and the gate saw nothing.
type strangerT struct {
	*JunosCLI
	before func()
}

func (s strangerT) Open(ctx context.Context, allow func(string) error) error {
	s.before()
	return s.JunosCLI.Open(ctx, allow)
}

// A stranger's 'commit confirmed' that became pending after the pre-flight is
// never confirmed by tacctl's 'commit check': the state (the banner) is read
// before the check, the candidate discarded and the transaction failed.
func TestStrangerPendingBeforeCheck(t *testing.T) {
	for _, c := range []struct {
		name  string
		apply bool
	}{{"check", false}, {"apply", true}} {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t, nil)
			before := d.srv.Committed()
			p := &planner{desired: desiredLines()}
			mod := func(in *Input) {
				in.Transport = strangerT{in.Transport.(*JunosCLI), func() { runShell(t, d, "configure", "commit confirmed 5") }}
			}
			var o Outcome
			if c.apply {
				o = apply(t, d, p, mod)
			} else {
				o = check(t, d, p, mod)
			}
			wantExit(t, o, ExitFailedCheck, ResultFailed)
			if !strings.Contains(o.Reason, "a confirmed commit of gotest became pending until 2026-10-13 14:05:00 UTC before the check") || !o.Discarded {
				t.Errorf("reason %q discarded %v", o.Reason, o.Discarded)
			}
			if indexOf(o.Log, plan.ApplyCommitCheck) >= 0 || strings.Contains(strings.Join(o.Log, "\n"), "commit confirmed") {
				t.Errorf("checked or committed over a stranger's pending commit: %q", o.Log)
			}
			if u, pending := d.srv.PendingUntil(); !pending || !u.Equal(testStart.Add(5*time.Minute)) {
				t.Error("the stranger's pending commit was confirmed")
			}
			if d.srv.Committed() != before || d.srv.ExclusiveHolder() != "" {
				t.Error("the device changed or the lock was left")
			}
		})
	}
}

// expireT lets the device's own window end right before the cancel's
// 'rollback 1' (after the history read that found the commit pending).
type expireT struct {
	*JunosCLI
	clk *fakedev.FakeClock
}

func (e expireT) Cancel(ctx context.Context, id string) error {
	e.clk.Advance(10*time.Minute + time.Second)
	return e.JunosCLI.Cancel(ctx, id)
}

// The cancel commits only the inverse of tacctl's change: after the device's
// own rollback, 'rollback 1' loads the change itself, and committing it would
// make it permanent.
func TestCancelAfterExpiryCommitsNothing(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = expireT{in.Transport.(*JunosCLI), d.clk}
		in.Hold = func(context.Context, time.Time) (bool, error) { return false, nil }
	})
	if d.srv.Committed() != before {
		t.Fatalf("the cancel made the change permanent (%s: %q):\n%s", o.Exit, o.Reason, d.srv.Committed())
	}
	for _, h := range d.srv.History() {
		if strings.HasPrefix(h.Comment, "tacctl apply cancel") {
			t.Errorf("a cancel was committed: %+v", h)
		}
	}
	// the prompt after 'rollback 1' no longer shows the banner: discarded
	// before the compare (lab L2; before the spike the compare's inverse
	// check was the first guard to see it, and stays the second)
	if indexOf(o.Log, plan.ApplyCancel(o.ID)) >= 0 || !endsWith(o.Log, plan.ApplyRollback1, plan.ApplyRollback0, plan.ApplyExit) {
		t.Errorf("log %q", o.Log)
	}
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "the commit after tacctl's is by root via other at 2026-10-13 14:10:00 UTC") ||
		!strings.Contains(o.Reason, "the configuration lacks the change") || !strings.Contains(o.Reason, "shows no pending commit") {
		t.Errorf("reason %q", o.Reason)
	}
}

// bannerT keeps the banner in the held session's prompt after 'rollback 1'
// though the device's window ended: the compare's inverse check still
// refuses the cancel's commit.
type bannerT struct {
	*JunosCLI
	clk *fakedev.FakeClock
}

func (b bannerT) Cancel(ctx context.Context, id string) error {
	b.clk.Advance(10*time.Minute + time.Second)
	b.mu.Lock()
	held := b.held
	b.held = bannerSession{held}
	b.mu.Unlock()
	return b.JunosCLI.Cancel(ctx, id)
}

type bannerSession struct{ devssh.CLISession }

func (bannerSession) PromptArea() ([]string, bool) {
	return []string{"# commit confirmed will be rolled back in 1 minute"}, true
}

func TestCancelNotInverseCommitsNothing(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = bannerT{in.Transport.(*JunosCLI), d.clk}
		in.Hold = func(context.Context, time.Time) (bool, error) { return false, nil }
	})
	if d.srv.Committed() != before || indexOf(o.Log, plan.ApplyCancel(o.ID)) >= 0 {
		t.Fatalf("the cancel was committed: %q", o.Log)
	}
	if !strings.Contains(o.Reason, "not the inverse") {
		t.Errorf("reason %q", o.Reason)
	}
}

// expiryTextT shows the device's own rollback with another 'via' than the one
// tacctl knows.
type expiryTextT struct{ Reader }

func (e expiryTextT) History(ctx context.Context) (History, error) {
	h, err := e.Reader.History(ctx)
	return otherVia(h), err
}

func (e expiryTextT) State(ctx context.Context) (CommitState, error) {
	st, err := e.Reader.State(ctx)
	st.History = otherVia(st.History)
	return st, err
}

func otherVia(h History) History {
	for i := range h {
		if h[i].User == textExpiryUser && h[i].Via == textExpiryVia {
			h[i].Via = "timer"
		}
	}
	return h
}

// An entry after tacctl's commit that tacctl does not recognise is never
// taken for someone else's confirm: the state is settled from the
// configuration (the delta), or unknown.
func TestUnrecognisedEntryAfterCommit(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	p := &planner{desired: desiredLines()}
	o := apply(t, d, p, func(in *Input) {
		in.Hold = func(context.Context, time.Time) (bool, error) {
			d.clk.Advance(10*time.Minute + time.Second)
			return false, nil
		}
		in.Verify = func(ctx context.Context) (Reader, error) {
			r, err := d.verify(ctx)
			if err != nil {
				return nil, err
			}
			return expiryTextT{r}, nil
		}
	})
	if d.srv.Committed() != before {
		t.Fatal("the device did not roll back")
	}
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "the configuration lacks the change") {
		t.Errorf("reason %q", o.Reason)
	}

	// the reconciliation: settled from the configuration with a planner,
	// unknown without one
	r, err := d.verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	rd := expiryTextT{r}
	rc := Reconcile(context.Background(), rd, "example-sw1", o.ID, o.Until, nil)
	wantExit(t, rc, ExitUnknown, ResultUnknown)
	rc = Reconcile(context.Background(), rd, "example-sw1", o.ID, o.Until, factsOf(p))
	wantExit(t, rc, ExitRolledBack, ResultRolledBack)
}

// factsOf is the reconciliation's planner over the test planner.
func factsOf(p *planner) func(context.Context, string) (plan.Delta, error) {
	return func(ctx context.Context, raw string) (plan.Delta, error) {
		return (&planner{desired: p.desired}).plan(ctx, raw, netIP{127, 0, 0, 1})
	}
}

// A device named 'shapes' has its lock apart from the shape store's: the
// applied apply files its shape and returns.
func TestLockDeviceNamedShapes(t *testing.T) {
	d := newDevice(t, nil)
	done := make(chan Outcome, 1)
	p := &planner{desired: desiredLines()}
	rev := d.reviewed(p)
	go func() {
		in := d.input(p)
		in.Device, in.Names = "shapes", []string{"shapes", "example-sw1"}
		done <- Driver{}.Apply(context.Background(), in, rev)
	}()
	select {
	case o := <-done:
		wantExit(t, o, ExitApplied, ResultApplied)
		if o.StoreErr != nil {
			t.Error(o.StoreErr)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the device 'shapes' deadlocked on the store's lock")
	}
	fi, err := os.Stat(filepath.Join(d.state, "locks"))
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the locks directory: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(d.state, "locks", "shapes.lock")); err != nil {
		t.Error(err)
	}
	for _, bad := range []string{"", ".", "..", ".hidden", "a/b", "a\\b", "a\x00b"} {
		if _, err := LockDevice(d.state, bad); err == nil {
			t.Errorf("%q names a lock file", bad)
		}
	}
}

// The held login dialled with the job's own context still types the discard
// after the second interrupt.
func TestInterruptDialledWithJobContext(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	in := d.input(&planner{desired: desiredLines()})
	_ = in.Transport.Close()
	j, err := DialJunos(ctx, d.target(fakedev.DefaultUser, fakedev.DefaultPassword))
	if err != nil {
		t.Fatal(err)
	}
	in.Transport = &cancelT{JunosCLI: j, afterLoads: 2, cancel: cancel}
	o := Driver{}.Check(ctx, in)
	assertNoSecret(t, o, d.state)
	wantExit(t, o, ExitInterrupted, ResultFailed)
	if !o.Discarded || !endsWith(o.Log, plan.ApplyRollback0, plan.ApplyExit) {
		t.Errorf("the discard was not typed: %q %q", o.Reason, o.Log)
	}
	if d.srv.Committed() != before || d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
		t.Error("changed")
	}
	// the connection still ends with the transport
	if err := j.Close(); err != nil {
		t.Error(err)
	}
}

// strangeCompare answers the gate's compare with a line no compare has,
// holding words of a stranger's staged change.
type strangeCompare struct{ devssh.CLISession }

func (s strangeCompare) Run(ctx context.Context, cmd string) (string, error) {
	out, err := s.CLISession.Run(ctx, cmd)
	if cmd == plan.ApplyCompare && err == nil {
		out = "[edit snmp]\n+   location x;\n?? zz-stranger-private words\n" + out
	}
	return out, err
}

func (s strangeCompare) PromptArea() ([]string, bool) {
	return s.CLISession.(devssh.PromptArea).PromptArea()
}

// The gate never quotes a line of a stranger's staged compare: its number
// only.
func TestGateCompareNotQuoted(t *testing.T) {
	d := newDevice(t, nil)
	o := check(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		j := in.Transport.(*JunosCLI)
		shell := j.newShell
		j.newShell = func() (devssh.CLISession, error) {
			s, err := shell()
			if err != nil {
				return nil, err
			}
			return strangeCompare{s}, nil
		}
	})
	wantExit(t, o, ExitFailed, ResultFailed)
	if !strings.Contains(o.Reason, "compare line 3: not a compare line") {
		t.Errorf("reason %q", o.Reason)
	}
	if strings.Contains(fmt.Sprintf("%+v", o), "zz-stranger") {
		t.Errorf("the stranger's line is quoted: %q", o.Reason)
	}
}

// panicT panics in one method.
type panicT struct {
	*JunosCLI
	at string
}

func (p panicT) Load(ctx context.Context, l plan.Line) (Loaded, error) {
	if p.at == "load" {
		panic("boom in load " + l.Text)
	}
	return p.JunosCLI.Load(ctx, l)
}

func (p panicT) Confirm(ctx context.Context, id, user string) error {
	if p.at == "confirm" {
		panic("boom in confirm")
	}
	return p.JunosCLI.Confirm(ctx, id, user)
}

// A panic in the transaction ends at a named exit: before the confirmed
// commit the candidate is discarded, after it the record says unknown with
// the window's end.
func TestPanicNamedExit(t *testing.T) {
	run := func(t *testing.T, d *device, at string) (o Outcome) {
		t.Helper()
		defer func() {
			if v := recover(); v != nil {
				t.Fatalf("the panic reached the caller: %v", v)
			}
		}()
		return apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
			in.Transport = panicT{in.Transport.(*JunosCLI), at}
		})
	}
	t.Run("before", func(t *testing.T) {
		d := newDevice(t, nil)
		before := d.srv.Committed()
		o := run(t, d, "load")
		wantExit(t, o, ExitFailed, ResultFailed)
		if !o.Discarded || !strings.Contains(o.Reason, "internal error") || !o.Until.IsZero() {
			t.Errorf("%+v", o)
		}
		if d.srv.Committed() != before || d.srv.Candidate() != before || d.srv.ExclusiveHolder() != "" {
			t.Error("changed")
		}
	})
	t.Run("after", func(t *testing.T) {
		d := newDevice(t, nil)
		o := run(t, d, "confirm")
		wantExit(t, o, ExitUnknown, ResultUnknown)
		if !o.Until.Equal(testStart.Add(10*time.Minute)) || !strings.Contains(o.Reason, "internal error") {
			t.Errorf("%+v", o)
		}
		if _, p := d.srv.PendingUntil(); !p {
			t.Error("not pending")
		}
	})
}

// A secret of two characters does not mask every word that holds them: only
// a whole field, and the statement where it stands.
func TestShortSecretMasking(t *testing.T) {
	line := plan.Line{Section: "snmp", Op: plan.OpSet, Text: "set snmp community ro authorization read-only",
		Secret: true, HasValue: true, Elided: "set snmp community <secret> authorization read-only"}
	d := newDevice(t, map[string]string{"load.errors": "set snmp community ro => error: invalid community ro for this release\n"})
	in := d.input(&planner{desired: []plan.Line{line}})
	in.Allow.Expected = []devices.Section{{Name: "snmp", Lines: []string{line.Text}, Secret: []bool{true}}}
	o := Driver{}.Check(context.Background(), in)
	wantExit(t, o, ExitFailedLoad, ResultFailed)
	want := "load: set snmp community <secret> authorization read-only: error: invalid community <secret> for this release"
	if !strings.HasPrefix(o.Reason, want) {
		t.Errorf("reason %q, want %q", o.Reason, want)
	}
	for _, l := range append(append([]string{o.Reason}, o.Log...), o.VerifyLog...) {
		for _, f := range strings.Fields(l) {
			if strings.Trim(f, `"';:,`) == "ro" {
				t.Errorf("the secret stands in %q", l)
			}
		}
	}
	m := newMasker([]plan.Line{line})
	for in, out := range map[string]string{
		"error: invalid community ro": "error: invalid community <secret>",
		// the value after "community" is elided with its quotes since the
		// device-secret masking (lab 2026-10-13)
		`community "ro" is bad`:      `community <secret> is bad`,
		`a "ro" word`:                `a "<secret>" word`,
		"ro":                         "<secret>",
		"error: protocol error (ro)": "error: protocol error (<secret>)",
		"set snmp community ro authorization read-only": "set snmp community <secret> authorization read-only",
	} {
		if got := m.text(in); got != out {
			t.Errorf("%q -> %q, want %q", in, got, out)
		}
	}
}
