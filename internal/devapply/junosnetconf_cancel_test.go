package devapply

// The NETCONF transport's cancel and revert (lab, plan N2): closing the held
// session does not roll a confirmed commit back, so Cancel does it, the way
// the command line's does, and Revert undoes a commit that something else
// confirmed first.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devssh"
)

// committedHeld drives the transport by hand to a pending confirmed commit
// of the reviewed change, in the held session, with its compare taken.
func committedHeld(t *testing.T, d *device) (*JunosNetconf, plan.Delta) {
	t.Helper()
	ctx := context.Background()
	rev := d.reviewed(&planner{desired: desiredLines()})
	j := d.dialNetconf(ModeAuto)
	t.Cleanup(func() { _ = j.Close() })
	if _, err := j.Login(ctx); err != nil {
		t.Fatal(err)
	}
	if err := j.Open(ctx, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	for _, l := range rev.Lines {
		if _, err := j.Load(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := j.Compare(ctx, rev); err != nil {
		t.Fatal(err)
	}
	if err := j.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if err := j.CommitConfirmed(ctx, 5, "tacctl-x", "alice"); err != nil {
		t.Fatal(err)
	}
	return j, rev
}

// Closing the held session leaves the commit pending; the window's end
// rolls it back, not the close (RollsBackOnClose is false).
func TestNetconfClosingTheHeldSessionIsNotACancel(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	before := d.srv.Committed()
	j, _ := committedHeld(t, d)
	if j.RollsBackOnClose() {
		t.Error("RollsBackOnClose")
	}
	_ = j.Close()
	time.Sleep(100 * time.Millisecond)
	if d.srv.Committed() == before {
		t.Fatal("rolled back by the close")
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Fatal("not pending after the close")
	}
	d.clk.Advance(6 * time.Minute)
	if d.srv.Committed() != before {
		t.Errorf("not rolled back at the window's end:\n%s", d.srv.Committed())
	}
}

// Cancel loads rollback 1, reads the compare, commits the inverse with the
// cancel's comment; the pending marker is gone and the configuration is the
// one before the change.
func TestNetconfCancelCommitsTheInverse(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	before := d.srv.Committed()
	j, _ := committedHeld(t, d)
	if err := j.Cancel(context.Background(), "tacctl-x"); err != nil {
		t.Fatal(err)
	}
	if d.srv.Committed() != before {
		t.Errorf("not back to the configuration before the change:\n%s", d.srv.Committed())
	}
	if _, p := d.srv.PendingUntil(); p {
		t.Error("still pending")
	}
	h := d.srv.History()
	if h[0].Comment != "tacctl apply cancel tacctl-x" || h[0].Confirmed {
		t.Errorf("history[0] %+v", h[0])
	}
	st, err := j.State(context.Background())
	if err != nil || st.Pending {
		t.Errorf("state %+v (%v)", st, err)
	}
	if !endsWithSub(j.Log(), "netconf: load-configuration rollback 1", plan.ApplyCompare, plan.ApplyCancel("tacctl-x")) {
		t.Errorf("log %q", j.Log())
	}
}

// After the device's own rollback 'rollback 1' loads the change itself;
// Cancel must commit nothing.
func TestNetconfCancelAfterTheWindowCommitsNothing(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	before := d.srv.Committed()
	j, _ := committedHeld(t, d)
	d.clk.Advance(6 * time.Minute) // the device's own rollback
	n := len(d.srv.History())
	err := j.Cancel(context.Background(), "tacctl-x")
	if !errors.Is(err, ErrUnrecognised) || !strings.Contains(err.Error(), "nothing was committed") {
		t.Fatalf("cancel: %v", err)
	}
	if d.srv.Committed() != before || len(d.srv.History()) != n {
		t.Errorf("something was committed: %d entries\n%s", len(d.srv.History()), d.srv.Committed())
	}
	if j.Held() {
		t.Error("the candidate was left")
	}
}

// A candidate that is not the exact inverse of the commit (here: the held
// compare is another one) is discarded and nothing is committed; the
// pending commit stays for the window.
func TestNetconfCancelRefusesWhatIsNotTheInverse(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	j, rev := committedHeld(t, d)
	// the held session's last compare is now the (empty) candidate against
	// the committed configuration: not the change the commit made
	if _, err := j.Compare(context.Background(), rev); err != nil {
		t.Fatal(err)
	}
	n := len(d.srv.History())
	err := j.Cancel(context.Background(), "tacctl-x")
	if !errors.Is(err, ErrUnrecognised) || !strings.Contains(err.Error(), "not the inverse") || !strings.Contains(err.Error(), "nothing was committed") {
		t.Fatalf("cancel: %v", err)
	}
	if len(d.srv.History()) != n {
		t.Error("something was committed")
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Error("the pending commit is gone")
	}
}

// Revert needs the pending marker to be absent: a commit that still
// stands is not committed over.
func TestNetconfRevertRefusesAPendingCommit(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	j, _ := committedHeld(t, d)
	n := len(d.srv.History())
	err := j.Revert(context.Background(), "tacctl-x")
	if !errors.Is(err, ErrUnrecognised) || !strings.Contains(err.Error(), "shows a pending commit") {
		t.Fatalf("revert: %v", err)
	}
	if len(d.srv.History()) != n {
		t.Error("something was committed")
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Error("the pending commit is gone")
	}
}

// checkedN lets a stranger's commit confirm tacctl's pending commit right
// after it was committed, before the verification (any session's commit
// confirms it over NETCONF too).
type checkedN struct {
	*JunosNetconf
}

func (c checkedN) CommitConfirmed(ctx context.Context, minutes int, id, user string) error {
	if err := c.JunosNetconf.CommitConfirmed(ctx, minutes, id, user); err != nil {
		return err
	}
	c.mu.Lock()
	held := c.held
	c.mu.Unlock()
	_, err := held.RPC(ctx, `<commit-configuration><check/></commit-configuration>`)
	return err
}

// Without the proof the change is reverted in the held session, as over the
// command line.
func TestNetconfConfirmedBeforeVerifyIsReverted(t *testing.T) {
	for _, c := range []struct {
		name   string
		verify func(d *device) func(context.Context) (Reader, error)
		why    string
	}{
		{"refused", func(*device) func(context.Context) (Reader, error) {
			return func(context.Context) (Reader, error) { return nil, fmt.Errorf("x: %w", devssh.ErrAuth) }
		}, "the fresh login was refused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := netDevice(t, nil, ModeAuto)
			before := d.srv.Committed()
			o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
				in.Transport = checkedN{JunosNetconf: in.Transport.(*JunosNetconf)}
				in.Verify = c.verify(d)
			})
			wantExit(t, o, ExitRolledBack, ResultRolledBack)
			if !strings.Contains(o.Reason, c.why) || !strings.Contains(o.Reason, "no confirmed commit was pending") {
				t.Errorf("reason %q", o.Reason)
			}
			if indexOf(o.Log, plan.ApplyCancel(o.ID)) < 0 {
				t.Errorf("log %q", o.Log)
			}
			if d.srv.Committed() != before {
				t.Errorf("not reverted:\n%s", d.srv.Committed())
			}
			if h := d.srv.History(); h[0].Comment != "tacctl apply cancel "+o.ID {
				t.Errorf("history %+v", h[0])
			}
		})
	}
}

// A stranger's commit before the verification: the change is applied by
// someone else only with the verification's proof.
func TestNetconfConfirmedBeforeVerifyNeedsProof(t *testing.T) {
	d := netDevice(t, nil, ModeAuto)
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = checkedN{JunosNetconf: in.Transport.(*JunosNetconf)}
	})
	wantExit(t, o, ExitAppliedByOther, ResultApplied)
	if !o.Until.IsZero() || indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice")) >= 0 {
		t.Errorf("until %v log %q", o.Until, o.Log)
	}
	d.clk.Advance(11 * time.Minute)
	if d.srv.Committed() == before {
		t.Error("the change is not in place")
	}
}

// endsWithSub reports whether the log holds the words, in order, ending the
// way the cancel does (the transport may log a word after them).
func endsWithSub(log []string, words ...string) bool {
	i := 0
	for _, l := range log {
		if i < len(words) && l == words[i] {
			i++
		}
	}
	return i == len(words)
}
