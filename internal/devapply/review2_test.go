package devapply

// The second safety review's findings.

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

// checkedT lets a stranger's 'commit check' confirm tacctl's pending commit
// right after it was committed, before the verification: typed in the held
// session behind the transport's back, as no other session may under the
// exclusive lock.
type checkedT struct {
	*JunosCLI
	revertErr error
}

func (c checkedT) CommitConfirmed(ctx context.Context, minutes int, id, user string) error {
	if err := c.JunosCLI.CommitConfirmed(ctx, minutes, id, user); err != nil {
		return err
	}
	c.mu.Lock()
	held := c.held
	c.mu.Unlock()
	_, err := held.Run(ctx, "commit check")
	return err
}

func (c checkedT) Revert(ctx context.Context, id string) error {
	if c.revertErr != nil {
		return c.revertErr
	}
	return c.JunosCLI.Revert(ctx, id)
}

// A stranger's 'commit check' before the verification: the change is
// applied by someone else only with the verification's proof.
func TestConfirmedBeforeVerifyNeedsProof(t *testing.T) {
	d := newDevice(t, nil)
	before := d.srv.Committed()
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = checkedT{JunosCLI: in.Transport.(*JunosCLI)}
	})
	wantExit(t, o, ExitAppliedByOther, ResultApplied)
	if !strings.Contains(o.Reason, "the fresh login's landed compare is the change the check showed") || !o.Until.IsZero() {
		t.Errorf("reason %q until %v", o.Reason, o.Until)
	}
	if indexOf(o.VerifyLog, plan.ApplyLandedCompare) < 0 || indexOf(o.Log, plan.ApplyConfirm(o.ID, "alice")) >= 0 {
		t.Errorf("log %q verify %q", o.Log, o.VerifyLog)
	}
	d.clk.Advance(11 * time.Minute)
	if d.srv.Committed() == before {
		t.Error("the change is not in place")
	}
}

// Without the proof the change is reverted in the held session.
func TestConfirmedBeforeVerifyRevertedWithoutProof(t *testing.T) {
	for _, c := range []struct {
		name   string
		verify func(d *device) func(context.Context) (Reader, error)
		why    string
	}{
		{"refused", func(*device) func(context.Context) (Reader, error) {
			return func(context.Context) (Reader, error) { return nil, fmt.Errorf("x: %w", devssh.ErrAuth) }
		}, "the fresh login was refused"},
		{"landed", func(d *device) func(context.Context) (Reader, error) {
			return func(ctx context.Context) (Reader, error) {
				r, err := d.verify(ctx)
				if err != nil {
					return nil, err
				}
				return landedT{r}, nil
			}
		}, "what landed is not the change the check showed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := newDevice(t, nil)
			before := d.srv.Committed()
			o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
				in.Transport = checkedT{JunosCLI: in.Transport.(*JunosCLI)}
				in.Verify = c.verify(d)
			})
			wantExit(t, o, ExitRolledBack, ResultRolledBack)
			if !strings.Contains(o.Reason, c.why) || !strings.Contains(o.Reason, "no confirmed commit was pending") {
				t.Errorf("reason %q", o.Reason)
			}
			if tail := []string{plan.ApplyRollback1, plan.ApplyCompare, plan.ApplyCancel(o.ID)}; !endsWith(o.Log, tail...) && !endsWith(o.Log, append(tail, showCommitShell)...) {
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

// A revert that cannot be done leaves the record pending, never applied.
func TestConfirmedBeforeVerifyRevertFails(t *testing.T) {
	d := newDevice(t, nil)
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = checkedT{JunosCLI: in.Transport.(*JunosCLI), revertErr: errors.New("refused")}
		in.Verify = func(context.Context) (Reader, error) { return nil, fmt.Errorf("x: %w", devssh.ErrAuth) }
	})
	wantExit(t, o, ExitPending, ResultPending)
	if !strings.Contains(o.Reason, "the revert: refused") || !strings.Contains(o.Reason, "no confirmed commit's banner stands") || o.Until.IsZero() {
		t.Errorf("reason %q until %v", o.Reason, o.Until)
	}
}

// Revert commits only the exact inverse, and only without a banner.
func TestRevertGuards(t *testing.T) {
	d := newDevice(t, nil)
	j := d.dial()
	defer func() { _ = j.Close() }()
	if err := j.Revert(context.Background(), "tacctl-x"); !errors.Is(err, ErrNotSent) {
		t.Errorf("no compare: %v", err)
	}
}

// stateR is a Reader with a fixed commit state.
type stateR struct {
	Reader
	st CommitState
}

func (s stateR) State(context.Context) (CommitState, error) { return s.st, nil }
func (s stateR) Log() []string                              { return nil }

// A stranger's pending commit over an entry that named tacctl's fate: the
// fate is reported, the stranger's commit too, and the record keeps the
// stranger's window.
func TestReconcileFateUnderStrangersBanner(t *testing.T) {
	id := "tacctl-20261013T140000Z-3f2a"
	ourC := CommitEntry{TimeText: "2026-10-13 14:00:00 UTC", User: "alice", Via: "cli", Comment: "tacctl apply " + id + " by alice", RollbackIn: 10}
	canc := CommitEntry{TimeText: "2026-10-13 14:01:00 UTC", User: "alice", Via: "cli", Comment: "tacctl apply cancel " + id}
	other := CommitEntry{TimeText: "2026-10-13 14:02:00 UTC", User: "bob", Via: "cli", RollbackIn: 5}
	now := testStart.Add(3 * time.Minute)
	r := stateR{st: CommitState{History: History{other, canc, ourC}, Pending: true, Minutes: 4}}
	o := ReconcileAt(context.Background(), r, "example-sw1", id, testStart.Add(10*time.Minute), now, nil)
	wantExit(t, o, ExitRolledBack, ResultRolledBack)
	if !strings.Contains(o.Reason, "cancelled at 2026-10-13 14:01:00 UTC") || !strings.Contains(o.Reason, "(by bob via cli at 2026-10-13 14:02:00 UTC) is pending for about 4 more minutes") {
		t.Errorf("reason %q", o.Reason)
	}
	if !o.Until.Equal(now.Add(5 * time.Minute)) {
		t.Errorf("until %v", o.Until)
	}
}

// The device secrets a compare may print: an SNMP trap group's name and
// the public keys of a login.
func TestDeviceSecretsTrapGroupAndKeys(t *testing.T) {
	m := &masker{}
	for in, out := range map[string]string{
		"trap-group zz-tg-name {":                                            "trap-group <secret> {",
		"[edit snmp trap-group zz-tg-name]":                                  "[edit snmp trap-group <secret>]",
		"set snmp trap-group zz-tg-name targets 192.0.2.5":                   "set snmp trap-group <secret> targets 192.0.2.5",
		`+    ssh-rsa "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABzz user@zzhost";`:     `+    ssh-rsa <secret>;`,
		`ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIzz";`:             `ssh-ed25519 <secret>;`,
		`ssh-ecdsa "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYzz";`: `ssh-ecdsa <secret>;`,
		"key ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQzz":          "key ecdsa-sha2-nistp384 <secret>",
	} {
		got := m.text(in)
		if got != out {
			t.Errorf("%q -> %q, want %q", in, got, out)
		}
		for _, s := range []string{"zz-tg-name", "AAAA", "zzhost"} {
			if strings.Contains(got, s) {
				t.Errorf("%q stands in %q", s, got)
			}
		}
	}
}

// noAreaSession never tells its prompt area: a device that does not echo
// the empty line typed ahead puts both prompts on one line.
type noAreaSession struct{ devssh.CLISession }

func (noAreaSession) PromptArea() ([]string, bool) { return nil, false }

func TestStateWithoutPromptArea(t *testing.T) {
	d := newDevice(t, nil)
	j := d.dial()
	defer func() { _ = j.Close() }()
	j.newShell = func() (devssh.CLISession, error) {
		s, err := j.client.CLI(devssh.VendorJuniper, devssh.WithMode(devssh.ModeShell))
		if err != nil {
			return nil, err
		}
		return noAreaSession{s}, nil
	}
	_, err := j.State(context.Background())
	if err == nil || !errors.Is(err, ErrUnrecognised) ||
		!strings.Contains(err.Error(), "did not echo the empty line typed ahead (both prompts on one line)") ||
		!strings.Contains(err.Error(), "apply cannot run on this device") {
		t.Errorf("%v", err)
	}
}
