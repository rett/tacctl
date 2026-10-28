package devapply

import (
	"strings"
	"testing"
)

// A virtual chassis of four members (two EX4600 and two EX4300, one host
// name) that commits with synchronize: 'show version' has a block for each,
// 'commit check' and the commits print one for each member, the login
// banner carries the build line, and the prompt line is '{master:0}'.
func chassisKnobs() map[string]string {
	return map[string]string{
		"chassis":            "fpc0 ex4600-40f 18.1R3-S6.1\nfpc1 ex4600-40f 21.4R3-S1.5\nfpc2 ex4300-48t\nfpc3 ex4300-48t\n",
		"device":             "hostname example-sw1\nmodel ex4600-40f\njunos 21.4R3-S2.4\n",
		"banner":             "--- JUNOS 21.4R3-S2.4 built 2022-12-09 14:32:20 UTC\n",
		"commit.synchronize": "",
	}
}

// The whole apply runs against the chassis on both transports: the
// pre-flight, the check, the confirmed commit, the verification, the
// confirm; and the next run starts from a history that ends in 'commit
// synchronize'.
func TestApplyOnAVirtualChassis(t *testing.T) {
	both(t, chassisKnobs(), func(t *testing.T, d *device) {
		p := &planner{desired: desiredLines()}
		o := apply(t, d, p, nil)
		wantExit(t, o, ExitApplied, ResultApplied)
		if o.Identity.Hostname != "example-sw1" || o.Identity.Model != "ex4600-40f" || o.Identity.Release != "21.4R3-S2.4" {
			t.Errorf("identity %+v", o.Identity)
		}
		if h := d.srv.History(); len(h) < 3 || strings.Join(h[0].Options, " ") != "synchronize" {
			t.Errorf("history %+v", h[:2])
		}
		o = apply(t, d, p, nil)
		wantExit(t, o, ExitNoChange, ResultNoChange)
	})
}

// A member whose check is anything but the success stops the apply before
// anything is committed, and the reason names the member and its text.
func TestApplyOnAVirtualChassisMemberRefuses(t *testing.T) {
	knobs := chassisKnobs()
	knobs["chassis.check"] = "fpc2 => warning: member is out of sync\n"
	both(t, knobs, func(t *testing.T, d *device) {
		before := d.srv.Committed()
		o := apply(t, d, &planner{desired: desiredLines()}, nil)
		if o.Exit == ExitApplied || o.Exit == ExitPending {
			t.Fatalf("exit %s: %s", o.Exit, o.Line())
		}
		if !strings.Contains(o.Reason, "member fpc2") {
			t.Errorf("the reason does not name the member: %q", o.Reason)
		}
		if d.srv.Committed() != before {
			t.Error("committed")
		}
		if _, pending := d.srv.PendingUntil(); pending || d.srv.ExclusiveHolder() != "" {
			t.Error("pending or locked")
		}
	})
}

// A commit that is made while a member answers it with something else than
// 'commit complete' (or, over NETCONF, with no success) is not taken for an
// applied change: the apply cancels it, names the member, and the device is
// rolled back.
func TestApplyOnAVirtualChassisMemberOddCommit(t *testing.T) {
	knobs := chassisKnobs()
	knobs["chassis.commit"] = "fpc1 => warning: the member is behind\n"
	both(t, knobs, func(t *testing.T, d *device) {
		o := apply(t, d, &planner{desired: desiredLines()}, nil)
		wantExit(t, o, ExitRolledBack, ResultRolledBack)
		if !strings.Contains(o.Reason, "member fpc1") {
			t.Errorf("the reason does not name the member: %q", o.Reason)
		}
	})
}
