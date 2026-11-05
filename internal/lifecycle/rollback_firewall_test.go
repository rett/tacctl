package lifecycle

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The break-glass firewall in a plan (rollback_firewall.go): the key goes for
// every target (also 0.2.23 and 0.2.22, which read every other key), the step
// appears only when there is a rules file or a boot unit to remove, and
// ApplyRollback runs the command's seam once.

func TestPlanRollbackFirewall(t *testing.T) {
	for _, target := range []string{RollbackTarget0223, RollbackTarget0222, RollbackTarget0221, RollbackTarget0220, RollbackTarget0219,
		RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := poolState(t)
		s.write(s.p.Overrides, "breakglass:\n  firewall: drop\n", 0o600)
		s.in.Conf.Reload()
		s.write(s.p.FirewallRules, "table inet tacctl\n", 0o600)
		s.write(s.p.FirewallUnit, "[Unit]\n", 0o644)
		s.in.Target = target
		calls := 0
		s.in.RemoveFirewall = func() ([]string, error) { calls++; return []string{"the nftables table inet tacctl"}, nil }
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if !slices.Contains(p.Keys(), "breakglass.firewall") || !p.FirewallTodo() || !p.Pending() {
			t.Errorf("%s: keys %q firewall %v", target, p.Keys(), p.FirewallTodo())
		}
		if st := stepText(p); !strings.Contains(st, "the break-glass firewall: remove the nftables table, its rules file and its boot unit") ||
			!strings.Contains(st, "remove breakglass.firewall") {
			t.Errorf("%s: steps:\n%s", target, st)
		}
		if target == RollbackTarget0223 || target == RollbackTarget0222 {
			// they convert nothing else, but a key they refuse is a file to convert: a snapshot
			if !p.PendingFiles() {
				t.Errorf("%s: the key is a file to convert", target)
			}
		}
		done, err := ApplyRollback(p)
		if err != nil || calls != 1 {
			t.Fatalf("%s: calls %d %v", target, calls, err)
		}
		if !slices.ContainsFunc(done, func(d string) bool {
			return strings.Contains(d, "break-glass firewall: removed the nftables table inet tacctl; the nftables package stays")
		}) {
			t.Errorf("%s: done %q", target, done)
		}
		s.in.Conf.Reload()
		if _, ok := s.in.Conf.Value("breakglass.firewall"); ok {
			t.Errorf("%s: the key is left", target)
		}
	}
}

func TestPlanRollbackFirewallNothingToRemove(t *testing.T) {
	s := poolState(t)
	p := plan0223(t, s)
	if p.FirewallTodo() || strings.Contains(stepText(p), "firewall") {
		t.Errorf("a host without the firewall:\n%s", stepText(p))
	}
	// holds alone, no file: no table was ever loaded, so no step and no note
	s.write(s.p.Overrides, "breakglass_hold:\n  sw1:\n    address: 192.0.2.10\n    since: '2026-10-12T13:11:00+00:00'\n    by: alice\n    reason: x\n", 0o600)
	s.in.Conf.Reload()
	if p := plan0223(t, s); p.FirewallTodo() || len(p.Notes) != 0 {
		t.Errorf("holds without a table: %v %q", p.FirewallTodo(), p.Notes)
	}
}

func TestPlanRollbackFirewallNamesTheHoldsThatStand(t *testing.T) {
	s := poolState(t)
	s.write(s.p.Overrides, "breakglass_hold:\n  sw1:\n    address: 192.0.2.10\n    since: '2026-10-12T13:11:00+00:00'\n    by: alice\n    reason: x\n", 0o600)
	s.in.Conf.Reload()
	s.write(s.p.FirewallRules, "table inet tacctl\n", 0o600)
	p := plan0223(t, s)
	if !p.FirewallTodo() || !slices.Equal(p.FirewallHolds(), []string{"sw1 (192.0.2.10)"}) ||
		!slices.ContainsFunc(p.Notes, func(n string) bool { return strings.Contains(n, "hold of sw1 (192.0.2.10) stands") }) {
		t.Errorf("%v %q %q", p.FirewallTodo(), p.FirewallHolds(), p.Notes)
	}
	// without the seam the step is listed and nothing runs
	if done, err := ApplyRollback(p); err != nil || slices.ContainsFunc(done, func(d string) bool { return strings.Contains(d, "firewall") }) {
		t.Errorf("done %q %v", done, err)
	}
	// a seam that fails stops the rollback with the error, after saying what went
	s.in.RemoveFirewall = func() ([]string, error) {
		return []string{"the nftables table inet tacctl"}, errors.New("systemctl daemon-reload failed")
	}
	p = plan0223(t, s)
	done, err := ApplyRollback(p)
	if err == nil || !strings.Contains(err.Error(), "daemon-reload") || len(done) == 0 {
		t.Errorf("done %q err %v", done, err)
	}
}
