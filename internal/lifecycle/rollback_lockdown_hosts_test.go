package lifecycle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// An emergency lockdown on a scope that has enrolled hosts stops the rollback
// to every target, the ones that take a lockdown over as it stands (0.2.19 to
// 0.2.22) included: the lockdown is an sshd drop-in on the hosts, which no
// older release removes, and its pending list is a leaf their schema refuses.
// A lockdown on a scope with no host is not stopped by this, and a lifted one
// that still waits for a host is. Nothing is changed.
func TestPlanRollbackRefusesALockdownWithHosts(t *testing.T) {
	standing := rbConf + "emergency:\n  lockdown:\n    lab:\n      groups:\n        - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      pending:\n        - web2\n"
	lifted := rbConf + "emergency:\n  lockdown:\n    lab:\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      pending:\n        - web1\n"
	hostsFile := "web1|admin@web1.example.net||lab|192.0.2.1|\nweb2|admin@web2.example.net||lab|192.0.2.1|\nweb3|admin@web3.example.net||dmz|192.0.2.1|\n"
	for _, target := range []string{RollbackTarget0222, RollbackTarget0221, RollbackTarget0220, RollbackTarget0219, RollbackTarget0218, RollbackTarget} {
		for name, rec := range map[string]string{"standing": standing, "lifted": lifted} {
			s := newRBSandbox(t)
			s.write(s.p.Overrides, rec, 0o640)
			s.write(s.p.LinuxHosts, hostsFile, 0o600)
			s.reload()
			s.in.Target = target // reload resets the input
			before := s.snapshotOf()
			p, err := PlanRollback(s.in)
			var ref *RollbackRefusal
			if p != nil || !errors.As(err, &ref) {
				t.Fatalf("%s, target %q: the plan was made: %v %v", name, target, p, err)
			}
			text := strings.Join(ref.Lines, "\n")
			if name == "standing" && (target == RollbackTarget0222 || target == RollbackTarget0221 || target == RollbackTarget0220 || target == RollbackTarget0219) {
				// the lockdown itself would be taken over: the hosts are the reason
				for _, want := range []string{"Scope lab is locked down and has enrolled hosts (web1, web2)", "cannot lift a lockdown on a host",
					"Lift it first and sync the hosts: tacctl emergency lockdown lab disable; tacctl host sync web1 web2. Nothing was changed."} {
					if !strings.Contains(text, want) {
						t.Errorf("%s, target %q: the refusal lacks %q:\n%s", name, target, want, text)
					}
				}
			}
			if name == "lifted" {
				for _, want := range []string{"A lockdown that was lifted still has its sshd drop-in on web1.", "tacctl host sync web1. Nothing was changed."} {
					if !strings.Contains(text, want) {
						t.Errorf("%s, target %q: the refusal lacks %q:\n%s", name, target, want, text)
					}
				}
			}
			if !reflect.DeepEqual(before, s.snapshotOf()) {
				t.Errorf("%s, target %q: the refusal changed a file", name, target)
			}
		}
	}
}

// With no host in the scope the record is as 0.2.22 reads it, and a lifted
// record whose hosts are gone is no reason: the targets that take a lockdown
// over do, as before.
func TestPlanRollbackLockdownWithoutHostsIsAsBefore(t *testing.T) {
	rec := rbConf + "emergency:\n  lockdown:\n    lab:\n      groups:\n        - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n"
	for _, target := range []string{RollbackTarget0222, RollbackTarget0221, RollbackTarget0220, RollbackTarget0219} {
		s := newRBSandbox(t)
		s.write(s.p.Overrides, rec, 0o640)
		s.write(s.p.LinuxHosts, "web3|admin@web3.example.net||dmz|192.0.2.1|\n", 0o600)
		s.reload()
		s.in.Target = target // reload resets the input
		if _, err := PlanRollback(s.in); err != nil {
			t.Errorf("target %q: %v", target, err)
		}
	}
}

// A list that names a host that is not enrolled any more is a leaf the older
// schema refuses: the rollback is refused too, with the command that drops it.
func TestPlanRollbackRefusesAListOfForgottenHosts(t *testing.T) {
	for name, tc := range map[string]struct{ rec, want string }{
		"standing": {"emergency:\n  lockdown:\n    lab:\n      groups:\n        - operator\n        - readonly\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      pending:\n        - gone\n",
			"Lift it first and sync the hosts: tacctl emergency lockdown lab enable operator,readonly. Nothing was changed."},
		"lifted": {"emergency:\n  lockdown:\n    lab:\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      pending:\n        - gone\n",
			"Lift it first and sync the hosts: tacctl emergency lockdown lab disable. Nothing was changed."},
	} {
		s := newRBSandbox(t)
		s.write(s.p.Overrides, rbConf+tc.rec, 0o640)
		s.reload()
		s.in.Target = RollbackTarget0222 // reload resets the input
		_, err := PlanRollback(s.in)
		var ref *RollbackRefusal
		if !errors.As(err, &ref) {
			t.Fatalf("%s: %v", name, err)
		}
		text := strings.Join(ref.Lines, "\n")
		for _, want := range []string{"names hosts that are not enrolled any more (gone)", tc.want} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the refusal lacks %q:\n%s", name, want, text)
			}
		}
	}
}
