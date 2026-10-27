package lifecycle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// An emergency lockdown stops the rollback to every target, in the dry run
// and the apply alike: no older release has the record. Nothing is changed.
func TestPlanRollbackRefusesWhileALockdownStands(t *testing.T) {
	for _, target := range []string{RollbackTarget, RollbackTarget029, RollbackTarget0216, RollbackTarget0217, RollbackTarget0218} {
		s := newRBSandbox(t)
		s.in.Target = target
		s.write(s.p.Overrides, rbConf+`emergency:
  lockdown:
    lab:
      groups:
        - operator
        - readonly
      since: '2026-10-25T12:00:00+00:00'
      by: alice
      reason: drill
`, 0o640)
		s.reload()
		before := s.snapshotOf()
		p, err := PlanRollback(s.in)
		var ref *RollbackRefusal
		if p != nil || !errors.As(err, &ref) {
			t.Fatalf("target %q: the plan was made: %v %v", target, p, err)
		}
		text := strings.Join(ref.Lines, "\n")
		for _, want := range []string{"Scope lab is locked down (groups operator, readonly, by alice since 2026-10-25 ",
			"Every older release lacks the record", "Lift it first: tacctl emergency lockdown lab disable. Nothing was changed."} {
			if !strings.Contains(text, want) {
				t.Errorf("target %q: the refusal lacks %q:\n%s", target, want, text)
			}
		}
		if !reflect.DeepEqual(before, s.snapshotOf()) {
			t.Errorf("target %q: the refusal changed a file", target)
		}
		// lifted, the same state plans as it did
		s.write(s.p.Overrides, rbConf, 0o640)
		s.reload()
		if _, err := PlanRollback(s.in); err != nil {
			t.Errorf("target %q, without the lockdown: %v", target, err)
		}
	}
}

// A user name with a period (0.2.20) stops the rollback to every target, in
// the dry run and the apply alike: each of them reads letters, digits, '_' and
// '-' only. The store's users and the keys under users in console.yaml are
// listed with the command that fixes each; nothing is changed.
func TestRollbackRefusesDottedUsers(t *testing.T) {
	const store = "version: 1\nusers:\n  alice.smith:\n    group: operator\n  bob:\n    group: operator\n  a.b-c_d:\n    group: operator\n"
	const consoleDots = "version: 1\nusers:\n  carol.jones: enable\n  dave: disable\n"
	for _, target := range []string{RollbackTarget, RollbackTarget029, RollbackTarget0216, RollbackTarget0217, RollbackTarget0218} {
		s := newRBSandbox(t)
		s.in.Target = target
		s.write(s.p.StoreFile, store, 0o600)
		s.write(s.p.ConsoleFile, consoleDots, 0o600)
		before := s.snapshotOf()
		p, err := PlanRollback(s.in)
		var ref *RollbackRefusal
		if p != nil || !errors.As(err, &ref) {
			t.Fatalf("target %q: the plan was made: %v %v", target, p, err)
		}
		text := strings.Join(ref.Lines, "\n")
		for _, want := range []string{
			"The store has 2 users whose name has a period",
			"  a.b-c_d   (tacctl user rename a.b-c_d <new-name>)",
			"  alice.smith   (tacctl user rename alice.smith <new-name>)",
			s.p.ConsoleFile + " has 1 override under users for a name with a period",
			"  carol.jones   (tacctl console user carol.jones clear)",
			"Nothing was changed.",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("target %q: the refusal lacks %q:\n%s", target, want, text)
			}
		}
		for _, not := range []string{"bob", "dave"} {
			if strings.Contains(text, "  "+not+" ") {
				t.Errorf("target %q: the refusal lists %q:\n%s", target, not, text)
			}
		}
		if !reflect.DeepEqual(before, s.snapshotOf()) {
			t.Errorf("target %q: the refusal changed a file", target)
		}

		// Only the console file has one: still refused, no store line.
		s.write(s.p.StoreFile, "version: 1\nusers:\n  bob:\n    group: operator\n", 0o600)
		_, err = PlanRollback(s.in)
		if !errors.As(err, &ref) || strings.Contains(strings.Join(ref.Lines, "\n"), "The store has") ||
			!strings.Contains(strings.Join(ref.Lines, "\n"), "carol.jones") {
			t.Errorf("target %q, console only: %v", target, err)
		}
		// Only the store has one.
		s.write(s.p.StoreFile, store, 0o600)
		s.write(s.p.ConsoleFile, "version: 1\nusers:\n  dave: disable\n", 0o600)
		_, err = PlanRollback(s.in)
		if !errors.As(err, &ref) || strings.Contains(strings.Join(ref.Lines, "\n"), "under users") {
			t.Errorf("target %q, store only: %v", target, err)
		}
		// Renamed and cleared, the same state plans as it did.
		s.write(s.p.StoreFile, "version: 1\nusers:\n  alice-smith:\n    group: operator\n  bob:\n    group: operator\n", 0o600)
		if _, err := PlanRollback(s.in); err != nil {
			t.Errorf("target %q, without dotted names: %v", target, err)
		}
		// A store that cannot be read cannot be ruled out: an error, not a plan.
		s.write(s.p.StoreFile, "users: [\n", 0o600)
		if p, err := PlanRollback(s.in); p != nil || err == nil || errors.As(err, &ref) ||
			!strings.Contains(err.Error(), "cannot be read, so a user name with a period cannot be ruled out") {
			t.Errorf("target %q, unreadable store: %v %v", target, p, err)
		}
	}
	// An install with no store has no store users to look at.
	s := newRBSandbox(t)
	s.in.HasStore = false
	s.in.Target = RollbackTarget0218
	if _, err := PlanRollback(s.in); err != nil {
		t.Errorf("no store: %v", err)
	}
}
