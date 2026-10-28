package lifecycle

import (
	"errors"
	"os"
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
// '-' only. The store's users are
// listed with the command that fixes each; nothing is changed. An override
// of such a name in console.yaml (the ignored switch of a user) is not a
// reason to refuse: the plan takes it out (TestRollbackTakesOutDottedConsoleUsers).
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
			"Nothing was changed.",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("target %q: the refusal lacks %q:\n%s", target, want, text)
			}
		}
		for _, not := range []string{"bob", "dave", "carol.jones", "console"} {
			if strings.Contains(text, "  "+not+" ") {
				t.Errorf("target %q: the refusal lists %q:\n%s", target, not, text)
			}
		}
		if !reflect.DeepEqual(before, s.snapshotOf()) {
			t.Errorf("target %q: the refusal changed a file", target)
		}

		// Only the store has one.
		s.write(s.p.StoreFile, store, 0o600)
		s.write(s.p.ConsoleFile, "version: 1\nusers:\n  dave: disable\n", 0o600)
		_, err = PlanRollback(s.in)
		if !errors.As(err, &ref) || strings.Contains(strings.Join(ref.Lines, "\n"), "under users") {
			t.Errorf("target %q, store only: %v", target, err)
		}
		// Renamed, the same state plans as it did.
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

// An override of a user name with a period in console.yaml (0.2.19 and before
// wrote one for any name; 0.2.20 ignores it) is a key no release a rollback
// goes to reads: the plan says it removes the entry, the apply does, and every
// other switch of the file stays for the older release to read as it always
// did.
func TestRollbackTakesOutDottedConsoleUsers(t *testing.T) {
	const consoleDots = "version: 1\ntiers: {readonly: disable, operator: enable, engineer: enable, superuser: enable}\n" +
		"users: {carol.jones: enable, dave: disable, erin.king: disable}\nsettings: {idle_timeout: 12}\n"
	for _, target := range []string{RollbackTarget, RollbackTarget029, RollbackTarget0216, RollbackTarget0217, RollbackTarget0218} {
		s := newRBSandbox(t)
		s.in.Target = target
		s.write(s.p.ConsoleFile, consoleDots, 0o600)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		st := stepText(p)
		for _, w := range []string{"remove users.carol.jones: ignored override of a name with a period", "remove users.erin.king: ignored override of a name with a period"} {
			if !strings.Contains(st, w) {
				t.Errorf("%s: steps lack %q:\n%s", target, w, st)
			}
		}
		if strings.Contains(st, "users.dave") {
			t.Errorf("%s: a name without a period is removed:\n%s", target, st)
		}
		if !p.PendingFiles() {
			t.Errorf("%s: the console.yaml change is not a file to back up", target)
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		b, _ := os.ReadFile(s.p.ConsoleFile)
		got := string(b)
		for _, w := range []string{"readonly: disable", "dave: disable", "idle_timeout: 12"} {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q is gone:\n%s", target, w, got)
			}
		}
		if strings.Contains(got, "carol.jones") || strings.Contains(got, "erin.king") {
			t.Errorf("%s: a dotted name is left:\n%s", target, got)
		}
		// Done: a second plan has nothing to take out.
		s.reload()
		s.in.Target = target
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "users.") {
			t.Errorf("%s: second plan: %v\n%s", target, err, stepText(p))
		}
	}
}
