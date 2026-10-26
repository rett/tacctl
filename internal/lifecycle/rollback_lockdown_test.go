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
