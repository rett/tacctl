package lifecycle

import (
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// A break-glass hold stops the rollback, in the dry run and the apply alike:
// the older release has no such record. Nothing is read further and nothing
// is changed.
func TestPlanRollbackRefusesWhileABreakGlassHoldStands(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+`breakglass_hold:
  sw-lab-1:
    address: 192.0.2.21
    since: '2026-10-10T14:02:00+00:00'
    by: alice
    reason: console recovery
  sw-lab-2:
    address: 198.51.100.7
    since: '2026-10-10T15:00:00+00:00'
    by: bob
    reason: another
`, 0o640)
	s.reload()
	before := s.snapshotOf()
	p, err := PlanRollback(s.in)
	var ref *RollbackRefusal
	if p != nil || !errors.As(err, &ref) {
		t.Fatalf("the plan was made: %v %v", p, err)
	}
	text := strings.Join(ref.Lines, "\n")
	for _, want := range []string{"Break-glass is held on sw-lab-1 (192.0.2.21, by alice since 2026-10-10 ",
		"Break-glass is held on sw-lab-2 (198.51.100.7, by bob since ",
		"0.2.3 has no such record: the device would stay unanswered until 0.2.3's first render and then be answered without anyone releasing it.",
		"Release it first: tacctl breakglass release sw-lab-1; tacctl breakglass release sw-lab-2. Nothing was changed."} {
		if !strings.Contains(text, want) {
			t.Errorf("the refusal lacks %q:\n%s", want, text)
		}
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("the refusal changed a file")
	}
	// Released, the same state plans as it did.
	s.write(s.p.Overrides, rbConf, 0o640)
	s.reload()
	if _, err := PlanRollback(s.in); err != nil {
		t.Errorf("without the hold: %v", err)
	}
}

// A record without an address silences nothing: it is a stray key, removed
// as one.
func TestPlanRollbackRemovesAHoldRecordWithoutAnAddress(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"breakglass_hold:\n  sw-lab-1:\n    by: alice\n", 0o640)
	s.reload()
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(p.Keys(), "breakglass_hold.sw-lab-1.by") {
		t.Errorf("keys %q", p.Keys())
	}
}
