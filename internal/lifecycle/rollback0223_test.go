package lifecycle

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// The rollback to 0.2.23 on the sandbox of rollback_test.go: 0.2.24 and this
// release changed no stored file 0.2.23 reads strictly but breakglass.firewall
// (rollback_firewall_test.go), so with that key unset the plan converts nothing
// but the per-tier drop-in (TestPlanRollback0223DropIn), whatever 0.2.23
// itself added to the state.

func plan0223(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0223
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The plan leaves every file, asks for no --yes, takes no snapshot, and keeps
// what 0.2.23 has and the older targets drop: the users' email addresses, a
// pool of SNMPv3 users, a staging entry marked covered. The per-tier drop-in is
// the one 0.2.23 wrote, so it is left too. It writes nothing.
func TestPlanRollback0223ConvertsNothing(t *testing.T) {
	s := poolState(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers0223(), 0o640)
	rbStoreEmail(t, s)
	s.write(s.p.StateDir+"/staging", stagingKept+stagingCovered, 0o600)
	before := s.snapshotOf()
	p := plan0223(t, s)
	if p.Target != RollbackTarget0223 {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.23 does not know", "nothing to remove (every key of tacctl.yaml is one 0.2.23 knows)",
		"leave every other file untouched", "are in formats 0.2.23 reads"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "email", "v3 user", "staging", "add scope", "0.2.3", "0.2.9", "sudoers drop-in 0.2"} {
		if strings.Contains(strings.ToLower(st), not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	for _, step := range p.Steps {
		if step.Todo {
			t.Errorf("step %q does something", step.Title)
		}
	}
	if len(p.Keys()) != 0 || p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Notes) != 0 || len(p.Warnings) != 0 ||
		len(p.todoSudoers()) != 0 || len(p.managedUsers) != 0 || len(p.EmailUsers()) != 0 || p.SNMPPoolDropped().Any() {
		t.Errorf("keys %q pending %v yes %v notes %q warnings %d sudoers %d managed %d email %q", p.Keys(), p.Pending(), p.NeedsYes(), p.Notes, len(p.Warnings), len(p.todoSudoers()), len(p.managedUsers), p.EmailUsers())
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the plan wrote a file")
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 {
		t.Errorf("apply: %q %v", done, err)
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the apply wrote a file")
	}
	if got := string(mustRead(t, s.p.TierSudoersFile)); got != tier.Sudoers0223() {
		t.Error("the per-tier drop-in was rewritten")
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0223WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0223(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.23: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}
