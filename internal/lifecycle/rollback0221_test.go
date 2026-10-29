package lifecycle

import (
	"reflect"
	"strings"
	"testing"
)

// The rollback to 0.2.21 on the sandbox of rollback_test.go: a 0.2.22 state
// is the 0.2.21 one with server.name.

func plan0221(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0221
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The plan removes the server name and leaves everything else, asks for no
// --yes, adds no scope to any user and rewrites no drop-in; it writes nothing.
func TestPlanRollback0221RemovesTheServerName(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"server:\n  addresses: [192.0.2.10]\n  name: core-1\n", 0o640)
	s.reload()
	before := s.snapshotOf()
	p := plan0221(t, s)
	if p.Target != RollbackTarget0221 {
		t.Errorf("target %q", p.Target)
	}
	if got := p.Keys(); !reflect.DeepEqual(got, []string{"server.name"}) {
		t.Errorf("keys %q", got)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.21 does not know", "remove server.name", "the server name is 0.2.22's",
		"leave every other file untouched", "are in formats 0.2.21 reads"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"server.addresses", "add scope", "0.2.3", "0.2.9", "sudoers drop-in 0.2"} {
		if strings.Contains(st, not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	if !p.Pending() || !p.PendingFiles() || p.NeedsYes() || len(p.todoSudoers()) != 0 || len(p.managedUsers) != 0 {
		t.Errorf("pending %v files %v yes %v sudoers %d managed %d", p.Pending(), p.PendingFiles(), p.NeedsYes(), len(p.todoSudoers()), len(p.managedUsers))
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the plan wrote a file")
	}
}

// Without a server name there is nothing to remove.
func TestPlanRollback0221WithNoServerName(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"server:\n  addresses: [192.0.2.10]\n", 0o640)
	s.reload()
	p := plan0221(t, s)
	if len(p.Keys()) != 0 || p.Pending() || !strings.Contains(stepText(p), "nothing to remove (no server name or timeout scale is set)") {
		t.Errorf("keys %q pending %v:\n%s", p.Keys(), p.Pending(), stepText(p))
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0221WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0221(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.21: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}
