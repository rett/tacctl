package lifecycle

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// The rollback to 0.2.24 on the sandbox of rollback_test.go: this release
// changed no stored file, so the plan converts nothing, whatever 0.2.24 itself
// added to the state (the break-glass firewall included).

func plan0224(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0224
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The plan leaves every file, asks for no --yes, takes no snapshot, and keeps
// what 0.2.24 has and the older targets drop: the users' email addresses, a
// pool of SNMPv3 users, a staging entry marked covered, the break-glass
// firewall (its setting, its rules file and its boot unit). The per-tier
// drop-in is the same text in both releases, so it is left too. It writes
// nothing.
func TestPlanRollback0224ConvertsNothing(t *testing.T) {
	s := poolState(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	rbStoreEmail(t, s)
	s.write(s.p.StateDir+"/staging", stagingKept+stagingCovered, 0o600)
	s.write(s.p.Overrides, "breakglass:\n  firewall: drop\n", 0o600)
	s.in.Conf.Reload()
	s.write(s.p.FirewallRules, "table inet tacctl\n", 0o600)
	s.write(s.p.FirewallUnit, "[Unit]\n", 0o644)
	calls := 0
	s.in.RemoveFirewall = func() ([]string, error) { calls++; return []string{"the nftables table inet tacctl"}, nil }
	before := s.snapshotOf()
	p := plan0224(t, s)
	if p.Target != RollbackTarget0224 {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.24 does not know", "nothing to remove (every key of tacctl.yaml is one 0.2.24 knows)",
		"leave every other file untouched", "are in formats 0.2.24 reads"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "remove breakglass", "firewall: remove", "email", "v3 user", "staging", "add scope", "0.2.3", "0.2.9", "sudoers drop-in 0.2"} {
		if strings.Contains(strings.ToLower(st), not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	for _, step := range p.Steps {
		if step.Todo {
			t.Errorf("step %q does something", step.Title)
		}
	}
	if len(p.Keys()) != 0 || p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Notes) != 0 || len(p.Warnings) != 0 || p.FirewallTodo() ||
		len(p.todoSudoers()) != 0 || len(p.managedUsers) != 0 || len(p.EmailUsers()) != 0 || p.SNMPPoolDropped().Any() {
		t.Errorf("keys %q pending %v yes %v notes %q warnings %d sudoers %d managed %d email %q", p.Keys(), p.Pending(), p.NeedsYes(), p.Notes, len(p.Warnings), len(p.todoSudoers()), len(p.managedUsers), p.EmailUsers())
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the plan wrote a file")
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 || calls != 0 {
		t.Errorf("apply: %q %v (firewall removed %d times)", done, err, calls)
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the apply wrote a file")
	}
	if got := string(mustRead(t, s.p.TierSudoersFile)); got != tier.Sudoers() {
		t.Error("the per-tier drop-in was rewritten")
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0224WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0224(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.24: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}

// A device whose apply is not settled refuses the target, as it does every
// other (the dry run too).
func TestPlanRollback0224RefusesAnUnsettledApply(t *testing.T) {
	s := newRBSandbox(t)
	s.in.Target = RollbackTarget0224
	s.write(s.p.ConfigRecords, `{"version": 1, "devices": {
 "sw1": {"address": "192.0.2.11", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "via": "netconf"}}}}
`, 0o600)
	if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "sw1") {
		t.Errorf("an unsettled apply was not refused: %v", err)
	}
}
