package lifecycle

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

func plan0217(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0217
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The rollback to 0.2.17 (docs/plans/0.2.18-plan.md D273 to D275) rewrites
// this release's per-tier drop-in with 0.2.17's (the old verb names' rules)
// and converts nothing else: audit.strict and the
// registry stay, and no snapshot is needed.
func TestPlanRollback0217PutsBackTheTiersDropIn(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+"audit:\n  strict: true\n", 0o640)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	s.oldSyntaxKey()
	s.reload()
	before := s.snapshotOf()
	p := plan0217(t, s)
	if p.Target != RollbackTarget0217 || !p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Keys()) != 0 || len(p.Notes) != 0 {
		t.Errorf("target %q pending %v files %v yes %v keys %q notes %q", p.Target, p.Pending(), p.PendingFiles(), p.NeedsYes(), p.Keys(), p.Notes)
	}
	st := stepText(p)
	for _, w := range []string{"put back the per-tier sudoers drop-in 0.2.17 writes", "rewrite " + s.p.TierSudoersFile,
		"the rules of 'device ios-syntax', 'device notice list' and 'device client-config' become 0.2.17's 'device config-syntax', 'device notices' and 'device ssh-config'", "leave every other file untouched",
		"formats 0.2.17 reads (0.2.18 changed none of them, and 0.2.19 none but the blocks"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	if strings.Contains(st, "audit.strict") || strings.Contains(st, "0.2.3") {
		t.Errorf("steps:\n%s", st)
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("planning wrote a file")
	}
	done, err := ApplyRollback(p)
	if err != nil || len(done) != 1 || !strings.Contains(done[0], "rewritten with the text 0.2.17 writes") {
		t.Fatalf("apply: %q %v", done, err)
	}
	after := s.snapshotOf()
	if after[s.p.TierSudoersFile] != tier.Sudoers0217() || after[s.p.Overrides] != before[s.p.Overrides] {
		t.Errorf("after the apply:\n%s", after[s.p.TierSudoersFile])
	}
	// Again: nothing left to do.
	p = plan0217(t, s)
	if p.Pending() || !strings.Contains(stepText(p), "is already the text 0.2.17 writes") {
		t.Errorf("second plan:\n%s", stepText(p))
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 {
		t.Errorf("second apply: %q %v", done, err)
	}
	s.in.WithHosts = true
	if st := stepText(plan0217(t, s)); !strings.Contains(st, "0.2.18 changed nothing on the hosts; no host is synced") {
		t.Errorf("--hosts:\n%s", st)
	}
	if v, err := CheckRollbackVersion("v0.2.17"); err != nil || v != RollbackTarget0217 {
		t.Errorf("v0.2.17: %q %v", v, err)
	}
}

// An edited drop-in is left, and an absent one is said to be absent.
func TestPlanRollback0217LeavesAnEditedDropIn(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers()+"# local\n", 0o640)
	s.oldSyntaxKey()
	if p := plan0217(t, s); p.Pending() || !strings.Contains(stepText(p), "leaves "+s.p.TierSudoersFile) {
		t.Errorf("edited:\n%s", stepText(p))
	}
	s = newRBSandbox(t)
	s.oldSyntaxKey()
	if err := os.Remove(s.p.TierSudoersFile); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if p := plan0217(t, s); p.Pending() || !strings.Contains(stepText(p), "no per-tier drop-in is installed") {
		t.Errorf("absent:\n%s", stepText(p))
	}
}
