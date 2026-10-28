package lifecycle

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

func plan0219(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0219
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The rollback to 0.2.19 rewrites this release's per-tier drop-in with
// 0.2.19's (the engineer's row of 'scope mgmt-acl * mode' and the operator's
// rows of 'console system-shell' and 'console password-cache' are taken out)
// and converts nothing else in a state that has none of 0.2.20's keys.
func TestPlanRollback0219PutsBackTheTiersDropIn(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	s.reload()
	before := s.snapshotOf()
	p := plan0219(t, s)
	if p.Target != RollbackTarget0219 || !p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Keys()) != 0 || len(p.Warnings) != 0 {
		t.Errorf("target %q pending %v files %v yes %v keys %q warnings %v", p.Target, p.Pending(), p.PendingFiles(), p.NeedsYes(), p.Keys(), p.Warnings)
	}
	st := stepText(p)
	for _, w := range []string{"put back the per-tier sudoers drop-in 0.2.19 writes", "rewrite " + s.p.TierSudoersFile,
		"the engineer's rule of 'scope mgmt-acl * mode' and the operator's rules of 'console system-shell' and 'console password-cache' are taken out",
		"nothing to remove (no scope has a management filter mode)",
		"leave every other file untouched", "formats 0.2.19 reads", "an emergency lockdown and the break-glass entries stay"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("planning wrote a file")
	}
	done, err := ApplyRollback(p)
	if err != nil || len(done) != 1 || !strings.Contains(done[0], "rewritten with the text 0.2.19 writes") {
		t.Fatalf("apply: %q %v", done, err)
	}
	if got := s.snapshotOf()[s.p.TierSudoersFile]; got != tier.Sudoers0219() || strings.Contains(got, "scope mgmt-acl * mode") || strings.Contains(got, "console system-shell") {
		t.Errorf("after the apply:\n%s", got)
	}
	p = plan0219(t, s)
	if p.Pending() || !strings.Contains(stepText(p), "is already the text 0.2.19 writes") {
		t.Errorf("second plan:\n%s", stepText(p))
	}
	s.in.WithHosts = true
	if st := stepText(plan0219(t, s)); !strings.Contains(st, "0.2.20 changed nothing on the enrolled hosts") || !strings.Contains(st, "no host is synced") {
		t.Errorf("--hosts:\n%s", st)
	}
	for _, v := range []string{"0.2.19", "v0.2.19"} {
		if got, err := CheckRollbackVersion(v); err != nil || got != RollbackTarget0219 {
			t.Errorf("%s: %q %v", v, got, err)
		}
	}
	// An edited drop-in is left; the texts of the releases before are not
	// this release's and are left too (0.2.19's upgrade rewrites them).
	for name, text := range map[string]string{"edited": tier.Sudoers() + "# local\n", "0.2.18's": tier.Sudoers0218()} {
		s := newRBSandbox(t)
		s.write(s.p.TierSudoersFile, text, 0o640)
		if p := plan0219(t, s); p.Pending() || !strings.Contains(stepText(p), "leaves "+s.p.TierSudoersFile) {
			t.Errorf("%s:\n%s", name, stepText(p))
		}
	}
}

// 0.2.19 has the emergency lockdown record as this release writes it: a
// lockdown that stands does not refuse the rollback to 0.2.19, and the record,
// a partial one too, stays in tacctl.yaml. The blocks' statements of 0.2.19
// are its own: no warning.
func TestPlanRollback0219KeepsALockdown(t *testing.T) {
	for name, rec := range map[string]string{
		"standing": "emergency:\n  lockdown:\n    lab:\n      groups:\n        - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n",
		"partial":  "emergency:\n  lockdown:\n    lab:\n      reason: drill\n",
	} {
		s := newRBSandbox(t)
		s.write(s.p.Overrides, rbConf+rec, 0o640)
		s.write(filepath.Join(s.p.BlocksDir, "dc1", "juniper", "system"), "set system syslog host 192.0.2.50 any notice\nabsent system services telnet\n", 0o600)
		s.reload()
		p := plan0219(t, s)
		if len(p.Keys()) != 0 || p.PendingFiles() || p.NeedsYes() {
			t.Errorf("%s: keys %q files %v warnings %v", name, p.Keys(), p.PendingFiles(), p.Warnings)
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := s.snapshotOf()[s.p.Overrides]; got != rbConf+rec {
			t.Errorf("%s: tacctl.yaml after the apply:\n%s", name, got)
		}
	}
}

// The management filter mode is the one key of tacctl.yaml 0.2.19 does not
// know: it is removed after a snapshot, and the step says whose it is.
func TestPlanRollback0219RemovesTheModeOnly(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.Overrides, rbConf+rbStrictConf+"audit:\n  strict: true\n", 0o640)
	s.reload()
	p := plan0219(t, s)
	if got := strings.Join(p.Keys(), " "); got != "scope_mgmt_acl.mode.lab scope_mgmt_acl.mode.dmz" || !p.PendingFiles() || !p.NeedsYes() {
		t.Errorf("keys %q files %v yes %v", got, p.PendingFiles(), p.NeedsYes())
	}
	if st := stepText(p); !strings.Contains(st, "(the management filter mode of a scope is 0.2.20's; 0.2.19's schema refuses it") {
		t.Errorf("steps:\n%s", st)
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(s.p.Overrides)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(b); strings.Contains(got, "mode:") || !strings.Contains(got, "strict: true") || !strings.Contains(got, "10.0.0.0/8") {
		t.Errorf("tacctl.yaml after the apply:\n%s", got)
	}
}
