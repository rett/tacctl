package lifecycle

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

func plan0218(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0218
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The rollback to 0.2.18 rewrites this release's per-tier drop-in with
// 0.2.18's (the engineer's rows of apply, enroll, collect, onboard, sync and
// support-bundle are taken out) and converts nothing else.
func TestPlanRollback0218PutsBackTheTiersDropIn(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	s.reload()
	before := s.snapshotOf()
	p := plan0218(t, s)
	if p.Target != RollbackTarget0218 || !p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Keys()) != 0 || len(p.Warnings) != 0 {
		t.Errorf("target %q pending %v files %v yes %v keys %q warnings %v", p.Target, p.Pending(), p.PendingFiles(), p.NeedsYes(), p.Keys(), p.Warnings)
	}
	st := stepText(p)
	for _, w := range []string{"put back the per-tier sudoers drop-in 0.2.18 writes", "rewrite " + s.p.TierSudoersFile,
		"the engineer's rules of 'device config apply', 'device enroll'", "nothing to remove (no emergency lockdown is recorded)",
		"leave every other file untouched", "formats 0.2.18 reads"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	if !reflect.DeepEqual(before, s.snapshotOf()) {
		t.Error("planning wrote a file")
	}
	done, err := ApplyRollback(p)
	if err != nil || len(done) != 1 || !strings.Contains(done[0], "rewritten with the text 0.2.18 writes") {
		t.Fatalf("apply: %q %v", done, err)
	}
	if got := s.snapshotOf()[s.p.TierSudoersFile]; got != tier.Sudoers0218() {
		t.Errorf("after the apply:\n%s", got)
	}
	if tier.Sudoers0218() == tier.Sudoers() {
		t.Error("0.2.18's text and this release's do not differ")
	}
	p = plan0218(t, s)
	if p.Pending() || !strings.Contains(stepText(p), "is already the text 0.2.18 writes") {
		t.Errorf("second plan:\n%s", stepText(p))
	}
	s.in.WithHosts = true
	if st := stepText(plan0218(t, s)); !strings.Contains(st, "0.2.19 changed nothing on the hosts; no host is synced") {
		t.Errorf("--hosts:\n%s", st)
	}
	for _, v := range []string{"0.2.18", "v0.2.18"} {
		if got, err := CheckRollbackVersion(v); err != nil || got != RollbackTarget0218 {
			t.Errorf("%s: %q %v", v, got, err)
		}
	}
}

// An edited drop-in is left, and an absent one is said to be absent.
func TestPlanRollback0218LeavesAnEditedDropIn(t *testing.T) {
	s := newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers()+"# local\n", 0o640)
	if p := plan0218(t, s); p.Pending() || !strings.Contains(stepText(p), "leaves "+s.p.TierSudoersFile) {
		t.Errorf("edited:\n%s", stepText(p))
	}
	s = newRBSandbox(t)
	if err := os.Remove(s.p.TierSudoersFile); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if p := plan0218(t, s); p.Pending() || !strings.Contains(stepText(p), "no per-tier drop-in is installed") {
		t.Errorf("absent:\n%s", stepText(p))
	}
}

// A lockdown record that locks nothing (a hand-edited one with no group) does
// not stop the rollback, and its keys, which every older schema refuses, are
// removed after a snapshot.
func TestPlanRollbackRemovesAPartialLockdownRecord(t *testing.T) {
	for _, target := range []string{RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		s.write(s.p.Overrides, rbConf+"emergency:\n  lockdown:\n    lab:\n      reason: drill\n", 0o640)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if got := strings.Join(p.Keys(), " "); !strings.HasSuffix(got, "emergency.lockdown.lab.reason") || !p.PendingFiles() {
			t.Errorf("%s: keys %q files %v", target, got, p.PendingFiles())
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if got := s.snapshotOf()[s.p.Overrides]; strings.Contains(got, "emergency") {
			t.Errorf("%s: tacctl.yaml after the apply:\n%s", target, got)
		}
	}
}

// The system blocks that hold statements 0.2.19 added are named in a warning
// for every target that has blocks; the files stay, and no text is shown.
func TestPlanRollbackWarnsOfBlocksWith0219Statements(t *testing.T) {
	for _, target := range []string{RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		old := filepath.Join(s.p.BlocksDir, "lab", "juniper", "system")
		s.write(old, "set system time-zone UTC\n", 0o600)
		fresh := filepath.Join(s.p.BlocksDir, "dc1", "juniper", "system")
		s.write(fresh, "set system syslog host 192.0.2.50 any notice\nabsent system services telnet\n", 0o600)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		var text string
		for _, w := range p.Warnings {
			text += w.Title + "\n" + strings.Join(w.Lines, "\n") + "\n"
		}
		for _, want := range []string{"System blocks use statements " + target + " does not know", "scope dc1, juniper system block: 2 statements", "The files stay in " + s.p.BlocksDir} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the warning lacks %q:\n%s", target, want, text)
			}
		}
		if strings.Contains(text, "scope lab") || strings.Contains(text, "192.0.2.50") || !p.NeedsYes() {
			t.Errorf("%s: the warning:\n%s", target, text)
		}
		before := s.snapshotOf()
		if _, err := ApplyRollback(p); err != nil {
			t.Fatal(err)
		}
		if got := s.snapshotOf(); got[fresh] != before[fresh] {
			t.Errorf("%s: the block file changed", target)
		}
	}
	// 0.2.3 does not read blocks at all.
	s := newRBSandbox(t)
	s.write(filepath.Join(s.p.BlocksDir, "dc1", "juniper", "system"), "set system syslog host 192.0.2.50 any notice\n", 0o600)
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w.Title, "System blocks") {
			t.Errorf("0.2.3 warns of blocks: %s", w.Title)
		}
	}
}
