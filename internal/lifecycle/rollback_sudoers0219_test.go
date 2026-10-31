package lifecycle

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// The per-tier drop-in this release writes has the engineer's row of 'scope
// mgmt-acl * mode', which no older release has. The text 0.2.19 wrote, which
// lacks it, is an older text of this tool's: every target that rewrites the
// drop-in recognises it (as it does this release's), and puts back its own.
func TestRollbackRewritesTheDropInOf0219(t *testing.T) {
	for _, c := range []struct {
		target string
		want   func() string
	}{
		{RollbackTarget0218, tier.Sudoers0218},
		{RollbackTarget0217, tier.Sudoers0217},
		{RollbackTarget, tier.Sudoers023},
	} {
		for name, text := range map[string]string{"this release's": tier.Sudoers(), "0.2.19's": tier.Sudoers0219()} {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			s.write(s.p.TierSudoersFile, text, 0o640)
			s.reload()
			s.in.Target = c.target
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if st := stepText(p); !strings.Contains(st, "rewrite "+s.p.TierSudoersFile) {
				t.Errorf("%s, %s text: the drop-in is not rewritten:\n%s", c.target, name, st)
			}
			if _, err := ApplyRollback(p); err != nil {
				t.Fatalf("%s, %s text: %v", c.target, name, err)
			}
			if got := s.snapshotOf()[s.p.TierSudoersFile]; got != c.want() || strings.Contains(got, "scope mgmt-acl * mode") {
				t.Errorf("%s, %s text: after the apply:\n%s", c.target, name, got)
			}
		}
	}
}

// The per-tier drop-in this release writes has the engineer's row of 'device
// clone', which no older release has. The text 0.2.22 wrote, which lacks it,
// is an older text of this tool's too: every target that rewrites the drop-in
// recognises it, as it does this release's, and puts back its own (the
// targets that leave the file alone leave it).
func TestRollbackRewritesTheDropInOf0222(t *testing.T) {
	for _, c := range []struct {
		target string
		want   func() string
	}{
		{RollbackTarget0219, tier.Sudoers0219},
		{RollbackTarget0218, tier.Sudoers0218},
		{RollbackTarget0217, tier.Sudoers0217},
		{RollbackTarget, tier.Sudoers023},
	} {
		for name, text := range map[string]string{"this release's": tier.Sudoers(), "0.2.22's": tier.Sudoers0222()} {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			s.write(s.p.TierSudoersFile, text, 0o640)
			s.reload()
			s.in.Target = c.target
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if st := stepText(p); !strings.Contains(st, "rewrite "+s.p.TierSudoersFile) {
				t.Errorf("%s, %s text: the drop-in is not rewritten:\n%s", c.target, name, st)
			}
			if _, err := ApplyRollback(p); err != nil {
				t.Fatalf("%s, %s text: %v", c.target, name, err)
			}
			if got := s.snapshotOf()[s.p.TierSudoersFile]; got != c.want() || strings.Contains(got, "device clone") {
				t.Errorf("%s, %s text: after the apply:\n%s", c.target, name, got)
			}
		}
	}
	// The release before this one reads the file as it is: nothing is rewritten.
	s := newRBSandbox(t)
	s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
	s.reload()
	s.in.Target = RollbackTarget0222
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if st := stepText(p); strings.Contains(st, "rewrite "+s.p.TierSudoersFile) {
		t.Errorf("0.2.22: the drop-in is rewritten:\n%s", st)
	}
}
