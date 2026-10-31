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
	// The releases that wrote 0.2.22's text (0.2.22, 0.2.21, 0.2.20) get it
	// back from this release's exact text, which loses the engineer's row of
	// 'device clone'; 0.2.22's text itself, and a text edited by hand, are
	// left.
	for _, target := range []string{RollbackTarget0222, RollbackTarget0221, RollbackTarget0220} {
		s := newRBSandbox(t)
		s.write(s.p.TierSudoersFile, tier.Sudoers(), 0o640)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if st := stepText(p); !strings.Contains(st, "rewrite "+s.p.TierSudoersFile) || !strings.Contains(st, "'device clone' is taken out") {
			t.Errorf("%s: the drop-in is not rewritten:\n%s", target, st)
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if got := s.snapshotOf()[s.p.TierSudoersFile]; got != tier.Sudoers0222() || strings.Contains(got, "device clone") {
			t.Errorf("%s: after the apply:\n%s", target, got)
		}
		for name, text := range map[string]string{"0.2.22's": tier.Sudoers0222(), "an edited": tier.Sudoers() + "# edited\n"} {
			s := newRBSandbox(t)
			s.write(s.p.TierSudoersFile, text, 0o640)
			s.reload()
			s.in.Target = target
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if st := stepText(p); strings.Contains(st, "rewrite "+s.p.TierSudoersFile) || len(p.todoSudoers()) != 0 {
				t.Errorf("%s, %s text: the drop-in is rewritten:\n%s", target, name, st)
			}
		}
	}
}
