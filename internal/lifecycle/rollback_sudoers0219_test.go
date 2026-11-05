package lifecycle

import (
	"reflect"
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

// The per-tier drop-in this release writes has the operator's row of 'log
// failures *' (the log filters), which 0.2.23 and no older release has. The
// text 0.2.23 wrote, which lacks it, is an older text of this tool's too:
// every target that rewrites the drop-in recognises it, as it does this
// release's, and puts back its own; the rollback to 0.2.23 puts back 0.2.23's
// text and leaves one it does not know (an edited file) and one that is
// 0.2.23's already.
func TestRollbackRewritesTheDropInOf0223(t *testing.T) {
	for _, c := range []struct {
		target string
		want   func() string
	}{
		{RollbackTarget0223, tier.Sudoers0223},
		{RollbackTarget0222, tier.Sudoers0222},
		{RollbackTarget0221, tier.Sudoers0222},
		{RollbackTarget0220, tier.Sudoers0222},
		{RollbackTarget0219, tier.Sudoers0219},
		{RollbackTarget0218, tier.Sudoers0218},
		{RollbackTarget0217, tier.Sudoers0217},
		{RollbackTarget, tier.Sudoers023},
	} {
		for name, text := range map[string]string{"this release's": tier.Sudoers(), "0.2.23's": tier.Sudoers0223()} {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			s.write(s.p.TierSudoersFile, text, 0o640)
			s.reload()
			s.in.Target = c.target
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			rewritten := strings.Contains(stepText(p), "rewrite "+s.p.TierSudoersFile)
			if want := text != c.want(); rewritten != want {
				t.Errorf("%s, %s text: rewritten %v:\n%s", c.target, name, rewritten, stepText(p))
			}
			if _, err := ApplyRollback(p); err != nil {
				t.Fatalf("%s, %s text: %v", c.target, name, err)
			}
			if got := s.snapshotOf()[s.p.TierSudoersFile]; got != c.want() {
				t.Errorf("%s, %s text: after the apply:\n%s", c.target, name, got)
			}
		}
	}
}

// The dry run of the rollback to 0.2.23 shows the step of the drop-in, --apply
// writes it, and a drop-in tacctl did not write (an edited file) is left, as
// every other target leaves it: the plan says so and writes nothing.
func TestPlanRollback0223DropIn(t *testing.T) {
	s := newRBSandbox(t)
	before := s.snapshotOf()
	p := plan0223(t, s)
	st := stepText(p)
	for _, w := range []string{"put back the per-tier sudoers drop-in 0.2.23 writes", "rewrite " + s.p.TierSudoersFile + " (0.2.23's text, after 'visudo -cf': the operator's rule of 'log failures *' is taken out)"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	if len(p.todoSudoers()) != 1 || !p.Pending() || p.PendingFiles() || p.NeedsYes() {
		t.Errorf("sudoers %d pending %v files %v yes %v", len(p.todoSudoers()), p.Pending(), p.PendingFiles(), p.NeedsYes())
	}
	if !reflect.DeepEqual(s.snapshotOf(), before) {
		t.Error("the plan wrote a file")
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 1 {
		t.Errorf("apply: %q %v", done, err)
	}
	if got := s.snapshotOf()[s.p.TierSudoersFile]; got != tier.Sudoers0223() || strings.Contains(got, "log failures *") {
		t.Errorf("the drop-in after the apply:\n%s", got)
	}

	// 0.2.23's text is done already; an edited file is left
	p = plan0223(t, s)
	if len(p.todoSudoers()) != 0 || strings.Contains(stepText(p), "put back the per-tier") {
		t.Errorf("0.2.23's own text is not left alone:\n%s", stepText(p))
	}
	s.write(s.p.TierSudoersFile, tier.Sudoers()+"# edited\n", 0o640)
	before = s.snapshotOf()
	p = plan0223(t, s)
	if len(p.todoSudoers()) != 0 || !strings.Contains(stepText(p), "leaves "+s.p.TierSudoersFile) {
		t.Errorf("an edited file is not reported as left:\n%s", stepText(p))
	}
	if done, err := ApplyRollback(p); err != nil || len(done) != 0 || !reflect.DeepEqual(s.snapshotOf(), before) {
		t.Errorf("an edited file was touched: %q %v", done, err)
	}
}
