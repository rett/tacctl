package lifecycle

import (
	"strings"
	"testing"
)

// A break-glass entry of the Junos root account (0.2.20) is one every older
// schema accepts: every target keeps it in tacctl.yaml and warns, naming the
// scopes, what the older release renders for it and the command that removes
// it; --apply needs --yes. 0.2.3, which has no 'device config', is not told of
// the comparison.
func TestPlanRollbackWarnsOfTheRootBreakGlassEntry(t *testing.T) {
	withRoot := strings.Replace(rbConf, "    - bg-admin:admin\n", "    - bg-admin:admin\n    - root:admin\n  dmz:\n    users:\n    - root:admin\n", 1)
	if !strings.Contains(withRoot, "root:admin") {
		t.Fatal("the fixture lacks the entry")
	}
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		s.write(s.p.Overrides, withRoot, 0o640)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		var w string
		for _, x := range p.Warnings {
			if x.Title == "Scopes that record the Junos root account for break-glass" {
				w = strings.Join(x.Lines, "\n")
			}
		}
		for _, want := range []string{target + " has no break-glass entry for the Junos root account (0.2.20): scopes dmz, lab record 'root'",
			"so it stays in tacctl.yaml", "'set system login user root class ... authentication encrypted-password'", "'set system services ssh root-login allow'",
			"'username root privilege 15 ...'", "tacctl scope breakglass dmz remove root; tacctl scope breakglass lab remove root"} {
			if !strings.Contains(w, want) {
				t.Errorf("%s: the warning lacks %q:\n%s", target, want, w)
			}
		}
		if pull := strings.Contains(w, "'device config pull' and 'device config diff' expect"); pull != (target != RollbackTarget) {
			t.Errorf("%s: the comparison line %v:\n%s", target, pull, w)
		}
		if !p.NeedsYes() || strings.Contains(strings.Join(p.Keys(), " "), "breakglass") {
			t.Errorf("%s: yes %v keys %q", target, p.NeedsYes(), p.Keys())
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if got := s.snapshotOf()[s.p.Overrides]; !strings.Contains(got, "- root:admin") {
			t.Errorf("%s: the entry is gone:\n%s", target, got)
		}
	}
	// Without the entry, no warning.
	for _, target := range []string{RollbackTarget0219, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(warnText(p), "root account") {
			t.Errorf("%s: %s", target, warnText(p))
		}
	}
}
