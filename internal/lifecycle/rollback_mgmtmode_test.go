package lifecycle

import (
	"strings"
	"testing"
)

const rbStrictConf = "scope_mgmt_acl:\n  permits:\n    lab:\n    - 10.0.0.0/8\n  mode:\n    lab: strict\n    dmz: strict\n"

// The management filter mode of a scope (0.2.20) is a key every older schema
// refuses: every target removes it after a snapshot, warns which scopes were
// strict and what the older release's plan will do for them, keeps the other
// keys of the same family, and does not refuse the rollback (the precedent is
// the warning about the system blocks of 0.2.19, not the refusal of a
// lockdown, which would have been put back by the next render).
func TestPlanRollbackRemovesTheMgmtACLModeAndWarns(t *testing.T) {
	for _, target := range []string{RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.oldSyntaxKey()
		s.write(s.p.Overrides, rbConf+rbStrictConf, 0o640)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: refused: %v", target, err)
		}
		keys := strings.Join(p.Keys(), " ")
		if !strings.Contains(keys, "scope_mgmt_acl.mode.lab") || !strings.Contains(keys, "scope_mgmt_acl.mode.dmz") || strings.Contains(keys, "scope_mgmt_acl.permits") || !p.PendingFiles() {
			t.Errorf("%s: keys %q files %v", target, keys, p.PendingFiles())
		}
		var w string
		for _, x := range p.Warnings {
			if x.Title == "Scopes with a strict management filter lose the mode" {
				w = strings.Join(x.Lines, "\n")
			}
		}
		for _, want := range []string{target + " has no management filter mode (0.2.20)", "scopes dmz, lab are strict", "default-accept term",
			"stays in the snapshot --apply takes first", "keeps it: nothing here contacts a device", "would put the ssh-only filter back",
			"To stay deny by default, keep this release"} {
			if !strings.Contains(w, want) {
				t.Errorf("%s: the warning lacks %q:\n%s", target, want, w)
			}
		}
		st := stepText(p)
		if !strings.Contains(st, "remove scope_mgmt_acl.mode.lab") {
			t.Errorf("%s: the steps do not remove the key:\n%s", target, st)
		}
		if strings.Contains(st, "no release knows this key") || strings.Contains(st, "emergency lockdown is 0.2.19's") {
			t.Errorf("%s: the steps describe the key wrongly:\n%s", target, st)
		}
		if (target == RollbackTarget0218 || target == RollbackTarget0217) && !strings.Contains(st, "the management filter mode of a scope is 0.2.20's") {
			t.Errorf("%s: the steps do not say whose the key is:\n%s", target, st)
		}
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		got := s.snapshotOf()[s.p.Overrides]
		if strings.Contains(got, "mode:") || strings.Contains(got, "strict") || !strings.Contains(got, "10.0.0.0/8") {
			t.Errorf("%s: tacctl.yaml after the apply:\n%s", target, got)
		}
		// the second plan has nothing to remove and nothing to warn of
		s.reload()
		p, err = PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range p.Warnings {
			if strings.Contains(x.Title, "management filter") {
				t.Errorf("%s: warns again: %v", target, x)
			}
		}
	}
}

// A scope that is ssh-only (no key, or the word written by hand) is no
// warning, and neither is a list with no mode.
func TestPlanRollbackSaysNothingOfASSHOnlyScope(t *testing.T) {
	for _, conf := range []string{"scope_mgmt_acl:\n  permits:\n    lab:\n    - 10.0.0.0/8\n", "scope_mgmt_acl:\n  mode:\n    lab: ssh-only\n"} {
		for _, target := range []string{RollbackTarget0218, RollbackTarget} {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			s.write(s.p.Overrides, rbConf+conf, 0o640)
			s.reload()
			s.in.Target = target
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			for _, x := range p.Warnings {
				if strings.Contains(x.Title, "management filter") {
					t.Errorf("%s, %q: %v", target, conf, x)
				}
			}
		}
	}
}
