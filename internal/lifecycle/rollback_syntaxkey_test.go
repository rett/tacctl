package lifecycle

import (
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
)

// The key of the configuration syntax setting (docs/plans/0.2.18-plan.md
// D273): the rollback to 0.2.17, 0.2.16 and 0.2.9 writes devices.yaml's
// ios_syntax back as config_syntax, the value and every other key kept; a
// second run has nothing to do; the rollback to 0.2.3 removes the setting
// under either key.
func TestRollbackWritesTheSyntaxKeyBack(t *testing.T) {
	for _, target := range []string{RollbackTarget0217, RollbackTarget0216, RollbackTarget029} {
		s := newRBSandbox(t)
		s.in.Target = target
		before := s.snapshotOf()
		if !strings.Contains(before[s.p.DevicesFile], "    ios_syntax: modern") {
			t.Fatalf("the sandbox registry:\n%s", before[s.p.DevicesFile])
		}
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		st := stepText(p)
		for _, w := range []string{s.p.DevicesFile + ": write the configuration syntax setting under the key " + target + " reads (config_syntax)",
			"write ios_syntax of core-sw1 (modern) as config_syntax", "unknown key 'ios_syntax'"} {
			if !strings.Contains(st, w) {
				t.Errorf("%s: steps lack %q:\n%s", target, w, st)
			}
		}
		if !p.PendingFiles() {
			t.Errorf("%s: no file to convert", target)
		}
		if !reflect.DeepEqual(before, s.snapshotOf()) {
			t.Errorf("%s: planning wrote a file", target)
		}
		done, err := ApplyRollback(p)
		if err != nil || !strings.Contains(strings.Join(done, "\n"), "devices.yaml: wrote the configuration syntax of 1 device under config_syntax") {
			t.Fatalf("%s: apply: %q %v", target, done, err)
		}
		dv := s.snapshotOf()[s.p.DevicesFile]
		if strings.Contains(dv, "ios_syntax") || !strings.Contains(dv, "    config_syntax: modern") {
			t.Errorf("%s: devices.yaml:\n%s", target, dv)
		}
		// This release reads the result as it was.
		f, err := devreg.Load(s.p.DevicesFile)
		if err != nil || f.Find("core-sw1") == nil || f.Find("core-sw1").IOSSyntax != "modern" || len(f.Notes) != 0 {
			t.Errorf("%s: reread: %v %+v", target, err, f)
		}
		s.reload()
		s.in.Target = target
		p2, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if st := stepText(p2); !strings.Contains(st, "no device has a configuration syntax setting under ios_syntax") {
			t.Errorf("%s: second plan:\n%s", target, st)
		}
		snap := s.snapshotOf()
		if done, err := ApplyRollback(p2); err != nil || strings.Contains(strings.Join(done, "\n"), "configuration syntax") || s.snapshotOf()[s.p.DevicesFile] != snap[s.p.DevicesFile] {
			t.Errorf("%s: second apply: %q %v", target, done, err)
		}
	}

	// 0.2.3 removes the setting from a registry that holds the old key.
	s := newRBSandbox(t)
	s.oldSyntaxKey()
	s.in.Target = RollbackTarget
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stepText(p), "remove the ios_syntax key of core-sw1 (modern)") {
		t.Errorf("0.2.3 steps:\n%s", stepText(p))
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	if dv := s.snapshotOf()[s.p.DevicesFile]; strings.Contains(dv, "syntax") {
		t.Errorf("0.2.3: devices.yaml keeps a syntax key:\n%s", dv)
	}
}
