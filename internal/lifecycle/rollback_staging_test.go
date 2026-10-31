package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The staging entries marked covered (0.2.23) would make an older release
// take a real prefix out of a scope, so every target drops them from
// state/staging, the ones that return early included, and only them. The
// lines are derivable: the plan names them, asks for nothing (no warning, no
// --yes) and the snapshot --apply takes first holds the file.

const (
	stagingKept    = "192.0.2.80/32|lab|device|lab-sw1|2026-10-01 10:00\n192.0.2.9/32|lab|host|web1|2026-10-01 10:00\n"
	stagingCovered = "192.0.2.50/32|lab|device|lab-sw2|2026-10-02 11:00|covered\n"
)

func TestPlanRollbackEveryTargetDropsTheCoveredStagingEntries(t *testing.T) {
	for _, target := range allRollbackTargets {
		t.Run(target, func(t *testing.T) {
			s := newRBSandbox(t)
			s.oldSyntaxKey()
			path := filepath.Join(s.p.StateDir, "staging")
			s.write(path, stagingKept+stagingCovered, 0o600)
			s.in.Target = target
			p, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if !p.PendingFiles() || !p.Pending() {
				t.Errorf("files %v pending %v", p.PendingFiles(), p.Pending())
			}
			// no warning of its own, so no --yes for it (the 0.2.3 sandbox
			// needs one for other reasons)
			for _, w := range p.Warnings {
				if strings.Contains(strings.Join(w.Lines, " "), "192.0.2.50") {
					t.Errorf("warning %q", w.Title)
				}
			}
			if got := strings.Join(p.StagingCovered(), ";"); got != "192.0.2.50/32 (scope lab, device lab-sw2)" {
				t.Errorf("covered entries %q", got)
			}
			st := stepText(p)
			if !strings.Contains(st, path+": drop the staging entries of addresses a scope answers already") || !strings.Contains(st, "drop 192.0.2.50/32 (scope lab, device lab-sw2)") {
				t.Errorf("steps:\n%s", st)
			}
			if strings.Contains(st, "192.0.2.80") || strings.Contains(st, "web1") {
				t.Errorf("the plan names an entry that stays:\n%s", st)
			}
			if !strings.Contains(string(mustRead(t, path)), "|covered") {
				t.Fatal("the plan wrote a file")
			}
			done, err := ApplyRollback(p)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(done, "\n"), "dropped 1 staging entry") {
				t.Errorf("done %q", done)
			}
			if got := string(mustRead(t, path)); got != stagingKept {
				t.Errorf("staging after the apply:\n%s", got)
			}
			// idempotent: nothing is left to plan
			s.reload()
			p2, err := PlanRollback(s.in)
			if err != nil {
				t.Fatal(err)
			}
			if len(p2.StagingCovered()) != 0 || strings.Contains(stepText(p2), "staging entries") {
				t.Errorf("the second plan still has it:\n%s", stepText(p2))
			}
		})
	}
}

// A file with covered entries only is removed; a file without any is not
// touched, and the plan says nothing of staging.
func TestPlanRollbackStagingCoveredEdges(t *testing.T) {
	s := newRBSandbox(t)
	path := filepath.Join(s.p.StateDir, "staging")
	s.write(path, stagingCovered, 0o600)
	s.in.Target = RollbackTarget0222
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the file stays: %v", err)
	}

	s = newRBSandbox(t)
	s.write(filepath.Join(s.p.StateDir, "staging"), stagingKept, 0o600)
	for _, target := range allRollbackTargets {
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(stepText(p), "staging") {
			t.Errorf("%s names staging with no covered entry:\n%s", target, stepText(p))
		}
	}
}
