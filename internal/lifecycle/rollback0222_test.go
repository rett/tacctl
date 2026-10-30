package lifecycle

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// The rollback to 0.2.22 on the sandbox of rollback_test.go: a state of this
// release is the 0.2.22 one, so the plan converts nothing.

func plan0222(t *testing.T, s *rbSandbox) *RollbackPlan {
	t.Helper()
	s.in.Target = RollbackTarget0222
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// The plan leaves every file, asks for no --yes, adds no scope to any user and
// rewrites no drop-in; a server name and a timing scale, which 0.2.22 has,
// stay. It writes nothing.
func TestPlanRollback0222ConvertsNothing(t *testing.T) {
	s := scaleState(t)
	s.write(s.p.Overrides, string(mustRead(t, s.p.Overrides))+"server:\n  addresses: [192.0.2.10]\n  name: core-1\n", 0o640)
	s.reload()
	before := s.snapshotOf()
	p := plan0222(t, s)
	if p.Target != RollbackTarget0222 {
		t.Errorf("target %q", p.Target)
	}
	st := stepText(p)
	for _, w := range []string{s.p.Overrides + ": remove the keys 0.2.22 does not know", "nothing to remove (every key of tacctl.yaml is one 0.2.22 knows)",
		"leave every other file untouched", "are in formats 0.2.22 reads"} {
		if !strings.Contains(st, w) {
			t.Errorf("steps lack %q:\n%s", w, st)
		}
	}
	for _, not := range []string{"remove device.", "remove server.", "remove timeout_scale", "add scope", "0.2.3", "0.2.9", "sudoers drop-in 0.2"} {
		if strings.Contains(st, not) {
			t.Errorf("steps name %q:\n%s", not, st)
		}
	}
	for _, step := range p.Steps {
		if step.Todo {
			t.Errorf("step %q does something", step.Title)
		}
	}
	if len(p.Keys()) != 0 || p.Pending() || p.PendingFiles() || p.NeedsYes() || len(p.Notes) != 0 || len(p.todoSudoers()) != 0 || len(p.managedUsers) != 0 {
		t.Errorf("keys %q pending %v yes %v notes %q sudoers %d managed %d", p.Keys(), p.Pending(), p.NeedsYes(), p.Notes, len(p.todoSudoers()), len(p.managedUsers))
	}
	if after := s.snapshotOf(); !reflect.DeepEqual(after, before) {
		t.Error("the plan wrote a file")
	}
}

// --hosts is accepted and says nothing is done.
func TestPlanRollback0222WithHosts(t *testing.T) {
	s := newRBSandbox(t)
	s.in.WithHosts = true
	p := plan0222(t, s)
	if st := stepText(p); !strings.Contains(st, "nothing to do for 0.2.22: this release changed nothing on the enrolled hosts") {
		t.Errorf("steps:\n%s", st)
	}
}

// RollbackUndoes is the order of the releases: a target undoes the change of
// a release that is newer than it, never its own or an older one.
func TestRollbackUndoes(t *testing.T) {
	for _, c := range []struct {
		target, release string
		want            bool
	}{
		{"0.2.21", "0.2.22", true}, {"0.2.3", "0.2.22", true}, {"0.2.9", "0.2.22", true}, {"0.2.16", "0.2.22", true},
		{"0.2.22", "0.2.22", false}, {"v0.2.22", "0.2.22", false}, {"0.2.22", "0.2.23", true},
		{"0.2.23", "0.2.22", false}, {"0.3.0", "0.2.22", false}, {"0.2.9", "0.2.10", true}, {"0.2.10", "0.2.9", false},
		{"", "0.2.22", false}, {"0.2.22", "x", false},
	} {
		if got := RollbackUndoes(c.target, c.release); got != c.want {
			t.Errorf("RollbackUndoes(%q, %q) = %v, want %v", c.target, c.release, got, c.want)
		}
	}
}

// A change registered once in the list of additions reaches the plan of every
// target older than its release, the ones that return early (0.2.22, 0.2.21,
// 0.2.20) included, and none newer: this is how a later release adds a step
// without touching the plan of a target. The entry here is of the next
// release, so it reaches all of them.
func TestPlanRollbackAdditionReachesEveryTarget(t *testing.T) {
	var reads, adds []string
	add := rollbackAddition{Release: "0.2.23",
		Read: func(p *RollbackPlan) error { reads = append(reads, p.target()); return nil },
		Add: func(p *RollbackPlan) {
			adds = append(adds, p.target())
			p.Steps = append(p.Steps, RollbackStep{Title: "the additional step of " + p.target(), Lines: []string{"added by a registered change"}})
			p.Notes = append(p.Notes, "a registered note")
		}}
	newer := rollbackAddition{Release: "0.2.22", // not for the 0.2.22 target itself
		Add: func(p *RollbackPlan) { p.Notes = append(p.Notes, "a change of 0.2.22") }}
	for _, target := range allRollbackTargets {
		t.Run(target, func(t *testing.T) {
			reads, adds = nil, nil
			s := newRBSandbox(t)
			s.in.Target = target
			p, err := planRollbackWith(s.in, []rollbackAddition{add, newer})
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reads, []string{target}) || !reflect.DeepEqual(adds, []string{target}) {
				t.Errorf("reads %q adds %q", reads, adds)
			}
			if st := stepText(p); !strings.Contains(st, "the additional step of "+target) || !strings.Contains(st, "added by a registered change") {
				t.Errorf("the registered step is missing:\n%s", st)
			}
			notes := strings.Join(p.Notes, "\n")
			if !strings.Contains(notes, "a registered note") {
				t.Errorf("notes:\n%s", notes)
			}
			if has := strings.Contains(notes, "a change of 0.2.22"); has != (target != RollbackTarget0222) {
				t.Errorf("the change of 0.2.22 reached %s: %v", target, has)
			}
		})
	}
}

// A Read that fails stops the plan with its error, for any target.
func TestPlanRollbackAdditionErrorStopsThePlan(t *testing.T) {
	boom := errors.New("cannot read the new file")
	for _, target := range allRollbackTargets {
		s := newRBSandbox(t)
		s.in.Target = target
		_, err := planRollbackWith(s.in, []rollbackAddition{{Release: "0.2.23", Read: func(*RollbackPlan) error { return boom }}})
		if !errors.Is(err, boom) {
			t.Errorf("%s: %v", target, err)
		}
	}
}

// The list the command uses holds the timing scale of 0.2.22 and nothing the
// 0.2.22 target would undo.
func TestRollbackAdditionsList(t *testing.T) {
	for _, a := range rollbackAdditions {
		if RollbackUndoes(RollbackTarget0222, a.Release) && a.Release == "0.2.22" {
			t.Errorf("the 0.2.22 target undoes a change of 0.2.22")
		}
		if releaseNumbers(a.Release) == nil || a.Read == nil && a.Add == nil {
			t.Errorf("entry %+v is not usable", a.Release)
		}
	}
}
