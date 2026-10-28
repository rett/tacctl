package lifecycle

import (
	"os"
	"strings"
	"testing"
)

// The colour setting and a list_max of -1 (0.2.20) are rejected by the
// console.yaml reader of every release a rollback goes to: each target's plan
// takes them out, keeps every other setting (the password cache included, for
// the targets that have it), says so, and leaves the file alone when it has
// neither.
func TestRollbackTakesOutTheConsoleSettingsOf0220(t *testing.T) {
	consoleWith := strings.NewReplacer("  list_max: 40\n", "  list_max: -1\n", "  space_completion: false\n", "  space_completion: false\n  color: true\n").Replace(rbConsole)
	if !strings.Contains(consoleWith, "color: true") || !strings.Contains(consoleWith, "list_max: -1") {
		t.Fatal("the fixture lacks the settings")
	}
	for _, target := range []string{RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.in.Target = target
		// Nothing to take out: the plan is the plan of before (no console step).
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if strings.Contains(stepText(p), "take out the settings") || strings.Contains(stepText(p), "removed settings.color") {
			t.Errorf("%s: a console step for a file without the settings:\n%s", target, stepText(p))
		}

		s.write(s.p.ConsoleFile, consoleWith, 0o600)
		s.reload()
		s.in.Target = target
		p, err = PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		st := stepText(p)
		if !p.PendingFiles() {
			t.Errorf("%s: the console.yaml change is not a file to back up", target)
		}
		for _, w := range []string{"remove settings.color: on", "set settings.list_max to 1000 (it never asked)"} {
			if !strings.Contains(st, w) {
				t.Errorf("%s: steps lack %q:\n%s", target, w, st)
			}
		}
		if target != RollbackTarget {
			if !strings.Contains(st, s.p.ConsoleFile+": take out the settings "+target+" does not know") {
				t.Errorf("%s: no console step:\n%s", target, st)
			}
			// The file is no longer among the ones left alone.
			if i := strings.Index(st, "leave every other file untouched"); i < 0 || strings.Contains(st[i:], s.p.ConsoleFile) {
				t.Errorf("%s: console.yaml is said to be left alone:\n%s", target, st)
			}
		}
		done, err := ApplyRollback(p)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		want := s.p.ConsoleFile + ": "
		if target == RollbackTarget {
			want += "removed settings.password_cache, settings.color, set settings.list_max to 1000 (it never asked)"
		} else {
			want += "removed settings.color, set settings.list_max to 1000 (it never asked)"
		}
		found := false
		for _, d := range done {
			found = found || d == want
		}
		if !found {
			t.Errorf("%s: done %q lacks %q", target, done, want)
		}
		b, _ := os.ReadFile(s.p.ConsoleFile)
		got := string(b)
		if strings.Contains(got, "color") || !strings.Contains(got, "list_max: 1000\n") || !strings.Contains(got, "space_completion: false") || !strings.Contains(got, "idle_timeout: 12") {
			t.Errorf("%s: the file after the apply:\n%s", target, got)
		}
		if hasCache := strings.Contains(got, "password_cache"); hasCache != (target != RollbackTarget) {
			t.Errorf("%s: password_cache kept: %v\n%s", target, hasCache, got)
		}
		// Done: the plan again has nothing to take out.
		s.reload()
		s.in.Target = target
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "settings.color") {
			t.Errorf("%s: second plan: %v\n%s", target, err, stepText(p))
		}
	}
}

// A console.yaml this release cannot read refuses the rollback to every
// target, before anything is changed.
func TestRollbackRefusesAnUnreadableConsoleFileForEveryTarget(t *testing.T) {
	for _, target := range []string{RollbackTarget0218, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.write(s.p.ConsoleFile, "version: 1\nsettings: {color: maybe}\n", 0o600)
		s.reload()
		s.in.Target = target
		if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "color") {
			t.Errorf("%s: %v", target, err)
		}
	}
}
