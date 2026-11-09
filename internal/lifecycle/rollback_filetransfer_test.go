package lifecycle

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
)

// The console's file transfer settings (0.2.28, settings.file_transfer) are
// rejected by the console.yaml reader of every release a rollback goes to,
// 0.2.27 included (its source answers "settings: unknown key"; the test in
// internal/console reads the tag): each target's plan takes the key out, says
// what it held, keeps every other setting, asks for no --yes, and leaves a
// file without it alone.
func TestRollbackTakesOutTheFileTransferSettings(t *testing.T) {
	const ft = "  file_transfer:\n    tiers: [operator, superuser]\n    users: {bob: 'enable:readonly', carol: disable}\n    quota: {operator: 1G}\n    quota_users: {bob: unlimited}\n    rate_users: {carol: 1M}\n"
	consoleWith := strings.Replace(rbConsole, "  space_completion: false\n", "  space_completion: false\n"+ft, 1)
	if !strings.Contains(consoleWith, "file_transfer") {
		t.Fatal("the fixture lacks the setting")
	}
	for _, target := range []string{RollbackTarget0227, RollbackTarget0226, RollbackTarget0225, RollbackTarget0224, RollbackTarget0223, RollbackTarget0222,
		RollbackTarget0221, RollbackTarget0220, RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		// a file without the key: no console step, and the file is not written
		s.in.Target = target
		before := string(mustRead(t, s.p.ConsoleFile))
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if strings.Contains(stepText(p), "file_transfer") || strings.Contains(stepText(p), "file transfer") {
			t.Errorf("%s: a step for a file without the key:\n%s", target, stepText(p))
		}

		s.write(s.p.ConsoleFile, consoleWith, 0o600)
		s.reload()
		s.in.Target = target
		p, err = PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		st := stepText(p)
		if !p.PendingFiles() || !p.Pending() {
			t.Errorf("%s: the console.yaml change is not a file to back up", target)
		}
		if !strings.Contains(st, "remove settings.file_transfer: tiers operator,superuser, 2 user switchs, 2 quotas, 1 rate") &&
			!strings.Contains(st, "remove settings.file_transfer: tiers operator,superuser, 2 user switches, 2 quotas, 1 rate") {
			t.Errorf("%s: steps do not name the file transfer settings:\n%s", target, st)
		}
		if target != RollbackTarget {
			if !strings.Contains(st, s.p.ConsoleFile+": take out the settings "+target+" does not know") {
				t.Errorf("%s: no console step:\n%s", target, st)
			}
			// the file is no longer among the ones left alone
			if i := strings.Index(st, "leave every other file untouched"); i >= 0 && strings.Contains(st[i:], s.p.ConsoleFile) {
				t.Errorf("%s: console.yaml is said to be left alone:\n%s", target, st)
			}
		}
		for _, w := range p.Warnings {
			if strings.Contains(strings.Join(w.Lines, " "), "file_transfer") || strings.Contains(w.Title, "file transfer") {
				t.Errorf("%s: the file transfer settings are a warning: %v", target, w)
			}
		}
		if target == RollbackTarget0227 && p.NeedsYes() {
			t.Errorf("%s: the file transfer settings need --yes: %v", target, p.Warnings)
		}
		done, err := ApplyRollback(p)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		found := false
		for _, d := range done {
			found = found || (strings.HasPrefix(d, s.p.ConsoleFile+": ") && strings.Contains(d, "settings.file_transfer"))
		}
		if !found {
			t.Errorf("%s: done %q", target, done)
		}
		got := string(mustRead(t, s.p.ConsoleFile))
		if strings.Contains(got, "file_transfer") || !strings.Contains(got, "idle_timeout: 12") || !strings.Contains(got, "space_completion: false") || !strings.Contains(got, "system_shell_tiers:") {
			t.Errorf("%s: the file after the apply:\n%s", target, got)
		}
		// the password cache's own settings stay for the targets that have them
		if hasCache := strings.Contains(got, "password_cache:"); hasCache != (target != RollbackTarget) {
			t.Errorf("%s: password_cache kept: %v\n%s", target, hasCache, got)
		}
		// done: the plan again has nothing to take out
		s.reload()
		s.in.Target = target
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "file_transfer") {
			t.Errorf("%s: second plan: %v\n%s", target, err, stepText(p))
		}
		// a file without the key is not written by the targets that read the
		// rest of it as it is
		if RollbackUndoes(target, "0.2.20") {
			continue
		}
		s2 := newRBSandbox(t)
		s2.in.Target = target
		p2, err := PlanRollback(s2.in)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ApplyRollback(p2); err != nil {
			t.Fatal(err)
		}
		if after := string(mustRead(t, s2.p.ConsoleFile)); after != before {
			t.Errorf("%s: a file without the key was rewritten:\n%s", target, after)
		}
	}
}

// The target of the release before this one: the plan converts the file
// (and takes the snapshot of --apply) only when the key is there, and then
// converts nothing else, leaves the per-tier sudoers drop-in and the rest of
// console.yaml as they are, and the second plan is the first of a clean state.
func TestPlanRollback0227TakesOnlyTheFileTransferSettings(t *testing.T) {
	s := poolState(t)
	s.write(s.p.ConsoleFile, "version: 1\nsettings:\n  idle_timeout: 12\n  color: true\n  list_max: -1\n  system_shell_users: {bob: 'enable:operator'}\n  password_cache_users: {carol: true}\n"+
		"  file_transfer: {tiers: [engineer, superuser], rate: {engineer: 64K}}\n", 0o600)
	s.reload()
	was := s.snapshotOf()
	p := plan0227(t, s)
	if len(p.Keys()) != 0 || !p.PendingFiles() || p.NeedsYes() || len(p.Warnings) != 0 || len(p.console.Set) != 0 {
		t.Errorf("keys %q files %v yes %v set %q", p.Keys(), p.PendingFiles(), p.NeedsYes(), p.console.Set)
	}
	if got := strings.Join(p.console.Remove, "; "); got != "settings.file_transfer: tiers engineer,superuser, 1 rate" {
		t.Errorf("remove: %q", got)
	}
	if _, err := ApplyRollback(p); err != nil {
		t.Fatal(err)
	}
	got := string(mustRead(t, s.p.ConsoleFile))
	for _, w := range []string{"idle_timeout: 12", "color: true", "list_max: -1", "system_shell_users:", "password_cache_users:"} {
		if !strings.Contains(got, w) {
			t.Errorf("the file lost %q:\n%s", w, got)
		}
	}
	if strings.Contains(got, "file_transfer") {
		t.Errorf("the file keeps the key:\n%s", got)
	}
	// nothing else is written: the state is the one before but console.yaml
	if after := s.snapshotOf(); after[s.p.ConsoleFile] == was[s.p.ConsoleFile] {
		t.Error("console.yaml was not written")
	} else {
		after[s.p.ConsoleFile] = was[s.p.ConsoleFile]
		for f, text := range after {
			// the lock file beside console.yaml is the one new file
			if old, had := was[f]; (!had && !strings.HasSuffix(f, "/"+console.LockName)) || (had && text != old) {
				t.Errorf("the rollback wrote %s", f)
			}
		}
	}
}
