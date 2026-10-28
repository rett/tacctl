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
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
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
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.write(s.p.ConsoleFile, "version: 1\nsettings: {color: maybe}\n", 0o600)
		s.reload()
		s.in.Target = target
		if _, err := PlanRollback(s.in); err == nil || !strings.Contains(err.Error(), "color") {
			t.Errorf("%s: %v", target, err)
		}
	}
}

// The system shell of single users (0.2.20, settings.system_shell_users) is a
// key every older release rejects: each target's plan takes it out, says which
// users had a setting, keeps the tiers' list and every other setting, and
// leaves a file without it alone.
func TestRollbackTakesOutTheSystemShellOfUsers(t *testing.T) {
	consoleWith := strings.Replace(rbConsole, "  space_completion: false\n", "  space_completion: false\n  system_shell_users: {bob: 'enable:operator', carol: disable}\n", 1)
	if !strings.Contains(consoleWith, "system_shell_users") {
		t.Fatal("the fixture lacks the setting")
	}
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.in.Target = target
		s.write(s.p.ConsoleFile, consoleWith, 0o600)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if st := stepText(p); !strings.Contains(st, "remove settings.system_shell_users: bob enable, carol disable") || !p.PendingFiles() {
			t.Errorf("%s: steps:\n%s", target, st)
		}
		done, err := ApplyRollback(p)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		found := false
		for _, d := range done {
			found = found || (strings.HasPrefix(d, s.p.ConsoleFile+": ") && strings.Contains(d, "settings.system_shell_users"))
		}
		if !found {
			t.Errorf("%s: done %q", target, done)
		}
		b, _ := os.ReadFile(s.p.ConsoleFile)
		got := string(b)
		if strings.Contains(got, "system_shell_users") || !strings.Contains(got, "system_shell_tiers:") || !strings.Contains(got, "idle_timeout: 12") {
			t.Errorf("%s: the file after the apply:\n%s", target, got)
		}
		s.reload()
		s.in.Target = target
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "system_shell_users") {
			t.Errorf("%s: second plan: %v\n%s", target, err, stepText(p))
		}
	}
}

// The users who turned the password cache on (0.2.20, settings.
// password_cache_users) are a key every older release rejects, even those
// that have the cache's own settings: each target's plan takes it out and
// names the users, keeps the cache's tiers and lifetimes for the targets that
// have them, and leaves a file without the key alone.
func TestRollbackTakesOutTheUsersOfThePasswordCache(t *testing.T) {
	consoleWith := strings.Replace(rbConsole, "  space_completion: false\n", "  space_completion: false\n  password_cache_users: {bob: true, carol: true}\n", 1)
	if !strings.Contains(consoleWith, "password_cache_users") || !strings.Contains(rbConsole, "password_cache:") {
		t.Fatal("the fixture lacks the settings")
	}
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.in.Target = target
		s.write(s.p.ConsoleFile, consoleWith, 0o600)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if st := stepText(p); !strings.Contains(st, "remove settings.password_cache_users: bob, carol (on)") || !p.PendingFiles() {
			t.Errorf("%s: steps:\n%s", target, st)
		}
		done, err := ApplyRollback(p)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		found := false
		for _, d := range done {
			found = found || (strings.HasPrefix(d, s.p.ConsoleFile+": ") && strings.Contains(d, "settings.password_cache_users"))
		}
		if !found {
			t.Errorf("%s: done %q", target, done)
		}
		b, _ := os.ReadFile(s.p.ConsoleFile)
		got := string(b)
		if strings.Contains(got, "password_cache_users") || !strings.Contains(got, "idle_timeout: 12") {
			t.Errorf("%s: the file after the apply:\n%s", target, got)
		}
		// The cache's tiers and lifetimes stay for the targets that have them.
		if hasCache := strings.Contains(got, "password_cache:"); hasCache != (target != RollbackTarget) {
			t.Errorf("%s: password_cache kept: %v\n%s", target, hasCache, got)
		}
		s.reload()
		s.in.Target = target
		if p, err = PlanRollback(s.in); err != nil || strings.Contains(stepText(p), "password_cache_users") {
			t.Errorf("%s: second plan: %v\n%s", target, err, stepText(p))
		}
	}
}

// The rollback keeps the console switches this release ignores, and an older
// release reads them: a user or a tier switched off there gets /bin/bash again,
// a system-shell disable of one user is removed so the user has their tier's,
// and the password cache is on again for the users of an allowed tier. None of
// it is a change the plan names, so each user who would gain a system shell or
// the cache is listed as a warning with the reason, and --apply needs --yes.
func TestRollbackWarnsOfWhoGainsASystemShellOrTheCache(t *testing.T) {
	const store = "version: 1\ngroups:\n  operator: {priv_lvl: 7, builtin: true}\n  readonly: {priv_lvl: 1, builtin: true}\n  superuser: {priv_lvl: 15, builtin: true}\n" +
		"users:\n  alice: {group: superuser, hash: abcdef, disabled: false}\n  bob: {group: operator, hash: abcdef, disabled: false}\n  carol: {group: readonly, hash: abcdef, disabled: false}\n  dave: {group: operator, hash: abcdef, disabled: false}\n"
	const consoleText = "version: 1\ntiers: {readonly: disable, operator: enable, engineer: enable, superuser: enable}\nusers: {dave: disable, carol: enable}\n" +
		"settings:\n  system_shell_tiers: [operator, superuser]\n  system_shell_users: {bob: disable}\n  password_cache: {tiers: [operator, superuser], idle: 15, max: 8}\n  password_cache_users: {dave: true}\n"
	for _, target := range []string{RollbackTarget0219, RollbackTarget0218, RollbackTarget0217, RollbackTarget0216, RollbackTarget029, RollbackTarget} {
		s := newRBSandbox(t)
		s.write(s.p.StoreFile, store, 0o600)
		s.write(s.p.ConsoleFile, consoleText, 0o600)
		s.reload()
		s.in.Target = target
		p, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if !p.NeedsYes() {
			t.Errorf("%s: --apply would not need --yes", target)
		}
		var text string
		for _, w := range p.Warnings {
			if w.Title == "Users who gain a system shell or the password cache" {
				text = strings.Join(w.Lines, "\n")
			}
		}
		if text == "" {
			t.Fatalf("%s: no warning:\n%v", target, p.Warnings)
		}
		for _, want := range []string{
			// dave: the user switch is off (his tier is on), bob's own disable is removed and his tier has the shell
			"dave (operator): users.dave: disable gives a plain /bin/bash login shell",
			"bob (operator): its own system-shell disable is removed and the operator tier has the system shell",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s: the warning lacks %q:\n%s", target, want, text)
			}
		}
		// carol is enabled by her own override against the off tier: she does not gain; alice (superuser) has it already.
		for _, not := range []string{"carol", "alice (superuser): "} {
			if strings.Contains(text, not) {
				t.Errorf("%s: the warning lists %q:\n%s", target, not, text)
			}
		}
		cache := strings.Contains(text, "operator: bob (the cache is on for the tier again")
		if wantCache := target != RollbackTarget; cache != wantCache {
			t.Errorf("%s: cache lines %v, want %v:\n%s", target, cache, wantCache, text)
		}
		// dave turned the cache on himself: it is not given to him.
		if strings.Contains(text, "operator: bob, dave") || strings.Contains(text, "dave (the cache") {
			t.Errorf("%s: the warning lists a user who chose the cache:\n%s", target, text)
		}
		// Applying changes nothing about the warning: the switches stay in the file.
		if _, err := ApplyRollback(p); err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		b, _ := os.ReadFile(s.p.ConsoleFile)
		if !strings.Contains(string(b), "users: {dave: disable, carol: enable}") && !strings.Contains(string(b), "dave: disable") {
			t.Errorf("%s: the switches are gone:\n%s", target, b)
		}
		s.reload()
		s.in.Target = target
		p2, err := PlanRollback(s.in)
		if err != nil {
			t.Fatalf("%s: %v", target, err)
		}
		if !p2.NeedsYes() {
			t.Errorf("%s: the second plan has no warning, though the switches stay", target)
		}
	}

	// A file with nothing to give back is no warning; a state with no store
	// names the tiers and the settings it cannot map to users.
	s := newRBSandbox(t)
	s.write(s.p.ConsoleFile, "version: 1\nsettings: {idle_timeout: 12}\n", 0o600)
	s.reload()
	s.in.Target = RollbackTarget029
	if p, err := PlanRollback(s.in); err != nil || p.NeedsYes() {
		t.Errorf("nothing to give back: %v %v", err, p != nil && p.NeedsYes())
	}
	s.write(s.p.StoreFile, "version: 1\n", 0o600)
	s.write(s.p.ConsoleFile, consoleText, 0o600)
	s.reload()
	s.in.HasStore = false
	s.in.Target = RollbackTarget029
	p, err := PlanRollback(s.in)
	if err != nil {
		t.Fatal(err)
	}
	var lines string
	for _, w := range p.Warnings {
		lines += strings.Join(w.Lines, "\n")
	}
	for _, want := range []string{"users.dave: disable", "tiers.readonly: disable", "its own system-shell disable is removed", "every user of operator,superuser"} {
		if !strings.Contains(lines, want) {
			t.Errorf("no store: the warning lacks %q:\n%s", want, lines)
		}
	}
}
