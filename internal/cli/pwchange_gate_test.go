package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
)

// asBob runs tacctl as bob, an operator of the managed users (SUDO_USER and
// SUDO_UID as sudo sets them), with bob flagged unless the store says
// otherwise.
func (sb *sandbox) asBob(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, args, idAs("bob", "tac-users tac-operator"), "SUDO_USER=bob", "SUDO_UID=1003"))
}

// A caller who must change the password runs 'passwd', 'version' and 'help'
// and nothing else: one message, exit 1, a line in the audit log with the
// words of the command and no argument, and nothing changed.
func TestCommandsAreRefusedWhileAPasswordChangeIsRequired(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "passwd", "bob", "--hash", hashOf(t, "CorrectHorse99"))
	if flaggedUsers(t, sb) != "bob" {
		t.Fatalf("bob is not flagged: %q", flaggedUsers(t, sb))
	}
	before := sb.store()
	snaps := len(sb.snapshotDirs())
	for _, args := range [][]string{{"user", "list"}, {"status"}, {"device", "list"}, {"ssh", "sw1"}, {"user", "show", "bob"},
		{"config", "validate"}, {"console", "show"}, {"user", "show", "bob", "not-a-password"}, {"backend", "list"}} {
		sb.asBob("", args...)
		if sb.code != 1 || !strings.Contains(sb.err.String(), "A password change is required of 'bob': no command runs until it is done but 'tacctl passwd' (and 'version' and 'help')") ||
			!strings.Contains(sb.err.String(), "Run: tacctl passwd") || sb.out.Len() != 0 {
			t.Errorf("%q: exit %d stdout %q stderr %q", args, sb.code, sb.out.String(), sb.err.String())
		}
		if got := strings.Count(sb.err.String(), "[ERROR]"); got != 1 {
			t.Errorf("%q: %d messages, want one: %q", args, got, sb.err.String())
		}
		words := args[0]
		if len(args) > 1 {
			words += " " + args[1]
		}
		if args[0] == "status" {
			words = "status"
		}
		line := `password-change DENY user=bob tier=operator cmd="` + words + `"`
		if args[0] == "status" {
			line = `password-change DENY user=bob tier=operator cmd=status`
		}
		if !hasAudit(sb.runner, "auth.warning", line) {
			t.Errorf("%q: no audit line %q in %q", args, line, auditLines(sb.runner))
		}
		if len(centralLines(sb.runner)) != 0 {
			t.Errorf("%q: the refused command wrote central lines %q", args, centralLines(sb.runner))
		}
		noLoggerHas(t, strings.Join(args, " "), sb.runner, "not-a-password")
	}
	if sb.store() != before || len(sb.snapshotDirs()) != snaps {
		t.Error("a refused command changed the state")
	}
}

// 'passwd', 'version' and 'help' run, the policy line the console asks for
// too, and once the password is changed so does everything.
func TestPasswordChangeCommandsRunAndUnlock(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "passwd", "bob", "--hash", hashOf(t, "CorrectHorse99"))
	for _, args := range [][]string{{"version"}, {"--version"}, {"help"}, {"_console-policy"}} {
		sb.asBob("", args...)
		if sb.code != 0 && args[0] != "help" || strings.Contains(sb.err.String(), "password change is required") {
			t.Errorf("%q: exit %d stderr %q", args, sb.code, sb.err.String())
		}
	}
	// the change itself, with a wrong current password first
	sb.asBob("wrong\n", "passwd")
	if sb.code != 1 || !strings.Contains(sb.err.String(), "Current password does not match.") || flaggedUsers(t, sb) != "bob" {
		t.Errorf("a wrong current password: exit %d %q flagged %q", sb.code, sb.err.String(), flaggedUsers(t, sb))
	}
	sb.asBob("CorrectHorse99\nNewHorse123456\nNewHorse123456\n", "passwd")
	if sb.code != 0 || flaggedUsers(t, sb) != "" {
		t.Fatalf("the change: exit %d %q flagged %q", sb.code, sb.err.String(), flaggedUsers(t, sb))
	}
	sb.asBob("", "user", "list")
	if sb.code != 0 || strings.Contains(sb.err.String(), "password change") {
		t.Errorf("after the change: exit %d %q", sb.code, sb.err.String())
	}
}

// A superuser, an unflagged caller and a caller who is no tier-managed user
// are never refused, whatever the store says.
func TestPasswordChangeRefusalSparesSuperusersAndOthers(t *testing.T) {
	sb := pwSandbox(t)
	flag := func(users ...string) {
		for _, u := range users {
			if _, err := store.Mutate(sb.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
				return s.UserSet(u, "password_change_required=true")
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	flag("alice")
	if out := plain(sb.cfgRun("", []string{"user", "list"}, idAs("alice", "tac-users tac-superuser"), "SUDO_USER=alice", "SUDO_UID=1001")); sb.code != 0 || !strings.Contains(out, "alice") {
		t.Errorf("a flagged superuser: exit %d %q", sb.code, sb.err.String())
	}
	// bob is not flagged
	sb.asBob("", "user", "list")
	if sb.code != 0 {
		t.Errorf("an unflagged operator: exit %d %q", sb.code, sb.err.String())
	}
	flag("bob")
	// a local administrator named like the user is no tacctl user: the gate
	// gave them no tier
	sb.cfgRun("", []string{"user", "list"}, func(r *fake.Runner) {}, "SUDO_USER=bob", "SUDO_UID=1003")
	if sb.code != 0 || strings.Contains(sb.err.String(), "password change") {
		t.Errorf("an administrator who is no managed user: exit %d %q", sb.code, sb.err.String())
	}
	// root
	sb.run("", []string{"user", "list"})
	if sb.code != 0 {
		t.Errorf("root: exit %d %q", sb.code, sb.err.String())
	}
	// moved into a superuser group, the same flag no longer binds; moved out
	// it binds again
	sb.asAlice("", "user", "move", "bob", "superuser")
	if out := plain(sb.cfgRun("", []string{"user", "list"}, idAs("bob", "tac-users tac-superuser"), "SUDO_USER=bob", "SUDO_UID=1003")); sb.code != 0 || !strings.Contains(out, "bob") {
		t.Errorf("bob moved to superuser: exit %d %q", sb.code, sb.err.String())
	}
	sb.asAlice("", "user", "move", "bob", "operator")
	sb.asBob("", "user", "list")
	if sb.code != 1 || !strings.Contains(sb.err.String(), "A password change is required of 'bob'") {
		t.Errorf("bob moved back: exit %d %q", sb.code, sb.err.String())
	}
}

// The policy line the console asks for says password_change=yes for a caller
// who is held to a change and for nobody else: a superuser with the flag, an
// unflagged user and a caller with no tier get no such field.
func TestConsolePolicyLineCarriesThePasswordChange(t *testing.T) {
	sb := pwSandbox(t)
	policy := func(user, uid, groups string) string {
		t.Helper()
		out := plain(sb.cfgRun("", []string{"_console-policy"}, idAs(user, groups), "SUDO_USER="+user, "SUDO_UID="+uid))
		if sb.code != 0 {
			t.Fatalf("_console-policy: exit %d %q", sb.code, sb.err.String())
		}
		return out
	}
	if out := policy("bob", "1003", "tac-users tac-operator"); strings.Contains(out, "password_change") {
		t.Errorf("an unflagged user: %q", out)
	}
	sb.asAlice("", "user", "require-password-change", "bob")
	if out := policy("bob", "1003", "tac-users tac-operator"); !strings.HasSuffix(strings.TrimSpace(out), "password_change=yes") || !strings.Contains(out, "tier=operator") {
		t.Errorf("a flagged user: %q", out)
	}
	if _, err := store.Mutate(sb.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
		return s.UserSet("alice", "password_change_required=true")
	}); err != nil {
		t.Fatal(err)
	}
	if out := policy("alice", "1001", "tac-users tac-superuser"); strings.Contains(out, "password_change") {
		t.Errorf("a flagged superuser: %q", out)
	}
	// not a managed user (the gate gives no tier): nothing, whatever the name
	if out := plain(sb.cfgRun("", []string{"_console-policy"}, func(*fake.Runner) {}, "SUDO_USER=bob", "SUDO_UID=1003")); strings.Contains(out, "password_change") {
		t.Errorf("a caller with no tier: %q", out)
	}
	// the answer parses into what the console reads
	r, ok := console.ParseRemote(policy("bob", "1003", "tac-users tac-operator"))
	if !ok || !r.PasswordChange || r.Tier != tier.Operator {
		t.Errorf("ParseRemote: %+v", r)
	}
}
