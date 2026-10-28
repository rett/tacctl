package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// The password cache is a permission of the tier ('console password-cache
// tiers') and a choice of the user, off until they turn it on with 'console
// password-cache on'. These tests run the root side of those words as the
// invoking user (sandbox users: alice superuser, bob operator, carol
// readonly).

// pcAs runs 'console password-cache <args>' as user, whose groups are tac-users
// and tac-<group>.
func pcAs(sb *sandbox, user, group string, args ...string) string {
	return plain(sb.cfgRun("", append([]string{"console", "password-cache"}, args...), func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
	}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user)))
}

// pcLine is the _console-policy line of user.
func pcLine(sb *sandbox, user, group string) string {
	return strings.TrimSpace(plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
	}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user))))
}

// Whether the cache is active in a session is the tier's permission and the
// user's choice, both: the matrix of the two, as the policy line says it
// (password_cache=yes is what the console starts the cache by, pc_allowed the
// permission alone).
func TestPasswordCacheNeedsThePermissionAndTheChoice(t *testing.T) {
	sb := consoleSandbox(t)
	sb.con("password-cache", "tiers", "operator,superuser")
	cases := []struct {
		user, group string
		allowed     bool
	}{{"bob", "operator", true}, {"alice", "superuser", true}, {"carol", "readonly", false}}
	for _, c := range cases {
		got := pcLine(sb, c.user, c.group)
		switch {
		case c.allowed && !strings.Contains(got, " password_cache=no pc_allowed=yes "):
			t.Errorf("%s allowed, not turned on: %q", c.user, got)
		case !c.allowed && strings.Contains(got, "password_cache"):
			t.Errorf("%s not allowed: %q", c.user, got)
		}
	}
	// Allowed and on: active.
	pcAs(sb, "bob", "operator", "on")
	sb.expect(0, "The password cache is on for you", "")
	if got := pcLine(sb, "bob", "operator"); !strings.Contains(got, " password_cache=yes pc_allowed=yes ") {
		t.Errorf("bob on: %q", got)
	}
	// The choice persists: the next policy line (a new session) is the same,
	// and the file holds it as a map of the user.
	if got := pcLine(sb, "bob", "operator"); !strings.Contains(got, " password_cache=yes ") {
		t.Errorf("bob, next session: %q", got)
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  password_cache_users: {bob: true}\n") {
		t.Errorf("console.yaml:\n%s", y)
	}
	// The permission goes: on is still there but the cache is not active.
	sb.con("password-cache", "tiers", "superuser")
	if got := pcLine(sb, "bob", "operator"); strings.Contains(got, "password_cache") {
		t.Errorf("bob, tier no longer allowed: %q", got)
	}
	// ... and turning it on is refused for a tier that is not allowed, with
	// the way out in one sentence, and saves nothing.
	pcAs(sb, "bob", "operator", "off")
	sb.expect(0, "The password cache is off for you", "")
	before := sb.consoleYAML()
	pcAs(sb, "bob", "operator", "on")
	sb.expect(1, "", "The password cache is not allowed for the operator tier; a superuser allows it with: tacctl console password-cache tiers <tiers>. Nothing was changed.")
	if sb.consoleYAML() != before {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
	// Readonly follows the permission: it is never allowed, and the gate
	// does not let the word through for it.
	pcAs(sb, "carol", "readonly", "on")
	sb.expect(1, "", "is not permitted for the readonly tier")
	pcAs(sb, "carol", "readonly")
	sb.expect(1, "", "is not permitted for the readonly tier")
}

// Each tier that can have the cache sets its own choice; the audit row says who
// and on or off; the state word prints the permission and the choice.
func TestPasswordCacheEachUserSetsTheirOwn(t *testing.T) {
	sb := consoleSandbox(t)
	sb.con("password-cache", "tiers", "operator,engineer,superuser")
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600) // bob is an engineer
	for _, c := range []struct{ user, group, tier string }{{"alice", "superuser", "superuser"}, {"bob", "operator", "engineer"}} {
		out := pcAs(sb, c.user, c.group)
		for _, w := range []string{"tiers: operator,engineer,superuser\n", "idle: 15 min\n", "max: 8 h\n", "your tier (" + c.tier + "): allowed\n", "your setting: off\n"} {
			if !strings.Contains(out, w) {
				t.Errorf("%s state lacks %q:\n%s", c.user, w, out)
			}
		}
		pcAs(sb, c.user, c.group, "on")
		if sb.code != 0 {
			t.Fatalf("%s on: %d %q", c.user, sb.code, sb.stderr())
		}
		if !hasAudit(sb.runner, "auth.info", "console set key=password-cache item=user:"+c.user+" from=off to=on by="+c.user) &&
			!hasAudit(sb.runner, "auth.notice", "console set key=password-cache item=user:"+c.user+" from=off to=on by="+c.user) {
			t.Errorf("%s: no audit row: %q", c.user, auditLines(sb.runner))
		}
		if out = pcAs(sb, c.user, c.group); !strings.Contains(out, "your setting: on\n") {
			t.Errorf("%s state after on:\n%s", c.user, out)
		}
		// Already on: nothing is written.
		before := sb.consoleYAML()
		if out = pcAs(sb, c.user, c.group, "on"); !strings.Contains(out, "already on for you") || sb.consoleYAML() != before {
			t.Errorf("%s on again: %q", c.user, out)
		}
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "password_cache_users: {alice: true, bob: true}") {
		t.Errorf("console.yaml:\n%s", y)
	}
	pcAs(sb, "alice", "superuser", "off")
	if !hasAuditPrefix(sb.runner, "auth.info", "console set key=password-cache item=user:alice from=on to=off by=alice") &&
		!hasAuditPrefix(sb.runner, "auth.notice", "console set key=password-cache item=user:alice from=on to=off by=alice") {
		t.Errorf("no audit row for off: %q", auditLines(sb.runner))
	}
	if y := sb.consoleYAML(); strings.Contains(y, "alice") || !strings.Contains(y, "password_cache_users: {bob: true}") {
		t.Errorf("console.yaml after alice's off:\n%s", y)
	}
}

// A user changes only their own setting: no word names another user, the
// target is the one sudo was run by, and the superuser's administration of the
// others is refused for everyone else.
func TestPasswordCacheCannotSetAnotherUsersValue(t *testing.T) {
	sb := consoleSandbox(t)
	sb.con("password-cache", "tiers", "operator,superuser")
	pcAs(sb, "alice", "superuser", "on")
	before := sb.consoleYAML()
	for _, args := range [][]string{
		{"on", "alice"}, {"off", "alice"}, {"alice", "on"}, {"user", "alice", "clear"}, {"user", "bob", "on"}, {"user"}, {"user", "alice"},
		{"tiers", "operator"}, {"tiers"}, {"idle", "5"}, {"max", "2"},
	} {
		pcAs(sb, "bob", "operator", args...)
		if sb.code != 1 {
			t.Errorf("bob %v: exit %d %q", args, sb.code, sb.stderr())
		}
		if sb.consoleYAML() != before {
			t.Errorf("bob %v changed console.yaml:\n%s", args, sb.consoleYAML())
		}
	}
	// The administration is refused as a tier denial and logged.
	pcAs(sb, "bob", "operator", "user", "alice", "clear")
	sb.expect(1, "", "'tacctl console password-cache' is not permitted for the operator tier.")
	if !hasAuditPrefix(sb.runner, "auth.warning", "tier DENY user=bob tier=operator cmd=console password-cache") {
		t.Errorf("not logged: %q", sb.runner.Argvs())
	}
	// Run by root with no invoking user, there is no one to set it for.
	sb.cfgRun("", []string{"console", "password-cache", "on"}, nil)
	sb.expect(1, "", "run this as a tacctl user. Nothing was changed.")
	if sb.consoleYAML() != before {
		t.Errorf("root changed console.yaml:\n%s", sb.consoleYAML())
	}
}

// The superuser lists the users who turned the cache on and clears one, which
// switches it off for that user; 'console show' lists them as well.
func TestPasswordCacheSuperuserAdministersTheUsers(t *testing.T) {
	sb := consoleSandbox(t)
	sb.con("password-cache", "tiers", "operator,superuser")
	pcAs(sb, "bob", "operator", "on")
	pcAs(sb, "alice", "superuser", "on")
	if got := strings.TrimSpace(sb.con("password-cache", "user")); got != "alice: on (superuser)\nbob: on (operator)" {
		t.Errorf("list: %q", got)
	}
	if got := strings.TrimSpace(sb.con("password-cache", "user", "bob")); got != "on" {
		t.Errorf("bob: %q", got)
	}
	if got := strings.TrimSpace(sb.con("password-cache", "user", "carol")); got != "off" {
		t.Errorf("carol: %q", got)
	}
	if out := sb.con("show"); !strings.Contains(out, "  password-cache users: alice, bob (turned it on for themselves)\n") {
		t.Errorf("show:\n%s", out)
	}
	out := sb.con("password-cache", "user", "bob", "clear")
	if sb.code != 0 || !strings.Contains(out, "The password cache setting of 'bob' is cleared: it is off for them.") {
		t.Errorf("clear: %d %q", sb.code, out)
	}
	if got := pcLine(sb, "bob", "operator"); !strings.Contains(got, " password_cache=no pc_allowed=yes ") {
		t.Errorf("bob after the clear: %q", got)
	}
	if out = sb.con("password-cache", "user", "bob", "clear"); !strings.Contains(out, "'bob' has not turned the password cache on. Nothing was changed.") {
		t.Errorf("clear twice: %q", out)
	}
	sb.con("password-cache", "user", "zed")
	sb.expect(1, "", "User 'zed' does not exist.")
	sb.con("password-cache", "user", "alice", "keep")
	sb.expect(1, "", "Usage: tacctl console password-cache")
	sb.con("password-cache", "user", "alice", "clear", "x")
	sb.expect(1, "", "Unknown argument: 'x'")
	sb.con("password-cache", "on", "x")
	sb.expect(1, "", "Unknown argument: 'x'")
}

// The choice follows the user as the system-shell setting does: dropped when the
// user is removed, moved when renamed, and not inherited by a user created
// under the name.
func TestPasswordCacheSettingFollowsTheUser(t *testing.T) {
	sb := consoleSandbox(t)
	sb.write("shells", "/bin/sh\n/bin/bash\n", 0o644)
	sb.con("password-cache", "tiers", "operator,superuser")
	pcAs(sb, "bob", "operator", "on")
	admin := func(stdin string, args ...string) string {
		return plain(sb.cfgRun(stdin, args, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	}
	out := admin("", "user", "rename", "bob", "robert")
	if sb.code != 0 || !strings.Contains(out, "The password-cache setting of 'bob' (on) moves to 'robert'.") {
		t.Fatalf("rename: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	for _, l := range []string{
		"console set key=password-cache item=user:bob from=on to=none by=alice",
		"console set key=password-cache item=user:robert from=none to=on by=alice",
	} {
		if !hasAudit(sb.runner, "auth.notice", l) {
			t.Errorf("no %q in %q", l, auditLines(sb.runner))
		}
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "password_cache_users: {robert: true}") || strings.Contains(y, "bob") {
		t.Errorf("console.yaml after the rename:\n%s", y)
	}
	out = admin("y\n", "user", "remove", "robert")
	if sb.code != 0 || !strings.Contains(out, "The password-cache setting of 'robert' (on) is dropped.") {
		t.Fatalf("remove: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	if y := sb.consoleYAML(); strings.Contains(y, "password_cache_users") {
		t.Errorf("console.yaml after the removal:\n%s", y)
	}
	// A user created under the old name is off.
	admin("", "user", "add", "bob", "operator", "--hash", testHash, "--scopes", "lab")
	if sb.code != 0 {
		t.Fatalf("add: %d %q", sb.code, sb.stderr())
	}
	if got := pcLine(sb, "bob", "operator"); !strings.Contains(got, " password_cache=no pc_allowed=yes ") {
		t.Errorf("recreated bob: %q", got)
	}
	// An entry left by a hand edit is dropped when the name is added, and an
	// entry of a name that is no user is not honoured.
	sb.write("state/console.yaml", "version: 1\nsettings: {password_cache: {tiers: [operator, superuser], idle: 15, max: 8}, password_cache_users: {dave: true}}\n", 0o600)
	if got := strings.TrimSpace(sb.con("password-cache", "user")); got != "dave: on (no such user)" {
		t.Errorf("dead entry: %q", got)
	}
	out = admin("", "user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab")
	if sb.code != 0 || !strings.Contains(out, "The password-cache setting of 'dave' (on) is dropped.") {
		t.Errorf("add dave: %d\n%s", sb.code, out)
	}
	if got := pcLine(sb, "dave", "operator"); !strings.Contains(got, " password_cache=no ") {
		t.Errorf("dave: %q", got)
	}
}
