package cli

import (
	"strings"
	"testing"
)

// refusedStranding checks that the last command was refused as one that
// would leave who without a login on this server to change the password,
// with the way out.
func refusedStranding(t *testing.T, sb *sandbox, what, who string) {
	t.Helper()
	all := plain(sb.out.String() + sb.err.String())
	if sb.code != 1 || !strings.Contains(all, what+" would leave "+who+", who must change the password, without a login on this server to do it at.") ||
		!strings.Contains(all, "tacctl user require-password-change "+who+" off") || !strings.Contains(all, "Nothing was changed.") {
		t.Errorf("not refused: exit %d\n%s", sb.code, all)
	}
}

// 'scope add' writes outside the store's own verbs: a new scope whose prefix
// answers the server's address more closely than the server's scope takes the
// server's logins away from a flagged user, and is refused by the guard of the
// write path, store and rendered files as they were.
func TestScopeAddThatTakesTheServerAddressIsRefused(t *testing.T) {
	sb := pwSandbox(t)
	sb.run("", []string{"scope", "prefixes", "srv", "add", "127.0.0.0/8"})
	sb.expect(0, "", "")
	sb.run("y\n", []string{"scope", "prefixes", "srv", "remove", "127.0.0.1/32"})
	if sb.code != 0 {
		t.Fatalf("prefix remove: %d %s", sb.code, sb.err.String())
	}
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	store, rendered := sb.read("state/store.yaml"), sb.renderedConfig()
	sb.run("y\n", []string{"scope", "add", "other", "--prefixes", "127.0.0.1/32"})
	refusedStranding(t, sb, "This change", "bob")
	if sb.read("state/store.yaml") != store || sb.renderedConfig() != rendered {
		t.Error("a refused scope add changed the store or the rendered file")
	}
	sb.run("", []string{"user", "show", "bob"})
	if strings.Contains(plain(sb.out.String()), pwTextStranded) {
		t.Errorf("bob is stranded:\n%s", plain(sb.out.String()))
	}
}

// A tier change of a group is a tacctl.yaml write: lowering a superuser group
// newly holds a flagged member. The member has the server's own login all the
// same (every user is in the scope tacctl manages for it, which the sync of
// the server that the group's new tier starts takes over), so the change is
// made and the member can change the password there.
func TestGroupTierOfAFlaggedMemberKeepsTheServerLogin(t *testing.T) {
	sb := pwSandbox(t)
	sb.run("", []string{"group", "add", "admins", "15", "ADMIN-CLASS", "--tier", "superuser"})
	sb.expect(0, "", "")
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	sb.run("", []string{"user", "move", "bob", "admins"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "scope", "bob", "replace", "lab"})
	sb.expect(0, "", "")
	if got := sb.read("state/linux-hosts"); !strings.HasPrefix(got, "authsrv|local|22|tacctl|") {
		t.Fatalf("the server's scope was not taken over: %q", got)
	}
	sb.run("y\n", []string{"group", "edit", "admins", "tier", "operator"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "show", "bob"})
	if out := plain(sb.out.String()); strings.Contains(out, pwTextStranded) || !strings.Contains(out, "required (no device accepts the user until it is changed at this server)") {
		t.Errorf("user show:\n%s", out)
	}
}

// A backend that is not enabled answers nobody: a flagged user whose server
// logins go to it cannot log in to change the password, and disabling the
// backend of the server's own logins is refused, its service untouched.
func TestBackendOfTheServerLoginsCountsForTheStanding(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [radius]\n", 0o600)
	sb.run("", []string{"user", "show", "bob"})
	if out := plain(sb.out.String()); !strings.Contains(out, pwTextStranded) || !strings.Contains(out, "backend 'tacacs', which answers this server's own TACACS+ logins, is not enabled") {
		t.Errorf("user show:\n%s", out)
	}
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\n", 0o600)
	sb.run("", []string{"backend", "disable", "tacacs", "-y"})
	refusedStranding(t, sb, "This change", "bob")
	if got := sb.read("state/tacctl.yaml"); got != "backends:\n  enabled: [tacacs, radius]\n" {
		t.Errorf("tacctl.yaml: %q", got)
	}
	for _, c := range sb.runner.Argvs() {
		if strings.HasPrefix(c, "systemctl stop") || strings.HasPrefix(c, "systemctl disable") {
			t.Errorf("the service was touched: %s", c)
		}
	}
}

// 'host enroll --local' with another --server moves where the server's own
// logins come from: the managed scope follows (its prefixes are the login
// addresses), so a flagged user keeps the login, and the setting holds the
// new address, as the registry entry does.
func TestHostEnrollLocalWithAnotherServerAddressMovesTheScope(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	sb.run("", []string{"host", "enroll", "--local", "--name", "authsrv", "--server", "192.0.2.10", "--build-on-host"})
	if sb.code != 0 {
		t.Fatalf("exit %d\n%s", sb.code, sb.err.String())
	}
	if got := sb.read("state/linux-hosts"); !strings.HasPrefix(got, "authsrv|local||tacctl|192.0.2.10|") {
		t.Errorf("registry: %q", got)
	}
	if st := sb.store(); !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]") || strings.Contains(st, "\n  srv:") {
		t.Errorf("store:\n%s", st)
	}
	if got := sb.read("state/tacctl.yaml"); !strings.Contains(got, "server:\n  addresses:\n  - 192.0.2.10\n") {
		t.Errorf("tacctl.yaml:\n%s", got)
	}
	sb.run("", []string{"user", "show", "bob"})
	if strings.Contains(plain(sb.out.String()), pwTextStranded) {
		t.Errorf("bob is stranded:\n%s", plain(sb.out.String()))
	}
}
