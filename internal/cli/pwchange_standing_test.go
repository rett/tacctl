package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// flagUser sets the flag in the store directly, as a state the verbs refuse
// to make (a user who cannot log in to change the password).
func flagUser(t *testing.T, sb *sandbox, name string) {
	t.Helper()
	if _, err := store.Mutate(sb.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
		return s.UserSet(name, "password_change_required=true")
	}); err != nil {
		t.Fatal(err)
	}
}

// A change that would leave a flagged user with no login on this server is
// refused before anything is written or snapshotted, with the exact command
// that lifts the requirement; once it is lifted the change goes through, and
// a user the flag does not hold is never in the way.
func TestPwGuardRefusesWhatWouldStrandAFlaggedUser(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	snaps := strings.Join(sb.snapshotDirs(), ",")
	storeBefore := sb.read("state/store.yaml")
	for _, c := range []struct {
		name string
		args []string
	}{
		{"user scope remove", []string{"user", "scope", "bob", "remove", "srv"}},
		{"user scope replace", []string{"user", "scope", "bob", "replace", "lab"}},
		{"user scope remove --all", []string{"user", "scope", "bob", "remove", "--all"}},
		{"scope prefixes remove", []string{"scope", "prefixes", "srv", "add", "10.99.0.0/16"}},
		{"scope protocols", []string{"scope", "protocols", "srv", "set", "radius"}},
	} {
		args := c.args
		if c.name == "scope prefixes remove" {
			// the loopback prefix goes: srv no longer answers the server
			sb.run("", []string{"scope", "prefixes", "srv", "add", "10.99.0.0/16"})
			sb.expect(0, "", "")
			storeBefore = sb.read("state/store.yaml")
			snaps = strings.Join(sb.snapshotDirs(), ",")
			args = []string{"scope", "prefixes", "srv", "remove", "127.0.0.1/32"}
		}
		sb.asAlice("y\n", args...)
		out := plain(sb.err.String() + sb.out.String())
		if sb.code != 1 || !strings.Contains(out, "would leave bob, who must change the password, without a login on this server") ||
			!strings.Contains(out, "tacctl user require-password-change bob off") || !strings.Contains(out, "Nothing was changed.") {
			t.Errorf("%s: exit %d\n%s", c.name, sb.code, out)
		}
		if sb.read("state/store.yaml") != storeBefore || strings.Join(sb.snapshotDirs(), ",") != snaps {
			t.Errorf("%s: wrote or snapshotted though refused", c.name)
		}
	}
	// a user the flag does not hold, and a change that leaves bob his login
	sb.asAlice("", "user", "scope", "carol", "add", "srv")
	sb.expect(0, "", "")
	sb.asAlice("", "user", "scope", "bob", "add", "lab")
	sb.expect(0, "", "")
	// lifted, the same change goes through
	sb.asAlice("", "user", "require-password-change", "bob", "off")
	sb.expect(0, "Cleared 1", "")
	sb.asAlice("", "user", "scope", "bob", "remove", "srv")
	sb.expect(0, "", "")
}

// More than three users are named by the one command that lifts them all.
func TestPwGuardNamesTheWayOutForManyUsers(t *testing.T) {
	sb := pwSandbox(t)
	for _, n := range []string{"dave", "erin", "frank", "gina"} {
		sb.asAlice("", "user", "add", n, "operator", "--hash", hashOf(t, "CorrectHorse99"), "--scopes", "srv")
		sb.expect(0, "", "")
	}
	sb.asAlice("", "user", "scope", "dave", "remove", "srv")
	sb.expect(1, "", "tacctl user require-password-change dave off")
	sb.asAlice("", "scope", "protocols", "srv", "set", "radius")
	sb.expect(1, "", "tacctl user require-password-change --all off")
}

// A flagged user who cannot log in in the first place, or whom the devices of
// a shared scope still accept, is shown as such by user show, user list and
// status.
func TestStandingOfAFlaggedUserIsShownEverywhere(t *testing.T) {
	sb := pwSandbox(t)
	// carol is not in srv: flagged by hand, she could never change it
	flagUser(t, sb, "carol")
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	show := plain(sb.run("", []string{"user", "show", "carol"}))
	if !strings.Contains(show, "Password change:  flagged, cannot log in to change it (it is not in scope 'srv', the scope of this server") {
		t.Errorf("user show carol:\n%s", show)
	}
	list := plain(sb.run("", []string{"user", "list"}))
	if !strings.Contains(list, "(flagged, cannot log in to change it)") || !strings.Contains(list, "(change required)") {
		t.Errorf("user list:\n%s", list)
	}
	st := plain(sb.run("", []string{"status"}))
	if !strings.Contains(st, "Password change:      flagged, cannot log in to change it: carol") {
		t.Errorf("status:\n%s", st)
	}
	// a server that is not enrolled strands everyone flagged
	sb.write("state/linux-hosts", "", 0o600)
	st = plain(sb.run("", []string{"status"}))
	if !strings.Contains(st, "flagged, cannot log in to change it: bob, carol") {
		t.Errorf("status, not enrolled:\n%s", st)
	}
	sb.write("state/linux-hosts", "authsrv|local|22|srv|127.0.0.1|\n", 0o600)
	// a shared scope: devices still accept bob
	sb.asAlice("", "scope", "prefixes", "srv", "add", "192.0.2.0/24")
	sb.expect(0, "", "")
	if out := plain(sb.err.String() + sb.out.String()); !strings.Contains(out, "bob must change the password, and devices in the server's scope still accept the old one.") ||
		!strings.Contains(out, "Scope 'srv', this server's, also answers 192.0.2.0/24") {
		t.Errorf("the verb that made the scope shared did not warn:\n%s", out)
	}
	show = plain(sb.run("", []string{"user", "show", "bob"}))
	if !strings.Contains(show, "Password change:  flagged, devices in a scope shared with the server still accept the password (192.0.2.0/24)") {
		t.Errorf("user show bob:\n%s", show)
	}
	list = plain(sb.run("", []string{"user", "list"}))
	if !strings.Contains(list, "(flagged, devices in a scope shared with the server still accept the password)") {
		t.Errorf("user list:\n%s", list)
	}
	st = plain(sb.run("", []string{"status"}))
	if !strings.Contains(st, "flagged, devices in a scope shared with the server still accept the password: bob") {
		t.Errorf("status:\n%s", st)
	}
	// a second change to the shared scope says nothing new
	sb.asAlice("", "scope", "prefixes", "srv", "add", "198.51.100.0/24")
	sb.expect(0, "", "")
	if strings.Contains(sb.err.String()+sb.out.String(), "still accept the old one") {
		t.Errorf("warned again for a scope that was shared already:\n%s", sb.err.String()+sb.out.String())
	}
}

// Flagging before devices were added: the user is told when a prefix makes
// the scope shared, not only at the flagging.
func TestPwGuardWarnsWhenAScopeBecomesSharedUnderAFlaggedUser(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	if strings.Contains(sb.err.String(), "also answers") {
		t.Fatalf("a scope of the server alone is warned of:\n%s", sb.err.String())
	}
	sb.asAlice("", "scope", "prefixes", "srv", "add", "198.51.100.0/24")
	sb.expect(0, "[WARN] bob must change the password, and devices in the server's scope still accept the old one.", "")
	// a user flagged by the verb that opens the scope is told by that verb
	sb = pwSandbox(t)
	sb.asAlice("", "scope", "prefixes", "srv", "add", "198.51.100.0/24")
	sb.expect(0, "", "")
	sb.asAlice("", "user", "require-password-change", "bob")
	if n := strings.Count(sb.err.String()+sb.out.String(), "also answers 198.51.100.0/24"); n != 1 {
		t.Errorf("the shared scope was warned of %d times:\n%s", n, sb.err.String()+sb.out.String())
	}
}

// A scope rename follows into the registry before the backends render, so a
// user who must change the password is still in this server's scope in the
// file written by the rename.
func TestScopeRenameKeepsAFlaggedUserInTheServersScope(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	sb.run("", []string{"config", "render"})
	if r := sb.renderedConfig(); !strings.Contains(r, "- name: bob\n    scopes: [\"srv\"]") {
		t.Fatalf("before:\n%s", r)
	}
	sb.asAlice("", "scope", "rename", "srv", "srv2")
	sb.expect(0, "Scope renamed: srv -> srv2", "")
	if r := sb.renderedConfig(); !strings.Contains(r, "- name: bob\n    scopes: [\"srv2\"]") {
		t.Errorf("after the rename, bob in the rendered file:\n%s", r)
	}
	if got := sb.read("state/linux-hosts"); !strings.HasPrefix(got, "authsrv|local|22|srv2|") {
		t.Errorf("registry: %q", got)
	}
}

// The server's registration is where a flagged user changes the password: the
// verbs that drop it, or move it to another scope or method, are refused
// while anyone is flagged, with the way out.
func TestPwHostGuardRefusesChangesOfTheServersRegistration(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	reg := sb.read("state/linux-hosts")
	for _, args := range [][]string{
		{"host", "forget", "authsrv", "--yes"},
		{"host", "unenroll", "authsrv"},
	} {
		sb.asAlice("y\n", args...)
		out := plain(sb.err.String() + sb.out.String())
		if sb.code != 1 || !strings.Contains(out, "bob must change the password there") || !strings.Contains(out, "tacctl user require-password-change bob off") || !strings.Contains(out, "Nothing was changed.") {
			t.Errorf("%v: exit %d\n%s", args, sb.code, out)
		}
		if sb.read("state/linux-hosts") != reg {
			t.Errorf("%v: the registry changed", args)
		}
	}
	// nobody flagged: forgetting goes through
	sb.asAlice("", "user", "require-password-change", "bob", "off")
	sb.expect(0, "Cleared 1", "")
	sb.asAlice("y\n", "host", "forget", "authsrv", "--yes")
	sb.expect(0, "", "")
	if got := sb.read("state/linux-hosts"); strings.Contains(got, "authsrv") {
		t.Errorf("not forgotten: %q", got)
	}
}

// Enrolling this server where a scope of the operator's answers 127.0.0.1
// together with devices gives the server a scope of its own: the operator's
// scope keeps its other prefixes, and no warning of a shared scope is left.
func TestHostEnrollLocalTakesTheServerOutOfASharedScope(t *testing.T) {
	hs := newHostSandbox(t)
	hs.run(nil, "scope", "prefixes", "lab", "add", "127.0.0.1/32")
	hs.run(nil, "host", "enroll", "--local", "--name", "authsrv", "--build-on-host")
	hs.expect(0, "Host 'authsrv' enrolled", "")
	if out := plain(hs.out.String() + hs.err.String()); strings.Contains(out, "also answers") {
		t.Errorf("a shared-scope warning:\n%s", out)
	}
	if got := hs.registry(); !strings.HasPrefix(got, "authsrv|local||tacctl|192.0.2.10|") {
		t.Errorf("registry: %q", got)
	}
	if st := hs.store(); strings.Contains(st, "127.0.0.1/32, 172") || !strings.Contains(st, "tacctl:\n    prefixes: [127.0.0.1/32, 192.0.2.10/32]") || !strings.Contains(st, "prefixes: [172.16.0.0/12, 192.168.0.0/16]") {
		t.Errorf("store:\n%s", st)
	}
}
