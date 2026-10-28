package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/store"
)

// pwSandbox is the multi-scope sandbox with a scope of its own for this
// server's logins (srv, 127.0.0.1), bob in it too, and this server enrolled
// in it as 'authsrv' (alice is a superuser, bob an operator, carol a
// read-only user who is not in srv).
func pwSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "add", "srv", "--prefixes", "127.0.0.1/32"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "scope", "bob", "add", "srv"})
	sb.expect(0, "", "")
	sb.run("", []string{"user", "scope", "alice", "add", "srv"})
	sb.expect(0, "", "")
	sb.write("state/linux-hosts", "authsrv|local|22|srv|127.0.0.1|\n", 0o600)
	return sb
}

// flaggedUsers are the users of the sandbox's store that carry the key.
func flaggedUsers(t *testing.T, sb *sandbox) string {
	t.Helper()
	names, err := store.PasswordChangeKeys(sb.path("state", "store.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(names, ",")
}

func hashOf(t *testing.T, pw string) string {
	t.Helper()
	h, err := hash.Generate(pw, 4)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A new user must change the password, unless told not to: the flag is
// stored, the command says what it means, and the line goes to the audit
// log without a password or a hash.
func TestUserAddRequiresAPasswordChangeByDefault(t *testing.T) {
	sb := pwSandbox(t)
	h := hashOf(t, "CorrectHorse99")
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", h, "--scopes", "lab,srv")
	sb.expect(0, "must change the password at the first login to this server; no device accepts the user until then (--no-change-required skips this", "")
	if got := flaggedUsers(t, sb); got != "dave" {
		t.Errorf("flagged: %q", got)
	}
	wantDetail(t, "user add", auditCalls(sb.runner), "auth.info", "user password-change name=dave state=required via=add by=alice")
	noLoggerHas(t, "user add", sb.runner, h[:30])
	// the option skips it
	sb.asAlice("", "user", "add", "erin", "operator", "--hash", h, "--scopes", "lab,srv", "--no-change-required")
	sb.expect(0, "User 'erin' added", "")
	if strings.Contains(sb.out.String(), "must change") || flaggedUsers(t, sb) != "dave" {
		t.Errorf("--no-change-required: %q flagged %q", sb.out.String(), flaggedUsers(t, sb))
	}
	for _, l := range auditLines(sb.runner) {
		if strings.Contains(l, "password-change") {
			t.Errorf("a line for a requirement that was not set: %s", l)
		}
	}
	// the option may come anywhere after the group, the usage names it
	sb.asAlice("", "user", "add", "frank", "operator", "--no-change-required", "--hash", h, "--scopes", "lab,srv")
	sb.expect(0, "User 'frank' added", "")
	sb.run("", []string{"user", "add", "gina", "operator", "--bogus"})
	sb.expect(1, "", "[--no-change-required]")
}

// A superuser is never held to it, and a user who has no login on this
// server could never change the password: the flag is not set, and the
// command says why.
func TestUserAddDoesNotRequireWhatCannotBeMet(t *testing.T) {
	sb := pwSandbox(t)
	h := hashOf(t, "CorrectHorse99")
	for _, c := range []struct {
		name, group, scopes, why string
	}{
		{"root2", "superuser", "srv", "a superuser is never required to change the password"},
		{"ivan", "operator", "lab", "it is not in scope 'srv', the scope of this server"},
		{"jane.doe", "operator", "srv", "its name is no Linux account name (a period)"},
	} {
		sb.asAlice("", "user", "add", c.name, c.group, "--hash", h, "--scopes", c.scopes)
		sb.expect(0, "No password change is required of '"+c.name+"': "+c.why, "")
		if strings.Contains(sb.out.String(), "must change") {
			t.Errorf("%s: said the user must change it:\n%s", c.name, sb.out.String())
		}
	}
	if got := flaggedUsers(t, sb); got != "" {
		t.Errorf("flagged: %q", got)
	}
	// a server that is not enrolled has no login to change the password at
	sb.write("state/linux-hosts", "", 0o600)
	sb.asAlice("", "user", "add", "kate", "operator", "--hash", h, "--scopes", "lab,srv")
	sb.expect(0, "No password change is required of 'kate': this server is not enrolled (tacctl host enroll --local)", "")
	if got := flaggedUsers(t, sb); got != "" {
		t.Errorf("flagged on a server that is not enrolled: %q", got)
	}
}

// An administrator's reset requires a change by default; --no-change-required
// lifts one that stands; a superuser is not flagged.
func TestUserPasswdResetRequiresAPasswordChange(t *testing.T) {
	sb := pwSandbox(t)
	h := hashOf(t, "CorrectHorse99")
	sb.asAlice("", "user", "passwd", "bob", "--hash", h)
	sb.expect(0, "Password changed for 'bob'.", "")
	if !strings.Contains(sb.out.String(), "'bob' must change it at the next login to this server") || flaggedUsers(t, sb) != "bob" {
		t.Errorf("reset: %q flagged %q", sb.out.String(), flaggedUsers(t, sb))
	}
	wantDetail(t, "reset", auditCalls(sb.runner), "auth.info", "user password-change name=bob state=required via=passwd by=alice")
	sb.asAlice("", "user", "passwd", "bob", "--no-change-required", "--hash", h)
	sb.expect(0, "The password change required of 'bob' is lifted.", "")
	if flaggedUsers(t, sb) != "" {
		t.Errorf("still flagged: %q", flaggedUsers(t, sb))
	}
	wantDetail(t, "lift", auditCalls(sb.runner), "auth.info", "user password-change name=bob state=cleared via=passwd by=alice")
	// the option before the hash, and no hash: the prompt
	sb.asAlice("", "user", "passwd", "bob", "--hash", h, "--no-change-required")
	sb.expect(0, "Password changed for 'bob'.", "")
	if flaggedUsers(t, sb) != "" || strings.Contains(sb.out.String(), "must change") {
		t.Errorf("--no-change-required after the hash: %q", flaggedUsers(t, sb))
	}
	pw := "Str0ng-reset-Pass-77x"
	sb.asAlice(pw+"\n"+pw+"\n", "user", "passwd", "bob")
	sb.expect(0, "Password changed for 'bob'.", "")
	if flaggedUsers(t, sb) != "bob" {
		t.Errorf("the prompt: %q", flaggedUsers(t, sb))
	}
	noLoggerHas(t, "reset", sb.runner, pw, h[:30])
	// a superuser's reset sets nothing
	sb.asAlice("", "user", "passwd", "alice", "--hash", h)
	sb.expect(0, "No password change is required of 'alice': a superuser is never required to change the password.", "")
	if flaggedUsers(t, sb) != "bob" {
		t.Errorf("flagged after a superuser's reset: %q", flaggedUsers(t, sb))
	}
}

// 'user require-password-change': one user, --all, on and off, the
// superuser skipped and counted, a user with no login skipped with the reason.
func TestUserRequirePasswordChange(t *testing.T) {
	sb := pwSandbox(t)
	flag := func(args ...string) string {
		t.Helper()
		sb.asAlice("", append([]string{"user", "require-password-change"}, args...)...)
		return plain(sb.out.String() + sb.err.String())
	}
	// carol is not in srv: skipped with the reason; alice is a superuser
	out := flag("--all")
	for _, want := range []string{"Skipped alice (a superuser is never required to change the password).",
		"Skipped carol (it is not in scope 'srv', the scope of this server, so it has no login on it).",
		"Password change required of bob:", "Flagged 1, skipped 2 (1 superuser), already required 0."} {
		if !strings.Contains(out, want) {
			t.Errorf("--all lacks %q:\n%s", want, out)
		}
	}
	if sb.code != 0 || flaggedUsers(t, sb) != "bob" {
		t.Errorf("exit %d flagged %q", sb.code, flaggedUsers(t, sb))
	}
	wantDetail(t, "--all", auditCalls(sb.runner), "auth.info", "user password-change name=bob state=required via=require by=alice")
	// again: nothing to write, already required
	snaps := strings.Join(sb.snapshotDirs(), ",")
	out = flag("--all", "on")
	if !strings.Contains(out, "Flagged 0, skipped 2 (1 superuser), already required 1.") || strings.Join(sb.snapshotDirs(), ",") != snaps {
		t.Errorf("second run (snapshots %q -> %q):\n%s", snaps, strings.Join(sb.snapshotDirs(), ","), out)
	}
	// one user, named
	out = flag("alice", "on")
	if !strings.Contains(out, "Skipped alice (a superuser") || !strings.Contains(out, "Flagged 0, skipped 1 (1 superuser), already required 0.") || sb.code != 0 {
		t.Errorf("a named superuser: %d\n%s", sb.code, out)
	}
	// off: the one user, then every user who has it, a superuser's included
	out = flag("bob", "off")
	if !strings.Contains(out, "Password change no longer required of bob.") || !strings.Contains(out, "Cleared 1, not required 0.") || flaggedUsers(t, sb) != "" {
		t.Errorf("off: %q\n%s", flaggedUsers(t, sb), out)
	}
	wantDetail(t, "off", auditCalls(sb.runner), "auth.info", "user password-change name=bob state=cleared via=require by=alice")
	flag("bob")
	if _, err := store.Mutate(sb.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
		return s.UserSet("alice", "password_change_required=true")
	}); err != nil {
		t.Fatal(err)
	}
	if got := flaggedUsers(t, sb); got != "alice,bob" {
		t.Fatalf("flagged: %q", got)
	}
	out = flag("--all", "off")
	if !strings.Contains(out, "Cleared 2, not required 1.") || flaggedUsers(t, sb) != "" {
		t.Errorf("--all off: %q\n%s", flaggedUsers(t, sb), out)
	}
	// the refusals
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, "Usage: tacctl user require-password-change <username>|--all [on|off]"},
		{[]string{"--all", "bob"}, "'bob' is neither on nor off."},
		{[]string{"bob", "maybe"}, "'maybe' is neither on nor off."},
		{[]string{"bob", "on", "x"}, "Usage: tacctl user require-password-change"},
		{[]string{"--all", "on", "off"}, "Usage: tacctl user require-password-change"},
		{[]string{"ghost"}, "User 'ghost' does not exist."},
		{[]string{"--bogus"}, "Unknown option: '--bogus'"},
	} {
		sb.asAlice("", append([]string{"user", "require-password-change"}, c.args...)...)
		if sb.code != 1 || !strings.Contains(plain(sb.err.String()), c.want) {
			t.Errorf("%q: exit %d %q", c.args, sb.code, sb.err.String())
		}
	}
	if got := flaggedUsers(t, sb); got != "" {
		t.Errorf("a refusal wrote: %q", got)
	}
}

// The user's own change lifts the requirement and is logged; the new password
// must differ from the current one, flagged or not.
func TestPasswdSelfLiftsTheRequiredChange(t *testing.T) {
	sb := pwSandbox(t)
	sb.asAlice("", "user", "passwd", "bob", "--hash", hashOf(t, "CorrectHorse99"))
	if flaggedUsers(t, sb) != "bob" {
		t.Fatalf("bob is not flagged: %q", flaggedUsers(t, sb))
	}
	sb.run("CorrectHorse99\nCorrectHorse99\nCorrectHorse99\n", []string{"passwd"}, "SUDO_USER=bob")
	sb.expect(1, "", "[ERROR] New password must differ from the current one.")
	if flaggedUsers(t, sb) != "bob" {
		t.Errorf("a refused change lifted it: %q", flaggedUsers(t, sb))
	}
	sb.run("CorrectHorse99\nNewHorse123456\nNewHorse123456\n", []string{"passwd"}, "SUDO_USER=bob")
	sb.expect(0, "[INFO] Password changed for 'bob'.", "")
	if !strings.Contains(sb.out.String(), "The required password change is done.") || flaggedUsers(t, sb) != "" {
		t.Errorf("after the change: %q flagged %q", sb.out.String(), flaggedUsers(t, sb))
	}
	calls := auditCalls(sb.runner)
	wantDetail(t, "self", calls, "auth.info", "user password-change name=bob state=cleared via=self by=bob")
	noLoggerHas(t, "self", sb.runner, "CorrectHorse99", "NewHorse123456")
	// not flagged: no line, no sentence
	sb.run("NewHorse123456\nOtherHorse12345\nOtherHorse12345\n", []string{"passwd"}, "SUDO_USER=bob")
	sb.expect(0, "[INFO] Password changed for 'bob'.", "")
	if strings.Contains(sb.out.String(), "required") {
		t.Errorf("a change that was not required says so: %q", sb.out.String())
	}
	for _, l := range auditLines(sb.runner) {
		if strings.Contains(l, "password-change") {
			t.Errorf("a line for a requirement that stood no more: %s", l)
		}
	}
}

// 'user list' marks the date, 'user show' has a line, 'status' counts: for a
// user who is held to the change; a flagged superuser is not marked as held.
func TestUserListShowAndStatusOfARequiredChange(t *testing.T) {
	sb := pwSandbox(t)
	list := func() string { return plain(sb.run("", []string{"user", "list"})) }
	if strings.Contains(list(), "change required") {
		t.Fatalf("a list of nobody held:\n%s", list())
	}
	if out := plain(sb.run("", []string{"status"})); strings.Contains(out, "Password change") {
		t.Errorf("status says something with nobody held:\n%s", out)
	}
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	if _, err := store.Mutate(sb.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
		return s.UserSet("alice", "password_change_required=true")
	}); err != nil {
		t.Fatal(err)
	}
	out := list()
	if !strings.Contains(out, "unknown (change required)") || strings.Count(out, "change required") != 1 {
		t.Errorf("user list:\n%s", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "  alice ") && strings.Contains(l, "required") {
			t.Errorf("a superuser is marked: %q", l)
		}
	}
	if show := plain(sb.run("", []string{"user", "show", "bob"})); !strings.Contains(show, "Password change:  required (no device accepts the user until it is changed at this server)") {
		t.Errorf("user show bob:\n%s", show)
	}
	if show := plain(sb.run("", []string{"user", "show", "alice"})); !strings.Contains(show, "Password change:  flagged, not required: a superuser is never held to it") {
		t.Errorf("user show alice:\n%s", show)
	}
	if show := plain(sb.run("", []string{"user", "show", "carol"})); strings.Contains(show, "Password change:") {
		t.Errorf("user show carol:\n%s", show)
	}
	if st := plain(sb.run("", []string{"status"})); !strings.Contains(st, "Password change:      1 pending (no device accepts these users until they change it)") {
		t.Errorf("status:\n%s", st)
	}
}

// A flag that changes a rendered user restarts the backend and one that
// changes nothing (the user has no scope but the server's) restarts nothing.
func TestRequiredChangeRestartsOnlyWhatChanged(t *testing.T) {
	sb := pwSandbox(t)
	h := hashOf(t, "CorrectHorse99")
	sb.asAlice("", "user", "add", "lone", "operator", "--hash", h, "--scopes", "srv", "--no-change-required")
	sb.expect(0, "", "")
	sb.run("", []string{"config", "render"})
	sb.expect(0, "", "")
	before := sb.runner.Count("systemctl", "restart")
	sb.asAlice("", "user", "require-password-change", "lone")
	sb.expect(0, "Flagged 1", "")
	if n := sb.runner.Count("systemctl", "restart"); n != before {
		t.Errorf("a flag that changes no file restarted %d times", n-before)
	}
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	if n := sb.runner.Count("systemctl", "restart"); n != 1 {
		t.Errorf("flagging bob (lab and srv): %d restarts, want 1", n)
	}
	if rendered := sb.renderedConfig(); !strings.Contains(rendered, "- name: bob\n    scopes: [\"srv\"]") {
		t.Errorf("bob in the rendered file:\n%s", rendered)
	}
	sb.asAlice("", "user", "require-password-change", "bob", "off")
	sb.expect(0, "Cleared 1", "")
	if n := sb.runner.Count("systemctl", "restart"); n != 1 {
		t.Errorf("lifting it: %d restarts, want 1", n)
	}
	if rendered := sb.renderedConfig(); !strings.Contains(rendered, "- name: bob\n    scopes: [\"lab\", \"srv\"]") {
		t.Errorf("bob after the lift:\n%s", rendered)
	}
}

// Devices that share the scope of the server still accept a user who must
// change the password: the verbs say so and name the prefixes.
func TestRequiredChangeWarnsOfAScopeSharedWithDevices(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "prefixes", "lab", "add", "127.0.0.1/32"})
	sb.expect(0, "", "")
	sb.write("state/linux-hosts", "authsrv|local|22|lab|127.0.0.1|\n", 0o600)
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "[WARN]", "")
	if out := plain(sb.out.String()); !strings.Contains(out, "Flagged 1") || !strings.Contains(out, "[WARN] Scope 'lab', this server's, also answers 172.16.0.0/12, 192.168.0.0/16: a device there still accepts a user who must change the password") {
		t.Errorf("require:\n%s", out)
	}
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", hashOf(t, "CorrectHorse99"))
	sb.expect(0, "also answers 172.16.0.0/12", "")
	// off needs no warning
	sb.asAlice("", "user", "require-password-change", "--all", "off")
	if strings.Contains(sb.out.String(), "also answers") {
		t.Errorf("a warning for lifting:\n%s", sb.out.String())
	}
}

// A server enrolled with another address than loopback is logged in from that
// address too: the enrolled scope must answer it, and a prefix of just that
// address is the server's own, not a device's.
func TestRequiredChangeKnowsTheServersLoginAddresses(t *testing.T) {
	sb := pwSandbox(t)
	sb.write("state/linux-hosts", "authsrv|local|22|srv|192.0.2.10|\n", 0o600)
	// srv answers 127.0.0.1 only: the logins from 192.0.2.10 find no scope of it
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "", "")
	if out := plain(sb.out.String() + sb.err.String()); !strings.Contains(out, "Skipped bob (scope 'srv' does not answer 192.0.2.10 for TACACS+, where this server's own logins come from") {
		t.Errorf("without the address:\n%s", out)
	}
	if got := flaggedUsers(t, sb); got != "" {
		t.Errorf("flagged: %q", got)
	}
	// with the address in the scope it is the server's own: no warning
	sb.run("", []string{"scope", "prefixes", "srv", "add", "192.0.2.10/32"})
	sb.expect(0, "", "")
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1, skipped 0, already required 0.", "")
	if strings.Contains(sb.out.String()+sb.err.String(), "also answers") {
		t.Errorf("the server's own address is warned of:\n%s", sb.out.String()+sb.err.String())
	}
	// a wider prefix that holds it is shared with devices
	sb.run("", []string{"scope", "prefixes", "srv", "add", "192.0.2.0/24"})
	sb.expect(0, "", "")
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", hashOf(t, "CorrectHorse99"), "--scopes", "srv")
	sb.expect(0, "also answers 192.0.2.0/24", "")
}

// The barrier looks at the protocol of the server's method: a scope that
// serves only the other protocol does not answer the server.
func TestRequiredChangeBarrierFollowsTheMethod(t *testing.T) {
	sb := pwSandbox(t)
	sb.write("state/linux-hosts", "authsrv|local|22|srv|127.0.0.1||radius\n", 0o600)
	sb.run("", []string{"scope", "protocols", "srv", "set", "tacacs"})
	sb.expect(0, "", "")
	sb.asAlice("", "user", "require-password-change", "bob")
	if out := plain(sb.out.String() + sb.err.String()); !strings.Contains(out, "Skipped bob (scope 'srv' does not answer 127.0.0.1 for RADIUS") {
		t.Errorf("radius server, tacacs scope:\n%s", out)
	}
}

// A reset that cannot require a change (the registry cannot be read, the user
// has no login here) lifts nothing that stands, and says so; for a user who
// was not flagged it says the change could not be required and why. Only
// --no-change-required, or a superuser, clears the flag.
func TestUserPasswdResetKeepsAFlagItCannotRenew(t *testing.T) {
	sb := pwSandbox(t)
	h := hashOf(t, "CorrectHorse99")
	sb.asAlice("", "user", "require-password-change", "bob")
	sb.expect(0, "Flagged 1", "")
	// the registry cannot be read: a directory where the file should be
	if err := os.Remove(sb.path("state", "linux-hosts")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sb.path("state", "linux-hosts"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.asAlice("", "user", "passwd", "bob", "--hash", h)
	out := plain(sb.out.String() + sb.err.String())
	if sb.code != 0 || !strings.Contains(out, "Password changed for 'bob'.") ||
		!strings.Contains(out, "The password change required of 'bob' stands (it was not lifted, and could not be required again): the host registry cannot be read") {
		t.Errorf("reset of a flagged user, registry unreadable: exit %d\n%s", sb.code, out)
	}
	if got := flaggedUsers(t, sb); got != "bob" {
		t.Errorf("the reset lifted the flag: %q", got)
	}
	for _, l := range auditLines(sb.runner) {
		if strings.Contains(l, "password-change") {
			t.Errorf("a line for a flag that did not change: %s", l)
		}
	}
	// an unflagged user: not flagged, and told why
	sb.asAlice("", "user", "passwd", "carol", "--hash", h)
	out = plain(sb.out.String() + sb.err.String())
	if !strings.Contains(out, "A password change could not be required of 'carol': the host registry cannot be read") || flaggedUsers(t, sb) != "bob" {
		t.Errorf("reset of an unflagged user: %q flagged %q", out, flaggedUsers(t, sb))
	}
	// the explicit option still lifts it
	sb.asAlice("", "user", "passwd", "bob", "--hash", h, "--no-change-required")
	sb.expect(0, "The password change required of 'bob' is lifted.", "")
	if flaggedUsers(t, sb) != "" {
		t.Errorf("--no-change-required: %q", flaggedUsers(t, sb))
	}
	// a flagged user with no login here (not in the server's scope) stays flagged
	if err := os.Remove(sb.path("state", "linux-hosts")); err != nil {
		t.Fatal(err)
	}
	sb.write("state/linux-hosts", "authsrv|local|22|srv|127.0.0.1|\n", 0o600)
	flagUser(t, sb, "carol")
	sb.asAlice("", "user", "passwd", "carol", "--hash", h)
	if out := plain(sb.out.String() + sb.err.String()); !strings.Contains(out, "stands") || !strings.Contains(out, "it is not in scope 'srv'") || flaggedUsers(t, sb) != "carol" {
		t.Errorf("reset of a flagged user with no login: %q flagged %q", out, flaggedUsers(t, sb))
	}
	// a superuser's reset clears a flag it never binds
	flagUser(t, sb, "alice")
	sb.asAlice("", "user", "passwd", "alice", "--hash", h)
	sb.expect(0, "The password change required of 'alice' is lifted.", "")
	if flaggedUsers(t, sb) != "carol" {
		t.Errorf("flagged after a superuser's reset: %q", flaggedUsers(t, sb))
	}
}
