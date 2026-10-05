package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/paths"
)

// The native families end to end, in-process: a sandbox state tree holding
// tests/fixtures/store.multiscope.yaml (alice, bob, carol; scopes prod,
// prod-inner, lab, dmz), the fake runner answering systemctl, logger and
// id. The bats files (user_crud, user_lifecycle, tiers, characterisation)
// and the differential corpus users.txt pin the bytes against 0.1.16; these
// tests pin the wiring: gate, preflight, StoreApply, prompts, exit codes.

type sandbox struct {
	t        *testing.T
	dir      string
	env      []string
	runner   *fake.Runner
	out, err bytes.Buffer
	code     int
}

func newSandbox(t *testing.T, withStore bool) *sandbox {
	t.Helper()
	w := t.TempDir()
	sb := &sandbox{t: t, dir: w}
	for _, d := range []string{"etc", "state", "log", "bin", "systemd", "tmp"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", filepath.Join(w, "tmp"))
	if withStore {
		data, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(w, "state", "store.yaml"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sb.env = []string{
		"TACCTL_SKIP_SUDO=1",
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_VAR_LIB=" + filepath.Join(w, "var-lib"),
		"TACCTL_LOG=" + filepath.Join(w, "log"),
		"TACCTL_BIN=" + filepath.Join(w, "bin"),
		"TACCTL_SYSTEMD_DIR=" + filepath.Join(w, "systemd"),
		"TACCTL_OVERRIDE_DIR=" + filepath.Join(w, "systemd", "tacquito.service.d"),
		"TACCTL_SETTLE_SECONDS=0",
		"TACCTL_LOGIN_DEFS=" + filepath.Join(w, "login.defs"),
		"TMPDIR=" + filepath.Join(w, "tmp"),
	}
	return sb
}

// run runs tacctl args with stdin and the extra environment; it returns
// stdout.
func (sb *sandbox) run(stdin string, args []string, extraEnv ...string) string {
	sb.t.Helper()
	sb.out.Reset()
	sb.err.Reset()
	sb.runner = &fake.Runner{}
	sb.runner.On([]string{"systemctl"}, execx.Result{})
	sb.runner.On([]string{"logger"}, execx.Result{})
	sb.runner.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(sb.runner)
	a := app.New(args, paths.NewEnv(append(append([]string(nil), sb.env...), extraEnv...)), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(stdin), Stdout: &sb.out, Stderr: &sb.err}, sb.runner)
	// tacctl's fixed host locations (the installed command, /root, ...)
	// stay in the sandbox too.
	a.Paths = a.Paths.Reroot(sb.dir)
	sb.code = exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}), a.Out)
	if n := len(sb.runner.Execs()); n != 0 {
		sb.t.Errorf("%q: exec'd (%d execs)", args, n)
	}
	return sb.out.String()
}

func (sb *sandbox) store() string {
	sb.t.Helper()
	data, err := os.ReadFile(filepath.Join(sb.dir, "state", "store.yaml"))
	if err != nil {
		sb.t.Fatal(err)
	}
	return string(data)
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

func (sb *sandbox) expect(code int, outHas, errHas string) {
	sb.t.Helper()
	if sb.code != code || !strings.Contains(plain(sb.out.String()), outHas) || !strings.Contains(plain(sb.err.String()), errHas) {
		sb.t.Errorf("exit %d (want %d)\nstdout %q (want %q)\nstderr %q (want %q)", sb.code, code, sb.out.String(), outHas, sb.err.String(), errHas)
	}
}

const testHash = "24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

func TestUserListShowAndUsage(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.run("", []string{"user", "list"})
	sb.expect(0, "USERNAME", "")
	for _, want := range []string{"\n  alice                superuser       \x1b[0;32mactive    \x1b[0m unknown      prod,lab", "carol"} {
		if !strings.Contains(out, want) {
			t.Errorf("user list lacks %q:\n%s", want, out)
		}
	}
	sb.run("", []string{"user", "show", "alice"})
	sb.expect(0, "Scopes:           prod", "")
	sb.run("", []string{"user", "show", "ghost"})
	sb.expect(1, "", "[ERROR] User 'ghost' does not exist.")
	sb.run("", []string{"user", "show", "bad name"})
	sb.expect(1, "", "Username must contain only letters")
	for _, w := range []string{"", "help", "bogus"} {
		args := []string{"user"}
		if w != "" {
			args = append(args, w)
		}
		if got := sb.run("", args); got != userUsage() || sb.code != 1 {
			t.Errorf("%q: %d %q", args, sb.code, got)
		}
	}
}

func TestUserAddRemoveThroughStoreApply(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab, dmz,lab"})
	sb.expect(0, "[INFO] User 'dave' added (operator) with scopes: lab,dmz", "")
	if !strings.Contains(sb.store(), "  dave:\n    group: operator\n    scopes: [lab, dmz]\n    hash: '"+testHash+"'") {
		t.Errorf("store:\n%s", sb.store())
	}
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("no restart: %q", sb.runner.Argvs())
	}
	snaps, _ := filepath.Glob(filepath.Join(sb.dir, "state", "backups", "*", "store.yaml"))
	if len(snaps) != 1 {
		t.Errorf("snapshots %q", snaps)
	}
	sb.run("", []string{"user", "add", "dave", "operator", "--hash", testHash})
	sb.expect(1, "", "[ERROR] User 'dave' already exists.")
	sb.run("", []string{"user", "add", "eve", "nogroup"})
	sb.expect(1, "", "[ERROR] Group 'nogroup' does not exist. Available: readonly|operator|superuser")
	sb.run("", []string{"user", "add", "eve", "operator", "--bogus"})
	sb.expect(1, "", "[ERROR] Unknown argument: '--bogus'")
	sb.run("", []string{"user", "add", "eve", "operator", "--scopes", "it's"})
	sb.expect(1, "", "xargs: unmatched single quote")

	before := sb.store()
	sb.run("n\n", []string{"user", "remove", "dave"})
	sb.expect(0, "[INFO] Cancelled.", "")
	sb.run("", []string{"user", "remove", "dave"})
	sb.expect(0, "[INFO] Cancelled.", "")
	if sb.store() != before {
		t.Error("a cancelled remove changed the store")
	}
	sb.run("Y\n", []string{"user", "remove", "dave"})
	sb.expect(0, "[INFO] User 'dave' removed.", "")
	if strings.Contains(sb.store(), "dave") {
		t.Error("dave still in the store")
	}
}

func TestUserAddPromptsAndGenerates(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("CorrectHorse99\nCorrectHorse99\n", []string{"user", "add", "dave", "operator", "--scopes", "lab"},
		"TACCTL_TEST_RANDOM=a1b2c3d4e5f60718293a4b5c6d7e8f90")
	sb.expect(0, "added (operator)", "  Confirm password: **************")
	sb.run("short\n", []string{"user", "add", "eve", "operator", "--scopes", "lab"})
	sb.expect(1, "", "[ERROR] Password is 5 characters; minimum is 12.")
	long := strings.Repeat("Abcdefghij", 8)
	sb.run(long+"\n"+long+"\n", []string{"user", "add", "eve", "operator", "--scopes", "lab"})
	sb.expect(1, "", "[ERROR] Password is longer than 72 bytes")
	if strings.Contains(sb.store(), "eve") {
		t.Error("a refused password created a user")
	}
	// A blank line generates the password; with the random knob it is the
	// knob's bytes, and so is the salt.
	sb.run("\n", []string{"user", "add", "eve", "operator", "--scopes", "lab"}, "TACCTL_TEST_RANDOM=a1b2c3d4e5f60718293a4b5c6d7e8f90")
	sb.expect(0, "added", "Generated password:")
	if app.TestKnobs {
		if !strings.Contains(sb.err.String(), "Generated password: \x1b[1mobLD1OX2BxgpOktcbX6PkKGy\x1b[0m") {
			t.Errorf("generated password not from the knob: %q", sb.err.String())
		}
		want, _ := hash.GenerateWith("obLD1OX2BxgpOktcbX6PkKGy", 12, bytes.NewReader([]byte{0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90}))
		if !strings.Contains(sb.store(), "hash: "+want) {
			t.Errorf("hash not salted from the knob")
		}
	}
}

func TestUserVerifyAndPasswdSelf(t *testing.T) {
	sb := newSandbox(t, true)
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"user", "passwd", "alice", "--hash", h})
	sb.expect(0, "[INFO] Password changed for 'alice'.", "")
	sb.run("CorrectHorse99\n", []string{"user", "verify", "alice"}, "SUDO_USER=ops", "SUDO_UID=7")
	sb.expect(0, "[INFO] Password is correct.", "  Enter password to verify: **************")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "verify OK user=alice by=ops(uid=7)") {
		t.Errorf("audit: %q", sb.runner.Argvs())
	}
	sb.run("nope\n", []string{"user", "verify", "alice"})
	sb.expect(0, "User:", "[ERROR] Password does not match.")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "verify FAIL user=alice result=NO_MATCH by=root(uid=1000)") {
		t.Errorf("audit: %q", sb.runner.Argvs())
	}

	sb.run("CorrectHorse99\nNewHorse123456\nNewHorse123456\n", []string{"passwd"}, "SUDO_USER=alice")
	sb.expect(0, "[INFO] Password changed for 'alice'.", "  Current password: **************")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "passwd OK user=alice (self-service)") {
		t.Errorf("audit: %q", sb.runner.Argvs())
	}
	sb.run("CorrectHorse99\n", []string{"passwd"}, "SUDO_USER=alice")
	sb.expect(1, "", "[ERROR] Current password does not match.")
	sb.run("NewHorse123456\nNewHorse123456\nNewHorse123456\n", []string{"passwd"}, "SUDO_USER=alice")
	sb.expect(1, "", "[ERROR] New password must differ from the current one.")
	sb.run("", []string{"passwd", "bob"}, "SUDO_USER=alice")
	sb.expect(1, "", "takes no arguments")
	sb.run("", []string{"passwd"})
	sb.expect(1, "", "As root, use: tacctl user passwd <username>")
	sb.run("", []string{"passwd"}, "SUDO_USER=ghost")
	sb.expect(1, "", "[ERROR] No tacctl user named 'ghost'.")
}

func TestUserScopeVerbs(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"user", "scope", "bob", "add", "dmz,lab"})
	sb.expect(0, "[INFO] Granted 1 scope(s) to user 'bob': dmz\n[INFO] (Skipped: lab)", "")
	sb.run("", []string{"user", "scope", "bob", "remove", "prod"})
	sb.expect(0, "[WARN] Nothing to remove (not present: prod).", "")
	sb.run("", []string{"user", "scope", "bob", "replace", "prod"})
	sb.expect(0, "[INFO] Replaced scopes on user 'bob': prod", "")
	sb.run("", []string{"user", "scope", "bob", "remove", "--all"})
	sb.expect(0, "[INFO] Aborted.", "")
	sb.run("yes\n", []string{"user", "scope", "bob", "remove", "--all"})
	sb.expect(0, "[INFO] Removed all scopes from user 'bob'.", "")
	if !strings.Contains(sb.store(), "  bob:\n    group: operator\n    scopes: []") {
		t.Errorf("store:\n%s", sb.store())
	}
	sb.run("", []string{"user", "scope", "bob", "remove", "--all", "lab"})
	sb.expect(1, "", "'--all' takes no scope names")
	sb.run("", []string{"user", "scope", "bob", "set", "lab"})
	sb.expect(1, "", "[ERROR] 'set' was renamed: use 'tacctl user scope bob replace <scope>[,<scope>...]'")
	sb.run("", []string{"user", "scope", "bob", "clear"})
	sb.expect(1, "", "[ERROR] 'clear' was renamed: use 'tacctl user scope bob remove --all'")
	sb.run("", []string{"user", "scope", "bob", "--help"})
	sb.expect(0, "tacctl user scope bob remove  --all                 Revoke every scope (confirms)", "")
	sb.run("", []string{"user", "scope", "bob", "bogus"})
	sb.expect(1, "", "Run 'tacctl user scope bob' for usage.")
}

func TestUserMoveUsageNamesUser(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"user", "move", "alice"})
	sb.expect(1, "", "[ERROR] Usage: tacctl user move <username> <new-group>")
	sb.run("", []string{"user", "move", "alice", "superuser"})
	sb.expect(0, "[INFO] User 'alice' is already in group 'superuser'.", "")
}

// Preflight, the tier gate and the store_require of mutating verbs.
func TestNativePrelude(t *testing.T) {
	sb := newSandbox(t, false)
	sb.run("", []string{"user", "list"})
	sb.expect(1, "", "[ERROR] Config not found: no store at ")
	// hash needs neither.
	sb.run("", []string{"hash", "commands"})
	sb.expect(0, "client-side recipes", "")
	sb.run("", []string{"_completion-names", "users"})
	sb.expect(1, "", "Config not found")

	sb = newSandbox(t, true)
	sb.runner = nil
	ro := func(args ...string) {
		sb.t.Helper()
		sb.out.Reset()
		sb.err.Reset()
		r := &fake.Runner{}
		r.On([]string{"id"}, execx.Result{Stdout: []byte("carol tac-users\n")})
		r.On([]string{"logger"}, execx.Result{})
		r.On([]string{"systemctl"}, execx.Result{})
		sb.runner = r
		a := app.New(args, paths.NewEnv(append(append([]string(nil), sb.env...), "SUDO_USER=carol")), "/x", 1000,
			app.Stdio{Stdin: strings.NewReader(""), Stdout: &sb.out, Stderr: &sb.err}, r)
		sb.code = exitCode(Run(context.Background(), a, BuildInfo{Version: "v"}), a.Out)
	}
	ro("user", "list")
	sb.expect(0, "carol", "")
	ro("user", "remove", "bob")
	sb.expect(1, "", "[ERROR] 'tacctl user remove' is not permitted for the readonly tier.")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user=carol tier=readonly cmd=user remove") {
		t.Errorf("denial not logged: %q", sb.runner.Argvs())
	}
	ro("_completion-names", "groups")
	sb.expect(0, "operator\nreadonly\nsuperuser\n", "")
	ro("version")
	sb.expect(0, "tacctl v", "")
	// scope list is open to the readonly tier, scope show (the secret's
	// length) is not.
	ro("scope", "list")
	sb.expect(0, "prod-inner", "")
	ro("scope", "show", "lab")
	sb.expect(1, "", "[ERROR] 'tacctl scope show' is not permitted for the readonly tier.")
	// install, upgrade and uninstall are superuser commands (and native
	// since WP3.3d): denied before anything runs.
	for _, c := range []string{"install", "upgrade", "uninstall"} {
		ro(c, "-y")
		sb.expect(1, "", "[ERROR] 'tacctl "+c+" -y' is not permitted for the readonly tier.")
		if len(sb.runner.Execs()) != 0 || sb.runner.Called("git") || sb.runner.Called("systemctl") {
			t.Errorf("%s: ran %q", c, sb.runner.Argvs())
		}
	}
}

func TestCompletionNames(t *testing.T) {
	sb := newSandbox(t, true)
	if got := sb.run("", []string{"_completion-names", "users"}); got != "alice\nbob\ncarol\n" {
		t.Errorf("users: %q", got)
	}
	if got := sb.run("", []string{"_completion-names", "scopes"}); got != "dmz\nlab\nprod\nprod-inner\n" {
		t.Errorf("scopes: %q", got)
	}
	if got := sb.run("", []string{"_completion-names", "bogus"}); got != "" || sb.code != 0 {
		t.Errorf("bogus: %d %q", sb.code, got)
	}
}

func TestHashFamily(t *testing.T) {
	sb := newSandbox(t, false)
	for _, w := range []string{"", "help", "-h", "--help"} {
		args := []string{"hash"}
		if w != "" {
			args = append(args, w)
		}
		if got := sb.run("", args); got != hashUsage() || sb.code != 0 || sb.err.Len() != 0 {
			t.Errorf("%q: %d %q %q", args, sb.code, got, sb.err.String())
		}
	}
	sb.run("", []string{"hash", "bogus"})
	sb.expect(1, "tacctl hash", "[ERROR] Unknown subcommand: 'bogus'")
	out := sb.run("CorrectHorse99\nCorrectHorse99\n", []string{"hash", "generate"})
	m := regexp.MustCompile(`(?m)^  ([0-9a-f]{120})$`).FindStringSubmatch(out)
	if sb.code != 0 || m == nil || hash.Verify("CorrectHorse99", m[1]) != hash.Match || !strings.HasPrefix(m[1], "24326224313224") {
		t.Errorf("hash generate: %d %q", sb.code, out)
	}
	if got := sb.run("", []string{"hash", "commands"}); got != hashRecipes() {
		t.Errorf("hash commands: %q", got)
	}
}

// A writer error is reported as the store dispatcher reports it.
func TestStoreApplyWriterErrorIsReported(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"user", "add", "dave", "operator", "--hash", hash.DisabledMarkerHex, "--scopes", "lab"})
	sb.expect(1, "", "tacctl store: user 'dave': the disabled marker is not a password hash; use disabled=true")
	if strings.Contains(sb.err.String(), "[ERROR] tacctl store") {
		t.Errorf("store error printed with [ERROR]: %q", sb.err.String())
	}
}

// Every user verb has a Spec (its arguments for completion), and every
// kind a Spec names is one completion can answer.
func TestUserSpecs(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	for _, c := range userCmd(inv).Commands() {
		spec, ok := userSpecs[c.Name()]
		if !ok {
			t.Errorf("user %s has no spec", c.Name())
			continue
		}
		kinds := append([]string(nil), spec.Args...)
		for _, f := range spec.Flags {
			kinds = append(kinds, f.Kind)
		}
		for _, k := range kinds {
			k = strings.TrimSuffix(k, KindList)
			if _, native := completionKinds[k]; k != "" && !native && !strings.Contains(k, "|") && k != KindFile {
				t.Errorf("user %s: kind %q is no completion kind", c.Name(), k)
			}
		}
	}
	if len(userSpecs) != len(userCmd(inv).Commands()) {
		t.Errorf("%d specs for %d verbs", len(userSpecs), len(userCmd(inv).Commands()))
	}
}

// testPasswd is the passwd database of the sandboxes ('getent passwd
// <uid>'): tier.VerifyCaller checks SUDO_USER against SUDO_UID's entry.
var testPasswd = map[string]string{"0": "root", "7": "ops", "1000": "tester", "1001": "alice", "1002": "carol", "1003": "bob"}

// fakePasswd answers 'getent passwd <uid>' from testPasswd (exit 2 for an
// unknown uid, as getent does).
func fakePasswd(r *fake.Runner) {
	r.Func(func(c execx.Cmd) bool { return c.Name == "getent" && len(c.Args) == 2 && c.Args[0] == "passwd" },
		func(c execx.Cmd) (execx.Result, error) {
			name, ok := testPasswd[c.Args[1]]
			if !ok {
				return execx.Result{Code: 2}, nil
			}
			return execx.Result{Stdout: []byte(name + ":x:" + c.Args[1] + ":" + c.Args[1] + "::/home/" + name + ":/bin/bash\n")}, nil
		})
}

// A SUDO_USER that is not SUDO_UID's account (a sudoers rule elsewhere with
// SETENV) is refused before any command, root claimed or not; the genuine
// pair runs.
func TestSpoofedSudoUserRefused(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{{"user", "list"}, {"version"}, {"passwd"}, {"host", "list"}, {"ssh", "core-sw1"}, {"device", "list"}} {
		for _, claimed := range []string{"root", "alice", ""} {
			sb.run("", args, "SUDO_USER="+claimed, "SUDO_UID=1003")
			if sb.code != 1 || !strings.Contains(sb.stderr(), "SUDO_USER '"+claimed+"' is not the account of SUDO_UID 1003, so tacctl access is denied.") {
				t.Errorf("%v as %q: exit %d %q", args, claimed, sb.code, sb.stderr())
			}
			if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning") || sb.runner.Called("ssh") {
				t.Errorf("%v as %q: %q", args, claimed, sb.runner.Argvs())
			}
		}
	}
	// The genuine pair (bob is 1003) passes the gate.
	sb.run("", []string{"version"}, "SUDO_USER=bob", "SUDO_UID=1003")
	if sb.code != 0 {
		t.Errorf("bob: exit %d %q", sb.code, sb.stderr())
	}
}
