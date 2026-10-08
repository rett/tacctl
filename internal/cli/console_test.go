package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
)

// 'tacctl console' end to end, in-process, on the sandbox of native_test.go
// (alice superuser, bob operator, carol readonly, all in scope lab). The
// bats file console_cli.bats pins the command line; internal/console's tests
// pin the model.

// consoleSandbox enrols this server (authsrv, --local, scope lab) and lists
// /bin/bash in the sandbox's /etc/shells.
func consoleSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	sb.write("shells", "# /etc/shells\n/bin/sh\n/bin/bash\n", 0o644)
	return sb
}

func (sb *sandbox) con(args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun("", append([]string{"console"}, args...), nil))
}

func (sb *sandbox) consoleYAML() string {
	sb.t.Helper()
	data, err := os.ReadFile(sb.path("state", "console.yaml"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		sb.t.Fatal(err)
	}
	return string(data)
}

func TestConsoleUsageAndUnknown(t *testing.T) {
	sb := consoleSandbox(t)
	for _, args := range [][]string{{"console"}, {"console", "help"}, {"console", "-h"}, {"console", "--help"}} {
		out := plain(sb.cfgRun("", args, nil))
		if sb.code != 0 || !strings.Contains(out, "Usage: tacctl console <subcommand>") || !strings.Contains(out, "system-shell path [<path>]") {
			t.Errorf("%v: exit %d, %q", args, sb.code, out)
		}
	}
	sb.con("frobnicate")
	sb.expect(1, "Usage: tacctl console", "Unknown subcommand: 'frobnicate'")
	if sb.consoleYAML() != "" {
		t.Error("console.yaml written by a usage")
	}
}

func TestConsoleSpecsCoverEveryVerb(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range consoleVerbs {
		w := strings.Fields(v[0])[0]
		seen[w] = true
		s, ok := specFor([]string{"console", w})
		if !ok || !reflect.DeepEqual(s, consoleSpecs[w]) {
			t.Errorf("no spec for 'console %s'", w)
		}
	}
	if len(consoleSpecs) != len(seen) {
		t.Errorf("%d specs for %d verbs", len(consoleSpecs), len(seen))
	}
	c := child(newRoot(&invocation{}), "console")
	if c == nil || len(c.Commands()) != len(seen) {
		t.Fatalf("the console family is not in the tree: %v", c)
	}
	if child(newRoot(&invocation{}), "_console-policy") == nil {
		t.Error("no _console-policy")
	}
}

func TestConsoleShowDefaults(t *testing.T) {
	sb := consoleSandbox(t)
	out := sb.con("show")
	for _, want := range []string{
		"Login console", "  readonly: enable\n  operator: enable\n  engineer: enable\n  superuser: enable\n",
		"  idle-timeout: 30 min\n", "  agent-forwarding: disabled\n", "  ssh-escape: disabled\n",
		"  system-shell tiers: superuser\n", "  system-shell path: /bin/bash\n", "  list-max: 40",
		"Users of authsrv (scope lab)\n",
		"  USERNAME  TIER       SHELL    WHY\n",
		"  alice     superuser  console  tier superuser\n",
		"  bob       operator   console  tier operator\n",
		"  carol     readonly   console  tier readonly\n",
		"/usr/local/bin/tacctl-console: missing", "does not list the console", "sshd drop-in " + sb.path("sshd_config.d", "tacctl-console.conf") + ": missing",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if sb.consoleYAML() != "" {
		t.Error("show wrote console.yaml")
	}
}

func TestConsoleShowNotEnrolled(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.con("show")
	if sb.code != 0 || !strings.Contains(out, "this server is not enrolled (tacctl host enroll --local): no tacctl user has an account here") ||
		strings.Contains(out, "alice") || !strings.Contains(out, "sshd: not checked (no user has the console)") {
		t.Errorf("exit %d:\n%s", sb.code, out)
	}
	if sb.runner.Called("sshd") {
		t.Error("sshd ran with no console user")
	}
}

// The forwarding check: sshd -T through the runner, the red warning when the
// drop-in is missing or forwarding is still on.
func TestConsoleShowSSHDWarning(t *testing.T) {
	sb := consoleSandbox(t)
	sshd := func(tcp string) func(*fake.Runner) {
		return func(r *fake.Runner) {
			r.On([]string{"sshd", "-T"}, execx.Result{Stdout: []byte("port 22\nallowtcpforwarding " + tcp + "\nallowagentforwarding no\n" +
				"forcecommand " + paths.ConsoleCommand + "\npubkeyauthentication no\n")})
		}
	}
	raw := sb.cfgRun("", []string{"console", "show"}, sshd("yes"))
	out := plain(raw)
	if !sb.runner.Called("sshd", "-T", "-C", "user=alice,host=localhost,addr=127.0.0.1") {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
	for _, want := range []string{"sshd for alice: allowtcpforwarding yes, allowagentforwarding no",
		"WARNING: a console user can do more over ssh than the console allows", "drop-in", "is missing", "allowtcpforwarding is 'yes'", "tacctl host sync authsrv"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if !strings.Contains(raw, "\x1b[0;31mWARNING") {
		t.Errorf("the warning is not red: %q", raw)
	}
	// Drop-in present and forwarding closed: no warning.
	sb.write("sshd_config.d/tacctl-console.conf", "Match Group tac-console\n", 0o644)
	out = plain(sb.cfgRun("", []string{"console", "show"}, sshd("no")))
	if strings.Contains(out, "WARNING") || !strings.Contains(out, "tacctl-console.conf: present") {
		t.Errorf("clean server:\n%s", out)
	}
	// Drop-in present, forwarding still on: warned.
	out = plain(sb.cfgRun("", []string{"console", "show"}, sshd("yes")))
	if !strings.Contains(out, "WARNING") || strings.Contains(out, "is missing;") {
		t.Errorf("forwarding on:\n%s", out)
	}
	// sshd that cannot answer: said, not fatal.
	out = plain(sb.cfgRun("", []string{"console", "show"}, func(r *fake.Runner) { r.Fail([]string{"sshd"}, 255, "Missing Match criteria for address") }))
	if sb.code != 0 || !strings.Contains(out, "could not be checked: sshd -T failed: Missing Match criteria for address") {
		t.Errorf("sshd failure: %d\n%s", sb.code, out)
	}
	// With every tier off there is no console user: sshd is not asked.
	sb.con("tiers", "readonly", "disable")
	sb.con("tiers", "operator", "disable")
	sb.con("tiers", "superuser", "disable")
	out = plain(sb.cfgRun("", []string{"console", "show"}, sshd("yes")))
	if strings.Contains(out, "WARNING") || !strings.Contains(out, "sshd: not checked (no user has the console)") {
		t.Errorf("no console users:\n%s", out)
	}
}

func TestConsoleWritesTiersAndUsers(t *testing.T) {
	sb := consoleSandbox(t)
	out := sb.con("tiers", "readonly", "disable")
	if sb.code != 0 || !strings.Contains(out, "The console is disabled for the readonly tier.") || !strings.Contains(out, "Apply to the accounts: tacctl host sync authsrv\n") {
		t.Errorf("tiers: %d %q", sb.code, out)
	}
	out = sb.con("user", "bob", "enable")
	if sb.code != 0 || !strings.Contains(out, "Apply to the accounts: tacctl host sync authsrv") {
		t.Errorf("user: %d %q", sb.code, out)
	}
	sb.con("user", "carol", "disable")
	if got := strings.TrimSpace(sb.con("tiers")); got != "readonly: disable\noperator: enable\nengineer: enable\nsuperuser: enable" {
		t.Errorf("tiers: %q", got)
	}
	if got := strings.TrimSpace(sb.con("user", "bob")); got != "enable" {
		t.Errorf("user bob: %q", got)
	}
	if got := strings.TrimSpace(sb.con("user", "alice")); got != "none" {
		t.Errorf("user alice: %q", got)
	}
	out = sb.con("show")
	for _, want := range []string{"  bob       operator   console  user override\n", "  carol     readonly   bash     user override\n", "  alice     superuser  console  tier superuser\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	// A readonly tier switched off, no override: bash for its users.
	sb.con("user", "carol", "clear")
	out = sb.con("show")
	if !strings.Contains(out, "  carol     readonly   bash     tier readonly disabled\n") {
		t.Errorf("after clear:\n%s", out)
	}
	if out = sb.con("user", "carol", "clear"); !strings.Contains(out, "'carol' has no override.") {
		t.Errorf("clear twice: %q", out)
	}
	st, err := os.Stat(sb.path("state", "console.yaml"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("console.yaml: %v %v", st, err)
	}
	want := `# tacctl login console: which tacctl users get the console as their login shell on this server.
# Edit with 'tacctl console ...'; 'tacctl host sync <this server>' applies the shells.
version: 1
tiers: {readonly: disable, operator: enable, engineer: enable, superuser: enable}
users: {bob: enable}
settings:
  idle_timeout: 30
  agent_forwarding: false
  ssh_escape: false
  system_shell: /bin/bash
  system_shell_tiers: [superuser]
  forwarding_tiers: [superuser]
  gateway_ports: false
  list_max: 40
`
	if y := sb.consoleYAML(); y != want {
		t.Errorf("console.yaml:\n%s\nwant:\n%s", y, want)
	}
	// Every write took a snapshot of the state before it: the later ones hold
	// console.yaml, and backup diff shows it.
	snaps, _ := os.ReadDir(sb.path("state", "backups"))
	var held int
	for _, e := range snaps {
		if _, err := os.Stat(sb.path("state", "backups", e.Name(), "console.yaml")); err == nil {
			held++
		}
	}
	if held == 0 {
		t.Errorf("no snapshot holds console.yaml (%d entries)", len(snaps))
	}
	sb.con("user", "alice", "disable")
	out = plain(sb.cfgRun("", []string{"backup", "diff"}, nil))
	if !strings.Contains(out, "console.yaml") {
		t.Errorf("backup diff:\n%s", out)
	}
}

func TestConsoleWriteNotEnrolled(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.con("tiers", "operator", "disable")
	if sb.code != 0 || !strings.Contains(out, "This server is not enrolled, so no account has the console yet: tacctl host enroll --local") ||
		strings.Contains(out, "host sync") {
		t.Errorf("%d %q", sb.code, out)
	}
}

func TestConsoleSettings(t *testing.T) {
	sb := consoleSandbox(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"idle-timeout"}, "30"},
		{[]string{"agent-forwarding"}, "disabled"},
		{[]string{"ssh-escape"}, "disabled"},
		{[]string{"system-shell", "tiers"}, "superuser"},
		{[]string{"system-shell", "path"}, "/bin/bash"},
	} {
		if got := strings.TrimSpace(sb.con(c.args...)); got != c.want {
			t.Errorf("%v = %q, want %q", c.args, got, c.want)
		}
	}
	out := sb.con("idle-timeout", "15")
	if !strings.Contains(out, "end after 15 minute(s) idle") || strings.Contains(out, "host sync") {
		t.Errorf("idle-timeout: %q", out)
	}
	if got := strings.TrimSpace(sb.con("idle-timeout")); got != "15" {
		t.Errorf("idle-timeout now %q", got)
	}
	sb.con("idle-timeout", "0")
	if got := strings.TrimSpace(sb.con("idle-timeout")); got != "0" || !strings.Contains(sb.con("show"), "idle-timeout: never") {
		t.Errorf("idle-timeout 0: %q", got)
	}
	out = sb.con("agent-forwarding", "enable")
	if !strings.Contains(out, "The sshd drop-in follows it at the next sync.") || !strings.Contains(out, "Apply to the accounts: tacctl host sync authsrv") {
		t.Errorf("agent-forwarding: %q", out)
	}
	if got := strings.TrimSpace(sb.con("agent-forwarding")); got != "enabled" {
		t.Errorf("agent-forwarding now %q", got)
	}
	sb.con("ssh-escape", "enable")
	if got := strings.TrimSpace(sb.con("ssh-escape")); got != "enabled" {
		t.Errorf("ssh-escape now %q", got)
	}
	sb.con("system-shell", "tiers", "operator,superuser")
	if got := strings.TrimSpace(sb.con("system-shell", "tiers")); got != "operator,superuser" {
		t.Errorf("tiers now %q", got)
	}
	sb.con("system-shell", "tiers", "none")
	if got := strings.TrimSpace(sb.con("system-shell", "tiers")); got != "none" {
		t.Errorf("tiers now %q", got)
	}
	sb.write("shells", "/bin/bash\n/bin/sh\n", 0o644)
	sb.con("system-shell", "path", "/bin/sh")
	if sb.code != 0 || strings.TrimSpace(sb.con("system-shell", "path")) != "/bin/sh" {
		t.Errorf("path: %d", sb.code)
	}
}

func TestConsoleRefusals(t *testing.T) {
	sb := consoleSandbox(t)
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"tiers", "root", "enable"}, "Unknown tier 'root'"},
		{[]string{"tiers", "readonly", "maybe"}, "Usage: tacctl console tiers"},
		{[]string{"tiers", "readonly", "enable", "x"}, "Unknown argument: 'x'"},
		{[]string{"user"}, "expected at least 1 argument(s), got 0"},
		{[]string{"user", "zed", "enable"}, "User 'zed' does not exist."},
		{[]string{"user", "bob", "maybe"}, "Usage: tacctl console user"},
		{[]string{"idle-timeout", "1441"}, "expected 0-1440"},
		{[]string{"idle-timeout", "abc"}, "Invalid number of minutes 'abc'"},
		{[]string{"idle-timeout", "-5"}, "Unknown flag: '-5'"},
		{[]string{"idle-timeout", "07"}, "Invalid number of minutes '07'"},
		{[]string{"idle-timeout", "1", "2"}, "Unknown argument: '2'"},
		{[]string{"agent-forwarding", "yes"}, "Usage: tacctl console agent-forwarding"},
		{[]string{"ssh-escape", "on"}, "Usage: tacctl console ssh-escape"},
		{[]string{"system-shell"}, "expected at least 1 argument(s), got 0"},
		{[]string{"system-shell", "mode"}, "Usage: tacctl console system-shell"},
		{[]string{"system-shell", "tiers", "superuser,superuser"}, "Tier 'superuser' is listed twice."},
		{[]string{"system-shell", "tiers", "root"}, "Unknown tier 'root'"},
		{[]string{"system-shell", "tiers", "operator,none"}, "Unknown tier 'none'"},
		{[]string{"system-shell", "path", "bash"}, "must be an absolute path"},
		{[]string{"system-shell", "path", "/bin/../bin/bash"}, "must be an absolute path"},
		{[]string{"system-shell", "path", "/nonexistent/sh"}, "is not an existing file"},
		{[]string{"system-shell", "path", "/etc"}, "is not an existing file"},
		{[]string{"system-shell", "path", "/etc/hostname"}, "not executable"},
		{[]string{"show", "now"}, "Unknown argument: 'now'"},
	} {
		sb.con(c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%v: exit %d, stderr %q (want %q)", c.args, sb.code, sb.stderr(), c.err)
		}
	}
	// A shell that is not in /etc/shells.
	sb.write("shells", "/bin/sh\n", 0o644)
	sb.con("system-shell", "path", "/bin/bash")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'/bin/bash' is not listed in "+sb.path("shells")+".") {
		t.Errorf("unlisted: %d %q", sb.code, sb.stderr())
	}
	if sb.consoleYAML() != "" {
		t.Errorf("a refused verb wrote console.yaml:\n%s", sb.consoleYAML())
	}
	if len(sb.runner.Calls()) > 0 && sb.runner.Called("sshd") {
		t.Error("sshd ran")
	}
	// A hand-edited file that is wrong: every verb says so, nothing is rewritten.
	sb.write("state/console.yaml", "version: 1\nsettings: {system_shell: bash}\n", 0o600)
	sb.con("show")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "settings.system_shell: The system shell must be an absolute path") {
		t.Errorf("bad file: %d %q", sb.code, sb.stderr())
	}
}

// Lower tiers: show is the operator's, the writes are administrators'.
func TestConsoleTierGate(t *testing.T) {
	sb := consoleSandbox(t)
	as := func(user, group string, args ...string) {
		sb.cfgRun("", args, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user))
	}
	as("carol", "readonly", "console", "show")
	sb.expect(1, "", "'tacctl console show' is not permitted for the readonly tier.")
	as("bob", "operator", "console", "show")
	sb.expect(0, "Login console", "")
	as("bob", "operator", "console", "tiers", "readonly", "disable")
	sb.expect(1, "", "'tacctl console tiers' is not permitted for the operator tier.")
	as("bob", "operator", "console")
	sb.expect(1, "", "is not permitted for the operator tier")
	as("alice", "superuser", "console", "idle-timeout", "10")
	sb.expect(0, "", "")
}

func uidOf(user string) string {
	for uid, name := range testPasswd {
		if name == user {
			return uid
		}
	}
	return ""
}

func TestConsolePolicyLinePerTier(t *testing.T) {
	sb := consoleSandbox(t)
	policy := func(user, group string, env ...string) string {
		sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
			if group != "" {
				r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
			}
		}, append([]string{"SUDO_USER=" + user, "SUDO_UID=" + uidOf(user)}, env...)...)
		return strings.TrimSpace(plain(sb.out.String()))
	}
	const tail = " ssh_escape=no agent=no"
	for _, c := range []struct{ user, group, want string }{
		{"alice", "superuser", "shell=console idle=30 system_shell=yes system_shell_path=/bin/bash" + tail + " forward=yes tier=superuser list_max=40"},
		{"bob", "operator", "shell=console idle=30 system_shell=no system_shell_path=/bin/bash" + tail + " forward=no tier=operator list_max=40"},
		{"carol", "readonly", "shell=console idle=30 system_shell=no system_shell_path=/bin/bash" + tail + " forward=no tier=readonly list_max=40"},
	} {
		if got := policy(c.user, c.group); got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.user, got, c.want)
		}
	}
	// In tac-users with no tacctl user: the tier gate denies it everything,
	// so the console falls back to its defaults.
	if got := policy("ops", "readonly"); got != "" || sb.code != 1 || !strings.Contains(sb.stderr(), "'ops' has no active tacctl user, so tacctl access is denied.") {
		t.Errorf("none: %d %q %q", sb.code, got, sb.stderr())
	}
	// Not in tac-users: unrestricted, system shell yes.
	if got := policy("tester", ""); got != "shell=system idle=30 system_shell=yes system_shell_path=/bin/bash"+tail+" forward=yes tier=unrestricted list_max=40" {
		t.Errorf("unrestricted: %q", got)
	}
	// The logged line (auth.info) carries the session marker.
	policy("alice", "superuser", "TACCTL_CONSOLE=0123456789ab")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "console policy user=alice tier=superuser system_shell=yes session=0123456789ab") {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
	// Settings and overrides change the line.
	sb.con("system-shell", "tiers", "readonly")
	sb.con("user", "carol", "disable")
	sb.con("idle-timeout", "5")
	sb.con("ssh-escape", "enable")
	sb.con("agent-forwarding", "enable")
	if got := policy("carol", "readonly"); got != "shell=system idle=5 system_shell=yes system_shell_path=/bin/bash ssh_escape=yes agent=yes forward=no tier=readonly list_max=40" {
		t.Errorf("carol after changes: %q", got)
	}
	if got := policy("alice", "superuser"); !strings.Contains(got, "system_shell=no") {
		t.Errorf("alice after tiers=readonly: %q", got)
	}
	// A system shell that cannot run is no system shell.
	sb.write("shells", "/bin/sh\n", 0o644)
	if got := policy("carol", "readonly"); !strings.Contains(got, "system_shell=no") {
		t.Errorf("unlisted shell: %q", got)
	}
	if !sb.runner.CalledRegexp(`^logger -t tacctl -p auth.warning console policy system_shell /bin/bash unusable: `) {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
}

// With no console.yaml the policy of a user who has no tier (root running
// it, no SUDO_USER) is the unrestricted one and logs as root.
func TestConsolePolicyRoot(t *testing.T) {
	sb := consoleSandbox(t)
	sb.cfgRun("", []string{"_console-policy"}, nil)
	if got := strings.TrimSpace(plain(sb.out.String())); !strings.Contains(got, "tier=unrestricted") || !strings.Contains(got, "system_shell=yes") {
		t.Errorf("root: %q", got)
	}
	if !sb.runner.CalledRegexp(`^logger -t tacctl -p auth.info console policy user=root tier=unrestricted `) {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
}

// A snapshot that holds console.yaml brings it back with the restore; one
// without it (an older snapshot) leaves the live file alone.
func TestConsoleYAMLRestore(t *testing.T) {
	sb := renderedSandbox(t)
	minimal := fixture(t, "store.minimal.yaml")
	sb.mkSnapshot("20250101_000000_000", minimal, "")
	sb.mkSnapshot("20250101_000000_001", minimal, "")
	snapText := "version: 1\nsettings: {idle_timeout: 7}\n"
	sb.write("state/backups/20250101_000000_001/console.yaml", snapText, 0o600)
	sb.write("state/console.yaml", "version: 1\nsettings: {idle_timeout: 99}\n", 0o600)

	sb.run("y\n", []string{"backup", "restore", "20250101_000000_000"})
	sb.expect(0, "Restored snapshot 20250101_000000_000.", "")
	if got := sb.read("state/console.yaml"); !strings.Contains(got, "idle_timeout: 99") {
		t.Errorf("a snapshot without console.yaml changed the live one:\n%s", got)
	}
	sb.run("y\n", []string{"backup", "restore", "20250101_000000_001"})
	sb.expect(0, "Restored snapshot 20250101_000000_001.", "")
	if got := sb.read("state/console.yaml"); got != snapText {
		t.Errorf("console.yaml after restore:\n%s", got)
	}
	if st, err := os.Stat(sb.path("state/console.yaml")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", st, err)
	}
}
