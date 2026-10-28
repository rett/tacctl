package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
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
	for _, args := range [][]string{{"console", "-h"}, {"console", "--help"}} {
		out := plain(sb.cfgRun("", args, nil))
		if sb.code != 0 || !strings.HasPrefix(out, "Possible completions:\n") || !strings.Contains(out, "  forget ") {
			t.Errorf("%v: exit %d, %q", args, sb.code, out)
		}
	}
	for _, args := range [][]string{{"console"}, {"console", "help"}} {
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
		"Login console", "Every user of every tier has the console as login shell on this server.\n",
		"  idle-timeout: 30 min\n", "  agent-forwarding: disabled\n", "  ssh-escape: disabled\n",
		"  system-shell path: /bin/bash\n", "  space-completion: on (", "  list-max: 40",
		"System shell (the console's own word, for the tiers and users that have it):\n" +
			"  readonly: disabled\n  operator: disabled\n  engineer: disabled (never)\n  superuser: enabled (always)\n",
		"Users of authsrv (scope lab)\n",
		"  USERNAME  TIER       SHELL    WHY           SYSTEM SHELL\n",
		"  alice     superuser  console  managed user  enabled (always)\n",
		"  bob       operator   console  managed user  disabled (tier operator)\n",
		"  carol     readonly   console  managed user  disabled (tier readonly)\n",
		sb.consoleCommand() + ": missing", "does not list the console", "sshd drop-in " + sb.path("sshd_config.d", "tacctl-console.conf") + ": missing",
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
				"forcecommand " + sb.consoleCommand() + "\npubkeyauthentication no\n")})
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
}

// There is no switch for the console: the verbs 'tiers' and 'user' are gone
// (an unknown sub-command, with the usage), and the file a setting writes
// has no tiers and no users mapping.
func TestConsoleHasNoSwitch(t *testing.T) {
	sb := consoleSandbox(t)
	for _, args := range [][]string{{"tiers"}, {"tiers", "readonly", "disable"}, {"user", "bob", "enable"}, {"user", "bob"}} {
		out := sb.con(args...)
		sb.expect(1, "Usage: tacctl console <subcommand>", "Unknown subcommand: '"+args[0]+"'")
		if strings.Contains(out, "\n  tiers [<tier>") || strings.Contains(out, "\n  user <name>") {
			t.Errorf("%v: the usage still lists the verb:\n%s", args, out)
		}
	}
	if sb.consoleYAML() != "" {
		t.Errorf("a refused verb wrote console.yaml:\n%s", sb.consoleYAML())
	}
	sb.con("idle-timeout", "20")
	want := `# tacctl login console: which tacctl users get the console as their login shell on this server.
# Edit with 'tacctl console ...'; 'tacctl host sync <this server>' applies the shells.
version: 1
settings:
  idle_timeout: 20
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
	st, err := os.Stat(sb.path("state", "console.yaml"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("console.yaml: %v %v", st, err)
	}
	// Every write took a snapshot of the state before it: the later ones hold
	// console.yaml, and backup diff shows it.
	sb.con("idle-timeout", "25")
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
	out := plain(sb.cfgRun("", []string{"backup", "diff"}, nil))
	if !strings.Contains(out, "console.yaml") {
		t.Errorf("backup diff:\n%s", out)
	}
}

// A console.yaml written before 0.2.20 has a switch per tier and per user.
// They are ignored: every user of every tier has the console in 'console
// show' and in the policy line, no listing mentions them, and a write of
// another setting leaves them in the file.
func TestConsoleIgnoresStoredSwitches(t *testing.T) {
	sb := consoleSandbox(t)
	const old = "version: 1\ntiers: {readonly: disable, operator: disable, engineer: disable, superuser: disable}\nusers: {bob: disable, carol: disable, ghost: enable}\n"
	sb.write("state/console.yaml", old, 0o600)
	out := sb.con("show")
	for _, w := range []string{
		"  alice     superuser  console  managed user  enabled (always)\n",
		"  bob       operator   console  managed user  disabled (tier operator)\n",
		"  carol     readonly   console  managed user  disabled (tier readonly)\n",
	} {
		if !strings.Contains(out, w) {
			t.Errorf("show lacks %q:\n%s", w, out)
		}
	}
	for _, not := range []string{"ghost", "override", "ignored", "bash "} {
		if strings.Contains(out, not) {
			t.Errorf("show mentions %q:\n%s", not, out)
		}
	}
	for user, group := range map[string]string{"alice": "superuser", "bob": "operator", "carol": "readonly"} {
		line := plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user)))
		if !strings.HasPrefix(line, "shell=console ") {
			t.Errorf("%s: policy line %q", user, line)
		}
	}
	sb.con("idle-timeout", "20")
	y := sb.consoleYAML()
	for _, w := range []string{"tiers: {readonly: disable, operator: disable, engineer: disable, superuser: disable}", "users: {bob: disable, carol: disable, ghost: enable}", "idle_timeout: 20"} {
		if !strings.Contains(y, w) {
			t.Errorf("console.yaml lost %q:\n%s", w, y)
		}
	}
}

func TestConsoleWriteNotEnrolled(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.con("agent-forwarding", "enable")
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
		{[]string{"space-completion"}, "on"},
		{[]string{"system-shell", "operator"}, "disabled"},
		{[]string{"system-shell", "superuser"}, "enabled (always)"},
		{[]string{"system-shell", "engineer"}, "disabled (never)"},
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
	// space-completion: on by default and then not in the file; off is
	// written and shown; on again removes the key.
	if y := sb.consoleYAML(); strings.Contains(y, "space_completion") {
		t.Errorf("console.yaml has the key while on:\n%s", y)
	}
	out = sb.con("space-completion", "off")
	if sb.code != 0 || !strings.Contains(out, "ordinary space") || !strings.Contains(out, "next console login") || strings.Contains(out, "host sync") {
		t.Errorf("space-completion off: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("space-completion")); got != "off" || !strings.Contains(sb.con("show"), "  space-completion: off (") {
		t.Errorf("space-completion now %q", got)
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  space_completion: false\n") {
		t.Errorf("console.yaml lacks the key while off:\n%s", y)
	}
	out = sb.con("space-completion", "on")
	if !strings.Contains(out, "completes a fixed word") {
		t.Errorf("space-completion on: %q", out)
	}
	if y := sb.consoleYAML(); strings.Contains(y, "space_completion") || strings.TrimSpace(sb.con("space-completion")) != "on" {
		t.Errorf("space-completion on again:\n%s", y)
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
		{[]string{"idle-timeout", "1441"}, "expected 0-1440"},
		{[]string{"idle-timeout", "abc"}, "Invalid number of minutes 'abc'"},
		{[]string{"idle-timeout", "-5"}, "Unknown flag: '-5'"},
		{[]string{"idle-timeout", "07"}, "Invalid number of minutes '07'"},
		{[]string{"idle-timeout", "1", "2"}, "Unknown argument: '2'"},
		{[]string{"agent-forwarding", "yes"}, "Usage: tacctl console agent-forwarding"},
		{[]string{"ssh-escape", "on"}, "Usage: tacctl console ssh-escape"},
		{[]string{"space-completion", "enable"}, "Usage: tacctl console space-completion"},
		{[]string{"space-completion", "on", "off"}, "Unknown argument: 'off'"},
		{[]string{"system-shell", "mode"}, "Unknown tier 'mode'"},
		{[]string{"system-shell", "tiers", "superuser"}, "Unknown tier 'tiers'"},
		{[]string{"system-shell", "root", "enable"}, "Unknown tier 'root'"},
		{[]string{"system-shell", "operator", "maybe"}, "Usage: tacctl console system-shell"},
		{[]string{"system-shell", "operator", "enable", "x"}, "Unknown argument: 'x'"},
		{[]string{"system-shell", "user"}, "expected at least 1 argument(s), got 0"},
		{[]string{"system-shell", "user", "zed"}, "User 'zed' does not exist."},
		{[]string{"system-shell", "user", "zed", "enable"}, "User 'zed' does not exist."},
		{[]string{"system-shell", "user", "bob", "maybe"}, "Usage: tacctl console system-shell"},
		{[]string{"system-shell", "user", "bob", "enable", "x"}, "Unknown argument: 'x'"},
		{[]string{"system-shell", "path", "/bin/bash", "x"}, "Unknown argument: 'x'"},
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
	as("bob", "operator", "console", "idle-timeout", "10")
	sb.expect(1, "", "'tacctl console idle-timeout' is not permitted for the operator tier.")
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
		{"alice", "superuser", "shell=console idle=30 system_shell=yes system_shell_path=/bin/bash" + tail + " forward=yes tier=superuser list_max=40 space_completion=yes color=auto"},
		{"bob", "operator", "shell=console idle=30 system_shell=no system_shell_path=/bin/bash" + tail + " forward=no tier=operator list_max=40 space_completion=yes color=auto"},
		{"carol", "readonly", "shell=console idle=30 system_shell=no system_shell_path=/bin/bash" + tail + " forward=no tier=readonly list_max=40 space_completion=yes color=auto"},
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
	if got := policy("tester", ""); got != "shell=system idle=30 system_shell=yes system_shell_path=/bin/bash"+tail+" forward=yes tier=unrestricted list_max=40 space_completion=yes color=auto" {
		t.Errorf("unrestricted: %q", got)
	}
	// The logged line (auth.info) carries the session marker.
	policy("alice", "superuser", "TACCTL_CONSOLE=0123456789ab")
	if !hasAudit(sb.runner, "auth.info", "console policy user=alice tier=superuser system_shell=yes session=0123456789ab") {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
	// A marker that is no session id (the caller sets the variable through
	// sudo's env_keep) is logged as '-', never as it is.
	for _, bad := range []string{"x\ninjected line", "../etc", "0123456789AB", "0123456789abc", "evil user=root"} {
		policy("alice", "superuser", "TACCTL_CONSOLE="+bad)
		if !hasAudit(sb.runner, "auth.info", "console policy user=alice tier=superuser system_shell=yes session=-") {
			t.Errorf("marker %q: calls %q", bad, sb.runner.Argvs())
		}
		for _, a := range sb.runner.Argvs() {
			if strings.Contains(a, "injected") || strings.Contains(a, "evil") {
				t.Errorf("marker %q reached the log: %q", bad, a)
			}
		}
	}
	// Settings change the line.
	sb.con("system-shell", "user", "carol", "enable")
	sb.con("idle-timeout", "5")
	sb.con("ssh-escape", "enable")
	sb.con("agent-forwarding", "enable")
	if got := policy("carol", "readonly"); got != "shell=console idle=5 system_shell=yes system_shell_path=/bin/bash ssh_escape=yes agent=yes forward=no tier=readonly list_max=40 space_completion=yes color=auto" {
		t.Errorf("carol after changes: %q", got)
	}
	if got := policy("alice", "superuser"); !strings.Contains(got, "system_shell=yes") {
		t.Errorf("alice after carol's setting: %q", got)
	}
	if got := policy("bob", "operator"); !strings.Contains(got, "system_shell=no") {
		t.Errorf("bob after carol's setting: %q", got)
	}
	sb.con("space-completion", "off")
	if got := policy("alice", "superuser"); !strings.HasSuffix(got, " list_max=40 space_completion=no color=auto") {
		t.Errorf("after space-completion off: %q", got)
	}
	sb.con("space-completion", "on")
	// The colour and the list threshold of 0.2.20 are in the line.
	sb.con("color", "on")
	sb.con("list-max", "-3")
	if got := policy("alice", "superuser"); !strings.HasSuffix(got, " list_max=-1 space_completion=yes color=on") {
		t.Errorf("after color on and list-max -3: %q", got)
	}
	sb.con("color", "auto")
	sb.con("list-max", "0")
	// A system shell that cannot run is no system shell.
	sb.write("shells", "/bin/sh\n", 0o644)
	if got := policy("carol", "readonly"); !strings.Contains(got, "system_shell=no") {
		t.Errorf("unlisted shell: %q", got)
	}
	if !hasAuditMatch(sb.runner, "auth.warning", `console policy system_shell /bin/bash unusable: `) {
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
	if !hasAuditMatch(sb.runner, "auth.info", `shell policy user=root tier=unrestricted`) {
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

// The engineer tier has the console or no login on this server (B2): like
// every tier it has the console, and a stored switch cannot turn it off.
func TestConsoleEngineerHasTheConsole(t *testing.T) {
	sb := consoleSandbox(t)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	sb.write("state/console.yaml", "version: 1\ntiers: {readonly: enable, operator: enable, engineer: disable, superuser: enable}\nusers: {bob: disable}\n", 0o600)
	out := sb.con("show")
	if w := "  bob       engineer   console  managed user  disabled (never)\n"; !strings.Contains(out, w) {
		t.Errorf("show lacks %q:\n%s", w, out)
	}
	out = plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users\n")})
	}, "SUDO_USER=bob"))
	if !strings.HasPrefix(out, "shell=console ") || !strings.Contains(out, " tier=engineer ") {
		t.Errorf("policy line %q", out)
	}
}

// 'console color [auto|on|off]' and 'console list-max [<n>]': shown, set
// server-wide, written to the file only when set (the colour) or as the
// number (list_max), and listed by 'console show'.
func TestConsoleColorAndListMax(t *testing.T) {
	sb := consoleSandbox(t)
	for _, c := range []struct {
		args []string
		want string
	}{{[]string{"color"}, "auto"}, {[]string{"list-max"}, "40"}} {
		if got := strings.TrimSpace(sb.con(c.args...)); got != c.want {
			t.Errorf("%v = %q, want %q", c.args, got, c.want)
		}
	}
	if y := sb.consoleYAML(); strings.Contains(y, "color") {
		t.Errorf("console.yaml has the colour while auto:\n%s", y)
	}
	for mode, want := range map[string]string{"on": "always in colour", "off": "never in colour"} {
		out := sb.con("color", mode)
		if sb.code != 0 || !strings.Contains(out, "next console login") || strings.Contains(out, "host sync") {
			t.Errorf("color %s: %d %q", mode, sb.code, out)
		}
		if got := strings.TrimSpace(sb.con("color")); got != mode || !strings.Contains(sb.con("show"), "  color: "+mode+" (the console's lists: "+want+")") {
			t.Errorf("color now %q", got)
		}
		wantKey := map[string]string{"on": "\n  color: true\n", "off": "\n  color: false\n"}[mode]
		if y := sb.consoleYAML(); !strings.Contains(y, wantKey) {
			t.Errorf("console.yaml lacks %q:\n%s", wantKey, y)
		}
	}
	sb.con("color", "auto")
	if y := sb.consoleYAML(); strings.Contains(y, "color") || strings.TrimSpace(sb.con("color")) != "auto" {
		t.Errorf("auto again:\n%s", y)
	}
	for _, args := range [][]string{{"color", "blue"}, {"color", "on", "off"}, {"color", "ON"}} {
		sb.con(args...)
		if sb.code != 1 {
			t.Errorf("console %v: exit %d", args, sb.code)
		}
	}
	if strings.Contains(sb.stderr(), "panic") {
		t.Error("panic")
	}

	// list-max: a number, 0 for the default, a negative one never asks.
	for _, c := range []struct{ arg, stored, shown string }{
		{"25", "25", "25"}, {"0", "40", "40"}, {"1000", "1000", "1000"}, {"1", "1", "1"}, {"-1", "-1", "never ask"}, {"-7", "-1", "never ask"},
	} {
		out := sb.con("list-max", c.arg)
		if sb.code != 0 || !strings.Contains(out, "next console login") {
			t.Errorf("list-max %s: %d %q", c.arg, sb.code, out)
		}
		if got := strings.TrimSpace(sb.con("list-max")); got != c.shown {
			t.Errorf("list-max %s: now %q, want %q (as 'console show' says it)", c.arg, got, c.shown)
		}
		if !strings.Contains(sb.con("show"), "  list-max: "+c.shown+" (") {
			t.Errorf("list-max %s: show lacks %q", c.arg, c.shown)
		}
		if y := sb.consoleYAML(); !strings.Contains(y, "\n  list_max: "+c.stored+"\n") {
			t.Errorf("list-max %s: console.yaml:\n%s", c.arg, y)
		}
	}
	if out := sb.con("list-max", "-3"); !strings.Contains(out, "without asking") {
		t.Errorf("list-max -3: %q", out)
	}
	for _, args := range [][]string{{"list-max", "1001"}, {"list-max", "x"}, {"list-max", "1", "2"}, {"list-max", "1.5"}} {
		before := sb.consoleYAML()
		sb.con(args...)
		if sb.code != 1 || sb.consoleYAML() != before {
			t.Errorf("console %v: exit %d, file changed %v", args, sb.code, sb.consoleYAML() != before)
		}
	}
}

// 'console system-shell' with no argument lists each tier (the superuser
// tier always, the engineer tier never), '<tier>' prints one, '<tier> enable|
// disable' sets it and is written as the list the older releases read, with
// the superuser tier always among them.
func TestConsoleSystemShellPerTier(t *testing.T) {
	sb := consoleSandbox(t)
	const defaults = "readonly: disabled\noperator: disabled\nengineer: disabled (never)\nsuperuser: enabled (always)"
	if got := strings.TrimSpace(sb.con("system-shell")); got != defaults {
		t.Errorf("defaults:\n%s", got)
	}
	if sb.consoleYAML() != "" {
		t.Error("a listing wrote console.yaml")
	}
	out := sb.con("system-shell", "operator", "enable")
	if sb.code != 0 || !strings.Contains(out, "system-shell is enabled for the operator tier. It applies from the next console login.") {
		t.Errorf("enable operator: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("system-shell", "operator")); got != "enabled" {
		t.Errorf("operator: %q", got)
	}
	sb.con("system-shell", "readonly", "enable")
	want := "readonly: enabled\noperator: enabled\nengineer: disabled (never)\nsuperuser: enabled (always)"
	if got := strings.TrimSpace(sb.con("system-shell")); got != want {
		t.Errorf("both:\n%s", got)
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  system_shell_tiers: [readonly, operator, superuser]\n") || strings.Contains(y, "system_shell_users") {
		t.Errorf("console.yaml:\n%s", y)
	}
	// The policy line follows: bob and carol have it now.
	for user, group := range map[string]string{"bob": "operator", "carol": "readonly"} {
		line := plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user)))
		if !strings.Contains(line, " system_shell=yes ") {
			t.Errorf("%s: %q", user, line)
		}
	}
	sb.con("system-shell", "operator", "disable")
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  system_shell_tiers: [readonly, superuser]\n") {
		t.Errorf("after disable:\n%s", y)
	}

	// The superuser tier cannot be disabled, the engineer tier cannot be
	// enabled, and neither writes anything.
	before := sb.consoleYAML()
	sb.con("system-shell", "superuser", "disable")
	sb.expect(1, "", "The superuser tier always has the system shell; it cannot be disabled. Nothing was changed.")
	sb.con("system-shell", "engineer", "enable")
	sb.expect(1, "", "The engineer tier cannot be given the system shell on this server: a shell here would reach the server's secrets. Nothing was changed.")
	if out = sb.con("system-shell", "engineer", "disable"); sb.code != 0 || !strings.Contains(out, "The engineer tier never has the system shell. Nothing was changed.") {
		t.Errorf("engineer disable: %d %q", sb.code, out)
	}
	if out = sb.con("system-shell", "superuser", "enable"); sb.code != 0 || !strings.Contains(out, "system-shell is enabled for the superuser tier.") {
		t.Errorf("superuser enable: %d %q", sb.code, out)
	}
	if sb.consoleYAML() != before {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
	// A hand-edited list without the superuser tier is read as having it, and
	// the next write puts it back.
	sb.write("state/console.yaml", "version: 1\nsettings: {system_shell_tiers: []}\n", 0o600)
	if got := strings.TrimSpace(sb.con("system-shell")); got != defaults {
		t.Errorf("empty list:\n%s", got)
	}
	sb.con("system-shell", "operator", "enable")
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  system_shell_tiers: [operator, superuser]\n") {
		t.Errorf("rewritten:\n%s", y)
	}
}

// 'console system-shell user <name> [enable|disable|clear]': a user's setting
// beats the tier's in both directions and is listed with the user's tier and
// in 'console show'; a superuser cannot be disabled, an engineer cannot be
// enabled, and a setting that could count for nothing is not stored.
func TestConsoleSystemShellPerUser(t *testing.T) {
	sb := consoleSandbox(t)
	out := sb.con("system-shell", "user", "carol", "enable")
	if sb.code != 0 || !strings.Contains(out, "system-shell is enabled for 'carol'.") {
		t.Errorf("enable carol: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("system-shell", "user", "carol")); got != "enabled (user setting)" {
		t.Errorf("carol: %q", got)
	}
	if got := strings.TrimSpace(sb.con("system-shell", "user", "bob")); got != "disabled (tier operator)" {
		t.Errorf("bob: %q", got)
	}
	if got := strings.TrimSpace(sb.con("system-shell", "user", "alice")); got != "enabled (always)" {
		t.Errorf("alice: %q", got)
	}
	// Enabled for the operator tier, taken from one user of it.
	sb.con("system-shell", "operator", "enable")
	sb.con("system-shell", "user", "bob", "disable")
	if got := strings.TrimSpace(sb.con("system-shell", "user", "bob")); got != "disabled (user setting)" {
		t.Errorf("bob: %q", got)
	}
	list := strings.TrimSpace(sb.con("system-shell"))
	for _, w := range []string{"readonly: disabled\noperator: enabled\nengineer: disabled (never)\nsuperuser: enabled (always)\n\nUsers with a setting of their own:\n",
		"  bob: disabled (operator)\n", "  carol: enabled (readonly)"} {
		if !strings.Contains(list+"\n", w) {
			t.Errorf("listing lacks %q:\n%s", w, list)
		}
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "\n  system_shell_users: {bob: false, carol: true}\n") {
		t.Errorf("console.yaml:\n%s", y)
	}
	show := sb.con("show")
	for _, w := range []string{
		"  alice     superuser  console  managed user  enabled (always)\n",
		"  bob       operator   console  managed user  disabled (user setting)\n",
		"  carol     readonly   console  managed user  enabled (user setting)\n",
	} {
		if !strings.Contains(show, w) {
			t.Errorf("show lacks %q:\n%s", w, show)
		}
	}
	// The policy line: carol has it, bob has not, though his tier has it.
	line := func(user, group string) string {
		return plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user)))
	}
	if got := line("carol", "readonly"); !strings.Contains(got, " system_shell=yes ") {
		t.Errorf("carol: %q", got)
	}
	if got := line("bob", "operator"); !strings.Contains(got, " system_shell=no ") {
		t.Errorf("bob: %q", got)
	}
	// clear: the tier decides again.
	sb.con("system-shell", "user", "bob", "clear")
	if got := line("bob", "operator"); !strings.Contains(got, " system_shell=yes ") {
		t.Errorf("bob after clear: %q", got)
	}
	if out = sb.con("system-shell", "user", "bob", "clear"); !strings.Contains(out, "'bob' has no system-shell setting of their own.") {
		t.Errorf("clear twice: %q", out)
	}
	sb.con("system-shell", "user", "carol", "clear")
	if y := sb.consoleYAML(); strings.Contains(y, "system_shell_users") {
		t.Errorf("the key is left while empty:\n%s", y)
	}

	// Refusals; nothing is written for any of them.
	before := sb.consoleYAML()
	sb.con("system-shell", "user", "alice", "disable")
	sb.expect(1, "", "'alice' is a superuser, and superusers always have the system shell; it cannot be disabled. Nothing was changed.")
	if out = sb.con("system-shell", "user", "alice", "enable"); sb.code != 0 || !strings.Contains(out, "'alice' is a superuser, who always has the system shell. Nothing was changed.") {
		t.Errorf("alice enable: %d %q", sb.code, out)
	}
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	sb.con("system-shell", "user", "bob", "enable")
	sb.expect(1, "", "The engineer tier cannot be given the system shell on this server: a shell here would reach the server's secrets. Nothing was changed.")
	if out = sb.con("system-shell", "user", "bob", "disable"); sb.code != 0 || !strings.Contains(out, "'bob' is an engineer, who never has the system shell. Nothing was changed.") {
		t.Errorf("bob disable: %d %q", sb.code, out)
	}
	if got := strings.TrimSpace(sb.con("system-shell", "user", "bob")); got != "disabled (never)" {
		t.Errorf("engineer bob: %q", got)
	}
	if sb.consoleYAML() != before {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}

	// A setting of a user who is gone stays (a rename does not move it, a
	// removal does not drop it) and is listed, and the policy never reads it
	// for another name; clear removes it.
	sb.write("state/console.yaml", "version: 1\nsettings: {system_shell_users: {ghost: true}}\n", 0o600)
	list = strings.TrimSpace(sb.con("system-shell"))
	if !strings.Contains(list, "  ghost: enabled (no such user)") {
		t.Errorf("listing:\n%s", list)
	}
	if got := strings.TrimSpace(sb.con("system-shell", "user", "ghost")); got != "enabled (user setting; no such user)" {
		t.Errorf("ghost: %q", got)
	}
	if show = sb.con("show"); !strings.Contains(show, "System-shell settings of users that have no account here: ghost: enabled") {
		t.Errorf("show:\n%s", show)
	}
	sb.con("system-shell", "user", "ghost", "clear")
	if sb.code != 0 || strings.Contains(sb.consoleYAML(), "ghost") {
		t.Errorf("clear ghost: %d\n%s", sb.code, sb.consoleYAML())
	}
}

// Only a superuser sets the system shell, for a tier or a user, or its path:
// an operator and an engineer read each form (the list, one tier, one user,
// the path) and are refused each form that sets something (the refusal is
// logged as a tier denial), a readonly user is refused all of it at the gate,
// and the superuser is not refused.
func TestConsoleSystemShellIsTheSuperusersToSet(t *testing.T) {
	sb := consoleSandbox(t)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600) // bob is an engineer
	as := func(user, group string, args ...string) {
		sb.cfgRun("", append([]string{"console", "system-shell"}, args...), func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user))
	}
	writes := [][]string{
		{"operator", "enable"}, {"readonly", "disable"}, {"engineer", "enable"}, {"superuser", "disable"},
		{"user", "carol", "enable"}, {"user", "carol", "disable"}, {"user", "carol", "clear"}, {"path", "/bin/sh"},
	}
	reads := []struct {
		args []string
		want string
	}{
		{nil, "superuser: enabled (always)"}, {[]string{"readonly"}, "disabled"}, {[]string{"operator"}, "disabled"},
		{[]string{"engineer"}, "disabled (never)"}, {[]string{"superuser"}, "enabled (always)"},
		{[]string{"user", "carol"}, "disabled (tier readonly)"}, {[]string{"path"}, "/bin/bash"},
	}
	for _, who := range []struct{ user, group, tier string }{{"bob", "operator", "engineer"}, {"carol", "readonly", "readonly"}} {
		for _, r := range reads {
			as(who.user, who.group, r.args...)
			if who.tier == "readonly" {
				// below the row: the gate refuses the verb altogether
				sb.expect(1, "", "'tacctl console system-shell' is not permitted for the readonly tier.")
				continue
			}
			sb.expect(0, r.want, "")
		}
		for _, args := range writes {
			as(who.user, who.group, args...)
			sb.expect(1, "", "'tacctl console system-shell' is not permitted for the "+who.tier+" tier.")
		}
		if sb.consoleYAML() != "" {
			t.Errorf("%s: a refusal wrote console.yaml:\n%s", who.user, sb.consoleYAML())
		}
	}
	// A refusal inside the verb (the gate lets the row through) is logged.
	as("bob", "operator", "operator", "enable")
	if !hasAuditPrefix(sb.runner, "auth.warning", "tier DENY user=bob tier=engineer cmd=console system-shell") {
		t.Errorf("not logged: %q", sb.runner.Argvs())
	}
	// An operator (a user of a tier that is not the engineer's) reads and is refused the same way.
	sb.write("state/tacctl.yaml", "", 0o600)
	for _, r := range reads {
		as("bob", "operator", r.args...)
		want := r.want
		if len(r.args) == 2 {
			want = "disabled (tier readonly)"
		}
		sb.expect(0, want, "")
	}
	for _, args := range writes {
		as("bob", "operator", args...)
		sb.expect(1, "", "'tacctl console system-shell' is not permitted for the operator tier.")
		if !hasAuditPrefix(sb.runner, "auth.warning", "tier DENY user=bob tier=operator cmd=console system-shell") {
			t.Errorf("operator refusal of %v not logged: %q", args, sb.runner.Argvs())
		}
	}
	if sb.consoleYAML() != "" {
		t.Errorf("a refusal wrote console.yaml:\n%s", sb.consoleYAML())
	}
	// The superuser sets every form.
	for _, args := range [][]string{{"operator", "enable"}, {"user", "carol", "enable"}, {"user", "carol", "clear"}, {"operator", "disable"}, {"path", "/bin/sh"}} {
		as("alice", "superuser", args...)
		if sb.code != 0 {
			t.Errorf("superuser %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	as("alice", "superuser")
	sb.expect(0, "operator: disabled", "")
}

// 'user remove' drops the system-shell setting of the user, 'user rename'
// moves it to the new name (the person keeps the access), both say so and are
// logged as 'console set'; a user created later under the old name has none,
// a setting left under a name by a hand edit is dropped when a user of that name
// is added, and an entry of a name that is no store user is not honoured.
func TestSystemShellSettingFollowsTheUser(t *testing.T) {
	sb := consoleSandbox(t)
	sb.write("shells", "/bin/sh\n/bin/bash\n", 0o644)
	sb.con("system-shell", "user", "carol", "enable")
	sb.con("system-shell", "user", "bob", "enable")
	state := func(name string) string { return strings.TrimSpace(sb.con("system-shell", "user", name)) }

	// rename: carol -> erin
	out := plain(sb.cfgRun("", []string{"user", "rename", "carol", "erin"}, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	if sb.code != 0 || !strings.Contains(out, "The system-shell setting of 'carol' (enable) moves to 'erin'.") {
		t.Fatalf("rename: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	if y := sb.consoleYAML(); !strings.Contains(y, "system_shell_users: {bob: true, erin: true}") || strings.Contains(y, "carol") {
		t.Errorf("console.yaml after the rename:\n%s", y)
	}
	wantLines := []string{
		"console set key=system-shell item=user:carol from=enable to=none by=alice",
		"console set key=system-shell item=user:erin from=none to=enable by=alice",
	}
	for _, l := range wantLines {
		if !hasAudit(sb.runner, "auth.notice", l) {
			t.Errorf("no %q in %q", l, auditLines(sb.runner))
		}
	}
	if got := state("erin"); got != "enabled (user setting)" {
		t.Errorf("erin: %q", got)
	}

	// remove: erin goes, and a user created under the name has no setting
	out = plain(sb.cfgRun("y\n", []string{"user", "remove", "erin"}, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	if sb.code != 0 || !strings.Contains(out, "The system-shell setting of 'erin' (enable) is dropped.") {
		t.Fatalf("remove: %d %q\n%s", sb.code, sb.stderr(), out)
	}
	if y := sb.consoleYAML(); strings.Contains(y, "erin") || !strings.Contains(y, "system_shell_users: {bob: true}") {
		t.Errorf("console.yaml after the removal:\n%s", y)
	}
	if !hasAudit(sb.runner, "auth.notice", "console set key=system-shell item=user:erin from=enable to=none by=alice") {
		t.Errorf("remove not logged: %q", auditLines(sb.runner))
	}
	sb.cfgRun("", []string{"user", "add", "erin", "readonly", "--hash", testHash, "--scopes", "lab"}, nil, "SUDO_USER=alice", "SUDO_UID=1001")
	if sb.code != 0 {
		t.Fatalf("add erin: %d %q", sb.code, sb.stderr())
	}
	if got := state("erin"); got != "disabled (tier readonly)" {
		t.Errorf("recreated erin: %q", got)
	}

	// a user without a setting: nothing is said, console.yaml is not touched
	before := sb.consoleYAML()
	out = plain(sb.cfgRun("y\n", []string{"user", "remove", "erin"}, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	if sb.code != 0 || strings.Contains(out, "system-shell") || sb.consoleYAML() != before {
		t.Errorf("remove without a setting: %d\n%s", sb.code, out)
	}

	// an entry left by a hand edit is dropped when the name is added, and is
	// listed as no such user until then
	sb.write("state/console.yaml", "version: 1\nsettings: {system_shell_users: {bob: true, frank: true}}\n", 0o600)
	if list := sb.con("system-shell"); !strings.Contains(list, "  frank: enabled (no such user)") {
		t.Errorf("listing:\n%s", list)
	}
	out = plain(sb.cfgRun("", []string{"user", "add", "frank", "operator", "--hash", testHash, "--scopes", "lab"}, nil, "SUDO_USER=alice", "SUDO_UID=1001"))
	if sb.code != 0 || !strings.Contains(out, "The system-shell setting of 'frank' (enable) is dropped.") || strings.Contains(sb.consoleYAML(), "frank") {
		t.Errorf("add frank: %d\n%s\n%s", sb.code, out, sb.consoleYAML())
	}
	if got := state("frank"); got != "disabled (tier operator)" {
		t.Errorf("frank: %q", got)
	}

	// not honoured for a name that is no store user: the caller has no tier
	// at all, so the policy line is the gate's refusal, and the entry changes
	// nothing for a store user of another name
	sb.write("state/console.yaml", "version: 1\nsettings: {system_shell_users: {ghost: true}}\n", 0o600)
	sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "ghost"}, execx.Result{Stdout: []byte("ghost tac-users tac-readonly\n")})
	}, "SUDO_USER=ghost")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'ghost' has no active tacctl user") {
		t.Errorf("ghost: %d %q", sb.code, sb.stderr())
	}
	if got := state("ghost"); got != "enabled (user setting; no such user)" {
		t.Errorf("ghost state: %q", got)
	}
}
