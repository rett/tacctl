package cli

import (
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'tacctl ssh' in-process: the argv of the ssh it runs per vendor,
// legacy-ssh, pin, -p and '--' (always '-l <caller>', by password, no agent,
// no key), the refusals (who may connect, to what), the audit line, the
// exit status and the host-key diagnosis. ssh (through 'sudo -u <caller>') and
// ssh-keyscan are scripted; nothing reaches a host.

const sshTestSock = "/tmp/agent.sock"

// withTerminal makes stdin count as a terminal for the test.
func withTerminal(t *testing.T, tty bool) {
	t.Helper()
	old := sshTerminal
	sshTerminal = func(io.Reader) bool { return tty }
	t.Cleanup(func() { sshTerminal = old })
}

// sshSandbox registers the devices of the table: core-sw1 (cisco, legacy,
// pinned, prod), lab-rtr2 (juniper, pinned, lab), oob-con1 (wti, unpinned,
// prod), edge-fw (other, port, pinned, dmz), and the enrolled host web1
// (lab, port 2222, enrolled as admin with an identity, unpinned). The store
// (store.multiscope.yaml) has alice (superuser: prod, lab), bob (operator:
// lab) and carol (readonly: lab, dmz).
func sshSandbox(t *testing.T) (*sandbox, devreg.HostKey, devreg.HostKey) {
	t.Helper()
	sb := newSandbox(t, true)
	rsa, ed := hkKey(t, "rsa"), hkKey(t, "ed25519")
	for _, add := range []struct {
		args []string
		keys []devreg.HostKey
	}{
		{[]string{"core-sw1", "10.99.0.1", "--vendor", "cisco", "--legacy-ssh"}, []devreg.HostKey{rsa}},
		{[]string{"lab-rtr2", "192.168.5.1", "--vendor", "juniper"}, []devreg.HostKey{ed}},
		{[]string{"oob-con1", "10.99.0.9", "--vendor", "wti", "--no-host-key"}, nil},
		{[]string{"edge-fw", "203.0.113.5", "--port", "2222"}, []devreg.HostKey{ed, rsa}},
	} {
		sb.devScan("", scan("x", add.keys...), append([]string{"add"}, add.args...)...)
		if sb.code != 0 {
			t.Fatalf("add %v: %d %q", add.args, sb.code, sb.stderr())
		}
	}
	sb.write("state/linux-hosts", "web1|admin@web1.example.net|2222|lab|192.0.2.1|/k/id_web1\nauthsrv|local||lab|192.0.2.1|\n", 0o600)
	return sb, rsa, ed
}

// sshRun runs 'tacctl <args>' as user (SUDO_USER, with the SUDO_UID of
// testPasswd as sudo sets it; "" for none) with an agent socket; script
// adds rules to the fake runner.
func (sb *sandbox) sshRun(user string, script func(*fake.Runner), args ...string) string {
	sb.t.Helper()
	env := []string{"SSH_AUTH_SOCK=" + sshTestSock}
	if user != "" {
		env = append(env, "SUDO_USER="+user)
		for uid, name := range testPasswd {
			if name == user {
				env = append(env, "SUDO_UID="+uid)
			}
		}
	}
	return plain(sb.cfgRun("", args, script, env...))
}

// sshArgv is the ssh the run started, as one argv; "" when none.
func (sb *sandbox) sshArgv() string {
	for _, c := range sb.runner.Calls() {
		if argv := c.Argv(); slices.Contains(argv, "ssh") {
			return strings.Join(argv, " ")
		}
	}
	return ""
}

func TestSSHArgvTable(t *testing.T) {
	withTerminal(t, true)
	sb, _, _ := sshSandbox(t)
	kh := sb.path("var-lib", "ssh", "known_hosts")
	ct := "-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password"
	legacy := "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
	wti := "-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=password"
	pin := func(n string) string {
		return "-o UserKnownHostsFile=" + kh + " -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=" + n + " -o UpdateHostKeys=no"
	}
	// No agent socket reaches ssh, though the caller has one.
	as := func(u string) string { return "sudo -u " + u + " -H ssh " }
	for _, c := range []struct {
		user string
		args []string
		want string
	}{
		{"alice", []string{"ssh", "core-sw1"}, as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " -l alice 10.99.0.1"},
		{"alice", []string{"ssh", "10.99.0.1"}, as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " -l alice 10.99.0.1"},
		{"alice", []string{"ssh", "CORE-SW1", "-p", "2200", "--", "-v", "show", "version"},
			as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " -p 2200 -l alice 10.99.0.1 -v show version"},
		{"alice", []string{"ssh", "lab-rtr2"}, as("alice") + ct + " " + pin("lab-rtr2") + " -l alice 192.168.5.1"},
		{"alice", []string{"ssh", "oob-con1"}, as("alice") + wti + " -l alice 10.99.0.9"},
		{"carol", []string{"ssh", "edge-fw"}, as("carol") + ct + " " + pin("edge-fw") + " -p 2222 -l carol 203.0.113.5"},
		{"carol", []string{"ssh", "edge-fw", "-p", "22"}, as("carol") + ct + " " + pin("edge-fw") + " -p 22 -l carol 203.0.113.5"},
		// An enrolled host: neither the enrolment's account (admin) nor its
		// identity; the caller, by password.
		{"alice", []string{"ssh", "web1"}, as("alice") + ct + " -p 2222 -l alice web1.example.net"},
		{"alice", []string{"device", "ssh", "core-sw1"}, as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " -l alice 10.99.0.1"},
		{"carol", []string{"ssh", "lab-rtr2"}, as("carol") + ct + " " + pin("lab-rtr2") + " -l carol 192.168.5.1"},
		{"carol", []string{"device", "ssh", "web1"}, as("carol") + ct + " -p 2222 -l carol web1.example.net"},
	} {
		sb.sshRun(c.user, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
		}, c.args...)
		if sb.code != 0 {
			t.Errorf("%s %v: exit %d %q", c.user, c.args, sb.code, sb.stderr())
		}
		if got := sb.sshArgv(); got != c.want {
			t.Errorf("%s %v:\n got %s\nwant %s", c.user, c.args, got, c.want)
		}
		for _, bad := range []string{"BatchMode", "SSH_AUTH_SOCK", " -i ", "admin"} {
			if strings.Contains(sb.sshArgv(), bad) {
				t.Errorf("%v: %s on argv", c.args, bad)
			}
		}
	}
}

func TestSSHAuditKnownHostsAndNotices(t *testing.T) {
	withTerminal(t, true)
	sb, rsa, _ := sshSandbox(t)
	if err := os.Remove(sb.path("var-lib", "ssh", "known_hosts")); err != nil {
		t.Fatal(err)
	}
	sb.sshRun("alice", nil, "ssh", "core-sw1")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice device=core-sw1 addr=10.99.0.1") {
		t.Errorf("no audit line: %q", sb.runner.Argvs())
	}
	// The audit line comes before ssh starts.
	argvs := sb.runner.Argvs()
	li := slices.IndexFunc(argvs, func(s string) bool { return strings.HasPrefix(s, "logger -t tacctl -p auth.info ssh ") })
	si := slices.IndexFunc(argvs, func(s string) bool { return strings.HasPrefix(s, "sudo -u alice") })
	if li < 0 || si < 0 || li > si {
		t.Errorf("order: %q", argvs)
	}
	// The generated known_hosts is brought back before a pinned session.
	if !strings.Contains(sb.knownHosts(), "core-sw1 "+rsa.String()) {
		t.Errorf("known_hosts:\n%s", sb.knownHosts())
	}
	if strings.Contains(sb.stderr(), "hostkey-unpinned") {
		t.Errorf("pinned device warned: %q", sb.stderr())
	}
	// Unpinned: the notice first, on stderr; ssh still runs.
	out := sb.sshRun("alice", nil, "ssh", "oob-con1")
	if sb.code != 0 || !strings.Contains(sb.stderr(), "hostkey-unpinned: no host key is pinned for 'oob-con1'") || out != "" {
		t.Errorf("unpinned: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.sshRun("alice", nil, "ssh", "web1")
	if !strings.Contains(sb.stderr(), "hostkey-unpinned: no host key is pinned for 'web1'") {
		t.Errorf("unpinned host: %q", sb.stderr())
	}
	// Acknowledged: no warning.
	sb.dev("", "notice", "oob-con1", "ack", "hostkey-unpinned")
	sb.sshRun("alice", nil, "ssh", "oob-con1")
	if strings.Contains(sb.stderr(), "hostkey-unpinned") {
		t.Errorf("acked notice repeated: %q", sb.stderr())
	}
}

func TestSSHRefusals(t *testing.T) {
	withTerminal(t, true)
	sb, _, _ := sshSandbox(t)
	carol := func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}
	for _, c := range []struct {
		user   string
		script func(*fake.Runner)
		args   []string
		code   int
		err    string
	}{
		{"", nil, []string{"ssh", "core-sw1"}, 1, "tacctl ssh runs ssh as the user who invoked it; run it from your own account, not as root"},
		{"root", nil, []string{"ssh", "core-sw1"}, 1, "run it from your own account, not as root"},
		{"alice", nil, []string{"ssh", "10.1.2.3"}, 1, "'10.1.2.3' is not a registered device; register it: tacctl device add <name> 10.1.2.3"},
		{"alice", nil, []string{"ssh", "nosuch"}, 1, "Device 'nosuch' not found. List them with: tacctl device list"},
		{"alice", nil, []string{"ssh", "authsrv"}, 1, "'authsrv' is this server (enrolled with --local)"},
		{"alice", nil, []string{"ssh", "core-sw1", "-x"}, 1, "Unknown option: '-x' (pass ssh's own options after --)"},
		{"alice", nil, []string{"ssh", "core-sw1", "-l", "admin"}, 1, "Unknown option: '-l' (pass ssh's own options after --)"},
		{"alice", nil, []string{"ssh", "core-sw1", "-p", "0"}, 1, "Invalid port '0'"},
		{"alice", nil, []string{"ssh", "core-sw1", "extra"}, 1, "Unknown argument: 'extra'"},
		{"alice", nil, []string{"ssh", "-p", "22"}, 1, "Name the device or host to connect to."},
		// Every tier, superusers included, reaches only its own scopes.
		{"alice", nil, []string{"ssh", "edge-fw"}, 1, "'alice' has no access to scope 'dmz' (device edge-fw)"},
		// A local account that is not a tacctl user.
		{"tester", nil, []string{"ssh", "lab-rtr2"}, 1, "'tester' is not a tacctl user; tacctl ssh logs you in with your tacctl account"},
		{"carol", carol, []string{"ssh", "core-sw1"}, 1, "'carol' has no access to scope 'prod' (device core-sw1)"},
		{"carol", carol, []string{"ssh", "10.99.0.9"}, 1, "'carol' has no access to scope 'prod' (device oob-con1)"},
	} {
		sb.sshRun(c.user, c.script, c.args...)
		if sb.code != c.code || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%s %v: %d %q, want %d %q", c.user, c.args, sb.code, sb.stderr(), c.code, c.err)
		}
		if a := sb.sshArgv(); a != "" {
			t.Errorf("%s %v ran ssh: %s", c.user, c.args, a)
		}
	}
	// The scope refusal is logged.
	sb.sshRun("carol", carol, "ssh", "core-sw1")
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "ssh DENY user=carol device=core-sw1 scope=prod reason=scope") {
		t.Errorf("no deny line: %q", sb.runner.Argvs())
	}
	// A device no scope covers is refused to everyone, superusers included.
	sb.devScan("", scan("x"), "add", "stray", "100.64.0.9", "--no-host-key")
	sb.sshRun("alice", nil, "ssh", "stray")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'stray' is in no configured scope, so no one may open a session to it.") ||
		!sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "ssh DENY user=alice device=stray scope=- reason=unconfigured") {
		t.Errorf("unconfigured: %d %q %q", sb.code, sb.stderr(), sb.runner.Argvs())
	}
	// A disabled tacctl user is refused (the tier gate has no tier for one
	// either; an unrestricted local admin who is a disabled tacctl user
	// reaches tacctl ssh and is refused there).
	sb.run("", []string{"user", "disable", "bob"})
	sb.sshRun("bob", nil, "ssh", "lab-rtr2")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "tacctl user 'bob' is disabled") ||
		!sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "ssh DENY user=bob device=lab-rtr2 scope=lab reason=disabled") || sb.sshArgv() != "" {
		t.Errorf("disabled: %d %q %q", sb.code, sb.stderr(), sb.runner.Argvs())
	}
	// No terminal.
	withTerminal(t, false)
	sb.sshRun("alice", nil, "ssh", "core-sw1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "a terminal is required") || sb.sshArgv() != "" {
		t.Errorf("no tty: %d %q", sb.code, sb.stderr())
	}
	// No name: the usage, exit 0.
	out := sb.sshRun("alice", nil, "ssh")
	if sb.code != 0 || !strings.Contains(out, "Usage: tacctl ssh <name|address> [-p <port>] [-X|-Y] [-L|-R|-D <spec>]... [-- <ssh args>]") {
		t.Errorf("usage: %d %q", sb.code, out)
	}
}

func TestSSHExitStatusAndHostKeyDiagnosis(t *testing.T) {
	withTerminal(t, true)
	sb, rsa, ed := sshSandbox(t)
	status := func(code int, keys ...devreg.HostKey) func(*fake.Runner) {
		return func(r *fake.Runner) {
			r.On([]string{"sudo", "-u", "alice"}, execx.Result{Code: code})
			r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: keyscanOut("x", keys...)})
		}
	}
	sb.sshRun("alice", status(3), "ssh", "core-sw1")
	if sb.code != 3 || sb.runner.Called("ssh-keyscan") {
		t.Errorf("exit 3: %d %q", sb.code, sb.runner.Argvs())
	}
	// 255 with the pinned key still offered: ssh's own failure, no diagnosis.
	sb.sshRun("alice", status(255, rsa), "ssh", "core-sw1")
	if sb.code != 255 || strings.Contains(sb.stderr(), "pinned") {
		t.Errorf("255 same key: %d %q", sb.code, sb.stderr())
	}
	if !sb.runner.Called("ssh-keyscan", "-T", "5", "-p", "22", "-t", "ed25519,ecdsa,rsa,ssh-rsa", "10.99.0.1") {
		t.Errorf("keyscan: %q", sb.runner.Argvs())
	}
	// 255 with another key: pinned and offered, the console command, the fix.
	sb.sshRun("alice", status(255, hkKey(t, "ecdsa")), "ssh", "lab-rtr2", "-p", "2200")
	e := sb.stderr()
	for _, want := range []string{
		"The ssh host key of 'lab-rtr2' (192.168.5.1 port 2200) is not the one pinned for it; ssh refused the connection.",
		"  Pinned:  ED25519 " + ed.Fingerprint(),
		"Offered: ECDSA",
		"Compare on the device console: Junos: 'file show /etc/ssh/ssh_host_ed25519_key.pub'",
		"tacctl device hostkey lab-rtr2 accept",
		"tacctl device hostkey lab-rtr2 set SHA256:<fingerprint>",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("diagnosis lacks %q:\n%s", want, e)
		}
	}
	_ = rsa
	if sb.code != 255 || !sb.runner.Called("ssh-keyscan", "-T", "5", "-p", "2200") {
		t.Errorf("255 changed: %d %q", sb.code, sb.runner.Argvs())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "ssh hostkey-mismatch user=alice device=lab-rtr2 addr=192.168.5.1") {
		t.Errorf("no mismatch line: %q", sb.runner.Argvs())
	}
	// 255 on an unpinned device: nothing to compare.
	sb.sshRun("alice", status(255, rsa), "ssh", "oob-con1")
	if sb.code != 255 || sb.runner.Called("ssh-keyscan") {
		t.Errorf("255 unpinned: %d %q", sb.code, sb.runner.Argvs())
	}
	// ssh that cannot be started.
	sb.sshRun("alice", func(r *fake.Runner) { r.Missing("sudo") }, "ssh", "core-sw1")
	if sb.code != 127 || !strings.Contains(sb.stderr(), "ssh could not be run") {
		t.Errorf("missing: %d %q", sb.code, sb.stderr())
	}
}

// No child of 'tacctl ssh' carries a secret: the scope secrets and the
// password hashes of the store stay off every argv.
func TestSSHNoSecretOnArgv(t *testing.T) {
	withTerminal(t, true)
	sb, rsa, _ := sshSandbox(t)
	var secrets []string
	for _, m := range regexp.MustCompile(`(?m)^\s+(?:secret|hash): (\S+)$`).FindAllStringSubmatch(sb.store(), -1) {
		secrets = append(secrets, m[1])
	}
	if len(secrets) < 4 {
		t.Fatalf("secrets: %q", secrets)
	}
	for _, args := range [][]string{{"ssh", "core-sw1"}, {"ssh", "lab-rtr2", "--", "uptime"}, {"ssh", "oob-con1"}, {"ssh", "web1"}, {"ssh", "edge-fw"}} {
		sb.sshRun("alice", func(r *fake.Runner) {
			r.On([]string{"sudo"}, execx.Result{Code: 255})
			r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: keyscanOut("x", hkKey(t, "ecdsa"))})
		}, args...)
		for _, s := range secrets {
			if sb.runner.ArgvContains(s) {
				t.Errorf("%v: a secret on argv: %q", args, sb.runner.Argvs())
			}
		}
	}
	_ = rsa
}

// 'device ssh-config': the caller's entries only, the same pin as 'tacctl
// ssh', the hint on stderr; nothing written into a home.
func TestDeviceSSHConfig(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	old := sshConfigServer
	sshConfigServer = func() string { return "authsrv" }
	t.Cleanup(func() { sshConfigServer = old })
	kh := sb.path("var-lib", "ssh", "known_hosts")
	out := sb.sshRun("alice", nil, "device", "ssh-config")
	if sb.code != 0 {
		t.Fatalf("ssh-config: %d %q", sb.code, sb.stderr())
	}
	for _, want := range []string{
		"# Generated by tacctl device ssh-config on authsrv, ",
		"Host core-sw1\n    HostName 10.99.0.1\n    PubkeyAuthentication no\n    PreferredAuthentications keyboard-interactive,password\n" +
			"    KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\n" +
			"    HostKeyAlgorithms +ssh-rsa\n    PubkeyAcceptedAlgorithms +ssh-rsa\n    UserKnownHostsFile " + kh +
			"\n    GlobalKnownHostsFile none\n    StrictHostKeyChecking yes\n    HostKeyAlias core-sw1\n    UpdateHostKeys no\n",
		"Host oob-con1\n    HostName 10.99.0.9\n    PubkeyAuthentication no\n    PreferredAuthentications password\n    # No host key is pinned",
		"Host edge-fw\n    HostName 203.0.113.5\n    Port 2222\n    PubkeyAuthentication no\n    PreferredAuthentications keyboard-interactive,password\n    UserKnownHostsFile " + kh,
		"Host web1\n    HostName web1.example.net\n    Port 2222\n    PubkeyAuthentication no\n    PreferredAuthentications keyboard-interactive,password\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ssh-config lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "authsrv\n") || strings.Contains(out, "Host authsrv") {
		t.Errorf("a --local host has a block:\n%s", out)
	}
	// No login (ssh uses the local username) and nothing of the enrolment.
	for _, bad := range []string{"User ", "IdentityFile", "admin"} {
		if strings.Contains(out, bad) {
			t.Errorf("ssh-config has %q:\n%s", bad, out)
		}
	}
	if e := sb.stderr(); !strings.Contains(e, "Save it with: tacctl device ssh-config > ~/.ssh/tacctl.conf") ||
		!strings.Contains(e, "'Include ~/.ssh/tacctl.conf' at the top of ~/.ssh/config") {
		t.Errorf("hint: %q", e)
	}
	// carol (readonly; lab, dmz) gets her own scopes' blocks only.
	out = sb.sshRun("carol", func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}, "device", "ssh-config")
	if sb.code != 0 {
		t.Fatalf("carol: %d %q", sb.code, sb.stderr())
	}
	var hostsSeen []string
	for _, l := range strings.Split(out, "\n") {
		if h, ok := strings.CutPrefix(l, "Host "); ok {
			hostsSeen = append(hostsSeen, h)
		}
	}
	if want := []string{"lab-rtr2", "edge-fw", "web1"}; !slices.Equal(hostsSeen, want) {
		t.Errorf("carol's blocks = %q, want %q", hostsSeen, want)
	}
	sb.sshRun("alice", nil, "device", "ssh-config", "x")
	sb.expect(1, "", "Usage: tacctl device ssh-config")
}

// From a console session (TACCTL_CONSOLE): no configuration file, no local
// command, no control master, no forwardings, no agent, no escape character
// unless console.yaml's ssh_escape, the target after '--'; an unpinned
// entry is refused; the log lines carry console=<session>; every session
// logs its end.
func TestSSHConsoleSession(t *testing.T) {
	withTerminal(t, true)
	sb, _, _ := sshSandbox(t)
	kh := sb.path("var-lib", "ssh", "known_hosts")
	ct := "-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password"
	pin := "-o UserKnownHostsFile=" + kh + " -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=lab-rtr2 -o UpdateHostKeys=no"
	hard := "-F /dev/null -o PermitLocalCommand=no -o ControlMaster=no -o ClearAllForwardings=yes -o ForwardAgent=no"
	session := "TACCTL_CONSOLE=0123456789ab"
	run := func(args ...string) {
		t.Helper()
		env := []string{"SSH_AUTH_SOCK=" + sshTestSock, "SUDO_USER=alice", session}
		for uid, name := range testPasswd {
			if name == "alice" {
				env = append(env, "SUDO_UID="+uid)
			}
		}
		sb.cfgRun("", args, nil, env...)
	}
	run("ssh", "lab-rtr2", "-p", "2200", "--", "show", "version")
	want := "sudo -u alice -H ssh " + hard + " -o EscapeChar=none " + ct + " " + pin + " -p 2200 -l alice -- 192.168.5.1 show version"
	if sb.code != 0 || sb.sshArgv() != want {
		t.Errorf("console argv (%d %q):\n got %s\nwant %s", sb.code, sb.stderr(), sb.sshArgv(), want)
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice device=lab-rtr2 addr=192.168.5.1 console=0123456789ab") ||
		!sb.runner.CalledRegexp(`^logger -t tacctl -p auth\.info ssh end user=alice device=lab-rtr2 status=0 duration=\d+ console=0123456789ab$`) {
		t.Errorf("log: %q", sb.runner.Argvs())
	}
	// ssh_escape keeps the escape character.
	sb.run("", []string{"console", "ssh-escape", "enable"})
	run("ssh", "lab-rtr2")
	if want := "sudo -u alice -H ssh " + hard + " " + ct + " " + pin + " -l alice -- 192.168.5.1"; sb.sshArgv() != want {
		t.Errorf("ssh_escape:\n got %s\nwant %s", sb.sshArgv(), want)
	}
	// Unpinned: a device and an enrolled host are refused, with the fix.
	for _, name := range []string{"oob-con1", "web1"} {
		run("ssh", name)
		if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(),
			"'"+name+"' has no pinned host key, so the console does not connect to it; an administrator pins it: tacctl device hostkey "+name+" accept") {
			t.Errorf("%s: %d %q %q", name, sb.code, sb.stderr(), sb.sshArgv())
		}
		if !sb.runner.CalledRegexp(`^logger -t tacctl -p auth\.warning ssh DENY user=alice device=` + name + ` scope=\S+ reason=unpinned console=0123456789ab$`) {
			t.Errorf("%s: no deny line: %q", name, sb.runner.Argvs())
		}
	}
	// Words after -- are the remote command: a leading option is refused.
	run("ssh", "lab-rtr2", "--", "-o", "ProxyCommand=sh")
	if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(), "ssh's own options are not available") {
		t.Errorf("option after --: %d %q", sb.code, sb.stderr())
	}
	// A refusal of admission carries the session too.
	sb.cfgRun("", []string{"ssh", "edge-fw"}, nil, "SUDO_USER=alice", session)
	if !sb.runner.CalledRegexp(`ssh DENY user=alice device=edge-fw scope=dmz reason=scope console=0123456789ab$`) {
		t.Errorf("deny: %q", sb.runner.Argvs())
	}
	// A marker that is not a session id is logged as '?', and still hardens.
	sb.cfgRun("", []string{"ssh", "lab-rtr2"}, nil, "SUDO_USER=alice", "TACCTL_CONSOLE=x y")
	if !strings.HasPrefix(sb.sshArgv(), "sudo -u alice -H ssh -F /dev/null") ||
		!sb.runner.CalledRegexp(`ssh user=alice device=lab-rtr2 addr=192\.168\.5\.1 console=\?$`) {
		t.Errorf("bad marker: %q", sb.runner.Argvs())
	}
	// Outside the console: the end line too, no console field, no hardening.
	sb.sshRun("alice", func(r *fake.Runner) { r.On([]string{"sudo", "-u", "alice"}, execx.Result{Code: 4}) }, "ssh", "lab-rtr2")
	if sb.code != 4 || strings.Contains(sb.sshArgv(), "/dev/null") ||
		!sb.runner.CalledRegexp(`^logger -t tacctl -p auth\.info ssh end user=alice device=lab-rtr2 status=4 duration=\d+$`) {
		t.Errorf("plain: %d %q", sb.code, sb.runner.Argvs())
	}
}

// Forwarding: -X/-Y need a display and pass DISPLAY to the ssh run as the
// caller; -L/-R/-D come before the login and are checked for shape; the log
// line names the kinds. In a console session only the tiers of console
// forwarding tiers (default superuser) may, ClearAllForwardings is left out
// for them, and anyone else is refused and logged.
func TestSSHForwarding(t *testing.T) {
	withTerminal(t, true)
	sb, _, _ := sshSandbox(t)
	groups := func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "alice"}, execx.Result{Stdout: []byte("alice tac-users tac-superuser\n")})
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}
	env := func(user string, extra ...string) []string {
		e := []string{"SUDO_USER=" + user}
		for uid, name := range testPasswd {
			if name == user {
				e = append(e, "SUDO_UID="+uid)
			}
		}
		return append(e, extra...)
	}
	// Outside the console: ports, in order, before the login.
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "-L", "8443:localhost:443", "-D", "1080", "-L", "127.0.0.1:2222:[2001:db8::1]:22"}, groups, env("alice")...)
	if sb.code != 0 || !strings.HasSuffix(sb.sshArgv(), " -L 8443:localhost:443 -L 127.0.0.1:2222:[2001:db8::1]:22 -D 1080 -l alice 192.168.5.1") {
		t.Errorf("ports (%d %q): %s", sb.code, sb.stderr(), sb.sshArgv())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice device=lab-rtr2 addr=192.168.5.1 forward=local,dynamic") {
		t.Errorf("log: %q", sb.runner.Argvs())
	}
	// A spec ssh could read as something else is refused.
	for _, bad := range []string{"8443:host;id", "-oProxyCommand=x", "a b"} {
		sb.cfgRun("", []string{"ssh", "lab-rtr2", "-R", bad}, groups, env("alice")...)
		if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(), "is not a forwarding spec for -R") {
			t.Errorf("%q: %d %q", bad, sb.code, sb.stderr())
		}
	}
	// X11 needs a display, which goes to ssh through env(1).
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "-X"}, groups, env("alice")...)
	if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(), "-X needs an X11 display") {
		t.Errorf("no display: %d %q", sb.code, sb.stderr())
	}
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "-Y"}, groups, env("alice", "DISPLAY=localhost:10.0")...)
	if sb.code != 0 || !strings.HasPrefix(sb.sshArgv(), "sudo -u alice -H env DISPLAY=localhost:10.0 ssh ") ||
		!strings.HasSuffix(sb.sshArgv(), " -Y -l alice 192.168.5.1") {
		t.Errorf("-Y (%d %q): %s", sb.code, sb.stderr(), sb.sshArgv())
	}
	// In the console: a superuser forwards, without ClearAllForwardings.
	session := "TACCTL_CONSOLE=0123456789ab"
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "-X", "-L", "8443:localhost:443"}, groups, env("alice", session, "DISPLAY=localhost:10.0")...)
	argv := sb.sshArgv()
	if sb.code != 0 || !strings.HasPrefix(argv, "sudo -u alice -H env DISPLAY=localhost:10.0 ssh -F /dev/null -o PermitLocalCommand=no -o ControlMaster=no -o ForwardAgent=no -o EscapeChar=none ") ||
		strings.Contains(argv, "ClearAllForwardings") || !strings.HasSuffix(argv, " -X -L 8443:localhost:443 -l alice -- 192.168.5.1") {
		t.Errorf("console superuser (%d %q): %s", sb.code, sb.stderr(), argv)
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice device=lab-rtr2 addr=192.168.5.1 forward=x11,local console=0123456789ab") {
		t.Errorf("console log: %q", sb.runner.Argvs())
	}
	// A readonly user is refused, with the fix, and logged.
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "-L", "8443:localhost:443"}, groups, env("carol", session)...)
	if sb.code != 1 || sb.sshArgv() != "" ||
		!strings.Contains(sb.stderr(), "Forwarding (-X, -Y, -L, -R, -D) is not available to the readonly tier in the console") ||
		!sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "ssh DENY user=carol reason=forward tier=readonly console=0123456789ab") {
		t.Errorf("console readonly: %d %q %q", sb.code, sb.stderr(), sb.runner.Argvs())
	}
	// Opened to readonly by console forwarding tiers.
	sb.run("", []string{"console", "forwarding", "tiers", "readonly,superuser"})
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "-L", "8443:localhost:443"}, groups, env("carol", session)...)
	if sb.code != 0 || !strings.HasSuffix(sb.sshArgv(), " -L 8443:localhost:443 -l carol -- 192.168.5.1") {
		t.Errorf("readonly opened (%d %q): %s", sb.code, sb.stderr(), sb.sshArgv())
	}
}
