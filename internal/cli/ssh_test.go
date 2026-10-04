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
// legacy-ssh, pin, -l/-p and '--', the refusals, the audit line, the exit
// status and the host-key diagnosis. ssh (through 'sudo -u <caller>') and
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
// prod), edge-fw (other, login and port, pinned, dmz), and the enrolled
// host web1 (lab, port 2222, an identity, unpinned).
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
		{[]string{"edge-fw", "203.0.113.5", "--login", "netops", "--port", "2222"}, []devreg.HostKey{ed, rsa}},
	} {
		sb.devScan("", scan("x", add.keys...), append([]string{"add"}, add.args...)...)
		if sb.code != 0 {
			t.Fatalf("add %v: %d %q", add.args, sb.code, sb.stderr())
		}
	}
	sb.write("state/linux-hosts", "web1|admin@web1.example.net|2222|lab|192.0.2.1|/k/id_web1\nauthsrv|local||lab|192.0.2.1|\n", 0o600)
	return sb, rsa, ed
}

// sshRun runs 'tacctl <args>' as user (SUDO_USER; "" for none) with an
// agent socket; script adds rules to the fake runner.
func (sb *sandbox) sshRun(user string, script func(*fake.Runner), args ...string) string {
	sb.t.Helper()
	env := []string{"SSH_AUTH_SOCK=" + sshTestSock}
	if user != "" {
		env = append(env, "SUDO_USER="+user)
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
	kh := sb.path("state", "known_hosts")
	ct := "-o ConnectTimeout=10"
	legacy := "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
	wti := "-o PreferredAuthentications=password -o PubkeyAuthentication=no"
	pin := func(n string) string {
		return "-o UserKnownHostsFile=" + kh + " -o StrictHostKeyChecking=yes -o HostKeyAlias=" + n + " -o UpdateHostKeys=no"
	}
	as := func(u string) string { return "sudo -u " + u + " -H env SSH_AUTH_SOCK=" + sshTestSock + " ssh " }
	for _, c := range []struct {
		user string
		args []string
		want string
	}{
		{"alice", []string{"ssh", "core-sw1"}, as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " 10.99.0.1"},
		{"alice", []string{"ssh", "10.99.0.1"}, as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " 10.99.0.1"},
		{"alice", []string{"ssh", "CORE-SW1", "-l", "admin", "-p", "2200", "--", "-v", "show", "version"},
			as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " -p 2200 -l admin 10.99.0.1 -v show version"},
		{"alice", []string{"ssh", "lab-rtr2"}, as("alice") + ct + " " + pin("lab-rtr2") + " 192.168.5.1"},
		{"alice", []string{"ssh", "oob-con1"}, as("alice") + ct + " " + wti + " 10.99.0.9"},
		{"alice", []string{"ssh", "edge-fw"}, as("alice") + ct + " " + pin("edge-fw") + " -p 2222 -l netops 203.0.113.5"},
		{"alice", []string{"ssh", "edge-fw", "-l", "root", "-p", "22"}, as("alice") + ct + " " + pin("edge-fw") + " -p 22 -l root 203.0.113.5"},
		{"alice", []string{"ssh", "web1"}, as("alice") + ct + " -p 2222 -i /k/id_web1 -l admin web1.example.net"},
		{"alice", []string{"device", "ssh", "core-sw1"}, as("alice") + ct + " " + legacy + " " + pin("core-sw1") + " 10.99.0.1"},
		{"carol", []string{"ssh", "lab-rtr2"}, as("carol") + ct + " " + pin("lab-rtr2") + " 192.168.5.1"},
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
		if strings.Contains(sb.sshArgv(), "BatchMode") {
			t.Errorf("%v: BatchMode", c.args)
		}
	}
}

func TestSSHAuditKnownHostsAndNotices(t *testing.T) {
	withTerminal(t, true)
	sb, rsa, _ := sshSandbox(t)
	if err := os.Remove(sb.path("state", "known_hosts")); err != nil {
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
		{"alice", nil, []string{"ssh", "core-sw1", "-l", "-oProxyCommand=x"}, 1, "Invalid login '-oProxyCommand=x'"},
		{"alice", nil, []string{"ssh", "core-sw1", "-p", "0"}, 1, "Invalid port '0'"},
		{"alice", nil, []string{"ssh", "core-sw1", "extra"}, 1, "Unknown argument: 'extra'"},
		{"alice", nil, []string{"ssh", "-l", "x"}, 1, "Name the device or host to connect to."},
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
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "ssh DENY user=carol device=core-sw1 scope=prod") {
		t.Errorf("no deny line: %q", sb.runner.Argvs())
	}
	// No terminal.
	withTerminal(t, false)
	sb.sshRun("alice", nil, "ssh", "core-sw1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "a terminal is required") || sb.sshArgv() != "" {
		t.Errorf("no tty: %d %q", sb.code, sb.stderr())
	}
	// No name: the usage, exit 0.
	out := sb.sshRun("alice", nil, "ssh")
	if sb.code != 0 || !strings.Contains(out, "Usage: tacctl ssh <name|address> [-l <login>] [-p <port>] [-- <ssh args>]") {
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
		"Compare on the device console: Junos: 'show system ssh host-key'",
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
	kh := sb.path("state", "known_hosts")
	out := sb.sshRun("alice", nil, "device", "ssh-config")
	if sb.code != 0 {
		t.Fatalf("ssh-config: %d %q", sb.code, sb.stderr())
	}
	for _, want := range []string{
		"# Generated by tacctl device ssh-config on authsrv, ",
		"Host core-sw1\n    HostName 10.99.0.1\n    KexAlgorithms +diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\n" +
			"    HostKeyAlgorithms +ssh-rsa\n    PubkeyAcceptedAlgorithms +ssh-rsa\n    UserKnownHostsFile " + kh +
			"\n    StrictHostKeyChecking yes\n    HostKeyAlias core-sw1\n    UpdateHostKeys no\n",
		"Host oob-con1\n    HostName 10.99.0.9\n    PreferredAuthentications password\n    PubkeyAuthentication no\n    # No host key is pinned",
		"Host edge-fw\n    HostName 203.0.113.5\n    User netops\n    Port 2222\n    UserKnownHostsFile " + kh,
		"Host web1\n    HostName web1.example.net\n    User admin\n    Port 2222\n    IdentityFile /k/id_web1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("ssh-config lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "authsrv\n") || strings.Contains(out, "Host authsrv") {
		t.Errorf("a --local host has a block:\n%s", out)
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
