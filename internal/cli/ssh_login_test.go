package cli

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'tacctl ssh <name> --login <local-user>' in-process (ssh.go, sshLoginEntry):
// the session logs in as a local account of the device. The argv is the
// plain session's with '-l <local-user>'; a host, an unpinned device, a tier
// below the engineer's and a device outside the caller's scopes are refused
// before anything is started; the password cache is never used; the log
// lines carry login=. ssh runs through the fake runner; nothing reaches a
// host.

// loginTier is the fake 'id -nG' of a user of the sandbox in the tier group.
func loginTier(user, group string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users " + group + "\n")})
	}
}

// setEngineer makes the sandbox's operators engineers (the tier setting
// engineerSandbox writes) or, with false, puts the default back.
func setEngineer(sb *sandbox, on bool) {
	sb.t.Helper()
	text := ""
	if on {
		text = "tier:\n  operator: engineer\n"
	}
	sb.write("state/tacctl.yaml", text, 0o600)
}

// loginOpts are the ssh options every pinned session to lab-rtr2 has.
func loginOpts(sb *sandbox) string {
	return "-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password " +
		"-o UserKnownHostsFile=" + sb.path("var-lib", "ssh", "known_hosts") +
		" -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=lab-rtr2 -o UpdateHostKeys=no"
}

// The argv of a session as a local account: the caller's sudo, the device's
// options and pin, '-l <local-user>' in place of '-l <caller>', the port and
// the forwardings as for a plain session, the words after '--' after the
// target, and no askpass of any kind.
func TestSSHLoginArgv(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	setEngineer(sb, true)
	opts := loginOpts(sb)
	kh := sb.path("var-lib", "ssh", "known_hosts")
	legacy := "-o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o Ciphers=+aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa"
	coreOpts := "-o ConnectTimeout=10 -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password " + legacy +
		" -o UserKnownHostsFile=" + kh + " -o GlobalKnownHostsFile=none -o StrictHostKeyChecking=yes -o HostKeyAlias=core-sw1 -o UpdateHostKeys=no"
	for _, c := range []struct {
		user   string
		script func(*fake.Runner)
		args   []string
		want   string
	}{
		// an engineer, a superuser; ssh and device ssh
		{"bob", loginTier("bob", "tac-engineer"), []string{"ssh", "lab-rtr2", "--login", "admin"},
			"sudo -u bob -H ssh " + opts + " -l admin 192.168.5.1"},
		{"bob", loginTier("bob", "tac-engineer"), []string{"device", "ssh", "192.168.5.1", "--login=admin"},
			"sudo -u bob -H ssh " + opts + " -l admin 192.168.5.1"},
		{"alice", nil, []string{"device", "ssh", "core-sw1", "--login", "bg-admin.1"},
			"sudo -u alice -H ssh " + coreOpts + " -l bg-admin.1 10.99.0.1"},
		// the option may come before the name
		{"alice", nil, []string{"ssh", "--login", "root", "lab-rtr2"},
			"sudo -u alice -H ssh " + opts + " -l root 192.168.5.1"},
		// the port, every forwarding and the words after '--' as for a plain session
		{"bob", loginTier("bob", "tac-engineer"),
			[]string{"ssh", "lab-rtr2", "--login", "admin", "-p", "2200", "-g", "-L", "8443:localhost:443", "-R", "8080:localhost:80", "-D", "1080", "--", "show", "version"},
			"sudo -u bob -H ssh " + opts + " -p 2200 -g -L 8443:localhost:443 -R 8080:localhost:80 -D 1080 -l admin 192.168.5.1 show version"},
		// ssh's own options after '--' are still handled as they are today
		{"alice", nil, []string{"ssh", "lab-rtr2", "--login", "admin", "--", "-v", "show", "version"},
			"sudo -u alice -H ssh " + opts + " -l admin 192.168.5.1 -v show version"},
	} {
		sb.sshRun(c.user, c.script, c.args...)
		if sb.code != 0 {
			t.Errorf("%s %v: exit %d %q", c.user, c.args, sb.code, sb.stderr())
		}
		if got := sb.sshArgv(); got != c.want {
			t.Errorf("%s %v:\n got %s\nwant %s", c.user, c.args, got, c.want)
		}
		if strings.Contains(sb.sshArgv(), "-l "+c.user+" ") {
			t.Errorf("%v: the caller's name is a login on argv: %s", c.args, sb.sshArgv())
		}
	}
	// X11 goes to ssh through env(1) as for a plain session.
	sb.cfgRun("", []string{"ssh", "lab-rtr2", "--login", "admin", "-Y"}, nil, "SUDO_USER=alice", "SUDO_UID="+uidOf("alice"), "DISPLAY=localhost:10.0")
	if sb.code != 0 || !strings.HasPrefix(sb.sshArgv(), "sudo -u alice -H env DISPLAY=localhost:10.0 ssh ") ||
		!strings.HasSuffix(sb.sshArgv(), " -Y -l admin 192.168.5.1") {
		t.Errorf("-Y (%d %q): %s", sb.code, sb.stderr(), sb.sshArgv())
	}
}

// A session as a local account of the device is for registered devices
// only: an enrolled host (a --local one too) is refused with the reason, a
// device with no pinned host key is refused with the way to pin it, the name
// is checked, an address nobody registered is refused as ever, and a tier
// below the engineer's, or a device out of the caller's scopes, is refused as
// for the other --login verbs and for a plain session. Nothing is started.
func TestSSHLoginRefusals(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	setEngineer(sb, true)
	engineer := loginTier("bob", "tac-engineer")
	for _, c := range []struct {
		user   string
		script func(*fake.Runner)
		args   []string
		err    string
	}{
		{"bob", engineer, []string{"ssh", "web1", "--login", "admin"},
			"--login is for registered devices: 'web1' is an enrolled Linux host, and hosts are reached as you. Nothing was started."},
		{"alice", nil, []string{"device", "ssh", "authsrv", "--login", "admin"},
			"'authsrv' is an enrolled Linux host, and hosts are reached as you. Nothing was started."},
		{"alice", nil, []string{"ssh", "oob-con1", "--login", "admin"},
			"'oob-con1' has no pinned host key, and a local password goes only to a device whose key was verified. Nothing was started."},
		{"alice", nil, []string{"ssh", "oob-con1", "--login", "admin"}, "tacctl device hostkey oob-con1 accept"},
		{"alice", nil, []string{"ssh", "lab-rtr2", "--login", "bad name"}, "--login takes the name of one of the device's local accounts (letters, digits, '.', '_' and '-'): 'bad name'"},
		{"alice", nil, []string{"ssh", "lab-rtr2", "--login", "-oProxyCommand=x"}, "--login takes the name of one of the device's local accounts"},
		{"alice", nil, []string{"ssh", "lab-rtr2", "--login"}, "--login"},
		{"alice", nil, []string{"ssh", "10.1.2.3", "--login", "admin"}, "'10.1.2.3' is not a registered device; register it: tacctl device add <name> 10.1.2.3"},
		{"alice", nil, []string{"ssh", "nosuch", "--login", "admin"}, "Device 'nosuch' not found. List them with: tacctl device list"},
		// below the engineer's tier, with the wording of the other --login verbs
		{"carol", loginTier("carol", "tac-readonly"), []string{"ssh", "lab-rtr2", "--login", "admin"}, "'tacctl device ssh --login' is not permitted for the readonly tier."},
		// a device outside the caller's scopes, at any tier
		{"bob", engineer, []string{"ssh", "core-sw1", "--login", "admin"}, "'bob' has no access to scope 'prod' (device core-sw1)"},
		{"alice", nil, []string{"ssh", "edge-fw", "--login", "admin"}, "'alice' has no access to scope 'dmz' (device edge-fw)"},
	} {
		sb.sshRun(c.user, c.script, c.args...)
		if sb.code == 0 || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%s %v: %d %q, want %q", c.user, c.args, sb.code, sb.stderr(), c.err)
		}
		if a := sb.sshArgv(); a != "" {
			t.Errorf("%s %v ran ssh: %s", c.user, c.args, a)
		}
		if sb.runner.Called("ssh-keyscan") {
			t.Errorf("%s %v: scanned a device: %q", c.user, c.args, sb.runner.Argvs())
		}
		if hasAuditPrefix(sb.runner, "auth.info", "ssh user=") {
			t.Errorf("%s %v: a session was logged: %q", c.user, c.args, sb.runner.Argvs())
		}
	}
	// An operator (the default tier of bob) is below the engineer's.
	setEngineer(sb, false)
	sb.sshRun("bob", loginTier("bob", "tac-operator"), "device", "ssh", "lab-rtr2", "--login", "admin")
	if sb.code == 0 || !strings.Contains(sb.stderr(), "'tacctl device ssh --login' is not permitted for the operator tier.") || sb.sshArgv() != "" {
		t.Errorf("operator: %d %q %s", sb.code, sb.stderr(), sb.sshArgv())
	}
	sb.sshRun("bob", loginTier("bob", "tac-operator"), "ssh", "lab-rtr2")
	if sb.code != 0 {
		t.Errorf("operator, plain: %d %q", sb.code, sb.stderr())
	}
	setEngineer(sb, true)
	// A refusal for the entry is logged with the account; the tier denial as
	// every tier denial; no unpinned notice reaches the person first.
	sb.sshRun("bob", engineer, "ssh", "web1", "--login", "admin")
	if !hasAudit(sb.runner, "auth.warning", "ssh DENY user=bob device=web1 scope=lab reason=login-host login=admin") {
		t.Errorf("no deny line for the host: %q", sb.runner.Argvs())
	}
	sb.sshRun("alice", nil, "ssh", "oob-con1", "--login", "admin")
	if !hasAudit(sb.runner, "auth.warning", "ssh DENY user=alice device=oob-con1 scope=prod reason=login-unpinned login=admin") ||
		strings.Contains(sb.stderr(), "hostkey-unpinned") {
		t.Errorf("unpinned: %q %q", sb.stderr(), sb.runner.Argvs())
	}
	sb.sshRun("carol", loginTier("carol", "tac-readonly"), "ssh", "lab-rtr2", "--login", "admin")
	if !hasAudit(sb.runner, "auth.warning", "tier DENY user=carol tier=readonly cmd=device ssh --login") {
		t.Errorf("no tier deny line: %q", sb.runner.Argvs())
	}
	sb.sshRun("bob", engineer, "ssh", "core-sw1", "--login", "admin")
	if !hasAudit(sb.runner, "auth.warning", "ssh DENY user=bob device=core-sw1 scope=prod reason=scope") {
		t.Errorf("no scope deny line: %q", sb.runner.Argvs())
	}
	// Without --login the same readonly user still reaches the device: the
	// gate of the flag does not touch the plain session.
	sb.sshRun("carol", loginTier("carol", "tac-readonly"), "ssh", "lab-rtr2")
	if sb.code != 0 || !strings.HasSuffix(sb.sshArgv(), " -l carol 192.168.5.1") {
		t.Errorf("plain readonly: %d %q %s", sb.code, sb.stderr(), sb.sshArgv())
	}
}

// The session start and end lines carry login=<local-user> and no password
// field; a plain session's lines are exactly what they were (no login field,
// the same bytes) whether or not the line before had one.
func TestSSHLoginAudit(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	sb.sshRun("alice", nil, "ssh", "lab-rtr2", "--login", "admin", "-L", "8443:localhost:443")
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if !hasAudit(sb.runner, "auth.info", "ssh user=alice device=lab-rtr2 addr=192.168.5.1 forward=local login=admin") ||
		!hasAuditMatch(sb.runner, "auth.info", `^ssh end user=alice device=lab-rtr2 status=0 duration=\d+ login=admin$`) {
		t.Errorf("login lines: %q", sb.runner.Argvs())
	}
	for _, c := range auditCalls(sb.runner) {
		if strings.Contains(c.Line, "password=") {
			t.Errorf("a password field: %s", c.Line)
		}
	}
	// A plain session, with and without forwarding, status 4.
	sb.sshRun("alice", func(r *fake.Runner) { r.On([]string{"sudo", "-u", "alice"}, execx.Result{Code: 4}) }, "ssh", "lab-rtr2")
	if !hasAudit(sb.runner, "auth.info", "ssh user=alice device=lab-rtr2 addr=192.168.5.1") ||
		!hasAuditMatch(sb.runner, "auth.info", `^ssh end user=alice device=lab-rtr2 status=4 duration=\d+$`) {
		t.Errorf("plain lines: %q", sb.runner.Argvs())
	}
	sb.sshRun("alice", nil, "device", "ssh", "core-sw1", "-D", "1080")
	if !hasAudit(sb.runner, "auth.info", "ssh user=alice device=core-sw1 addr=10.99.0.1 forward=dynamic") {
		t.Errorf("plain forward line: %q", sb.runner.Argvs())
	}
	for _, args := range [][]string{{"ssh", "lab-rtr2"}, {"ssh", "web1"}, {"ssh", "oob-con1", "--", "uptime"}} {
		sb.sshRun("alice", nil, args...)
		for _, c := range auditCalls(sb.runner) {
			if strings.Contains(c.Line, "login") {
				t.Errorf("%v: a plain line mentions a login: %s", args, c.Line)
			}
		}
	}
}

// From a console session the words after '--' stay the remote command and an
// option among them is refused; the target follows '--'; an unpinned device
// is refused; the lines end with the account and the session.
func TestSSHLoginConsole(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	opts := loginOpts(sb)
	hard := "-F /dev/null -o PermitLocalCommand=no -o ControlMaster=no -o ClearAllForwardings=yes -o ForwardAgent=no -o EscapeChar=none"
	session := "TACCTL_CONSOLE=0123456789ab"
	run := func(args ...string) {
		t.Helper()
		sb.cfgRun("", args, nil, "SUDO_USER=alice", "SUDO_UID="+uidOf("alice"), session)
	}
	run("ssh", "lab-rtr2", "--login", "admin", "-p", "2200", "--", "show", "version")
	want := "sudo -u alice -H ssh " + hard + " " + opts + " -p 2200 -l admin -- 192.168.5.1 show version"
	if sb.code != 0 || sb.sshArgv() != want {
		t.Errorf("console argv (%d %q):\n got %s\nwant %s", sb.code, sb.stderr(), sb.sshArgv(), want)
	}
	if !hasAudit(sb.runner, "auth.info", "ssh user=alice device=lab-rtr2 addr=192.168.5.1 login=admin console=0123456789ab") ||
		!hasAuditMatch(sb.runner, "auth.info", `^ssh end user=alice device=lab-rtr2 status=0 duration=\d+ login=admin console=0123456789ab$`) {
		t.Errorf("console log: %q", sb.runner.Argvs())
	}
	run("ssh", "lab-rtr2", "--login", "admin", "--", "-o", "ProxyCommand=sh")
	if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(), "In the tacctl console the words after -- are the remote command; ssh's own options are not available.") {
		t.Errorf("option after --: %d %q", sb.code, sb.stderr())
	}
	// -l is no option of the console line either way
	run("ssh", "lab-rtr2", "--login", "admin", "-l", "root")
	if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(), "Unknown option: '-l'") {
		t.Errorf("-l: %d %q", sb.code, sb.stderr())
	}
	run("ssh", "oob-con1", "--login", "admin")
	if sb.code != 1 || sb.sshArgv() != "" || !strings.Contains(sb.stderr(), "has no pinned host key") {
		t.Errorf("unpinned: %d %q", sb.code, sb.stderr())
	}
}

// A hold on the device is no reason to stop: the session goes on as the
// account, and the warning says that is what is used. The plain session's
// warning is unchanged.
func TestSSHLoginHeldDevice(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	sb.write("state/tacctl.yaml", sb.overrides()+"breakglass_hold:\n  lab-rtr2:\n    address: 192.168.5.1\n    since: '2026-10-13T00:00:00Z'\n    by: alice\n    reason: console recovery\n", 0o600)
	out := sb.sshRun("alice", nil, "ssh", "lab-rtr2", "--login", "bgadmin")
	if sb.code != 0 || !strings.HasSuffix(sb.sshArgv(), " -l bgadmin 192.168.5.1") {
		t.Fatalf("held, login: %d %q %s", sb.code, sb.stderr(), sb.sshArgv())
	}
	if e := out; !strings.Contains(e, "break-glass is held on lab-rtr2: you log in as its local account 'bgadmin'") || strings.Contains(e, "takes local accounts only") {
		t.Errorf("warning: %q", e)
	}
	out = sb.sshRun("alice", nil, "ssh", "lab-rtr2")
	if sb.code != 0 || !strings.Contains(out, "break-glass is held on lab-rtr2: it takes local accounts only") {
		t.Errorf("plain warning: %d %q", sb.code, out)
	}
	out = sb.sshRun("alice", nil, "ssh", "core-sw1", "--login", "admin")
	if sb.code != 0 || strings.Contains(out, "break-glass") {
		t.Errorf("not held: %d %q", sb.code, out)
	}
}

// The password cache is out of a session as a local account: with a client
// in the environment and a password cached, nothing is asked, taken, stored
// or forgotten (not even when ssh ends with 255), ssh is started through sudo
// with no askpass and none of the cache's variables, and the line's token is
// unspent.
func TestSSHLoginNeverUsesThePasswordCache(t *testing.T) {
	b := newAskedBox(t)
	const cached = "secret-pw-17"
	if err := b.c.ag.Store([]byte(cached)); err != nil {
		t.Fatal(err)
	}
	before := b.c.stored()
	for _, args := range [][]string{
		{"ssh", "core-sw1", "--login", "admin"},
		{"device", "ssh", "core-sw1", "--login=admin"},
		{"ssh", "core-sw1", "-p", "22", "--login", "admin", "--", "show", "version"},
	} {
		b.c.begin(t)
		b.sb.cfgRun("", args, func(r *fake.Runner) {
			r.On([]string{"sudo", "-u", "alice"}, execx.Result{Code: 255})
			r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: keyscanOut("x", b.rsa)})
		}, "SUDO_USER=alice", "SUDO_UID="+strconv.Itoa(b.c.uid), "TERM=xterm", askpass.EnvVar+"="+b.c.ag.Env())
		if b.sb.code != 255 {
			t.Fatalf("%v: exit %d %q", args, b.sb.code, b.sb.stderr())
		}
		if len(b.prompts) != 0 || b.dumpOff != 0 {
			t.Errorf("%v: asked for a password (%q, %d not-dumpable marks)", args, b.prompts, b.dumpOff)
		}
		call, ok := b.call()
		if !ok {
			t.Fatalf("%v: no ssh call: %q", args, b.sb.runner.Argvs())
		}
		got := strings.Join(call.Argv(), " ")
		if b.cachedPath(t) || !strings.HasPrefix(got, "sudo -u alice -H ssh ") || !strings.Contains(got, " -l admin ") ||
			call.Credential != nil || countPrefix(call.Env, askpass.EnvVar+"=") != 0 {
			t.Errorf("%v: the cached path was taken: %s", args, got)
		}
		for _, bad := range []string{"SSH_ASKPASS", "NumberOfPasswordPrompts", "password=", cached} {
			if strings.Contains(got, bad) || slices.ContainsFunc(call.Env, func(kv string) bool { return strings.Contains(kv, bad) }) {
				t.Errorf("%v: %q on the ssh command: %s %q", args, bad, got, call.Env)
			}
		}
		for _, c := range auditCalls(b.sb.runner) {
			if strings.Contains(c.Line, "password=") {
				t.Errorf("%v: audit line %q", args, c.Line)
			}
		}
		// the token of the line was never spent: its one get still answers
		pw, err := b.c.cl.Get(context.Background())
		if err != nil || string(pw) != cached {
			t.Errorf("%v: the cache was used: %q %v", args, pw, err)
		}
		askpass.Zero(pw)
	}
	if got := b.c.stored(); got != before {
		t.Errorf("stored into the cache: %d events, %d before", got, before)
	}
	b.c.mu.Lock()
	for _, e := range b.c.events {
		if e.Kind == askpass.EventForgotten {
			t.Error("the cache was told to forget (ssh ended with 255)")
		}
	}
	b.c.mu.Unlock()
	if !b.c.ag.Cached() {
		t.Error("the cached password is gone")
	}
	// An unusable client in the environment changes nothing either.
	b.c.begin(t)
	b.sb.cfgRun("", []string{"ssh", "core-sw1", "--login", "admin"}, nil, "SUDO_USER=alice", "SUDO_UID="+strconv.Itoa(b.c.uid), askpass.EnvVar+"=not-a-token")
	if b.sb.code != 0 || !strings.Contains(b.sb.sshArgv(), " -l admin 10.99.0.1") {
		t.Errorf("bad variable: %d %q %s", b.sb.code, b.sb.stderr(), b.sb.sshArgv())
	}
}

// Without --login the cache is used as before: a second line over the same
// sandbox asks (the first ssh to a pinned device with the cache on and
// empty), so the flag's exclusion above is the flag's, not the sandbox's.
func TestSSHPlainStillUsesThePasswordCache(t *testing.T) {
	b := newAskedBox(t)
	b.ssh(0, true, "ssh", "core-sw1")
	if b.sb.code != 0 || len(b.prompts) != 1 || !b.cachedPath(t) {
		t.Errorf("plain: exit %d, %d prompts, cached path %v", b.sb.code, len(b.prompts), b.cachedPath(t))
	}
	if !hasAudit(b.sb.runner, "auth.info", "ssh user=alice device=core-sw1 addr=10.99.0.1 password=asked") {
		t.Errorf("no password=asked line: %q", b.sb.runner.Argvs())
	}
}

// The line's variable is dropped, unread, for a --login line.
func TestDropAskpassClearsTheProcessValue(t *testing.T) {
	serial(t) // processAskpass is process state
	old := processAskpass
	t.Cleanup(func() { processAskpass = old })
	processAskpass = "sock:token"
	inv := &invocation{hooks: &hooks{}}
	inv.dropAskpass()
	if processAskpass != "" {
		t.Errorf("kept %q", processAskpass)
	}
}

// 'tacctl device' lists --login under the ssh row as it lists the other ssh
// options, and the row does not change what '?' says of the --login of
// another verb that has no option line of its own ('device collect --login'
// is described by the shared line of onboard, not by ssh's).
func TestDeviceUsageListsTheSSHLoginOption(t *testing.T) {
	sb := newSandbox(t, true)
	out := plain(sb.run("", []string{"device"}))
	i := strings.Index(out, "\n  ssh <name|address>")
	if i < 0 {
		t.Fatalf("no ssh row in the usage:\n%s", out)
	}
	rest := out[i+1:]
	if j := strings.Index(rest, "\n  scan"); j > 0 {
		rest = rest[:j]
	}
	if !strings.Contains(rest, "--login <local-user>") || !strings.Contains(rest, "(engineer and up)") {
		t.Errorf("the ssh row lacks the --login option line:\n%s", rest)
	}

	texts := flagTexts(t)
	if got := texts["device collect --login"]; !strings.HasPrefix(got, "(onboard, collect;") {
		t.Errorf("device collect --login is described as %q", got)
	}
}

// The gate sees 'ssh' and 'device ssh' as readonly rows and --login is the
// engineer's: both verbs carry a tier note, which the manual page's
// Requires line and the TIERS list read; and the help of 'ssh' spells the
// value of --login as the flag's Spec does.
func TestSSHLoginTierNoteAndHelpValue(t *testing.T) {
	for _, k := range []string{"ssh ", "device ssh"} {
		if n := tierNotes[k]; !strings.Contains(n, "--login") || !strings.Contains(n, "engineer tier") {
			t.Errorf("tierNotes[%q] = %q", k, n)
		}
	}
	page, err := os.ReadFile(filepath.Join("..", "..", "man", "tacctl.1"))
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(page), `Requires: \fBreadonly\fR. A session as you is every tier's; \-\-login`); n != 2 {
		t.Errorf("%d Requires lines of the man page name the engineer tier of --login, want 2 (ssh, device ssh)", n)
	}
	flag := sshSpec.Flags[1]
	if flag.Names[0] != "--login" || !strings.Contains(sshUsage(), "--login "+flag.Arg+" ") {
		t.Errorf("the help of ssh does not spell the value of --login as %s", flag.Arg)
	}
}
