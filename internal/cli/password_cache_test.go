package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/testpty"
	"github.com/rett/tacctl/internal/tier"
)

// The password cache's wiring (D70): the root side of a pull and of
// 'tacctl ssh' against a real agent on a socket, the helper verb, the
// shell's start of the agent, and the console's verbs and policy line. The
// agent itself is internal/askpass's tests.

// cacheAgent is a listening agent in a short temporary directory, marked in
// flight, and a client for it as the process's own user.
type cacheAgent struct {
	ag  *askpass.Agent
	cl  *askpass.Client
	uid int

	mu     sync.Mutex
	events []askpass.Event
}

func newCacheAgent(t *testing.T) *cacheAgent {
	t.Helper()
	c := &cacheAgent{uid: os.Geteuid()}
	ag, err := askpass.New(askpass.Options{
		SweepEvery: -1,
		Notify: func(e askpass.Event) {
			c.mu.Lock()
			c.events = append(c.events, e)
			c.mu.Unlock()
		},
	})
	if errors.Is(err, askpass.ErrNoLock) {
		t.Skipf("mlock is not available here: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ag.Close)
	dir, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if _, _, err := ag.Listen(filepath.Join(dir, "run")); err != nil {
		t.Fatal(err)
	}
	c.ag = ag
	c.begin(t)
	return c
}

// begin opens a new line (the previous token dies) and makes the client for
// it, as the root side of that line would have it.
func (c *cacheAgent) begin(t *testing.T) {
	t.Helper()
	c.ag.EndLine()
	env := c.ag.BeginLine()
	cl, err := askpass.NewClient(env)
	if err != nil {
		t.Fatal(err)
	}
	c.cl = cl
}

func (c *cacheAgent) stored() int {
	c.ag.Flush()
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, e := range c.events {
		if e.Kind == askpass.EventStored {
			n++
		}
	}
	return n
}

// peek returns the cached password through a fresh in-flight mark.
func (c *cacheAgent) peek(t *testing.T) string {
	t.Helper()
	c.begin(t)
	b, err := c.cl.Get(context.Background())
	if err != nil {
		return ""
	}
	defer askpass.Zero(b)
	return string(b)
}

// withPasswd makes uid the account of name in the sandbox's passwd database.
func withPasswd(t *testing.T, uid int, name string) {
	t.Helper()
	key := strconv.Itoa(uid)
	old, had := testPasswd[key]
	testPasswd[key] = name
	t.Cleanup(func() {
		if had {
			testPasswd[key] = old
		} else {
			delete(testPasswd, key)
		}
	})
}

// The pull's password source marks the process not dumpable and takes the
// variable out of the environment before it asks anything.
func TestNewDevicePasswordsHardensAndTakesTheVariable(t *testing.T) {
	c := newCacheAgent(t)
	n := 0
	old := setNotDumpable
	setNotDumpable = func() error { n++; return nil }
	t.Cleanup(func() { setNotDumpable = old })
	t.Setenv(askpass.EnvVar, c.ag.Env())
	a := app.New(nil, paths.NewEnv([]string{askpass.EnvVar + "=" + c.ag.Env(), "SUDO_UID=" + strconv.Itoa(c.uid)}), "/opt/x/dist/tacctl", 0,
		app.Stdio{}, &fake.Runner{})
	src := newDevicePasswords(&invocation{ctx: context.Background(), app: a})
	tp, ok := src.(*terminalPasswords)
	if !ok || tp.client == nil || tp.client.ExpectUID != c.uid {
		t.Fatalf("source %#v", src)
	}
	if n != 1 {
		t.Errorf("not dumpable set %d times", n)
	}
	if _, set := os.LookupEnv(askpass.EnvVar); set { //nolint:forbidigo // the test looks at the process environment itself
		t.Error("the variable is still in the environment")
	}
}

// A cached password is used and not stored again; the device accepts it.
func TestPullUsesTheCachedPassword(t *testing.T) {
	c := newCacheAgent(t)
	b := newPullBox(t)
	b.devices([3]string{"lab-a", "192.168.1.21", "juniper"}, [3]string{"lab-b", "192.168.1.22", "juniper"})
	b.serve("juniper", b.expected("lab-a"))
	if err := c.ag.Store([]byte(testPassword)); err != nil {
		t.Fatal(err)
	}
	c.stored() // the store above
	before := c.stored()
	newDevicePasswords = func(inv *invocation) devicePasswords { return &terminalPasswords{inv: inv, client: c.cl} }
	b.run("device", "config", "pull", "lab-a", "lab-b")
	if b.sb.code != 0 {
		t.Fatalf("exit %d: %q", b.sb.code, b.sb.stderr())
	}
	if n := b.srv.Attempts(); n != 2 {
		t.Errorf("%d password presentations for two devices", n)
	}
	if got := c.stored(); got != before {
		t.Errorf("the cached password was stored again (%d events, %d before)", got, before)
	}
	if got := c.peek(t); got != testPassword {
		t.Errorf("the cache lost the password: %q", got)
	}
}

// A password the cache gave and a device refused is forgotten at once.
func TestPullForgetsAWrongCachedPassword(t *testing.T) {
	c := newCacheAgent(t)
	b := newPullBox(t)
	b.devices([3]string{"lab-a", "192.168.1.21", "juniper"}, [3]string{"lab-b", "192.168.1.22", "juniper"})
	b.serve("juniper", "set system host-name x\n")
	if err := c.ag.Store([]byte("not-the-password")); err != nil {
		t.Fatal(err)
	}
	newDevicePasswords = func(inv *invocation) devicePasswords { return &terminalPasswords{inv: inv, client: c.cl} }
	b.run("device", "config", "pull", "lab-a", "lab-b")
	if b.sb.code != 1 {
		t.Fatalf("exit %d: %q", b.sb.code, b.sb.stderr())
	}
	if c.ag.Cached() {
		t.Error("a rejected password is still cached")
	}
	// One dial presents it by both password methods; the second device is
	// never started.
	if n := b.srv.Attempts(); n > 2 {
		t.Errorf("%d presentations of a wrong password (the run must stop at the first device)", n)
	}
}

// A password typed for the run is stored once a device accepted it, and
// what is stored is what was typed; one that was refused is not stored.
func TestPullStoresTheTypedPasswordAfterTheDeviceAccepted(t *testing.T) {
	for _, typed := range []string{testPassword, "not-the-password"} {
		c := newCacheAgent(t)
		b := newPullBox(t)
		b.devices([3]string{"lab-a", "192.168.1.21", "juniper"})
		b.serve("juniper", "set system host-name x\n")
		newDevicePasswords = func(inv *invocation) devicePasswords { return &terminalPasswords{inv: inv, client: c.cl} }
		master, slave, err := testpty.Open()
		if err != nil {
			t.Skipf("no pty: %v", err)
		}
		b.sb.tty = slave
		var shown strings.Builder
		var mu sync.Mutex
		go func() {
			buf := make([]byte, 512)
			sent := false
			for {
				n, err := master.Read(buf)
				mu.Lock()
				shown.Write(buf[:n])
				ready := !sent && strings.Contains(shown.String(), "Password for alice")
				mu.Unlock()
				if ready {
					sent = true
					_, _ = master.WriteString(typed + "\r")
				}
				if err != nil {
					return
				}
			}
		}()
		b.sb.run("", []string{"device", "config", "pull", "lab-a"}, "SUDO_USER=alice")
		_ = master.Close()
		_ = slave.Close()
		want := typed == testPassword
		if (b.sb.code == 0) != want {
			t.Fatalf("typed %q: exit %d %q", typed, b.sb.code, b.sb.stderr())
		}
		got := c.peek(t)
		switch {
		case want && got != testPassword:
			t.Errorf("the cache holds %q, want what was typed", got)
		case !want && got != "":
			t.Errorf("a refused password was cached: %q", got)
		}
	}
}

// The passwords source zeroes its private copy: Done drops what no device
// accepted or rejected, and Accepted without a cache stores nothing.
func TestTerminalPasswordsDropTheirCopy(t *testing.T) {
	tp := &terminalPasswords{}
	tp.typed([]byte("typed-secret"))
	copyOf := tp.secret
	tp.Done()
	if tp.secret != nil || !slices.Equal(copyOf, make([]byte, len(copyOf))) {
		t.Errorf("Done left %q / %q", tp.secret, copyOf)
	}
	tp.typed([]byte("typed-secret"))
	tp.Accepted() // no client: nothing to store, copy zeroed
	if tp.secret != nil {
		t.Error("Accepted kept the copy")
	}
	tp.Rejected() // no client: no panic
}

// takeAskpass reads the variable once, removes it from the process
// environment, and holds the socket to the user sudo ran for.
func TestTakeAskpass(t *testing.T) {
	c := newCacheAgent(t)
	mk := func(env ...string) *invocation {
		a := app.New(nil, paths.NewEnv(env), "/opt/x/dist/tacctl", 0, app.Stdio{}, &fake.Runner{})
		return &invocation{ctx: context.Background(), app: a}
	}
	val := c.ag.Env()
	t.Setenv(askpass.EnvVar, val)
	cl := mk(askpass.EnvVar+"="+val, "SUDO_UID=4242").takeAskpass()
	if cl == nil || cl.ExpectUID != 4242 || cl.Env() != val {
		t.Fatalf("client %+v", cl)
	}
	if v, ok := os.LookupEnv(askpass.EnvVar); ok { //nolint:forbidigo // the test looks at the process environment itself
		t.Errorf("still in the process environment: %q", v)
	}
	for name, env := range map[string][]string{
		"not run by sudo": {askpass.EnvVar + "=" + val},
		"sudo by root":    {askpass.EnvVar + "=" + val, "SUDO_UID=0"},
		"malformed":       {askpass.EnvVar + "=/tmp/x:nottoken", "SUDO_UID=1000"},
		"unset":           {"SUDO_UID=1000"},
	} {
		if got := mk(env...).takeAskpass(); got != nil {
			t.Errorf("%s: got a client", name)
		}
	}
}

// withAccount makes the sandbox's alice a local account with these ids.
func withAccount(t *testing.T, acct sshAccount) {
	t.Helper()
	old := sshAccountOf
	sshAccountOf = func(name string) (sshAccount, error) {
		if name != "alice" {
			return sshAccount{}, errors.New("no such account")
		}
		return acct, nil
	}
	t.Cleanup(func() { sshAccountOf = old })
}

// testAccount is alice's account for the cached ssh path: her uid is the
// one the agent's socket belongs to (the test's own, as SUDO_UID).
func testAccount() sshAccount {
	return sshAccount{UID: uint32(os.Geteuid()), GID: 4322, Groups: []uint32{4322, 27, 100}, Home: "/home/alice"}
}

// 'tacctl ssh' with a cached password: pinned entry, SSH_ASKPASS naming
// this binary and forced, one prompt, no configuration file; ssh started as
// the user directly (no sudo), with the line's token in its environment
// once and in no argument.
func TestSSHUsesTheCachedPassword(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the agent's user must not be root")
	}
	withTerminal(t, true)
	withAccount(t, testAccount())
	sb, _, _ := sshSandbox(t)
	c := newCacheAgent(t)
	withPasswd(t, c.uid, "alice")
	if err := c.ag.Store([]byte("secret-pw-17")); err != nil {
		t.Fatal(err)
	}
	run := func(script func(*fake.Runner), env []string, args ...string) {
		t.Helper()
		e := append([]string{"SUDO_USER=alice", "SUDO_UID=" + strconv.Itoa(c.uid), askpass.EnvVar + "=" + c.ag.Env(),
			"TERM=xterm", "LC_ALL=C.UTF-8", "SSH_AUTH_SOCK=/tmp/agent.sock", "HOME=/root", "USER=root"}, env...)
		sb.cfgRun("", args, script, e...)
	}
	sshCall := func() execx.Cmd {
		t.Helper()
		for _, call := range sb.runner.Calls() {
			if slices.Contains(call.Argv(), "ssh") && slices.Contains(call.Argv(), "-l") {
				return call
			}
		}
		t.Fatalf("no ssh call: %q", sb.runner.Argvs())
		return execx.Cmd{}
	}
	run(nil, nil, "ssh", "core-sw1")
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	call := sshCall()
	argv := strings.Join(call.Argv(), " ")
	if call.Name != "ssh" || strings.Contains(argv, "sudo") || call.AsUser != "" {
		t.Errorf("the cached path starts ssh through sudo: %s", argv)
	}
	for _, want := range []string{
		"ssh -F /dev/null ", "-o NumberOfPasswordPrompts=1 ", "-o StrictHostKeyChecking=yes", "-o UserKnownHostsFile=", "-l alice 10.99.0.1",
	} {
		if !strings.Contains(argv, want) {
			t.Errorf("argv lacks %q:\n%s", want, argv)
		}
	}
	// ssh's own first-value rule: NumberOfPasswordPrompts and -F precede the plan's options.
	if i, j := strings.Index(argv, "NumberOfPasswordPrompts=1"), strings.Index(argv, "PreferredAuthentications"); i < 0 || j < 0 || i > j {
		t.Errorf("option order:\n%s", argv)
	}
	token := strings.SplitN(c.ag.Env(), ":", 2)[1]
	if strings.Contains(argv, token) || strings.Contains(argv, c.ag.Env()) || strings.Contains(argv, "secret-pw-17") {
		t.Errorf("the token or the password is on argv:\n%s", argv)
	}
	// Started as the user: their uid, gid and groups, set in the child.
	if cr := call.Credential; cr == nil || cr.Uid != uint32(c.uid) || cr.Gid != 4322 || !slices.Equal(cr.Groups, []uint32{4322, 27, 100}) || cr.NoSetGroups {
		t.Errorf("credential %+v", cr)
	}
	// The environment is explicit: the account's, the helper's, the token once.
	for _, want := range []string{
		askpass.EnvVar + "=" + c.ag.Env(), "SSH_ASKPASS=/opt/x/dist/tacctl", "SSH_ASKPASS_REQUIRE=force", "TACCTL_ASKPASS_HELPER=1",
		"HOME=/home/alice", "USER=alice", "LOGNAME=alice", "TERM=xterm", "LC_ALL=C.UTF-8",
	} {
		if !slices.Contains(call.Env, want) {
			t.Errorf("environment lacks %q: %q", want, call.Env)
		}
	}
	if n := countPrefix(call.Env, askpass.EnvVar+"="); n != 1 {
		t.Errorf("%d TACCTL_ASKPASS entries", n)
	}
	for _, bad := range []string{"SUDO_", "SSH_AUTH_SOCK", "HOME=/root", "USER=root"} {
		if countPrefix(call.Env, bad) != 0 || slices.Contains(call.Env, bad) {
			t.Errorf("environment has %s: %q", bad, call.Env)
		}
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice device=core-sw1 addr=10.99.0.1 password=cached") {
		t.Errorf("no audit line says the cache was used: %q", sb.runner.Argvs())
	}
	// No token in the log lines either (this process logs them as argv).
	for _, l := range sb.runner.Argvs() {
		if strings.HasPrefix(l, "logger ") && strings.Contains(l, token) {
			t.Errorf("a log line carries the token: %s", l)
		}
	}

	// Not used: an unpinned entry, an option after the target.
	for name, c := range map[string]struct {
		args []string
		env  []string
	}{
		"unpinned":    {[]string{"ssh", "oob-con1"}, nil},
		"ssh option":  {[]string{"ssh", "core-sw1", "--", "-o", "ProxyJump=x"}, nil},
		"unpinned ho": {[]string{"ssh", "web1"}, nil},
	} {
		run(nil, c.env, c.args...)
		call := sshCall()
		got := strings.Join(call.Argv(), " ")
		for _, bad := range []string{"SSH_ASKPASS", "preserve-env", "NumberOfPasswordPrompts"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: %s on argv:\n%s", name, bad, got)
			}
		}
		if countPrefix(call.Env, askpass.EnvVar+"=") != 0 || call.Credential != nil || !strings.HasPrefix(got, "sudo -u alice -H ") {
			t.Errorf("%s: the cached path was taken: %s", name, got)
		}
	}
	// Nothing cached: ssh is as it always was.
	c.ag.Forget(askpass.WhyCommand)
	run(nil, nil, "ssh", "core-sw1")
	if got := strings.Join(sshCall().Argv(), " "); strings.Contains(got, "SSH_ASKPASS") || !strings.HasPrefix(got, "sudo -u alice -H ssh ") {
		t.Errorf("empty cache:\n%s", got)
	}
}

// An account this process cannot look up keeps the old path and its prompt:
// no cache, nothing in the environment, the line still runs.
func TestSSHCachedPathNeedsTheLocalAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the agent's user must not be root")
	}
	withTerminal(t, true)
	old := sshAccountOf
	sshAccountOf = func(string) (sshAccount, error) { return sshAccount{}, errors.New("not in the local database") }
	t.Cleanup(func() { sshAccountOf = old })
	sb, _, _ := sshSandbox(t)
	c := newCacheAgent(t)
	withPasswd(t, c.uid, "alice")
	if err := c.ag.Store([]byte("secret-pw-17")); err != nil {
		t.Fatal(err)
	}
	sb.cfgRun("", []string{"ssh", "core-sw1"}, nil, "SUDO_USER=alice", "SUDO_UID="+strconv.Itoa(c.uid), askpass.EnvVar+"="+c.ag.Env())
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	if got := sb.sshArgv(); strings.Contains(got, "SSH_ASKPASS") || !strings.HasPrefix(got, "sudo -u alice -H ssh ") {
		t.Errorf("argv %s", got)
	}
	if sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice device=core-sw1 addr=10.99.0.1 password=cached") {
		t.Error("the audit line says the cache was used")
	}
}

// The environment of the user's ssh is built from the account and a short
// list, never from the root process's.
func TestSSHUserEnviron(t *testing.T) {
	root := []string{"PATH=/usr/sbin:/usr/bin", "HOME=/root", "USER=root", "LOGNAME=root", "SUDO_USER=alice", "SUDO_UID=1000",
		"TERM=screen", "LANG=en_US.UTF-8", "LC_TIME=C", "DISPLAY=localhost:10.0", "XAUTHORITY=/home/user/.Xauthority",
		"SSH_AUTH_SOCK=/tmp/a", "LD_PRELOAD=/x.so", "TACCTL_CONSOLE=0123456789ab", "SOMETHING=else"}
	got := sshUserEnviron(root, sshAccount{Home: "/home/alice"}, "alice", []string{"DISPLAY=:9", "SSH_ASKPASS=/x"})
	want := []string{"TERM=screen", "LANG=en_US.UTF-8", "LC_TIME=C", "DISPLAY=:9", "XAUTHORITY=/home/user/.Xauthority",
		"HOME=/home/alice", "USER=alice", "LOGNAME=alice", "PATH=/usr/sbin:/usr/bin", "SSH_ASKPASS=/x"}
	if !slices.Equal(got, want) {
		t.Errorf("environment\n got %q\nwant %q", got, want)
	}
}

func countPrefix(l []string, p string) int {
	n := 0
	for _, s := range l {
		if strings.HasPrefix(s, p) {
			n++
		}
	}
	return n
}

// ssh ending with 255 after using the cache makes it forget (a refusal
// cannot be told from the other failures); any other status does not.
func TestSSHForgetsOn255(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the agent's user must not be root")
	}
	withTerminal(t, true)
	withAccount(t, testAccount())
	sb, rsa, _ := sshSandbox(t)
	c := newCacheAgent(t)
	withPasswd(t, c.uid, "alice")
	for _, tc := range []struct {
		code   int
		cached bool
	}{{3, true}, {255, false}} {
		c.begin(t) // a line of its own
		if err := c.ag.Store([]byte("secret-pw-17")); err != nil {
			t.Fatal(err)
		}
		sb.cfgRun("", []string{"ssh", "core-sw1"}, func(r *fake.Runner) {
			r.On([]string{"ssh", "-F"}, execx.Result{Code: tc.code})
			r.On([]string{"ssh-keyscan"}, execx.Result{Stdout: keyscanOut("x", rsa)})
		}, "SUDO_USER=alice", "SUDO_UID="+strconv.Itoa(c.uid), askpass.EnvVar+"="+c.ag.Env())
		if sb.code != tc.code {
			t.Errorf("exit %d, want %d", sb.code, tc.code)
		}
		if c.ag.Cached() != tc.cached {
			t.Errorf("status %d: cached %v, want %v", tc.code, c.ag.Cached(), tc.cached)
		}
	}
}

// The helper: a password prompt gets the password, once; nothing else gets
// anything.
func TestAskpassHelperVerb(t *testing.T) {
	c := newCacheAgent(t)
	if err := c.ag.Store([]byte("secret-pw-17")); err != nil {
		t.Fatal(err)
	}
	run := func(env func() []string, args ...string) (string, int) {
		var out, errb strings.Builder
		a := app.New(append([]string{"_askpass"}, args...), paths.NewEnv(env()), "/opt/x/dist/tacctl", os.Geteuid(),
			app.Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}, &fake.Runner{})
		code := exitCode(Run(context.Background(), a, BuildInfo{}), a.Out)
		if errb.Len() != 0 {
			t.Errorf("%q: stderr %q", args, errb.String())
		}
		return out.String(), code
	}
	env := func() []string { return []string{askpass.EnvVar + "=" + c.ag.Env()} }
	if out, code := run(env, "alice@10.99.0.1's password: "); out != "secret-pw-17\n" || code != 0 {
		t.Errorf("password prompt: %q %d", out, code)
	}
	for _, p := range []string{
		"Are you sure you want to continue connecting (yes/no/[fingerprint])? ",
		"Enter passphrase for key '/home/user/.ssh/id_ed25519': ",
		"Verification code: ",
	} {
		c.begin(t)
		if out, code := run(env, p); out != "" || code != 1 {
			t.Errorf("%q: %q %d", p, out, code)
		}
	}
	// A second get of the same line is a refusal and the cache forgets.
	c.begin(t)
	run(env, "Password: ")
	if out, code := run(env, "Password: "); out != "" || code != 1 {
		t.Errorf("second prompt: %q %d", out, code)
	}
	if c.ag.Cached() {
		t.Error("still cached after the retry")
	}
	if out, code := run(func() []string { return nil }, "Password: "); out != "" || code != 1 {
		t.Errorf("no cache: %q %d", out, code)
	}
	if out, code := run(env); out != "" || code != 1 {
		t.Errorf("no prompt: %q %d", out, code)
	}
	// Main's rewrite: one argument and the marker.
	if got := askpassHelperArgs([]string{"A=b", askpass.HelperEnv + "=1"}, []string{"Password: "}); !slices.Equal(got, []string{"_askpass", "Password: "}) {
		t.Errorf("rewrite: %q", got)
	}
	for _, args := range [][]string{{"Password: ", "x"}, {}, {"user"}} {
		if got := askpassHelperArgs([]string{"A=b"}, args); !slices.Equal(got, args) {
			t.Errorf("rewrote %q without the marker: %q", args, got)
		}
	}
	if got := askpassHelperArgs([]string{askpass.HelperEnv + "=1"}, []string{"a", "b"}); len(got) != 2 {
		t.Errorf("two arguments rewritten: %q", got)
	}
}

// environWith puts the variable in once and takes an inherited one off.
func TestEnvironWith(t *testing.T) {
	env := []string{"A=1", askpass.EnvVar + "=/old:" + strings.Repeat("a", 64), "B=2"}
	if got := environWith(env, "/new:tok"); !slices.Equal(got, []string{"A=1", "B=2", askpass.EnvVar + "=/new:tok"}) {
		t.Errorf("%q", got)
	}
	if got := environWith(env, ""); !slices.Equal(got, []string{"A=1", "B=2"}) {
		t.Errorf("%q", got)
	}
}

// askpassWords is exactly the four command lines tier.AskpassKeep keeps the
// variable for.
func TestAskpassWords(t *testing.T) {
	for words, want := range map[string]bool{
		"ssh core-sw1": true, "device ssh core-sw1": true, "device config pull --all": true, "device config diff --pull x": true,
		"device config diff --all --pull": true, "device config diff --section aaa --pull --all": true,
		// A diff reads the last pull and logs in to nothing without --pull:
		// its line never opens the cache. After '--' a word is no option.
		"device config diff --all": false, "device config diff x": false, "device config diff": false,
		"device config diff --exit-code --section aaa x": false, "device config diff x -- --pull": false,
		"device config diff --pulled x": false,
		"device config show x":          false, "device config list": false, "device list": false, "user list": false, "host sync x": false,
		"ssh": true, "device": false, "device config": false, "ssh core-sw1 -- show version": true, "device ssh core-sw1 -- -v": true,
	} {
		if got := askpassWords(strings.Fields(words)); got != want {
			t.Errorf("%q: %v", words, got)
		}
	}
}

// The shell's agent: it starts when asked and allowed, says why when it
// cannot (one line), and is never created otherwise.
func TestOpenPasswordCache(t *testing.T) {
	newInv := func(env ...string) (*invocation, *strings.Builder) {
		var errb strings.Builder
		r := &fake.Runner{}
		a := app.New(nil, paths.NewEnv(env), "/opt/x/dist/tacctl", os.Geteuid(),
			app.Stdio{Stdin: strings.NewReader(""), Stdout: &strings.Builder{}, Stderr: &errb}, r)
		return &invocation{ctx: context.Background(), app: a}, &errb
	}
	called := 0
	old := newAskpassAgent
	newAskpassAgent = func(o askpass.Options) (*askpass.Agent, error) { called++; return old(o) }
	t.Cleanup(func() { newAskpassAgent = old })

	// Off: nothing is created, nothing is said.
	inv, errb := newInv()
	if c := inv.openPasswordCache(shellRun{mode: shellInteractive}, false); c != nil || called != 0 || errb.Len() != 0 {
		t.Errorf("off: %v %d %q", c, called, errb.String())
	}
	// The console's answer, but not an interactive run: nothing.
	if c := inv.openPasswordCache(shellRun{mode: shellBatch, cacheMode: cacheOn}, true); c != nil || called != 0 {
		t.Errorf("batch: %v %d", c, called)
	}
	// Interactive and on: an agent with a socket, the lifetimes given.
	dir, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	inv, errb = newInv("XDG_RUNTIME_DIR=" + dir)
	c := inv.openPasswordCache(shellRun{mode: shellInteractive, cacheMode: cacheOn, pcIdle: 3 * 60e9, pcMax: 2 * 3600e9}, true)
	if c == nil {
		if strings.Contains(errb.String(), "cannot lock memory") {
			t.Skipf("mlock is not available here: %q", errb.String())
		}
		t.Fatalf("no cache: %q", errb.String())
	}
	if called != 1 || !strings.HasPrefix(c.ag.Env(), filepath.Join(dir, "tacctl")+"/") {
		t.Errorf("called %d, env %q", called, c.ag.Env())
	}
	if _, err := os.Stat(strings.SplitN(c.ag.Env(), ":", 2)[0]); err != nil {
		t.Errorf("no socket: %v", err)
	}
	// Between lines the agent has no token at all; only the lines that use
	// the cache open it, each with a token of its own.
	if tok := strings.SplitN(c.ag.Env(), ":", 2)[1]; tok != "" {
		t.Errorf("a token is valid between lines: %q", tok)
	}
	if got := c.BeginLine([]string{"user", "list"}); got != "" {
		t.Errorf("a line that does not use the cache opened it: %q", got)
	}
	// A diff without --pull logs in to nothing: no token for it; with
	// --pull there is one.
	if got := c.BeginLine([]string{"device", "config", "diff", "--all"}); got != "" {
		c.EndLine()
		t.Errorf("a diff without --pull opened the cache: %q", got)
	}
	if got := c.BeginLine([]string{"device", "config", "diff", "--all", "--pull"}); got == "" {
		t.Error("a diff with --pull did not open the cache")
	}
	c.EndLine()
	first := c.BeginLine([]string{"ssh", "core"})
	c.EndLine()
	second := c.BeginLine([]string{"device", "config", "pull", "--all"})
	c.EndLine()
	if _, _, err := askpass.ParseEnv(first); err != nil || first == second || !strings.HasPrefix(first, filepath.Join(dir, "tacctl")+"/") {
		t.Errorf("line values %q, %q", first, second)
	}
	c.close()
	if _, err := os.Stat(strings.SplitN(c.ag.Env(), ":", 2)[0]); err == nil {
		t.Error("the socket is left behind")
	}
	c.close() // idempotent
	if errb.Len() != 0 {
		t.Errorf("said %q", errb.String())
	}

	// No lock: exactly one line, no cache.
	newAskpassAgent = func(askpass.Options) (*askpass.Agent, error) { return nil, askpass.ErrNoLock }
	inv, errb = newInv("XDG_RUNTIME_DIR=" + dir)
	if c := inv.openPasswordCache(shellRun{mode: shellInteractive, cacheMode: cacheOn}, true); c != nil {
		t.Error("a cache without a lock")
	}
	if got := errb.String(); got != "password cache unavailable: cannot lock memory\n" {
		t.Errorf("said %q", got)
	}
	// A socket directory that cannot be made: one line too, and no agent
	// left behind.
	newAskpassAgent = old
	bad, err := os.MkdirTemp("/tmp", "pc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(bad) })
	if err := os.WriteFile(filepath.Join(bad, "tacctl"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	inv, errb = newInv("XDG_RUNTIME_DIR=" + bad)
	if c := inv.openPasswordCache(shellRun{mode: shellInteractive, cacheMode: cacheOn}, true); c != nil {
		t.Error("a cache without a directory")
	}
	if got := errb.String(); strings.Count(got, "\n") != 1 || !strings.HasPrefix(got, "password cache unavailable: ") {
		t.Errorf("said %q", got)
	}
}

// --password-cache of the plain shell: a caller who is not under a tier
// asks for it themselves; a managed caller's tier must be open to it.
func TestPlainShellCachePolicy(t *testing.T) {
	policy := func(out string, code int) (*invocation, *strings.Builder) {
		var errb strings.Builder
		r := &fake.Runner{}
		r.On([]string{"sudo", "-n"}, execx.Result{Stdout: []byte(out), Code: code})
		a := app.New(nil, paths.NewEnv(nil), "/opt/x/dist/tacctl", os.Geteuid(),
			app.Stdio{Stdin: strings.NewReader(""), Stdout: &strings.Builder{}, Stderr: &errb}, r)
		return &invocation{ctx: context.Background(), app: a}, &errb
	}
	r := shellRun{exe: "/opt/x/dist/tacctl", mode: shellInteractive, cacheMode: cacheAsk}
	inv, errb := policy("", 0)
	if ok, idle, max := inv.plainShellCachePolicy(r, false); !ok || idle != askpass.DefaultIdle || max != askpass.DefaultMax || errb.Len() != 0 {
		t.Errorf("unmanaged: %v %v %v %q", ok, idle, max, errb.String())
	}
	inv, errb = policy("shell=console idle=30 tier=operator password_cache=yes pc_idle=20 pc_max=3\n", 0)
	if ok, idle, max := inv.plainShellCachePolicy(r, true); !ok || idle != 20*60e9 || max != 3*3600e9 || errb.Len() != 0 {
		t.Errorf("allowed: %v %v %v %q", ok, idle, max, errb.String())
	}
	inv, errb = policy("shell=console tier=readonly password_cache=no pc_idle=15 pc_max=8\n", 0)
	if ok, _, _ := inv.plainShellCachePolicy(r, true); ok || !strings.Contains(errb.String(), "not enabled for your tier") {
		t.Errorf("refused: %v %q", ok, errb.String())
	}
	inv, errb = policy("", 1)
	if ok, _, _ := inv.plainShellCachePolicy(r, true); ok || !strings.Contains(errb.String(), "the policy could not be read") {
		t.Errorf("unreadable: %v %q", ok, errb.String())
	}
}

// 'console password-cache' sets the tiers and lifetimes, in console.yaml
// only when set, and the policy line carries them for a tier that has it.
func TestConsolePasswordCacheVerbs(t *testing.T) {
	sb := consoleSandbox(t)
	if out := sb.con("password-cache"); sb.code != 0 || out != "tiers: none\nidle: 15 min\nmax: 8 h\n" {
		t.Errorf("defaults: %d %q", sb.code, out)
	}
	if out := sb.con("password-cache", "tiers"); out != "none\n" {
		t.Errorf("tiers: %q", out)
	}
	if strings.Contains(sb.consoleYAML(), "password_cache") {
		t.Errorf("written before set:\n%s", sb.consoleYAML())
	}
	sb.con("password-cache", "tiers", "operator,superuser")
	sb.expect(0, "The password cache is open to: operator,superuser.", "")
	sb.con("password-cache", "idle", "30")
	sb.expect(0, "forgotten after 30 minute(s) without a use", "")
	sb.con("password-cache", "max", "4")
	sb.expect(0, "4 hour(s) after it was cached", "")
	y := sb.consoleYAML()
	for _, want := range []string{"password_cache:", "tiers: [operator, superuser]", "idle: 30", "max: 4"} {
		if !strings.Contains(y, want) {
			t.Errorf("console.yaml lacks %q:\n%s", want, y)
		}
	}
	if out := sb.con("password-cache"); out != "tiers: operator,superuser\nidle: 30 min\nmax: 4 h\n" {
		t.Errorf("shown: %q", out)
	}
	if out := sb.con("show"); !strings.Contains(out, "password-cache tiers: operator,superuser") ||
		!strings.Contains(out, "password-cache idle: 30 min") || !strings.Contains(out, "password-cache max: 4 h") {
		t.Errorf("show:\n%s", out)
	}
	// Refusals change nothing.
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"password-cache", "tiers", "readonly"}, "can be opened to operator, engineer and superuser"},
		{[]string{"password-cache", "tiers", "operator,operator"}, "listed twice"},
		{[]string{"password-cache", "tiers", "wizard"}, "Unknown tier 'wizard'"},
		{[]string{"password-cache", "idle", "0"}, "expected 1-120"},
		{[]string{"password-cache", "idle", "121"}, "expected 1-120"},
		{[]string{"password-cache", "max", "25"}, "expected 1-24"},
		{[]string{"password-cache", "max", "x"}, "expected 1-24"},
		{[]string{"password-cache", "keep"}, "Usage: tacctl console password-cache"},
	} {
		before := sb.consoleYAML()
		sb.con(c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.want) || sb.consoleYAML() != before {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
	}
	sb.con("password-cache", "tiers", "none")
	sb.con("password-cache", "idle", "15")
	sb.con("password-cache", "max", "8")
	if strings.Contains(sb.consoleYAML(), "password_cache") {
		t.Errorf("defaults again, still written:\n%s", sb.consoleYAML())
	}
	// 'console forget' as a command says where the cache is.
	if out := sb.con("forget"); sb.code != 0 || !strings.Contains(out, "Nothing is cached in this process.") && !strings.Contains(sb.stderr(), "Nothing is cached in this process.") {
		t.Errorf("forget: %d %q %q", sb.code, out, sb.stderr())
	}
}

func TestConsolePolicyLinePasswordCache(t *testing.T) {
	sb := consoleSandbox(t)
	sb.con("password-cache", "tiers", "operator,engineer")
	sb.con("password-cache", "idle", "20")
	policy := func(user, group string) string {
		sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
			if group != "" {
				r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
			}
		}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user))
		return strings.TrimSpace(plain(sb.out.String()))
	}
	for _, c := range []struct {
		user, group string
		on          bool
	}{{"bob", "operator", true}, {"alice", "superuser", false}, {"carol", "readonly", false}} {
		got := policy(c.user, c.group)
		has := strings.HasSuffix(got, " password_cache=yes pc_idle=20 pc_max=8")
		if has != c.on || (!c.on && strings.Contains(got, "password_cache")) {
			t.Errorf("%s: %q", c.user, got)
		}
	}
	// A console of this version reads it.
	r, ok := console.ParseRemote(policy("bob", "operator"))
	if !ok || !r.PasswordCache || r.PCIdle != 20*60e9 || r.PCMax != 8*3600e9 {
		t.Errorf("parsed %+v", r)
	}
}

// The shell gives TACCTL_ASKPASS to the lines that use the cache, in the
// environment of the sudo process and with the value the loop opened the
// cache with for that line (shell.LineEnv), never on sudo's command line;
// any other line, and any line when the shell has no cache, does not carry
// one.
func TestShellPassesTheLineTokenInTheEnvironment(t *testing.T) {
	const line1 = "/run/user/1000/tacctl/ap-h-1-x.sock:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const line2 = "/run/user/1000/tacctl/ap-h-1-x.sock:" + "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	stale := askpass.EnvVar + "=/tmp/stale.sock:" + "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	h := newHarness(t, nil, "HOME="+t.TempDir(), stale)
	inv := &invocation{ctx: context.Background(), app: h.app}
	exec := inv.shellExec(testExe, true, tier.Engineer, []string{"TACCTL_CONSOLE=0123456789ab"})
	last := func() execx.Cmd {
		var got execx.Cmd
		for _, call := range h.runner.Calls() {
			if call.Name == "sudo" {
				got = call
			}
		}
		return got
	}
	for _, c := range []struct {
		line, value string
		wantEnv     string // "" none, else the value
	}{
		{"device config pull --all", line1, line1},
		{"ssh core-sw1", line2, line2},
		{"device ssh core-sw1", line1, line1},
		{"device config diff --pull x", line2, line2},
		{"device config show core-sw1", "", ""},
		{"user list", "", ""},
		{"console show", "", ""},
		// A line that uses the cache but has no value (the shell has no
		// cache): the inherited one is taken off.
		{"ssh core-sw1", "", ""},
	} {
		h.runner.Reset()
		ctx := shell.WithLineEnv(context.Background(), c.value)
		exec(ctx, strings.Fields(c.line), nil)
		got := last()
		if got.Name == "" {
			t.Fatalf("%q: no sudo line", c.line)
		}
		argv := strings.Join(got.Argv(), " ")
		if strings.Contains(argv, "0123456789abcdef") || strings.Contains(argv, "fedcba98") || strings.Contains(argv, askpass.EnvVar) {
			t.Errorf("%q: the variable is on sudo's command line: %q", c.line, got.Argv())
		}
		n := countPrefix(got.Env, askpass.EnvVar+"=")
		switch {
		case c.wantEnv != "":
			if n != 1 || !slices.Contains(got.Env, askpass.EnvVar+"="+c.wantEnv) {
				t.Errorf("%q: environment %q", c.line, got.Env)
			}
		case n != 0:
			t.Errorf("%q: carries %q", c.line, got.Env)
		case askpassWords(strings.Fields(c.line)) && got.Env == nil:
			t.Errorf("%q: the inherited variable was not taken off", c.line)
		}
	}
}

// The root side takes the variable out of the process before anything else
// runs: the environment passed on has none, the process environment has
// none, a program started by an unrelated verb sees none, and the value is
// handed over once.
func TestCaptureAskpassKeepsChildrenFromInheritingIt(t *testing.T) {
	const val = "/run/user/1000/tacctl/ap-h-1-x.sock:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	t.Setenv(askpass.EnvVar, val)
	t.Setenv("KEEP_ME", "yes")
	saved := processAskpass
	t.Cleanup(func() { processAskpass = saved })
	got := captureAskpass([]string{"A=1", askpass.EnvVar + "=" + val, "KEEP_ME=yes"})
	if !slices.Equal(got, []string{"A=1", "KEEP_ME=yes"}) {
		t.Errorf("environment passed on: %q", got)
	}
	// A real child, as an unrelated verb (the gate's id, logger, ...) starts.
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: "sh", Args: []string{"-c", "echo \"[$TACCTL_ASKPASS][$KEEP_ME]\""}})
	if err != nil || strings.TrimSpace(string(res.Stdout)) != "[][yes]" {
		t.Errorf("a child saw %q (%v)", res.Stdout, err)
	}
	// The app's environment (built from the cleaned one) has none; the
	// verb that uses it gets it, once.
	a := app.New(nil, paths.NewEnv(got), "/opt/x/dist/tacctl", 0, app.Stdio{}, &fake.Runner{})
	inv := &invocation{ctx: context.Background(), app: a}
	if v := inv.askpassValue(); v != val {
		t.Errorf("first take: %q", v)
	}
	if v := inv.askpassValue(); v != "" {
		t.Errorf("second take: %q", v)
	}
}

// A store never lands after a forget in one run: workers that report an
// accepted and a refused password at the same time leave the cache empty
// whichever goes first (run with -race).
func TestAcceptedNeverStoresAfterRejected(t *testing.T) {
	c := newCacheAgent(t)
	for i := 0; i < 40; i++ {
		c.begin(t)
		tp := &terminalPasswords{inv: &invocation{}, client: c.cl}
		tp.typed([]byte("typed-secret"))
		var wg sync.WaitGroup
		start := make(chan struct{})
		for _, f := range []func(){tp.Accepted, tp.Rejected, tp.Accepted, tp.Rejected} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				f()
			}()
		}
		close(start)
		wg.Wait()
		if c.ag.Cached() {
			t.Fatalf("round %d: the cache holds a password after a rejection", i)
		}
		// And the order the other way: Rejected first, then Accepted.
		tp2 := &terminalPasswords{inv: &invocation{}, client: c.cl}
		tp2.typed([]byte("typed-secret"))
		tp2.Rejected()
		tp2.Accepted()
		if c.ag.Cached() {
			t.Fatalf("round %d: a store landed after a forget", i)
		}
	}
	// Accepted alone stores what was typed.
	c.begin(t)
	tp := &terminalPasswords{inv: &invocation{}, client: c.cl}
	tp.typed([]byte("typed-secret"))
	tp.Accepted()
	if got := c.peek(t); got != "typed-secret" {
		t.Errorf("cache holds %q", got)
	}
}

// The account looked up must be the one SUDO_UID names, and never root: any
// other falls back to the sudo path with its prompt, and no get is spent.
func TestSSHCachedPathRequiresTheSudoAccount(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the agent's user must not be root")
	}
	withTerminal(t, true)
	sb, _, _ := sshSandbox(t)
	c := newCacheAgent(t)
	withPasswd(t, c.uid, "alice")
	if err := c.ag.Store([]byte("secret-pw-17")); err != nil {
		t.Fatal(err)
	}
	for name, uid := range map[string]uint32{
		"another account": uint32(c.uid) + 1,
		"root":            0,
	} {
		acct := testAccount()
		acct.UID = uid
		withAccount(t, acct)
		c.begin(t)
		sb.cfgRun("", []string{"ssh", "core-sw1"}, nil, "SUDO_USER=alice", "SUDO_UID="+strconv.Itoa(c.uid), askpass.EnvVar+"="+c.ag.Env())
		if sb.code != 0 {
			t.Fatalf("%s: exit %d %q", name, sb.code, sb.stderr())
		}
		got := sb.sshArgv()
		if strings.Contains(got, "SSH_ASKPASS") || !strings.HasPrefix(got, "sudo -u alice -H ssh ") {
			t.Errorf("%s: the cached path was taken: %s", name, got)
		}
		for _, call := range sb.runner.Calls() {
			if call.Credential != nil || countPrefix(call.Env, askpass.EnvVar+"=") != 0 {
				t.Errorf("%s: a credential or the token went to %q", name, call.Argv())
			}
		}
		// The line's get was not spent: the helper would still be answered.
		cl, _ := askpass.NewClient(c.ag.Env())
		cl.ExpectUID = c.uid
		if b, err := cl.Get(context.Background()); err != nil || string(b) != "secret-pw-17" {
			t.Errorf("%s: the line's get was spent: %q %v", name, b, err)
		}
	}
}
