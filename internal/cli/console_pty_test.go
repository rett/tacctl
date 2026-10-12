package cli

// The login console on a pseudo-terminal: the real console (RunConsole on
// the environment console.Scrub makes, in this test binary started again in
// helper mode) with a runner that answers the root side's policy and the
// caller's groups, writes the console's log lines to a file, runs a line
// 'slow' as sleep(1) and every other line as echo(1), and starts the
// system shell (a stub script) for real. Each session has testpty's hard
// deadline.

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/testpty"
)

const consolePtyHelperRun = "-test.run=^TestConsolePtyHelper$"

// consolePtyRunner is the helper's runner.
type consolePtyRunner struct {
	execx.Real
	log, policy, groups string
	mu                  sync.Mutex
}

func (r *consolePtyRunner) Run(ctx context.Context, c execx.Cmd) (execx.Result, error) {
	switch {
	case c.Name == "logger":
		r.mu.Lock()
		defer r.mu.Unlock()
		f, err := os.OpenFile(r.log, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			_, _ = io.WriteString(f, strings.Join(c.Args[3:], " ")+"\n")
			_ = f.Close()
		}
		return execx.Result{}, nil
	case c.Name == "id":
		return execx.Result{Stdout: []byte(r.groups + "\n")}, nil
	case c.Name == "sudo" && slices.Contains(c.Args, "_console-policy"):
		return execx.Result{Stdout: []byte(r.policy + "\n")}, nil
	case c.Name == "sudo":
		return execx.Result{}, nil
	}
	return r.Real.Run(ctx, c)
}

func (r *consolePtyRunner) Start(ctx context.Context, c execx.Cmd) (execx.Process, error) {
	if c.Name == "sudo" {
		i := slices.Index(c.Args, testExe)
		words := c.Args[i+1:]
		switch words[0] {
		case "slow":
			c.Name, c.Args = "sleep", []string{"8"}
		case "ssh":
			// The password cache's variable as the sudo process was given it.
			// ('ssh slow' keeps the line running, as a session does).
			script := "echo ASKPASS=${TACCTL_ASKPASS}"
			if len(words) > 1 && words[1] == "slow" {
				script += "; sleep 8"
			}
			c.Name, c.Args = "sh", []string{"-c", script}
		default:
			c.Name, c.Args = "echo", append([]string{"RAN"}, c.Argv()...)
		}
	}
	return r.Real.Start(ctx, c)
}

// TestConsolePtyHelper is the console for the terminal tests below: they
// start this binary with only this test selected and key=value arguments
// (log, policy, groups, idle in seconds). In a normal run it does nothing.
func TestConsolePtyHelper(t *testing.T) {
	if !slices.Contains(os.Args, consolePtyHelperRun) {
		return
	}
	opt := map[string]string{}
	for _, a := range os.Args {
		if k, v, ok := strings.Cut(a, "="); ok && !strings.HasPrefix(k, "-") {
			opt[k] = v
		}
	}
	if opt["idle"] != "" {
		consolePolicyHook = func(p *console.Remote) { p.Idle = p.Idle / time.Minute * time.Second }
	}
	dirty := []string{"TERM=xterm", "USER=carol", "HOME=" + opt["home"], "SSH_CLIENT=192.0.2.9 50000 22",
		"SSH_TTY=/dev/pts/9", "TACCTL_LEAK=1", "LD_PRELOAD=/nonexistent.so", "PATH=/usr/bin:/bin"}
	env := console.Scrub(dirty, paths.ConsoleCommand, false)
	// The stub shell and sleep are found through the console's PATH.
	r := &consolePtyRunner{log: opt["log"], policy: strings.ReplaceAll(opt["policy"], ",", " "), groups: strings.ReplaceAll(opt["groups"], ",", " ")}
	a := app.New(nil, paths.NewEnv(env), testExe, os.Geteuid(),
		app.Stdio{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}, r)
	var args []string
	if opt["c"] != "" {
		args = []string{"-c", opt["c"]}
	}
	code := exitCode(RunConsole(context.Background(), a, BuildInfo{Version: "0.2.1-pty"}, args), a.Out)
	_, _ = io.WriteString(os.Stdout, "CONSOLE-EXIT "+strconv.Itoa(code)+"\n")
}

type consolePty struct {
	*testpty.Session
	t   *testing.T
	log string
}

// startConsole runs the console helper on a pty with the policy (fields
// separated by commas), the groups and the extra key=value arguments.
func startConsole(t *testing.T, policy, groups string, extra ...string) *consolePty {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "log")
	argv := append([]string{exe, consolePtyHelperRun, "-test.count=1", "log=" + log, "home=" + dir,
		"policy=" + policy, "groups=" + groups}, extra...)
	s, err := testpty.Start(testpty.Options{Path: exe, Argv: argv,
		Env: []string{"PATH=/usr/bin:/bin", "TERM=xterm", "LC_ALL=C.UTF-8", "HOME=" + dir}, Rows: 40, Cols: 120})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		if out := s.Output(); strings.Contains(out, "DATA RACE") {
			t.Errorf("data race in the console:\n%s", out)
		}
	})
	return &consolePty{Session: s, t: t, log: log}
}

func (p *consolePty) expect(re string) {
	p.t.Helper()
	if err := p.Expect(re, 5*time.Second); err != nil {
		p.t.Fatal(err)
	}
}

func (p *consolePty) send(s string) {
	p.t.Helper()
	if err := p.Send(s); err != nil {
		p.t.Fatal(err)
	}
}

// ends waits for the console to end with code and gives its log lines.
func (p *consolePty) ends(code int) []string {
	p.t.Helper()
	p.expect(`CONSOLE-EXIT ` + strconv.Itoa(code) + `\r\n`)
	if _, err := p.Wait(5 * time.Second); err != nil {
		p.t.Fatal(err)
	}
	b, _ := os.ReadFile(p.log)
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

const ptyPolicyRO = "shell=console,idle=30,system_shell=no,system_shell_path=/bin/bash,tier=readonly,list_max=40"

func TestConsolePtyBannerPromptAndExit(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, ptyPolicyRO, "carol,tac-users,tac-readonly")
	p.expect(`tacctl console on ` + host + ` — type 'help'\. Devices: device list\. This session is logged\.\r\n`)
	p.expect(host + `> `)
	p.send("user list\r")
	p.expect(`RAN sudo -n TACCTL_CONSOLE=[0-9a-f]{12} ` + regexp.QuoteMeta(testExe) + ` user list\r\n`)
	p.expect(host + `> `)
	p.send("help\r")
	p.expect(`system-shell +Start your system shell as yourself; superusers only unless enabled for your tier`)
	p.expect(host + `> `)
	// Ctrl-C during a line ends the line, not the console.
	p.send("slow\r")
	p.Settle(300 * time.Millisecond)
	p.send("\x03")
	p.expect(`\[exit 130\]`)
	p.expect(host + `> `)
	p.send("exit\r")
	log := p.ends(0)
	if len(log) != 2 || !regexp.MustCompile(`^auth\.info console start session=[0-9a-f]{12} user=carol from=192\.0\.2\.9 tty=/dev/pts/9 mode=interactive$`).MatchString(log[0]) ||
		!regexp.MustCompile(`^auth\.info console end session=[0-9a-f]{12} user=carol reason=exit lines=4 status=0$`).MatchString(log[1]) {
		t.Errorf("log %q", log)
	}
}

// A typed space completes a fixed word in the console, and does not when
// the policy line says space_completion=no.
func TestConsolePtySpaceCompletion(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, ptyPolicyRO, "carol,tac-users,tac-readonly")
	p.expect(host + `> `)
	p.send("de x\r")
	p.expect(`RAN sudo -n TACCTL_CONSOLE=[0-9a-f]{12} ` + regexp.QuoteMeta(testExe) + ` device x\r\n`)
	p.send("exit\r")
	p.ends(0)

	p = startConsole(t, ptyPolicyRO+",space_completion=no", "carol,tac-users,tac-readonly")
	p.expect(host + `> `)
	p.send("de x\r")
	p.expect(`RAN sudo -n TACCTL_CONSOLE=[0-9a-f]{12} ` + regexp.QuoteMeta(testExe) + ` de x\r\n`)
	p.send("exit\r")
	p.ends(0)
}

func TestConsolePtyIdle(t *testing.T) {
	p := startConsole(t, strings.Replace(ptyPolicyRO, "idle=30", "idle=1", 1), "carol,tac-users,tac-readonly", "idle=s")
	start := time.Now()
	p.expect(`idle timeout after 1s`)
	if d := time.Since(start); d < 900*time.Millisecond {
		t.Errorf("idle after %v", d)
	}
	log := p.ends(0)
	if len(log) != 2 || !strings.HasSuffix(log[1], "reason=idle lines=0 status=0") {
		t.Errorf("log %q", log)
	}
}

func TestConsolePtyCommandRefusedOnATerminal(t *testing.T) {
	p := startConsole(t, ptyPolicyRO, "carol,tac-users,tac-readonly", "c=scp -t .")
	p.expect(regexp.QuoteMeta(console.RefusedText) + `\r\n`)
	log := p.ends(126)
	if len(log) != 3 || !strings.HasSuffix(log[0], "mode=command") || !strings.HasSuffix(log[1], "reason=command first=scp") {
		t.Errorf("log %q", log)
	}
	// One tacctl line runs, with the terminal.
	p = startConsole(t, ptyPolicyRO, "carol,tac-users,tac-readonly", "c=device list")
	p.expect(`RAN sudo -n TACCTL_CONSOLE=[0-9a-f]{12} \S+ device list\r\n`)
	if log := p.ends(0); len(log) != 2 || !strings.HasSuffix(log[1], "reason=command lines=1 status=0") {
		t.Errorf("log %q", log)
	}
}

func TestConsolePtySystemShell(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	// Refused for a readonly caller.
	p := startConsole(t, ptyPolicyRO, "carol,tac-users,tac-readonly")
	p.expect(host + `> `)
	p.send("system-shell\r")
	p.expect(`system-shell is not available for the readonly tier on this console\. An administrator enables it with: tacctl console system-shell tiers superuser,readonly`)
	p.expect(`\[exit 1\]`)
	p.send("exit\r")
	if log := p.ends(0); len(log) != 3 ||
		!regexp.MustCompile(`^auth\.warning console system-shell DENY session=[0-9a-f]{12} user=carol tier=readonly$`).MatchString(log[1]) {
		t.Errorf("log %q", log)
	}

	// Started for a superuser: the stub prints its environment.
	stub := filepath.Join(t.TempDir(), "stub-shell")
	if err := os.WriteFile(stub, []byte("#!/bin/sh\necho \"ARGS=$#\"\nenv | sort | sed 's/^/ENV /'\nexit 7\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	su := "shell=console,idle=30,system_shell=yes,system_shell_path=" + stub + ",tier=superuser,list_max=40"
	p = startConsole(t, su, "carol,tac-users,tac-superuser")
	p.expect(host + `> `)
	p.send("system-shell\r")
	p.expect(`back in the tacctl console\r\n`)
	p.expect(`\[exit 7\]`)
	out := p.Output()
	for _, want := range []string{"ARGS=0", "ENV SHELL=" + stub, "ENV PATH=" + console.ConsolePath, "ENV USER=carol", "ENV TERM=xterm"} {
		if !strings.Contains(out, want+"\r\n") {
			t.Errorf("system shell lacks %q:\n%q", want, out)
		}
	}
	for _, bad := range []string{"ENV TACCTL_", "ENV LD_PRELOAD", "ENV SSH_AUTH_SOCK"} {
		if strings.Contains(out, bad) {
			t.Errorf("system shell has %q", bad)
		}
	}
	p.send("exit\r")
	log := p.ends(0)
	if len(log) != 4 || !regexp.MustCompile(`console system-shell start session=[0-9a-f]{12} user=carol tty=/dev/pts/9 shell=\S+stub-shell$`).MatchString(log[1]) ||
		!regexp.MustCompile(`console system-shell end session=[0-9a-f]{12} user=carol status=7 duration=\d+$`).MatchString(log[2]) ||
		!strings.HasSuffix(log[3], "reason=exit lines=2 status=0") {
		t.Errorf("log %q", log)
	}
}

// The console with the password cache on: the agent starts with the session
// and is shut between lines; a line that uses the cache gets a token of its
// own in the sudo process's environment, which works while that line runs
// (a store is taken and said) and is dead after it; a line that does not use
// the cache opens nothing; 'console forget' empties it; the socket is gone
// when the session ends.
func TestConsolePtyPasswordCache(t *testing.T) {
	if ag, err := askpass.New(askpass.Options{}); errors.Is(err, askpass.ErrNoLock) {
		t.Skipf("mlock is not available here: %v", err)
	} else if err == nil {
		ag.Close()
	}
	host := regexp.QuoteMeta(shortHostname())
	pol := strings.Replace(ptyPolicyRO, "tier=readonly", "tier=operator,password_cache=yes,pc_idle=1,pc_max=1", 1)
	p := startConsole(t, pol, "carol,tac-users,tac-operator")
	p.expect(host + `> `)
	ctx := context.Background()
	tokenOf := func(out string, n int) string {
		m := regexp.MustCompile(`ASKPASS=(\S+:[0-9a-f]{64})`).FindAllStringSubmatch(out, -1)
		if len(m) < n {
			t.Fatalf("no value %d in %q", n, out)
		}
		return m[n-1][1]
	}
	p.send("ssh core\r")
	p.expect(`ASKPASS=(\S+:[0-9a-f]{64})\r\n`)
	env1 := tokenOf(p.Output(), 1)
	if !strings.Contains(env1, "/tacctl/ap-") {
		t.Errorf("socket %q is not in the tacctl socket directory", env1)
	}
	cl1, err := askpass.NewClient(env1)
	if err != nil {
		t.Fatal(err)
	}
	p.expect(host + `> `)
	// The first line is over: its token is dead, whatever is asked.
	if _, err := cl1.Get(ctx); !errors.Is(err, askpass.ErrDenied) {
		t.Errorf("get with the ended line's token: %v", err)
	}
	// A line that does not use the cache opens nothing, whatever token.
	p.send("slow\r")
	time.Sleep(300 * time.Millisecond)
	if err := cl1.Store(ctx, []byte("typed-pw-0")); !errors.Is(err, askpass.ErrDenied) {
		t.Errorf("store while a line that does not use the cache runs: %v", err)
	}
	p.send("\x03")
	p.expect(host + `> `)
	// A line that uses the cache has a token of its own, good while it runs.
	p.send("ssh slow\r")
	p.expect(`ASKPASS=(\S+:[0-9a-f]{64})\r\n`)
	env2 := tokenOf(p.Output(), 2)
	if env2 == env1 {
		t.Fatal("two lines, one token")
	}
	cl2, _ := askpass.NewClient(env2)
	if _, err := cl1.Have(ctx); !errors.Is(err, askpass.ErrDenied) {
		t.Errorf("the previous line's token during the next: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err := cl2.Store(ctx, []byte("typed-pw-1"))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("store: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if have, err := cl2.Have(ctx); err != nil || !have {
		t.Errorf("have while the line runs: %v %v", have, err)
	}
	p.send("\x03")
	p.expect(`password cached for this session \(console password-cache\)`)
	p.expect(host + `> `)
	if _, err := cl2.Get(ctx); !errors.Is(err, askpass.ErrDenied) {
		t.Errorf("get with the token of the line that ended: %v", err)
	}
	p.send("console forget\r")
	p.expect(`password forgotten \(console forget\)`)
	p.send("console forget\r")
	p.expect(`no password is cached`)
	p.send("exit\r")
	p.ends(0)
	if _, err := os.Stat(strings.SplitN(env2, ":", 2)[0]); err == nil {
		t.Error("the socket outlived the session")
	}
}

// A console whose policy does not turn the cache on has no agent: no
// variable reaches the lines, 'console forget' says so.
func TestConsolePtyNoPasswordCache(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, strings.Replace(ptyPolicyRO, "tier=readonly", "tier=operator", 1), "carol,tac-users,tac-operator")
	p.expect(host + `> `)
	p.send("ssh core\r")
	p.expect(`ASKPASS=\r\n`)
	p.send("console forget\r")
	p.expect(`no password is cached: the password cache is not on in this session`)
	p.send("exit\r")
	p.ends(0)
}
