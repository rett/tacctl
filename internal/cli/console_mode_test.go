package cli

// The login console in-process (console_mode.go): the per-line argv with
// the session marker and the -n rule, the -c guard, the batch, the policy
// asked of the root side, the log lines, system-shell's refusals and its
// environment, and the scrub-and-execute of consoleMain. The terminal side
// is console_pty_test.go.

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

const consoleTestPolicy = "shell=console idle=30 system_shell=no system_shell_path=/bin/bash ssh_escape=no agent=no tier=readonly list_max=40\n"

// consoleHarness is the console with args, stdin (not a terminal), the
// caller's groups and the root side's policy answer ("": sudo fails).
func consoleHarness(t *testing.T, stdin, groups, policy string, args ...string) (*harness, func() error) {
	t.Helper()
	h := &harness{runner: &fake.Runner{}}
	env := []string{"USER=carol", "HOME=" + t.TempDir(), "SSH_CLIENT=192.0.2.9 50000 22", "PATH=" + console.ConsolePath,
		"SHELL=/usr/local/bin/tacctl-console"}
	h.app = app.New(nil, paths.NewEnv(env), testExe, 1000,
		app.Stdio{Stdin: strings.NewReader(stdin), Stdout: &h.out, Stderr: &h.err}, h.runner)
	h.runner.On([]string{"id", "-nG"}, execx.Result{Stdout: []byte(groups + "\n")})
	if policy == "" {
		h.runner.Fail([]string{"sudo", "-n"}, 1, "sudo: a password is required")
	} else {
		h.runner.Func(func(c execx.Cmd) bool { return c.Name == "sudo" && slices.Contains(c.Args, "_console-policy") },
			func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(policy)}, nil })
	}
	return h, func() error { return RunConsole(context.Background(), h.app, BuildInfo{Version: "0.2.1-test"}, args) }
}

// consoleLog are the console's own log lines (logger -t tacctl-console).
func consoleLog(r *fake.Runner) []string {
	var out []string
	for _, c := range r.Calls() {
		if c.Name == "logger" && len(c.Args) == 5 && c.Args[1] == console.LogTag {
			out = append(out, c.Args[3]+" "+c.Args[4])
		}
	}
	return out
}

var reSession = regexp.MustCompile(`TACCTL_CONSOLE=([0-9a-f]{12})`)

func TestConsoleLineArgv(t *testing.T) {
	for _, c := range []struct {
		groups, line, want string
	}{
		{"carol tac-users tac-readonly", "user list", "sudo -n TACCTL_CONSOLE=<id> " + testExe + " user list"},
		{"carol tac-users tac-operator", "log failures", "sudo -n TACCTL_CONSOLE=<id> " + testExe + " log failures"},
		{"carol tac-users tac-superuser", "user add bob ops", "sudo TACCTL_CONSOLE=<id> " + testExe + " user add bob ops"},
		{"carol tac-users", "user list", "sudo -n TACCTL_CONSOLE=<id> " + testExe + " user list"},
		{"carol adm", "user list", "sudo TACCTL_CONSOLE=<id> " + testExe + " user list"},
		{"carol tac-users tac-readonly", "ssh core-sw1", "sudo -n TACCTL_CONSOLE=<id> " + testExe + " ssh core-sw1"},
		// The words of noSudo run as the user, without the marker.
		{"carol tac-users tac-readonly", "hash commands", testExe + " hash commands"},
		// A metacharacter is part of a word.
		{"carol tac-users tac-readonly", "user list; id", "sudo -n TACCTL_CONSOLE=<id> " + testExe + " user list; id"},
	} {
		h, run := consoleHarness(t, "", c.groups, consoleTestPolicy, "-c", c.line)
		if err := run(); err != nil {
			t.Errorf("%q: %v (%q)", c.line, err, h.err.String())
		}
		argvs := lines(h.runner)
		if len(argvs) != 2 {
			t.Fatalf("%q: ran %q", c.line, argvs)
		}
		m := reSession.FindStringSubmatch(argvs[0])
		if m == nil || argvs[0] != "sudo -n TACCTL_CONSOLE="+m[1]+" "+testExe+" _console-policy" {
			t.Fatalf("%q: policy asked as %q", c.line, argvs[0])
		}
		if want := strings.ReplaceAll(c.want, "<id>", m[1]); argvs[1] != want {
			t.Errorf("%q:\n got %q\nwant %q", c.line, argvs[1], want)
		}
		want := []string{
			"auth.info console start session=" + m[1] + " user=carol from=192.0.2.9 tty=- mode=command",
			"auth.info console end session=" + m[1] + " user=carol reason=command lines=1 status=0",
		}
		if got := consoleLog(h.runner); !slices.Equal(got, want) {
			t.Errorf("%q: log %q", c.line, got)
		}
	}
}

func TestConsoleGuardRefusals(t *testing.T) {
	for _, line := range []string{
		"scp -t .", "scp -f /etc/passwd", "/usr/lib/openssh/sftp-server", "internal-sftp", "rsync --server -e.LsfxC . .",
		"bash", "sh -c id", "system-shell", "exit", "quit", "history", "", "_console-policy", "user list\nbash",
		"env", "/bin/sh", "user 'list",
	} {
		h, run := consoleHarness(t, "", "carol tac-users tac-readonly", consoleTestPolicy, "-c", line)
		if code := exitCode(run(), h.app.Out); code != 126 {
			t.Errorf("%q: status %d", line, code)
		}
		if h.err.String() != console.RefusedText+"\n" {
			t.Errorf("%q: stderr %q", line, h.err.String())
		}
		if got := lines(h.runner); len(got) != 0 || h.runner.Count("sudo") != 0 {
			t.Errorf("%q: ran %q", line, got)
		}
		log := consoleLog(h.runner)
		if len(log) != 3 || !strings.Contains(log[1], "auth.warning console DENY session=") ||
			!strings.Contains(log[1], " reason=command first=") || !strings.HasSuffix(log[2], "reason=command lines=0 status=126") {
			t.Errorf("%q: log %q", line, log)
		}
	}
	h, run := consoleHarness(t, "", "", consoleTestPolicy, "-c", "scp -t .")
	_ = run()
	if log := consoleLog(h.runner); len(log) < 2 || !strings.HasSuffix(log[1], "reason=command first=scp") {
		t.Errorf("first word: %q", log)
	}
}

func TestConsoleOptionsRefused(t *testing.T) {
	for _, args := range [][]string{{"-x"}, {"-c"}, {"-c", "user list", "extra"}, {"--help"}, {"-l"}, {"user", "list"}} {
		h, run := consoleHarness(t, "", "", consoleTestPolicy, args...)
		if code := exitCode(run(), h.app.Out); code != 126 || h.err.String() != console.NoOptionsText+"\n" {
			t.Errorf("%q: %d %q", args, code, h.err.String())
		}
		if len(h.runner.Calls()) != 0 {
			t.Errorf("%q: ran %q", args, h.runner.Argvs())
		}
	}
}

func TestConsoleBatch(t *testing.T) {
	h, run := consoleHarness(t, "user list\nsystem-shell\nuser list\n", "carol tac-users tac-readonly", consoleTestPolicy)
	if code := exitCode(run(), h.app.Out); code != 126 {
		t.Errorf("status %d", code)
	}
	argvs := lines(h.runner)
	if len(argvs) != 2 || !strings.HasSuffix(argvs[1], " user list") {
		t.Errorf("ran %q", argvs)
	}
	if !strings.Contains(h.err.String(), console.RefusedText) {
		t.Errorf("stderr %q", h.err.String())
	}
	log := consoleLog(h.runner)
	if len(log) != 3 || !strings.HasSuffix(log[0], "mode=batch") || !strings.HasSuffix(log[1], "first=system-shell") ||
		!strings.HasSuffix(log[2], "reason=failed lines=2 status=126") {
		t.Errorf("log %q", log)
	}
	// A batch to its end.
	h, run = consoleHarness(t, "user list\n\nhelp user\n", "carol tac-users tac-readonly", consoleTestPolicy)
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if log := consoleLog(h.runner); len(log) != 2 || !strings.HasSuffix(log[1], "reason=eof lines=2 status=0") {
		t.Errorf("log %q", log)
	}
}

func TestConsoleHelpNamesSystemShell(t *testing.T) {
	h, run := consoleHarness(t, "", "", "", "-c", "help")
	if err := run(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.out.String(), "\n  system-shell ") || !strings.Contains(h.out.String(), shellTop("0.2.1-test", true)) {
		t.Errorf("help:\n%s", h.out.String())
	}
	if strings.Contains(shellTop("v", false), "system-shell") {
		t.Error("tacctl shell's help names system-shell")
	}
}

func TestConsoleSystemShell(t *testing.T) {
	newSession := func(pol console.Remote, tr tier.Tier) (*consoleSession, *harness) {
		h, _ := consoleHarness(t, "", "", consoleTestPolicy)
		h.app.Env = paths.NewEnv([]string{"USER=carol", "TERM=xterm", "PATH=" + console.ConsolePath, "SHELL=/usr/local/bin/tacctl-console",
			"TACCTL_STATE_DIR=/x"})
		inv := &invocation{ctx: context.Background(), app: h.app}
		return &consoleSession{inv: inv, sess: console.Session{ID: "0123456789ab", User: "carol", TTY: "/dev/pts/4"}, pol: pol, tier: tr}, h
	}
	// Refused for the tier: the message names the command that opens it.
	cs, h := newSession(console.DefaultRemote(), tier.Readonly)
	if code := cs.systemShell(context.Background(), true); code != 1 {
		t.Errorf("refused: %d", code)
	}
	if !strings.Contains(h.err.String(), "system-shell is not available for the readonly tier on this console. "+
		"An administrator enables it with: tacctl console system-shell tiers superuser,readonly") {
		t.Errorf("refusal %q", h.err.String())
	}
	if log := consoleLog(h.runner); !slices.Equal(log, []string{"auth.warning console system-shell DENY session=0123456789ab user=carol tier=readonly"}) {
		t.Errorf("log %q", log)
	}
	// Not interactive: the console's refusal, whatever the policy.
	pol := console.DefaultRemote()
	pol.SystemShell, pol.SystemShellPath = true, "/bin/zsh"
	cs, h = newSession(pol, tier.Superuser)
	if code := cs.systemShell(context.Background(), false); code != 126 || !strings.Contains(h.err.String(), console.RefusedText) {
		t.Errorf("batch: %d %q", code, h.err.String())
	}
	// Allowed: the shell as the user (no sudo), no arguments, the
	// console's environment without TACCTL_* and with SHELL=<path>.
	cs, h = newSession(pol, tier.Superuser)
	h.runner.On([]string{"/bin/zsh"}, execx.Result{Code: 3})
	if code := cs.systemShell(context.Background(), true); code != 3 {
		t.Errorf("status %d", code)
	}
	recs := h.runner.Records()
	i := slices.IndexFunc(recs, func(r fake.Record) bool { return r.Cmd.Name == "/bin/zsh" })
	if i < 0 {
		t.Fatalf("no shell started: %q", h.runner.Argvs())
	}
	c := recs[i].Cmd
	if len(c.Args) != 0 || c.AsUser != "" || !slices.Equal(c.Env, []string{"USER=carol", "TERM=xterm", "PATH=" + console.ConsolePath, "SHELL=/bin/zsh"}) {
		t.Errorf("shell %q env %q as %q", c.Args, c.Env, c.AsUser)
	}
	log := consoleLog(h.runner)
	if len(log) != 2 || log[0] != "auth.info console system-shell start session=0123456789ab user=carol tty=/dev/pts/4 shell=/bin/zsh" ||
		!regexp.MustCompile(`^auth\.info console system-shell end session=0123456789ab user=carol status=3 duration=\d+$`).MatchString(log[1]) {
		t.Errorf("log %q", log)
	}
	if !strings.Contains(h.out.String(), "back in the tacctl console") {
		t.Errorf("out %q", h.out.String())
	}
	if consoleTiersWith(tier.None) != "<tiers>" || consoleTiersWith(tier.Operator) != "superuser,operator" {
		t.Error("consoleTiersWith")
	}
}

func TestConsoleRemotePolicy(t *testing.T) {
	// No answer: the defaults, and the tier from the groups.
	h, run := consoleHarness(t, "", "carol tac-users tac-operator", "", "-c", "user list")
	_ = run()
	if got := lines(h.runner); len(got) != 2 || !strings.HasPrefix(got[1], "sudo -n TACCTL_CONSOLE=") {
		t.Errorf("ran %q", got)
	}
	inv := &invocation{ctx: context.Background(), app: h.app}
	if pol := inv.consoleRemotePolicy(testExe, "TACCTL_CONSOLE=0123456789ab"); pol != console.DefaultRemote() {
		t.Errorf("policy %+v", pol)
	}
	h, _ = consoleHarness(t, "", "", "idle=7 system_shell=yes tier=operator")
	inv = &invocation{ctx: context.Background(), app: h.app}
	if pol := inv.consoleRemotePolicy(testExe, "TACCTL_CONSOLE=0123456789ab"); !pol.Known || !pol.SystemShell || pol.Tier != tier.Operator {
		t.Errorf("policy %+v", pol)
	}
}

func TestShellArgvExtraEnv(t *testing.T) {
	env := func(k string) string {
		if k == "SSH_AUTH_SOCK" {
			return "/tmp/a"
		}
		return ""
	}
	for _, c := range []struct {
		words    []string
		noPrompt bool
		extra    []string
		want     string
	}{
		{[]string{"user", "list"}, true, []string{"TACCTL_CONSOLE=0123456789ab"}, "sudo -n TACCTL_CONSOLE=0123456789ab /x user list"},
		{[]string{"user", "list"}, false, []string{"TACCTL_CONSOLE=0123456789ab"}, "sudo TACCTL_CONSOLE=0123456789ab /x user list"},
		{[]string{"host", "list"}, false, []string{"TACCTL_CONSOLE=0123456789ab"}, "sudo TACCTL_CONSOLE=0123456789ab SSH_AUTH_SOCK=/tmp/a /x host list"},
		{[]string{"host", "list"}, true, nil, "sudo -n SSH_AUTH_SOCK=/tmp/a /x host list"},
		{[]string{"completion", "bash"}, true, []string{"TACCTL_CONSOLE=0123456789ab"}, "/x completion bash"},
	} {
		if got := strings.Join(shellArgv("/x", c.words, c.noPrompt, c.extra, env), " "); got != c.want {
			t.Errorf("%q: %q, want %q", c.words, got, c.want)
		}
	}
	for _, c := range []struct {
		managed bool
		t       tier.Tier
		want    bool
	}{
		{true, tier.Readonly, true}, {true, tier.Operator, true}, {true, tier.None, true},
		{true, tier.Superuser, false}, {false, tier.Superuser, false}, {false, tier.None, false},
	} {
		if got := shellNoPrompt(c.managed, c.t); got != c.want {
			t.Errorf("shellNoPrompt(%t, %s) = %t", c.managed, c.t, got)
		}
	}
}

func TestConsoleMainScrubsAndExecutes(t *testing.T) {
	r := &fake.Runner{}
	var out, errb bytes.Buffer
	stdio := app.Stdio{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &errb}
	argv := []string{"-tacctl-console"}
	dirty := []string{"TERM=xterm", "LD_PRELOAD=/tmp/x.so", "TACCTL_SKIP_SUDO=1", "PATH=/tmp/evil", "USER=carol"}
	if code := consoleMain(context.Background(), argv, dirty, stdio, BuildInfo{}, testExe, 1000, r); code != 0 {
		t.Fatalf("status %d %q", code, errb.String())
	}
	ex := r.Execs()
	want := []string{"TERM=xterm", "USER=carol", "PATH=" + console.ConsolePath, "SHELL=" + paths.ConsoleCommand}
	if len(ex) != 1 || ex[0].Path != testExe || !slices.Equal(ex[0].Argv, argv) || !slices.Equal(ex[0].Env, want) {
		t.Fatalf("execs %+v", ex)
	}
	if len(r.Calls()) != 0 {
		t.Errorf("ran before the re-exec: %q", r.Argvs())
	}
	// A failed execve is the refusal status.
	r = &fake.Runner{ExecErr: errors.New("exec format error")}
	if code := consoleMain(context.Background(), argv, dirty, stdio, BuildInfo{}, testExe, 1000, r); code != 126 {
		t.Errorf("failed exec: %d", code)
	}
	if code := consoleMain(context.Background(), argv, dirty, stdio, BuildInfo{}, "", 1000, &fake.Runner{}); code != 126 {
		t.Errorf("no exe: %d", code)
	}
	// The scrubbed environment: the console runs.
	r = &fake.Runner{}
	out.Reset()
	if code := consoleMain(context.Background(), []string{"tacctl-console", "-c", "help"}, want, stdio, BuildInfo{Version: "v"}, testExe, 1000, r); code != 0 {
		t.Fatalf("status %d %q", code, errb.String())
	}
	if len(r.Execs()) != 0 || !strings.Contains(out.String(), "system-shell") {
		t.Errorf("execs %+v out %q", r.Execs(), out.String())
	}
}
