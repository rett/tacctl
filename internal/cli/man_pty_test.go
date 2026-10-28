package cli

// 'man' at the shell and at the console, on a pseudo-terminal, with the real
// man, groff and less: the page opens, q returns to the prompt, and the pager
// cannot start a program. The line runs as '<exe> man ...' (a word of noSudo),
// which the two helpers' runners send to this test binary started again in
// helper mode (TestManPtyHelper), where the command is the real one on the
// terminal it was given, with the page built into the binary and an
// environment that tries to turn the pager into a shell.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
)

const manPtyHelperRun = "-test.run=^TestManPtyHelper$"

// shellPtyMan makes TestShellPtyHelper run the lines 'man ...' for real.
const shellPtyMan = "man-real"

// manPtyCanary is the prefix of the files that the hostile environment of the
// helper would create if the pager ran what it was told to.
const manPtyCanary = "canary="

// manPtyRunner sends 'man ...' of the shell or the console to the helper.
type manPtyRunner struct {
	execx.Runner
	canary string
}

func (r manPtyRunner) Start(ctx context.Context, c execx.Cmd) (execx.Process, error) {
	if len(c.Args) > 0 && c.Args[0] == "man" && c.Name != "sudo" {
		exe, _ := os.Executable()
		c.Name = exe
		c.Args = append([]string{manPtyHelperRun, "-test.count=1", manPtyCanary + r.canary}, c.Args...)
	}
	return r.Runner.Start(ctx, c)
}

// TestManPtyHelper is 'tacctl man ...' for the terminal tests: this binary
// started with only this test selected, the canary prefix and the words.
func TestManPtyHelper(t *testing.T) {
	if !slices.Contains(os.Args, manPtyHelperRun) {
		return
	}
	i := slices.IndexFunc(os.Args, func(a string) bool { return strings.HasPrefix(a, manPtyCanary) })
	canary := strings.TrimPrefix(os.Args[i], manPtyCanary)
	// What a user (or an attacker who can set the environment of a login) may
	// export to make a pager run something.
	env := append([]string{"PATH=/usr/bin:/bin", "TERM=xterm", "LC_ALL=C.UTF-8", "TACCTL_SKIP_SUDO=1"},
		"PAGER=touch "+canary+".pager", "MANPAGER=touch "+canary+".manpager", "LESSOPEN=|touch "+canary+".lessopen %s",
		"LESSCLOSE=touch "+canary+".lessclose", "LESS=-r", "MANOPT=-P 'touch "+canary+".manopt'", "LESSSECURE=0",
		"GROFF_TMAC_PATH="+filepath.Dir(canary), "MAN_KEEP_FORMATTING=1")
	a := app.New(os.Args[i+1:], paths.NewEnv(env), "", os.Geteuid(),
		app.Stdio{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}, execx.Real{})
	a.Paths = a.Paths.Reroot(t.TempDir()) // no page installed: the built-in copy
	code := exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.1-pty"}), a.Out)
	_ = a.Close()
	if code != 0 {
		t.Fail() // the helper's own status, for the shell's [exit n]
	}
}

// manToolsOrSkip skips the test where the page cannot be shown for real.
func manToolsOrSkip(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"man", "groff", "less"} {
		if _, err := (execx.Real{}).LookPath(tool); err != nil {
			t.Skipf("%s is not installed: the pager cannot be run for real", tool)
		}
	}
}

// noCanaries fails the test if the hostile environment had any effect.
func noCanaries(t *testing.T, canary string) {
	t.Helper()
	if m, _ := filepath.Glob(canary + ".*"); len(m) > 0 {
		t.Errorf("the environment of the caller ran a program: %v", m)
	}
}

// manSession drives a prompt: man opens the page at a heading, the keys that
// run a program, edit or write are refused, q returns to the prompt.
func manSession(t *testing.T, p interface {
	Send(string) error
	Expect(string, time.Duration) error
}, prompt string, canary string) {
	t.Helper()
	const slow = 20 * time.Second
	expect := func(re string) {
		t.Helper()
		if err := p.Expect(re, slow); err != nil {
			t.Fatal(err)
		}
	}
	send := func(s string) {
		t.Helper()
		if err := p.Send(s); err != nil {
			t.Fatal(err)
		}
	}
	// At the heading: the first paragraph of TIERS is on the screen.
	send("man tiers\r")
	expect(`A\s+user\s+of\s+tacctl\s+who\s+has\s+a\s+local\s+account`)
	// No shell escape, no editor, no pipe, no log file, no other file.
	for _, k := range []struct{ keys, refusal string }{
		{"!", `Command not available`}, {"v", `Command not available`}, {"|", `Command not available`},
		{":e", `Command not available`}, {"s" + canary + ".save\r", `log file support is not available`},
	} {
		send(k.keys)
		expect(k.refusal)
		send("\r")
	}
	send("q")
	expect(prompt)
	// A word that is no entry opens the top of the page and says so.
	send("man nosuch\r")
	expect(`no entry for 'nosuch'; the page is opened at the top\.`)
	expect(`tacctl - manage pluggable network-device AAA`)
	send("q")
	expect(prompt)
	noCanaries(t, canary)
}

func TestPtyShellMan(t *testing.T) {
	manToolsOrSkip(t)
	canary := filepath.Join(t.TempDir(), "x")
	s := startCLIShell(t, 120, shellPtyMan, manPtyCanary+canary)
	manSession(t, s, `tacctl> `, canary)
	if err := s.Send("exit\r"); err != nil {
		t.Fatal(err)
	}
}

func TestPtyConsoleMan(t *testing.T) {
	manToolsOrSkip(t)
	canary := filepath.Join(t.TempDir(), "x")
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, ptyPolicyRO, "carol,tac-users,tac-readonly", manPtyCanary+canary)
	p.expect(host + `> `)
	manSession(t, p.Session, host+`> `, canary)
	p.send("exit\r")
	log := p.ends(0)
	if len(log) != 2 {
		t.Errorf("log %q", log)
	}
}
