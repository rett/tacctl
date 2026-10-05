package shell

// Terminal tests: the shell runs in a process of its own (this test binary,
// started again in helper mode) on a pseudo-terminal, with its commands run
// as real programs, so the keys, the signals of the terminal's line
// discipline and the raw/cooked switching are the real ones. Each session
// has the 10 s deadline of internal/testpty, after which its whole process
// group is killed.

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/testpty"
	"github.com/rett/tacctl/internal/ui"
)

const (
	helperArg = "tacctl-shell-pty-helper"
	childArg  = "tacctl-shell-pty-child"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case helperArg:
			ptyHelper(os.Args[2:])
			return
		case childArg:
			ptyChild()
			return
		}
	}
	m.Run()
}

// ptyChild is a command for the shell to run: it reports what it inherited
// and the terminal as it finds it, on one line, then waits 8 s and prints
// 'finished'. It is one process that does nothing after the report, so the
// report is the moment from which a Ctrl-C is certain to reach it; it keeps
// the Go runtime's default for SIGINT (die of it, status 130).
//
//	CHILD isig=<b> icanon=<b> echo=<b> foreground=<b> sigign=<hex> sigblk=<hex>
//
// A shell script ('sh -c "echo started; sleep 8"') cannot be the command
// of a Ctrl-C test: dash catches SIGINT under -c and spawns with vfork, and
// its handler drops SIGINT in the vforked child before the exec, so a
// Ctrl-C in that window is lost and the sleep runs out.
func ptyChild() {
	fd := int(os.Stdin.Fd())
	tio, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		fmt.Printf("CHILD error %v\n", err)
		return
	}
	fg, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		fmt.Printf("CHILD error %v\n", err)
		return
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Printf("CHILD error %v\n", err)
		return
	}
	field := func(name string) string {
		m := regexp.MustCompile(`(?m)^` + name + `:\s*([0-9a-f]+)$`).FindSubmatch(status)
		if m == nil {
			return "none"
		}
		return string(m[1])
	}
	fmt.Printf("CHILD isig=%t icanon=%t echo=%t foreground=%t sigign=%s sigblk=%s\n",
		tio.Lflag&unix.ISIG != 0, tio.Lflag&unix.ICANON != 0, tio.Lflag&unix.ECHO != 0,
		fg == unix.Getpgrp(), field("SigIgn"), field("SigBlk"))
	time.Sleep(8 * time.Second)
	fmt.Println("finished")
}

// ptyHelper is the shell as 'tacctl shell' runs it, with each line run as
// a program ('sleep 1', 'sh -c ...') and the completer of editor_test.go.
// It prints 'STATUS <n>' when the shell ends.
func ptyHelper(args []string) {
	fs := flag.NewFlagSet(helperArg, flag.ContinueOnError)
	idle := fs.Duration("idle", 0, "")
	hist := fs.String("hist", "", "")
	listMax := fs.Int("listmax", 0, "")
	if err := fs.Parse(args); err != nil {
		return
	}
	// As cli.Main: SIGINT, SIGTERM and SIGHUP cancel the context.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	out := ui.Output{Stdout: os.Stdout, Stderr: os.Stderr}
	sh := New(Options{
		Out:      out,
		Idle:     *idle,
		History:  NewHistory(*hist, os.Stderr),
		Complete: testCompleter,
		ListMax:  *listMax,
		Exec: func(ctx context.Context, words []string, stdin io.Reader) int {
			code, _, err := execx.Attached(ctx, execx.Real{}, execx.Cmd{Name: words[0], Args: words[1:]}, stdin, os.Stdout, os.Stderr)
			if err != nil && code == 0 {
				code = 1
			}
			return code
		},
	})
	status := sh.Interactive(ctx, os.Stdin)
	fmt.Printf("STATUS %d\n", status)
}

type ptySession struct {
	*testpty.Session
	t    *testing.T
	hist string
}

func startShell(t *testing.T, args ...string) *ptySession {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hist := filepath.Join(t.TempDir(), "history")
	s, err := testpty.Start(testpty.Options{
		Path: exe,
		Argv: append([]string{exe, helperArg, "-hist", hist}, args...),
		Env:  []string{"PATH=/usr/bin:/bin", "TERM=xterm", "HOME=" + t.TempDir(), "LC_ALL=C.UTF-8"},
		Rows: 24, Cols: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		s.Close()
		if out := s.Output(); strings.Contains(out, "DATA RACE") {
			t.Errorf("data race in the shell:\n%s", out)
		}
	})
	p := &ptySession{Session: s, t: t, hist: hist}
	p.expect(`tacctl> `)
	return p
}

func (p *ptySession) send(s string) {
	p.t.Helper()
	if err := p.Send(s); err != nil {
		p.t.Fatal(err)
	}
}

func (p *ptySession) expect(re string) {
	p.t.Helper()
	if err := p.Expect(re, 5*time.Second); err != nil {
		p.t.Fatal(err)
	}
}

// line types a line and waits for the shell to echo the end of the line.
func (p *ptySession) line(s string) {
	p.t.Helper()
	p.send(s + "\r")
}

// output waits for a line of output of a command: after the newline of
// the line typed, or after the shell switched bracketed paste off.
func (p *ptySession) output(line string) {
	p.t.Helper()
	p.expect(`(?:\n|\x1b\[\?2004l)` + regexp.QuoteMeta(line) + `\r\n`)
}

// exits waits for the shell to end with status.
func (p *ptySession) exits(status int) {
	p.t.Helper()
	p.expect(`STATUS ` + strconv.Itoa(status) + `\r\n`)
	if _, err := p.Wait(5 * time.Second); err != nil {
		p.t.Fatal(err)
	}
}

func TestPtyPromptRunAndExit(t *testing.T) {
	p := startShell(t)
	p.line("echo hello")
	p.output("hello")
	p.expect(`tacctl> `)
	p.line("sh -c 'exit 3'")
	p.expect(`\[exit 3\]`)
	p.expect(`tacctl> `)
	p.line("true")
	p.expect(`tacctl> `)
	if strings.Contains(p.Settle(100*time.Millisecond), "[exit") {
		t.Error("[exit] after a zero status")
	}
	p.line("exit")
	p.exits(0)
	b, err := os.ReadFile(p.hist)
	if err != nil || string(b) != "echo hello\nsh -c 'exit 3'\ntrue\nexit\n" {
		t.Errorf("history %q, %v", b, err)
	}
}

func TestPtyCompletion(t *testing.T) {
	p := startShell(t)
	p.send("us\t")
	p.expect(`user `)
	p.send("\t")
	if out := p.Settle(200 * time.Millisecond); strings.Contains(out, "List all users") {
		t.Fatalf("the first Tab listed: %q", out)
	}
	p.send("\t")
	p.expect(`\r\nlist  show\r\n`)
	p.expect(`tacctl> user `)
	p.send("sh\t")
	p.expect(`show `)
	p.send("b\t\r")
	p.expect(`user show bob \r\n`)
	p.expect(`\[exit 127\]`) // no program 'user' here: the line ran as completed
	p.line("quit")
	p.exits(0)
}

// '?' lists the choices with their descriptions at once and inserts
// nothing; inside quotes and after a backslash it is a character.
func TestPtyQuestionMark(t *testing.T) {
	p := startShell(t)
	p.send("user ?")
	p.expect(`tacctl> user \r\nPossible completions:\r\n  list  List all users\r\n  show  Show a user\r\n`)
	p.expect(`tacctl> user `)
	p.send("\x15") // Ctrl-U
	p.send("echo \"^show ?\" '?' a\\?\r")
	p.output(`^show ? ? a?`)
	p.expect(`tacctl> `)
	p.line("exit")
	p.exits(0)
	b, err := os.ReadFile(p.hist)
	if err != nil || string(b) != "echo \"^show ?\" '?' a\\?\nexit\n" {
		t.Errorf("history %q, %v", b, err)
	}
}

// A '?' list taller than the terminal (24 rows) pages: a screenful, the
// more prompt; Space the next screenful, Enter one row, q stops; the
// prompt and the line come back. -listmax -1: no question first.
func TestPtyPager(t *testing.T) {
	p := startShell(t, "-listmax", "-1")
	p.send("many ?")
	p.expect(`Possible completions:\r\n  n01  device\r\n(?s:.*)  n22  device\r\n` + regexp.QuoteMeta(morePrompt))
	if out := p.Settle(200 * time.Millisecond); strings.Contains(out, "n23") {
		t.Fatalf("more than a screenful: %q", out)
	}
	p.send(" ")
	p.expect(`\r\x1b\[K  n23  device\r\n(?s:.*)  n45  device\r\ntacctl> many `)
	p.send("?")
	p.expect(regexp.QuoteMeta(morePrompt))
	p.send("\r")
	p.expect(`\r\x1b\[K  n23  device\r\n` + regexp.QuoteMeta(morePrompt))
	p.send("q")
	p.expect(`\r\x1b\[Ktacctl> many `)
	if out := p.Settle(200 * time.Millisecond); strings.Contains(out, "n24") {
		t.Fatalf("listed after q: %q", out)
	}
	p.send("n01\r")
	p.expect(`\[exit 127\]`)
	p.line("exit")
	p.exits(0)
	b, _ := os.ReadFile(p.hist)
	if string(b) != "many n01\nexit\n" {
		t.Errorf("history %q", b)
	}
}

// Above ListMax (40 by default) Tab asks first; below it, no question.
func TestPtyLongListAsks(t *testing.T) {
	p := startShell(t)
	p.send("many \t")
	p.expect(`many n`)
	p.send("\t")
	p.expect(regexp.QuoteMeta("Show all 45 devices? [y/N] "))
	p.send("x")
	p.expect(regexp.QuoteMeta("\r\ntype more letters to narrow it (e.g. n0…<Tab>)\r\ntacctl> many n"))
	p.send("\x15user \t\t")
	p.expect(`\r\nlist  show\r\n`)
	if strings.Contains(p.Output(), "Show all 2") {
		t.Error("a short list asked")
	}
	p.send("\x15exit\r")
	p.exits(0)
}

func TestPtyCtrlCAtThePrompt(t *testing.T) {
	p := startShell(t)
	p.send("abc")
	p.expect(`abc`)
	p.send("\x03")
	p.expect(`abc\^C\r\n`)
	p.expect(`tacctl> `)
	p.send("\x03")
	p.expect(`\^C\r\n`)
	p.expect(`tacctl> `)
	p.line("echo alive")
	p.output("alive")
	p.expect(`tacctl> `)
	p.send("\x04")
	p.exits(0)
	b, _ := os.ReadFile(p.hist)
	if string(b) != "echo alive\n" {
		t.Errorf("history %q: an interrupted line was recorded", b)
	}
	if strings.Contains(p.Output(), "[exit 127]") {
		t.Error("the interrupted line ran")
	}
}

// Ctrl-C while a command runs ends the command, not the shell. The command
// (ptyChild) reports, once it is in place, that the terminal is cooked with
// ISIG, that it is in the foreground process group and that SIGINT is
// neither ignored nor blocked; the test checks the terminal again on its
// side before it sends Ctrl-C.
func TestPtyCtrlCDuringACommand(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := startShell(t)
	p.line(exe + " " + childArg)
	p.expect(`CHILD [^\n]*\n`)
	m := regexp.MustCompile(`CHILD isig=(\w+) icanon=(\w+) echo=(\w+) foreground=(\w+) sigign=([0-9a-f]+) sigblk=([0-9a-f]+)\r?\n`).FindStringSubmatch(p.Output())
	if m == nil {
		t.Fatalf("no report from the command: %q", p.Output())
	}
	if m[1] != "true" || m[2] != "true" || m[3] != "true" {
		t.Errorf("the command got the terminal with isig=%s icanon=%s echo=%s, not cooked", m[1], m[2], m[3])
	}
	if m[4] != "true" {
		t.Error("the command is not in the terminal's foreground process group")
	}
	for i, name := range []string{"SigIgn", "SigBlk"} {
		mask, err := strconv.ParseUint(m[5+i], 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if mask&(1<<(uint(syscall.SIGINT)-1)) != 0 {
			t.Errorf("%s %s: SIGINT set in the command", name, m[5+i])
		}
	}
	tio, err := unix.IoctlGetTermios(int(p.Master.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if tio.Lflag&unix.ISIG == 0 {
		t.Fatal("ISIG is off on the terminal while the command runs: Ctrl-C would be a byte, not SIGINT")
	}
	if t.Failed() {
		t.FailNow()
	}
	start := time.Now()
	p.send("\x03")
	p.expect(`\[exit 130\]`)
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("the command ended %v after Ctrl-C", d)
	}
	p.expect(`tacctl> `)
	p.line("echo alive")
	p.output("alive")
	p.line("exit")
	p.exits(0)
	if strings.Contains(p.Output(), "finished") {
		t.Error("the command was not interrupted")
	}
}

// Ctrl-Z does nothing at the prompt, and a command inherits SIGTSTP and
// SIGQUIT as ignored (and SIGINT not ignored): Ctrl-Z during a command
// stops nothing, so the session cannot hang on a stopped child.
func TestPtyCtrlZIgnored(t *testing.T) {
	p := startShell(t)
	p.send("\x1a\x1c")
	p.line("echo after")
	p.output("after")
	p.line(`sh -c 'grep ^SigIgn: /proc/self/status; echo started; sleep 1; echo finished'`)
	p.output("started")
	p.send("\x1a")
	p.expect(`finished\r\n`) // after the terminal's echo of ^Z
	p.expect(`tacctl> `)
	m := regexp.MustCompile(`SigIgn:\s*([0-9a-f]+)`).FindStringSubmatch(p.Output())
	if m == nil {
		t.Fatalf("no SigIgn line: %q", p.Output())
	}
	mask, err := strconv.ParseUint(m[1], 16, 64)
	if err != nil {
		t.Fatal(err)
	}
	bit := func(sig syscall.Signal) bool { return mask&(1<<(uint(sig)-1)) != 0 }
	if !bit(syscall.SIGTSTP) || !bit(syscall.SIGQUIT) {
		t.Errorf("SigIgn %s: SIGTSTP or SIGQUIT not ignored in the command", m[1])
	}
	if bit(syscall.SIGINT) {
		t.Errorf("SigIgn %s: SIGINT ignored in the command", m[1])
	}
	p.line("exit")
	p.exits(0)
}

func TestPtyCtrlD(t *testing.T) {
	p := startShell(t)
	p.send("\x04")
	p.exits(0)
}

func TestPtyIdleTimeout(t *testing.T) {
	p := startShell(t, "-idle", "400ms")
	// A command that runs longer than the idle time does not trip it.
	p.line("sh -c 'sleep 0.8; echo done'")
	p.output("done")
	p.expect(`tacctl> `)
	start := time.Now()
	p.expect(`idle timeout after 400ms`)
	if d := time.Since(start); d < 300*time.Millisecond {
		t.Errorf("idle timeout after %v", d)
	}
	p.exits(0)
}

func TestPtyReverseSearch(t *testing.T) {
	p := startShell(t)
	p.line("echo alpha")
	p.output("alpha")
	p.line("echo beta")
	p.output("beta")
	p.expect(`tacctl> `)
	p.send("\x12")
	p.expect("\\(reverse-i-search\\)`': ")
	p.send("alp")
	p.expect("\\(reverse-i-search\\)`alp': echo alpha")
	p.send("\r")
	p.output("alpha")
	p.expect(`tacctl> `)
	// Ctrl-G gives the line back as it was.
	p.send("draft")
	p.send("\x12")
	p.send("bet")
	p.expect("`bet': echo beta")
	p.send("\x07")
	p.send(" more\r")
	p.expect(`\[exit 127\]`) // 'draft more' ran as typed
	p.line("exit")
	p.exits(0)
	b, _ := os.ReadFile(p.hist)
	if !strings.Contains(string(b), "echo alpha\necho beta\necho alpha\ndraft more\n") {
		t.Errorf("history %q", b)
	}
}

func TestPtyWordMoves(t *testing.T) {
	p := startShell(t)
	p.send("echo one two")
	p.expect(`two`)
	p.send("\x1bb\x1bbX")
	p.send("\r")
	p.output("Xone two")
	p.expect(`tacctl> `)
	p.send("echo one two")
	p.expect(`two`)
	p.send("\x01\x1bfY\r")
	p.output("Yone two")
	p.line("exit")
	p.exits(0)
}

func TestPtyPaste(t *testing.T) {
	p := startShell(t)
	p.send("\x1b[200~echo pasted\nline\r\tend\x1b[201~")
	if out := p.Settle(300 * time.Millisecond); strings.Contains(out, "\npasted") {
		t.Fatalf("a newline in a paste ran the line: %q", out)
	}
	p.send("\r")
	p.output("pasted line end")
	p.send("\x1b[200~" + strings.Repeat("x", PasteMax+100) + "\x1b[201~")
	p.send("\x15") // Ctrl-U: drop the pasted text
	p.line("exit")
	p.exits(0)
}

func TestPtyTerminate(t *testing.T) {
	p := startShell(t)
	if err := syscall.Kill(p.Pid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	p.exits(128 + int(syscall.SIGTERM))
}

// A resize (SIGWINCH) while a line is being typed repaints it for the new
// width; the line still runs whole.
func TestPtyResize(t *testing.T) {
	p := startShell(t)
	p.send("echo " + strings.Repeat("w", 30))
	p.expect(`w{30}`)
	if err := p.Resize(24, 20); err != nil {
		t.Fatal(err)
	}
	p.Settle(200 * time.Millisecond)
	p.send(" end\r")
	p.output(strings.Repeat("w", 30) + " end")
	p.expect(`tacctl> `)
	if err := p.Resize(30, 120); err != nil {
		t.Fatal(err)
	}
	p.line("echo wide")
	p.output("wide")
	p.line("exit")
	p.exits(0)
}

// A terminal that reports no size (0x0, as expect(1) leaves its pty) keeps
// the editor's default width: the prompt and the line are not wrapped
// after every character.
func TestPtyZeroSize(t *testing.T) {
	p := startShell(t)
	if err := p.Resize(0, 0); err != nil {
		t.Fatal(err)
	}
	p.Settle(200 * time.Millisecond)
	p.line("echo zero")
	p.output("zero")
	p.expect(`tacctl> `)
	p.send("echo abc")
	p.expect(`echo abc`)
	p.send("\r")
	p.output("abc")
	p.line("exit")
	p.exits(0)
}
