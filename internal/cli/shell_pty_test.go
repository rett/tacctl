package cli

// 'tacctl shell' on a pseudo-terminal: the real command (Run with the
// arguments 'shell', in this test binary started again in helper mode),
// for what 'help' prints, what a double Tab lists and what '?' prints.

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/testpty"
)

// shellPtyHelperRun is the argument that starts the helper test below.
// shellPtyFakeNames makes the helper answer the live names from a script.
const shellPtyFakeNames = "fake-names"

// shellPtyManyNames makes the fake registry hold 45 devices (core01..core45).
const shellPtyManyNames = "many-names"

const shellPtyHelperRun = "-test.run=^TestShellPtyHelper$"

// TestShellPtyHelper is 'tacctl shell' for the terminal tests: they start
// this binary with only this test selected. In a normal run it does nothing.
func TestShellPtyHelper(t *testing.T) {
	if !slices.Contains(os.Args, shellPtyHelperRun) {
		return
	}
	exe, _ := os.Executable()
	env := paths.NewEnv([]string{"TACCTL_SKIP_SUDO=1", "PATH=/usr/bin:/bin", "HOME=" + t.TempDir()})
	var runner execx.Runner = execx.Real{}
	if slices.Contains(os.Args, shellPtyFakeNames) {
		// The names of the registry as 'sudo -n tacctl _completion-names'
		// answers them; every other program exits 0 with no output.
		f := &fake.Runner{}
		many := slices.Contains(os.Args, shellPtyManyNames)
		f.OnFunc([]string{"sudo", "-n", "tacctl", "_completion-names"}, func(c execx.Cmd) (execx.Result, error) {
			if slices.Contains(c.Args, "devices") && slices.Contains(c.Args, "--desc") && many {
				var b strings.Builder
				for i := 1; i <= 45; i++ {
					fmt.Fprintf(&b, "core%02d\tcisco 10.0.0.%d prod\n", i, i)
				}
				return execx.Result{Stdout: []byte(b.String())}, nil
			}
			if slices.Contains(c.Args, "devices") && slices.Contains(c.Args, "--desc") {
				return execx.Result{Stdout: []byte("ar1\tcisco 10.0.0.1 prod\ndev\tjuniper 10.20.0.22 lab\nweb1\tlinux h.example lab\n")}, nil
			}
			return execx.Result{}, nil
		})
		runner = f
	}
	a := app.New([]string{"shell"}, env, exe, os.Geteuid(),
		app.Stdio{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}, runner)
	if err := Run(context.Background(), a, BuildInfo{Version: "0.2.1-pty"}); err != nil {
		t.Fatal(err)
	}
}

func startCLIShell(t *testing.T, cols uint16, extra ...string) *testpty.Session {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := testpty.Start(testpty.Options{
		Path: exe,
		Argv: append([]string{exe, shellPtyHelperRun, "-test.count=1"}, extra...),
		Env:  []string{"PATH=/usr/bin:/bin", "TERM=xterm", "LC_ALL=C.UTF-8", "HOME=" + t.TempDir()},
		Rows: 60, Cols: cols,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Expect(`tacctl> `, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	return s
}

// The help of the shell is the usage of 'tacctl' with the shell's own
// lines after it.
func TestPtyShellHelp(t *testing.T) {
	s := startCLIShell(t, 140)
	if err := s.Send("help\r"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`Ctrl-D +Leave the shell\r\n\r\n`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(s.Output(), "\r\n", "\n")
	if want := shellTop("0.2.1-pty", false); !strings.Contains(out, want) {
		t.Errorf("help is not the usage block:\n%q\nwant\n%q", out, want)
	}
	// The command list is the one of 'tacctl' itself.
	top := Usage("top", UsageVars{"version": "0.2.1-pty"})
	list := top[strings.Index(top, "Commands:\n"):strings.Index(top, "\nRun any command")]
	if !strings.Contains(out, list) {
		t.Errorf("help lacks the command list of the usage:\n%q", out)
	}
	if !strings.Contains(out, "\nUsage: <command> [arguments]\n") || !strings.Contains(out, "\n  help user\n") {
		t.Errorf("help does not speak of the shell:\n%q", out)
	}
	if err := s.Send("shell\r"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`already in the tacctl shell`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`\[exit 1\]`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// shellColumns is the Tab list as bash prints it: the words down then
// across, as many columns as fit width (each 2 wider than the longest).
func shellColumns(words []string, width int) string {
	colw := 0
	for _, w := range words {
		colw = max(colw, len(w)+2)
	}
	ncols := max(1, width/colw)
	nrows := (len(words) + ncols - 1) / ncols
	var b strings.Builder
	for r := range nrows {
		var row strings.Builder
		for c := range ncols {
			if i := c*nrows + r; i < len(words) {
				row.WriteString(words[i] + strings.Repeat(" ", colw-len(words[i])))
			}
		}
		b.WriteString(strings.TrimRight(row.String(), " ") + "\r\n")
	}
	return b.String()
}

// A double Tab on an empty line lists the command names alone, in columns
// that fit the terminal, alphabetical, without the shell's own words;
// 'shell' is not among them.
func TestPtyShellTabListing(t *testing.T) {
	s := startCLIShell(t, 140)
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(200 * time.Millisecond); strings.Contains(got, "version") {
		t.Fatalf("the first Tab listed: %q", got)
	}
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range topRows() {
		if r.Name != "shell" {
			names = append(names, r.Name)
		}
	}
	sort.Strings(names)
	want := "tacctl> \r\n" + shellColumns(names, 140) + "tacctl> "
	if err := s.Expect(regexp.QuoteMeta(want), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	out := s.Output()
	for _, w := range []string{"shell", "history", "Print tacctl version", "[--long]"} {
		if strings.Contains(out, w) {
			t.Errorf("the listing has %q:\n%q", w, out)
		}
	}
}

// Tab twice after 'ssh ': the line stays where it is, the list starts on
// the next line with the live names alone, in columns; no flag is listed,
// and the prompt comes back with the line.
func TestPtyShellNamesListing(t *testing.T) {
	s := startCLIShell(t, 120, shellPtyFakeNames)
	if err := s.Send("ssh \t"); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(200 * time.Millisecond); strings.Contains(got, "web1") {
		t.Fatalf("the first Tab listed: %q", got)
	}
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	const list = "tacctl> ssh \r\nar1   dev   web1\r\ntacctl> ssh "
	if err := s.Expect(regexp.QuoteMeta(list), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(100 * time.Millisecond); strings.Contains(got, "-p") || strings.Contains(got, "cisco") {
		t.Errorf("a flag or a description was listed: %q", got)
	}
	// A '-' asks for the flags (Tab twice: there are several).
	if err := s.Send("-\t\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`-D\s+-L\s+-R\s+-X\s+-Y\s+-g\s+-p`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// '?' inserts nothing and prints help for the cursor's position: on an
// empty line the command rows of 'help', after 'ssh ' the names with their
// descriptions, after 'user add ' the usage of 'user add' and what comes
// next; inside quotes it is typed.
func TestPtyShellQuestionMark(t *testing.T) {
	s := startCLIShell(t, 120, shellPtyFakeNames)
	if err := s.Send("?"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`tacctl> \r\nPossible completions:\r\n  backend .*\r\n(?s:.*)  version \[--long\] +Print tacctl version.*\r\ntacctl> $`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("ssh ?"); err != nil {
		t.Fatal(err)
	}
	const list = "tacctl> ssh \r\nPossible completions:\r\n" +
		"  ar1   cisco   10.0.0.1   prod\r\n" +
		"  dev   juniper 10.20.0.22 lab\r\n" +
		"  web1  linux   h.example  lab\r\n" +
		"tacctl> ssh "
	if err := s.Expect(regexp.QuoteMeta(list), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("\x15user add ?"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("tacctl> user add \r\nUsage:\r\n  add <username> <group> ")+`(?s:.*)`+
		regexp.QuoteMeta("Options:\r\n")+`(?s:.*)`+regexp.QuoteMeta("Next: <username> <group>\r\ntacctl> user add "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// Inside quotes it is typed: the line keeps it.
	if err := s.Send("\x15group commands add x permit --match \"^show ?"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta(`--match "^show ?`), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(200 * time.Millisecond); strings.Contains(got, "\r\n") {
		t.Errorf("'?' inside quotes printed: %q", got)
	}
}

// A line longer than the terminal is wide stays whole above the list, and
// the prompt and line come back after it; the columns follow the width,
// also after the terminal changed its size.
func TestPtyShellListingWrapped(t *testing.T) {
	s := startCLIShell(t, 10, shellPtyFakeNames)
	if err := s.Send("ssh \t\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("tacctl> ssh \r\nar1\r\ndev\r\nweb1\r\ntacctl> ss\r\nh "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Resize(60, 40); err != nil {
		t.Fatal(err)
	}
	// The shell takes the new size on SIGWINCH and repaints the line on
	// one row; Tab before that would list at the old width.
	if err := s.Expect(regexp.QuoteMeta("tacctl> ssh "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("\t\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("tacctl> ssh \r\nar1   dev   web1\r\ntacctl> ssh "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// More than 40 names: Tab and '?' ask first. n (or any key but y) shows
// a hint and the line comes back; y lists.
func TestPtyShellLongListAsks(t *testing.T) {
	s := startCLIShell(t, 120, shellPtyFakeNames, shellPtyManyNames)
	if err := s.Send("ssh \t"); err != nil {
		t.Fatal(err)
	}
	// The first Tab completes the common prefix 'core'.
	if err := s.Expect(`ssh core`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("tacctl> ssh core\r\n")+`.*`+regexp.QuoteMeta("Show all 45 devices? [y/N] "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("n"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("\r\ntype more letters to narrow it (e.g. core0…<Tab>)\r\ntacctl> ssh core"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(200 * time.Millisecond); strings.Contains(got, "core01") {
		t.Fatalf("listed after n: %q", got)
	}
	// Tab again asks again; y lists the names in columns.
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("Show all 45 devices? [y/N] "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("y"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("y\r\ncore01  core04")+`(?s:.*)`+regexp.QuoteMeta("core45\r\ntacctl> ssh core"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// '?' asks too, by the same count; Ctrl-C at the question is a no.
	if err := s.Send("?"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("Show all 45 devices? [y/N] "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("\x03"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("type more letters to narrow it (e.g. core0…<Tab>)\r\ntacctl> ssh core"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// The line is still there and runs as typed.
	if err := s.Send("01?"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("Possible completions:\r\n  core01  cisco 10.0.0.1  prod\r\ntacctl> ssh core01"), 5*time.Second); err != nil {
		t.Fatal(err)
	}
}
