package cli

// 'tacctl shell' on a pseudo-terminal: the real command (Run with the
// arguments 'shell', in this test binary started again in helper mode),
// for what 'help' prints and what a double Tab lists.

import (
	"context"
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
		f.OnFunc([]string{"sudo", "-n", "tacctl", "_completion-names"}, func(c execx.Cmd) (execx.Result, error) {
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
	if want := shellTop("0.2.1-pty"); !strings.Contains(out, want) {
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

// A double Tab on an empty line lists the commands as the usage does, then
// and not the shell's own words; 'shell' is not among them.
func TestPtyShellTabListing(t *testing.T) {
	s := startCLIShell(t, 140)
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(200 * time.Millisecond); strings.Contains(got, "Install tacctl") {
		t.Fatalf("the first Tab listed: %q", got)
	}
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`  version \[--long\] +Print tacctl version.*\r\n`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	out := strings.ReplaceAll(s.Output(), "\r\n", "\n")
	// The command rows of the help, as 'help' prints them, by name.
	type row struct{ name, left, desc string }
	var all []row
	width := 0
	for _, r := range topRows() {
		width = max(width, len(r.Left))
		if r.Name != "shell" {
			all = append(all, row{r.Name, r.Left, r.Desc})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].name < all[j].name })
	var want strings.Builder
	for _, r := range all {
		want.WriteString("  " + r.left + strings.Repeat(" ", width-len(r.left)) + "  " + r.desc + "\n")
	}
	if !strings.Contains(out, want.String()) {
		t.Errorf("listing:\n%q\nwant\n%q", out, want.String())
	}
	for _, w := range []string{"  shell ", "  history ", "  help [<command>]", "  exit | quit"} {
		if strings.Contains(out, w) {
			t.Errorf("the listing has %q:\n%q", w, out)
		}
	}
	if strings.Contains(out, "  shell ") {
		t.Errorf("the listing offers shell:\n%q", out)
	}
}

// Tab twice after 'ssh ': the line stays where it is, the list starts on
// the next line with the live names and their descriptions (vendor,
// address, scope, in columns), no flag is listed, and the prompt comes
// back with the line.
func TestPtyShellNamesListing(t *testing.T) {
	s := startCLIShell(t, 120, shellPtyFakeNames)
	if err := s.Send("ssh \t"); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(200 * time.Millisecond); strings.Contains(got, "cisco") {
		t.Fatalf("the first Tab listed: %q", got)
	}
	if err := s.Send("\t"); err != nil {
		t.Fatal(err)
	}
	// The line is printed again, ending the line, before the first name.
	const list = "tacctl> ssh \r\n" +
		"  ar1   cisco   10.0.0.1   prod\r\n" +
		"  dev   juniper 10.20.0.22 lab\r\n" +
		"  web1  linux   h.example  lab\r\n" +
		"tacctl> ssh "
	if err := s.Expect(regexp.QuoteMeta(list), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := s.Settle(100 * time.Millisecond); strings.Contains(got, "-p") {
		t.Errorf("a flag was listed: %q", got)
	}
	// A '-' asks for the flags.
	if err := s.Send("-\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`ssh -p `, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}

// A line longer than the terminal is wide stays whole above the list, and
// the prompt and line come back after it, also after the terminal changed
// its size.
func TestPtyShellListingWrapped(t *testing.T) {
	s := startCLIShell(t, 10, shellPtyFakeNames)
	if err := s.Send("ssh \t\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("tacctl> ssh \r\n  ar1 ")+`(?s:.*)`+regexp.QuoteMeta("web1  linux   h.example  lab\r\ntacctl> ss\r\nh "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Resize(60, 40); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("\t\t"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(regexp.QuoteMeta("tacctl> ssh \r\n  ar1 ")+`(?s:.*)`+regexp.QuoteMeta("web1  linux   h.example  lab\r\ntacctl> ssh "), 5*time.Second); err != nil {
		t.Fatal(err)
	}
}
