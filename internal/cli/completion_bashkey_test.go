package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/testpty"
)

// The block is the generated part, untouched, and the help key after it; the
// zsh and fish scripts have none.
func TestBashScriptEndsWithTheHelpKey(t *testing.T) {
	var b bytes.Buffer
	if err := GenCompletion(&b, "bash"); err != nil {
		t.Fatal(err)
	}
	var gen strings.Builder
	if err := newRoot(&invocation{}).GenBashCompletionV2(&gen, false); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), gen.String()) {
		t.Error("the generated part is not intact")
	}
	if !strings.HasSuffix(b.String(), bashHelpKey) || !strings.Contains(bashHelpKey, "TACCTL_HELP_KEY") {
		t.Error("the script does not end with the help key")
	}
	for _, shell := range []string{"zsh", "fish"} {
		var o bytes.Buffer
		if err := GenCompletion(&o, shell); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(o.String(), "TACCTL_HELP_KEY") {
			t.Errorf("%s has the help key", shell)
		}
	}
}

// The block passes shellcheck when it is installed.
func TestBashHelpKeyBlockIsShellcheckClean(t *testing.T) {
	sc, err := exec.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is not installed")
	}
	f := filepath.Join(t.TempDir(), "block.bash")
	if err := os.WriteFile(f, []byte(bashHelpKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(sc, "-s", "bash", f).CombinedOutput(); err != nil {
		t.Errorf("shellcheck:\n%s", out)
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("bash -n:\n%s", out)
		}
	}
}

// bashKeySession is a real interactive bash that has sourced the script with
// a tacctl that only says what it was asked ("HELP[<words>]" for --help,
// "RAN[<words>]" otherwise), TACCTL_HELP_KEY as given ("-": unset), in a
// directory that holds the file f.c.
func bashKeySession(t *testing.T, key string) *testpty.Session {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := "#!/bin/sh\ncase \"$*\" in\n  *--help) echo \"HELP[$*]\" ;;\n  *) echo \"RAN[$*]\" ;;\nesac\n"
	if err := os.WriteFile(filepath.Join(bin, "tacctl"), []byte(fake), 0o755); err != nil {
		t.Fatal(err)
	}
	var script bytes.Buffer
	if err := GenCompletion(&script, "bash"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tacctl.bash"), script.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.c"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	rc := "PS1='$ '\ncd " + dir + "\n"
	if key != "-" {
		rc += "export TACCTL_HELP_KEY='" + key + "'\n"
	}
	rc += "source " + filepath.Join(dir, "tacctl.bash") + "\n"
	if err := os.WriteFile(filepath.Join(dir, "rc"), []byte(rc), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := testpty.Start(testpty.Options{
		Path: bash, Argv: []string{bash, "--noprofile", "--rcfile", filepath.Join(dir, "rc"), "-i"},
		Env:  []string{"PATH=" + bin + ":/usr/bin:/bin", "TERM=xterm", "LC_ALL=C.UTF-8", "HOME=" + dir},
		Rows: 40, Cols: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Expect(`\$ `, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	return s
}

// The question mark on a tacctl line prints the help of the words before the
// cursor and leaves the line as it is (Enter then runs the line without it);
// anywhere else it types itself, 'ls *.?' included.
func TestBashHelpKeyQuestionMark(t *testing.T) {
	for _, c := range []struct {
		name, keys, want string
	}{
		{"a verb", "tacctl user add ?", `HELP\[user add --help\]`},
		{"the top level", "tacctl ?", `HELP\[--help\]`},
		{"the word being typed is left out", "tacctl user ad?", `HELP\[user --help\]`},
		{"before the cursor only", "tacctl user show\x1b[D\x1b[D\x1b[D\x1b[D?", `HELP\[user --help\]`},
	} {
		s := bashKeySession(t, "-")
		if err := s.Send(c.keys); err != nil {
			t.Fatal(err)
		}
		if err := s.Expect(c.want, 5*time.Second); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		// The line is untouched: no question mark was typed.
		if err := s.Send("\r"); err != nil {
			t.Fatal(err)
		}
		out := s.Settle(500 * time.Millisecond)
		if strings.Contains(out, "?]") || strings.Contains(out, "HELP[") {
			t.Errorf("%s: the line was changed or run as help:\n%q", c.name, out)
		}
	}
	for _, c := range []struct {
		name, keys, want string
	}{
		{"a glob", "ls *.?\r", `f\.c`},
		{"inside a command line", "echo xy\x1b[D?\r", `x\?y`},
		{"an open quote", "tacctl user \"a ?\"\r", `RAN\[user a \?\]`},
		{"a second command", "echo a; tacctl user ?\r", `RAN\[user \?\]`},
		{"not tacctl", "echo tacctl ?\r", `tacctl \?`},
	} {
		s := bashKeySession(t, "-")
		if err := s.Send(c.keys); err != nil {
			t.Fatal(err)
		}
		if err := s.Expect(c.want, 5*time.Second); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if out := s.Settle(300 * time.Millisecond); strings.Contains(out, "HELP[") {
			t.Errorf("%s: help was printed:\n%q", c.name, out)
		}
	}
}

// TACCTL_HELP_KEY: a readline key spelling is that key (the question mark
// then types itself); off binds nothing.
func TestBashHelpKeyOtherKeys(t *testing.T) {
	s := bashKeySession(t, `\eh`)
	if err := s.Send("tacctl user \x1bh"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`HELP\[user --help\]`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// The line is still there; a question mark types itself and runs.
	if err := s.Send("?\r"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`RAN\[user \?\]`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	// The key does nothing outside a tacctl line.
	if err := s.Expect(`\$ `, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := s.Send("echo ab\x1bh\r"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`\rab\r\n`, 5*time.Second); err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{"off", "?", `"`} {
		s = bashKeySession(t, key)
		if err := s.Send("tacctl user ?\r"); err != nil {
			t.Fatal(err)
		}
		want := `RAN\[user \?\]`
		if key == "?" {
			want = `HELP\[user --help\]`
		}
		if err := s.Expect(want, 5*time.Second); err != nil {
			t.Fatalf("key %q: %v", key, err)
		}
	}
}
