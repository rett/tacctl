package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
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
	var r execx.Real
	sc, err := r.LookPath("shellcheck")
	if err != nil {
		t.Skip("shellcheck is not installed")
	}
	f := filepath.Join(t.TempDir(), "block.bash")
	if err := os.WriteFile(f, []byte(bashHelpKey), 0o600); err != nil {
		t.Fatal(err)
	}
	if res, err := r.Run(t.Context(), execx.Cmd{Name: sc, Args: []string{"-s", "bash", f}}); err != nil || res.Code != 0 {
		t.Errorf("shellcheck: %v\n%s%s", err, res.Stdout, res.Stderr)
	}
	if bash, err := r.LookPath("bash"); err == nil {
		if res, err := r.Run(t.Context(), execx.Cmd{Name: bash, Args: []string{"-n", f}}); err != nil || res.Code != 0 {
			t.Errorf("bash -n: %v\n%s%s", err, res.Stdout, res.Stderr)
		}
	}
}

// bashKey is a real interactive bash that has sourced the script, with a
// tacctl that records every call (one line of its arguments in calls) and
// answers 'HELP[<words>]' to the help-only entry point and 'RAN[<args>]' to
// anything else. The key must call only the first.
type bashKey struct {
	*testpty.Session
	t     *testing.T
	calls string
}

// bashKeySession starts it, TACCTL_HELP_KEY as given ("-": unset), in a
// directory that holds the file f.c.
func bashKeySession(t *testing.T, key string) *bashKey {
	t.Helper()
	var r execx.Real
	bash, err := r.LookPath("bash")
	if err != nil {
		t.Skip("bash is not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(dir, "calls")
	fake := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\ncase \"$1\" in\n  __help) shift; echo \"HELP[$*]\" ;;\n  *) echo \"RAN[$*]\" ;;\nesac\n"
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
	// An empty readline configuration: /etc/inputrc does not reach the test.
	inputrc := filepath.Join(dir, "inputrc")
	if err := os.WriteFile(inputrc, nil, 0o644); err != nil {
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
		Env:  []string{"PATH=" + bin + ":/usr/bin:/bin", "TERM=xterm", "LC_ALL=C.UTF-8", "HOME=" + dir, "INPUTRC=" + inputrc},
		Rows: 40, Cols: 120,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Expect(`\$ `, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	return &bashKey{Session: s, t: t, calls: calls}
}

// recorded are the calls of the fake tacctl so far, one entry per call.
func (b *bashKey) recorded() []string {
	data, _ := os.ReadFile(b.calls)
	if len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// onlyHelp fails the test when the key called tacctl with anything but the
// help-only entry point and the words after '--'.
func (b *bashKey) onlyHelp(what string) {
	b.t.Helper()
	for _, c := range b.recorded() {
		if c != "__help --" && !strings.HasPrefix(c, "__help -- ") {
			b.t.Errorf("%s: the key called tacctl %q", what, c)
		}
	}
}

// The question mark on a tacctl line prints the help of the words before the
// cursor and leaves the line as it is (Enter then runs the line without it);
// anywhere else it types itself, 'ls *.?' included. The key calls only the
// help-only entry point, whatever the words are: a flag that waits for a
// value, a '--' earlier, a hidden or underscore command, an empty line.
func TestBashHelpKeyQuestionMark(t *testing.T) {
	for _, c := range []struct {
		name, keys, help, line string
	}{
		{"a verb", "tacctl user add ?", `HELP\[-- user add\]`, "user add"},
		{"the top level", "tacctl ?", `HELP\[--\]`, ""},
		{"the top level, no blank", "tacctl?", `HELP\[--\]`, ""},
		{"the word being typed is left out", "tacctl user ad?", `HELP\[-- user\]`, "user ad"},
		{"before the cursor only", "tacctl user show\x1b[D\x1b[D\x1b[D\x1b[D?", `HELP\[-- user\]`, "user show"},
		{"a flag that waits for a value, last", "tacctl breakglass hold sw1 --reason ?", `HELP\[-- breakglass hold sw1 --reason\]`, "breakglass hold sw1 --reason "},
		{"its value being typed", "tacctl breakglass hold sw1 --reason why?", `HELP\[-- breakglass hold sw1 --reason\]`, "breakglass hold sw1 --reason why"},
		{"a flag of install", "tacctl install --yes --branch ?", `HELP\[-- install --yes --branch\]`, "install --yes --branch "},
		{"a dash-dash earlier", "tacctl log search -- ?", `HELP\[-- log search --\]`, "log search -- "},
		{"a dash-dash and a help flag", "tacctl log search -- --help ?", `HELP\[-- log search -- --help\]`, "log search -- --help "},
		{"a help flag", "tacctl user add --help ?", `HELP\[-- user add --help\]`, "user add --help "},
		{"an underscore command", "tacctl _console-policy ?", `HELP\[-- _console-policy\]`, "_console-policy "},
		{"a hidden command", "tacctl __complete user ?", `HELP\[-- __complete user\]`, "__complete user "},
		{"inside a word", "tacctl device description sw1 why?", `HELP\[-- device description sw1\]`, "device description sw1 why"},
		{"no command at all", "tacctl nosuch --x ?", `HELP\[-- nosuch --x\]`, "nosuch --x "},
	} {
		s := bashKeySession(t, "-")
		if err := s.Send(c.keys); err != nil {
			t.Fatal(err)
		}
		if err := s.Expect(c.help, 5*time.Second); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		s.Settle(300 * time.Millisecond)
		// Before the line is run: only the help-only entry point was called.
		s.onlyHelp(c.name)
		if got := len(s.recorded()); got != 1 {
			t.Errorf("%s: %d calls, want 1", c.name, got)
		}
		// The line is untouched: Enter runs it without a question mark.
		if err := s.Send("\r"); err != nil {
			t.Fatal(err)
		}
		out := s.Settle(500 * time.Millisecond)
		if strings.Contains(out, "?]") || strings.Contains(out, "HELP[") {
			t.Errorf("%s: the line was changed or run as help:\n%q", c.name, out)
		}
		want := "RAN[" + strings.TrimSpace(c.line)
		if !strings.Contains(out, want) {
			t.Errorf("%s: the line run is not %q:\n%q", c.name, want, out)
		}
	}
	// A carriage return before the cursor (typed with Ctrl-V) is no blank: the
	// key types the character, and tacctl is never called.
	{
		s := bashKeySession(t, "-")
		if err := s.Send("tacctl user\x16\radd ?"); err != nil {
			t.Fatal(err)
		}
		s.Settle(500 * time.Millisecond)
		if got := s.recorded(); len(got) != 0 {
			t.Errorf("a carriage return: tacctl was called: %q", got)
		}
		if err := s.Send("\x03"); err != nil {
			t.Fatal(err)
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
		{"a quoted insert", "tacctl user a\x16?\r", `RAN\[user a\?\]`},
		{"a dollar", "tacctl user $x ?\r", `RAN\[user \?\]`},
		{"a tilde", "tacctl user ~ ?\r", `RAN\[user \S+ \?\]`},
		{"a glob on a tacctl line", "tacctl user a*?\r", `RAN\[user a\*\?\]`},
		{"a non-ASCII word", "tacctl user \u00e9?\r", `RAN\[user \S*\?\]`},
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
		// Only the line run (a RAN above) and never a help call.
		for _, call := range s.recorded() {
			if strings.HasPrefix(call, "__help") {
				t.Errorf("%s: the key called %q", c.name, call)
			}
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
	if err := s.Expect(`HELP\[-- user\]`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	s.onlyHelp("alt-h")
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
			want = `HELP\[-- user\]`
		}
		if err := s.Expect(want, 5*time.Second); err != nil {
			t.Fatalf("key %q: %v", key, err)
		}
	}
}

// The block does not fail under 'set -u', with an empty list of words
// included (bash before 4.4 treats an empty array as unset there).
func TestBashHelpKeyUnderSetU(t *testing.T) {
	s := bashKeySession(t, "-")
	if err := s.Send("set -u\r"); err != nil {
		t.Fatal(err)
	}
	s.Settle(300 * time.Millisecond)
	if err := s.Send("tacctl ?"); err != nil {
		t.Fatal(err)
	}
	if err := s.Expect(`HELP\[--\]`, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	s.onlyHelp("set -u")
}
