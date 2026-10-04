package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/execx"
)

func newPrompter(in string) (*Prompter, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return NewPrompter(strings.NewReader(in), Output{Stdout: &out, Stderr: &errb}), &out, &errb
}

// --- Ask / Confirm: read -rp semantics ---

func TestAskReadsALineAndTrimsBlanks(t *testing.T) {
	for in, want := range map[string]string{
		"y\n": "y", "  y \n": "y", "\ty\t\n": "y", "y": "y", "yes please\n": "yes please",
		"": "", "\n": "", "   \n": "", "y\nn\n": "y", "y\r\n": "y\r",
	} {
		p, _, errb := newPrompter(in)
		if got := p.Ask("  Continue? [y/N]: "); got != want {
			t.Errorf("Ask(%q) = %q, want %q", in, got, want)
		}
		if errb.Len() != 0 {
			t.Errorf("a prompt was shown for piped input: %q", errb.String())
		}
	}
}

func TestAskSharesTheInputBetweenPrompts(t *testing.T) {
	p, _, _ := newPrompter("first\nsecond\nthird")
	if a, b, c, d := p.Ask(""), p.Ask(""), p.Ask(""), p.Ask(""); a != "first" || b != "second" || c != "third" || d != "" {
		t.Errorf("%q %q %q %q", a, b, c, d)
	}
}

func TestConfirmExactYes(t *testing.T) {
	for in, want := range map[string]bool{
		"y\n": true, "Y\n": true, " y \n": true, "y": true,
		"yes\n": false, "Yes\n": false, "n\n": false, "": false, "\n": false, "yy\n": false,
	} {
		p, _, _ := newPrompter(in)
		if got := p.Confirm("? "); got != want {
			t.Errorf("Confirm(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestConfirmPrefix(t *testing.T) {
	for in, want := range map[string]bool{
		"y\n": true, "Y\n": true, "yes\n": true, "Yes\n": true, "yolo\n": true, " y\n": true,
		"n\n": false, "": false, "\n": false, "no\n": false, "ay\n": false,
	} {
		p, _, _ := newPrompter(in)
		if got := p.ConfirmPrefix("? "); got != want {
			t.Errorf("ConfirmPrefix(%q) = %v, want %v", in, got, want)
		}
	}
}

// --- Password: read_password_masked, compared with the bash function ---

// bashFunc returns the source of the named function of lib/users.sh as the
// 0.1.18 tag has it (testdata/users-0.1.18.sh, copied from the tag).
func bashFunc(t *testing.T, file, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", strings.TrimSuffix(file, ".sh")+"-0.1.18.sh"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	var out []string
	in := false
	for _, l := range lines {
		if strings.HasPrefix(l, name+"() {") {
			in = true
		}
		if in {
			out = append(out, l)
			if l == "}" {
				break
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("function %s not found in testdata for %s", name, file)
	}
	return strings.Join(out, "\n") + "\n"
}

func runBash(t *testing.T, script, stdin string, extraPath string) (stdout, stderr string, code int) {
	t.Helper()
	res, err := execx.Real{}.Run(context.Background(), execx.Cmd{
		Name:  "bash",
		Args:  []string{"-c", script},
		Stdin: strings.NewReader(stdin),
		Env:   []string{"LC_ALL=C.UTF-8", "PATH=" + extraPath + "/usr/bin:/bin"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(res.Stdout), string(res.Stderr), res.Code
}

var maskedInputs = []string{
	"abc\n", "abc", "", "\n", "ab\x7fc\n", "\x7f\x7fab\x08c\n", "ab\x08\x08\x08\n", "é\x7fx\n", "日本語\x7f\n", "a\r\n", "a b\tc\n",
	"abc\ndef\n", "pass*word\n", "Correct-Horse-42\n", "\x7f\n", "a\x7f\x7f\x7fb\n", "ab\x00cd\n", "€uro\n",
}

func TestPasswordMatchesBashReadPasswordMasked(t *testing.T) {
	fn := bashFunc(t, "users.sh", "read_password_masked")
	for _, in := range maskedInputs {
		wantOut, wantErr, _ := runBash(t, fn+`read_password_masked "  Enter: "`, in, "")
		p, _, errb := newPrompter(in)
		got, err := p.Password("  Enter: ")
		if err != nil {
			t.Fatal(err)
		}
		// bash prints the password on stdout through 'echo' (and $() strips
		// trailing newlines, which the callers rely on).
		if got+"\n" != wantOut || errb.String() != wantErr {
			t.Errorf("input %q:\n got %q + stderr %q\nwant stdout %q + stderr %q", in, got, errb.String(), wantOut, wantErr)
		}
	}
}

// One bufio.Reader serves consecutive prompts: the second prompt sees what
// the first did not consume.
func TestPasswordLeavesTheRestOfTheInput(t *testing.T) {
	p, _, errb := newPrompter("one\ntwo\ny\n")
	a, _ := p.Password("P1: ")
	b, _ := p.Password("P2: ")
	if a != "one" || b != "two" || !p.Confirm("? ") {
		t.Errorf("%q %q", a, b)
	}
	if errb.String() != "P1: ***\nP2: ***\n" {
		t.Errorf("stderr = %q", errb.String())
	}
}

// --- PromptPassword: prompt_password, compared with the bash function ---

func TestPromptPasswordMatchesBash(t *testing.T) {
	funcs := bashFunc(t, "users.sh", "read_password_masked") + bashFunc(t, "users.sh", "validate_password_strength") +
		bashFunc(t, "users.sh", "prompt_password")
	pre := `BOLD='\033[1m'; RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
PASSWORD_MIN_LENGTH=12
` + funcs
	for _, tc := range []struct{ name, in, user string }{
		{"typed twice", "Correct-Horse-42\nCorrect-Horse-42\n", "jsmith"},
		{"mismatch", "Correct-Horse-42\nCorrect-Horse-43\n", "jsmith"},
		{"too short", "short\nshort\n", "jsmith"},
		{"weak", "Qwerty123456\nQwerty123456\n", "jsmith"},
		{"equals user", "ThisIsJSmithAlready\nThisIsJSmithAlready\n", "ThisIsJSmithAlready"},
		{"no confirmation line", "Correct-Horse-42\n", "jsmith"},
		{"with backspace", "Correct-Horse-4x\x7f2\nCorrect-Horse-42\n", "jsmith"},
		{"no user", "Correct-Horse-42\nCorrect-Horse-42\n", ""},
	} {
		// bash runs prompt_password in $(...), so its stderr is the terminal's
		// and its stdout is the password; exit 1 on a rejection.
		wantOut, wantErr, _ := runBash(t, pre+`pw=$(prompt_password "`+tc.user+`"); rc=$?; echo "[$pw] rc=$rc"`, tc.in, "")
		p, _, errb := newPrompter(tc.in)
		pw, err := p.PromptPassword(tc.user, 12, fixedReader{0})
		gotOut := fmt.Sprintf("[%s] rc=0\n", pw)
		if err != nil {
			if !errors.Is(err, ErrReported) {
				t.Errorf("%s: err = %v", tc.name, err)
			}
			gotOut = "[] rc=1\n"
		}
		if gotOut != wantOut || errb.String() != wantErr {
			t.Errorf("%s:\n got %q + stderr %q\nwant %q + stderr %q", tc.name, gotOut, errb.String(), wantOut, wantErr)
		}
	}
}

// Blank input (or none) generates a password, printed in bold on stderr.
func TestPromptPasswordGenerates(t *testing.T) {
	for _, in := range []string{"\n", ""} {
		p, _, errb := newPrompter(in)
		pw, err := p.PromptPassword("jsmith", 12, fixedReader{0})
		want := strings.Repeat("A", 24)
		if err != nil || pw != want {
			t.Errorf("%q: %q, %v", in, pw, err)
		}
		wantErr := "  Enter password (leave blank to auto-generate): \n  Generated password: \033[1m" + want + "\033[0m\n"
		if errb.String() != wantErr {
			t.Errorf("%q: stderr = %q", in, errb.String())
		}
	}
	// The bash generates with openssl; the shape is the same: 24 base64 characters.
	_, wantErr, _ := runBash(t, `openssl() { printf 'AAAAAAAAAAAAAAAAAAAAAAAA\n'; }
`+bashFunc(t, "users.sh", "read_password_masked")+bashFunc(t, "users.sh", "validate_password_strength")+bashFunc(t, "users.sh", "prompt_password")+
		`BOLD='\033[1m'; NC='\033[0m'; pw=$(prompt_password x)`, "\n", "")
	p, _, errb := newPrompter("\n")
	_, _ = p.PromptPassword("x", 12, fixedReader{0})
	if errb.String() != wantErr {
		t.Errorf("stderr = %q, bash %q", errb.String(), wantErr)
	}
}

func TestPromptPasswordTooLong(t *testing.T) {
	long := strings.Repeat("x7Q", 25) // 75 bytes
	p, _, errb := newPrompter(long + "\n" + long + "\n")
	_, err := p.PromptPassword("u", 12, nil)
	if !errors.Is(err, ErrReported) || !strings.Contains(errb.String(), "[ERROR]\033[0m Password is longer than 72 bytes") {
		t.Errorf("err = %v, stderr = %q", err, errb.String())
	}
}

// --- the terminal path, on a pseudo-terminal ---

func openPty(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("no pseudo-terminal: %v", err)
	}
	if err := unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = s.Close() })
	return m, s
}

// waitRaw waits until the slave left canonical mode (the prompter switched
// to raw), so that what the test types reaches the byte loop.
func waitRaw(t *testing.T, s *os.File) {
	t.Helper()
	for i := 0; i < 500; i++ {
		tio, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if tio.Lflag&unix.ICANON == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the terminal never left canonical mode")
}

func ttyPassword(t *testing.T, typed string) (string, string, error) {
	t.Helper()
	m, s := openPty(t)
	var errb bytes.Buffer
	p := NewPrompter(s, Output{Stdout: &bytes.Buffer{}, Stderr: &errb})
	if !p.Interactive() {
		t.Fatal("the pty slave is not seen as a terminal")
	}
	type result struct {
		pw  string
		err error
	}
	done := make(chan result, 1)
	go func() {
		pw, err := p.Password("P: ")
		done <- result{pw, err}
	}()
	waitRaw(t, s)
	if _, err := m.WriteString(typed); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		tio, err := unix.IoctlGetTermios(int(s.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if tio.Lflag&unix.ICANON == 0 || tio.Lflag&unix.ECHO == 0 {
			t.Error("the terminal was not restored")
		}
		return r.pw, errb.String(), r.err
	case <-time.After(5 * time.Second):
		t.Fatal("Password did not return")
	}
	return "", "", nil
}

func TestPasswordOnATerminal(t *testing.T) {
	for _, tc := range []struct{ typed, pw, stderr string }{
		{"abc\r", "abc", "P: ***\n"},
		{"abc\n", "abc", "P: ***\n"},
		{"ab\x7fc\r", "ac", "P: **\b \b*\n"},
		{"\x7f\x7fab\x08c\r", "ac", "P: **\b \b*\n"},
		{"é\x7f\r", "", "P: *\b \b\n"},
		{"日本\r", "日本", "P: **\n"},
		{"\r", "", "P: \n"},
	} {
		pw, stderr, err := ttyPassword(t, tc.typed)
		if err != nil || pw != tc.pw || stderr != tc.stderr {
			t.Errorf("typed %q: %q, stderr %q, err %v; want %q, %q", tc.typed, pw, stderr, err, tc.pw, tc.stderr)
		}
	}
}

func TestPasswordCtrlCOnATerminal(t *testing.T) {
	pw, stderr, err := ttyPassword(t, "ab\x03")
	if !errors.Is(err, ErrInterrupted) || pw != "" || stderr != "P: **\n" {
		t.Errorf("%q, %q, %v", pw, stderr, err)
	}
}

// On a terminal the prompt of Ask is shown (read -p), once.
func TestAskShowsThePromptOnATerminal(t *testing.T) {
	m, s := openPty(t)
	var errb bytes.Buffer
	p := NewPrompter(s, Output{Stdout: &bytes.Buffer{}, Stderr: &errb})
	if _, err := m.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	if !p.Confirm("  Remove? [y/N]: ") || errb.String() != "  Remove? [y/N]: " {
		t.Errorf("stderr = %q", errb.String())
	}
}
