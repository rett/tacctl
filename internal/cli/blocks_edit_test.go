package cli

// 'edit' of the configuration blocks (0.2.7, B5): the editor flow with fake
// editors (real shell scripts, started through the fake runner's function
// seam, so what they see is exactly the command the verb built), run as the
// test's own user with the credential drop stubbed where a test looks at it.

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// realRun starts the command the verb built, for real: its argv, its whole
// environment and its working directory (the credential is the fake
// runner's to note: the test is not root), and answers with its exit status.
func realRun(c execx.Cmd) (execx.Result, error) {
	c.Credential = nil
	c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
	return execx.Real{}.Run(context.Background(), c)
}

// editBox is a sandbox with a terminal, a place for the private
// directories, and fake editors.
type editBox struct {
	t    *testing.T
	sb   *sandbox
	base string
	rec  string
	// cmds are the commands the fake runner was asked to start.
	cmds []execx.Cmd
}

func newEditBox(t *testing.T) *editBox {
	t.Helper()
	return newEditBoxOn(t, newSandbox(t, true))
}

// newEditBoxOn is an edit box on a sandbox that is already made (a device
// box's).
func newEditBoxOn(t *testing.T, sb *sandbox) *editBox {
	t.Helper()
	b := &editBox{t: t, sb: sb, base: sb.editDir(), rec: sb.path("rec")}
	for _, d := range []string{b.base, b.rec} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	sb.terminal(true)
	return b
}

// editor writes an executable script that records what it was given
// ($REC/pwd, args, name, filemode, dirmode, seed<N>, env, ran) and then runs
// body, which may use $f (the private copy, the last argument) and $n (the
// number of this run). It returns the script's path.
func (b *editBox) editor(name, body string) string {
	b.t.Helper()
	script := "#!/bin/sh\nREC=" + b.rec + "\nfor f; do :; done\n" +
		"n=$(cat \"$REC/ran\" 2>/dev/null || echo 0); n=$((n+1)); echo $n > \"$REC/ran\"\n" +
		"pwd > \"$REC/pwd\"; printf '%s\\n' \"$@\" > \"$REC/args\"; basename \"$f\" > \"$REC/name\"\n" +
		"stat -c '%a' \"$f\" > \"$REC/filemode\"; stat -c '%a' \"$(dirname \"$f\")\" > \"$REC/dirmode\"\n" +
		"cp \"$f\" \"$REC/seed$n\"; env | sort > \"$REC/env\"\n" + body + "\n"
	p := filepath.Join(b.t.TempDir(), name)
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		b.t.Fatal(err)
	}
	return p
}

func (b *editBox) recorded(name string) string {
	b.t.Helper()
	data, err := os.ReadFile(filepath.Join(b.rec, name))
	if err != nil {
		b.t.Fatalf("the editor recorded no %s: %v", name, err)
	}
	return string(data)
}

func (b *editBox) ran() int {
	data, err := os.ReadFile(filepath.Join(b.rec, "ran"))
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range strings.TrimSpace(string(data)) {
		n = n*10 + int(c-'0')
	}
	return n
}

// leftover lists what is under the private directories' base.
func (b *editBox) leftover() []string {
	b.t.Helper()
	m, _ := filepath.Glob(filepath.Join(b.base, "*"))
	return m
}

// run runs tacctl with VISUAL set to editor (which the fake runner starts for
// real), answering the questions with stdin.
func (b *editBox) run(stdin, editor string, args ...string) string {
	b.t.Helper()
	return b.runEnv(stdin, editor, nil, args...)
}

func (b *editBox) runEnv(stdin, editor string, script func(*fake.Runner), args ...string) string {
	b.t.Helper()
	b.cmds = nil
	env := []string{}
	if editor != "" {
		env = append(env, "VISUAL="+editor)
	}
	return plain(b.sb.cfgRun(stdin, args, func(r *fake.Runner) {
		route(r)
		if editor != "" {
			r.OnFunc([]string{editor}, func(c execx.Cmd) (execx.Result, error) {
				b.cmds = append(b.cmds, c)
				return realRun(c)
			})
		}
		if script != nil {
			script(r)
		}
	}, env...))
}

func (b *editBox) edit(stdin, editor string, args ...string) string {
	return b.run(stdin, editor, append([]string{"scope", "block", "lab", "juniper", "edit"}, args...)...)
}

const (
	editSNMPAdd = "printf 'set snmp community edit-secret-xyz authorization read-only\\nset snmp community edit-secret-xyz clients 192.0.2.0/24\\n' >> \"$f\""
)

func TestEditNewBlockFromTheTemplate(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-add", editSNMPAdd)
	n := b.sb.snapshots()
	out := b.edit("y\n", ed, "snmp")
	if b.sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is set (") {
		t.Fatalf("edit: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	// the editor ran once, as the verb says: the block's name in the title,
	// the private copy 0600 in a 0700 directory of its own, that directory the
	// working directory
	if b.ran() != 1 {
		t.Errorf("ran %d times", b.ran())
	}
	if got := strings.TrimSpace(b.recorded("name")); got != "scope-lab-juniper-snmp.txt" {
		t.Errorf("the copy is called %q", got)
	}
	if got := strings.TrimSpace(b.recorded("filemode")); got != "600" {
		t.Errorf("file mode %s", got)
	}
	if got := strings.TrimSpace(b.recorded("dirmode")); got != "700" {
		t.Errorf("directory mode %s", got)
	}
	pwd := strings.TrimSpace(b.recorded("pwd"))
	if filepath.Dir(pwd) != b.base || !strings.HasPrefix(filepath.Base(pwd), "tacctl-edit-") {
		t.Errorf("working directory %q (base %q)", pwd, b.base)
	}
	if got := strings.TrimSpace(b.recorded("args")); got != filepath.Join(pwd, "scope-lab-juniper-snmp.txt") {
		t.Errorf("argv %q", got)
	}
	// its environment is its own: the invoking user's terminal and home, the
	// editor as given, nothing of sudo's or tacctl's
	env := b.recorded("env")
	for _, want := range []string{"VISUAL=" + ed, "HOME=", "USER=", "LOGNAME=", "PATH="} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	noneOf(t, "the editor's environment", env, "SUDO_", "TACCTL_", "SSH_AUTH_SOCK")
	// the seed is the commented template: it states nothing
	seed := b.recorded("seed1")
	if !strings.Contains(seed, "# The snmp block of this scope (Junos).") || !strings.Contains(seed, "#   set snmp community <string> authorization read-only|read-write") {
		t.Errorf("seed:\n%s", seed)
	}
	for _, l := range strings.Split(strings.TrimSuffix(seed, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") {
			t.Errorf("a line of the template is not a comment: %q", l)
		}
	}
	// installed: the text the editor left, the manifest, the snapshot, the log
	got := b.sb.read("state/blocks/lab/juniper/snmp")
	if !strings.HasSuffix(got, "set snmp community edit-secret-xyz authorization read-only\nset snmp community edit-secret-xyz clients 192.0.2.0/24\n") ||
		!strings.HasPrefix(got, "# The snmp block of this scope") {
		t.Errorf("stored:\n%s", got)
	}
	if o := b.sb.overrides(); !strings.Contains(o, "blocks:\n  lab:\n    juniper:\n    - snmp\n") {
		t.Errorf("manifest:\n%s", o)
	}
	if b.sb.snapshots() != n+1 {
		t.Errorf("snapshots %d -> %d", n, b.sb.snapshots())
	}
	if b.sb.logged("block-edit name=lab/juniper/snmp bytes=") != 1 {
		t.Errorf("log: %q", b.sb.runner.Argvs())
	}
	noneOf(t, "output and log", out+b.sb.stderr()+strings.Join(b.sb.runner.Argvs(), "\n"), "edit-secret-xyz")
	if l := b.leftover(); len(l) != 0 {
		t.Errorf("private directory left: %v", l)
	}
	if !strings.Contains(out, "Owned by tacctl once in force: 1 community") || !strings.Contains(out, "No file in force: every statement is new.") {
		t.Errorf("check output:\n%s", out)
	}
}

func TestEditExistingBlockSeedsTheFileAndShowsTheDiff(t *testing.T) {
	b := newEditBox(t)
	b.sb.blk("", "lab", "juniper", "set", "snmp", "--file", b.sb.blockFile("snmp.txt", verbSNMPFile), "-y")
	if b.sb.code != 0 {
		t.Fatal(b.sb.stderr())
	}
	ed := b.editor("ed-change", "sed -i 's/192.0.2.50\\/32/192.0.2.51\\/32/' \"$f\"")
	n := b.sb.snapshots()
	out := b.edit("y\n", ed, "snmp")
	if b.sb.code != 0 {
		t.Fatalf("edit: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if seed := b.recorded("seed1"); seed != verbSNMPFile {
		t.Errorf("the seed is not the file in force:\n%s", seed)
	}
	for _, want := range []string{"- set snmp community <secret:1> clients 192.0.2.50/32", "+ set snmp community <secret:1> clients 192.0.2.51/32", "3 unchanged"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff lacks %q:\n%s", want, out)
		}
	}
	noneOf(t, "output", out, "nms-ro-secret", "nms-traps-secret")
	if got := b.sb.read("state/blocks/lab/juniper/snmp"); !strings.Contains(got, "192.0.2.51/32") || strings.Contains(got, "192.0.2.50/32") {
		t.Errorf("stored:\n%s", got)
	}
	if b.sb.snapshots() != n+1 {
		t.Errorf("snapshots %d -> %d", n, b.sb.snapshots())
	}
}

func TestEditUnchangedWritesNothing(t *testing.T) {
	b := newEditBox(t)
	b.sb.blk("", "lab", "juniper", "set", "snmp", "--file", b.sb.blockFile("snmp.txt", verbSNMPFile), "-y")
	ed := b.editor("ed-noop", "true")
	n := b.sb.snapshots()
	before := b.sb.read("state/blocks/lab/juniper/snmp")
	out := b.edit("", ed, "snmp")
	if b.sb.code != 0 || !strings.Contains(out, "The edit changed nothing: the snmp block of scope 'lab' is as it was. Nothing was written.") {
		t.Errorf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if b.sb.snapshots() != n || b.sb.read("state/blocks/lab/juniper/snmp") != before || b.sb.logged("block-edit") != 0 {
		t.Error("an unchanged edit wrote something")
	}
	if len(b.leftover()) != 0 {
		t.Errorf("private directory left: %v", b.leftover())
	}
	// a new block saved as the template states nothing: refused, use remove
	b2 := newEditBox(t)
	out = b2.edit("", b2.editor("ed-noop", "true"), "system")
	if b2.sb.code != 1 || !strings.Contains(b2.sb.stderr(), "The text states nothing (comments and blank lines only). To take a block away: tacctl scope block lab juniper remove system. Nothing was changed.") {
		t.Errorf("%d\n%s%s", b2.sb.code, out, b2.sb.stderr())
	}
}

func TestEditEditorFailureAbandons(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-fail", editSNMPAdd+"\nexit 3")
	n := b.sb.snapshots()
	out := b.edit("y\n", ed, "snmp")
	if b.sb.code != 1 || !strings.Contains(out, "The editor exited with status 3. Nothing was written.") {
		t.Errorf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if b.sb.snapshots() != n || b.sb.logged("block-edit") != 0 {
		t.Error("a failed editor wrote something")
	}
	if _, err := os.Stat(b.sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("the store was written: %v", err)
	}
	if len(b.leftover()) != 0 {
		t.Errorf("private directory left: %v", b.leftover())
	}
}

// A text that fails the check comes back with its findings at the top, as
// comments with the window's line numbers; the findings never reach the file,
// whether the person removed them or not.
func TestEditCheckErrorsThenFixedOnTheSecondRound(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-twice", `if [ "$n" = 1 ]; then
  printf 'set snmp community edit-secret-xyz authorization read-only\n' >> "$f"
else
  printf 'set snmp community edit-secret-xyz clients 192.0.2.0/24\n' >> "$f"
fi`)
	out := b.edit("\ny\n", ed, "snmp")
	if b.sb.code != 0 || !strings.Contains(out, "The snmp block of scope 'lab' is set (") {
		t.Fatalf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if b.ran() != 2 {
		t.Fatalf("ran %d times", b.ran())
	}
	if !strings.Contains(out, "error: community 1 has neither clients nor client-list-name") {
		t.Errorf("the first round's findings:\n%s%s", out, b.sb.stderr())
	}
	second := b.recorded("seed2")
	for _, want := range []string{"# tacctl: the text below was not installed", "# tacctl: line numbers are those of this window", "# tacctl: line "} {
		if !strings.Contains(second, want) {
			t.Errorf("the second round's text lacks %q:\n%s", want, second)
		}
	}
	// the number shown is the line of the window: header (3 lines) + the text
	var shown int
	for _, l := range strings.Split(second, "\n") {
		if rest, ok := strings.CutPrefix(l, "# tacctl: line "); ok {
			for _, c := range rest {
				if c < '0' || c > '9' {
					break
				}
				shown = shown*10 + int(c-'0')
			}
		}
	}
	lines := strings.Split(second, "\n")
	if shown < 4 || shown > len(lines) || !strings.Contains(lines[shown-1], "set snmp community edit-secret-xyz authorization read-only") {
		t.Errorf("the finding points at line %d, which is %q", shown, lines[min(max(shown, 1), len(lines))-1])
	}
	stored := b.sb.read("state/blocks/lab/juniper/snmp")
	if strings.Contains(stored, "# tacctl:") {
		t.Errorf("the findings were stored:\n%s", stored)
	}
	if strings.Count(stored, "set snmp community edit-secret-xyz") != 2 {
		t.Errorf("stored:\n%s", stored)
	}
	// a second failure does not stack the earlier findings: they are stripped
	// before the new ones are put in
	b = newEditBox(t)
	ed = b.editor("ed-bad", `printf 'set snmp community edit-secret-xyz authorization read-only\n' >> "$f"`)
	b.edit("\n\nn\n", ed, "snmp")
	if b.sb.code != 1 || b.ran() != 3 {
		t.Fatalf("exit %d, ran %d", b.sb.code, b.ran())
	}
	third := b.recorded("seed3")
	if n := strings.Count(third, "# tacctl: the text below was not installed"); n != 1 {
		t.Errorf("the findings of earlier rounds were not stripped (%d headers):\n%s", n, third)
	}
	if strings.Count(third, "set snmp community edit-secret-xyz authorization read-only") != 2 {
		t.Errorf("third text:\n%s", third)
	}
}

func TestEditCheckErrorsThenAbandoned(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-bad", `printf 'set snmp community edit-secret-xyz authorization read-only\n' >> "$f"`)
	n := b.sb.snapshots()
	out := b.edit("n\n", ed, "snmp")
	if b.sb.code != 1 || b.ran() != 1 || !strings.Contains(out+b.sb.stderr(), "Nothing was written.") {
		t.Errorf("%d, ran %d\n%s%s", b.sb.code, b.ran(), out, b.sb.stderr())
	}
	if b.sb.snapshots() != n || b.sb.logged("block-edit") != 0 {
		t.Error("an abandoned edit wrote something")
	}
	if _, err := os.Stat(b.sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("the store was written: %v", err)
	}
	noneOf(t, "output", out+b.sb.stderr(), "edit-secret-xyz")
	if len(b.leftover()) != 0 {
		t.Errorf("private directory left: %v", b.leftover())
	}
	// the rounds are limited
	b = newEditBox(t)
	ed = b.editor("ed-bad", `printf 'set snmp community edit-secret-xyz authorization read-only\n' >> "$f"`)
	b.edit("\n\n\n\n\n\n", ed, "snmp")
	if b.sb.code != 1 || b.ran() != blockEditRounds {
		t.Errorf("exit %d, ran %d (rounds %d)", b.sb.code, b.ran(), blockEditRounds)
	}
}

func TestEditAnswerNoLeavesEverythingAsItWas(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-add", editSNMPAdd)
	n := b.sb.snapshots()
	out := b.edit("n\n", ed, "snmp")
	if b.sb.code != 0 || !strings.Contains(out, "Aborted.") || b.sb.snapshots() != n {
		t.Errorf("%d\n%s", b.sb.code, out)
	}
	if _, err := os.Stat(b.sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("the store was written: %v", err)
	}
	if len(b.leftover()) != 0 {
		t.Errorf("private directory left: %v", b.leftover())
	}
	// -y answers it
	out = b.edit("", ed, "snmp", "-y")
	if b.sb.code != 0 || !strings.Contains(out, "is set (") {
		t.Errorf("-y: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
}

func TestEditRefusals(t *testing.T) {
	// no terminal
	b := newEditBox(t)
	b.sb.terminal(false)
	ed := b.editor("ed-add", editSNMPAdd)
	b.edit("y\n", ed, "snmp")
	b.sb.expect(1, "", "edit opens an editor and needs a terminal on standard input and output. Nothing was changed.")
	if b.ran() != 0 {
		t.Error("the editor ran without a terminal")
	}
	b.sb.terminal(true)
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return false }
	b.edit("y\n", ed, "snmp")
	b.sb.expect(1, "", "needs a terminal on standard input and output")
	b.sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }

	// usage and the block name
	b.edit("", ed)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Usage: tacctl scope block lab juniper edit <block> [-y]") {
		t.Errorf("no block: %d %q", b.sb.code, b.sb.stderr())
	}
	b.edit("", ed, "firewall")
	if b.sb.code != 1 || b.ran() != 0 {
		t.Errorf("unknown block: %d, ran %d: %q", b.sb.code, b.ran(), b.sb.stderr())
	}
	// tacctl.yaml that cannot be read is refused before the editor opens
	b.sb.write("state/tacctl.yaml", "blocks: [not, a, map\n", 0o640)
	b.edit("", ed, "snmp")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "tacctl.yaml cannot be read") || b.ran() != 0 {
		t.Errorf("unreadable tacctl.yaml: %d, ran %d: %q", b.sb.code, b.ran(), b.sb.stderr())
	}
}

func TestEditIsTheSuperusersOnly(t *testing.T) {
	sb := engineerSandbox(t)
	b := &editBox{t: t, sb: sb, base: sb.editDir(), rec: sb.path("rec")}
	_ = os.MkdirAll(b.base, 0o755)
	sb.terminal(true)
	sb.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	_ = os.MkdirAll(b.rec, 0o755)
	ed := b.editor("ed-add", editSNMPAdd)
	for _, args := range [][]string{
		{"scope", "block", "lab", "juniper", "edit", "snmp"},
		{"scope", "block", "lab", "juniper", "adopt", "lab-sw", "snmp"},
	} {
		sb.asEngineer("y\n", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads the configuration blocks of scope 'lab' (list, show, check); ") ||
			!strings.Contains(sb.stderr(), " is the superuser's. Nothing was changed.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	for _, args := range [][]string{
		{"device", "block", "lab-sw", "edit", "snmp"},
		{"device", "block", "lab-sw", "adopt", "snmp"},
	} {
		sb.asEngineer("y\n", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads the configuration blocks of device 'lab-sw' (list, show, check); ") ||
			!strings.Contains(sb.stderr(), " is the superuser's. Nothing was changed.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if b.ran() != 0 {
		t.Error("the editor ran for an engineer")
	}
	_ = ed
}

// In the login console an editor is held to the system shell's rule; a plain
// shell or a command line from bash is not.
func TestEditInTheConsoleFollowsTheSystemShellRule(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-noop", "true")
	b.sb.blk("", "lab", "juniper", "set", "snmp", "--file", b.sb.blockFile("snmp.txt", verbSNMPFile), "-y")
	runAs := func(extra ...string) {
		b.sb.cfgRun("", []string{"scope", "block", "lab", "juniper", "edit", "snmp", "-y"}, func(r *fake.Runner) {
			route(r)
			// alice is a tacctl user of the superuser group, as a person on
			// this server is: a caller outside the groups has no tier
			r.On([]string{"id", "-nG", "--", "alice"}, execx.Result{Stdout: []byte("alice tac-users tac-superuser\n")})
			r.OnFunc([]string{ed}, realRun)
		}, append([]string{"VISUAL=" + ed, "SUDO_USER=alice"}, extra...)...)
	}
	// as the superuser the console opens it by default
	runAs("TACCTL_CONSOLE=0123456789abcdef")
	if b.sb.code != 0 || b.ran() != 1 {
		t.Errorf("a superuser in the console: %d, ran %d: %q", b.sb.code, b.ran(), b.sb.stderr())
	}
	// a hand-edited list that names no tier does not close it to the
	// superuser tier, which always has the system shell
	b.sb.write("state/console.yaml", "version: 1\nsettings: {system_shell_tiers: []}\n", 0o600)
	runAs("TACCTL_CONSOLE=0123456789abcdef")
	if b.sb.code != 0 || b.ran() != 2 {
		t.Errorf("console, empty tier list: %d, ran %d: %q", b.sb.code, b.ran(), b.sb.stderr())
	}
	// a console.yaml the policy cannot be read from fails closed: refused,
	// nothing opens
	b.sb.write("state/console.yaml", "version: 1\nsettings: {system_shell: bash}\n", 0o600)
	runAs("TACCTL_CONSOLE=0123456789abcdef")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "In the login console an editor can start a shell, so edit is open only to those who may start the system shell") || b.ran() != 2 {
		t.Errorf("console, policy unreadable: %d, ran %d: %q", b.sb.code, b.ran(), b.sb.stderr())
	}
	if b.sb.logged("block edit DENY user=alice tier=superuser") != 1 {
		t.Errorf("the denial is not logged: %q", b.sb.runner.Argvs())
	}
	// the same line from a plain shell (no marker) is not held to the rule
	runAs()
	if b.sb.code != 0 || b.ran() != 3 {
		t.Errorf("outside the console: %d, ran %d: %q", b.sb.code, b.ran(), b.sb.stderr())
	}
}

func TestEditChoosesTheEditor(t *testing.T) {
	b := newEditBox(t)
	visual := b.editor("visual", editSNMPAdd)
	other := b.editor("other", "exit 9")
	run := func(env []string, script func(*fake.Runner)) string {
		return plain(b.sb.cfgRun("y\n", []string{"scope", "block", "lab", "juniper", "edit", "snmp", "-y"}, func(r *fake.Runner) {
			route(r)
			for _, p := range []string{visual, other} {
				r.OnFunc([]string{p}, realRun)
			}
			if script != nil {
				script(r)
			}
		}, env...))
	}
	// VISUAL before EDITOR
	run([]string{"VISUAL=" + visual, "EDITOR=" + other}, nil)
	if b.sb.code != 0 {
		t.Errorf("VISUAL: %d %q", b.sb.code, b.sb.stderr())
	}
	// EDITOR alone, with an argument of its own
	b.sb.blk("", "lab", "juniper", "remove", "snmp", "-y")
	run([]string{"EDITOR=" + visual + " -nw"}, nil)
	if b.sb.code != 0 || !strings.Contains(b.recorded("args"), "-nw") {
		t.Errorf("EDITOR with an argument: %d %q\n%s", b.sb.code, b.sb.stderr(), b.recorded("args"))
	}
	// neither: the system's 'editor', then 'vi'
	b.sb.blk("", "lab", "juniper", "remove", "snmp", "-y")
	var started []string
	run(nil, func(r *fake.Runner) {
		r.OnFunc([]string{"/fake/bin/editor"}, func(c execx.Cmd) (execx.Result, error) {
			started = append(started, c.Name)
			return execx.Result{}, nil
		})
	})
	if len(started) != 1 || started[0] != "/fake/bin/editor" {
		t.Errorf("default editor: %v (exit %d)", started, b.sb.code)
	}
	started = nil
	run(nil, func(r *fake.Runner) {
		r.Missing("editor")
		r.OnFunc([]string{"/fake/bin/vi"}, func(c execx.Cmd) (execx.Result, error) {
			started = append(started, c.Name)
			return execx.Result{}, nil
		})
	})
	if len(started) != 1 || started[0] != "/fake/bin/vi" {
		t.Errorf("vi: %v (exit %d)", started, b.sb.code)
	}
	// none at all, and a name that is not there
	run(nil, func(r *fake.Runner) { r.Missing("editor", "vi") })
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "No editor was found") {
		t.Errorf("no editor: %d %q", b.sb.code, b.sb.stderr())
	}
	run([]string{"VISUAL=nosuchedit"}, func(r *fake.Runner) { r.Missing("nosuchedit") })
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "VISUAL names 'nosuchedit', which is not found in PATH") {
		t.Errorf("missing editor: %d %q", b.sb.code, b.sb.stderr())
	}
	run([]string{"VISUAL=./relative"}, nil)
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "not an absolute path") {
		t.Errorf("relative editor: %d %q", b.sb.code, b.sb.stderr())
	}
	if len(b.leftover()) != 0 {
		t.Errorf("private directory left: %v", b.leftover())
	}
}

// What the editor leaves is read as a regular file of the user's of a
// reasonable size, and nothing else.
func TestEditReadBackIgnoresLinksAndHugeFiles(t *testing.T) {
	b := newEditBox(t)
	secretFile := filepath.Join(t.TempDir(), "root-only")
	if err := os.WriteFile(secretFile, []byte("set snmp community stolen-secret authorization read-only\nset snmp community stolen-secret clients 192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := b.editor("ed-link", "rm -f \"$f\"; ln -s '"+secretFile+"' \"$f\"")
	n := b.sb.snapshots()
	out := b.edit("y\n", link, "snmp")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "The editor left no file to read back (it is not there, or it is a link)") {
		t.Errorf("link: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	noneOf(t, "output", out+b.sb.stderr(), "stolen-secret")
	huge := b.editor("ed-huge", "head -c 300000 /dev/zero | tr '\\0' 'a' > \"$f\"")
	out = b.edit("y\n", huge, "snmp")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "a block is at most 262144 (256 KiB)") {
		t.Errorf("huge: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	gone := b.editor("ed-gone", "rm -f \"$f\"")
	out = b.edit("y\n", gone, "snmp")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "The editor left no file to read back") {
		t.Errorf("gone: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	// a directory in its place
	dir := b.editor("ed-dir", "rm -f \"$f\"; mkdir \"$f\"")
	out = b.edit("y\n", dir, "snmp")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "something that is not a regular file") {
		t.Errorf("directory: %d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if b.sb.snapshots() != n {
		t.Error("a refused read-back took a snapshot")
	}
	if _, err := os.Stat(b.sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("the store was written: %v", err)
	}
	if l := b.leftover(); len(l) != 0 {
		t.Errorf("private directories left: %v", l)
	}
}

// A stop signal while the editor runs abandons the edit and the directory is
// removed by tacctl.
func TestEditInterruptedRemovesTheDirectory(t *testing.T) {
	serial(t)
	b := newEditBox(t)
	ed := b.editor("ed-add", editSNMPAdd)
	n := b.sb.snapshots()
	out := plain(b.sb.cfgRun("y\n", []string{"scope", "block", "lab", "juniper", "edit", "snmp", "-y"}, func(r *fake.Runner) {
		route(r)
		r.OnFunc([]string{ed}, func(c execx.Cmd) (execx.Result, error) {
			res, err := realRun(c)
			_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
			time.Sleep(150 * time.Millisecond)
			return res, err
		})
	}, "VISUAL="+ed))
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Interrupted while the editor ran. Nothing was written.") {
		t.Errorf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if b.sb.snapshots() != n {
		t.Error("an interrupted edit took a snapshot")
	}
	if l := b.leftover(); len(l) != 0 {
		t.Errorf("private directory left: %v", l)
	}
}

// The credential drop: with the process root and a sudo user, the editor is
// started as that user (their uid, gid and groups, not root's), in a
// directory handed to them, with their home.
func TestEditRunsAsTheInvokingUser(t *testing.T) {
	b := newEditBox(t)
	ed := b.editor("ed-add", editSNMPAdd)
	uid, gid := os.Getuid(), os.Getgid()
	b.sb.hooks.editEuid = func() int { return 0 }
	b.sb.hooks.sshAccountOf = func(name string) (sshAccount, error) {
		if name != "alice" {
			t.Errorf("the account looked up is %q", name)
		}
		// this process's own ids, so that the directory can be handed over
		return sshAccount{UID: uint32(uid), GID: uint32(gid), Groups: []uint32{uint32(gid), 4242}, Home: "/home/alice"}, nil
	}
	run := func(name string) string {
		b.cmds = nil
		return plain(b.sb.cfgRun("y\n", []string{"scope", "block", "lab", "juniper", "edit", "snmp", "-y"}, func(r *fake.Runner) {
			route(r)
			// the passwd entry of the uid of this process is alice's
			r.OnFunc([]string{"getent", "passwd", strconv.Itoa(uid)}, func(execx.Cmd) (execx.Result, error) {
				return execx.Result{Stdout: []byte("alice:x:" + strconv.Itoa(uid) + ":" + strconv.Itoa(gid) + "::/home/alice:/bin/bash\n")}, nil
			})
			r.OnFunc([]string{ed}, func(c execx.Cmd) (execx.Result, error) {
				b.cmds = append(b.cmds, c)
				return realRun(c)
			})
		}, "VISUAL="+ed, "SUDO_USER="+name, "SUDO_UID="+strconv.Itoa(uid), "SUDO_GID="+strconv.Itoa(gid)))
	}
	out := run("alice")
	if b.sb.code != 0 || len(b.cmds) != 1 {
		t.Fatalf("%d, %d cmds\n%s%s", b.sb.code, len(b.cmds), out, b.sb.stderr())
	}
	c := b.cmds[0]
	if c.Credential == nil || int(c.Credential.Uid) != uid || int(c.Credential.Gid) != gid ||
		len(c.Credential.Groups) != 2 || c.Credential.Groups[1] != 4242 {
		t.Errorf("credential %+v", c.Credential)
	}
	env := strings.Join(c.Env, "\n")
	for _, want := range []string{"HOME=/home/alice", "USER=alice", "LOGNAME=alice", "VISUAL=" + ed} {
		if !strings.Contains(env, want) {
			t.Errorf("env lacks %q:\n%s", want, env)
		}
	}
	noneOf(t, "env", env, "SUDO_", "TACCTL_")
	// a SUDO_USER that is not SUDO_UID's account is refused: nothing runs
	b.sb.blk("", "lab", "juniper", "remove", "snmp", "-y")
	run("bob")
	if b.sb.code != 1 || len(b.cmds) != 0 {
		t.Errorf("spoofed pair: %d, %d cmds, %q", b.sb.code, len(b.cmds), b.sb.stderr())
	}
	// an account that is root's is never a drop target
	b.sb.hooks.sshAccountOf = func(string) (sshAccount, error) { return sshAccount{UID: 0, Home: "/root"}, nil }
	run("alice")
	if b.sb.code != 1 || len(b.cmds) != 0 || !strings.Contains(b.sb.stderr(), "is not the one sudo ran this for") {
		t.Errorf("root account: %d, %d cmds, %q", b.sb.code, len(b.cmds), b.sb.stderr())
	}
	if l := b.leftover(); len(l) != 0 {
		t.Errorf("private directory left: %v", l)
	}
}

func TestCaptureEditorTakesTheVariablesOffTheRootSide(t *testing.T) {
	serial(t)
	old := processEditor
	t.Cleanup(func() { processEditor = old })
	t.Setenv("VISUAL", "vim")
	t.Setenv("EDITOR", "nano")
	env := []string{"A=1", "VISUAL=vim", "EDITOR=nano", "B=2"}
	// the user's own process keeps them: they are what sudo is asked to carry
	if got := captureEditor(env, 1000); len(got) != 4 || os.Getenv("VISUAL") != "vim" { //nolint:forbidigo // the test reads the process environment captureEditor changes
		t.Errorf("user side: %q", got)
	}
	got := captureEditor(env, 0)
	if strings.Join(got, ",") != "A=1,B=2" || processEditor.visual != "vim" || processEditor.editor != "nano" {
		t.Errorf("root side: %q %+v", got, processEditor)
	}
	if v, ok := os.LookupEnv("VISUAL"); ok { //nolint:forbidigo // as above
		t.Errorf("the process environment still has VISUAL=%q", v)
	}
	if _, ok := os.LookupEnv("EDITOR"); ok { //nolint:forbidigo // as above
		t.Error("the process environment still has EDITOR")
	}
}

// The seed of a device's new block: the template, and the scope's objects as
// comments to uncomment where the device differs.
func TestEditDeviceBlockSeedHasTheScopesObjectsAsComments(t *testing.T) {
	b := newEditBox(t)
	b.sb.dev("", "add", "jsw1.lab.example.net", "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	b.sb.blk("", "lab", "juniper", "set", "snmp", "--file", b.sb.blockFile("snmp.txt", scopeLevelSNMP), "-y")
	if b.sb.code != 0 {
		t.Fatal(b.sb.stderr())
	}
	// uncomment one object and change it, the way the seed invites
	ed := b.editor("ed-override", `sed -i -e 's/^# set snmp community nms-ro /set snmp community nms-ro /' -e 's/clients 192.0.2.50\/32/clients 192.0.2.99\/32/' "$f"`)
	out := b.run("y\n", ed, "device", "block", "jsw1.lab.example.net", "edit", "snmp")
	if b.sb.code != 0 || !strings.Contains(out, "The snmp block of device 'jsw1.lab.example.net' is set (") {
		t.Fatalf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	seed := b.recorded("seed1")
	for _, want := range []string{"# The snmp block of this device (Junos).", "# The objects of scope 'lab' are below, as comments.",
		"# set snmp community nms-ro authorization read-only", "# set snmp community nms-ro clients 192.0.2.50/32",
		"# set snmp trap-group nms-traps targets 198.51.100.7"} {
		if !strings.Contains(seed, want) {
			t.Errorf("seed lacks %q:\n%s", want, seed)
		}
	}
	stored := b.sb.read("state/blocks/_devices/jsw1.lab.example.net/juniper/snmp")
	if !strings.Contains(stored, "\nset snmp community nms-ro authorization read-only\n") || !strings.Contains(stored, "\nset snmp community nms-ro clients 192.0.2.99/32\n") {
		t.Errorf("stored:\n%s", stored)
	}
	if b.sb.logged("block-edit name=_devices/jsw1.lab.example.net/juniper/snmp bytes=") != 1 {
		t.Errorf("log: %q", b.sb.runner.Argvs())
	}
	if n := b.recorded("name"); strings.TrimSpace(n) != "device-jsw1.lab.example.net-juniper-snmp.txt" {
		t.Errorf("name %q", n)
	}
	// a device block that exists is opened as it is
	b.run("", ed, "device", "block", "jsw1.lab.example.net", "edit", "snmp")
	if seed := b.recorded("seed2"); seed != stored {
		t.Errorf("an existing block is not opened as it is:\n%s", seed)
	}
	// and so is a block for a scope that has none
	b2 := newEditBox(t)
	b2.sb.dev("", "add", "jsw1.lab.example.net", "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	b2.run("", b2.editor("ed-noop", "true"), "device", "block", "jsw1.lab.example.net", "edit", "system")
	if seed := b2.recorded("seed1"); strings.Contains(seed, "The objects of scope") || !strings.Contains(seed, "# The system block of this device (Junos).") {
		t.Errorf("seed:\n%s", seed)
	}
}

// A block in force that has errors is opened with them listed.
func TestEditOpensABrokenBlockWithItsErrors(t *testing.T) {
	b := newEditBox(t)
	b.sb.write("state/blocks/lab/juniper/snmp", "set snmp community broken-secret authorization read-only\n", 0o600)
	b.sb.write("state/tacctl.yaml", "blocks:\n  lab:\n    juniper:\n    - snmp\n", 0o640)
	ed := b.editor("ed-fix", `printf 'set snmp community broken-secret clients 192.0.2.0/24\n' >> "$f"`)
	out := b.edit("y\n", ed, "snmp")
	if b.sb.code != 0 {
		t.Fatalf("%d\n%s%s", b.sb.code, out, b.sb.stderr())
	}
	if seed := b.recorded("seed1"); !strings.Contains(seed, "# tacctl: line ") || !strings.Contains(seed, "has neither clients nor client-list-name") {
		t.Errorf("seed:\n%s", seed)
	}
	if got := b.sb.read("state/blocks/lab/juniper/snmp"); strings.Contains(got, "# tacctl:") || !strings.Contains(got, "clients 192.0.2.0/24") {
		t.Errorf("stored:\n%s", got)
	}
}
