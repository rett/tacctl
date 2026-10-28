package cli

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/tier"
)

// hostile is an environment that would turn a pager, man or groff into a way
// to run a program, or to read another page, if it reached them.
var hostile = []string{
	"PAGER=sh -c id", "MANPAGER=sh -c id", "LESS=-r --shell-escape", "LESSOPEN=|/bin/sh %s", "LESSCLOSE=/bin/sh %s %s",
	"LESSSECURE=0", "LESSKEY=/home/user/.lesskey", "MANPATH=/home/user/man", "MANOPT=-P sh", "MAN_KEEP_FORMATTING=1",
	"MANROFFSEQ=x", "MANLESS=x", "GROFF_TMAC_PATH=/home/user", "GROFF_FONT_PATH=/home/user", "GROFF_COMMAND_PREFIX=x",
	"SHELL=/bin/sh", "BASH_ENV=/home/user/x", "ENV=/home/user/x", "LD_PRELOAD=/home/user/x.so", "TACCTL_COLOR=never",
	"SSH_AUTH_SOCK=/tmp/agent", "TMPDIR=/home/user/tmp", "EDITOR=vi", "VISUAL=vi", "XDG_CONFIG_HOME=/home/user/.config",
}

// manHarness is a run of 'tacctl man <args>' with a fake runner, the paths
// moved into a temporary directory and a terminal for the output; page is
// what is installed there ("": nothing; a name ending in .gz is gzipped).
type manHarness struct {
	*harness
	dir  string
	page string // the installed page's path, "" when none
}

func newManHarness(t *testing.T, installed []byte, gz bool, env []string, args ...string) *manHarness {
	t.Helper()
	h := &manHarness{harness: newHarness(t, append([]string{"man"}, args...), append(slices.Clone(env), "TERM=xterm", "LANG=C.UTF-8")...), dir: t.TempDir()}
	h.app.Paths = h.app.Paths.Reroot(h.dir)
	if installed != nil {
		h.page = h.app.Paths.ManPage
		if err := os.MkdirAll(filepath.Dir(h.page), 0o755); err != nil {
			t.Fatal(err)
		}
		data := installed
		if gz {
			var b bytes.Buffer
			zw := gzip.NewWriter(&b)
			_, _ = zw.Write(installed)
			_ = zw.Close()
			data = b.Bytes()
		}
		if err := os.WriteFile(h.page, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	h.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	return h
}

// started are the programs the run started, in order.
func (h *manHarness) started() []execx.Cmd { return h.runner.Calls() }

func envMap(env []string) map[string]string {
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// checkSafeEnv holds the environment given to man, groff and the pager to
// what manEnv makes: the terminal, the locale, a fixed PATH and HOME, and the
// pager's secure settings.
func checkSafeEnv(t *testing.T, env []string, wantLess string) {
	t.Helper()
	got := envMap(env)
	for _, name := range []string{"PAGER", "MANPAGER", "LESSOPEN", "LESSCLOSE", "LESSKEY", "MANPATH", "MANOPT", "MAN_KEEP_FORMATTING",
		"MANROFFSEQ", "MANLESS", "GROFF_TMAC_PATH", "GROFF_FONT_PATH", "GROFF_COMMAND_PREFIX", "SHELL", "BASH_ENV", "ENV",
		"LD_PRELOAD", "TACCTL_COLOR", "SSH_AUTH_SOCK", "TMPDIR", "EDITOR", "VISUAL", "XDG_CONFIG_HOME"} {
		if v, has := got[name]; has {
			t.Errorf("the environment has %s=%q", name, v)
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "MAN") || strings.HasPrefix(k, "GROFF") || strings.HasPrefix(k, "TACCTL") {
			t.Errorf("the environment has %s", k)
		}
	}
	want := map[string]string{"TERM": "xterm", "LANG": "C.UTF-8", "PATH": console.ConsolePath, "HOME": "/nonexistent",
		"LESSSECURE": "1", "LESSHISTFILE": "-", "LESS": wantLess}
	if len(env) != len(got) {
		t.Errorf("a variable is set twice: %q", env)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s=%q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("environment %q, want only %v", env, want)
	}
	if !regexp.MustCompile(`^-R( \+/\^[^ ]*[^\n]*)?$`).MatchString(got["LESS"]) {
		t.Errorf("LESS=%q", got["LESS"])
	}
}

// An installed page is shown by man -l with that file as its only page, in a
// less that cannot run a program; nothing the caller typed or exported
// reaches an argument or the environment.
func TestManInstalledPage(t *testing.T) {
	for _, gz := range []bool{false, true} {
		h := newManHarness(t, []byte(".TH X 1\n.SH TIERS\n"), gz, hostile)
		if err := h.run(); err != nil || h.out.Len() != 0 || h.err.Len() != 0 {
			t.Fatalf("gz=%v: %v %q %q", gz, err, h.out.String(), h.err.String())
		}
		calls := h.started()
		if len(calls) != 1 {
			t.Fatalf("started %v", h.runner.Argvs())
		}
		c := calls[0]
		if c.Name != "/fake/bin/man" || !slices.Equal(c.Args, []string{"-l", "-P", "/fake/bin/less", h.page}) {
			t.Errorf("gz=%v: %s %q", gz, c.Name, c.Args)
		}
		checkSafeEnv(t, c.Env, "-R")
		if len(h.runner.Execs()) != 0 {
			t.Errorf("execs %v", h.runner.Execs())
		}
	}
}

// Words choose the place and nothing else: the arguments of man are those of
// no words, and the pager's LESS holds a search made from the page's own
// text.
func TestManWordsReachTheSearchOnly(t *testing.T) {
	page := []byte(".TH X 1\n.SH TIERS\ntext\n.SS User management \\fB(tacctl user)\\fR\n.TP\n.BI \"device config plan \" name\nbody\n")
	for _, c := range []struct {
		words []string
		less  string
	}{
		{nil, "-R"},
		{[]string{"tiers"}, "-R +/^ *TIERS *$"},
		{[]string{"TIERS"}, "-R +/^ *TIERS *$"},
		{[]string{"user"}, "-R +/^ *User  *management  *.tacctl  *user. *$"},
		{[]string{"device", "config", "plan"}, "-R +/^       device  *config  *plan  *name *$"},
		{[]string{"nosuch", "$(id)"}, "-R"},
		{[]string{"--", "-P", "sh"}, "-R"},
	} {
		h := newManHarness(t, page, true, hostile, c.words...)
		if err := h.run(); err != nil {
			t.Fatalf("%q: %v", c.words, err)
		}
		call := h.started()[0]
		if !slices.Equal(call.Args, []string{"-l", "-P", "/fake/bin/less", h.page}) {
			t.Errorf("%q: arguments %q", c.words, call.Args)
		}
		checkSafeEnv(t, call.Env, c.less)
	}
}

// A word that names nothing opens the page at the top and says so on
// standard error; one that names an entry says nothing.
func TestManUnknownWordSaysSo(t *testing.T) {
	page := []byte(".TH X 1\n.SH TIERS\n")
	h := newManHarness(t, page, false, nil, "no", "such")
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if h.out.Len() != 0 || h.err.String() != "tacctl man: no entry for 'no such'; the page is opened at the top.\n" {
		t.Errorf("stdout %q stderr %q", h.out.String(), h.err.String())
	}
	h = newManHarness(t, page, false, nil, "tiers")
	if err := h.run(); err != nil || h.err.Len() != 0 {
		t.Errorf("%v %q", err, h.err.String())
	}
}

// With no page installed the copy in the binary is shown, on standard input.
func TestManBuiltInPage(t *testing.T) {
	h := newManHarness(t, nil, false, hostile, "tiers")
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	rec := h.runner.Records()
	if len(rec) != 1 {
		t.Fatalf("started %v", h.runner.Argvs())
	}
	c := rec[0].Cmd
	if !slices.Equal(c.Args, []string{"-l", "-P", "/fake/bin/less", "-"}) || !bytes.Equal(rec[0].Stdin, assets.ManPage()) {
		t.Errorf("%s %q, %d bytes on stdin", c.Name, c.Args, len(rec[0].Stdin))
	}
	checkSafeEnv(t, c.Env, "-R +/^ *TIERS *$")
	// An installed file that is not a file of the page (a directory, an
	// empty file) is not shown either.
	for _, mk := range []func(string) error{func(p string) error { return os.Mkdir(p, 0o755) }, func(p string) error { return os.WriteFile(p, nil, 0o644) }} {
		h = newManHarness(t, nil, false, nil)
		_ = os.MkdirAll(filepath.Dir(h.app.Paths.ManPage), 0o755)
		if err := mk(h.app.Paths.ManPage); err != nil {
			t.Fatal(err)
		}
		if err := h.run(); err != nil || h.started()[0].Args[len(h.started()[0].Args)-1] != "-" {
			t.Errorf("%v %q", err, h.runner.Argvs())
		}
	}
}

// --path says where the page was found and shows nothing.
func TestManPath(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n"), true, nil, "--path")
	if err := h.run(); err != nil || h.out.String() != h.page+"\n" || len(h.started()) != 0 {
		t.Errorf("%v %q %v", err, h.out.String(), h.runner.Argvs())
	}
	h = newManHarness(t, nil, false, nil, "--path")
	if err := h.run(); err != nil || h.out.String() != "built into tacctl\n" || len(h.started()) != 0 {
		t.Errorf("%v %q %v", err, h.out.String(), h.runner.Argvs())
	}
	for _, args := range [][]string{{"--path", "tiers"}, {"--path", "--path"}, {"--path=x"}, {"-x"}, {"--nosuch"}, {"tiers", "-P"}} {
		h = newManHarness(t, nil, false, nil, args...)
		if code := exitCode(h.run(), h.app.Out); code != 1 || h.out.Len() != 0 || len(h.started()) != 0 ||
			!strings.Contains(h.err.String(), "Usage: tacctl man [--path] [<word>...]") {
			t.Errorf("%q: exit %d, stdout %q stderr %q, started %v", args, code, h.out.String(), h.err.String(), h.runner.Argvs())
		}
	}
}

// Without less nothing pages: cat is the pager man is given (never the
// configured one), and the page says why on a terminal; more is not used.
func TestManWithoutLess(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n.SH TIERS\n"), false, hostile, "tiers")
	h.runner.Missing("less")
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	c := h.started()[0]
	if !slices.Equal(c.Args, []string{"-l", "-P", "/fake/bin/cat", h.page}) {
		t.Errorf("arguments %q", c.Args)
	}
	checkSafeEnv(t, c.Env, "-R +/^ *TIERS *$")
	if h.err.String() != "tacctl man: less is not installed, so the page is printed without a pager.\n" {
		t.Errorf("stderr %q", h.err.String())
	}
	if slices.ContainsFunc(h.runner.Argvs(), func(a string) bool { return strings.Contains(a, "more") }) {
		t.Errorf("more was used: %v", h.runner.Argvs())
	}
	// No note when the output is not a terminal.
	h = newManHarness(t, []byte(".TH X 1\n"), false, nil)
	h.runner.Missing("less")
	h.hooks.isTerminalWriter = func(io.Writer) bool { return false }
	if err := h.run(); err != nil || h.err.Len() != 0 {
		t.Errorf("%v %q", err, h.err.String())
	}
	// Neither less nor cat.
	h = newManHarness(t, []byte(".TH X 1\n"), false, nil)
	h.runner.Missing("less", "cat")
	if code := exitCode(h.run(), h.app.Out); code != 1 || len(h.started()) != 0 || !strings.Contains(h.err.String(), "neither less nor cat") {
		t.Errorf("exit %d %q %v", code, h.err.String(), h.runner.Argvs())
	}
}

// Without man, groff renders the page (the page, gunzipped, on its standard
// input) and less shows what it printed; a stream that is not a terminal gets
// the text itself.
func TestManWithoutMan(t *testing.T) {
	page := []byte(".TH X 1\n.SH TIERS\n")
	h := newManHarness(t, page, true, hostile, "tiers")
	h.runner.Missing("man")
	h.runner.On([]string{"/fake/bin/groff"}, execx.Result{Stdout: []byte("RENDERED\n")})
	if err := h.run(); err != nil || h.out.Len() != 0 || h.err.Len() != 0 {
		t.Fatalf("%v %q %q", err, h.out.String(), h.err.String())
	}
	rec := h.runner.Records()
	if len(rec) != 2 {
		t.Fatalf("started %v", h.runner.Argvs())
	}
	g, l := rec[0], rec[1]
	if g.Cmd.Name != "/fake/bin/groff" || !slices.Equal(g.Cmd.Args, []string{"-man", "-Tutf8", "-"}) || !bytes.Equal(g.Stdin, page) {
		t.Errorf("groff: %s %q %q", g.Cmd.Name, g.Cmd.Args, g.Stdin)
	}
	if l.Cmd.Name != "/fake/bin/less" || len(l.Cmd.Args) != 0 || string(l.Stdin) != "RENDERED\n" {
		t.Errorf("less: %s %q %q", l.Cmd.Name, l.Cmd.Args, l.Stdin)
	}
	checkSafeEnv(t, g.Cmd.Env, "-R +/^ *TIERS *$")
	checkSafeEnv(t, l.Cmd.Env, "-R +/^ *TIERS *$")

	// Not a terminal: the text is written, and no pager is started.
	h = newManHarness(t, page, false, nil)
	h.runner.Missing("man")
	h.runner.On([]string{"/fake/bin/groff"}, execx.Result{Stdout: []byte("RENDERED\n")})
	h.hooks.isTerminalWriter = func(io.Writer) bool { return false }
	if err := h.run(); err != nil || h.out.String() != "RENDERED\n" || len(h.started()) != 1 {
		t.Errorf("%v %q %v", err, h.out.String(), h.runner.Argvs())
	}
	// A locale that is not UTF-8 gets ascii.
	h = newManHarness(t, page, false, []string{"LC_ALL=C"})
	h.runner.Missing("man")
	if err := h.run(); err != nil || h.started()[0].Args[1] != "-Tascii" {
		t.Errorf("%v %q", err, h.runner.Argvs())
	}
	// groff failing is an error with its message.
	h = newManHarness(t, page, false, nil)
	h.runner.Missing("man")
	h.runner.Fail([]string{"/fake/bin/groff"}, 2, "troff: bad")
	if code := exitCode(h.run(), h.app.Out); code != 1 || !strings.Contains(h.err.String(), "groff failed: troff: bad") || len(h.started()) != 1 {
		t.Errorf("exit %d %q %v", code, h.err.String(), h.runner.Argvs())
	}
}

// With neither man nor groff the command names the page and what to install.
func TestManWithNeitherManNorGroff(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n"), true, nil, "tiers")
	h.runner.Missing("man", "groff")
	if code := exitCode(h.run(), h.app.Out); code != 1 || len(h.started()) != 0 || h.out.Len() != 0 ||
		!strings.Contains(h.err.String(), "neither man nor groff is installed") || !strings.Contains(h.err.String(), h.page) ||
		!strings.Contains(h.err.String(), "man-db") {
		t.Errorf("exit %d %q", code, h.err.String())
	}
	h = newManHarness(t, nil, false, nil)
	h.runner.Missing("man", "groff")
	if code := exitCode(h.run(), h.app.Out); code != 1 || !strings.Contains(h.err.String(), "built into tacctl") {
		t.Errorf("exit %d %q", code, h.err.String())
	}
}

// A program found at a path that cannot be named safely on man's command
// line, or not by an absolute path, is not used.
func TestManRefusesUnsafeToolPaths(t *testing.T) {
	for _, less := range []string{"/opt/my tools/less", "/opt/less;id", "less", "./less", "/opt/$HOME/less", "/opt/l'ess"} {
		h := newManHarness(t, []byte(".TH X 1\n"), false, nil)
		h.runner.Install("less", less)
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		c := h.started()[0]
		if c.Args[2] != "/fake/bin/cat" {
			t.Errorf("less at %q: the pager is %q", less, c.Args[2])
		}
	}
	h := newManHarness(t, []byte(".TH X 1\n"), false, nil)
	h.runner.Install("less", "/usr/bin/less")
	h.runner.Install("man", "/usr/bin/man")
	if err := h.run(); err != nil || h.started()[0].Name != "/usr/bin/man" || h.started()[0].Args[2] != "/usr/bin/less" {
		t.Errorf("%v %v", err, h.runner.Argvs())
	}
}

// The status of man is the status of the command, and a man that cannot be
// started is said.
func TestManExitStatus(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n"), false, nil)
	h.runner.Fail([]string{"/fake/bin/man"}, 3, "man: boom")
	if code := exitCode(h.run(), h.app.Out); code != 3 || h.err.String() != "man: boom\n" {
		t.Errorf("exit %d %q", code, h.err.String())
	}
}

// manEnv builds the environment from the terminal and the locale and a fixed
// set; nothing else of a large environment survives, and the console's
// environment (which console.Scrub made) is not widened.
func TestManEnvKeepsOnlyTheTerminalAndLocale(t *testing.T) {
	environ := append(slices.Clone(hostile), "TERM=screen", "LANG=de_DE.UTF-8", "LC_ALL=de_DE.UTF-8", "LC_TIME=C", "HOME=/home/user",
		"USER=alice", "LOGNAME=alice", "SSH_CONNECTION=192.0.2.9 1 192.0.2.1 22", "DISPLAY=:0", "PATH=/home/user/bin:/usr/bin", "LESS=-R")
	got := manEnv(environ, "-R +/^ *TIERS *$")
	m := envMap(got)
	want := map[string]string{"TERM": "screen", "LANG": "de_DE.UTF-8", "LC_ALL": "de_DE.UTF-8", "LC_TIME": "C", "PATH": console.ConsolePath,
		"HOME": "/nonexistent", "LESSSECURE": "1", "LESSHISTFILE": "-", "LESS": "-R +/^ *TIERS *$"}
	if len(m) != len(want) || len(got) != len(want) {
		t.Errorf("environment %q", got)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s=%q, want %q", k, m[k], v)
		}
	}
	if got := manEnv(nil, "-R"); !slices.Contains(got, "LESSSECURE=1") || !slices.Contains(got, "PATH="+console.ConsolePath) {
		t.Errorf("empty environment: %q", got)
	}
	if manLessValue("") != "-R" || manLessValue("^ *x") != "-R +/^ *x" {
		t.Errorf("LESS %q %q", manLessValue(""), manLessValue("^ *x"))
	}
}

// 'man' is a word that runs as the invoking user (no sudo), for every tier,
// and is classified a read.
func TestManIsOpenToEveryTierAndRunsWithoutSudo(t *testing.T) {
	a := app.New([]string{"man", "tiers"}, paths.NewEnv([]string{"PATH=/usr/bin"}), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard}, nil)
	if needsSudo(a) {
		t.Errorf("'man' re-runs under sudo")
	}
	if !noSudo["man"] {
		t.Errorf("man is not a word that runs as the invoking user")
	}
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer, tier.Superuser} {
		if !tier.Permits(tr, "man", "") || !tier.Permits(tr, "man", "tiers") {
			t.Errorf("%s may not run man", tr)
		}
	}
	rule := false
	for _, r := range tier.Rules {
		if r.Cmd == "man" {
			rule = true
			if r.Tier != tier.Readonly || len(r.Sudoers) != 0 {
				t.Errorf("row %+v: want a readonly row without sudoers", r)
			}
		}
	}
	if !rule {
		t.Errorf("no tier row for man")
	}
	if e := auditTable["man"]; e.Class != classRead || e.Notice {
		t.Errorf("man is %+v in the audit table, want a plain read", e)
	}
}

// The tree has the command, and its sub-words are free words.
func TestManIsInTheTreeAndTheLists(t *testing.T) {
	h := newHarness(t, []string{"man"})
	root := newRoot(&invocation{app: h.app, hooks: newTestHooks()})
	if c := child(root, "man"); c == nil || c.Hidden || c.Short != manShort {
		t.Fatalf("man in the tree: %+v", c)
	}
	// -h and --help are the help of the command, before anything runs.
	for _, flag := range []string{"-h", "--help"} {
		h := newHarness(t, []string{"man", flag})
		if err := h.run(); err != nil || len(h.runner.Calls()) != 0 || len(h.runner.Execs()) != 0 {
			t.Fatalf("%s: %v %v", flag, err, h.runner.Argvs())
		}
		out := stripSGR(h.out.String())
		for _, want := range []string{"man [--path] [<word>...]", manShort, "--path", "Print where the manual page was found"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: no %q in %q", flag, want, out)
			}
		}
	}
	words, _ := completeWords(t, nil, "m")
	if !slices.Contains(words, "man") {
		t.Errorf("m<Tab>: %q", words)
	}
	words, _ = completeWords(t, nil, "man", "--")
	if !slices.Equal(words, []string{"--path"}) {
		t.Errorf("man --<Tab>: %q", words)
	}
	// The shell and the console list it for every tier.
	for _, tr := range []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer, tier.Superuser} {
		if !viewShows(root, tr, false, []string{"man"}) {
			t.Errorf("%s: the lists hide man", tr)
		}
	}
}
