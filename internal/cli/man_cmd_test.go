package cli

import (
	"bytes"
	"compress/gzip"
	"fmt"
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
// moved into a temporary directory and a terminal for the output. page is the
// page the binary carries for this run (nil: the real one); install puts
// another where install and upgrade put the page.
type manHarness struct {
	*harness
	dir string
}

func newManHarness(t *testing.T, page []byte, env []string, args ...string) *manHarness {
	t.Helper()
	h := &manHarness{harness: newHarness(t, append([]string{"man"}, args...), append(slices.Clone(env), "TERM=xterm", "LANG=C.UTF-8")...), dir: t.TempDir()}
	h.app.Paths = h.app.Paths.Reroot(h.dir)
	if page != nil {
		h.hooks.manPage = func() []byte { return page }
	}
	// The tools are those the fake runner has.
	h.hooks.manLookPath = func(name string) (string, bool) {
		p, err := h.runner.LookPath(name)
		return p, err == nil
	}
	h.hooks.isTerminalWriter = func(io.Writer) bool { return true }
	return h
}

// install writes the page where install and upgrade put it (gzipped or not)
// and returns its path.
func (h *manHarness) install(t *testing.T, content []byte, gz bool) string {
	t.Helper()
	path := h.app.Paths.ManPage
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	data := content
	if gz {
		var b bytes.Buffer
		zw := gzip.NewWriter(&b)
		_, _ = zw.Write(content)
		_ = zw.Close()
		data = b.Bytes()
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
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
func checkSafeEnv(t *testing.T, env []string) {
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
		"LESSSECURE": "1", "LESSHISTFILE": "-", "LESS": "-R"}
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
}

// The page shown is the one the binary carries, on man's standard input,
// whatever is installed; man is given no other file, and nothing the caller
// exported reaches an argument or the environment.
func TestManShowsTheBuiltInPage(t *testing.T) {
	for _, installed := range []string{"none", "plain", "gz"} {
		h := newManHarness(t, nil, hostile)
		switch installed {
		case "plain":
			h.install(t, []byte(".TH OTHER 1\n.SH TIERS\n"), false)
		case "gz":
			h.install(t, []byte(".TH OTHER 1\n.SH TIERS\n"), true)
		}
		if err := h.run(); err != nil || h.out.Len() != 0 || h.err.Len() != 0 {
			t.Fatalf("%s: %v %q %q", installed, err, h.out.String(), h.err.String())
		}
		rec := h.runner.Records()
		if len(rec) != 1 {
			t.Fatalf("started %v", h.runner.Argvs())
		}
		c := rec[0].Cmd
		if c.Name != "/fake/bin/man" || !slices.Equal(c.Args, []string{"-l", "-P", "/fake/bin/less", "-"}) || !bytes.Equal(rec[0].Stdin, assets.ManPage()) {
			t.Errorf("%s: %s %q, %d bytes on stdin", installed, c.Name, c.Args, len(rec[0].Stdin))
		}
		checkSafeEnv(t, c.Env)
		if len(h.runner.Execs()) != 0 {
			t.Errorf("execs %v", h.runner.Execs())
		}
	}
	// The page of a word is searched for in the page that is shown.
	h := newManHarness(t, nil, nil, "tiers")
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	tiers, _ := manLookup(manTopics(assets.ManPage()), []string{"tiers"})
	if got := h.started()[0].Args; !slices.Equal(got, []string{"-l", "-P", manPager("/fake/bin/less", tiers.searchArgs()), "-"}) {
		t.Errorf("arguments %q", got)
	}
}

// Words choose the place and nothing else: the arguments of man are the
// fixed ones and the pager string, which holds a search made from the page's
// own text in single quotes; the LESS of the environment is always -R.
func TestManWordsReachTheSearchOnly(t *testing.T) {
	page := []byte(".TH X 1\n.SH TIERS\ntext\n.SS User management \\fB(tacctl user)\\fR\n.TP\n.BI \"device config plan \" name\nbody\n")
	for _, c := range []struct {
		words []string
		pager string
	}{
		{nil, "/fake/bin/less"},
		{[]string{"tiers"}, "/fake/bin/less '+/^TIERS'"},
		{[]string{"TIERS"}, "/fake/bin/less '+/^TIERS'"},
		{[]string{"user"}, "/fake/bin/less '+/^TIERS' '+/^   User  *management  *.tacctl  *user.'"},
		{[]string{"device", "config", "plan"}, "/fake/bin/less '+/^TIERS' '+/^   User  *management  *.tacctl  *user.' '+/^       device  *config  *plan  *name'"},
		{[]string{"nosuch", "$(id)"}, "/fake/bin/less"},
		{[]string{"--", "-P", "sh"}, "/fake/bin/less"},
	} {
		h := newManHarness(t, page, hostile, c.words...)
		if err := h.run(); err != nil {
			t.Fatalf("%q: %v", c.words, err)
		}
		call := h.started()[0]
		if !slices.Equal(call.Args, []string{"-l", "-P", c.pager, "-"}) {
			t.Errorf("%q: arguments %q", c.words, call.Args)
		}
		checkSafeEnv(t, call.Env)
	}
}

// No text of a heading or a tag can put a quote, a '$', a backquote, a
// newline or an escape other than '\.' into the search, which man gets inside
// single quotes and less reads as an option string.
func TestManPatternHasNoQuoteOrDollar(t *testing.T) {
	hostileText := []string{"a'b", `a"b`, "a`b`", "a$b", "$(id)", "a\\b", "a\nb", "a\rb", "a\tb", "'; touch x; '", `\'`, "a\x00b", "é'", "a b'c d",
		strings.Repeat("'", 100), "x.y\\.z"}
	ok := regexp.MustCompile(`^\^ *([A-Za-z0-9_:,=/@% *.-]|\\\.)*$`)
	check := func(what, p string) {
		t.Helper()
		if !ok.MatchString(p) || strings.ContainsAny(p, "'\"`$\n\r\t\x00") {
			t.Errorf("%s: pattern %q", what, p)
		}
	}
	for _, text := range hostileText {
		for _, topic := range []manTopic{
			{text: text, heading: true}, {text: text, heading: true, indent: 3},
			{text: text}, {text: text, indent: 7}, {text: text, indent: 7, lead: text}, {text: "ab", indent: 7, lead: text},
		} {
			for _, p := range topic.searchArgs() {
				check(fmt.Sprintf("%+v", topic), p)
			}
		}
	}
	for _, e := range shippedTopics(t) {
		for _, p := range e.searchArgs() {
			check(e.text, p)
		}
	}
	// The pager string holds the pattern in one pair of quotes, and nothing
	// of the pattern is outside them.
	for _, text := range hostileText {
		p := manTopic{text: text, indent: 7}.searchPattern()
		pager := manPager("/usr/bin/less", []string{p, p})
		if strings.Count(pager, "'") != 4 || !strings.HasSuffix(pager, "'") || !strings.HasPrefix(pager, "/usr/bin/less '+/") {
			t.Errorf("pager %q", pager)
		}
	}
}

// A word that names nothing opens the page at the top and says so on
// standard error; one that names an entry says nothing.
func TestManUnknownWordSaysSo(t *testing.T) {
	page := []byte(".TH X 1\n.SH TIERS\n")
	h := newManHarness(t, page, nil, "no", "such")
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	if h.out.Len() != 0 || h.err.String() != "tacctl man: no entry for 'no such'; the page is opened at the top.\n" {
		t.Errorf("stdout %q stderr %q", h.out.String(), h.err.String())
	}
	h = newManHarness(t, page, nil, "tiers")
	if err := h.run(); err != nil || h.err.Len() != 0 {
		t.Errorf("%v %q", err, h.err.String())
	}
}

// --path says which page is shown and whether an installed one differs, and
// shows nothing.
func TestManPath(t *testing.T) {
	built := []byte(".TH X 1\n.SH TIERS\n")
	for _, c := range []struct {
		install func(*testing.T, *manHarness) string
		want    string
	}{
		{func(*testing.T, *manHarness) string { return "" }, "built into tacctl\n"},
		{func(t *testing.T, h *manHarness) string { return h.install(t, built, false) },
			"built into tacctl\ninstalled: %s (identical to the built-in page)\n"},
		{func(t *testing.T, h *manHarness) string { return h.install(t, built, true) },
			"built into tacctl\ninstalled: %s (identical to the built-in page)\n"},
		{func(t *testing.T, h *manHarness) string { return h.install(t, []byte(".TH OLD 1\n"), true) },
			"built into tacctl\ninstalled: %s (differs from the built-in page)\n"},
		{func(t *testing.T, h *manHarness) string { return h.install(t, nil, false) },
			"built into tacctl\ninstalled: %s (empty, so not the built-in page)\n"},
		{func(t *testing.T, h *manHarness) string {
			p := h.app.Paths.ManPage
			_ = os.MkdirAll(p, 0o755)
			return p
		}, "built into tacctl\ninstalled: %s (cannot be read, so not the built-in page)\n"},
	} {
		h := newManHarness(t, built, nil, "--path")
		path := c.install(t, h)
		want := c.want
		if strings.Contains(want, "%s") {
			want = fmt.Sprintf(want, path)
		}
		if err := h.run(); err != nil || h.out.String() != want || h.err.Len() != 0 || len(h.started()) != 0 {
			t.Errorf("%v %q, want %q, %v", err, h.out.String(), want, h.runner.Argvs())
		}
	}
	for _, args := range [][]string{{"--path", "tiers"}, {"--path", "--path"}, {"--path=x"}, {"-x"}, {"--nosuch"}, {"tiers", "-P"}} {
		h := newManHarness(t, nil, nil, args...)
		if code := exitCode(h.run(), h.app.Out); code != 1 || h.out.Len() != 0 || len(h.started()) != 0 ||
			!strings.Contains(h.err.String(), "Usage: tacctl man [--path] [<word>...]") {
			t.Errorf("%q: exit %d, stdout %q stderr %q, started %v", args, code, h.out.String(), h.err.String(), h.runner.Argvs())
		}
	}
}

// Without less nothing pages: cat is the pager man is given (never the
// configured one), and the page says why on a terminal; more is not used.
func TestManWithoutLess(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n.SH TIERS\n"), hostile, "tiers")
	h.runner.Missing("less")
	if err := h.run(); err != nil {
		t.Fatal(err)
	}
	c := h.started()[0]
	if !slices.Equal(c.Args, []string{"-l", "-P", "/fake/bin/cat", "-"}) {
		t.Errorf("arguments %q", c.Args)
	}
	checkSafeEnv(t, c.Env)
	if h.err.String() != "tacctl man: less is not installed, so the page is printed without a pager.\n" {
		t.Errorf("stderr %q", h.err.String())
	}
	if slices.ContainsFunc(h.runner.Argvs(), func(a string) bool { return strings.Contains(a, "more") }) {
		t.Errorf("more was used: %v", h.runner.Argvs())
	}
	// No note when the output is not a terminal.
	h = newManHarness(t, []byte(".TH X 1\n"), nil)
	h.runner.Missing("less")
	h.hooks.isTerminalWriter = func(io.Writer) bool { return false }
	if err := h.run(); err != nil || h.err.Len() != 0 {
		t.Errorf("%v %q", err, h.err.String())
	}
	// Neither less nor cat.
	h = newManHarness(t, []byte(".TH X 1\n"), nil)
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
	h := newManHarness(t, page, hostile, "tiers")
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
	if l.Cmd.Name != "/fake/bin/less" || !slices.Equal(l.Cmd.Args, []string{"+/^TIERS"}) || string(l.Stdin) != "RENDERED\n" {
		t.Errorf("less: %s %q %q", l.Cmd.Name, l.Cmd.Args, l.Stdin)
	}
	checkSafeEnv(t, g.Cmd.Env)
	checkSafeEnv(t, l.Cmd.Env)

	// Not a terminal: the text is written, and no pager is started.
	h = newManHarness(t, page, nil)
	h.runner.Missing("man")
	h.runner.On([]string{"/fake/bin/groff"}, execx.Result{Stdout: []byte("RENDERED\n")})
	h.hooks.isTerminalWriter = func(io.Writer) bool { return false }
	if err := h.run(); err != nil || h.out.String() != "RENDERED\n" || len(h.started()) != 1 {
		t.Errorf("%v %q %v", err, h.out.String(), h.runner.Argvs())
	}
	// A locale that is not UTF-8 gets ascii.
	h = newManHarness(t, page, []string{"LC_ALL=C"})
	h.runner.Missing("man")
	if err := h.run(); err != nil || h.started()[0].Args[1] != "-Tascii" {
		t.Errorf("%v %q", err, h.runner.Argvs())
	}
	// groff failing is an error with its message.
	h = newManHarness(t, page, nil)
	h.runner.Missing("man")
	h.runner.Fail([]string{"/fake/bin/groff"}, 2, "troff: bad")
	if code := exitCode(h.run(), h.app.Out); code != 1 || !strings.Contains(h.err.String(), "groff failed: troff: bad") || len(h.started()) != 1 {
		t.Errorf("exit %d %q %v", code, h.err.String(), h.runner.Argvs())
	}
}

// With neither man nor groff the command names the page and what to install.
func TestManWithNeitherManNorGroff(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n"), nil, "tiers")
	h.runner.Missing("man", "groff")
	if code := exitCode(h.run(), h.app.Out); code != 1 || len(h.started()) != 0 || h.out.Len() != 0 ||
		!strings.Contains(h.err.String(), "neither man nor groff is installed") || !strings.Contains(h.err.String(), "built into tacctl") ||
		!strings.Contains(h.err.String(), "man-db") {
		t.Errorf("exit %d %q", code, h.err.String())
	}
	h = newManHarness(t, nil, nil)
	h.runner.Missing("man", "groff")
	if code := exitCode(h.run(), h.app.Out); code != 1 || !strings.Contains(h.err.String(), "built into tacctl") {
		t.Errorf("exit %d %q", code, h.err.String())
	}
}

// A program found at a path that cannot be named safely on man's command
// line, or not by an absolute path, is not used.
func TestManRefusesUnsafeToolPaths(t *testing.T) {
	for _, less := range []string{"/opt/my tools/less", "/opt/less;id", "less", "./less", "/opt/$HOME/less", "/opt/l'ess"} {
		h := newManHarness(t, []byte(".TH X 1\n"), nil)
		h.runner.Install("less", less)
		if err := h.run(); err != nil {
			t.Fatal(err)
		}
		c := h.started()[0]
		if c.Args[2] != "/fake/bin/cat" {
			t.Errorf("less at %q: the pager is %q", less, c.Args[2])
		}
	}
	h := newManHarness(t, []byte(".TH X 1\n"), nil)
	h.runner.Install("less", "/usr/bin/less")
	h.runner.Install("man", "/usr/bin/man")
	if err := h.run(); err != nil || h.started()[0].Name != "/usr/bin/man" || h.started()[0].Args[2] != "/usr/bin/less" {
		t.Errorf("%v %v", err, h.runner.Argvs())
	}
}

// The status of man is the status of the command, and a man that cannot be
// started is said.
func TestManExitStatus(t *testing.T) {
	h := newManHarness(t, []byte(".TH X 1\n"), nil)
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
	got := manEnv(environ)
	m := envMap(got)
	want := map[string]string{"TERM": "screen", "LANG": "de_DE.UTF-8", "LC_ALL": "de_DE.UTF-8", "LC_TIME": "C", "PATH": console.ConsolePath,
		"HOME": "/nonexistent", "LESSSECURE": "1", "LESSHISTFILE": "-", "LESS": "-R"}
	if len(m) != len(want) || len(got) != len(want) {
		t.Errorf("environment %q", got)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s=%q, want %q", k, m[k], v)
		}
	}
	if got := manEnv(nil); !slices.Contains(got, "LESSSECURE=1") || !slices.Contains(got, "PATH="+console.ConsolePath) {
		t.Errorf("empty environment: %q", got)
	}
	if manPager("/usr/bin/less", nil) != "/usr/bin/less" || manPager("/usr/bin/less", []string{"^ *x", "^y"}) != "/usr/bin/less '+/^ *x' '+/^y'" {
		t.Errorf("pager %q", manPager("/usr/bin/less", []string{"^ *x", "^y"}))
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
		for _, want := range []string{"man [--path] [<word>...]", manShort, "--path", "Print which manual page is shown and where one is installed"} {
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

// The programs are looked for in the directories of console.ConsolePath, the
// PATH the child gets, and not in the caller's PATH: a directory of the caller
// that holds a less (or a man, or a groff) is not used.
func TestManToolsAreLookedForOnTheConsolePath(t *testing.T) {
	dir := t.TempDir()
	hostileDir := filepath.Join(dir, "hostile")
	okDir, plainDir := filepath.Join(dir, "ok"), filepath.Join(dir, "plain")
	for _, d := range []string{hostileDir, okDir, plainDir, filepath.Join(plainDir, "dirless")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, mode os.FileMode) {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(hostileDir, "less"), 0o755)
	write(filepath.Join(plainDir, "less"), 0o644) // not executable
	write(filepath.Join(okDir, "less"), 0o755)
	if got, ok := lookInDirs("less", []string{"relative", plainDir, filepath.Join(plainDir, "dirless"), okDir, hostileDir}); !ok || got != filepath.Join(okDir, "less") {
		t.Errorf("lookInDirs: %q %v", got, ok)
	}
	if got, ok := lookInDirs("less", []string{"relative", "", "."}); ok {
		t.Errorf("a relative directory is searched: %q", got)
	}
	if got, ok := lookInDirs("nosuch", []string{okDir}); ok {
		t.Errorf("lookInDirs found %q", got)
	}

	// The real lookup, with a caller whose PATH starts with a directory that
	// holds a less, a man and a groff of its own.
	for _, tool := range []string{"man", "groff"} {
		write(filepath.Join(hostileDir, tool), 0o755)
	}
	h := newHarness(t, []string{"man"}, "PATH="+hostileDir+":/usr/bin:/bin")
	inv := &invocation{app: h.app} // no hooks: the real lookup
	for _, tool := range []string{"less", "man", "groff"} {
		got, ok := inv.manTool(tool)
		if ok && !slices.Contains(strings.Split(console.ConsolePath, ":"), filepath.Dir(got)) {
			t.Errorf("%s was found at %q, outside %s", tool, got, console.ConsolePath)
		}
		if strings.HasPrefix(got, hostileDir) {
			t.Errorf("%s of the caller's PATH was used: %q", tool, got)
		}
	}
	// The directories are those of the child's PATH.
	if dirs := strings.Split(console.ConsolePath, ":"); len(dirs) == 0 || !slices.ContainsFunc(dirs, filepath.IsAbs) {
		t.Errorf("console.ConsolePath %q", console.ConsolePath)
	}
	// A tool the lookup finds is also held to the safe path rule.
	hh := newManHarness(t, nil, nil)
	hh.hooks.manLookPath = func(string) (string, bool) { return "/opt/my tools/less", true }
	if _, ok := (&invocation{app: hh.app, hooks: hh.hooks}).manTool("less"); ok {
		t.Errorf("an unsafe path was accepted")
	}
}
