package cli

// 'tacctl man [--path] [<word>...]': the manual page in a pager, for every
// tier and for the console, where nobody has a man command of their own. It
// runs as the invoking user (noSudo, reexec.go), reads no state of tacctl and
// has no tier gate, like 'completion' and 'version'.
//
// The page is the one the binary carries (assets.ManPage), so it is the page of
// the running version whether or not 'install' and 'upgrade' placed one
// (paths.ManPage; --path says whether that one is the same). It is rendered by
// `man -l` with the page on standard input as the only page it can show;
// without man, by groff, then shown by less; with neither, the command says so.
//
// The pager must not be a way out of the console, and `man` and `less` can
// run commands (`!cmd`, `v`, `|`, -P, a LESSOPEN, a MANPAGER, a groff macro
// path). So nothing of the caller's environment decides how the page is
// shown: the child gets an environment made here (manEnv: the terminal and
// the locale, console.Scrub's rules, and no PAGER, MANPAGER, LESS*, MAN* or
// GROFF* of the caller), the pager is the `less` found on PATH, chosen by
// tacctl and named on the command line (man's -P), with LESSSECURE=1 (no
// shell escape, no editor, no pipe, no log file) and a LESS of its own. When
// there is no less, no pager is used and the page is printed whole: `more`
// has a shell escape that cannot be switched off. The words the person types
// only choose a heading of the page; they never reach an argument or the
// environment of man or the pager.

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
)

func init() {
	registerFamily(manCmd)
	registerSpecFunc("man", func(path []string) (Spec, bool) { return manSpec, len(path) == 1 })
}

// manSpec is 'tacctl man [--path] [<word>...]'.
var manSpec = Spec{MinArgs: 0, MaxArgs: -1, Flags: []Flag{{Names: []string{"--path"}, Alone: true}}}

const (
	manUse   = "man [--path] [<word>...]"
	manShort = "Open the manual page, at a command or topic"
	manUsage = "Usage: tacctl " + manUse
)

// manPageMax is the most of a page (installed, or after decompression) that is read.
const manPageMax = 16 << 20

// manHome is the HOME of the pager and of man: a directory that does not
// exist, so that neither reads a ~/.lesskey, a ~/.lesshst or a ~/.manpath.
const manHome = "/nonexistent"

// manLess is the LESS of the pager: colour and bold sequences are shown as
// the page writes them. The search that opens the page at an entry is not in
// it: less reads a '$' in an option string as its end, so the search is the
// '+/pattern' argument of the pager's command line (manPager).
const manLess = "-R"

// manSafePath is a program path that can be named on man's command line (-P
// takes a string that man splits at blanks).
var manSafePath = regexp.MustCompile(`^/[A-Za-z0-9/_.+-]+$`)

func manCmd(inv *invocation) *cobra.Command {
	c := verb(manUse, manShort)
	c.RunE = func(_ *cobra.Command, args []string) error { return inv.man(args) }
	return c
}

// manInstalled describes the installed page against the built-in one, for
// --path: where it is, and whether it is the same page.
func (inv *invocation) manInstalled(builtIn []byte) (line string, ok bool) {
	path := inv.app.Paths.ManPage
	if !filepath.IsAbs(path) {
		return "", false
	}
	if _, err := os.Lstat(path); err != nil {
		return "", false
	}
	text, err := readManFile(path)
	switch {
	case err != nil:
		return "installed: " + path + " (cannot be read, so not the built-in page)", true
	case len(text) == 0:
		return "installed: " + path + " (empty, so not the built-in page)", true
	case bytes.Equal(text, builtIn):
		return "installed: " + path + " (identical to the built-in page)", true
	}
	return "installed: " + path + " (differs from the built-in page)", true
}

// readManFile reads a manual page file, gunzipping it when it is gzip.
func readManFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	head := make([]byte, 2)
	n, _ := io.ReadFull(f, head)
	rd := io.MultiReader(bytes.NewReader(head[:n]), f)
	if n == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(rd)
		if err != nil {
			return nil, err
		}
		rd = zr
	}
	text, err := io.ReadAll(io.LimitReader(rd, manPageMax))
	if err != nil {
		return nil, err
	}
	return text, nil
}

// man is 'tacctl man'.
func (inv *invocation) man(args []string) error {
	p, err := Parse(manSpec, args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.usageErr(msg, manUsage)
	}
	page := inv.hooks.builtInManPage()
	if p.Has("--path") {
		if len(p.Args) > 0 {
			return inv.usageErr("--path takes no words.", manUsage)
		}
		inv.write("built into tacctl\n")
		if line, ok := inv.manInstalled(page); ok {
			inv.write(line + "\n")
		}
		return nil
	}
	var searches []string
	if len(p.Args) > 0 {
		if e, ok := manLookup(manTopics(page), p.Args); ok {
			searches = e.searchArgs()
		} else {
			inv.manNote("no entry for '" + strings.Join(p.Args, " ") + "'; the page is opened at the top.")
		}
	}
	return inv.manShow(page, searches)
}

// manTool resolves a program the command runs: found in the directories of
// console.ConsolePath, the PATH its child gets (not the caller's PATH, which
// may name a directory the caller writes to, and which the console has
// already replaced by this one), by an absolute path that can be named on a
// command line.
func (inv *invocation) manTool(name string) (string, bool) {
	p, ok := inv.hooks.lookManTool(name)
	if !ok || !manSafePath.MatchString(p) {
		return "", false
	}
	return p, true
}

// lookInDirs is the first executable regular file called name in the
// absolute directories dirs.
func lookInDirs(name string, dirs []string) (string, bool) {
	for _, d := range dirs {
		if !filepath.IsAbs(d) {
			continue
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// manEnv is the environment of man, groff and the pager: console.Scrub's
// rules (the terminal and the locale of the caller, a fixed PATH; every PAGER,
// MANPAGER, LESS*, MAN*, GROFF*, LD_*, TACCTL_* and the rest dropped), then
// only what the display needs of that, and the variables of the pager this
// command sets itself.
func manEnv(environ []string) []string {
	var out []string
	for _, kv := range console.Scrub(environ, "/bin/sh", false) {
		k, _, _ := strings.Cut(kv, "=")
		if k == "TERM" || k == "LANG" || strings.HasPrefix(k, "LC_") {
			out = append(out, kv)
		}
	}
	return append(out,
		"PATH="+console.ConsolePath,
		"HOME="+manHome,
		"LESSSECURE=1",
		"LESSHISTFILE=-",
		"LESS="+manLess,
	)
}

// manPager is the pager string given to man (-P): the less, and, to open the
// page at an entry, each search as a single-quoted argument (man splits the
// string at blanks and honours single quotes, with no shell). A pattern
// never holds a quote (searchPattern), so it cannot end the quoting.
func manPager(less string, patterns []string) string {
	for _, p := range patterns {
		less += " '+/" + p + "'"
	}
	return less
}

// manShow shows the page with man, else groff; neither: says what is missing.
func (inv *invocation) manShow(page []byte, searches []string) error {
	a := inv.app
	less, haveLess := inv.manTool("less")
	env := manEnv(a.Env.Environ())
	if !haveLess && inv.hooks.terminalWriter(a.Out.Stdout) {
		inv.manNote("less is not installed, so the page is printed without a pager.")
	}
	if man, ok := inv.manTool("man"); ok {
		pager := manPager(less, searches)
		if !haveLess {
			cat, ok := inv.manTool("cat")
			if !ok {
				return &ExitError{Code: 1, Err: errors.New("neither less nor cat is installed, so the page cannot be shown")}
			}
			pager = cat
		}
		return inv.manRun(execx.Cmd{Name: man, Args: []string{"-l", "-P", pager, "-"}, Env: env}, bytes.NewReader(page))
	}
	if groff, ok := inv.manTool("groff"); ok {
		return inv.manGroff(groff, page, less, haveLess, searches, env)
	}
	return &ExitError{Code: 1, Err: errors.New("neither man nor groff is installed, so the manual page cannot be shown; install man-db (the page is built into tacctl)")}
}

// manRun runs a command of the display with the terminal and returns its status.
func (inv *invocation) manRun(c execx.Cmd, stdin io.Reader) error {
	a := inv.app
	code, _, err := execx.Attached(inv.ctx, a.Runner, c, stdin, a.Out.Stdout, a.Out.Stderr)
	if err != nil {
		a.Out.Error("cannot run " + c.Name + ": " + err.Error())
		if code == 0 {
			code = 1
		}
	}
	if code != 0 {
		return exit(code)
	}
	return nil
}

// manGroff is the display without man: groff renders the page (the locale
// decides utf8 or ascii), less shows it on a terminal, else it is written.
func (inv *invocation) manGroff(groff string, page []byte, less string, haveLess bool, searches []string, env []string) error {
	a := inv.app
	device := manDevice(manLocale(env))
	paging := haveLess && inv.hooks.terminalWriter(a.Out.Stdout)
	args := []string{"-man", device}
	if !paging {
		// Text for a file or a pipe: no bold and underline sequences, no
		// backspaces (grotty -c -b -o -u).
		args = append(args, "-P-cbou")
	}
	res, err := a.Runner.Run(inv.ctx, execx.Cmd{Name: groff, Args: append(args, "-"), Env: env, Stdin: bytes.NewReader(page)})
	if err != nil || res.Code != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if err != nil {
			msg = err.Error()
		}
		a.Out.Error("groff failed: " + msg)
		return exit(1)
	}
	if !paging {
		_, err := a.Out.Stdout.Write(res.Stdout)
		return err
	}
	var lessArgs []string
	for _, p := range searches {
		lessArgs = append(lessArgs, "+/"+p)
	}
	return inv.manRun(execx.Cmd{Name: less, Args: lessArgs, Env: env}, bytes.NewReader(res.Stdout))
}

// manLocale is the locale name an environment selects for character
// classification: LC_ALL, else LC_CTYPE, else LANG.
func manLocale(env []string) string {
	vals := map[string]string{}
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok {
			vals[k] = v
		}
	}
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if vals[k] != "" {
			return vals[k]
		}
	}
	return ""
}

// manDevice is groff's output device for a locale name.
func manDevice(locale string) string {
	l := strings.ToLower(locale)
	if strings.Contains(l, "utf-8") || strings.Contains(l, "utf8") {
		return "-Tutf8"
	}
	return "-Tascii"
}

// manNote is a line on standard error about what the command did instead of
// what was asked.
func (inv *invocation) manNote(msg string) {
	_, _ = io.WriteString(inv.app.Out.Stderr, "tacctl man: "+msg+"\n")
}
