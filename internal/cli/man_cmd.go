package cli

// 'tacctl man [--path] [<word>...]': the manual page in a pager, for every
// tier and for the console, where nobody has a man command of their own. It
// runs as the invoking user (noSudo, reexec.go), reads no state of tacctl and
// has no tier gate, like 'completion' and 'version'.
//
// The page is the one 'install' and 'upgrade' placed (paths.ManPage), else
// the copy the binary carries (assets.ManPage), so it works on a host where
// the page was never installed. It is rendered by `man -l`, with the file as
// the only page it can show (an installed file by its path, the built-in copy
// on standard input); without man, by groff, then shown by less; with neither,
// the command says so and names the page.
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

	"github.com/rett/tacctl/internal/assets"
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

// manLess is the LESS of the pager when no entry is searched for: colour and
// bold sequences are shown as the page writes them.
const manLess = "-R"

// manSafePath is a program path that can be named on man's command line (-P
// takes a string that man splits at blanks).
var manSafePath = regexp.MustCompile(`^/[A-Za-z0-9/_.+-]+$`)

func manCmd(inv *invocation) *cobra.Command {
	c := verb(manUse, manShort)
	c.RunE = func(_ *cobra.Command, args []string) error { return inv.man(args) }
	return c
}

// manPageSource is the page to show: the installed file, or the built-in copy.
type manPageSource struct {
	path string // the installed file; "" for the built-in copy
	text []byte // the roff source
}

// manSource reads the installed page (gzip or plain) and falls back to the
// copy in the binary when there is none or it cannot be read.
func (inv *invocation) manSource() manPageSource {
	if p := inv.app.Paths.ManPage; filepath.IsAbs(p) {
		if text, err := readManFile(p); err == nil && len(text) > 0 {
			return manPageSource{path: p, text: text}
		}
	}
	return manPageSource{text: assets.ManPage()}
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
	src := inv.manSource()
	if p.Has("--path") {
		if len(p.Args) > 0 {
			return inv.usageErr("--path takes no words.", manUsage)
		}
		where := src.path
		if where == "" {
			where = "built into tacctl"
		}
		inv.write(where + "\n")
		return nil
	}
	pattern := ""
	if len(p.Args) > 0 {
		if e, ok := manLookup(manTopics(src.text), p.Args); ok {
			pattern = e.searchPattern()
		} else {
			inv.manNote("no entry for '" + strings.Join(p.Args, " ") + "'; the page is opened at the top.")
		}
	}
	return inv.manShow(src, pattern)
}

// manTool resolves a program the command runs: found on PATH, by an absolute
// path that can be named on a command line.
func (inv *invocation) manTool(name string) (string, bool) {
	p, err := inv.app.Runner.LookPath(name)
	if err != nil || !manSafePath.MatchString(p) {
		return "", false
	}
	return p, true
}

// manEnv is the environment of man, groff and the pager: console.Scrub's
// rules (the terminal and the locale of the caller, a fixed PATH; every PAGER,
// MANPAGER, LESS*, MAN*, GROFF*, LD_*, TACCTL_* and the rest dropped), then
// only what the display needs of that, and the variables of the pager this
// command sets itself.
func manEnv(environ []string, less string) []string {
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
		"LESS="+less,
	)
}

// manLessValue is the LESS of the pager: -R, and the search that opens the
// page at the entry (made by manTopic.searchPattern from the page's own text).
func manLessValue(pattern string) string {
	if pattern == "" {
		return manLess
	}
	return manLess + " +/" + pattern
}

// manShow shows the page with man, else groff; neither: says what is missing.
func (inv *invocation) manShow(src manPageSource, pattern string) error {
	a := inv.app
	less, haveLess := inv.manTool("less")
	env := manEnv(a.Env.Environ(), manLessValue(pattern))
	if !haveLess && inv.hooks.terminalWriter(a.Out.Stdout) {
		inv.manNote("less is not installed, so the page is printed without a pager.")
	}
	if man, ok := inv.manTool("man"); ok {
		pager := less
		if !haveLess {
			cat, ok := inv.manTool("cat")
			if !ok {
				return &ExitError{Code: 1, Err: errors.New("neither less nor cat is installed, so the page cannot be shown")}
			}
			pager = cat
		}
		argv := []string{"-l", "-P", pager}
		stdin := a.Stdin
		if src.path != "" {
			argv = append(argv, src.path)
		} else {
			argv = append(argv, "-")
			stdin = bytes.NewReader(src.text)
		}
		return inv.manRun(execx.Cmd{Name: man, Args: argv, Env: env}, stdin)
	}
	if groff, ok := inv.manTool("groff"); ok {
		return inv.manGroff(groff, src, less, haveLess, env)
	}
	where := src.path
	if where == "" {
		where = "built into tacctl, see 'tacctl man --path'"
	}
	return &ExitError{Code: 1, Err: errors.New("neither man nor groff is installed, so the manual page cannot be shown (the page: " + where + "); install man-db")}
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
func (inv *invocation) manGroff(groff string, src manPageSource, less string, haveLess bool, env []string) error {
	a := inv.app
	device := manDevice(manLocale(env))
	res, err := a.Runner.Run(inv.ctx, execx.Cmd{Name: groff, Args: []string{"-man", device, "-"}, Env: env, Stdin: bytes.NewReader(src.text)})
	if err != nil || res.Code != 0 {
		msg := strings.TrimSpace(string(res.Stderr))
		if err != nil {
			msg = err.Error()
		}
		a.Out.Error("groff failed: " + msg)
		return exit(1)
	}
	if !haveLess || !inv.hooks.terminalWriter(a.Out.Stdout) {
		_, err := a.Out.Stdout.Write(res.Stdout)
		return err
	}
	return inv.manRun(execx.Cmd{Name: less, Env: env}, bytes.NewReader(res.Stdout))
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
