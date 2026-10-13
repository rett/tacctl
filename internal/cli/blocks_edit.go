package cli

// 'edit' of the configuration blocks (0.2.7, docs/plans/0.2.7-blocks-plan.md
// B5): a block opened in the invoking user's editor, the way visudo and
// sudoedit do it.
//
//   - The editor is VISUAL, else EDITOR, else 'editor' (Debian's
//     alternatives), else 'vi', and it runs as the INVOKING user, never as
//     root: an editor's shell escape must not be a root shell. It works on a
//     private copy (0600) in a private directory (0700) made for it under
//     /var/tmp and owned by that user, which is removed afterwards on every
//     path (the editor's swap and backup files land there).
//   - sudo's env_reset drops VISUAL and EDITOR, so the sudoers drop-ins keep
//     them for the four command lines that open an editor (tier.EditorKeep),
//     and tacctl takes them out of its own environment at start (captureEditor)
//     so no other program it runs inherits them.
//   - What comes back is read as the user (the private file: regular, theirs,
//     at most blocks.MaxSize; a link or anything else is ignored), checked as
//     'set' checks, and installed as 'set' installs it (review, install),
//     after the question. A failed check offers to open the editor again with
//     the findings as '#' lines at the top; the findings never reach the file.
//   - In the login console the rule of the system shell applies: an editor
//     can start one, so the console's tiers for it are the tiers for an
//     editor.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/policy"
)

// blockEditDir is where the private directories of an edit are made; tests
// replace it.
var blockEditDir = "/var/tmp"

// blockEditRounds is how many times a text that fails its check is offered
// back to the editor.
const blockEditRounds = 5

// editEuid is the identity this process has (tests replace it, to run the
// credential drop on a process that is not root).
var editEuid = os.Geteuid

// findingPrefix starts every line the editor is shown that is not the
// block's: the findings of the last attempt. Every such line is removed
// before a text is read as a block.
const findingPrefix = "# tacctl: "

// --- the editor's variables ------------------------------------------------------

// processEditor is VISUAL and EDITOR as the root side's process had them at
// start (captureEditor): the environment itself no longer has them.
var processEditor struct{ visual, editor string }

// captureEditor takes VISUAL and EDITOR out of environ, which it returns
// without them, and out of the process's own environment, in the root side
// of a sudo line (euid 0): no program tacctl starts there (git, systemctl, a
// pager) then inherits an editor the caller named. The values are kept for
// the verbs that open one. The user's own process (the shell, the console,
// the sudo re-exec) keeps them: they are what sudo is asked to carry.
func captureEditor(environ []string, euid int) []string {
	if euid != 0 {
		return environ
	}
	out := make([]string, 0, len(environ))
	found := false
	for _, kv := range environ {
		if v, ok := strings.CutPrefix(kv, "VISUAL="); ok {
			processEditor.visual, found = v, true
			continue
		}
		if v, ok := strings.CutPrefix(kv, "EDITOR="); ok {
			processEditor.editor, found = v, true
			continue
		}
		out = append(out, kv)
	}
	if found {
		_ = os.Unsetenv("VISUAL") //nolint:forbidigo // removing the variables, not reading the environment
		_ = os.Unsetenv("EDITOR") //nolint:forbidigo // removing the variables, not reading the environment
	}
	return out
}

// editorVars are the caller's VISUAL and EDITOR: what captureEditor kept, or,
// where the invocation was built without Main (the in-process callers), the
// app's environment.
func (inv *invocation) editorVars() (visual, editor string) {
	visual, editor = processEditor.visual, processEditor.editor
	if visual == "" {
		visual = inv.app.Env.Get("VISUAL")
	}
	if editor == "" {
		editor = inv.app.Env.Get("EDITOR")
	}
	return visual, editor
}

// editorCommand is the editor to run as argv, and the word that names where
// it came from (for the messages). A value is a command, with arguments if
// the person wrote them ('emacs -nw'): a name found in PATH or an absolute
// path, as visudo takes it.
func (inv *invocation) editorCommand() (argv []string, from string, err error) {
	visual, editor := inv.editorVars()
	type cand struct{ from, value string }
	var order []cand
	if visual != "" {
		order = append(order, cand{"VISUAL", visual})
	}
	if editor != "" {
		order = append(order, cand{"EDITOR", editor})
	}
	for _, c := range order {
		if strings.ContainsFunc(c.value, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, "", fmt.Errorf("%s holds a control character; set it to the editor's name or path", c.from)
		}
		f := strings.Fields(c.value)
		if len(f) == 0 {
			continue
		}
		path, err := inv.editorPath(f[0])
		if err != nil {
			return nil, "", fmt.Errorf("%s names '%s', which is %s; use the editor's absolute path, or unset it", c.from, f[0], err.Error())
		}
		return append([]string{path}, f[1:]...), c.from, nil
	}
	for _, name := range []string{"editor", "vi"} {
		if path, err := inv.app.Runner.LookPath(name); err == nil {
			return []string{path}, name, nil
		}
	}
	return nil, "", errors.New("no editor was found (VISUAL and EDITOR are not set, and neither 'editor' nor 'vi' is installed); set VISUAL or EDITOR to one")
}

// editorPath resolves an editor's name: an absolute path as it is (it must
// be an executable file), anything else through PATH; a path with a '/' that
// is not absolute is refused (the editor runs in a directory of its own).
func (inv *invocation) editorPath(name string) (string, error) {
	if strings.Contains(name, "/") {
		if !filepath.IsAbs(name) {
			return "", errors.New("not an absolute path")
		}
		if _, err := inv.app.Runner.LookPath(name); err != nil {
			return "", errors.New("not an executable file")
		}
		return name, nil
	}
	p, err := inv.app.Runner.LookPath(name)
	if err != nil {
		return "", errors.New("not found in PATH")
	}
	return p, nil
}

// --- who the editor runs as ---------------------------------------------------------

// editorIdentity is the account the editor runs as and owns the private
// directory.
type editorIdentity struct {
	user string
	acct sshAccount
	// cred is the credential the editor is started with: nil when the
	// process is not root (a test, or tacctl run by the person themself) or
	// is root's own (no sudo user to drop to).
	cred *syscall.Credential
	// uid owns what the editor writes.
	uid int
}

// editorIdentity looks the invoking user up. With a SUDO_UID the account is
// the one sudo ran this for (the pair is verified as 'tacctl ssh' verifies
// it), never root; a process that is root and has no SUDO_UID is the
// person's own root session, which is who the editor runs as.
func (inv *invocation) editorIdentity() (editorIdentity, error) {
	a := inv.app
	euid := editEuid()
	uid, _, ok := inv.callerIDs()
	switch {
	case euid != 0:
		// no right to change identity: this process's own is the person's
		return editorIdentity{user: inv.sudoUser(), acct: sshAccount{UID: uint32(euid), Home: a.Env.Get("HOME")}, uid: euid}, nil
	case !ok || uid == 0:
		home := a.Env.Get("HOME")
		if home == "" {
			home = "/root"
		}
		return editorIdentity{user: "root", acct: sshAccount{Home: home}, uid: 0}, nil
	}
	if err := inv.verifySudoUser("the editor"); err != nil {
		return editorIdentity{}, errors.New("the invoking user could not be verified")
	}
	user := inv.sudoUser()
	acct, err := sshAccountOf(user)
	if err != nil || acct.Home == "" {
		return editorIdentity{}, errors.New("the account of '" + user + "' cannot be looked up here")
	}
	if acct.UID == 0 || int(acct.UID) != uid {
		return editorIdentity{}, errors.New("the account of '" + user + "' is not the one sudo ran this for")
	}
	return editorIdentity{user: user, acct: acct, uid: uid,
		cred: &syscall.Credential{Uid: acct.UID, Gid: acct.GID, Groups: acct.Groups}}, nil
}

// --- the console's rule ------------------------------------------------------------

// editorAllowed is the console's rule for an editor: a console session (the
// marker TACCTL_CONSOLE) may open one only where it may start the system
// shell ('console system-shell tiers'; never the engineer), since an editor
// can start a shell. A plain shell or a command from bash is not held to it:
// the person has a shell there already.
func (inv *invocation) editorAllowed(what string) error {
	if !inv.sshConsole() {
		return nil
	}
	pol, err := inv.consolePolicy()
	g := inv.tierGate()
	t := g.Caller(inv.ctx)
	if err != nil || g.EngineerBound(inv.ctx) || !pol.SystemShell(t) {
		inv.app.Logger(inv.ctx, "auth.warning", "block "+what+" DENY user="+inv.sudoUser()+" tier="+string(t)+inv.sshConsoleField())
		return inv.usageErr("In the login console an editor can start a shell, so " + what + " is open only to the tiers that may start the system shell (tacctl console system-shell tiers); the " +
			string(t) + " tier is not one of them. Nothing was changed.")
	}
	return nil
}

// terminalRequired refuses a verb that needs the person at a terminal.
func (inv *invocation) terminalRequired(what string) error {
	if sshTerminal(inv.app.Stdin) && isTerminalWriter(inv.app.Out.Stdout) {
		return nil
	}
	return inv.usageErr(what + " opens an editor and needs a terminal on standard input and output. Nothing was changed.")
}

// --- the editor's run ---------------------------------------------------------------

// editFileName is the private copy's name: it shows in the editor's title.
func (c *blockCtx) editFileName(block string) string {
	who := "scope-" + c.level.Scope
	if c.isDevice() {
		who = "device-" + c.dev.Name
	}
	name := who + "-" + c.vendor + "-" + block + ".txt"
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, name)
}

// editorRun is what one run of the editor ended as.
type editorRun struct {
	// text is the private file read back (valid when status is 0).
	text []byte
	// status is the editor's exit status.
	status int
	// signalled: tacctl was told to stop (INT, TERM, HUP) while the editor
	// ran: nothing is used.
	signalled bool
}

// runEditor writes seed to a private copy, runs the editor on it as the
// invoking user, reads the copy back and removes the directory, on every
// path.
func (c *blockCtx) runEditor(name string, seed []byte) (editorRun, error) {
	inv := c.inv
	a := inv.app
	var run editorRun
	argv, _, err := inv.editorCommand()
	if err != nil {
		return run, err
	}
	id, err := inv.editorIdentity()
	if err != nil {
		return run, err
	}
	dir, err := os.MkdirTemp(blockEditDir, "tacctl-edit-")
	if err != nil {
		return run, fmt.Errorf("cannot make a private directory for the editor: %w", err)
	}
	defer inv.removeEditDir(dir)
	if id.cred != nil {
		if err := os.Chown(dir, int(id.acct.UID), int(id.acct.GID)); err != nil {
			return run, fmt.Errorf("cannot hand the private directory to '%s': %w", id.user, err)
		}
	}
	path := filepath.Join(dir, name)
	err = inv.asCaller(func() error {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(seed); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
	if err != nil {
		return run, fmt.Errorf("cannot write the private copy: %w", err)
	}

	visual, editor := inv.editorVars()
	var extra []string
	if visual != "" {
		extra = append(extra, "VISUAL="+visual)
	}
	if editor != "" {
		extra = append(extra, "EDITOR="+editor)
	}
	cmd := execx.Cmd{
		Name: argv[0], Args: append(append([]string(nil), argv[1:]...), path), Dir: dir, Credential: id.cred,
		Env:    sshUserEnviron(a.Env.Environ(), id.acct, id.user, extra),
		Stdout: a.Out.Stdout, Stderr: a.Out.Stderr,
	}
	// The terminal itself, as the file it is (a reader would be copied from
	// and its bytes taken); what is not a file has no terminal to give.
	if f, ok := a.Stdin.(*os.File); ok {
		cmd.Stdin = f
	}
	// A stop signal is the editor's to meet first (the terminal's whole
	// foreground group gets INT and HUP; TERM is passed on) and this
	// process's to outlive, so that the directory is removed by it and not
	// left for a kill. A Ctrl-C is the editor's own key (a line editor is
	// told by it, not stopped): it neither ends the edit nor, being the
	// editor's, the steps after it.
	inv.ctx = context.WithoutCancel(inv.ctx)
	sigc := make(chan os.Signal, 4)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigc)
	proc, err := a.Runner.Start(inv.ctx, cmd)
	if err != nil {
		return run, fmt.Errorf("cannot start the editor '%s': %w", argv[0], err)
	}
	type waited struct {
		res execx.Result
		err error
	}
	done := make(chan waited, 1)
	go func() {
		r, err := proc.Wait()
		done <- waited{r, err}
	}()
	var w waited
loop:
	for {
		select {
		case s := <-sigc:
			if s != syscall.SIGINT {
				run.signalled = true
				_ = proc.Signal(s)
			}
		case w = <-done:
			break loop
		}
	}
	// a stop that arrived as the editor ended
	select {
	case s := <-sigc:
		run.signalled = run.signalled || s != syscall.SIGINT
	default:
	}
	if w.err != nil {
		return run, fmt.Errorf("the editor could not be waited for: %w", w.err)
	}
	run.status = w.res.Code
	if run.status != 0 || run.signalled {
		return run, nil
	}
	err = inv.asCaller(func() error {
		data, err := readPrivateFile(path, int64(blocks.MaxSize), id.cred != nil, id.uid)
		run.text = data
		return err
	})
	if err != nil {
		return run, err
	}
	return run, nil
}

// readPrivateFile reads the private copy back: a regular file (a link, a
// device or a pipe is refused, and never opened), no larger than max, and,
// when the editor was dropped to the user's identity, theirs.
func readPrivateFile(path string, max int64, checkOwner bool, uid int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("the editor left no file to read back (it is not there, or it is a link)")
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	switch {
	case err != nil:
		return nil, err
	case !st.Mode().IsRegular():
		return nil, errors.New("the editor left something that is not a regular file")
	case st.Size() > max:
		return nil, fmt.Errorf("the edited text is %d bytes: a block is at most %d (256 KiB)", st.Size(), max)
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && checkOwner && int(sys.Uid) != uid {
		return nil, errors.New("the file the editor left is not the invoking user's")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("the edited text is larger than %d bytes (256 KiB)", max)
	}
	return data, nil
}

// removeEditDir removes the private directory: as the user whose it is, and,
// if anything is left, once more as this process.
func (inv *invocation) removeEditDir(dir string) {
	_ = inv.asCaller(func() error { return os.RemoveAll(dir) })
	if _, err := os.Lstat(dir); err == nil {
		_ = os.RemoveAll(dir)
	}
}

// --- the findings the editor is shown ---------------------------------------------

// insertFindings puts the findings of the last attempt at the top of text,
// each as a '#' line that starts with findingPrefix.
func insertFindings(text string, lines []string) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(findingPrefix + l + "\n")
	}
	b.WriteString(text)
	return b.String()
}

// stripFindings removes every line that starts with findingPrefix: the
// findings of an earlier attempt are never part of a block, whether the
// person left them where they were or not.
func stripFindings(text string) string {
	if !strings.Contains(text, findingPrefix) {
		return text
	}
	var out []string
	for _, l := range strings.SplitAfter(text, "\n") {
		if !strings.HasPrefix(l, findingPrefix) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "")
}

// findingLines are the lines the editor is shown when a text failed its
// check: the errors, with the line numbers of the editor's window (the lines
// of the findings come first and shift the text down).
func findingLines(bc *blockCheck) []string {
	var errs []string
	var lines []int
	for _, f := range bc.findings {
		if f.Severity == blocks.SevError {
			errs = append(errs, f.Text)
			lines = append(lines, f.Line)
		}
	}
	for _, m := range bc.collision {
		errs = append(errs, m)
		lines = append(lines, 0)
	}
	if len(errs) == 0 {
		return nil
	}
	head := []string{
		"the text below was not installed: fix the errors and save, or quit without saving to give up.",
		"line numbers are those of this window; these lines are removed when the editor closes.",
	}
	shift := len(head) + len(errs)
	out := append([]string(nil), head...)
	for i, m := range errs {
		if lines[i] > 0 {
			out = append(out, "line "+strconv.Itoa(lines[i]+shift)+": error: "+m)
		} else {
			out = append(out, "error: "+m)
		}
	}
	return out
}

// --- the verb -----------------------------------------------------------------------

// edit is 'edit <block> [-y]'.
func (c *blockCtx) edit(block string, p Parsed) error {
	inv := c.inv
	if err := c.requireSuperuser("edit"); err != nil {
		return err
	}
	if err := inv.terminalRequired("edit"); err != nil {
		return err
	}
	if err := inv.editorAllowed("edit"); err != nil {
		return err
	}
	if err := inv.confWritable(); err != nil {
		return err
	}
	cur := c.file(block)
	if cur.err != nil {
		return cur.err
	}
	return c.editFlow(block, c.editSeed(block, cur), cur, "edit", "the edited text", p.Has("-y"))
}

// editSeed is the text the editor opens: the file in force; for a block
// that does not exist, the commented template and, for a device, the scope's
// objects as comments the person may uncomment to override.
func (c *blockCtx) editSeed(block string, cur blockFile) string {
	if cur.exists {
		s := string(cur.text)
		if s != "" && !strings.HasSuffix(s, "\n") {
			s += "\n"
		}
		return s
	}
	s := blocks.TemplateFor(c.vendor, block, c.layer())
	if !c.isDevice() {
		return s
	}
	text, err := policy.LayerTextFor(c.store(), c.inv.app.Conf(), c.vendor, blocks.ScopeLevel(c.scope), block)
	if err != nil || text == nil {
		return s
	}
	doc, fs, err := blocks.LintFor(c.vendor, block, string(text), blocks.LayerScope)
	if err != nil || blocks.HasErrors(fs) || doc.Empty() {
		return s
	}
	return s + "#\n" +
		"# The objects of scope '" + c.scope + "' are below, as comments. A device's object replaces the\n" +
		"# scope's object of the same key whole: to override one, remove the '# ' of its statements\n" +
		"# and change them; one you leave as a comment stays as the scope states it.\n" +
		"#\n" + blocks.CommentOut(doc.String(false))
}

// editFlow runs the editor on seed until the text passes its check or the
// person gives up, then asks, snapshots and writes as set does. event is
// the audit line's word (edit, adopt) and source what the check calls the
// text.
func (c *blockCtx) editFlow(block, seed string, cur blockFile, event, source string, yes bool) error {
	inv := c.inv
	a := inv.app
	name := c.editFileName(block)
	text := seed
	var header []string
	// A block in force that has errors is opened with them listed.
	if cur.exists && seed == string(cur.text) {
		if bc, err := c.examine(block, cur.text, ""); err == nil && bc.errors() > 0 {
			header = findingLines(bc)
		}
	}
	var bc *blockCheck
	for round := 1; ; round++ {
		shown := text
		if len(header) > 0 {
			shown = insertFindings(text, header)
		}
		run, err := c.runEditor(name, []byte(shown))
		switch {
		case err != nil:
			return inv.usageErr(upperFirst(msgsJoin(err))+".", "Nothing was changed.")
		case run.signalled:
			return inv.usageErr("Interrupted while the editor ran. Nothing was written.")
		case run.status != 0:
			a.Out.Info("The editor exited with status " + strconv.Itoa(run.status) + ". Nothing was written.")
			return exit(1)
		}
		text = stripFindings(string(run.text))
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		if strings.TrimSpace(text) == "" {
			return inv.usageErr("The text is empty. To take a block away: " + c.verb() + " remove " + block + ". Nothing was changed.")
		}
		bc, err = c.examine(block, []byte(text), source)
		if err != nil {
			return err
		}
		if bc.errors() == 0 {
			break
		}
		c.printCheck(block, bc, true)
		if round >= blockEditRounds {
			a.Out.ErrorE("Nothing was written.")
			return exit(1)
		}
		ans := a.Prompter().Ask("  Open the editor again to fix them? [Y/n]: ")
		if ans != "" && ans[0] != 'y' && ans[0] != 'Y' {
			a.Out.ErrorE("Nothing was written.")
			return exit(1)
		}
		header = findingLines(bc)
	}
	if bc.doc.Empty() {
		return inv.usageErr("The text states nothing (comments and blank lines only). To take a block away: " + c.verb() + " remove " + block + ". Nothing was changed.")
	}
	if cur.exists && cur.listed && string(cur.text) == text {
		a.Out.Info("The " + event + " changed nothing: the " + block + " block of " + c.what() + " is as it was. Nothing was written.")
		return nil
	}
	// An adopted draft pruned to nothing leaves the block as it was.
	if event == "adopt" && bc.hasCurrent && bc.current != nil && len(bc.added)+len(bc.removed) == 0 {
		a.Out.Info("No statement was adopted: the " + block + " block of " + c.what() + " is as it was. Nothing was written.")
		return nil
	}
	if !c.review(block, bc, yes) {
		return nil
	}
	return c.install(block, []byte(text), bc, cur, event)
}

// msgsJoin is an error's text, with its messages on one line.
func msgsJoin(err error) string { return strings.Join(msgs(err), " ") }
