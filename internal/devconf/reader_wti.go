package devconf

// The WTI reader (0.2.7). A WTI console server has no command that prints
// its configuration: its settings are the items of numbered menu pages,
// which a terminal session walks one declared page after another (the
// tables are package wti's Pages; docs/plans/wti-interface.md sections 1, 3,
// 4 and 8 describe the unit). ReadWTI is that walker. It returns ONE text,
// the captured screens in order, each headed '# page: /N > 28', which
// Extract("wti", ...) and wti.ParseDocument read.
//
// What a read does and never does:
//
//   - It types only what a page's table row lists: the keys of the login
//     ('<CR>' at the banner), '/H', '/SN', '/J', '/N', an item number, '>'
//     on the IP tables list, a listed user's name, SPACE at a pager and ESC.
//     It never types into a page that asks for text, a number or a secret
//     (a screen that is not a table row is never opened on purpose).
//   - It never takes the final ESC. Leaving a top-level menu with ESC makes
//     the unit write its whole configuration to flash, another person's
//     unsaved live edit included, so a read ends on a page of '/N' (or
//     '/F') and CLOSES the connection, which is the tested-safe exit. An
//     ESC is sent only when the page showing is known to be at least two
//     levels deep (a row of the tables, or a page entered by an item
//     number from one).
//   - The unit leaves a top-level menu only by saving, so '/N' and '/F'
//     cannot share one session: the user directory ('/F') is read in a
//     second session, opened by WTIReadOptions.Users, and a read without
//     one has no breakglass facts (UsersRead false).
//   - It never puts screen text in an error, a log line or a result: a
//     page may hold a secret (communities are printed in clear). An
//     unexpected page is reported by its path and its title line only.
//
// The reader sits behind WTITerminal so that devconf imports no transport;
// internal/devssh's TermSession satisfies it.

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/rett/tacctl/internal/devconf/wti"
)

// WTITerminal is the part of a terminal session the reader drives: a pty
// with a shell channel, keys typed and whole screens read (devssh's
// TermSession). Send starts a new screen; Expect returns the text the
// device printed since, as soon as done holds or the device has been quiet.
// Close sends nothing.
type WTITerminal interface {
	Send(ctx context.Context, p []byte) error
	Expect(ctx context.Context, done func(screen string) bool) (string, error)
	Close() error
}

// WTIReadOptions are the knobs of ReadWTI; the zero value reads a unit as
// the tables expect it.
type WTIReadOptions struct {
	// Prompt is the regular expression of the unit's command prompt line
	// (it is configurable on the unit); the default matches 'DSM> '. The
	// prompt is learned once, after the banner, and then compared whole.
	Prompt string
	// PageTimeout bounds one page: the keys, then the wait for its footer
	// (30 seconds when zero). A unit that is silent or keeps painting past
	// it ends the read with the transport's timeout error and the session
	// is closed; the caller's context bounds the whole read.
	PageTimeout time.Duration
	// MaxUsers is the most local users whose details are read (32 when
	// zero). A longer list is not read at all (UsersRead false): the
	// breakglass section would otherwise be a partial list.
	MaxUsers int
	// Users opens a second terminal session for the user directory ('/F').
	// It is called after the first session was closed, and its session is
	// closed by the reader. Nil: the user directory is not read. An error
	// from it, or from the walk of the second session, does not fail the
	// read: UsersRead is false and WTIReadInfo.UsersErr says why.
	Users func(ctx context.Context) (WTITerminal, error)
}

// WTIReadInfo is what a read learned beside the document.
type WTIReadInfo struct {
	// Version is the command menu version of '/H' ("8.10").
	Version string
	// Level is the login's access level from its help (wti.LevelViewOnly,
	// LevelUser, LevelSuperUser or LevelAdministrator).
	Level string
	// OtherSessions is the number of other active network sessions ('/SN'),
	// no name kept.
	OtherSessions int
	// SiteID is the '/J' line's value.
	SiteID string
	// Pages is the number of screens in the document.
	Pages int
	// UsersRead says the user directory is in the document; Users is the
	// number of local users it lists.
	UsersRead bool
	Users     int
	// UsersErr is why the user directory was not read when it was asked for
	// (Users was set): nil otherwise. The text names no screen.
	UsersErr error
}

var (
	// ErrUnsupportedVersion: the unit's command menu is not the version the
	// tables were verified on. The error is a *WTIVersionError.
	ErrUnsupportedVersion = errors.New("devconf: the WTI command menu version is not the one the tables were verified on")
	// ErrDenied: the login's access level cannot configure the unit ('/N'
	// is not among its configuration commands). The error is a
	// *WTIDeniedError.
	ErrDenied = errors.New("devconf: the WTI login's access level cannot read the configuration")
	// ErrUnexpectedScreen: a screen that is none of the ones the walk
	// expects at that point (the banner or the prompt not recognised, a
	// page whose footer never came, an error line). The error is a
	// *WTIPageError.
	ErrUnexpectedScreen = errors.New("devconf: an unexpected WTI screen")
)

// WTIVersionError is the error of a unit at another command menu version.
type WTIVersionError struct {
	// Version is the unit's version number (digits and dots only).
	Version string
}

func (e *WTIVersionError) Error() string {
	return fmt.Sprintf("devconf: the WTI command menu is version %s; the tables are verified for %s", e.Version, wti.Version)
}

// Is makes errors.Is(err, ErrUnsupportedVersion) hold.
func (e *WTIVersionError) Is(target error) bool { return target == ErrUnsupportedVersion }

// WTIDeniedError is the error of a login that cannot configure the unit.
type WTIDeniedError struct {
	// Level is the login's access level word (wti.LevelViewOnly,
	// LevelUser, ...), "" when it could not be told.
	Level string
}

func (e *WTIDeniedError) Error() string {
	if e.Level == "" {
		return "devconf: the WTI login's access level does not list the configuration commands"
	}
	return fmt.Sprintf("devconf: the WTI login's access level (%s) does not list the configuration commands", e.Level)
}

// Is makes errors.Is(err, ErrDenied) hold.
func (e *WTIDeniedError) Is(target error) bool { return target == ErrDenied }

// WTIPageError is the error of a page the walk could not take: its path
// as the document names it and its title line, which is all of the screen
// an error ever holds.
type WTIPageError struct {
	// Path is the page the walk was reading ("/N > 28"); "" at the login.
	Path string
	// Title is the screen's title line as the unit printed it (printable,
	// at most 48 characters), "" when none could be told.
	Title string
	// Err is wti.ErrUnknownPage, wti.ErrLayout or ErrUnexpectedScreen.
	Err error
	// Detail is a fixed phrase of this package, never device text.
	Detail string
}

func (e *WTIPageError) Error() string {
	var b strings.Builder
	b.WriteString("devconf: WTI")
	if e.Path != "" {
		b.WriteString(" page " + e.Path)
	}
	if e.Title != "" {
		fmt.Fprintf(&b, " (title %q)", e.Title)
	}
	b.WriteString(": " + e.Detail)
	return b.String()
}

// Unwrap returns the kind of failure.
func (e *WTIPageError) Unwrap() error { return e.Err }

// The texts of the unit the walk answers or waits for.
const (
	wtiContinue = "Do you wish to continue? (<CR> to continue, /X to exit)"
	wtiPagerKey = "Enter: SPACE for page"
	wtiMoreText = "<ESC> to quit"
	// wtiListPage is the number of IP tables entries one screen shows.
	wtiListPage = 12
	// wtiMaxScreen is the most one screen may hold (a menu is a few KiB).
	wtiMaxScreen = 128 << 10
	// wtiMaxDocument bounds the whole document.
	wtiMaxDocument = 4 << 20
	// wtiMaxHelpPages bounds the pager of '/H'.
	wtiMaxHelpPages = 12
	// wtiMaxClimb bounds the ESCs of one way back to a top-level page.
	wtiMaxClimb = 8
)

var (
	// reWTIPrompt is the default prompt line.
	reWTIPrompt = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,24}> ?$`)
	// reWTIFooter ends a menu page: the last line of its footer.
	reWTIFooter = regexp.MustCompile(`<ESC> to (?:return to previous menu|exit and save configuration|exit)\s*\.{3}\s*$`)
	// reWTIUserName is a name the reader will type at the user list.
	reWTIUserName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,31}$`)

	// wtiNavPages are pages the walk passes through that hold no setting,
	// so the tables have no row for them: they are identified, never kept.
	wtiNavPages = []struct {
		path  string
		title *regexp.Regexp
	}{
		{"/F > 1", regexp.MustCompile(`^USER DIRECTORY:\s*$`)},
	}
)

// ReadWTI reads a WTI unit through a terminal session: the login, the gates
// (command menu version, access level, other sessions), then the pages of
// the tables. The walk order is: the banner ('<CR>'), '/H' (paged with
// SPACE), '/SN' (ended with ESC), '/J', '/N', then each page of the tables
// below '/N' in the table's order ('/N 25', '/N 26', '/N 28', '/N 28 8',
// '/N 29', '/N 29 11' where the unit has it, '/N 5' and '>' three times for
// its four screens), each followed by ESC back to the page it was opened
// from, waiting for that page's footer. A session in Users then reads '/F',
// '/F 1 1' and '/F 1 1 <name>' for each name the list holds.
//
// The session is closed on every return, never with an ESC from a
// top-level page. raw is "" with an error. The errors are
// *WTIVersionError (errors.Is ErrUnsupportedVersion, before any page),
// *WTIDeniedError (ErrDenied), *WTIPageError (ErrUnexpectedScreen,
// wti.ErrUnknownPage, wti.ErrLayout) and the transport's own (the caller
// tells a timeout or a closed session by errors.Is on its package's
// values); none holds screen text.
func ReadWTI(ctx context.Context, term WTITerminal, opts WTIReadOptions) (raw string, info WTIReadInfo, err error) {
	defer func() { _ = term.Close() }()
	w, err := newWTIWalker(term, opts)
	if err != nil {
		return "", info, err
	}
	if err := w.login(ctx); err != nil {
		return "", info, err
	}
	// The gates: nothing is opened before the version and the level are
	// known.
	help, err := w.help(ctx)
	if err != nil {
		return "", info, err
	}
	d, err := wti.ParseDocument(wti.PageHeader + " /H\n" + help)
	if err != nil {
		return "", info, &WTIPageError{Path: "/H", Title: wtiTitle(help), Err: wti.ErrUnknownPage,
			Detail: "the help page is not the one of the tables"}
	}
	info.Version, info.Level = d.Version(), d.Level()
	if v := d.Version(); v != wti.Version {
		return "", info, &WTIVersionError{Version: shortVersion(v)}
	}
	if !d.CanConfigure() {
		return "", info, &WTIDeniedError{Level: d.Level()}
	}
	w.add("/H", help)
	if err := w.status(ctx); err != nil {
		return "", info, err
	}
	if err := w.siteID(ctx); err != nil {
		return "", info, err
	}
	if err := w.walk(ctx, "/N"); err != nil {
		return "", info, err
	}
	_ = term.Close() // on a page of /N: the connection ends, nothing is saved

	var users *wtiWalker
	if opts.Users != nil {
		users, info.UsersErr = w.readUsers(ctx, opts)
		if err := ctx.Err(); err != nil {
			return "", info, err
		}
	}
	text := w.doc.String()
	if users != nil {
		text += users.doc.String()
		w.pages += users.pages
	}
	if len(text) > wtiMaxDocument {
		return "", info, &WTIPageError{Err: ErrUnexpectedScreen, Detail: "the pages together are larger than a unit's configuration"}
	}
	full, err := wti.ParseDocument(text)
	if err != nil {
		return "", info, &WTIPageError{Err: wti.ErrLayout, Detail: "the captured pages do not form a document of the tables"}
	}
	if miss := full.Missing(); len(miss) > 0 {
		return "", info, &WTIPageError{Path: strings.Join(miss, ", "), Err: wti.ErrLayout,
			Detail: "the unit did not show a page the tables need"}
	}
	info.OtherSessions, _ = full.OtherSessions()
	info.SiteID = full.SiteID()
	info.Pages = w.pages
	info.UsersRead = full.UsersRead()
	info.Users = len(full.UserNames())
	return text, info, nil
}

// shortVersion is a version number as an error may carry it.
func shortVersion(v string) string {
	if len(v) > 16 {
		v = v[:16]
	}
	return v
}

// readUsers reads the user directory in a second session. It returns the
// walker that holds its pages, or nil and why not.
func (w *wtiWalker) readUsers(ctx context.Context, opts WTIReadOptions) (*wtiWalker, error) {
	term, err := opts.Users(ctx)
	if err != nil {
		return nil, fmt.Errorf("devconf: the second WTI session for the user directory could not be opened: %w", err)
	}
	defer func() { _ = term.Close() }()
	u, err := newWTIWalker(term, opts)
	if err != nil {
		return nil, err
	}
	if err := u.login(ctx); err != nil {
		return nil, err
	}
	if err := u.userDirectory(ctx); err != nil {
		return nil, err
	}
	return u, nil
}

// wtiWalker is the state of one session's walk.
type wtiWalker struct {
	term   WTITerminal
	opts   WTIReadOptions
	prompt string // the learned prompt line, trailing blanks trimmed
	re     *regexp.Regexp
	doc    strings.Builder
	pages  int
	// paths are the pages entered below the prompt, the last the one
	// showing: depth is len(paths), 0 at the prompt. An ESC is sent only
	// at depth two or more.
	paths []string
	// dead is set when the transport failed or ended: nothing is sent.
	dead bool
}

func newWTIWalker(term WTITerminal, opts WTIReadOptions) (*wtiWalker, error) {
	if opts.PageTimeout <= 0 {
		opts.PageTimeout = 30 * time.Second
	}
	if opts.MaxUsers <= 0 {
		opts.MaxUsers = 32
	}
	re := reWTIPrompt
	if opts.Prompt != "" {
		var err error
		if re, err = regexp.Compile(opts.Prompt); err != nil {
			return nil, fmt.Errorf("devconf: the WTI prompt pattern is not a regular expression: %w", err)
		}
	}
	return &wtiWalker{term: term, opts: opts, re: re}, nil
}

// lastLine is the text after the last newline: the line being written.
func lastLine(s string) string {
	return s[strings.LastIndexByte(s, '\n')+1:]
}

// atFooter reports a menu page painted to its footer.
func atFooter(s string) bool {
	return reWTIFooter.MatchString(strings.TrimRight(s, " \t\r\n"))
}

// atPrompt reports the prompt as the last line painted.
func (w *wtiWalker) atPrompt(s string) bool {
	l := strings.TrimRight(lastLine(s), " ")
	if w.prompt != "" {
		return l == w.prompt
	}
	return w.re.MatchString(lastLine(s))
}

// atPager reports a pager prompt as the last line painted.
func atPager(s string) bool {
	return strings.Contains(lastLine(s), wtiPagerKey)
}

// atMore reports the status list's own pager ('<CR> for more ports, <ESC>
// to quit') as the last line.
func atMore(s string) bool {
	return strings.Contains(strings.TrimRight(s, " \t\r\n"), wtiMoreText) &&
		strings.Contains(lastNonBlank(s), wtiMoreText)
}

func lastNonBlank(s string) string {
	return lastLine(strings.TrimRight(s, " \t\r\n"))
}

// step types send (nothing when nil) and collects the screen until done
// holds. ok is false when the device went quiet, or filled the screen,
// without done holding: the caller looks at the text and aborts. err is the
// transport's (a timeout, a close, too much output); the session is then
// dead and nothing more is sent.
func (w *wtiWalker) step(ctx context.Context, send []byte, done func(string) bool) (screen string, ok bool, err error) {
	if w.dead {
		return "", false, errors.New("devconf: the WTI session is closed")
	}
	sctx, cancel := context.WithTimeout(ctx, w.opts.PageTimeout)
	defer cancel()
	if send != nil {
		if err := w.term.Send(sctx, send); err != nil {
			w.dead = true
			return "", false, err
		}
	}
	prev := -1
	for {
		s, err := w.term.Expect(sctx, done)
		if err != nil {
			w.dead = true
			return "", false, err
		}
		if len(s) > wtiMaxScreen {
			return s[:4096], false, nil
		}
		if done != nil && done(s) {
			return s, true, nil
		}
		// The device went quiet short of what was waited for. A device that
		// is only slow has grown the screen since the last quiet: wait on,
		// within the page's timeout; one that did not is done.
		if len(s) == prev {
			return s, false, nil
		}
		prev = len(s)
	}
}

// wtiTransport wraps a transport error with the page it happened on; the transport's
// own text (device and failure, never a screen) is kept.
func wtiTransport(path string, err error) error {
	if path == "" {
		return fmt.Errorf("devconf: reading a WTI unit: %w", err)
	}
	return fmt.Errorf("devconf: reading WTI page %s: %w", path, err)
}

// login answers the banner and learns the prompt.
func (w *wtiWalker) login(ctx context.Context) error {
	s, _, err := w.step(ctx, nil, func(s string) bool {
		return strings.Contains(s, wtiContinue) || w.re.MatchString(lastLine(s))
	})
	if err != nil {
		return wtiTransport("", err)
	}
	if strings.Contains(s, wtiContinue) {
		s, _, err = w.step(ctx, []byte("\r"), func(s string) bool { return w.re.MatchString(lastLine(s)) })
		if err != nil {
			return wtiTransport("", err)
		}
	}
	if !w.re.MatchString(lastLine(s)) {
		return &WTIPageError{Err: ErrUnexpectedScreen,
			Detail: "the login did not end at a command prompt (the banner question or the prompt was not recognised)"}
	}
	w.prompt = strings.TrimRight(lastLine(s), " ")
	return nil
}

// help types '/H' and pages it with SPACE to the prompt; the text is the
// whole listing without its pager prompts and the prompt.
func (w *wtiWalker) help(ctx context.Context) (string, error) {
	var chunks []string
	key := []byte("/H\r")
	for i := 0; ; i++ {
		s, ok, err := w.step(ctx, key, func(s string) bool { return w.atPrompt(s) || atPager(s) })
		if err != nil {
			return "", wtiTransport("/H", err)
		}
		if !ok {
			return "", &WTIPageError{Path: "/H", Title: wtiTitle(s), Err: ErrUnexpectedScreen,
				Detail: "the help listing ended at neither a pager prompt nor the command prompt"}
		}
		chunks = append(chunks, dropLastLine(s))
		if w.atPrompt(s) {
			return strings.Join(chunks, "\n"), nil
		}
		if i >= wtiMaxHelpPages {
			return "", &WTIPageError{Path: "/H", Err: ErrUnexpectedScreen, Detail: "the help listing does not end"}
		}
		key = []byte(" ")
	}
}

// dropLastLine removes the line being written (a pager or command prompt).
func dropLastLine(s string) string {
	return strings.TrimRight(s[:strings.LastIndexByte(s, '\n')+1], "\n")
}

// status reads '/SN' and leaves its listing with ESC (it is a pager, not a
// menu: nothing is saved).
func (w *wtiWalker) status(ctx context.Context) error {
	s, ok, err := w.step(ctx, []byte("/SN\r"), func(s string) bool { return w.atPrompt(s) || atMore(s) })
	if err != nil {
		return wtiTransport("/SN", err)
	}
	if !ok {
		return &WTIPageError{Path: "/SN", Title: wtiTitle(s), Err: ErrUnexpectedScreen,
			Detail: "the network status did not end at its pager or the command prompt"}
	}
	if _, err := wti.ParseScreen("/SN", s); err != nil {
		return pageError("/SN", s, err)
	}
	// The count of other sessions is all that is kept of the list: the
	// user names of the sessions are blanked before the page is stored.
	w.add("/SN", redactSessions(dropPrompt(s, w)))
	if atMore(s) {
		out, ok, err := w.step(ctx, []byte{0x1b}, w.atPrompt)
		if err != nil {
			return wtiTransport("/SN", err)
		}
		if !ok {
			return &WTIPageError{Path: "/SN", Title: wtiTitle(out), Err: ErrUnexpectedScreen,
				Detail: "the network status did not end at the command prompt after ESC"}
		}
	}
	return nil
}

// siteID reads '/J'.
func (w *wtiWalker) siteID(ctx context.Context) error {
	s, ok, err := w.step(ctx, []byte("/J\r"), w.atPrompt)
	if err != nil {
		return wtiTransport("/J", err)
	}
	if !ok {
		return &WTIPageError{Path: "/J", Title: wtiTitle(s), Err: ErrUnexpectedScreen,
			Detail: "the site ID did not end at the command prompt"}
	}
	if _, err := wti.ParseScreen("/J", s); err != nil {
		return pageError("/J", s, err)
	}
	w.add("/J", dropPrompt(s, w))
	return nil
}

// reSessionRow is a row of the status table: 'N1  |      22|Active|user |'.
var reSessionRow = regexp.MustCompile(`^\s*N\d{1,2}\s*\|`)

// redactSessions blanks the USERNAME cell of every session row of a
// status screen: the cells are the table's four-column groups
// (port, TCP port, status, user name), two groups to a row.
func redactSessions(screen string) string {
	lines := strings.Split(screen, "\n")
	for i, l := range lines {
		if !reSessionRow.MatchString(l) {
			continue
		}
		cells := strings.Split(l, "|")
		for j := 3; j < len(cells); j += 4 {
			cells[j] = strings.Repeat(" ", len(cells[j]))
		}
		lines[i] = strings.Join(cells, "|")
	}
	return strings.Join(lines, "\n")
}

// dropPrompt is the screen without the prompt that ends it.
func dropPrompt(s string, w *wtiWalker) string {
	if w.atPrompt(s) {
		return dropLastLine(s)
	}
	return s
}

// pageError turns the table parser's error into the walk's: the page, the
// title line and the kind of failure, no screen text.
func pageError(path, screen string, err error) error {
	pe := &WTIPageError{Path: path, Title: wtiTitle(screen), Err: ErrUnexpectedScreen}
	switch {
	case errors.Is(err, wti.ErrUnknownPage):
		pe.Err, pe.Detail = wti.ErrUnknownPage, "the page is not one the tables know"
	case errors.Is(err, wti.ErrLayout):
		pe.Err, pe.Detail = wti.ErrLayout, "the page is laid out otherwise than the tables say"
	case errors.Is(err, wti.ErrPath):
		pe.Err, pe.Detail = wti.ErrUnknownPage, "the page is not the one that was asked for"
	default:
		pe.Detail = "the page could not be read"
	}
	return pe
}

// --- the walk ------------------------------------------------------------------

// top is the page showing ("" at the prompt).
func (w *wtiWalker) top() string {
	if len(w.paths) == 0 {
		return ""
	}
	return w.paths[len(w.paths)-1]
}

// keyOf is the key that opens a page from its parent: the last segment of
// its path.
func keyOf(path string) string {
	i := strings.LastIndex(path, ">")
	return strings.TrimSpace(path[i+1:])
}

// parentOf is the path of the page a path is opened from.
func parentOf(path string) string {
	i := strings.LastIndex(path, ">")
	if i < 0 {
		return ""
	}
	return strings.TrimSpace(path[:i])
}

// walk opens a top-level menu from the prompt and then every page of the
// tables below it, in the table's order, going back one level with ESC to
// the page each was opened from. It ends on the top-level page.
func (w *wtiWalker) walk(ctx context.Context, root string) error {
	if _, err := w.open(ctx, root+"\r", root, false); err != nil {
		return err
	}
	for i := range wti.Pages {
		row := &wti.Pages[i]
		if !strings.HasPrefix(row.Path, root+" > ") || strings.Contains(row.Path, "<") {
			continue
		}
		if row.Kind != wti.KindMenu && row.Kind != wti.KindList {
			continue
		}
		parent := parentOf(row.Path)
		if !w.has(parent) {
			continue // the parent page was not there (an optional one)
		}
		for w.top() != parent {
			if err := w.back(ctx); err != nil {
				return err
			}
		}
		skipped, err := w.open(ctx, keyOf(row.Path)+"\r", row.Path, !row.Required)
		if err != nil {
			return err
		}
		if skipped {
			continue
		}
		if row.Kind == wti.KindList {
			if err := w.paging(ctx, row.Path); err != nil {
				return err
			}
		}
	}
	for len(w.paths) > 1 {
		if err := w.back(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (w *wtiWalker) has(path string) bool {
	for _, p := range w.paths {
		if p == path {
			return true
		}
	}
	return false
}

// paging types '>' for the rest of a list's screens, each captured under
// the list's path.
func (w *wtiWalker) paging(ctx context.Context, path string) error {
	for i := 1; i < wti.IPTablesSlots/wtiListPage; i++ {
		s, ok, err := w.step(ctx, []byte(">\r"), atFooter)
		if err != nil {
			return wtiTransport(path, err)
		}
		if !ok || hasErrorLine(s) {
			return w.abort(ctx, path, s, len(w.paths), "the next screen of the list did not come to its footer")
		}
		if _, err := wti.ParseScreen(path, s); err != nil {
			return w.abortWith(ctx, path, s, len(w.paths), pageError(path, s, err))
		}
		w.add(path, s)
	}
	return nil
}

// open types key at the page showing and reads the page it opens, which
// must be the row path's. skipped is true for an optional page the unit
// refused (it repainted the page showing with an error line).
func (w *wtiWalker) open(ctx context.Context, key, path string, optional bool) (skipped bool, err error) {
	assume := len(w.paths) + 1 // the key opened a page one level below
	s, ok, err := w.step(ctx, []byte(key), atFooter)
	if err != nil {
		return false, wtiTransport(path, err)
	}
	switch {
	case hasErrorLine(s):
		if p, known := identify(s); optional && known && p == w.top() {
			return true, nil
		}
		return false, w.abort(ctx, path, s, assume, "the unit printed an error line")
	case !ok:
		return false, w.abort(ctx, path, s, assume, "the page did not come to its footer")
	}
	if _, err := wti.ParseScreen(path, s); err != nil {
		return false, w.abortWith(ctx, path, s, assume, pageError(path, s, err))
	}
	w.paths = append(w.paths, path)
	w.add(path, s)
	return false, nil
}

// back types ESC at the page showing, which is at least two deep, and
// checks that the parent's page is what comes.
func (w *wtiWalker) back(ctx context.Context) error {
	if len(w.paths) < 2 {
		// A top-level page is never left with ESC: that saves.
		return &WTIPageError{Path: w.top(), Err: ErrUnexpectedScreen, Detail: "internal: ESC at a top-level page refused"}
	}
	from, parent := w.top(), w.paths[len(w.paths)-2]
	s, ok, err := w.step(ctx, []byte{0x1b}, atFooter)
	if err != nil {
		return wtiTransport(from, err)
	}
	if p, known := identify(s); !ok || !known || p != parent {
		return w.abort(ctx, from, s, 0, "ESC did not return to the page it was opened from")
	}
	w.paths = w.paths[:len(w.paths)-1]
	return nil
}

// abort leaves the unit where it can be closed safely and returns the
// error. assume is the depth the screen is taken to be at when its title
// is none the tables know (0: not known, no ESC).
func (w *wtiWalker) abort(ctx context.Context, path, screen string, assume int, detail string) error {
	err := &WTIPageError{Path: path, Title: wtiTitle(screen), Err: ErrUnexpectedScreen, Detail: detail}
	w.climb(ctx, screen, assume)
	return err
}

// abortWith is abort with the error already made.
func (w *wtiWalker) abortWith(ctx context.Context, path, screen string, assume int, err error) error {
	w.climb(ctx, screen, assume)
	return err
}

// climb sends ESC while the page showing is known to be two or more
// levels deep, at most wtiMaxClimb times, and stops at the first screen
// that is not a page of a smaller depth. It never sends from a top-level
// page or from a screen it cannot place.
func (w *wtiWalker) climb(ctx context.Context, screen string, assume int) {
	depth := assume
	if p, ok := identify(screen); ok {
		depth = pathDepth(p)
	}
	for i := 0; i < wtiMaxClimb && depth >= 2 && !w.dead; i++ {
		s, ok, err := w.step(ctx, []byte{0x1b}, atFooter)
		if err != nil || !ok {
			return
		}
		p, known := identify(s)
		if !known || pathDepth(p) >= depth {
			return
		}
		depth = pathDepth(p)
	}
}

// pathDepth is the number of keys of a page's path ('/N > 28 > 8' is 3).
func pathDepth(path string) int { return strings.Count(path, ">") + 1 }

// identify returns the path of the table row (or navigation page) a
// screen's title belongs to. The first title line wins: an ERROR line
// above a repainted page does not hide it.
func identify(screen string) (path string, ok bool) {
	for _, l := range strings.Split(wti.Clean(screen), "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		for i := range wti.Pages {
			row := &wti.Pages[i]
			switch row.Kind {
			case wti.KindHelp, wti.KindStatus, wti.KindLine:
				continue
			}
			if row.Title.MatchString(l) {
				return row.Path, true
			}
		}
		for _, n := range wtiNavPages {
			if n.title.MatchString(l) {
				return n.path, true
			}
		}
	}
	return "", false
}

// hasErrorLine reports an 'ERROR:' line (the unit refused the entry).
func hasErrorLine(screen string) bool {
	for _, l := range strings.Split(wti.Clean(screen), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "ERROR:") {
			return true
		}
	}
	return false
}

// wtiTitle is the title line of a screen as an error may name it: the
// first line that is not blank, an echo of the keys typed or an error
// line, printable and at most 48 characters.
func wtiTitle(screen string) string {
	echoes := 0
	for _, l := range strings.Split(wti.Clean(screen), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case l == "", strings.HasPrefix(l, "ERROR:"):
			continue
		case echoes < 2 && len(l) <= 64 && !strings.ContainsAny(l, " \t") && !strings.HasSuffix(l, ":"):
			echoes++
			continue
		}
		var b strings.Builder
		n := 0
		for _, r := range l {
			if n == 48 {
				b.WriteString("...")
				break
			}
			if !unicode.IsPrint(r) {
				r = '?'
			}
			b.WriteRune(r)
			n++
		}
		return b.String()
	}
	return ""
}

// add appends a screen to the document under its header. A line of the
// device that would start a header is prefixed so that it cannot.
func (w *wtiWalker) add(path, screen string) {
	if w.doc.Len() > wtiMaxDocument {
		return
	}
	w.doc.WriteString(wti.PageHeader + " " + path + "\n")
	lines := strings.Split(wti.Clean(screen), "\n")
	for _, l := range lines {
		if strings.HasPrefix(l, wti.PageHeader) {
			l = "> " + l
		}
		w.doc.WriteString(l + "\n")
	}
	w.pages++
}

// --- the user directory ----------------------------------------------------------

// userDirectory is the walk of '/F': its top page, the user directory's
// list and one details page per name.
func (w *wtiWalker) userDirectory(ctx context.Context) error {
	if _, err := w.open(ctx, "/F\r", "/F", false); err != nil {
		return err
	}
	// The directory menu is a navigation page of no setting.
	assume := len(w.paths) + 1
	s, ok, err := w.step(ctx, []byte("1\r"), atFooter)
	if err != nil {
		return wtiTransport("/F > 1", err)
	}
	if p, known := identify(s); !ok || hasErrorLine(s) || !known || p != "/F > 1" {
		return w.abort(ctx, "/F > 1", s, assume, "the user directory menu did not come")
	}
	w.paths = append(w.paths, "/F > 1")

	const list = "/F > 1 > 1"
	assume = len(w.paths) + 1
	s, ok, err = w.step(ctx, []byte("1\r"), atFooter)
	if err != nil {
		return wtiTransport(list, err)
	}
	if !ok || hasErrorLine(s) {
		return w.abort(ctx, list, s, assume, "the user list did not come to its footer")
	}
	p, err := wti.ParseScreen(list, s)
	if err != nil {
		return w.abortWith(ctx, list, s, assume, pageError(list, s, err))
	}
	w.paths = append(w.paths, list)
	listText, names := s, p.Names
	read := len(names) <= w.opts.MaxUsers
	for _, n := range names {
		if !reWTIUserName.MatchString(n) {
			read = false
		}
	}
	var details []struct{ path, text string }
	if read {
		for _, name := range names {
			path := list + " > " + name
			assume := len(w.paths) + 1
			s, ok, err := w.step(ctx, []byte(name+"\r"), atFooter)
			if err != nil {
				return wtiTransport(path, err)
			}
			if !ok || hasErrorLine(s) {
				return w.abort(ctx, path, s, assume, "the user's details did not come to their footer")
			}
			if _, err := wti.ParseScreen(path, s); err != nil {
				return w.abortWith(ctx, path, s, assume, pageError(path, s, err))
			}
			w.paths = append(w.paths, path)
			details = append(details, struct{ path, text string }{path, s})
			if err := w.back(ctx); err != nil {
				return err
			}
		}
	}
	for len(w.paths) > 1 {
		if err := w.back(ctx); err != nil {
			return err
		}
	}
	if read {
		w.add(list, listText)
		for _, d := range details {
			w.add(d.path, d.text)
		}
	}
	return nil
}
