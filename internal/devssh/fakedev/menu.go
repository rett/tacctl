package fakedev

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Menu mode: a fake menu-driven unit (a WTI console server; the screens
// are the sanitised captures of tests/fixtures/devconf/wti and
// docs/plans/wti-interface.md describes the unit). A transcript directory
// that holds a file named 'menu' is a menu device: its shell sessions are
// served by menusession.go instead of the line-per-command shell, and the
// other transcript files keep their meaning ('prompt' is the prompt, by
// default 'DSM> '; 'login' the credentials). Exec requests and NETCONF
// are answered as for any transcript.
//
// The 'menu' file is the manifest: one 'key value' per line, blank lines
// and lines that start with '#' ignored, an unknown key an error (a typo
// must not give a different device than the one the test names).
//
//	screens <dir>      the directory of the captures (01-login-banner.txt,
//	                   02-port-list.txt, 03-help-<level>.txt, 04-..., 16-...,
//	                   32-..., 33-..., 30-iptables-uploaded-page*.txt and
//	                   pages/), relative to the manifest's directory; default
//	                   '../..' (tests/fixtures/devconf/wti from
//	                   tests/fixtures/devconf/wti/fake/<name>)
//	version <n.n>      the command menu version /H prints; default 8.10. The
//	                   captured screens are 8.10's; another version changes
//	                   only the number in the help screen.
//	level <level>      the login's access level: viewonly, user, superuser
//	                   or administrator (default administrator). /H prints
//	                   the capture of that level (03-help-<level>.txt), and
//	                   a command that screen does not list is refused.
//	sessions <n>       how many OTHER active sessions /SN shows (0-31,
//	                   default 0); the login's own is always shown, after
//	                   them, as the capture of /SN does.
//	session-users <names...>
//	                   the user names of those sessions in order (default
//	                   user1, user2, ...); a session may hold the login's own
//	                   name.
//	iptables <what>    the IP tables list at /N > 5: 'empty' (the default),
//	                   'filled' (the 25 entries of the capture
//	                   30-iptables-uploaded-page*.txt) or 'file <path>' (one
//	                   command per line, at most 48; a path relative to the
//	                   manifest's directory). The list is shown 12 entries
//	                   to a screen, '>' and '<' page, and /N shows
//	                   'IP Tables: On' when it is not empty.
//	page <path> = <file>
//	                   the screen of one page (path as the unit's headers
//	                   write it: '/N > 28 > 6'), for what the captures do
//	                   not hold or a unit that differs; the file is a
//	                   capture (its '# ---' header is dropped), relative to
//	                   the manifest's directory, else to the screens
//	                   directory. A page that has no file is an unknown
//	                   entry ('ERROR: Invalid entry.').
//
// A page's own screen is found by the '# path:' line in the header of the
// captures under <screens>/pages; the pages of the user directory (/F > 1
// > 1, and one per name it lists) are the captures 32 and 33.
//
// The unit is read-only on purpose. A value typed at a prompt page is
// never taken: the fake answers 'ERROR: Invalid entry.' and repaints, and
// logs an 'entry' event, so that a test can assert that a reader typed
// nothing. Keys, lines and what happened are logged as Commands and
// Events (menusession.go).

// The access levels, in the order of the unit's.
var menuLevels = []string{"viewonly", "user", "superuser", "administrator"}

// maxIPTablesEntries is the size of the unit's list.
const maxIPTablesEntries = 48

// ipPageSize is how many entries one IP tables screen shows.
const ipPageSize = 12

// The captured screens at the top of the screens directory.
const (
	screenBanner   = "01-login-banner.txt"
	screenPorts    = "02-port-list.txt"
	screenStatus   = "04-network-status.txt"
	screenSiteID   = "16-site-id.txt"
	screenUserList = "32-user-directory-view.txt"
	screenUserOne  = "33-user-directory-details.txt"
)

// The IP tables captures: the filled list is the entries of these.
var screenIPTables = []string{
	"30-iptables-uploaded-page.txt",
	"30-iptables-uploaded-page-2.txt",
	"30-iptables-uploaded-page-3.txt",
}

// menuConfig is a menu device: the manifest and the screens it names.
type menuConfig struct {
	version  string
	level    string
	sessions int
	users    []string
	iptables []string          // the list's entries; nil is empty
	filled   bool              // the list is the captured one (read with the screens)
	pages    map[string]string // page key ('/N > 28') to the capture's file
	screens  string            // the captures' directory
	prompt   string
	allowed  map[string]bool // the commands the level's help lists
}

// pageKey is the key of a page path.
func pageKey(path []string) string { return strings.Join(path, " > ") }

// pathKey normalises a path as a header or the manifest writes it
// ('/N>28 > 8') to the key.
func pathKey(s string) string {
	parts := strings.Split(s, ">")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return strings.Join(parts, " > ")
}

var (
	reVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+$`)
	// rePromptLine is what the unit's prompt looks like: a line to drop
	// from a capture, whose own prompt the fixture may have changed.
	rePromptLine = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,24}> ?$`)
	reHelpWord   = regexp.MustCompile(`^(/[A-Z]+)\b`)
	reIPEntry    = regexp.MustCompile(`^([0-9]+)\.\s+(iptables\s.*)$`)
	reIPSlot     = regexp.MustCompile(`^[0-9]+\.\s*$`)
)

// captureParts splits a capture into its header fields and its body.
func captureParts(s string) (map[string]string, string) {
	hdr := map[string]string{}
	body := stripCaptureHeader(s)
	if body == s {
		return hdr, body
	}
	for _, line := range strings.Split(strings.TrimSuffix(s[:len(s)-len(body)], "\n"), "\n") {
		if k, v, ok := strings.Cut(strings.TrimPrefix(line, "# "), ":"); ok && strings.HasPrefix(line, "# ") {
			hdr[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return hdr, body
}

// readCapture is the body of a capture file.
func readCapture(file string) (string, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	_, body := captureParts(string(b))
	return body, nil
}

// splitEcho separates the line the unit echoed (what the capture's
// person typed: '/H', '28', a user name) from the screen that follows. A
// capture of a screen with no echo (the port list, a page left with ESC)
// has none.
func splitEcho(body string) (echo, rest string) {
	first, after, found := strings.Cut(body, "\n")
	if !found {
		return "", body
	}
	next, _, _ := strings.Cut(after, "\n")
	echoed := strings.HasPrefix(first, "/") ||
		(next == "" && first != "" && len(first) <= 24 && !strings.ContainsAny(first, " \t:"))
	if !echoed {
		return "", body
	}
	return first, after
}

// loadMenu reads the manifest of the transcript and the index of the
// screens. override, when not empty, is the screens directory (and wins
// over the manifest's).
func loadMenu(t transcript, override string) (*menuConfig, error) {
	text, ok := t.read("menu")
	if !ok {
		return nil, fmt.Errorf("no menu manifest in %s", t.dir)
	}
	c := &menuConfig{
		version: "8.10", level: "administrator", pages: map[string]string{},
		screens: filepath.Join(t.dir, "..", ".."), prompt: t.promptOr("DSM> "),
	}
	overrides := map[string]string{} // page key to manifest-relative file
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, _ := strings.Cut(line, " ")
		val = strings.TrimSpace(val)
		bad := func(msg string) error { return fmt.Errorf("menu line %d (%s): %s", n+1, key, msg) }
		switch key {
		case "screens":
			if val == "" {
				return nil, bad("a directory is needed")
			}
			c.screens = relTo(t.dir, val)
		case "version":
			if !reVersion.MatchString(val) {
				return nil, bad("a version like 8.10 is needed")
			}
			c.version = val
		case "level":
			if !contains(menuLevels, val) {
				return nil, bad("one of " + strings.Join(menuLevels, ", ") + " is needed")
			}
			c.level = val
		case "sessions":
			v, err := strconv.Atoi(val)
			if err != nil || v < 0 || v > 31 {
				return nil, bad("0 to 31 is needed")
			}
			c.sessions = v
		case "session-users":
			c.users = strings.Fields(val)
		case "iptables":
			if err := c.setIPTables(t, val); err != nil {
				return nil, bad(err.Error())
			}
		case "page":
			p, f, ok := strings.Cut(val, "=")
			if !ok || strings.TrimSpace(p) == "" || strings.TrimSpace(f) == "" {
				return nil, bad("'<path> = <file>' is needed")
			}
			overrides[pathKey(p)] = strings.TrimSpace(f)
		default:
			return nil, fmt.Errorf("menu line %d: unknown key %q", n+1, key)
		}
	}
	if override != "" {
		c.screens = override
	}
	if len(c.users) > c.sessions {
		return nil, fmt.Errorf("menu: %d session-users for %d sessions", len(c.users), c.sessions)
	}
	if err := c.index(t.dir, overrides); err != nil {
		return nil, err
	}
	return c, c.loadHelpWords()
}

func relTo(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// promptOr is the prompt of a shell session, def when the transcript has
// none.
func (t transcript) promptOr(def string) string {
	if p, ok := t.read("prompt"); ok {
		return strings.TrimSuffix(p, "\n")
	}
	return def
}

// setIPTables sets the list: 'empty', 'filled' or 'file <path>'.
func (c *menuConfig) setIPTables(t transcript, val string) error {
	what, arg, _ := strings.Cut(val, " ")
	switch what {
	case "empty":
		c.iptables = nil
	case "filled":
		c.filled = true
	case "file":
		b, err := os.ReadFile(relTo(t.dir, strings.TrimSpace(arg)))
		if err != nil {
			return err
		}
		var list []string
		for _, l := range strings.Split(string(b), "\n") {
			if l = strings.TrimSpace(l); l != "" {
				list = append(list, l)
			}
		}
		if len(list) > maxIPTablesEntries {
			return fmt.Errorf("%d entries; the unit holds %d", len(list), maxIPTablesEntries)
		}
		c.iptables = list
	default:
		return fmt.Errorf("'empty', 'filled' or 'file <path>' is needed")
	}
	return nil
}

// index maps the page keys to files: the captures' '# path:' headers,
// the user directory, the manifest's own pages.
func (c *menuConfig) index(dir string, overrides map[string]string) error {
	files, err := filepath.Glob(filepath.Join(c.screens, "pages", "*.txt"))
	if err != nil {
		return err
	}
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		hdr, _ := captureParts(string(b))
		if p := hdr["path"]; p != "" {
			c.pages[pathKey(p)] = f
		}
	}
	// The user directory: the view and a details page per user it lists.
	if _, ok := c.pages["/F > 1"]; ok {
		c.pages["/F > 1 > 1"] = filepath.Join(c.screens, screenUserList)
	}
	for k, f := range overrides {
		p := relTo(dir, f)
		if _, err := os.Stat(p); err != nil {
			p = relTo(c.screens, f)
		}
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("menu: page %s: %v", k, err)
		}
		c.pages[k] = p
	}
	if view, ok := c.pages["/F > 1 > 1"]; ok {
		body, err := readCapture(view)
		if err != nil {
			return fmt.Errorf("menu: user directory: %w", err)
		}
		for _, name := range userNames(body) {
			k := "/F > 1 > 1 > " + name
			if _, set := c.pages[k]; !set {
				c.pages[k] = filepath.Join(c.screens, screenUserOne)
			}
		}
	}
	if c.filled {
		list, err := c.capturedIPTables()
		if err != nil {
			return err
		}
		c.iptables = list
	}
	return nil
}

// userNames are the names the user directory view lists: the lines
// between its title and its footer.
func userNames(body string) []string {
	var names []string
	in := false
	for _, l := range strings.Split(body, "\n") {
		l = strings.TrimRight(l, " \r")
		switch {
		case strings.HasPrefix(l, "VIEW USER DIRECTORY"):
			in = true
		case strings.HasPrefix(l, "Enter"):
			return names
		case in && l != "" && !strings.ContainsAny(l, " \t"):
			names = append(names, l)
		}
	}
	return names
}

// capturedIPTables is the list of the 30-iptables-uploaded-page captures.
func (c *menuConfig) capturedIPTables() ([]string, error) {
	var list []string
	for _, f := range screenIPTables {
		body, err := readCapture(filepath.Join(c.screens, f))
		if err != nil {
			return nil, fmt.Errorf("menu: the filled IP tables list: %w", err)
		}
		for _, l := range strings.Split(body, "\n") {
			m := reIPEntry.FindStringSubmatch(strings.TrimRight(l, " \r"))
			if m == nil {
				continue
			}
			if n, _ := strconv.Atoi(m[1]); n != len(list)+1 {
				return nil, fmt.Errorf("menu: %s: entry %d is out of order", f, n)
			}
			list = append(list, m[2])
		}
	}
	return list, nil
}

// loadHelpWords reads the level's help screen: the commands it lists are
// the commands the login has.
func (c *menuConfig) loadHelpWords() error {
	body, err := readCapture(filepath.Join(c.screens, "03-help-"+c.level+".txt"))
	if err != nil {
		return fmt.Errorf("menu: help of level %s: %w", c.level, err)
	}
	c.allowed = map[string]bool{}
	for _, l := range strings.Split(body, "\n") {
		if m := reHelpWord.FindStringSubmatch(l); m != nil {
			c.allowed[m[1]] = true
		}
	}
	return nil
}

// page is the body of the page at key, and whether there is one.
func (c *menuConfig) page(key string) (string, bool) {
	f, ok := c.pages[key]
	if !ok {
		return "", false
	}
	body, err := readCapture(f)
	if err != nil {
		return "", false
	}
	return body, true
}

// hasChildren reports whether some page lies under key (a menu, not a
// prompt).
func (c *menuConfig) hasChildren(key string) bool {
	for k := range c.pages {
		if strings.HasPrefix(k, key+" > ") {
			return true
		}
	}
	return false
}

// ipTablesScreen is the page of the list at /N > 5 that shows entries
// 12*n+1 to 12*n+12, built on the capture of the empty list (network-5)
// so the wording is the unit's.
func (c *menuConfig) ipTablesScreen(n int) (string, bool) {
	body, ok := c.page("/N > 5")
	if !ok {
		return "", false
	}
	_, rest := splitEcho(body)
	lines := strings.Split(rest, "\n")
	out := make([]string, 0, len(lines))
	slot := 0
	for _, l := range lines {
		if reIPSlot.MatchString(strings.TrimRight(l, " ")) {
			num := n*ipPageSize + slot + 1
			slot++
			entry := ""
			if num <= len(c.iptables) {
				entry = c.iptables[num-1]
			}
			if entry == "" {
				l = fmt.Sprintf("%d.", num)
			} else {
				l = fmt.Sprintf("%-4s%s", fmt.Sprintf("%d.", num), entry)
			}
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n"), true
}

// ipPages is how many screens the list has: 48 entries, 12 to a screen.
func ipPages() int { return maxIPTablesEntries / ipPageSize }
