package fakedev

import (
	"bufio"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// A menu device's shell session (menu.go has the manifest).
//
// What the unit does, as the captures show it and as this fake follows:
//
//   - the banner and 'Do you wish to continue? (<CR> to continue, /X to
//     exit)'; CR gives the port list and the prompt; anything else asks
//     again; '/X' ends the session.
//   - at the prompt a line is a command: '/H' (help, paged by SPACE; ENTER
//     for a line; 'q' or ESC ends the listing), '/SN' (network status, ends
//     at '<CR> for more ports, <ESC> to quit': ESC or CR returns to the
//     prompt), '/J' (site id), '/X' (end), and '/N' '/F' '/P' '/AC' (the
//     top-level menus). Only the commands the login's help screen lists
//     are accepted; the unit's refusal of the others is not in the
//     captures, so the fake prints 'Invalid command' (also for a listed
//     command it does not model, and for a line that is no command).
//   - at a menu page a number opens that item's page; ESC goes up one
//     level, and at the top-level menu it writes the configuration:
//     'Saving configuration to flash - Please wait...' and the prompt. '<'
//     and '>' page the IP tables list as single keys. A page that is
//     unknown, a value typed at a prompt page, a letter at a menu: 'ERROR:
//     Invalid entry.' and the page again. CR alone repaints the page, and
//     at a user's details page goes up.
//   - closing the connection ends the session wherever it is.
//
// What is logged, in the order it happened, readable through Commands
// (the keys and lines typed, one entry each: the text of a line, '<CR>'
// for an empty one, '<ESC>', '<SPACE>', '<' and '>', 'q') and through
// Events:
//
//	save <page>           'Saving configuration' was printed (an ESC at
//	                      the top of <page>, '/N' '/F' '/P' or '/AC')
//	close <where>         the client ended the connection at 'banner',
//	                      'prompt', '/H', '/SN' or a page ('/N > 28 > 8')
//	exit                  '/X'
//	refused <command>     a command the login's help does not list
//	unmodelled <command>  a listed command the fake does not model
//	entry <page>          a value was typed at a prompt page (refused)
//	no-page <page>[ > n]  a number was typed at a menu that has no page
//	                      for it (the text, when it is no number, is not
//	                      logged)
//	invalid               a line at the prompt that is no command
//
// A page's name in an event is its path as the unit's headers write it.

const (
	pagerText  = "Enter: SPACE for page, ENTER for line"
	invalidMsg = "ERROR: Invalid entry."
	savingMsg  = "Saving configuration to flash - Please wait..."
	refusedMsg = "Invalid command"
)

var (
	reDigits      = regexp.MustCompile(`^[0-9]{1,6}$`)
	reHelpVersion = regexp.MustCompile(`Version [0-9]+(\.[0-9]+)*`)
)

type keyKind int

const (
	keyLine      keyKind = iota // a line, CR or LF ended
	keyEsc                      // ESC
	keyImmediate                // '<' or '>' as the first key of a line
	keyEOF                      // the client ended the channel
)

type menuSession struct {
	s      *Server
	c      *menuConfig
	ch     io.ReadWriter
	in     *bufio.Reader
	echo   bool
	lastCR bool
	loc    string
	path   []string
	ip     int // the IP tables screen shown, 0-based
	user   string
}

// menu is a menu device's shell session.
func (s *Server) menu(ch ssh.Channel) {
	cfg, err := loadMenu(s.t, s.menuScreens)
	if err != nil {
		_, _ = io.WriteString(ch, "fakedev: "+err.Error()+"\r\n")
		return
	}
	user, _ := s.credentials()
	m := &menuSession{s: s, c: cfg, ch: ch, in: bufio.NewReader(ch), echo: s.echo, user: user}
	m.run()
}

// raw writes s as it is.
func (m *menuSession) raw(s string) { _, _ = io.WriteString(m.ch, s) }

// w writes s with its lines ended CRLF.
func (m *menuSession) w(s string) { m.raw(crlf(s)) }

func (m *menuSession) event(format string, a ...any) {
	m.s.logEvent(fmt.Sprintf(format, a...))
}

// closed records that the client went away.
func (m *menuSession) closed() { m.event("close %s", m.loc) }

// readByte reads a key; the LF of a CRLF is not a second key.
func (m *menuSession) readByte() (byte, bool) {
	for {
		b, err := m.in.ReadByte()
		if err != nil {
			return 0, false
		}
		if b == '\n' && m.lastCR {
			m.lastCR = false
			continue
		}
		m.lastCR = b == '\r'
		return b, true
	}
}

// readLine reads one line of input, echoing it as the unit does. ESC
// ends it at once and discards what was typed; with immediate, '<' and
// '>' as the first key act at once.
func (m *menuSession) readLine(immediate bool) (keyKind, string) {
	var buf []byte
	for {
		b, ok := m.readByte()
		if !ok {
			return keyEOF, ""
		}
		switch {
		case b == 0x1b:
			m.s.log("<ESC>")
			return keyEsc, ""
		case b == '\r' || b == '\n':
			if m.echo {
				m.raw("\r\n")
			}
			line := string(buf)
			if line == "" {
				m.s.log("<CR>")
			} else {
				m.s.log(line)
			}
			return keyLine, line
		case b == 0x7f || b == 0x08:
			if len(buf) > 0 {
				buf = buf[:len(buf)-1]
				if m.echo {
					m.raw("\b \b")
				}
			}
		case immediate && len(buf) == 0 && (b == '<' || b == '>'):
			if m.echo {
				m.raw(string(b))
			}
			m.s.log(string(b))
			return keyImmediate, string(b)
		case b >= 0x20:
			buf = append(buf, b)
			if m.echo {
				m.raw(string([]byte{b}))
			}
		}
	}
}

// pager keys.
const (
	pgSpace = iota
	pgEnter
	pgQuit
	pgEOF
)

// pagerKey waits for a key at a pager prompt.
func (m *menuSession) pagerKey() int {
	for {
		b, ok := m.readByte()
		if !ok {
			return pgEOF
		}
		switch b {
		case ' ':
			m.s.log("<SPACE>")
			return pgSpace
		case '\r', '\n':
			m.s.log("<CR>")
			return pgEnter
		case 'q', 'Q':
			m.s.log("q")
			return pgQuit
		case 0x1b:
			m.s.log("<ESC>")
			return pgQuit
		}
	}
}

// capture reads a screen of the captures' top directory.
func (m *menuSession) capture(name string) (string, bool) {
	body, err := readCapture(filepath.Join(m.c.screens, name))
	if err != nil {
		m.w("fakedev: " + err.Error() + "\n")
		return "", false
	}
	return body, true
}

// withoutPrompt drops the capture's own prompt lines from the end of
// lines (the fixture has its own prompt).
func withoutPrompt(lines []string) []string {
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	for n := len(lines); n > 0 && rePromptLine.MatchString(lines[n-1]); n = len(lines) {
		lines = lines[:n-1]
	}
	return lines
}

// textBeforePrompt is a capture's screen up to its prompt, every line
// ended with a newline.
func textBeforePrompt(rest string) string {
	lines := withoutPrompt(strings.Split(rest, "\n"))
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

// run is the session: banner, port list, the prompt and its commands.
func (m *menuSession) run() {
	banner, ok := m.capture(screenBanner)
	if !ok {
		return
	}
	question := ""
	for _, l := range strings.Split(strings.TrimRight(banner, "\n"), "\n") {
		question = l
	}
	m.loc = "banner"
	m.w(strings.TrimRight(banner, "\n"))
asking:
	for {
		switch k, line := m.readLine(false); {
		case k == keyEOF:
			m.closed()
			return
		case k == keyLine && line == "":
			break asking
		case k == keyLine && strings.EqualFold(strings.TrimSpace(line), "/X"):
			m.event("exit")
			return
		default:
			m.w("\n" + question)
		}
	}
	ports, ok := m.capture(screenPorts)
	if !ok {
		return
	}
	m.w(textBeforePrompt(ports) + m.c.prompt)
	for {
		m.loc = "prompt"
		k, line := m.readLine(false)
		switch {
		case k == keyEOF:
			m.closed()
			return
		case k == keyEsc:
			m.w("\n" + m.c.prompt)
		case strings.TrimSpace(line) == "":
			m.w(m.c.prompt)
		default:
			if !m.command(strings.TrimSpace(line)) {
				return
			}
		}
	}
}

// command runs one line typed at the prompt; false ends the session.
func (m *menuSession) command(line string) bool {
	word := strings.ToUpper(strings.Fields(line)[0])
	switch {
	case !strings.HasPrefix(word, "/"):
		m.event("invalid")
		m.w(refusedMsg + "\n" + m.c.prompt)
		return true
	case !m.c.allowed[word]:
		m.event("refused %s", word)
		m.w(refusedMsg + "\n" + m.c.prompt)
		return true
	}
	switch word {
	case "/X":
		m.event("exit")
		return false
	case "/H":
		return m.help()
	case "/SN":
		return m.status()
	case "/J":
		return m.siteID()
	case "/N", "/F", "/P", "/AC":
		return m.menuPages(word)
	}
	m.event("unmodelled %s", word)
	m.w(refusedMsg + "\n" + m.c.prompt)
	return true
}

type helpItem struct {
	text  string
	pager bool
}

// helpItems splits a help screen at the pager prompts the capture shows
// (the erase that follows one, and the text on the same line, is the
// start of the next page).
func helpItems(rest string) []helpItem {
	lines := withoutPrompt(strings.Split(rest, "\n"))
	items := make([]helpItem, 0, len(lines))
	afterPager := false
	for _, l := range lines {
		if strings.TrimSpace(l) == pagerText {
			items = append(items, helpItem{pager: true})
			afterPager = true
			continue
		}
		if afterPager {
			if i := strings.LastIndexByte(l, '\b'); i >= 0 {
				l = l[i+1:]
			}
			afterPager = false
		}
		items = append(items, helpItem{text: l})
	}
	return items
}

// help is '/H': the level's screen, paged.
func (m *menuSession) help() bool {
	body, ok := m.capture("03-help-" + m.c.level + ".txt")
	if !ok {
		return false
	}
	_, rest := splitEcho(body)
	rest = reHelpVersion.ReplaceAllString(rest, "Version "+m.c.version)
	items := helpItems(rest)
	if n := len(items); n > 1 && items[n-1].pager {
		items = append(items, m.legendTail(items[n-2].text)...)
	}
	m.loc = "/H"
	if m.emit(items) == pgEOF {
		m.closed()
		return false
	}
	m.w(m.c.prompt)
	return true
}

// legendTail is what follows the line last in another level's help: the
// capture of the Administrator help ends at its second pager prompt, and
// the legend box that goes on is the one the other captures hold.
func (m *menuSession) legendTail(last string) []helpItem {
	body, ok := m.capture("03-help-superuser.txt")
	if !ok {
		return nil
	}
	_, rest := splitEcho(body)
	items := helpItems(rest)
	for i, it := range items {
		if !it.pager && it.text == last {
			return items[i+1:]
		}
	}
	return nil
}

// emit writes the items, waiting at each pager prompt: SPACE gives the
// rest of the page, ENTER one line (and asks again), q or ESC stops.
func (m *menuSession) emit(items []helpItem) int {
	erase := strings.Repeat("\b \b", len(pagerText))
	lineMode, printed := false, false
	for _, it := range items {
		wait := false
		switch {
		case it.pager && !lineMode:
			wait = true
		case it.pager:
			continue
		case lineMode && printed:
			wait = true
		}
		if wait {
			m.raw(pagerText)
			k := m.pagerKey()
			if k == pgEOF {
				return pgEOF
			}
			m.raw(erase)
			switch k {
			case pgQuit:
				return pgQuit
			case pgSpace:
				lineMode = false
			case pgEnter:
				lineMode, printed = true, false
			}
			if it.pager {
				continue
			}
		}
		m.w(it.text + "\n")
		if lineMode {
			printed = true
		}
	}
	return pgSpace
}

// statusCell is one half of a row of '/SN'.
func statusCell(n int, active bool, user string) string {
	port, status := "", " Free "
	if active {
		port, status = "22", "Active"
	}
	if len(user) > 16 {
		user = user[:16]
	}
	return fmt.Sprintf("%-4s|%8s|%s|%-16s|", fmt.Sprintf("N%d", n), port, status, user)
}

var reStatusRow = regexp.MustCompile(`^N1\s*\|`)

// status is '/SN': the other sessions, then the login's own.
func (m *menuSession) status() bool {
	body, ok := m.capture(screenStatus)
	if !ok {
		return false
	}
	_, rest := splitEcho(body)
	users := make([]string, 0, m.c.sessions+1)
	for i := 0; i < m.c.sessions; i++ {
		if i < len(m.c.users) {
			users = append(users, m.c.users[i])
		} else {
			users = append(users, fmt.Sprintf("user%d", i+1))
		}
	}
	users = append(users, m.user)
	lines := strings.Split(strings.TrimRight(rest, "\n"), "\n")
	for i, l := range lines {
		if !reStatusRow.MatchString(l) {
			continue
		}
		for r := 0; r < 16 && i+r < len(lines); r++ {
			cell := func(n int) string {
				if n <= len(users) {
					return statusCell(n, true, users[n-1])
				}
				return statusCell(n, false, "")
			}
			lines[i+r] = cell(r+1) + cell(r+17)
		}
		break
	}
	m.loc = "/SN"
	m.w(strings.Join(lines, "\n"))
	for {
		switch m.pagerKey() {
		case pgEOF:
			m.closed()
			return false
		case pgQuit, pgEnter:
			m.w("\n" + m.c.prompt)
			return true
		}
	}
}

// siteID is '/J'.
func (m *menuSession) siteID() bool {
	body, ok := m.capture(screenSiteID)
	if !ok {
		return false
	}
	_, rest := splitEcho(body)
	m.w(textBeforePrompt(rest) + m.c.prompt)
	return true
}

// pageScreen is the screen of the page at m.path, without its echo, and
// whether there is one.
func (m *menuSession) pageScreen() (string, bool) {
	key := pageKey(m.path)
	if key == "/N > 5" {
		s, ok := m.c.ipTablesScreen(m.ip)
		return strings.TrimRight(s, "\n"), ok
	}
	body, ok := m.c.page(key)
	if !ok {
		return "", false
	}
	_, rest := splitEcho(body)
	if key == "/N" && len(m.c.iptables) > 0 {
		rest = strings.Replace(rest, "IP Tables:         Off", "IP Tables:         On ", 1)
	}
	return strings.TrimRight(rest, "\n"), true
}

// menuPages runs a top-level menu (/N, /F, /P, /AC) and what is under it,
// until ESC leaves it (the prompt follows) or the client goes.
func (m *menuSession) menuPages(top string) bool {
	m.path, m.ip = []string{top}, 0
	screen, ok := m.pageScreen()
	if !ok {
		m.event("unmodelled %s", top)
		m.w(refusedMsg + "\n" + m.c.prompt)
		return true
	}
	m.w(screen)
	for {
		m.loc = pageKey(m.path)
		k, line := m.readLine(true)
		cur := pageKey(m.path)
		switch k {
		case keyEOF:
			m.closed()
			return false
		case keyEsc:
			if len(m.path) == 1 {
				m.event("save %s", cur)
				m.w("\n" + savingMsg + "\n" + m.c.prompt)
				return true
			}
			m.pop()
			s, _ := m.pageScreen()
			m.w("\n" + strings.TrimLeft(s, "\n"))
		case keyImmediate:
			if cur != "/N > 5" {
				m.w("\n")
				m.invalid(cur, "")
				continue
			}
			if line == ">" {
				m.ip = min(m.ip+1, ipPages()-1)
			} else {
				m.ip = max(m.ip-1, 0)
			}
			s, _ := m.pageScreen()
			m.w("\n" + s)
		case keyLine:
			m.entry(cur, strings.TrimSpace(line))
		}
	}
}

// pop goes one level up.
func (m *menuSession) pop() {
	m.path = m.path[:len(m.path)-1]
	m.ip = 0
}

// entry handles a line typed at the page cur.
func (m *menuSession) entry(cur, line string) {
	if line == "" {
		s, _ := m.pageScreen()
		if strings.HasPrefix(cur, "/F > 1 > 1 > ") {
			m.pop() // a user's details page: CR returns
			s, _ = m.pageScreen()
			s = strings.TrimLeft(s, "\n")
		}
		m.w(s)
		return
	}
	child := cur + " > " + line
	if _, ok := m.c.pages[child]; ok {
		m.path = append(m.path, line)
		m.ip = 0
		s, _ := m.pageScreen()
		m.w(s)
		return
	}
	m.invalid(cur, line)
}

// invalid refuses an entry: the unit's error and the page again.
func (m *menuSession) invalid(cur, line string) {
	switch {
	case !m.c.hasChildren(cur):
		m.event("entry %s", cur)
	case reDigits.MatchString(line):
		m.event("no-page %s > %s", cur, line)
	default:
		m.event("no-page %s", cur)
	}
	s, _ := m.pageScreen()
	m.w(invalidMsg + "\n" + s)
}
