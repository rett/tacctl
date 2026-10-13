package wti

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// The errors of the parser. Each is wrapped with the page's title and
// nothing else of the screen: a screen may hold a secret.
var (
	// ErrUnknownPage: the screen's title is in no row of the table. Nothing
	// further is read from it.
	ErrUnknownPage = errors.New("wti: a page the tables do not know")
	// ErrLayout: the page is known but its items are not the table's (a
	// label, a missing item, a value form the page does not print, an
	// error line, an incomplete screen).
	ErrLayout = errors.New("wti: a page laid out otherwise than the tables say")
	// ErrPath: the page is not the one its header says was opened.
	ErrPath = errors.New("wti: a page other than the one asked for")
	// ErrDocument: the document is not a sequence of headed screens.
	ErrDocument = errors.New("wti: not a document of headed screens")
)

// maxPages bounds a document (the lab unit's has about a dozen screens).
const maxPages = 256

// IPTablesSlots is the number of entries the unit's IP tables page holds
// (four screens of twelve).
const IPTablesSlots = 48

// Clean makes a screen's text one statement-safe line per line: line ends
// unified, escape sequences removed, a backspace erasing the character
// before it on its own line (the unit's pager erases its prompt with
// 'BS SPACE BS' runs), other control characters dropped, tabs as blanks,
// trailing blanks trimmed.
func Clean(raw string) string {
	raw = strings.ToValidUTF8(raw, "?")
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	lines := strings.Split(raw, "\n")
	for i, l := range lines {
		var buf []rune
		rs := []rune(l)
		for j := 0; j < len(rs); j++ {
			r := rs[j]
			switch {
			case r == 0x1b:
				j++
				if j < len(rs) && rs[j] == '[' {
					j++
					for j < len(rs) && (rs[j] < 0x40 || rs[j] > 0x7e) {
						j++
					}
				}
			case r == '\b':
				if n := len(buf); n > 0 {
					buf = buf[:n-1]
				}
			case r == '\t':
				buf = append(buf, ' ')
			case r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == 0x2028 || r == 0x2029:
			default:
				buf = append(buf, r)
			}
		}
		lines[i] = strings.TrimRight(string(buf), " ")
	}
	return strings.Join(lines, "\n")
}

// shortTitle is a title as an error may name it: printable, 48 characters.
func shortTitle(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	n := 0
	for _, r := range s {
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

// Field is one item of a page, parsed.
type Field struct {
	Item *Item
	// Value is the canonical value ("" for a setting that is not set). For
	// a secret item it is a presence mark; for a community it is the string
	// in clear, and is not to be kept (see FormCommunity).
	Value string
}

// Entry is one slot of an IP tables screen.
type Entry struct {
	Slot int
	// Command is the unit's command without its leading 'iptables ' ("" for
	// an empty slot).
	Command string
}

// Parsed is one screen read by the table.
type Parsed struct {
	// Page is the row of the table the title matched.
	Page *Page
	// Path is the header's path ("" when none was given).
	Path string
	// Title is the screen's title line, as printed (never in an error: only
	// ShortTitle is).
	Title string
	// Fields are the page's declared items found, in the table's order.
	Fields []Field
	// Facts are the items read as facts, by name.
	Facts map[string]string
	// User is the user name of a details page (its header's, checked
	// against the page's own Username item).
	User string
	// Entries are an IP tables screen's slots, in order.
	Entries []Entry
	// Names are the user directory list's names.
	Names []string
	// Version, Commands and Config are the help page's version, every
	// command it lists and those under CONFIGURATION COMMANDS.
	Version  string
	Commands []string
	Config   []string
	// InUse and Ports are the status page's sessions not Free and its
	// session rows.
	InUse, Ports int
	// SiteID is the /J line's value.
	SiteID string
}

var reItem = regexp.MustCompile(`^(\d{1,3})\.?\s+(.*)$`)

// column splits a line of the two-column network menu at the second
// column's item number.
var reColumn = regexp.MustCompile(`\s{2,}(\d{1,2})\.\s+[A-Za-z]`)

func segments(line string, columns bool) []string {
	line = strings.TrimLeft(line, " ")
	if !columns {
		return []string{line}
	}
	var out []string
	for {
		loc := reColumn.FindStringSubmatchIndex(line)
		if loc == nil {
			return append(out, line)
		}
		out = append(out, strings.TrimRight(line[:loc[0]], " "))
		line = line[loc[2]:]
	}
}

// echoLine reports a line that is only the keys echoed back before the
// page: '/N', '28', '>', 'localadmin' (a title ends in a colon).
func echoLine(l string) bool {
	l = strings.TrimSpace(l)
	return l != "" && len(l) <= 64 && !strings.ContainsAny(l, " \t") && !strings.HasSuffix(l, ":")
}

// rowFor returns the row whose title matches, and the title's capture.
func rowFor(line string) (*Page, []string) {
	for i := range Pages {
		if m := Pages[i].Title.FindStringSubmatch(line); m != nil {
			return &Pages[i], m
		}
	}
	return nil, nil
}

// pathMatches reports whether a header's path is the row's; name is the
// user name a '<name>' row captured.
func pathMatches(pattern, path string) (name string, ok bool) {
	if prefix, found := strings.CutSuffix(pattern, "<name>"); found {
		if rest, has := strings.CutPrefix(path, prefix); has && rest != "" {
			return rest, true
		}
		return "", false
	}
	return "", pattern == path
}

// normPath puts a header's path in the table's form.
func normPath(p string) string {
	return strings.Join(strings.Fields(p), " ")
}

// ParseScreen reads one screen by the table. path is the header's path
// (empty to accept whatever page the title is).
func ParseScreen(path, screen string) (*Parsed, error) {
	path = normPath(path)
	lines := strings.Split(Clean(screen), "\n")
	var row *Page
	var capture []string
	title, at := "", -1
	echoes := 0
	for i, l := range lines {
		if strings.TrimSpace(l) == "" {
			continue
		}
		if r, m := rowFor(l); r != nil {
			row, capture, title, at = r, m, strings.TrimSpace(l), i
			break
		}
		if echoLine(l) && echoes < 2 {
			echoes++
			continue
		}
		return nil, fmt.Errorf("%w: %q", ErrUnknownPage, shortTitle(l))
	}
	if row == nil {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPage, "(no title)")
	}
	t := shortTitle(title)
	p := &Parsed{Page: row, Path: path, Title: title, Facts: map[string]string{}}
	if path != "" {
		name, ok := pathMatches(row.Path, path)
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrPath, t)
		}
		p.User = name
	}
	body := lines[at+1:]
	scan := body
	if row.Kind == KindPrompt {
		// the value a prompt page prints is the unit's own text: only the
		// lines above its footer can be an error line
		if head, _, ok := promptSplit(body); ok {
			scan = head
		}
	}
	for _, l := range scan {
		if strings.HasPrefix(strings.TrimSpace(l), "ERROR:") {
			return nil, fmt.Errorf("%w: %q: the unit printed an error", ErrLayout, t)
		}
	}
	var err error
	switch row.Kind {
	case KindMenu:
		err = parseMenu(p, body)
	case KindList:
		err = parseList(p, body)
	case KindUsers:
		err = parseUsers(p, body)
	case KindPrompt:
		err = parsePrompt(p, body)
	case KindStatus:
		err = parseStatus(p, append([]string{title}, body...))
	case KindHelp:
		p.Version = capture[1]
		parseHelp(p, body)
	case KindLine:
		p.SiteID = strings.TrimSpace(capture[1])
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %q", err, t)
	}
	return p, nil
}

// footer reports the line that ends a page's body.
func footer(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "Enter") }

func parseMenu(p *Parsed, body []string) error {
	byNum := map[int]string{}
	complete := false
	for _, l := range body {
		if footer(l) {
			complete = true
			break
		}
		for _, seg := range segments(l, p.Page.Columns) {
			m := reItem.FindStringSubmatch(seg)
			if m == nil {
				continue
			}
			n, _ := strconv.Atoi(m[1])
			if _, dup := byNum[n]; !dup {
				byNum[n] = m[2]
			}
		}
	}
	if !complete {
		return fmt.Errorf("%w: the screen is incomplete", ErrLayout)
	}
	for i := range p.Page.Items {
		it := &p.Page.Items[i]
		rest, ok := byNum[it.Number]
		if !ok {
			if it.Optional {
				continue
			}
			return fmt.Errorf("%w: an item is missing", ErrLayout)
		}
		value, ok := cutLabel(rest, it.Label)
		if !ok {
			return fmt.Errorf("%w: an item is not the table's", ErrLayout)
		}
		v, ok := it.Parse(value)
		if !ok {
			return fmt.Errorf("%w: a value is not of a form the page prints", ErrLayout)
		}
		if it.Fact != "" {
			p.Facts[it.Fact] = v
			if it.Fact == "user-name" {
				if p.User != "" && v != p.User {
					return fmt.Errorf("%w: the user is not the one asked for", ErrPath)
				}
				p.User = v
			}
		}
		p.Fields = append(p.Fields, Field{Item: it, Value: v})
	}
	return nil
}

// cutLabel returns what follows the label of an item's text: the value.
// The label ends at a colon or at a blank; it is matched without regard to
// case.
func cutLabel(rest, label string) (string, bool) {
	if len(rest) < len(label) || !strings.EqualFold(rest[:len(label)], label) {
		return "", false
	}
	tail := rest[len(label):]
	switch {
	case tail == "":
		return "", true
	case tail[0] == ':':
		return strings.TrimSpace(tail[1:]), true
	case tail[0] == ' ':
		return strings.TrimSpace(tail), true
	}
	return "", false
}

var reSlot = regexp.MustCompile(`^(\d{1,2})\.(?:\s+(.*))?$`)

func parseList(p *Parsed, body []string) error {
	complete := false
	for _, l := range body {
		if footer(l) {
			complete = true
			break
		}
		if strings.TrimSpace(l) == "" || strings.HasPrefix(l, " ") {
			continue
		}
		m := reSlot.FindStringSubmatch(l)
		if m == nil {
			return fmt.Errorf("%w: an entry is not one line of the form 'N. command'", ErrLayout)
		}
		n, _ := strconv.Atoi(m[1])
		if n < 1 || n > IPTablesSlots {
			return fmt.Errorf("%w: a slot is out of range", ErrLayout)
		}
		cmd := strings.TrimSpace(m[2])
		cmd = strings.TrimSpace(strings.TrimPrefix(cmd, "iptables "))
		if len(cmd) > 1024 {
			return fmt.Errorf("%w: an entry is longer than the unit takes", ErrLayout)
		}
		p.Entries = append(p.Entries, Entry{Slot: n, Command: strings.Join(strings.Fields(cmd), " ")})
	}
	if !complete {
		return fmt.Errorf("%w: the screen is incomplete", ErrLayout)
	}
	if len(p.Entries) == 0 {
		return fmt.Errorf("%w: no slot", ErrLayout)
	}
	return nil
}

// promptFooter is the line of a prompt page's footer that says ESC leaves
// the value as it is (the unit adds ' ...' after it).
const promptFooter = "<ESC> to return to previous menu"

// reRule is the line of dashes under a prompt page's value, as long as the
// field's limit.
var reRule = regexp.MustCompile(`^-{8,}$`)

// promptSplit cuts a prompt page's body after its footer line: head ends
// with the footer, tail is what the unit printed under it. ok is false for
// a body with no footer.
func promptSplit(body []string) (head, tail []string, ok bool) {
	for i, l := range body {
		if strings.Contains(l, promptFooter) {
			return body[:i+1], body[i+1:], true
		}
	}
	return body, nil, false
}

// parsePrompt reads a text prompt page: under its footer the field's whole
// value on a line of its own, then the rule line. A page with no value line
// (the rule comes first), no rule line or no footer is not the layout. The
// value is the page's only item, in the table's order; the prompt is never
// typed at, so nothing else of the page is read.
func parsePrompt(p *Parsed, body []string) error {
	_, tail, ok := promptSplit(body)
	if !ok {
		return fmt.Errorf("%w: the screen is incomplete", ErrLayout)
	}
	var lines []string
	for _, l := range tail {
		if t := strings.TrimSpace(l); t != "" {
			lines = append(lines, t)
		}
	}
	switch {
	case len(lines) == 0:
		return fmt.Errorf("%w: the screen is incomplete", ErrLayout)
	case reRule.MatchString(lines[0]) && (len(lines) == 1 || !reRule.MatchString(lines[1])):
		return fmt.Errorf("%w: the page prints no value line", ErrLayout)
	case len(lines) < 2:
		// the value is there and its rule line is not painted yet
		return fmt.Errorf("%w: the screen is incomplete", ErrLayout)
	case !reRule.MatchString(lines[1]):
		return fmt.Errorf("%w: the value is not followed by the rule line", ErrLayout)
	}
	if len(p.Page.Items) != 1 {
		return fmt.Errorf("%w: a prompt row holds one item", ErrLayout)
	}
	it := &p.Page.Items[0]
	v, ok := it.Parse(lines[0])
	if !ok {
		return fmt.Errorf("%w: a value is not of a form the page prints", ErrLayout)
	}
	p.Fields = append(p.Fields, Field{Item: it, Value: v})
	return nil
}

func parseUsers(p *Parsed, body []string) error {
	complete := false
	for _, l := range body {
		if footer(l) {
			complete = true
			break
		}
		p.Names = append(p.Names, strings.Fields(l)...)
	}
	if !complete {
		return fmt.Errorf("%w: the screen is incomplete", ErrLayout)
	}
	return nil
}

func parseStatus(p *Parsed, lines []string) error {
	for _, l := range lines {
		cells := strings.Split(l, "|")
		if len(cells) < 4 {
			continue
		}
		for i := 0; i+3 < len(cells); i += 4 {
			port := strings.TrimSpace(cells[i])
			if len(port) < 2 || port[0] != 'N' || !isDigits(port[1:]) {
				continue
			}
			p.Ports++
			if st := strings.TrimSpace(cells[i+2]); st != "" && !strings.EqualFold(st, "Free") {
				p.InUse++
			}
		}
	}
	if p.Ports == 0 {
		return fmt.Errorf("%w: no session row", ErrLayout)
	}
	return nil
}

var reCommand = regexp.MustCompile(`^(/[A-Z]{1,8})(?:\s|$)`)

func parseHelp(p *Parsed, body []string) {
	section := ""
	for _, l := range body {
		switch {
		case strings.Contains(l, "CONFIGURATION COMMANDS"):
			section = "config"
			continue
		case strings.Contains(l, "DISPLAY COMMANDS"), strings.Contains(l, "CONTROL COMMANDS"):
			section = "other"
			continue
		case strings.HasPrefix(strings.TrimSpace(l), "LEGEND"):
			section = ""
			continue
		}
		if section == "" {
			continue
		}
		if m := reCommand.FindStringSubmatch(l); m != nil {
			p.Commands = append(p.Commands, m[1])
			if section == "config" {
				p.Config = append(p.Config, m[1])
			}
		}
	}
}

// --- the document --------------------------------------------------------------

// The levels of a login, from the commands its help lists.
const (
	LevelViewOnly      = "viewonly"
	LevelUser          = "user"
	LevelSuperUser     = "superuser"
	LevelAdministrator = "administrator"
)

// Document is a unit's captured screens: the text the reader returns, each
// screen headed by '# page: /N > 28'.
type Document struct {
	// Pages are the parsed screens in the order they were captured.
	Pages []*Parsed

	byRow   map[string]*Parsed
	slots   map[int]string
	order   []string
	details map[string]*Parsed
	usersOK bool
	// full maps a statement key to the whole value its prompt page printed
	// (KindPrompt): the menu's own, truncated, value is not used.
	full map[string]string
}

// PageHeader is the line that heads a screen in a document.
const PageHeader = "# page:"

// ParseDocument reads a document: each '# page: <path>' line starts a
// screen. Blank and '#' lines before the first header are skipped. The
// first screen the table does not know, or does not read as the table
// says, ends the parse with its error (title only).
func ParseDocument(raw string) (*Document, error) {
	lines := strings.Split(Clean(raw), "\n")
	type block struct {
		path  string
		lines []string
	}
	var blocks []*block
	for _, l := range lines {
		if rest, ok := strings.CutPrefix(l, PageHeader); ok {
			blocks = append(blocks, &block{path: strings.TrimSpace(rest)})
			continue
		}
		if len(blocks) == 0 {
			if t := strings.TrimSpace(l); t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			return nil, fmt.Errorf("%w: text before the first page header", ErrDocument)
		}
		b := blocks[len(blocks)-1]
		b.lines = append(b.lines, l)
	}
	if len(blocks) == 0 {
		return nil, fmt.Errorf("%w: no page header", ErrDocument)
	}
	if len(blocks) > maxPages {
		return nil, fmt.Errorf("%w: more than %d screens", ErrDocument, maxPages)
	}
	d := &Document{byRow: map[string]*Parsed{}, slots: map[int]string{}, details: map[string]*Parsed{}, full: map[string]string{}}
	for _, b := range blocks {
		p, err := ParseScreen(b.path, strings.Join(b.lines, "\n"))
		if err != nil {
			return nil, err
		}
		if p.Path == "" {
			return nil, fmt.Errorf("%w: a screen has no path", ErrDocument)
		}
		d.Pages = append(d.Pages, p)
		switch p.Page.Kind {
		case KindList:
			for _, e := range p.Entries {
				d.slots[e.Slot] = e.Command
			}
		case KindUsers:
			d.usersOK = true
			d.order = nil
			for _, n := range p.Names {
				if !slices.Contains(d.order, n) {
					d.order = append(d.order, n)
				}
			}
		default:
			if p.Page.Path == "/F > 1 > 1 > <name>" {
				d.details[p.User] = p
			} else {
				d.byRow[p.Page.Path] = p
			}
			if p.Page.Kind == KindPrompt {
				for _, f := range p.Fields {
					d.full[f.Item.Key] = f.Value
				}
			}
		}
	}
	return d, nil
}

// Page returns the last screen captured of a page (by its row's path).
func (d *Document) Page(path string) *Parsed { return d.byRow[path] }

// Missing returns the paths of the pages the document lacks that a pull
// needs: a required page, the four screens of the IP tables list, a
// listed user's details.
func (d *Document) Missing() []string {
	var out []string
	for _, row := range Pages {
		if !row.Required {
			continue
		}
		if row.Kind == KindList {
			for n := 1; n <= IPTablesSlots; n++ {
				if _, ok := d.slots[n]; !ok {
					out = append(out, row.Path)
					break
				}
			}
			continue
		}
		if d.byRow[row.Path] == nil {
			out = append(out, row.Path)
		}
	}
	if d.usersOK {
		for _, n := range d.order {
			if d.details[n] == nil {
				out = append(out, "/F > 1 > 1 > <name>")
				break
			}
		}
	}
	return out
}

// UsersRead reports whether the user directory's list was captured.
func (d *Document) UsersRead() bool { return d.usersOK }

// UserNames are the local users the list names, in its order.
func (d *Document) UserNames() []string { return slices.Clone(d.order) }

// Version is the command menu version of the /H page ("" when not read).
func (d *Document) Version() string {
	if p := d.byRow["/H"]; p != nil {
		return p.Version
	}
	return ""
}

// Commands are the commands the /H page lists, and ConfigCommands those
// under CONFIGURATION COMMANDS.
func (d *Document) Commands() []string {
	if p := d.byRow["/H"]; p != nil {
		return slices.Clone(p.Commands)
	}
	return nil
}

// ConfigCommands are the commands under CONFIGURATION COMMANDS.
func (d *Document) ConfigCommands() []string {
	if p := d.byRow["/H"]; p != nil {
		return slices.Clone(p.Config)
	}
	return nil
}

// CanConfigure reports whether the login's menu lists /N as a
// configuration command (a ViewOnly or User login's does not).
func (d *Document) CanConfigure() bool {
	return slices.Contains(d.ConfigCommands(), "/N")
}

// Level is the access level the help page's commands show: Administrator
// where /UFW is a configuration command, SuperUser where /F is, User where
// /C is a command, else ViewOnly; "" when /H was not read.
func (d *Document) Level() string {
	p := d.byRow["/H"]
	switch {
	case p == nil:
		return ""
	case slices.Contains(p.Config, "/UFW"):
		return LevelAdministrator
	case slices.Contains(p.Config, "/F"):
		return LevelSuperUser
	case slices.Contains(p.Commands, "/C"):
		return LevelUser
	}
	return LevelViewOnly
}

// OtherSessions is the number of other sessions in use (the /SN page's rows
// not Free, less this login's own, never below zero); ok is false when
// /SN was not read. No name is kept.
func (d *Document) OtherSessions() (n int, ok bool) {
	p := d.byRow["/SN"]
	if p == nil {
		return 0, false
	}
	return max(p.InUse-1, 0), true
}

// SiteID is the /J page's value ("" when not read).
func (d *Document) SiteID() string {
	if p := d.byRow["/J"]; p != nil {
		return p.SiteID
	}
	return ""
}

// Fact returns a fact of a menu page ('iptables' of /N, 'lockout' of /F).
func (d *Document) Fact(name string) (string, bool) {
	for _, p := range d.byRow {
		if v, ok := p.Facts[name]; ok {
			return v, true
		}
	}
	return "", false
}

// Statements are the document's canonical statements, in the table's order
// (a page's items in item order, the IP tables entries in slot order, the
// users in the list's order). A setting that is not set has no statement.
// A community statement holds the string in clear (see FormCommunity).
func (d *Document) Statements() []Statement {
	var out []Statement
	add := func(section string, c Canonical) {
		if c.Value != "" {
			out = append(out, Statement{Section: section, Canonical: c})
		}
	}
	for _, row := range Pages {
		switch {
		case row.Kind == KindList:
			for n := 1; n <= IPTablesSlots; n++ {
				if cmd := d.slots[n]; cmd != "" {
					add(SectionMgmtACL, Canonical{Form: FormCommand, Key: "iptables", Value: cmd})
				}
			}
		case row.Kind == KindUsers, row.Kind == KindPrompt:
			// a prompt's value is taken at its menu item's place
		case row.Path == "/F > 1 > 1 > <name>":
			for _, n := range d.order {
				p := d.details[n]
				if p == nil {
					continue
				}
				for _, f := range p.Fields {
					if f.Item.Key == "" {
						continue
					}
					key := strings.TrimSpace(strings.TrimPrefix(f.Item.Key, "user {user}"))
					add(f.Item.Section, Canonical{Form: FormUser, Name: n, Key: key, Value: userValue(key, f.Value)})
				}
			}
		default:
			p := d.byRow[row.Path]
			if p == nil {
				continue
			}
			for _, f := range p.Fields {
				if f.Item.Key == "" {
					continue
				}
				v := f.Value
				if full, ok := d.full[f.Item.Key]; ok {
					v = full // the prompt page's whole value, not the menu's truncated one
				}
				if f.Item.Form == FormSecret && v != "" {
					v = SecretMark
				}
				add(f.Item.Section, Canonical{Form: f.Item.Form, Key: f.Item.Key, Value: v})
			}
		}
	}
	return out
}

func userValue(key, v string) string {
	if v != "" && userSecretKeys[key] {
		return SecretMark
	}
	return v
}
