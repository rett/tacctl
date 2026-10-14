package plan

// The output of one device (plan D108-D112): the box, the irregularity
// report, the one check line, ONE paste region between two banners, then the
// after-steps outside it. The region holds only statements, the wrapper
// lines and one label per section, ends at the confirmed commit (Junos) or
// at 'end' (IOS), and so can be pasted whole without making a permanent
// change; the line that confirms or saves is typed afterwards, by hand.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf"
)

// Header is what the output says about the device and the pull: all of it an
// input, the package reads no clock.
type Header struct {
	Device string
	// Address is the device's address, in the box.
	Address string
	Scope   string
	// Vendor is the registry's word: juniper or cisco.
	Vendor string
	// Protocol is TACACS+ or RADIUS.
	Protocol string
	// Pulled, PulledBy and Transport come from the record of the pull the
	// plan is based on.
	Pulled    time.Time
	PulledBy  string
	Transport string
	// SecretsVisible is whether the pull's login could read secrets.
	SecretsVisible bool
	// Now is the time of the rendering (the age is Now - Pulled).
	Now time.Time
	// Version is tacctl's version.
	Version string
	// User is the person who asked (the commit comment names them).
	User string
	// StaleDays is the 'stale-days' setting: a pull older than that is a
	// warning (0: no check).
	StaleDays int
	// Unit is what the pull of a WTI unit saw beside its sections (nil: the
	// record does not say, and for any other vendor).
	Unit *UnitInfo
}

// Wrapper is the procedure around the statements.
type Wrapper struct {
	// ConfirmMinutes is the N of 'commit confirmed N' (Junos; default 5,
	// clamped to 1-60).
	ConfirmMinutes int
}

// secretLinePrefix leads a --no-secrets statement inside a region: the line
// is a comment, so a paste never sets the literal placeholder; the report
// says to put the value in. These are the only comment lines of a region
// besides the section labels.
const secretLinePrefix = "VALUE NEEDED, then remove this mark: "

// RegionLine is one line of a region. Comment lines are labels (and the
// placeholder lines of --no-secrets); Line is the index into Delta.Lines the
// line comes from, -1 for the wrapper and the labels.
type RegionLine struct {
	Text    string
	Comment bool
	// Wrapper marks the lines that are the procedure around the
	// statements (configure, show | compare, commit check, the confirmed
	// commit, end); Plain leaves them out. An IOS submode header is none
	// of these: it belongs to the statements under it.
	Wrapper bool
	Line    int
}

// ErrNoSecretsPlain: a plain file of a --no-secrets plan would not be what
// it says.
var ErrNoSecretsPlain = errors.New("plan: --plain with --no-secrets: the statements hold a placeholder, not a value")

func commentLeader(family string) string {
	if family == devconf.FamilyIOS {
		return "!"
	}
	return "#"
}

func bannerChar(family string) string {
	if family == devconf.FamilyIOS {
		return "!!!!!"
	}
	return "#####"
}

// RegionLines returns the lines between the banners.
func RegionLines(d Delta, h Header, w Wrapper) []RegionLine {
	if d.Vendor == devconf.FamilyIOS {
		return iosRegion(d)
	}
	if d.Vendor == devconf.FamilyWTI {
		return wtiRegionLines(d, h)
	}
	return junosRegion(d, h, w)
}

// Region is the banner pair and the lines between them, as text.
func Region(d Delta, h Header, w Wrapper) string {
	if d.Empty() {
		return ""
	}
	var b strings.Builder
	if d.Vendor == devconf.FamilyWTI {
		// a unit's banners are its own: the steps and the IP tables block
		for _, l := range RegionLines(d, h, w) {
			b.WriteString(l.Text + "\n")
		}
		return b.String()
	}
	bc := bannerChar(d.Vendor)
	b.WriteString(bc + " PASTE FROM HERE: " + h.Device + " " + bc + "\n")
	for _, l := range RegionLines(d, h, w) {
		b.WriteString(l.Text + "\n")
	}
	b.WriteString(bc + " PASTE TO HERE: " + h.Device + " " + bc + "\n")
	return b.String()
}

// Plain is the statements only (D99, M5): no wrapper line, no comment, no
// banner. It is the list for 'load set <file>' on Junos, which reports the
// wrapper lines and every '#' line as errors, and the lines to type inside
// 'configure terminal' on IOS (an indented submode header stays: it is part
// of the statements under it). A --no-secrets plan has no plain form.
func Plain(d Delta, h Header, w Wrapper) (string, error) {
	if d.Vendor == devconf.FamilyWTI {
		return "", ErrWTIPlain
	}
	if d.Counts.Placeholders > 0 {
		return "", ErrNoSecretsPlain
	}
	var b strings.Builder
	for _, l := range RegionLines(d, h, w) {
		if !l.Comment && !l.Wrapper {
			b.WriteString(l.Text + "\n")
		}
	}
	return b.String(), nil
}

// Block is the whole output of one device: the report with its box and
// check line, the region, the after-steps.
func Block(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	b.WriteString(Report(d, h, w))
	// the restore point (--restore-point, IOS): its own banner pair, before
	// the region and outside it
	b.WriteString(RestoreRegion(d, h))
	if !d.Empty() {
		b.WriteString(Region(d, h, w))
		b.WriteString(After(d, h, w))
	}
	// --converge: the cleanup region, only for a device with no first region
	// (one output, one region: D111, amended)
	if d.Empty() && !d.Cleanup.Empty() {
		b.WriteString(CleanupRegion(d, h, w))
		b.WriteString(CleanupAfter(d, h, w))
	}
	b.WriteString(ByHand(d, h))
	return b.String()
}

// Sensitivity is the line that says the output holds a secret ("" when it
// holds none): the first line of the report, and what a caller repeats on
// its error stream so that a redirected output still shows it (D98).
func Sensitivity(d Delta, h Header) string { return sensitivityLine(d, h) }

// ByHand is the text for a unit the plan refuses and a person has to do by
// hand (D117): comment lines, after the region or, when there is none,
// after the report. Nothing in it is a region.
func ByHand(d Delta, h Header) string {
	if len(d.ByHand) == 0 {
		return ""
	}
	c := commentLeader(d.Vendor)
	var b strings.Builder
	b.WriteString(c + "\n")
	text := "By hand (this is no region and tacctl pastes none of it): the old server entry cannot be replaced from a session that a command authorization list governs. "
	if strings.HasPrefix(d.ByHand[0], "0. ") {
		// SF2: the console is under command authorization too
		text += "The console is under command authorization as well ('aaa authorization console'), so the steps cannot be typed as they are: step 0 takes that setting off first. "
	}
	for _, l := range wrapText(text+
		"Do it on the console, as any user that reaches privilege 15 there, one numbered step at a time (the indented lines are typed as they stand); then pull and plan again ("+
		"tacctl device config pull "+h.Device+", tacctl device config plan "+h.Device+").", 100) {
		b.WriteString(c + " " + l + "\n")
	}
	for _, l := range d.ByHand {
		if strings.HasPrefix(l, byHandIndent) {
			b.WriteString(c + "   " + l + "\n")
			continue
		}
		for i, w := range wrapText(l, 92) {
			pad := ""
			if i > 0 {
				pad = "   " // under the text of a numbered step
			}
			b.WriteString(c + "   " + pad + w + "\n")
		}
	}
	return b.String()
}

// lockoutHelp is the three comment lines that end every region's
// after-steps whether or not the device is held (D124): what a person does
// whose paste cut the session and left no login that works. The device's
// local account is the way in, and the verbs are the superuser's.
func lockoutHelp(d Delta, h Header) string {
	c := commentLeader(d.Vendor)
	way := "then log in as the device's local account (console: local login, then 'enable' with the local secret),"
	switch d.Vendor {
	case devconf.FamilyWTI:
		way = "then log in on the unit's serial console as its local Administrator account,"
	case devconf.FamilyJunos:
		way = "then log in as the device's local user (ssh or console),"
	}
	return c + " Locked out (the paste cut your session and no login works)? A superuser runs: tacctl breakglass hold " + h.Device + " --reason \"...\"\n" +
		c + " " + way + "\n" +
		c + " fix or back out, and the superuser runs: tacctl breakglass release " + h.Device + "\n"
}

// After is the text after the region (outside it): what to read, the check
// and the one line to type, the back-out as comments, what not to do.
func After(d Delta, h Header, w Wrapper) string {
	if d.Empty() {
		return ""
	}
	switch d.Vendor {
	case devconf.FamilyIOS:
		return iosAfter(d, h, w)
	case devconf.FamilyWTI:
		return wtiAfter(d, h)
	}
	return junosAfter(d, h, w)
}

// ErrNoBackout: the plan has nothing tacctl can type to undo it (no
// statement, or only values it does not hold).
var ErrNoBackout = errors.New("plan: there is nothing tacctl can type to undo this plan")

// backoutLines are the lines of the back-out in the order to type them.
func backoutLines(d Delta) []Line {
	if d.Empty() {
		return nil
	}
	if d.Vendor == devconf.FamilyIOS {
		return iosBackout(d)
	}
	return d.Backout
}

// HasBackout reports whether the plan has a back-out region: at least one
// line tacctl can type (a value it does not hold is a comment, not a line).
func HasBackout(d Delta) bool {
	if d.Vendor == devconf.FamilyWTI {
		return !d.Empty() && wtiHasBackout(d)
	}
	return slices.ContainsFunc(backoutLines(d), func(l Line) bool { return l.Op != OpComment })
}

// BackoutLines returns the lines between the back-out banners: the
// wrapper, the statements that put the pulled configuration back (plain
// executable lines, a value that is not known as a comment), and the end of
// the wrapper. The whole-paste invariant holds for them as for the
// region's.
func BackoutLines(d Delta, h Header, w Wrapper) []RegionLine {
	if d.Vendor == devconf.FamilyWTI {
		return wtiBackoutLines(d, h)
	}
	if d.Vendor == devconf.FamilyIOS {
		return iosBackoutRegion(d)
	}
	return junosBackoutRegion(d, h, w)
}

// StoredBackout is the text of the back-out that tacctl keeps beside the
// device's record (D111, point 3): the back-out as Backout prints it, except
// that a line which holds a secret's value is a comment that says to type it
// with its own value ('<secret>' in its place), as the back-out already does
// for a value tacctl does not hold. Nothing more than the printed back-out
// is ever stored, and no value: the record store keeps none (M1).
// ErrNoBackout when there is no line to type.
func StoredBackout(d Delta, h Header, w Wrapper) (string, error) {
	return Backout(d.kept(), h, w)
}

// kept is the delta with every value elided, and every back-out line that
// held one turned into a note.
func (d Delta) kept() Delta {
	c := d.shown()
	// A line that holds a value is a note whether or not its elided form is
	// known: with none the note names the section, and the value (Text) is
	// never copied.
	note := func(l Line) Line {
		text := l.Elided
		switch {
		case text == "":
			text = "a statement of " + l.Section + " that holds a secret"
		case l.Op == OpNo:
			text = "no " + text
		}
		return Line{Op: OpComment, Section: l.Section, Text: "type yourself, with its own value: " + text}
	}
	for i, l := range d.Backout {
		if l.Secret && l.HasValue {
			c.Backout[i] = note(l)
		}
	}
	for i, l := range d.Lines {
		for j, u := range l.Undo {
			if u.Secret && u.HasValue {
				c.Lines[i].Undo[j] = note(u)
			}
		}
	}
	return c
}

// Backout is the back-out as its own output (D108, review H2): the device
// box, what it is and the check, ONE delimited region of plain lines
// ('BACK-OUT FROM HERE' ... 'BACK-OUT TO HERE'), and after it nothing but
// comment lines. It is never part of Block: a copy of the whole output of a
// plan must not paste the undo. ErrNoBackout when there is no line to type.
func Backout(d Delta, h Header, w Wrapper) (string, error) {
	if d.Empty() || !HasBackout(d) {
		return "", ErrNoBackout
	}
	if d.Vendor == devconf.FamilyWTI {
		return wtiBackout(d, h)
	}
	var b strings.Builder
	c := commentLeader(d.Vendor)
	add := func(s string) {
		for _, l := range wrapText(s, 100) {
			b.WriteString(c + " " + l + "\n")
		}
	}
	bc := bannerChar(d.Vendor)
	b.WriteString(boxLine(d, h) + "\n")
	add("BACK-OUT of the plan for " + h.Device + ": it puts back what the pull of " + fmtTime(h.Pulled) +
		" showed, for the sections the plan changed. Use it only after the plan was pasted and the check was not fine.")
	if s := sensitivityLine(d, h); s != "" {
		add(s)
	}
	if d.Vendor == devconf.FamilyIOS {
		add("The change is live when the paste ends. NOTHING undoes it by itself. Keep a second terminal logged in at privilege 15 until the end.")
	} else {
		add("The switch undoes this by itself in " + fmt.Sprint(confirmMinutes(w)) + " minutes unless you type the one word after the check (see below).")
	}
	b.WriteString(c + "\n")
	b.WriteString(c + " Type this first, on " + h.Device + ", and check the name:   " + checkLine(d.Vendor) + "\n")
	add(promptCheck(d.Vendor))
	b.WriteString(c + "\n")
	b.WriteString(bc + " BACK-OUT FROM HERE: " + h.Device + " " + bc + "\n")
	for _, l := range BackoutLines(d, h, w) {
		b.WriteString(l.Text + "\n")
	}
	b.WriteString(bc + " BACK-OUT TO HERE: " + h.Device + " " + bc + "\n")
	if d.Vendor == devconf.FamilyIOS {
		b.WriteString(iosBackoutAfter(d, h, w))
	} else {
		b.WriteString(junosBackoutAfter(d, h, w))
	}
	return b.String(), nil
}

// CheckRegion verifies the whole-paste invariant on the lines between the
// banners (plan D109) as an allowlist: only the wrapper lines of the vendor
// in their places, statements of the shapes the planner emits, and comment
// lines. It returns the first fault. Junos: 'configure private', then only
// 'set <path>', 'delete <path>', 'insert <path> before|after term <term>' and
// comments, then 'show | compare | no-more', 'commit check' and the one
// 'commit confirmed N [comment "..."]' as the last line. IOS: 'configure
// terminal', then only the statements of owned shapes (a submode header and
// the leaves under it, with or without 'no') and comments, then 'end'.
func CheckRegion(vendor string, lines []string) error {
	if len(lines) < 2 {
		return fmt.Errorf("a region of %d lines", len(lines))
	}
	// A paste is ASCII, comments included: a byte outside 0x20-0x7e (an
	// em dash from a device's description, a control character) is a fault
	// wherever it stands.
	for i, l := range lines {
		for j := 0; j < len(l); j++ {
			if c := l[j]; c < 0x20 || c > 0x7e {
				return fmt.Errorf("line %d, %q, holds a byte (0x%02x) that is not printable ASCII", i+1, l, c)
			}
		}
	}
	switch vendor {
	case devconf.FamilyIOS:
		return checkIOSRegion(lines)
	case devconf.FamilyWTI:
		return checkWTIRegion(lines)
	}
	return checkJunosRegion(lines)
}

var reJunosConfirmed = regexp.MustCompile(`^commit confirmed [0-9]{1,3}( comment "[^"]*")?$`)

func checkJunosRegion(lines []string) error {
	n := len(lines)
	if n < 4 {
		return fmt.Errorf("a region of %d lines", n)
	}
	if lines[0] != "configure private" {
		return fmt.Errorf("the region starts %q, not 'configure private'", lines[0])
	}
	if lines[n-3] != "show | compare | no-more" || lines[n-2] != "commit check" || !reJunosConfirmed.MatchString(lines[n-1]) {
		return fmt.Errorf("the region ends %q, %q, %q, not 'show | compare | no-more', 'commit check', 'commit confirmed N'",
			lines[n-3], lines[n-2], lines[n-1])
	}
	for i := 1; i < n-3; i++ {
		if err := junosStatementOK(lines[i]); err != nil {
			return fmt.Errorf("line %d, %q: %w", i+1, lines[i], err)
		}
	}
	return nil
}

// junosStatementOK checks one line between the wrapper lines of a Junos
// region.
func junosStatementOK(l string) error {
	if l != strings.TrimSpace(l) || l == "" {
		return errors.New("empty or indented")
	}
	if strings.HasPrefix(l, "#") {
		return nil
	}
	if strings.ContainsAny(l, "\r\n\t") {
		return errors.New("a control character")
	}
	// outside double quotes: no pipe, no semicolon, no brace
	quoted := false
	for _, r := range l {
		switch {
		case r == '"':
			quoted = !quoted
		case !quoted && strings.ContainsRune("|;{}`", r):
			return fmt.Errorf("%q does not belong in a statement", r)
		}
	}
	t := splitTokens(l)
	switch t[0] {
	case "set", "delete":
		if len(t) < 2 {
			return fmt.Errorf("a bare %s", t[0])
		}
	case "insert":
		if len(t) < 5 || t[len(t)-3] != "before" && t[len(t)-3] != "after" || t[len(t)-2] != "term" {
			return errors.New("an insert that is not '<path> before|after term <term>'")
		}
	default:
		return fmt.Errorf("%q is not a set, delete or insert statement", t[0])
	}
	return nil
}

// iosTopStatements are the shapes of an IOS statement at the top level of a
// region (after an optional 'no'); an entry ending in a space is a prefix.
var iosTopStatements = []string{
	"aaa new-model", "aaa authentication login ", "aaa authentication enable ", "aaa authorization exec ",
	"aaa authorization commands ", "aaa authorization config-commands", "aaa accounting ", "aaa session-id ",
	"aaa group server tacacs+ ", "aaa group server radius ", "ip tacacs source-interface ", "ip radius source-interface ",
	"tacacs server ", "radius server ", "tacacs-server host ", "radius-server host ",
	"privilege exec ", "snmp-server community ", "snmp-server location ", "snmp-server contact ",
	"snmp-server host ", "snmp-server enable traps ", "snmp-server trap-source ",
	"banner login ", "ip domain name ", "ip domain list ", "clock timezone ", "ip name-server ", "ntp server ",
	"ntp authentication-key ", "ntp trusted-key ", "ntp authenticate",
	"ip access-list standard ", "ip access-list extended ", "ipv6 access-list ", "line vty ", "line con ",
}

// iosHeaderStatements are the top-level shapes that open a submode.
var iosHeaderStatements = []string{
	"aaa group server tacacs+ ", "aaa group server radius ", "tacacs server ", "radius server ",
	"ip access-list standard ", "ip access-list extended ", "ipv6 access-list ", "line vty ", "line con ",
}

// iosLeafWords are the first words of a leaf under a submode header.
var iosLeafWords = []string{"address", "key", "single-connection", "timeout", "retransmit", "port", "server",
	"permit", "deny", "remark", "login", "send-nat-address"}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if s == strings.TrimSuffix(p, " ") || strings.HasSuffix(p, " ") && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func checkIOSRegion(lines []string) error {
	n := len(lines)
	if lines[0] != "configure terminal" || lines[n-1] != "end" {
		return fmt.Errorf("the region starts %q and ends %q", lines[0], lines[n-1])
	}
	inBlock := false
	// banner is the closing delimiter of the login banner being read, "" when
	// none: every line up to it is the banner's text (any printable text, a
	// leading '!' no comment, a blank line allowed), and no section label or
	// comment may stand between the two.
	banner := ""
	for i := 1; i < n-1; i++ {
		l := lines[i]
		if banner != "" {
			if strings.ContainsAny(l, "\r\t") {
				return fmt.Errorf("line %d, inside the login banner, holds a control character", i+1)
			}
			if l == banner {
				banner = ""
			}
			continue
		}
		t := strings.TrimSpace(l)
		switch {
		case t == "":
			return fmt.Errorf("line %d is empty", i+1)
		case strings.HasPrefix(t, "!"):
			continue
		case strings.ContainsAny(l, "\r\t"):
			return fmt.Errorf("line %d, %q, holds a control character", i+1, l)
		}
		indent := len(l) - len(strings.TrimLeft(l, " "))
		no := strings.HasPrefix(t, "no ")
		body := strings.TrimPrefix(t, "no ")
		if indent == 0 {
			if !hasAnyPrefix(body, iosTopStatements) || no && strings.HasPrefix(body, "line ") {
				return fmt.Errorf("line %d, %q, is not a statement of an owned shape", i+1, t)
			}
			inBlock = !no && hasAnyPrefix(body, iosHeaderStatements)
			if f := strings.Fields(body); !no && len(f) >= 2 && f[0] == "banner" && f[1] == "login" {
				// 'banner login <d>': one delimiter character, nothing after it
				if len(f) != 3 || len(f[2]) != 1 || l != "banner login "+f[2] {
					return fmt.Errorf("line %d, %q, is not 'banner login' and one delimiter character", i+1, t)
				}
				banner = f[2]
			}
			continue
		}
		if f := strings.Fields(body); !inBlock || len(f) == 0 || !slices.Contains(iosLeafWords, f[0]) {
			return fmt.Errorf("line %d, %q, is not a leaf of an owned shape", i+1, t)
		}
	}
	if banner != "" {
		return fmt.Errorf("the login banner is not closed by its delimiter %q before 'end'", banner)
	}
	return nil
}

// --- shared text helpers -----------------------------------------------------------------

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04") }

func fmtStamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04Z") }

// ageText says how long ago a pull was.
func ageText(now, pulled time.Time) string {
	d := now.Sub(pulled)
	plural := func(n int, unit string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s ago", unit)
		}
		return fmt.Sprintf("%d %ss ago", n, unit)
	}
	switch {
	case d < time.Minute:
		return "less than a minute ago"
	case d < time.Hour:
		return plural(int(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int(d/time.Hour), "hour")
	}
	return plural(int(d/(24*time.Hour)), "day")
}

// wrapText breaks s into lines of at most width characters at spaces.
func wrapText(s string, width int) []string {
	var out []string
	cur := ""
	for _, w := range strings.Fields(s) {
		switch {
		case cur == "":
			cur = w
		case len(cur)+1+len(w) > width:
			out = append(out, cur)
			cur = w
		default:
			cur += " " + w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// confirmMinutes is the N of 'commit confirmed N': 5 when not given, and
// within the 1-60 the setting allows.
func confirmMinutes(w Wrapper) int {
	switch {
	case w.ConfirmMinutes <= 0:
		return 5
	case w.ConfirmMinutes > 60:
		return 60
	}
	return w.ConfirmMinutes
}

// commentSafe makes a word fit inside the double quotes of a commit comment:
// anything but letters, digits and . _ - @ : / is an underscore.
func commentSafe(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', strings.ContainsRune("._-@:/", r):
			return r
		}
		return '_'
	}, s)
}

// lineNumbers writes region line numbers as 'line 3', 'lines 5-9' or
// 'lines 3, 7-9'.
func lineNumbers(ns []int) string {
	ns = slices.Clone(ns)
	slices.Sort(ns)
	ns = slices.Compact(ns)
	var parts []string
	for i := 0; i < len(ns); {
		j := i
		for j+1 < len(ns) && ns[j+1] == ns[j]+1 {
			j++
		}
		if j > i {
			parts = append(parts, fmt.Sprintf("%d-%d", ns[i], ns[j]))
		} else {
			parts = append(parts, fmt.Sprint(ns[i]))
		}
		i = j + 1
	}
	word := "line"
	if len(ns) > 1 {
		word = "lines"
	}
	return word + " " + strings.Join(parts, ", ")
}

// --- the JSON shape -----------------------------------------------------------------

type jsonBasedOn struct {
	Pulled         time.Time `json:"pulled"`
	By             string    `json:"by"`
	Transport      string    `json:"transport"`
	AgeS           int64     `json:"age_s"`
	SecretsVisible bool      `json:"secrets_visible"`
}

type jsonItem struct {
	N        int    `json:"n"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Section  string `json:"section"`
	Words    string `json:"what"`
	Stmt     string `json:"statement"`
	Action   string `json:"action"`
	Fixed    bool   `json:"fixed"`
	Region   []int  `json:"region_lines,omitempty"`
}

type jsonExtra struct {
	Section string `json:"section"`
	Text    string `json:"text"`
	// Remove are the lines that remove it, in order, a submode header
	// before the line under it.
	Remove []string `json:"remove,omitempty"`
	Guard  string   `json:"guard,omitempty"`
}

// jsonRestorePoint is the restore block: the form it takes ('copy' or
// 'archive'), the file ('copy' only: the 'archive' form's file is named by the
// device), the one command, the file system and the not-lab-tested note.
type jsonRestorePoint struct {
	Mode       string `json:"mode"`
	File       string `json:"file,omitempty"`
	Command    string `json:"command"`
	FileSystem string `json:"file_system"`
	Note       string `json:"note,omitempty"`
}

type jsonDelta struct {
	Name            string      `json:"name"`
	Address         string      `json:"address,omitempty"`
	Scope           string      `json:"scope"`
	Vendor          string      `json:"vendor"`
	BasedOn         jsonBasedOn `json:"based_on"`
	Status          string      `json:"status"`
	Reason          string      `json:"reason,omitempty"`
	Irregularities  []jsonItem  `json:"irregularities"`
	Region          []string    `json:"region"`
	After           []string    `json:"after"`
	Backout         []string    `json:"backout"`
	Left            LeftCounts  `json:"left"`
	Extras          []jsonExtra `json:"extras"`
	Skipped         []Skip      `json:"skipped"`
	Withheld        []string    `json:"withheld"`
	Warnings        []string    `json:"warnings"`
	ByHand          []string    `json:"by_hand,omitempty"`
	ConfirmTimeout  int         `json:"confirm_timeout,omitempty"`
	HoldsSecret     bool        `json:"holds_secret"`
	CommandAuthLast bool        `json:"command_authorization_last,omitempty"`
	// RestorePoint is the restore block of an IOS plan made with
	// --restore-point (nil otherwise, and when the plan has nothing to paste).
	RestorePoint *jsonRestorePoint `json:"restore_point,omitempty"`
	// Converge, Cleanup and the two after it are present with --converge
	// only (D99): the cleanup region's lines, why it is refused as a whole,
	// and the extras it leaves.
	Converge       bool     `json:"converge,omitempty"`
	Cleanup        []string `json:"cleanup,omitempty"`
	CleanupAfter   []string `json:"cleanup_after,omitempty"`
	CleanupRefused string   `json:"cleanup_refused,omitempty"`
	// CleanupDeferred says the cleanup comes after the first region.
	CleanupDeferred string        `json:"cleanup_deferred,omitempty"`
	CleanupLeft     []CleanupLeft `json:"cleanup_left,omitempty"`
}

// CannotPlanJSON is the JSON object of a device that could not be planned
// (D99: status cannot-plan and the reason, every list empty), in the shape
// of JSON.
func CannotPlanJSON(h Header, reason string) ([]byte, error) {
	out := jsonDelta{Name: h.Device, Address: h.Address, Scope: h.Scope, Vendor: h.Vendor,
		BasedOn: jsonBasedOn{Pulled: h.Pulled, By: h.PulledBy, Transport: h.Transport, SecretsVisible: h.SecretsVisible},
		Status:  StatusCannotPlan, Reason: reason, Irregularities: []jsonItem{}, Region: []string{}, After: []string{}, Backout: []string{},
		Extras: []jsonExtra{}, Skipped: []Skip{}, Withheld: []string{}, Warnings: []string{}}
	if !h.Pulled.IsZero() && !h.Now.IsZero() {
		out.BasedOn.AgeS = int64(h.Now.Sub(h.Pulled).Seconds())
	}
	return json.MarshalIndent(out, "", "  ")
}

// JSON is the D99 shape of one device's output: values are always elided (a
// secret line has its '<secret>' in the text) and no option changes that.
func JSON(d Delta, h Header, w Wrapper) ([]byte, error) {
	out := jsonDelta{Name: h.Device, Address: h.Address, Scope: h.Scope, Vendor: h.Vendor,
		BasedOn: jsonBasedOn{Pulled: h.Pulled, By: h.PulledBy, Transport: h.Transport,
			AgeS: int64(h.Now.Sub(h.Pulled).Seconds()), SecretsVisible: h.SecretsVisible},
		Status: statusOf(d), Left: leftOf(d), Irregularities: []jsonItem{}, Region: []string{}, After: []string{}, Backout: []string{},
		Extras: []jsonExtra{}, Skipped: nonNilSkip(d.Skipped), Withheld: nonNil(d.Withheld), Warnings: headlineWarnings(d), ByHand: d.ByHand,
		HoldsSecret: d.HoldsSecret()}
	if out.Status == StatusCannotPlan {
		out.Reason = d.Refusal()
	}
	lineNo := map[int]int{}
	if !d.Empty() {
		rd := d
		if d.Vendor == devconf.FamilyWTI {
			// a value never reaches the JSON: the steps are made from the
			// elided copy
			rd = d.shown()
		}
		for n, rl := range RegionLines(rd, h, w) {
			text := rl.Text
			if rl.Line >= 0 && d.Vendor != devconf.FamilyWTI && d.Lines[rl.Line].Secret {
				// a value never reaches the JSON, whatever the region holds
				text = regionLineShown(d, rl)
				lineNo[rl.Line] = n + 1
			} else if rl.Line >= 0 {
				lineNo[rl.Line] = n + 1
			}
			out.Region = append(out.Region, text)
		}
		out.After = strings.Split(strings.TrimRight(After(d.shown(), h, w), "\n"), "\n")
		if d.Vendor == devconf.FamilyJunos {
			out.ConfirmTimeout = confirmMinutes(w)
		}
		if HasBackout(d) {
			for _, rl := range BackoutLines(d.shown(), h, w) {
				out.Backout = append(out.Backout, rl.Text)
			}
		}
	}
	if d.restoreShown() {
		out.RestorePoint = &jsonRestorePoint{Mode: d.Restore.Mode(), File: d.Restore.File(h), Command: d.Restore.Command(h),
			FileSystem: d.Restore.FileSystem(), Note: restoreNoteFor(d.Restore)}
	}
	for _, it := range d.Items {
		ji := jsonItem{N: it.N, Kind: it.Kind, Severity: it.Severity, Section: it.Section, Words: it.Words,
			Stmt: it.Statement, Action: it.Action, Fixed: it.Fixed}
		for _, i := range it.Lines {
			if n, ok := lineNo[i]; ok {
				ji.Region = append(ji.Region, n)
			}
		}
		out.Irregularities = append(out.Irregularities, ji)
	}
	for _, e := range d.Extras {
		je := jsonExtra{Section: e.Section, Text: e.Text, Guard: e.Guard}
		if len(e.Remove) > 0 {
			je.Remove = removeLines(e.Remove)
		}
		out.Extras = append(out.Extras, je)
	}
	if d.Converge {
		out.Converge = true
		out.CleanupRefused = d.Cleanup.Whole
		out.CleanupDeferred = d.Cleanup.Deferred
		out.CleanupLeft = d.Cleanup.Left
		for _, rl := range CleanupLines(d, h, w) {
			out.Cleanup = append(out.Cleanup, rl.Text)
		}
		if !d.Cleanup.Empty() {
			out.CleanupAfter = strings.Split(strings.TrimRight(CleanupAfter(d, h, w), "\n"), "\n")
		}
	}
	return json.MarshalIndent(out, "", "  ")
}

// shown is a copy of the delta in which every line that holds a value (and
// every undo that does) holds its elided form instead.
func (d Delta) shown() Delta {
	c := d
	c.Lines = make([]Line, len(d.Lines))
	for i, l := range d.Lines {
		if l.Secret && l.HasValue && l.Elided != "" {
			l.Text, l.HasValue = l.Elided, false
		}
		undo := make([]Line, len(l.Undo))
		for j, u := range l.Undo {
			if u.Secret && u.HasValue && u.Elided != "" {
				u.Text, u.HasValue = u.Elided, false
			}
			undo[j] = u
		}
		l.Undo = undo
		c.Lines[i] = l
	}
	c.Backout = make([]Line, len(d.Backout))
	for i, l := range d.Backout {
		if l.Secret && l.HasValue && l.Elided != "" {
			l.Text, l.HasValue = l.Elided, false
		}
		c.Backout[i] = l
	}
	if d.WTI != nil {
		w := *d.WTI
		w.Steps = make([]WTIStep, len(d.WTI.Steps))
		for i, st := range d.WTI.Steps {
			st.Enter = st.EnterShown
			w.Steps[i] = st
		}
		c.WTI = &w
	}
	return c
}

// regionLineShown is a region line of a secret statement with its value
// elided (a '<secret>' mark where it was).
func regionLineShown(d Delta, rl RegionLine) string {
	l := d.Lines[rl.Line]
	if rl.Comment {
		return "# " + l.Shown()
	}
	if len(l.Context) > 0 {
		return strings.Repeat(" ", len(l.Context)) + l.Shown()
	}
	return l.Shown()
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func nonNilSkip(s []Skip) []Skip {
	if s == nil {
		return []Skip{}
	}
	return s
}
