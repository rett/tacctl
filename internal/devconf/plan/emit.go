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
	// Legacy is the IOS 12.x rendering.
	Legacy bool
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
	return junosRegion(d, h, w)
}

// Region is the banner pair and the lines between them, as text.
func Region(d Delta, h Header, w Wrapper) string {
	if d.Empty() {
		return ""
	}
	var b strings.Builder
	bc := bannerChar(d.Vendor)
	b.WriteString(bc + " PASTE FROM HERE: " + h.Device + " " + bc + "\n")
	for _, l := range RegionLines(d, h, w) {
		b.WriteString(l.Text + "\n")
	}
	b.WriteString(bc + " PASTE TO HERE: " + h.Device + " " + bc + "\n")
	return b.String()
}

// Plain is the region with every comment line and both banners stripped
// (D99): no comment at all. A --no-secrets plan has no plain form.
func Plain(d Delta, h Header, w Wrapper) (string, error) {
	if d.Counts.Placeholders > 0 {
		return "", ErrNoSecretsPlain
	}
	var b strings.Builder
	for _, l := range RegionLines(d, h, w) {
		if !l.Comment {
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
	if d.Empty() {
		return b.String()
	}
	b.WriteString(Region(d, h, w))
	b.WriteString(After(d, h, w))
	return b.String()
}

// After is the text after the region (outside it): what to read, the check
// and the one line to type, the back-out as comments, what not to do.
func After(d Delta, h Header, w Wrapper) string {
	if d.Empty() {
		return ""
	}
	if d.Vendor == devconf.FamilyIOS {
		return iosAfter(d, h, w)
	}
	return junosAfter(d, h, w)
}

// CheckRegion verifies the whole-paste invariant on the lines between the
// banners (plan D109): the wrapper's first and last line, no line that
// confirms, saves or leaves, no comment but the labels and the placeholder
// lines. It returns the first fault.
func CheckRegion(vendor string, lines []string) error {
	if len(lines) < 2 {
		return fmt.Errorf("a region of %d lines", len(lines))
	}
	ios := vendor == devconf.FamilyIOS
	leader := commentLeader(vendor)
	first, last := lines[0], lines[len(lines)-1]
	switch {
	case ios && (first != "configure terminal" || last != "end"):
		return fmt.Errorf("the region starts %q and ends %q", first, last)
	case !ios && (first != "configure private" || !strings.HasPrefix(last, "commit confirmed ")):
		return fmt.Errorf("the region starts %q and ends %q", first, last)
	}
	for i, l := range lines {
		t := strings.TrimSpace(l)
		if t == "" {
			return fmt.Errorf("line %d is empty", i+1)
		}
		if strings.HasPrefix(t, leader) {
			continue
		}
		f := strings.Fields(t)
		bad := false
		switch f[0] {
		case "commit":
			check := len(f) >= 2 && f[1] == "check"
			confirmed := len(f) >= 2 && f[1] == "confirmed" && i == len(lines)-1
			bad = !check && !confirmed
		case "exit", "quit", "rollback", "write", "copy", "reload", "load", "request", "file", "configure":
			bad = i != 0 || t != "configure private" && t != "configure terminal"
		case "delete":
			bad = ios // a Junos delete is a statement; an IOS delete is a file command
		case "end":
			bad = !ios || i != len(lines)-1
		}
		if bad {
			return fmt.Errorf("line %d, %q, does not belong in a region", i+1, t)
		}
		if !ios && strings.HasPrefix(t, "commit confirmed ") && i != len(lines)-1 {
			return fmt.Errorf("line %d: commit confirmed is not the last line", i+1)
		}
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
	Remove  string `json:"remove,omitempty"`
	Guard   string `json:"guard,omitempty"`
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
	Extras          []jsonExtra `json:"extras"`
	Skipped         []Skip      `json:"skipped"`
	Withheld        []string    `json:"withheld"`
	Warnings        []string    `json:"warnings"`
	ConfirmTimeout  int         `json:"confirm_timeout,omitempty"`
	HoldsSecret     bool        `json:"holds_secret"`
	CommandAuthLast bool        `json:"command_authorization_last,omitempty"`
}

// JSON is the D99 shape of one device's output: values are always elided (a
// secret line has its '<secret>' in the text) and no option changes that.
func JSON(d Delta, h Header, w Wrapper) ([]byte, error) {
	out := jsonDelta{Name: h.Device, Address: h.Address, Scope: h.Scope, Vendor: h.Vendor,
		BasedOn: jsonBasedOn{Pulled: h.Pulled, By: h.PulledBy, Transport: h.Transport,
			AgeS: int64(h.Now.Sub(h.Pulled).Seconds()), SecretsVisible: h.SecretsVisible},
		Status: statusOf(d), Irregularities: []jsonItem{}, Region: []string{}, After: []string{},
		Extras: []jsonExtra{}, Skipped: nonNilSkip(d.Skipped), Withheld: nonNil(d.Withheld), Warnings: nonNil(d.Warnings),
		HoldsSecret: d.HoldsSecret()}
	lineNo := map[int]int{}
	if !d.Empty() {
		for n, rl := range RegionLines(d, h, w) {
			text := rl.Text
			if rl.Line >= 0 && d.Lines[rl.Line].Secret {
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
			je.Remove = e.Remove[0].Shown()
		}
		out.Extras = append(out.Extras, je)
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
