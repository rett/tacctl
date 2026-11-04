package backend

// The filters of 'tacctl log tail|search|failures|accounting' (--since,
// --until, --user, --device, --type, --json): what the command parsed, and
// the helpers every backend reads its logs with. A backend applies them to
// the lines of its own logs (what each can match is in docs/cli/maintenance.md)
// and says so when a filter cannot be applied to a log.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// LogTimeLayout is the time as journalctl is given it, in local time.
const LogTimeLayout = "2006-01-02 15:04:05"

// The values of LogFilter.Type.
const (
	// TypeLogin: a session's start or stop.
	TypeLogin = "login"
	// TypeChange: a configuration change (a Junos change-log record).
	TypeChange = "change"
	// TypeCommand: a command a person ran.
	TypeCommand = "command"
)

// LogTypes are the values of --type.
var LogTypes = []string{TypeLogin, TypeChange, TypeCommand}

// LogFilter is the filters of one 'log' command. The zero value filters
// nothing.
type LogFilter struct {
	// Since and Until bound the time of an entry, both inclusive (zero: no
	// bound).
	Since, Until time.Time
	// User is the user name an entry must name ("": any).
	User string
	// Device is the device or host as typed; Addrs are its canonical
	// addresses, which an entry's device must be one of.
	Device string
	Addrs  []string
	// Type is the kind of accounting record (accounting only; "": any).
	Type string
	// JSON writes one JSON object per entry, with no headings.
	JSON bool
}

// Active reports whether any filter selects entries (JSON only changes the
// form of the output).
func (f LogFilter) Active() bool {
	return f.HasWindow() || f.User != "" || f.Device != "" || f.Type != ""
}

// HasWindow reports whether --since or --until is set.
func (f LogFilter) HasWindow() bool { return !f.Since.IsZero() || !f.Until.IsZero() }

// InWindow reports whether t is within the bounds. An entry whose time is
// not known (zero) is outside a bound.
func (f LogFilter) InWindow(t time.Time) bool {
	if !f.HasWindow() {
		return true
	}
	if t.IsZero() {
		return false
	}
	return (f.Since.IsZero() || !t.Before(f.Since)) && (f.Until.IsZero() || !t.After(f.Until))
}

// MatchAddr reports whether addr (any text of an address) is one of the
// device's addresses.
func (f LogFilter) MatchAddr(addr string) bool {
	a := CanonAddr(addr)
	if a == "" {
		return false
	}
	for _, x := range f.Addrs {
		if x == a {
			return true
		}
	}
	return false
}

// JournalArgs are the journalctl arguments of the window ("--since" is left
// to the caller when it has a default of its own: sinceDefault).
func (f LogFilter) JournalArgs(sinceDefault string) []string {
	var out []string
	switch {
	case !f.Since.IsZero():
		out = append(out, "--since", f.Since.Format(LogTimeLayout))
	case sinceDefault != "":
		out = append(out, "--since", sinceDefault)
	}
	if !f.Until.IsZero() {
		out = append(out, "--until", f.Until.Format(LogTimeLayout))
	}
	return out
}

// Window is the window as a heading says it ("since 2026-11-04 10:00:00",
// "until ...", "from ... to ..."); "" without one.
func (f LogFilter) Window() string {
	switch {
	case !f.Since.IsZero() && !f.Until.IsZero():
		return "from " + f.Since.Format(LogTimeLayout) + " to " + f.Until.Format(LogTimeLayout)
	case !f.Since.IsZero():
		return "since " + f.Since.Format(LogTimeLayout)
	case !f.Until.IsZero():
		return "until " + f.Until.Format(LogTimeLayout)
	}
	return ""
}

// timeUnits is the unit words of a relative time.
const timeUnits = `s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks`

var (
	reTimeMinus = regexp.MustCompile(`^-\s*(\d{1,6})\s*(` + timeUnits + `)$`)
	reTimeAgo   = regexp.MustCompile(`^(\d{1,6})\s*(` + timeUnits + `)\s+ago$`)
)

// LogTimeForms is the forms ParseLogTime takes, for the usage message.
const LogTimeForms = "YYYY-MM-DD[ HH:MM[:SS]], now, today, yesterday, -1h, 2 hours ago"

// ParseLogTime is the time a --since or --until value names, in local time,
// relative to now. The forms: "YYYY-MM-DD", "YYYY-MM-DD HH:MM" and
// "YYYY-MM-DD HH:MM:SS" (a date alone is that day's midnight; a "T" may
// stand for the space), "now", "today" and "yesterday" (midnight), "-<n><unit>"
// and "<n> <unit> ago" with the units s, m, h, d and w (and their long
// words: seconds, minutes, hours, days, weeks). Anything else is an error.
func ParseLogTime(s string, now time.Time) (time.Time, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	now = now.Local()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	switch v {
	case "now":
		return now, nil
	case "today":
		return day, nil
	case "yesterday":
		return day.AddDate(0, 0, -1), nil
	}
	for _, re := range []*regexp.Regexp{reTimeMinus, reTimeAgo} {
		if m := re.FindStringSubmatch(v); m != nil {
			n, _ := strconv.Atoi(m[1])
			return agoBy(now, n, m[2]), nil
		}
	}
	if len(v) > 10 && v[10] == 't' {
		v = v[:10] + " " + v[11:]
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, v, now.Location()); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time '%s' (use %s)", s, LogTimeForms)
}

// agoBy is now minus n of the unit.
func agoBy(now time.Time, n int, unit string) time.Time {
	switch unit[0] {
	case 's':
		return now.Add(-time.Duration(n) * time.Second)
	case 'm':
		return now.Add(-time.Duration(n) * time.Minute)
	case 'h':
		return now.Add(-time.Duration(n) * time.Hour)
	case 'd':
		return now.AddDate(0, 0, -n)
	}
	return now.AddDate(0, 0, -7*n)
}

// JSONLine is v as one line of JSON, with "<", ">" and "&" as they are, and
// its newline.
func JSONLine(v any) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if enc.Encode(v) != nil {
		return "null\n"
	}
	return b.String()
}

// LineSink is an io.Writer that hands each complete line written to it
// (without its newline; a last one without a newline at Flush) to Fn.
type LineSink struct {
	Fn  func(line string)
	buf []byte
}

// Write implements io.Writer.
func (s *LineSink) Write(p []byte) (int, error) {
	s.buf = append(s.buf, p...)
	for {
		i := bytes.IndexByte(s.buf, '\n')
		if i < 0 {
			break
		}
		s.Fn(string(s.buf[:i]))
		s.buf = s.buf[i+1:]
	}
	return len(p), nil
}

// Flush hands over a last line that has no newline.
func (s *LineSink) Flush() {
	if len(s.buf) > 0 {
		s.Fn(string(s.buf))
		s.buf = nil
	}
}

// Ring keeps the last N strings added (all of them when N < 0).
type Ring struct {
	N     int
	items []string
}

// Add keeps s.
func (r *Ring) Add(s string) {
	if r.N == 0 {
		return
	}
	r.items = append(r.items, s)
	if r.N > 0 && len(r.items) > r.N {
		r.items = r.items[len(r.items)-r.N:]
	}
}

// Items are the strings kept, oldest first.
func (r *Ring) Items() []string { return r.items }

// CountArg is the number of lines a count argument asks for: a plain
// number, or '-N' as tail reads it. ok is false for anything else.
func CountArg(s string) (n int, ok bool) {
	s = strings.TrimPrefix(s, "-")
	v, err := strconv.ParseUint(s, 10, 31)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

// FollowSource is one command a filtered 'log tail -f' runs: Argv prints the
// new entries, and Line turns each into the text to write ("" and false:
// leave it out).
type FollowSource struct {
	Argv []string
	Line func(line string) (string, bool)
}

// FilteredFollower is a Follower that can apply a LogFilter (and the JSON
// form) to the entries it follows. A backend without it is not followed
// while a filter is set.
type FilteredFollower interface {
	FollowFiltered(f LogFilter) []FollowSource
}

// LogLine is one entry of a log as 'log ... --json' writes it: the time (UTC,
// RFC 3339, left out when the entry has none), the backend, where it was
// read (unit or log), the message and what could be read from it.
type LogLine struct {
	Time    string `json:"time,omitempty"`
	Backend string `json:"backend"`
	Unit    string `json:"unit,omitempty"`
	Log     string `json:"log,omitempty"`
	Message string `json:"message"`
	User    string `json:"user,omitempty"`
	Address string `json:"address,omitempty"`
	Device  string `json:"device,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

// FormatLogTime is t as a LogLine has it ("" for the zero time).
func FormatLogTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// Note is a note about a filter a backend cannot apply: on standard
// error with --json, so that the output stays one object per line, else a
// line of the section on w.
func (f LogFilter) Note(w io.Writer, errw io.Writer, text string) {
	if f.JSON {
		_, _ = io.WriteString(errw, "tacctl: "+text+"\n")
		return
	}
	_, _ = io.WriteString(w, "  "+text+"\n")
}
