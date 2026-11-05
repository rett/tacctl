package radius

// 'tacctl log tail|search|failures|accounting' with filters (--since,
// --until, --user, --device, --type) or --json. Without either the commands
// run as they always did (logs.go). What the filters match here:
//
//   - the auth log (tacctl-auth.log): the time at the start of the line,
//     the user (the last 'user=') and the device ('client=', the address
//     the request came from);
//   - the daemon log: the time at the start of the line ('Fri Oct  2
//     14:07:40 2026 : ...') and the user, when the line names it in
//     brackets ('[alice]' or '[alice/<via Auth-Type = PAP>]'). The daemon
//     log names the clients it serves by name and not by address, so
//     --device cannot be applied to it: the section says so and shows no
//     line;
//   - the accounting detail file: a record is a paragraph; its time is the
//     first line's, its user 'User-Name', its device the address in
//     'NAS-IP-Address', 'NAS-IPv6-Address', 'Packet-Src-IP-Address' or
//     'Packet-Src-IPv6-Address', and --type login is 'Acct-Status-Type'
//     Start or Stop. RADIUS accounting has no change or command records:
//     --type change and --type command say so and show no record.

import (
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/ui"
)

var _ backend.FilteredFollower = (*Module)(nil)

const daemonTimeForm = "Mon Jan _2 15:04:05 2006"

// Which log a line is of.
const (
	logAuth   = "auth"
	logDaemon = "daemon"
)

func (m *Module) filtered() bool {
	f := m.env.LogFilter
	return f.Active() || f.JSON
}

// lineMatch reports whether a line of the auth or daemon log passes the
// filters f at time at (the zero time: the line's own), and the entry it is.
func (m *Module) lineMatch(f backend.LogFilter, kind, line string, at time.Time) (backend.LogLine, bool) {
	l := backend.LogLine{Backend: "radius", Log: kind, Message: line}
	var lineAt time.Time
	switch kind {
	case logAuth:
		if s, ok := ParseAuthLine(line); ok {
			lineAt, l.User, l.Address, l.Outcome = s.Time, s.User, s.Address, s.Outcome
		}
	default:
		if len(line) >= len(daemonTimeForm) {
			lineAt, _ = time.ParseInLocation(daemonTimeForm, line[:len(daemonTimeForm)], time.Local)
		}
		if f.User != "" && !daemonNames(line, f.User) {
			return l, false
		}
	}
	if at.IsZero() {
		at = lineAt
	}
	l.Time = backend.FormatLogTime(at)
	switch {
	case f.HasWindow() && !f.InWindow(at):
		return l, false
	case kind == logAuth && f.User != "" && l.User != f.User:
		return l, false
	case f.Device != "" && (kind != logAuth || !f.MatchAddr(l.Address)):
		return l, false
	}
	if m.env.DeviceName != nil && l.Address != "" {
		l.Device = m.env.DeviceName(l.Address)
	}
	return l, true
}

// daemonNames reports whether a line of the daemon log names the user in
// brackets, as '[alice]' or '[alice/<via Auth-Type = PAP>]'.
func daemonNames(line, user string) bool {
	return strings.Contains(line, "["+user+"]") || strings.Contains(line, "["+user+"/")
}

// readFileLines is the lines of a file (nil when it cannot be read).
func readFileLines(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// logFiltered is Log for tail, search and failures with filters or --json.
func (m *Module) logFiltered(sub, arg string, w io.Writer) error {
	f := m.env.LogFilter
	head := func(text string) {
		if !f.JSON {
			echo(w, "")
			echo(w, text)
			echo(w, rule)
		}
	}
	end := func() {
		if !f.JSON {
			echo(w, "")
		}
	}
	emit := func(l backend.LogLine) {
		if f.JSON {
			_, _ = io.WriteString(w, backend.JSONLine(l))
		} else {
			_, _ = io.WriteString(w, l.Message+"\n")
		}
	}
	switch sub {
	case "tail":
		count := arg
		if count == "" {
			count = "20"
		}
		n, ok := backend.CountArg(count)
		if !ok {
			_, _ = io.WriteString(m.env.Out.Stderr, "tail: invalid number of lines: '"+count+"'\n")
			return backend.ErrFailed
		}
		head(ui.Bold + "Recent RADIUS Authentications" + ui.NC + " (" + m.L.AuthLog + ")")
		m.scanLog(w, logAuth, m.L.AuthLog, "  No log entries found.", n, emit, nil)
		if nonEmpty(m.L.DaemonLog) {
			if !f.JSON {
				echo(w, "")
				echo(w, ui.Bold+"FreeRADIUS Daemon Log"+ui.NC+" ("+m.L.DaemonLog+")")
				echo(w, rule)
			}
			m.scanLog(w, logDaemon, m.L.DaemonLog, "", n, emit, nil)
		}
		end()
	case "search":
		if arg == "" {
			m.env.Out.Error("Usage: tacctl log search <username>")
			return backend.ErrFailed
		}
		head(ui.Bold + "RADIUS log entries matching '" + arg + "'" + ui.NC)
		re, err := compileBRE(arg)
		if err != nil {
			_, _ = io.WriteString(m.env.Out.Stderr, "grep: "+err.Error()+"\n")
		}
		found := false
		for _, lg := range []struct{ kind, path string }{{logAuth, m.L.AuthLog}, {logDaemon, m.L.DaemonLog}} {
			if err != nil {
				break
			}
			if m.scanLog(w, lg.kind, lg.path, "", -1, emit, re) {
				found = true
			}
		}
		if !found && !f.JSON {
			echo(w, "  No matches found.")
		}
		end()
	case "failures":
		title, none := "RADIUS Authentication Failures (last 24 hours)", "No failures in the last 24 hours"
		g := f
		if f.HasWindow() {
			title, none = "RADIUS Authentication Failures ("+f.Window()+")", "No failures "+f.Window()
		} else {
			g.Since = m.now().Add(-24 * time.Hour)
		}
		head(ui.Bold + title + ui.NC)
		found := false
		for _, line := range readFileLines(m.L.AuthLog) {
			if !strings.Contains(line, " Access-Reject ") {
				continue
			}
			if l, ok := m.lineMatch(g, logAuth, line, time.Time{}); ok {
				found = true
				emit(l)
			}
		}
		if !found && !f.JSON {
			echo(w, "  "+ui.Green+none+ui.NC)
		}
		end()
	}
	return nil
}

// scanLog writes the last n entries (all when n < 0) of one log that pass
// the filters (and match re, when it is not nil), and reports whether it
// wrote any. none is the line for a log with nothing in it.
func (m *Module) scanLog(w io.Writer, kind, path, none string, n int, emit func(backend.LogLine), re *regexp.Regexp) bool {
	f := m.env.LogFilter
	if !nonEmpty(path) {
		if none != "" && !f.JSON {
			echo(w, none)
		}
		return false
	}
	if f.Device != "" && kind == logDaemon {
		f.Note(w, m.env.Out.Stderr, "--device cannot be applied to the daemon log (it names clients, not addresses); no lines shown.")
		return false
	}
	ring := &ringOf{n: n}
	for _, line := range readFileLines(path) {
		if re != nil && !re.MatchString(line) {
			continue
		}
		if l, ok := m.lineMatch(f, kind, line, time.Time{}); ok {
			ring.add(l)
		}
	}
	for _, l := range ring.items {
		emit(l)
	}
	if len(ring.items) == 0 && re == nil && f.Active() && !f.JSON {
		echo(w, "  No matching entries.")
	}
	return len(ring.items) > 0
}

// ringOf keeps the last n entries added (all when n < 0).
type ringOf struct {
	n     int
	items []backend.LogLine
}

func (r *ringOf) add(l backend.LogLine) {
	if r.n == 0 {
		return
	}
	r.items = append(r.items, l)
	if r.n > 0 && len(r.items) > r.n {
		r.items = r.items[len(r.items)-r.n:]
	}
}

// FollowFiltered is backend.FilteredFollower: the auth log and the daemon
// log, new lines only, the ones that pass the filters (each has the time it
// arrives, for --since and --until).
func (m *Module) FollowFiltered(f backend.LogFilter) []backend.FollowSource {
	src := func(kind, path string) backend.FollowSource {
		return backend.FollowSource{
			Argv: []string{"tail", "-F", "-q", "-n", "0", path},
			Line: func(line string) (string, bool) {
				l, ok := m.lineMatch(f, kind, line, m.now())
				if !ok {
					return "", false
				}
				if f.JSON {
					return strings.TrimSuffix(backend.JSONLine(l), "\n"), true
				}
				return line, true
			},
		}
	}
	if f.Device != "" {
		return []backend.FollowSource{src(logAuth, m.L.AuthLog)}
	}
	return []backend.FollowSource{src(logAuth, m.L.AuthLog), src(logDaemon, m.L.DaemonLog)}
}

// --- accounting ---------------------------------------------------------------

// acctRecord is a record of the detail file: its time (the first line's)
// and its attributes in order.
type acctRecord struct {
	text  string
	at    time.Time
	attrs map[string]string
}

// parseDetail is the record a paragraph of the detail file is.
func parseDetail(text string) acctRecord {
	r := acctRecord{text: text, attrs: map[string]string{}}
	lines := strings.Split(text, "\n")
	if len(lines) > 0 {
		r.at, _ = time.ParseInLocation(daemonTimeForm, strings.TrimSpace(lines[0]), time.Local)
	}
	for _, l := range lines[1:] {
		name, val, ok := strings.Cut(strings.TrimSpace(l), " = ")
		if !ok {
			continue
		}
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		r.attrs[name] = val
	}
	return r
}

// detailAddrs are the attributes whose address is the device's.
var detailAddrs = []string{"NAS-IP-Address", "NAS-IPv6-Address", "Packet-Src-IP-Address", "Packet-Src-IPv6-Address"}

// address is the device address of a record ("" when it has none that
// matches the filter's, else the first it has).
func (r acctRecord) address(f backend.LogFilter) string {
	first := ""
	for _, k := range detailAddrs {
		if a := backend.CanonAddr(r.attrs[k]); a != "" {
			if first == "" {
				first = a
			}
			if f.MatchAddr(a) {
				return a
			}
		}
	}
	return first
}

// accountingFiltered is Accounting for filters or --json.
func (m *Module) accountingFiltered(w io.Writer, count string) error {
	f := m.env.LogFilter
	if !f.JSON {
		echo(w, "")
		echo(w, ui.Bold+"Recent RADIUS Accounting Records"+ui.NC)
		echo(w, rule)
	}
	if !isFile(m.L.AcctLog) {
		if !f.JSON {
			echo(w, "  No accounting log found at "+m.L.AcctLog)
			echo(w, "")
		}
		return nil
	}
	if f.Type == backend.TypeChange || f.Type == backend.TypeCommand {
		f.Note(w, m.env.Out.Stderr, "RADIUS accounting has no "+f.Type+" records (only login: Acct-Status-Type Start or Stop).")
		if !f.JSON {
			echo(w, "")
		}
		return nil
	}
	data, err := os.ReadFile(m.L.AcctLog)
	if err != nil {
		return nil
	}
	var recs []acctRecord
	if text := strings.Trim(string(data), "\n"); text != "" {
		for _, p := range reBlankRuns.Split(text, -1) {
			r := parseDetail(p)
			switch {
			case f.HasWindow() && !f.InWindow(r.at):
			case f.User != "" && r.attrs["User-Name"] != f.User:
			case f.Device != "" && !f.MatchAddr(r.address(f)):
			case f.Type == backend.TypeLogin && r.attrs["Acct-Status-Type"] != "Start" && r.attrs["Acct-Status-Type"] != "Stop":
			default:
				recs = append(recs, r)
			}
		}
	}
	if n, numeric := awkStrnum(count); numeric && float64(len(recs)) > n {
		recs = recs[len(recs)-int(max(n, 0)):]
	}
	for _, r := range recs {
		if !f.JSON {
			_, _ = io.WriteString(w, r.text+"\n\n")
			continue
		}
		addr := r.address(f)
		o := struct {
			Time       string            `json:"time,omitempty"`
			Backend    string            `json:"backend"`
			Log        string            `json:"log"`
			User       string            `json:"user,omitempty"`
			Address    string            `json:"address,omitempty"`
			Device     string            `json:"device,omitempty"`
			Attributes map[string]string `json:"attributes"`
		}{backend.FormatLogTime(r.at), "radius", "accounting", r.attrs["User-Name"], addr, "", r.attrs}
		if m.env.DeviceName != nil && addr != "" {
			o.Device = m.env.DeviceName(addr)
		}
		_, _ = io.WriteString(w, backend.JSONLine(o))
	}
	if len(recs) == 0 && !f.JSON {
		echo(w, "  No matching records.")
	}
	if !f.JSON {
		echo(w, "")
	}
	return nil
}
