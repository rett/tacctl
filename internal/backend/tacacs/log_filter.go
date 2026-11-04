package tacacs

// 'tacctl log tail|search|failures|accounting' with filters (--since, --until,
// --user, --device, --type) or --json. Without either the commands run as
// they always did (log.go). What the filters match here:
//
//   - the journal (tail, search, failures): --since and --until go to
//     journalctl; --user matches a line that names the user in brackets
//     ('accepting user [alice] from [192.0.2.10] ...'); --device matches the
//     address a tacquito line names for the device that asked ('from [A]',
//     'bad secret detected for ip [A:port]', 'remote [A:port] has no secret
//     providers', the debug 'matches remote [A]'). A line that names no
//     device never matches --device.
//   - the accounting logs: the time of the logger's prefix, the record's
//     "User" and "Device" (a record written before patch 0006 has no device),
//     and its kind (acctType).

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

var _ backend.FilteredFollower = (*Backend)(nil)

// filtered reports whether the command runs with filters or --json.
func (b *Backend) filtered() bool {
	f := b.env.LogFilter
	return f.Active() || f.JSON
}

// journalMatch reports whether the journal message passes --user and
// --device.
func journalMatch(f backend.LogFilter, msg string) bool {
	if f.User != "" && !strings.Contains(msg, "["+f.User+"]") {
		return false
	}
	if f.Device != "" {
		s, ok := ParseSightingLine(msg, time.Time{})
		if !ok || !f.MatchAddr(s.Address) {
			return false
		}
	}
	return true
}

// journalLine is one line of journalctl's output as it is written for the
// command: the text itself, or with --json the entry as an object; with the
// message it carries ("" when the line is not an entry).
func (b *Backend) journalLine(f backend.LogFilter, line string) (out, msg string, at time.Time, ok bool) {
	if !f.JSON {
		return line, line, time.Time{}, true
	}
	var e journalEntry
	if json.Unmarshal([]byte(line), &e) != nil || e.Message == nil {
		return "", "", time.Time{}, false
	}
	msg = e.message()
	if us, err := strconv.ParseInt(e.Realtime, 10, 64); err == nil {
		at = time.UnixMicro(us)
	}
	l := backend.LogLine{Time: backend.FormatLogTime(at), Backend: "tacacs", Unit: e.Unit, Message: msg}
	if s, ok := ParseSightingLine(msg, at); ok {
		l.User, l.Address, l.Outcome = s.User, s.Address, s.Outcome
		if b.env.DeviceName != nil && s.Address != "" {
			l.Device = b.env.DeviceName(s.Address)
		}
	}
	return strings.TrimSuffix(backend.JSONLine(l), "\n"), msg, at, true
}

// journalScan runs journalctl over every listener's unit for the window of
// the filters (sinceDefault when it sets no start) and hands the lines it
// writes, with their messages, to keep; the lines keep accepts go to ring.
// count is passed to journalctl as -n when it is not "". It reports whether
// journalctl ran well.
func (b *Backend) journalScan(ctx context.Context, sinceDefault, count string, keep func(msg string) bool, ring *backend.Ring) bool {
	f := b.env.LogFilter
	args := append(b.journalUnits(), "--no-pager")
	args = append(args, f.JournalArgs(sinceDefault)...)
	if f.JSON {
		args = append(args, "-o", "json")
	}
	if count != "" {
		args = append(args, "-n", count)
	}
	sink := &backend.LineSink{Fn: func(line string) {
		if out, msg, _, ok := b.journalLine(f, line); ok && journalMatch(f, msg) && keep(msg) {
			ring.Add(out)
		}
	}}
	res, err := b.env.Runner.Run(ctx, execx.Cmd{Name: "journalctl", Args: args, Stdout: sink, Stderr: io.Discard})
	sink.Flush()
	return err == nil && res.Code == 0
}

// logFiltered is Log for tail, search and failures with filters or --json.
func (b *Backend) logFiltered(ctx context.Context, sub, arg string, w io.Writer) error {
	f := b.env.LogFilter
	heading := func(text string) {
		if !f.JSON {
			echoLine(w, "\n"+ui.Bold+text+ui.NC)
			writeString(w, rule+"\n")
		}
	}
	end := func() {
		if !f.JSON {
			writeString(w, "\n")
		}
	}
	all := func(string) bool { return true }
	switch sub {
	case "tail":
		count := or(arg, "20")
		n, ok := backend.CountArg(count)
		if !ok {
			writeString(b.env.Out.Stderr, "tail: invalid number of lines: '"+count+"'\n")
			return backend.ErrFailed
		}
		heading("Recent TACACS+ Log Entries")
		ring := &backend.Ring{N: n}
		// journalctl counts the entries only when no filter of ours is left
		// to apply after it.
		pass := ""
		if f.User == "" && f.Device == "" {
			pass = strconv.Itoa(n)
		}
		ran := b.journalScan(ctx, "", pass, all, ring)
		b.writeEntries(w, ring.Items(), ran, "  No matching entries.\n")
		end()
	case "search":
		if arg == "" {
			b.out().Error("Usage: tacctl log search <username>")
			return backend.ErrFailed
		}
		heading("Log entries matching '" + arg + "'")
		keep := func(string) bool { return false }
		if re, err := grepRegexp(arg); err == nil {
			keep = re.MatchString
		}
		since := ""
		if !f.HasWindow() {
			since = "7 days ago"
		}
		ring := &backend.Ring{N: -1}
		b.journalScan(ctx, since, "", keep, ring)
		b.writeEntries(w, ring.Items(), true, "  No matches found.\n")
		end()
	case "failures":
		title, none := "Authentication Failures (last 24 hours)", "No failures in the last 24 hours"
		since := "24 hours ago"
		if f.HasWindow() {
			title, none, since = "Authentication Failures ("+f.Window()+")", "No failures "+f.Window(), ""
		}
		heading(title)
		ring := &backend.Ring{N: -1}
		b.journalScan(ctx, since, "", failureRE.MatchString, ring)
		if items := ring.Items(); len(items) > 0 {
			writeString(w, strings.Join(items, "\n")+"\n")
		} else if !f.JSON {
			echoLine(w, "  "+ui.Green+none+ui.NC)
		}
		end()
	}
	return nil
}

// writeEntries writes the lines kept, else the line that says there were
// none (not with --json); none is it for a journal that was read.
func (b *Backend) writeEntries(w io.Writer, items []string, ran bool, none string) {
	switch {
	case len(items) > 0:
		writeString(w, strings.Join(items, "\n")+"\n")
	case b.env.LogFilter.JSON:
	case !ran:
		writeString(w, "  No log entries found.\n")
	default:
		writeString(w, none)
	}
}

// FollowFiltered is backend.FilteredFollower: the journal of every
// listener's unit, new entries only, the ones that pass the filters. A
// followed entry has the time it arrives, for --since and --until.
func (b *Backend) FollowFiltered(f backend.LogFilter) []backend.FollowSource {
	argv := append(append([]string{"journalctl"}, b.journalUnits()...), "--no-pager", "-f", "-n", "0")
	if f.JSON {
		argv = append(argv, "-o", "json")
	}
	return []backend.FollowSource{{Argv: argv, Line: func(line string) (string, bool) {
		out, msg, at, ok := b.journalLine(f, line)
		if !ok || !journalMatch(f, msg) {
			return "", false
		}
		if at.IsZero() {
			at = b.now()
		}
		if !f.InWindow(at) {
			return "", false
		}
		return out, true
	}}}
}

// --- accounting ---------------------------------------------------------------

// acctRec is the part of a record the filters read.
type acctRec struct {
	At     time.Time
	User   string
	Device string
	Flags  int
	Args   []string
}

const acctTimeForm = "2006/01/02 15:04:05"

// parseAcct is the record on a line of the accounting log; false for a line
// that is not one.
func parseAcct(line string) (acctRec, bool) {
	i := strings.Index(line, acctRecordMark)
	if i < 0 {
		return acctRec{}, false
	}
	var v struct {
		Flags  int
		User   string
		Device string
		Args   []string
	}
	if json.Unmarshal([]byte(line[i:]), &v) != nil {
		return acctRec{}, false
	}
	r := acctRec{User: v.User, Device: v.Device, Flags: v.Flags, Args: v.Args}
	if len(line) >= len(acctTimeForm) {
		if t, err := time.ParseInLocation(acctTimeForm, line[:len(acctTimeForm)], time.Local); err == nil {
			r.At = t
		}
	}
	return r, true
}

// reChangeCmd is the command of a Junos change-log record: the verb, a
// colon, then the configuration path in brackets ('set: [interfaces ge-0/0/1
// description] ...').
var reChangeCmd = regexp.MustCompile(`^[a-z][a-z-]*: \[`)

// acctType is the kind of a record (backend.TypeLogin, TypeChange,
// TypeCommand; "" for another, a watchdog update):
//   - a record with a command (a non-empty "cmd=" argument) is a change
//     when the command has the Junos change-log shape, else a command;
//   - a record without one is a login when it starts or stops a session
//     (the START and STOP flags, 2 and 4).
func acctType(r acctRec) string {
	for _, a := range r.Args {
		if v, ok := strings.CutPrefix(a, "cmd="); ok {
			v = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), junosCR))
			switch {
			case v == "":
			case reChangeCmd.MatchString(v):
				return backend.TypeChange
			default:
				return backend.TypeCommand
			}
		}
	}
	if r.Flags&(2|4) != 0 {
		return backend.TypeLogin
	}
	return ""
}

// acctMatch reports whether the line is a record that passes the filters.
func acctMatch(f backend.LogFilter, line string) (acctRec, bool) {
	r, ok := parseAcct(line)
	switch {
	case !ok:
		return r, false
	case f.HasWindow() && !f.InWindow(r.At):
		return r, false
	case f.User != "" && r.User != f.User:
		return r, false
	case f.Device != "" && !f.MatchAddr(r.Device):
		return r, false
	case f.Type != "" && acctType(r) != f.Type:
		return r, false
	}
	return r, true
}

// acctJSON is the record as an object: its fields decoded as the display
// has them, "Device" the address as it is, and after them "DeviceName" (the
// registered device or host at that address, when there is one) and "Time"
// (the logger's, UTC).
func (b *Backend) acctJSON(line string, r acctRec) (string, bool) {
	obj, dev, ok := displayRecord(line[strings.Index(line, acctRecordMark):], nil)
	if !ok {
		return "", false
	}
	extra := ""
	if b.env.DeviceName != nil {
		if n := b.env.DeviceName(backend.CanonAddr(dev)); n != "" && dev != "" {
			extra += `,"DeviceName":` + jsonText(n)
		}
	}
	if !r.At.IsZero() {
		extra += `,"Time":` + jsonText(backend.FormatLogTime(r.At))
	}
	return strings.TrimSuffix(obj, "}") + extra + "}", true
}

// tailItems is the items 'tail -n <count>' would write of them: the last
// count ('+K': from the Kth on), and the index of the first one written.
// false for a count tail refuses.
func tailItems[T any](items []T, count string) (kept []T, first int, ok bool) {
	from := false
	c := count
	switch {
	case strings.HasPrefix(c, "+"):
		from, c = true, c[1:]
	case strings.HasPrefix(c, "-"):
		c = c[1:]
	}
	n, err := strconv.ParseUint(c, 10, 31)
	if err != nil {
		return nil, 0, false
	}
	switch {
	case from:
		k := max(int(n), 1)
		if k > len(items) {
			return nil, len(items), true
		}
		return items[k-1:], k - 1, true
	case int(n) >= len(items):
		return items, 0, true
	}
	return items[len(items)-int(n):], len(items) - int(n), true
}

// readLines is the lines of a file, a last one without a newline included.
func readLines(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), nil
}

// accountingFiltered is Accounting for filters or --json: the records of
// each log that pass them, the last count of those.
func (b *Backend) accountingFiltered(w io.Writer, count string) error {
	f := b.env.LogFilter
	if _, _, ok := tailItems([]string(nil), count); !ok {
		writeString(b.env.Out.Stderr, "tail: invalid number of lines: '"+count+"'\n")
		return backend.ErrFailed
	}
	if !f.JSON {
		writeString(w, "\n")
		echoLine(w, ui.Bold+"Recent Accounting Entries"+ui.NC)
		writeString(w, rule+"\n")
	}
	acct := b.env.Paths.AcctLog
	switch {
	case !isRegular(acct):
		if !f.JSON {
			writeString(w, "  No accounting log found at "+acct+"\n")
		}
	case isEmptyFile(acct):
		if !f.JSON {
			writeString(w, "  No entries yet in "+acct+"\n")
		}
	default:
		b.filteredAcct(w, acct, count, "  No matching entries in "+acct+"\n")
	}
	for _, log := range b.acctLogs(false) {
		if !isRegular(log) {
			continue
		}
		if !f.JSON {
			writeString(w, "\n")
			echoLine(w, ui.Bold+log+ui.NC)
		}
		if isEmptyFile(log) {
			if !f.JSON {
				writeString(w, "  No entries yet.\n")
			}
			continue
		}
		b.filteredAcct(w, log, count, "  No matching entries.\n")
	}
	if !f.JSON {
		writeString(w, "\n")
	}
	return nil
}

// filteredAcct writes the records of one log that pass the filters, the
// last count of them.
func (b *Backend) filteredAcct(w io.Writer, path, count, none string) {
	f := b.env.LogFilter
	lines, err := readLines(path)
	if err != nil {
		writeString(b.env.Out.Stderr, "tail: cannot open '"+path+"' for reading: "+err.Error()+"\n")
		return
	}
	type hit struct {
		line string
		rec  acctRec
	}
	var hits []hit
	for _, l := range lines {
		if r, ok := acctMatch(f, l); ok {
			hits = append(hits, hit{l, r})
		}
	}
	last, _, _ := tailItems(hits, count)
	for _, h := range last {
		if f.JSON {
			if o, ok := b.acctJSON(h.line, h.rec); ok {
				writeString(w, o+"\n")
			}
			continue
		}
		writeString(w, AcctDisplay(h.line, b.env.DeviceName)+"\n")
	}
	if len(last) == 0 && !f.JSON {
		writeString(w, none)
	}
}
