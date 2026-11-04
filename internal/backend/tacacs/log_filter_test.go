package tacacs

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// The journal as 'journalctl' writes it, with tacquito's lines (patches/0003).
const filterJournal = `Nov 04 12:00:00 tacacs tacquito[1]: accepting user [alice] from [192.0.2.10] using a bcrypt password; client [192.0.2.50] port [ttyp0]
Nov 04 12:01:00 tacacs tacquito[1]: failed to validate the user [bob] from [192.0.2.10] using a bcrypt password
Nov 04 12:02:00 tacacs tacquito[1]: accepting user [alice] from [198.51.100.7] using a bcrypt password
Nov 04 12:03:00 tacacs tacquito[1]: bad secret detected for ip [198.51.100.7:50122]
Nov 04 12:04:00 tacacs tacquito[1]: ERROR could not read the request of [alice]
`

func (e *tenv) filter(f backend.LogFilter) { e.env.LogFilter = f }

func journalArgs(e *tenv) string {
	argvs := e.run.Argvs()
	return argvs[len(argvs)-1]
}

func TestLogTailFilters(t *testing.T) {
	e := newTenv(t)
	e.run.On([]string{"journalctl"}, execx.Result{Stdout: []byte(filterJournal)})
	head := "\n" + ui.Bold + "Recent TACACS+ Log Entries" + ui.NC + "\n" + rule + "\n"
	lines := strings.Split(strings.TrimSuffix(filterJournal, "\n"), "\n")

	// --user: the lines that name the user in brackets; journalctl cannot
	// count them, so it is not asked to.
	e.filter(backend.LogFilter{User: "alice"})
	out, err := e.log("tail")
	if err != nil {
		t.Fatal(err)
	}
	if want := head + strings.Join([]string{lines[0], lines[2], lines[4]}, "\n") + "\n\n"; out != want {
		t.Fatalf("%q", out)
	}
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager" {
		t.Fatal(got)
	}
	// The count limits what is left.
	out, _ = e.log("tail", "2")
	if want := head + lines[2] + "\n" + lines[4] + "\n\n"; out != want {
		t.Fatalf("%q", out)
	}

	// --device: the address a line names for the device that asked, not the
	// person's.
	e.filter(backend.LogFilter{Device: "sw1", Addrs: []string{"192.0.2.10"}})
	out, _ = e.log("tail")
	if want := head + lines[0] + "\n" + lines[1] + "\n\n"; out != want {
		t.Fatalf("%q", out)
	}
	e.filter(backend.LogFilter{Device: "192.0.2.50", Addrs: []string{"192.0.2.50"}})
	out, _ = e.log("tail")
	mustContain(t, out, "  No matching entries.\n")
	e.filter(backend.LogFilter{Device: "198.51.100.7", Addrs: []string{"198.51.100.7"}})
	out, _ = e.log("tail")
	if want := head + lines[2] + "\n" + lines[3] + "\n\n"; out != want {
		t.Fatalf("a bad secret line is of its device: %q", out)
	}

	// AND.
	e.filter(backend.LogFilter{User: "alice", Device: "sw1", Addrs: []string{"192.0.2.10"}})
	out, _ = e.log("tail")
	if want := head + lines[0] + "\n\n"; out != want {
		t.Fatalf("%q", out)
	}

	// The window goes to journalctl, which counts.
	e.filter(backend.LogFilter{Since: time.Date(2026, 11, 4, 10, 0, 0, 0, time.Local), Until: time.Date(2026, 11, 4, 13, 0, 0, 0, time.Local)})
	out, _ = e.log("tail", "3")
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager --since 2026-11-04 10:00:00 --until 2026-11-04 13:00:00 -n 3" {
		t.Fatal(got)
	}
	mustContain(t, out, lines[4]+"\n")

	// A bad count, and a journal that cannot be read.
	e.filter(backend.LogFilter{User: "alice"})
	_, err = e.log("tail", "x")
	wantCode(t, err, 1)
	mustContain(t, e.stderr.String(), "tail: invalid number of lines: 'x'")
	e.run.On([]string{"journalctl"}, execx.Result{Code: 1})
	out, _ = e.log("tail")
	mustContain(t, out, "  No log entries found.\n")
}

func TestLogSearchAndFailuresFilters(t *testing.T) {
	e := newTenv(t)
	e.run.On([]string{"journalctl"}, execx.Result{Stdout: []byte(filterJournal)})
	lines := strings.Split(strings.TrimSuffix(filterJournal, "\n"), "\n")

	e.filter(backend.LogFilter{User: "alice"})
	out, _ := e.log("search", "accepting")
	mustContain(t, out, "Log entries matching 'accepting'")
	mustContain(t, out, lines[0]+"\n"+lines[2]+"\n")
	mustNotContain(t, out, "bob")
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager --since 7 days ago" {
		t.Fatal(got)
	}
	e.filter(backend.LogFilter{Device: "198.51.100.7", Addrs: []string{"198.51.100.7"}})
	out, _ = e.log("search", "alice")
	mustContain(t, out, lines[2]+"\n")
	mustNotContain(t, out, lines[0])
	out, _ = e.log("search", "no-such-user")
	mustContain(t, out, "  No matches found.\n")

	// A window replaces the default seven days.
	e.filter(backend.LogFilter{Since: time.Date(2026, 11, 4, 10, 0, 0, 0, time.Local), User: "bob"})
	out, _ = e.log("search", "validate")
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager --since 2026-11-04 10:00:00" {
		t.Fatal(got)
	}
	mustContain(t, out, lines[1]+"\n")

	// failures: the filters apply to the failure lines.
	e.filter(backend.LogFilter{User: "alice"})
	out, _ = e.log("failures")
	mustContain(t, out, "Authentication Failures (last 24 hours)")
	mustContain(t, out, lines[4]+"\n")
	mustNotContain(t, out, "bad secret")
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager --since 24 hours ago" {
		t.Fatal(got)
	}
	e.filter(backend.LogFilter{Until: time.Date(2026, 11, 4, 12, 30, 0, 0, time.Local), Device: "198.51.100.7", Addrs: []string{"198.51.100.7"}})
	out, _ = e.log("failures")
	mustContain(t, out, "Authentication Failures (until 2026-11-04 12:30:00)")
	mustContain(t, out, "bad secret detected for ip [198.51.100.7:50122]\n")
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager --until 2026-11-04 12:30:00" {
		t.Fatal(got)
	}
	e.filter(backend.LogFilter{User: "nobody", Since: time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local)})
	out, _ = e.log("failures")
	mustContain(t, out, "  "+ui.Green+"No failures since 2026-11-04 12:00:00"+ui.NC)
}

// journalJSON is 'journalctl -o json' for the lines of filterJournal.
func journalJSON(t *testing.T) string {
	t.Helper()
	var b strings.Builder
	for i, l := range strings.Split(strings.TrimSuffix(filterJournal, "\n"), "\n") {
		_, msg, _ := strings.Cut(l, "]: ")
		at := time.Date(2026, 11, 4, 12, i, 0, 0, time.UTC).UnixMicro()
		rec, _ := json.Marshal(map[string]any{"__REALTIME_TIMESTAMP": itoa(at), "_SYSTEMD_UNIT": "tacquito.service", "MESSAGE": msg})
		b.Write(rec)
		b.WriteByte('\n')
	}
	// A message that is not UTF-8 is an array of bytes, and a line that is
	// no entry (a notice) is skipped.
	b.WriteString(`{"__REALTIME_TIMESTAMP":"1793793840000000","_SYSTEMD_UNIT":"tacquito.service","MESSAGE":[104,105]}` + "\n")
	b.WriteString("-- No entries --\n")
	return b.String()
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestLogTailJSON(t *testing.T) {
	e := newTenv(t)
	e.run.On([]string{"journalctl"}, execx.Result{Stdout: []byte(journalJSON(t))})
	e.env.DeviceName = names(map[string]string{"192.0.2.10": "sw1"})
	e.filter(backend.LogFilter{JSON: true})
	out, err := e.log("tail", "3")
	if err != nil {
		t.Fatal(err)
	}
	if got := journalArgs(e); got != "journalctl -u tacquito --no-pager -o json -n 3" {
		t.Fatal(got)
	}
	// One object per line, no headings.
	var all []backend.LogLine
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var o backend.LogLine
		if err := json.Unmarshal([]byte(l), &o); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		all = append(all, o)
	}
	if len(all) != 3 || strings.Contains(out, "Recent") || strings.Contains(out, rule) {
		t.Fatalf("%q", out)
	}
	// The last three of the six entries.
	if all[0].Message != "bad secret detected for ip [198.51.100.7:50122]" || all[2].Message != "hi" || all[2].Time != "2026-11-04T12:04:00Z" {
		t.Errorf("%+v", all)
	}

	// The fields of an entry that is a sighting.
	e.filter(backend.LogFilter{JSON: true, User: "alice", Device: "sw1", Addrs: []string{"192.0.2.10"}})
	out, _ = e.log("tail")
	want := `{"time":"2026-11-04T12:00:00Z","backend":"tacacs","unit":"tacquito.service","message":"` +
		`accepting user [alice] from [192.0.2.10] using a bcrypt password; client [192.0.2.50] port [ttyp0]",` +
		`"user":"alice","address":"192.0.2.10","device":"sw1","outcome":"accept"}` + "\n"
	if out != want {
		t.Fatalf("%s\nwant\n%s", out, want)
	}

	// search and failures: objects too, an entry whose message is bytes.
	e.filter(backend.LogFilter{JSON: true})
	out, _ = e.log("search", "^hi$")
	if !strings.Contains(out, `"message":"hi"`) || strings.Count(out, "\n") != 1 {
		t.Fatalf("%q", out)
	}
	out, _ = e.log("failures")
	if n := strings.Count(out, "\n"); n != 3 || strings.Contains(out, "Failures") {
		t.Fatalf("%q", out)
	}
	out, _ = e.log("search", "no-such-term")
	if out != "" {
		t.Fatalf("%q", out)
	}
}

func TestFollowFiltered(t *testing.T) {
	e := newTenv(t)
	f := backend.LogFilter{User: "alice", Device: "sw1", Addrs: []string{"192.0.2.10"}}
	src := e.b.FollowFiltered(f)
	if len(src) != 1 || !reflect.DeepEqual(src[0].Argv, []string{"journalctl", "-u", "tacquito", "--no-pager", "-f", "-n", "0"}) {
		t.Fatalf("%v", src)
	}
	lines := strings.Split(strings.TrimSuffix(filterJournal, "\n"), "\n")
	var got []string
	for _, l := range lines {
		if out, ok := src[0].Line(l); ok {
			got = append(got, out)
		}
	}
	if !reflect.DeepEqual(got, []string{lines[0]}) {
		t.Fatalf("%q", got)
	}

	// --json follows with -o json and writes objects.
	e.env.DeviceName = names(map[string]string{"192.0.2.10": "sw1"})
	f.JSON = true
	src = e.b.FollowFiltered(f)
	if !reflect.DeepEqual(src[0].Argv[len(src[0].Argv)-2:], []string{"-o", "json"}) {
		t.Fatalf("%v", src[0].Argv)
	}
	e.env.LogFilter = f
	rec := `{"__REALTIME_TIMESTAMP":"1793793600000000","_SYSTEMD_UNIT":"tacquito.service","MESSAGE":"accepting user [alice] from [192.0.2.10] using a bcrypt password"}`
	out, ok := src[0].Line(rec)
	if !ok || !strings.Contains(out, `"device":"sw1"`) || !strings.Contains(out, `"time":"2026-11-04T12:00:00Z"`) {
		t.Fatalf("%v %s", ok, out)
	}
	if _, ok := src[0].Line("-- Journal begins --"); ok {
		t.Error("a notice is written")
	}

	// The window is compared with the time an entry arrives (the clock).
	e.env.Now = func() time.Time { return time.Date(2026, 11, 4, 12, 0, 0, 0, time.Local) }
	f = backend.LogFilter{Until: time.Date(2026, 11, 4, 11, 0, 0, 0, time.Local)}
	if _, ok := e.b.FollowFiltered(f)[0].Line(lines[0]); ok {
		t.Error("an entry after --until")
	}
	f = backend.LogFilter{Since: time.Date(2026, 11, 4, 11, 0, 0, 0, time.Local)}
	if _, ok := e.b.FollowFiltered(f)[0].Line(lines[0]); !ok {
		t.Error("an entry after --since")
	}
}

// --- accounting ---------------------------------------------------------------

func acctLine(ts, user, device string, flags int, args ...string) string {
	a, _ := json.Marshal(args)
	if args == nil {
		a = []byte("null")
	}
	d := ""
	if device != "" {
		d = `,"Device":"` + device + `"`
	}
	return "2026/11/04 " + ts + " /opt/tacquito-src/cmds/server/config/accounters/local/local.go:105: " +
		`{"Flags":` + itoa(int64(flags)) + `,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"` + user + `","Port":"ttyp0","RemAddr":"192.0.2.50","Args":` + string(a) + d + "}"
}

// The records of a Cisco switch and a Junos switch.
var filterAcct = []string{
	acctLine("09:00:00", "alice", "192.0.2.10", 2, "task_id=1", "service=shell"),
	acctLine("09:01:00", "alice", "192.0.2.10", 4, "task_id=2", "service=shell", "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"),
	acctLine("09:02:00", "bob", "192.0.2.11", 4, "task_id=3", "service=shell", "cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\"<cr>"),
	acctLine("09:03:00", "alice", "192.0.2.11", 4, "task_id=4", "service=shell", "cmd=show version <cr>"),
	acctLine("09:04:00", "alice", "2001:db8::1", 4, "task_id=5", "service=shell"),
	acctLine("09:05:00", "alice", "192.0.2.10", 8, "task_id=6", "service=shell"),
	acctLine("09:06:00", "carol", "", 2, "task_id=7", "service=shell"),
	acctLine("09:07:00", "alice", "192.0.2.10", 4, "task_id=8", "service=shell", "cmd=delete: [system login user dave]<cr>"),
	acctLine("09:08:00", "alice", "192.0.2.10", 4, "task_id=9", "service=shell", "cmd=<cr>"),
}

func (e *tenv) acct(f backend.LogFilter, args ...string) string {
	e.t.Helper()
	e.filter(f)
	var w bytes.Buffer
	if err := e.b.Accounting(context.Background(), "tail", args, &w); err != nil {
		e.t.Fatal(err)
	}
	return w.String()
}

func local(h, m, s int) time.Time { return time.Date(2026, 11, 4, h, m, s, 0, time.Local) }

func TestAccountingType(t *testing.T) {
	for i, want := range []string{
		backend.TypeLogin, backend.TypeCommand, backend.TypeChange, backend.TypeCommand, backend.TypeLogin, "",
		backend.TypeLogin, backend.TypeChange, backend.TypeLogin,
	} {
		r, ok := parseAcct(filterAcct[i])
		if !ok {
			t.Fatalf("record %d", i)
		}
		if got := acctType(r); got != want {
			t.Errorf("record %d (%v): %q, want %q", i, r.Args, got, want)
		}
	}
	for _, l := range []string{"", "not a record", acctPrefix + `{"Flags":4,"User":"alice"`, `{"Flags":"x"}`} {
		if _, ok := parseAcct(l); ok {
			t.Errorf("%q is a record", l)
		}
	}
	if r, _ := parseAcct(filterAcct[0]); !r.At.Equal(local(9, 0, 0)) {
		t.Errorf("time %v", r.At)
	}
}

func TestAccountingFilters(t *testing.T) {
	e := newTenv(t)
	e.env.DeviceName = names(map[string]string{"192.0.2.10": "sw1", "192.0.2.11": "jsw1", "2001:db8::1": "rtr1"})
	writeFile(t, e.p.AcctLog, strings.Join(filterAcct, "\n")+"\nnot a record\n")
	body := func(out string) []string {
		t.Helper()
		ls := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
		return ls[3 : len(ls)-1]
	}
	task := func(out string) string {
		var ids []string
		for _, l := range body(out) {
			i := strings.Index(l, `"task_id=`)
			ids = append(ids, l[i+9:i+10])
		}
		return strings.Join(ids, " ")
	}
	cases := []struct {
		name string
		f    backend.LogFilter
		args []string
		want string // the task ids of the records shown
	}{
		{"no filter but a window", backend.LogFilter{Since: local(0, 0, 0)}, []string{"20"}, "1 2 3 4 5 6 7 8 9"},
		{"since", backend.LogFilter{Since: local(9, 6, 0)}, nil, "7 8 9"},
		{"until", backend.LogFilter{Until: local(9, 1, 0)}, nil, "1 2"},
		{"since and until", backend.LogFilter{Since: local(9, 2, 0), Until: local(9, 4, 0)}, nil, "3 4 5"},
		{"a window before the log", backend.LogFilter{Until: local(8, 0, 0)}, nil, ""},
		{"user", backend.LogFilter{User: "alice"}, nil, "1 2 4 5 6 8 9"},
		{"user is exact", backend.LogFilter{User: "ali"}, nil, ""},
		{"device by address", backend.LogFilter{Device: "192.0.2.11", Addrs: []string{"192.0.2.11"}}, nil, "3 4"},
		{"device v6", backend.LogFilter{Device: "rtr1", Addrs: []string{"2001:db8::1"}}, nil, "5"},
		{"a record with no device", backend.LogFilter{Device: "x", Addrs: []string{"192.0.2.10"}}, []string{"100"}, "1 2 6 8 9"},
		{"type login", backend.LogFilter{Type: backend.TypeLogin}, nil, "1 5 7 9"},
		{"type change", backend.LogFilter{Type: backend.TypeChange}, nil, "3 8"},
		{"type command", backend.LogFilter{Type: backend.TypeCommand}, nil, "2 4"},
		{"user and type", backend.LogFilter{User: "alice", Type: backend.TypeLogin}, nil, "1 5 9"},
		{"user, device and window", backend.LogFilter{User: "alice", Device: "sw1", Addrs: []string{"192.0.2.10"}, Since: local(9, 1, 0), Until: local(9, 7, 0)}, nil, "2 6 8"},
		{"the count limits what is left", backend.LogFilter{User: "alice"}, []string{"3"}, "6 8 9"},
		{"a count of one", backend.LogFilter{User: "alice", Type: backend.TypeLogin}, []string{"1"}, "9"},
		{"from the Kth on", backend.LogFilter{User: "alice"}, []string{"+5"}, "6 8 9"},
		{"-N", backend.LogFilter{User: "bob"}, []string{"-5"}, "3"},
	}
	for _, c := range cases {
		out := e.acct(c.f, c.args...)
		if c.want == "" {
			mustContain(t, out, "  No matching entries in "+e.p.AcctLog+"\n")
			continue
		}
		if got := task(out); got != c.want {
			t.Errorf("%s: records %q, want %q\n%s", c.name, got, c.want, out)
		}
		mustNotContain(t, out, "not a record")
	}

	// The display is the one of the unfiltered command: the device by name,
	// the values decoded.
	out := e.acct(backend.LogFilter{User: "bob"})
	mustContain(t, out, `"Device":"jsw1"}`)
	mustContain(t, out, `<unconfigured> -> \"a&b\""]`)
	mustContain(t, out, rule+"\n"+acctPrefixOf(filterAcct[2]))

	// Another listener's log is filtered too, under its name.
	mgmt := filepath.Join(e.p.Log, "accounting-mgmt.log")
	writeFile(t, mgmt, filterAcct[1]+"\n"+filterAcct[2]+"\n")
	out = e.acct(backend.LogFilter{User: "bob"})
	mustContain(t, out, ui.Bold+mgmt+ui.NC+"\n"+acctPrefixOf(filterAcct[2]))
	out = e.acct(backend.LogFilter{User: "carol"})
	mustContain(t, out, ui.Bold+mgmt+ui.NC+"\n  No matching entries.\n")

	// A bad count; no log; an empty log.
	e.filter(backend.LogFilter{User: "bob"})
	var w bytes.Buffer
	wantCode(t, e.b.Accounting(context.Background(), "tail", []string{"x"}, &w), 1)
	mustContain(t, e.stderr.String(), "tail: invalid number of lines: 'x'")
	writeFile(t, e.p.AcctLog, "")
	mustContain(t, e.acct(backend.LogFilter{User: "bob"}), "  No entries yet in "+e.p.AcctLog+"\n")
}

// acctPrefixOf is the start of a displayed line: the logger's prefix of a
// line of the fixture, up to the record.
func acctPrefixOf(line string) string { return line[:strings.Index(line, "{")] }

func TestAccountingJSON(t *testing.T) {
	e := newTenv(t)
	e.env.DeviceName = names(map[string]string{"192.0.2.11": "jsw1"})
	writeFile(t, e.p.AcctLog, strings.Join(filterAcct, "\n")+"\nnot a record\n")
	out := e.acct(backend.LogFilter{JSON: true, User: "bob"})
	// Nothing but the objects.
	if strings.Contains(out, "Recent") || strings.Contains(out, rule) || strings.Count(out, "\n") != 1 {
		t.Fatalf("%q", out)
	}
	want := `{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"bob","Port":"ttyp0","RemAddr":"192.0.2.50",` +
		`"Args":["task_id=3","service=shell","cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\""],` +
		`"Device":"192.0.2.11","DeviceName":"jsw1","Time":"` + local(9, 2, 0).UTC().Format(time.RFC3339) + `"}` + "\n"
	if out != want {
		t.Fatalf("%s\nwant\n%s", out, want)
	}
	// Every object is valid JSON; a device with no name has none added.
	out = e.acct(backend.LogFilter{JSON: true}, "100")
	n := 0
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%q: %v", l, err)
		}
		if _, ok := m["Time"]; !ok {
			t.Errorf("%q has no Time", l)
		}
		if d, _ := m["Device"].(string); (d == "192.0.2.11") != (m["DeviceName"] != nil) {
			t.Errorf("%q", l)
		}
		n++
	}
	if n != len(filterAcct) {
		t.Fatalf("%d objects", n)
	}
	// --json alone is the whole log, and a count still limits it.
	if out = e.acct(backend.LogFilter{JSON: true}, "2"); strings.Count(out, "\n") != 2 {
		t.Fatalf("%q", out)
	}
	// Nothing found writes nothing.
	if out = e.acct(backend.LogFilter{JSON: true, User: "nobody"}); out != "" {
		t.Fatalf("%q", out)
	}
	// An old record (escapes in the file) comes out decoded.
	writeFile(t, e.p.AcctLog, acctPrefix+acctOld+"\n")
	out = e.acct(backend.LogFilter{JSON: true})
	mustContain(t, out, `<unconfigured> -> \"a&b\""`)
	mustNotContain(t, out, `\u00`)
	mustNotContain(t, out, "DeviceName")
}
