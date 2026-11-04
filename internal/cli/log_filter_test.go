package cli

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'log tail|search|failures|accounting' with --since, --until, --user,
// --device, --type and --json: the flags are parsed here and applied by the
// backends (internal/backend/{tacacs,radius}/log_filter_test.go test the
// matching); these tests run the commands.

// The journal of tacquito: sw1 (dmz, 203.0.113.10), rtr1 (prod, 10.0.0.1), an
// IPv6 device, and the enrolled host web1 (its scope's only address).
var logJournalLines = []string{
	"Nov 04 12:00:00 tacacs tacquito[1]: accepting user [alice] from [203.0.113.10] using a bcrypt password; client [198.51.100.7] port [ttyp0]",
	"Nov 04 12:01:00 tacacs tacquito[1]: failed to validate the user [bob] from [203.0.113.10] using a bcrypt password",
	"Nov 04 12:02:00 tacacs tacquito[1]: accepting user [alice] from [10.0.0.1] using a bcrypt password",
	"Nov 04 12:03:00 tacacs tacquito[1]: bad secret detected for ip [192.0.2.50:50122]",
	"Nov 04 12:04:00 tacacs tacquito[1]: accepting user [carol] from [2001:db8::1] using a bcrypt password",
}

func logSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	store := sb.read("state/store.yaml")
	// bob is an operator of the scope dmz (203.0.113.0/24), not of prod.
	store = strings.Replace(store, "    group: operator\n    scopes: [lab]\n", "    group: operator\n    scopes: [dmz]\n", 1)
	store = strings.Replace(store, "filters:\n", "  site-a:\n    prefixes: [192.0.2.50/32]\n    secret: site-a-secret-0123456789abcdef\nfilters:\n", 1)
	sb.write("state/store.yaml", store, 0o600)
	sb.write("state/linux-hosts", "web1|root@web1.example.net||site-a|tacacs.example.net|\n", 0o600)
	if _, err := devreg.Mutate(sb.path("state", "devices.yaml"), "", nil, func(f *devreg.File) error {
		f.Devices = append(f.Devices,
			&devreg.Device{Name: "sw1", Address: "203.0.113.10", Vendor: "cisco"},
			&devreg.Device{Name: "rtr1", Address: "10.0.0.1", Vendor: "juniper"},
			&devreg.Device{Name: "rtr2", Address: "2001:db8::1", Vendor: "juniper"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return sb
}

// logRunAs runs tacctl args (as bob, an operator, when user is "bob") with the
// journal scripted: journalctl answers with out (the -f commands with
// followed, when it is not "").
func (sb *sandbox) logRunAs(user, out, followed string, args ...string) string {
	sb.t.Helper()
	var env []string
	if user != "" {
		env = []string{"SUDO_USER=" + user}
	}
	return plain(sb.cfgRun("", append([]string{"log"}, args...), func(r *fake.Runner) {
		if user != "" {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-operator\n")})
		}
		r.On([]string{"journalctl"}, execx.Result{Stdout: []byte(out)})
		if followed != "" {
			r.Func(func(c execx.Cmd) bool { return c.Name == "journalctl" && slices.Contains(c.Args, "-f") },
				func(execx.Cmd) (execx.Result, error) { return execx.Result{Stdout: []byte(followed)}, nil })
		}
	}, env...))
}

func (sb *sandbox) logRun(out string, args ...string) string {
	sb.t.Helper()
	return sb.logRunAs("", out, "", args...)
}

func journalOf(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// lastJournalctl is the arguments of the last journalctl the run made.
func (sb *sandbox) lastJournalctl() string {
	argvs := sb.runner.Argvs()
	for i := len(argvs) - 1; i >= 0; i-- {
		if strings.HasPrefix(argvs[i], "journalctl ") {
			return argvs[i]
		}
	}
	return ""
}

func TestLogFilterFlagErrors(t *testing.T) {
	sb := logSandbox(t)
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"tail", "--since"}, "--since needs a time. Usage: tacctl log tail [--since <value>] ..."},
		{[]string{"tail", "--since="}, "--since needs a time."},
		{[]string{"search", "alice", "--user"}, "--user needs a user name."},
		{[]string{"failures", "--device"}, "--device needs a device name or an address."},
		{[]string{"accounting", "--type"}, "--type needs login, change or command."},
		{[]string{"tail", "--since", "last week"}, "--since: invalid time 'last week' (use YYYY-MM-DD[ HH:MM[:SS]], now, today, yesterday, -1h, 2 hours ago)"},
		{[]string{"tail", "--until=tomorrow"}, "--until: invalid time 'tomorrow'"},
		{[]string{"tail", "--since", "1h"}, "--since: invalid time '1h'"},
		{[]string{"tail", "--since", "2026-11-05", "--until", "2026-11-04"}, "--since (2026-11-05 00:00:00) is later than --until (2026-11-04 00:00:00)."},
		{[]string{"tail", "--type", "login"}, "--type applies to 'log accounting' only."},
		{[]string{"search", "x", "--type=login"}, "--type applies to 'log accounting' only."},
		{[]string{"accounting", "--type", "session"}, "Unknown --type 'session' (use login, change, command)."},
		{[]string{"tail", "--device", "sw9"}, "Unknown device or host 'sw9' (a registered device, an enrolled host or an address)."},
		{[]string{"tail", "--device", "0.0.0.0"}, "--device: '0.0.0.0' is not an address of a device."},
	} {
		sb.logRun("", c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.msg) {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
		if sb.runner.Called("journalctl") {
			t.Errorf("%v: the journal was read", c.args)
		}
	}
	// A purge takes no filter: the words stay the unknown options they were.
	sb.logRun("", "clear", "--since", "today")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Unknown option: '--since'") {
		t.Errorf("clear: %d %q", sb.code, sb.stderr())
	}
}

func TestLogTailWithFilters(t *testing.T) {
	sb := logSandbox(t)
	j := journalOf(logJournalLines...)
	const plainArgv = "journalctl -u tacquito --no-pager"
	for _, c := range []struct {
		name string
		args []string
		want []int // the lines of the journal shown
		argv string
	}{
		{"user", []string{"--user", "alice"}, []int{0, 2}, plainArgv},
		{"user=, and a count", []string{"--user=alice", "1"}, []int{2}, plainArgv},
		{"device by registered name", []string{"--device", "sw1"}, []int{0, 1}, plainArgv},
		{"device by address", []string{"--device", "10.0.0.1"}, []int{2}, plainArgv},
		{"device by IPv6 name", []string{"--device", "rtr2"}, []int{4}, plainArgv},
		{"device by IPv6 in another form", []string{"--device=2001:DB8:0:0::1"}, []int{4}, plainArgv},
		{"device by IPv4-mapped address", []string{"--device", "::ffff:203.0.113.10"}, []int{0, 1}, plainArgv},
		{"enrolled host", []string{"--device", "web1"}, []int{3}, plainArgv},
		{"name in another case, and a user", []string{"--device", "SW1", "--user", "bob"}, []int{1}, plainArgv},
		{"user and device", []string{"--user", "alice", "--device", "rtr1"}, []int{2}, plainArgv},
		{"flags before the count", []string{"--user", "alice", "-5"}, []int{0, 2}, plainArgv},
		{"window and a count", []string{"--since", "2026-11-04 12:00", "--until", "2026-11-04 12:30:15", "3"}, []int{2, 3, 4},
			plainArgv + " --since 2026-11-04 12:00:00 --until 2026-11-04 12:30:15 -n 3"},
		{"window and user", []string{"--since=2026-11-04", "--user", "carol"}, []int{4}, plainArgv + " --since 2026-11-04 00:00:00"},
	} {
		out := sb.logRun(j, append([]string{"tail", "--backend=tacacs"}, c.args...)...)
		if sb.code != 0 {
			t.Fatalf("%s: %d %q", c.name, sb.code, sb.stderr())
		}
		var got, want []string
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "Nov 04") {
				got = append(got, l)
			}
		}
		for _, i := range c.want {
			want = append(want, logJournalLines[i])
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s: got\n%s\nwant\n%s", c.name, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
		if a := sb.lastJournalctl(); a != c.argv {
			t.Errorf("%s: %q, want %q", c.name, a, c.argv)
		}
	}

	// Relative times are counted from now.
	sb.logRun(j, "tail", "--backend=tacacs", "--since", "-1h", "--until", "2 minutes ago")
	m := regexp.MustCompile(`--since (\S+ \S+) --until (\S+ \S+) -n 20$`).FindStringSubmatch(sb.lastJournalctl())
	if m == nil {
		t.Fatalf("%q", sb.lastJournalctl())
	}
	since, _ := time.ParseInLocation(backend.LogTimeLayout, m[1], time.Local)
	until, _ := time.ParseInLocation(backend.LogTimeLayout, m[2], time.Local)
	if d := time.Since(since) - time.Hour; d < -time.Minute || d > time.Minute {
		t.Errorf("--since -1h is %v", since)
	}
	if d := time.Since(until) - 2*time.Minute; d < -time.Minute || d > time.Minute {
		t.Errorf("--until 2 minutes ago is %v", until)
	}

	// A filter that leaves nothing says so.
	out := sb.logRun(j, "tail", "--backend=tacacs", "--user", "dave")
	if !strings.Contains(out, "  No matching entries.\n") {
		t.Errorf("%s", out)
	}
}

func TestLogSearchAndFailuresWithFilters(t *testing.T) {
	sb := logSandbox(t)
	j := journalOf(logJournalLines...)
	out := sb.logRun(j, "search", "--backend=tacacs", "accepting", "--user", "alice", "--device", "rtr1")
	if !strings.Contains(out, logJournalLines[2]+"\n") || strings.Contains(out, logJournalLines[0]) || strings.Contains(out, logJournalLines[4]) {
		t.Errorf("search:\n%s", out)
	}
	// The flags may come first.
	out = sb.logRun(j, "search", "--device", "web1", "--backend=tacacs", "bad")
	if !strings.Contains(out, logJournalLines[3]+"\n") {
		t.Errorf("search:\n%s", out)
	}
	out = sb.logRun(j, "failures", "--backend=tacacs", "--device", "web1", "--since", "2026-11-04 00:00")
	if a := sb.lastJournalctl(); a != "journalctl -u tacquito --no-pager --since 2026-11-04 00:00:00" {
		t.Error(a)
	}
	if !strings.Contains(out, "Authentication Failures (since 2026-11-04 00:00:00)") || !strings.Contains(out, logJournalLines[3]+"\n") ||
		strings.Contains(out, "bob") {
		t.Errorf("failures:\n%s", out)
	}
	out = sb.logRun(j, "failures", "--backend=tacacs", "--user", "bob", "--until", "2026-11-04 12:30")
	if !strings.Contains(out, "(until 2026-11-04 12:30:00)") || !strings.Contains(out, logJournalLines[1]+"\n") {
		t.Errorf("failures:\n%s", out)
	}
	// Without a window: the last 24 hours, as before.
	sb.logRun(j, "failures", "--backend=tacacs", "--user", "bob")
	if a := sb.lastJournalctl(); a != "journalctl -u tacquito --no-pager --since 24 hours ago" {
		t.Error(a)
	}
}

// journalJSONOf is journalctl -o json for the lines.
func journalJSONOf(lines ...string) string {
	var b strings.Builder
	for i, l := range lines {
		_, msg, _ := strings.Cut(l, "]: ")
		rec, _ := json.Marshal(msg)
		b.WriteString(`{"__REALTIME_TIMESTAMP":"` + itoaT(time.Date(2026, 11, 4, 12, i, 0, 0, time.UTC).UnixMicro()) + `","_SYSTEMD_UNIT":"tacquito.service","MESSAGE":` + string(rec) + "}\n")
	}
	return b.String()
}

func TestLogJSONOfTheJournal(t *testing.T) {
	sb := logSandbox(t)
	in := journalJSONOf(logJournalLines...)
	for _, sub := range [][]string{{"tail"}, {"search", "user"}, {"failures"}} {
		out := sb.logRun(in, append(append([]string{}, sub...), "--backend=tacacs", "--json")...)
		if sb.code != 0 || !strings.Contains(sb.lastJournalctl(), " -o json") {
			t.Fatalf("%v: %d %q %q", sub, sb.code, sb.stderr(), sb.lastJournalctl())
		}
		if strings.Contains(out, "----") || strings.Contains(out, "Recent") || strings.Contains(out, "Matching") || strings.Contains(out, "Failures") {
			t.Errorf("%v: a heading in\n%s", sub, out)
		}
		n := 0
		for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			var o backend.LogLine
			if err := json.Unmarshal([]byte(l), &o); err != nil || o.Backend != "tacacs" || o.Unit != "tacquito.service" || o.Message == "" || o.Time == "" {
				t.Fatalf("%v: %q: %v", sub, l, err)
			}
			n++
		}
		if n == 0 {
			t.Errorf("%v: no object", sub)
		}
	}
	// The device is named in the object, and the filters apply.
	out := sb.logRun(in, "tail", "--backend=tacacs", "--json", "--device", "rtr1")
	want := `{"time":"2026-11-04T12:02:00Z","backend":"tacacs","unit":"tacquito.service","message":"accepting user [alice] from [10.0.0.1] using a bcrypt password",` +
		`"user":"alice","address":"10.0.0.1","device":"rtr1","outcome":"accept"}` + "\n"
	if out != want {
		t.Errorf("%s\nwant\n%s", out, want)
	}
}

func itoaT(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func logAcctLine(ts, user, device string, flags int, args string) string {
	d := ""
	if device != "" {
		d = `,"Device":"` + device + `"`
	}
	return "2026/11/04 " + ts + " /opt/tacquito-src/cmds/server/config/accounters/local/local.go:105: " +
		`{"Flags":` + itoaT(int64(flags)) + `,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"` + user + `","Port":"ttyp0","RemAddr":"198.51.100.7","Args":[` + args + `]` + d + "}"
}

func TestLogAccountingWithFilters(t *testing.T) {
	sb := logSandbox(t)
	sb.write("log/accounting.log", strings.Join([]string{
		logAcctLine("09:00:00", "alice", "203.0.113.10", 2, `"task_id=1","service=shell"`),
		logAcctLine("09:01:00", "alice", "203.0.113.10", 4, `"task_id=2","service=shell","cmd=show","cmd-arg=version","cmd-arg=<cr>"`),
		logAcctLine("09:02:00", "bob", "10.0.0.1", 4, `"task_id=3","service=shell","cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\"<cr>"`),
		logAcctLine("09:03:00", "alice", "2001:db8::1", 4, `"task_id=4","service=shell"`),
		logAcctLine("09:04:00", "alice", "", 4, `"task_id=5","service=shell","cmd=show version <cr>"`),
		"",
	}, "\n"), 0o600)
	ids := func(out string) string {
		var s []string
		for _, m := range regexp.MustCompile(`"task_id=(\d)"`).FindAllStringSubmatch(out, -1) {
			s = append(s, m[1])
		}
		return strings.Join(s, " ")
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"--user", "alice"}, "1 2 4 5"},
		{[]string{"--device", "sw1"}, "1 2"},
		{[]string{"--device", "rtr1"}, "3"},
		{[]string{"--device", "2001:DB8::1"}, "4"},
		{[]string{"--device", "rtr2", "--type", "login"}, "4"},
		{[]string{"--type", "login"}, "1 4"},
		{[]string{"--type=change"}, "3"},
		{[]string{"--type", "command"}, "2 5"},
		{[]string{"--since", "2026-11-04 09:01", "--until", "2026-11-04 09:03"}, "2 3 4"},
		{[]string{"--since", "2026-11-04 09:01", "--user", "alice", "2"}, "4 5"},
		{[]string{"--since", "2026-11-05"}, ""},
		{[]string{"--until", "2026-11-04 08:00"}, ""},
		{[]string{"--user", "alice", "--device", "sw1", "--type", "command", "--since", "today"}, "2"},
	} {
		out := sb.logRun("", append([]string{"accounting", "--backend=tacacs"}, c.args...)...)
		if sb.code != 0 {
			t.Fatalf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
		if got := ids(out); got != c.want {
			t.Errorf("%v: %q, want %q\n%s", c.args, got, c.want, out)
		}
		if c.want == "" && !strings.Contains(out, "  No matching entries in ") {
			t.Errorf("%v: %s", c.args, out)
		}
	}
	// The display names the devices, decodes the values.
	out := sb.logRun("", "accounting", "--backend=tacacs", "--user", "bob")
	if !strings.Contains(out, `"Device":"rtr1"}`) || !strings.Contains(out, `<unconfigured> -> \"a&b\""`) {
		t.Errorf("%s", out)
	}

	// --json: the record with the device's name and time added.
	out = sb.logRun("", "accounting", "--backend=tacacs", "--json", "--device", "10.0.0.1")
	want := `{"Flags":4,"Method":6,"PrivLvl":1,"Type":1,"Service":0,"User":"bob","Port":"ttyp0","RemAddr":"198.51.100.7",` +
		`"Args":["task_id=3","service=shell","cmd=set: [interfaces ge-0/0/1 description] <unconfigured> -> \"a&b\""],` +
		`"Device":"10.0.0.1","DeviceName":"rtr1","Time":"` + time.Date(2026, 11, 4, 9, 2, 0, 0, time.Local).UTC().Format(time.RFC3339) + `"}` + "\n"
	if out != want {
		t.Errorf("%s\nwant\n%s", out, want)
	}
	out = sb.logRun("", "accounting", "--backend=tacacs", "--json")
	if strings.Count(out, "\n") != 5 {
		t.Errorf("%s", out)
	}
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if !json.Valid([]byte(l)) {
			t.Errorf("not JSON: %q", l)
		}
	}
}

// The names a caller may use for --device are those they see; an address is
// always accepted.
func TestLogDeviceNamesRespectTheCallersScopes(t *testing.T) {
	sb := logSandbox(t)
	sb.write("log/accounting.log", logAcctLine("09:00:00", "alice", "10.0.0.1", 4, `"task_id=1"`)+"\n"+
		logAcctLine("09:01:00", "alice", "203.0.113.10", 4, `"task_id=2"`)+"\n", 0o600)
	out := sb.logRunAs("bob", "", "", "accounting", "--backend=tacacs", "--device", "sw1")
	if sb.code != 0 || !strings.Contains(out, `"task_id=2"`) || strings.Contains(out, `"task_id=1"`) {
		t.Fatalf("%d %q\n%s", sb.code, sb.stderr(), out)
	}
	// rtr1 is prod's: bob does not know it by name, and its address is not
	// named in the display.
	sb.logRunAs("bob", "", "", "accounting", "--backend=tacacs", "--device", "rtr1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Unknown device or host 'rtr1'") {
		t.Errorf("%d %q", sb.code, sb.stderr())
	}
	out = sb.logRunAs("bob", "", "", "accounting", "--backend=tacacs", "--device", "10.0.0.1")
	if sb.code != 0 || !strings.Contains(out, `"task_id=1"`) || !strings.Contains(out, `"Device":"10.0.0.1"`) {
		t.Errorf("%d\n%s", sb.code, out)
	}
	// The superuser knows both.
	sb.logRun("", "accounting", "--backend=tacacs", "--device", "rtr1")
	if sb.code != 0 {
		t.Errorf("%d %q", sb.code, sb.stderr())
	}
}

// A device whose registry entry has no address cannot be told apart.
func TestLogDeviceWithoutAnAddress(t *testing.T) {
	sb := logSandbox(t)
	// web1 is an enrolled host: take away its scope's address.
	store := sb.read("state/store.yaml")
	sb.write("state/store.yaml", strings.Replace(store, "prefixes: [192.0.2.50/32]", "prefixes: [192.0.2.0/24]", 1), 0o600)
	sb.logRun("", "tail", "--backend=tacacs", "--device", "web1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'web1' has no address recorded") {
		t.Errorf("%d %q", sb.code, sb.stderr())
	}
}

func TestLogRADIUSWithFilters(t *testing.T) {
	sb := logSandbox(t)
	sb.write("radius-log/tacctl-auth.log", strings.Join([]string{
		"2026-11-04 09:00:00 Access-Accept scope=dmz device=sw1 client=203.0.113.10 nas=sw1 reason='-' user=alice",
		"2026-11-04 09:30:00 Access-Reject scope=dmz device=sw1 client=203.0.113.10 nas=sw1 reason='bad' user=bob",
		"2026-11-04 10:00:00 Access-Accept scope=prod device=rtr1 client=10.0.0.1 nas=rtr1 reason='-' user=alice",
		"",
	}, "\n"), 0o600)
	sb.write("radius-log/tacctl-accounting.log", "Wed Nov  4 09:00:00 2026\n\tUser-Name = \"alice\"\n\tNAS-IP-Address = 203.0.113.10\n\tAcct-Status-Type = Start\n\n", 0o600)
	out := sb.logRun("", "tail", "--backend=radius", "--device", "rtr1", "--user", "alice")
	if sb.code != 0 || !strings.Contains(out, "client=10.0.0.1") || strings.Contains(out, "client=203.0.113.10") {
		t.Fatalf("%d %q\n%s", sb.code, sb.stderr(), out)
	}
	out = sb.logRun("", "failures", "--backend=radius", "--since", "2026-11-04 09:15", "--json")
	var o backend.LogLine
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &o); err != nil || o.User != "bob" || o.Outcome != "reject" || o.Device != "sw1" || o.Log != "auth" {
		t.Errorf("%v %+v\n%s", err, o, out)
	}
	out = sb.logRun("", "accounting", "--backend=radius", "--type", "login", "--device", "sw1")
	if !strings.Contains(out, "Acct-Status-Type = Start") {
		t.Errorf("%s", out)
	}
	out = sb.logRun("", "accounting", "--backend=radius", "--type", "command")
	if !strings.Contains(out, "RADIUS accounting has no command records") || strings.Contains(out, "User-Name") {
		t.Errorf("%s", out)
	}
}

// tail -f applies the filters to the entries that follow, after the tail.
func TestLogFollowWithFilters(t *testing.T) {
	sb := logSandbox(t)
	followed := journalOf(logJournalLines...)
	out := sb.logRunAs("", journalOf(logJournalLines[0]), followed, "tail", "--backend=tacacs", "-f", "--user", "alice", "--device", "sw1")
	if sb.code != 0 {
		t.Fatalf("%d %q", sb.code, sb.stderr())
	}
	// The tail shows the line once, and the followed lines add it once
	// again: alice's lines of sw1 only.
	if n := strings.Count(out, logJournalLines[0]); n != 2 {
		t.Errorf("%d times:\n%s", n, out)
	}
	for _, l := range logJournalLines[1:] {
		if strings.Contains(out, l) {
			t.Errorf("a line that does not pass: %s", l)
		}
	}
	if !strings.Contains(out, "Following new entries (Ctrl-C to stop)...") {
		t.Errorf("%s", out)
	}
	found := false
	for _, a := range sb.runner.Argvs() {
		if a == "journalctl -u tacquito --no-pager -f -n 0" {
			found = true
		}
	}
	if !found {
		t.Errorf("%q", sb.runner.Argvs())
	}

	// --json: objects only on standard output, the banner on standard error.
	out = sb.logRunAs("", "", journalJSONOf(logJournalLines...), "tail", "--backend=tacacs", "-f", "--json", "--user", "carol")
	var o backend.LogLine
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &o); err != nil || o.User != "carol" || o.Device != "rtr2" || strings.Contains(out, "Following") {
		t.Errorf("stdout:\n%s\n%v", out, err)
	}
	if !strings.Contains(sb.stderr(), "Following new entries") {
		t.Errorf("stderr:\n%s", sb.stderr())
	}
	found = false
	for _, a := range sb.runner.Argvs() {
		if a == "journalctl -u tacquito --no-pager -f -n 0 -o json" {
			found = true
		}
	}
	if !found {
		t.Errorf("%q", sb.runner.Argvs())
	}
}

// With more than one backend --json leaves the headings out (the objects name
// their backend), and a backend that cannot apply the filters to a followed
// log says so.
func TestLogFilterWithSeveralBackends(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.fakeUp()
	out := s.run("", "log", "tail", "7", "--json")
	s.expect(0, "", "")
	if strings.Contains(out, "== Backend") {
		t.Errorf("a heading:\n%s", out)
	}
	out = s.run("", "log", "tail", "7")
	if !strings.Contains(out, "== Backend: fake (fake, faked) ==") {
		t.Errorf("no heading:\n%s", out)
	}
	s.run("", "log", "tail", "-f", "--user", "alice")
	s.expect(0, "Backend 'fake' cannot follow its log with filters.", "")
}
