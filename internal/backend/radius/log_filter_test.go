package radius_test

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
)

// The RADIUS logs with the filters of 'tacctl log' (logs_filter.go): the
// clock of the test is Fri 2026-10-02 12:00 local time.

const (
	authAlice1 = "2026-10-02 09:00:00 Access-Accept scope=site-a device=sw1 client=192.0.2.10 nas=sw1 reason='-' user=alice"
	authBob    = "2026-10-02 09:30:00 Access-Reject scope=site-a device=sw1 client=192.0.2.10 nas=sw1 reason='not an enabled user of this scope' user=bob"
	authAlice2 = "2026-10-02 10:00:00 Access-Accept scope=site-a device=rtr1 client=2001:db8::1 nas=rtr1 reason='-' user=alice"
	authAlice3 = "2026-10-02 11:00:00 Access-Reject scope=site-a device=jsw1 client=192.0.2.11 nas=jsw1 reason='tacctl_pap: Crypt digest does not match' user=alice"
	authOld    = "2026-10-01 08:00:00 Access-Reject scope=site-a device=sw1 client=192.0.2.10 nas=sw1 reason='-' user=alice"

	daemonReady = "Fri Oct  2 09:00:00 2026 : Info: Ready to process requests"
	daemonBob   = "Fri Oct  2 09:30:00 2026 : Auth: (3) Login incorrect (tacctl_pap: Crypt digest does not match): [bob/<via Auth-Type = PAP>] (from client sw1 port 0)"
	daemonAlice = "Fri Oct  2 10:00:00 2026 : Auth: (4) Login OK: [alice/<via Auth-Type = PAP>] (from client sw1 port 0)"
)

func filterLogs(t *testing.T, r *renv) {
	t.Helper()
	l := r.m.L
	writeFile(t, l.AuthLog, strings.Join([]string{authOld, authAlice1, authBob, authAlice2, authAlice3}, "\n")+"\n")
	writeFile(t, l.DaemonLog, strings.Join([]string{daemonReady, daemonBob, daemonAlice}, "\n")+"\n")
}

func at(h, m int) time.Time { return time.Date(2026, 10, 2, h, m, 0, 0, time.Local) }

func runLog(t *testing.T, r *renv, f backend.LogFilter, sub string, args ...string) string {
	t.Helper()
	r.reset()
	r.env.LogFilter = f
	var b strings.Builder
	if err := r.m.Log(context.Background(), sub, args, &b); err != nil {
		t.Fatalf("log %s: %v\n%s", sub, err, r.stderr)
	}
	return strip(b.String())
}

func lines(s string, prefixes ...string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		for _, p := range prefixes {
			if strings.HasPrefix(l, p) {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

func TestLogTailFilters(t *testing.T) {
	r := newEnv(t)
	r.up()
	filterLogs(t, r)
	auth := func(s string) []string { return lines(s, "2026-") }
	daemon := func(s string) []string { return lines(s, "Fri ") }

	out := runLog(t, r, backend.LogFilter{User: "alice"}, "tail")
	contains(t, out, "\nRecent RADIUS Authentications ("+r.m.L.AuthLog+")\n")
	contains(t, out, "\nFreeRADIUS Daemon Log ("+r.m.L.DaemonLog+")\n")
	if got := auth(out); !reflect.DeepEqual(got, []string{authOld, authAlice1, authAlice2, authAlice3}) {
		t.Errorf("auth: %q", got)
	}
	if got := daemon(out); !reflect.DeepEqual(got, []string{daemonAlice}) {
		t.Errorf("daemon: %q", got)
	}

	// The count limits what is left; the user of "alice bob" is not alice.
	out = runLog(t, r, backend.LogFilter{User: "alice"}, "tail", "2")
	if got := auth(out); !reflect.DeepEqual(got, []string{authAlice2, authAlice3}) {
		t.Errorf("auth 2: %q", got)
	}

	// The window, on both logs.
	out = runLog(t, r, backend.LogFilter{Since: at(9, 15), Until: at(10, 0)}, "tail")
	if got := auth(out); !reflect.DeepEqual(got, []string{authBob, authAlice2}) {
		t.Errorf("window auth: %q", got)
	}
	if got := daemon(out); !reflect.DeepEqual(got, []string{daemonBob, daemonAlice}) {
		t.Errorf("window daemon: %q", got)
	}

	// The device: the auth log's client; the daemon log cannot be matched.
	out = runLog(t, r, backend.LogFilter{Device: "sw1", Addrs: []string{"192.0.2.10"}}, "tail")
	if got := auth(out); !reflect.DeepEqual(got, []string{authOld, authAlice1, authBob}) {
		t.Errorf("device: %q", got)
	}
	contains(t, out, "  --device cannot be applied to the daemon log")
	if got := daemon(out); got != nil {
		t.Errorf("daemon with a device: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{Device: "rtr1", Addrs: []string{"2001:db8::1"}}, "tail")
	if got := auth(out); !reflect.DeepEqual(got, []string{authAlice2}) {
		t.Errorf("device v6: %q", got)
	}

	// AND, and nothing left.
	out = runLog(t, r, backend.LogFilter{User: "alice", Device: "sw1", Addrs: []string{"192.0.2.10"}, Since: at(8, 0)}, "tail")
	if got := auth(out); !reflect.DeepEqual(got, []string{authAlice1}) {
		t.Errorf("and: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{User: "carol"}, "tail")
	contains(t, out, "  No matching entries.\n")

	// A bad count.
	r.env.LogFilter = backend.LogFilter{User: "alice"}
	err := r.m.Log(context.Background(), "tail", []string{"x"}, &strings.Builder{})
	wantCode(t, err, 1)
	contains(t, r.stderr.String(), "tail: invalid number of lines: 'x'")
}

func TestLogSearchAndFailuresFilters(t *testing.T) {
	r := newEnv(t)
	r.up()
	filterLogs(t, r)

	out := runLog(t, r, backend.LogFilter{User: "alice"}, "search", "Access-Accept")
	contains(t, out, "RADIUS log entries matching 'Access-Accept'")
	if got := lines(out, "2026-"); !reflect.DeepEqual(got, []string{authAlice1, authAlice2}) {
		t.Errorf("search: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{Since: at(9, 15)}, "search", "bob")
	if got := lines(out, "2026-", "Fri "); !reflect.DeepEqual(got, []string{authBob, daemonBob}) {
		t.Errorf("search window: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{User: "bob"}, "search", "alice")
	contains(t, out, "  No matches found.\n")

	// failures: the last 24 hours, then the window.
	out = runLog(t, r, backend.LogFilter{User: "alice"}, "failures")
	contains(t, out, "RADIUS Authentication Failures (last 24 hours)")
	if got := lines(out, "2026-"); !reflect.DeepEqual(got, []string{authAlice3}) {
		t.Errorf("failures: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{Until: at(10, 0)}, "failures")
	contains(t, out, "RADIUS Authentication Failures (until 2026-10-02 10:00:00)")
	if got := lines(out, "2026-"); !reflect.DeepEqual(got, []string{authOld, authBob}) {
		t.Errorf("failures until: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{Device: "jsw1", Addrs: []string{"192.0.2.11"}}, "failures")
	if got := lines(out, "2026-"); !reflect.DeepEqual(got, []string{authAlice3}) {
		t.Errorf("failures device: %q", got)
	}
	out = runLog(t, r, backend.LogFilter{User: "carol"}, "failures")
	contains(t, out, "  No failures in the last 24 hours\n")
	out = runLog(t, r, backend.LogFilter{User: "carol", Since: at(8, 0)}, "failures")
	contains(t, out, "  No failures since 2026-10-02 08:00:00\n")
}

func TestLogJSON(t *testing.T) {
	r := newEnv(t)
	r.up()
	filterLogs(t, r)
	r.env.DeviceName = func(a string) string {
		if a == "192.0.2.10" {
			return "sw1"
		}
		return ""
	}
	objs := func(out string) []backend.LogLine {
		t.Helper()
		var all []backend.LogLine
		for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if l == "" {
				continue
			}
			var o backend.LogLine
			if err := json.Unmarshal([]byte(l), &o); err != nil {
				t.Fatalf("%q: %v", l, err)
			}
			all = append(all, o)
		}
		return all
	}

	out := runLog(t, r, backend.LogFilter{JSON: true, User: "bob"}, "tail")
	if strings.Contains(out, "Recent") || strings.Contains(out, "----") {
		t.Fatalf("headings: %q", out)
	}
	got := objs(out)
	if len(got) != 2 || got[0].Log != "auth" || got[1].Log != "daemon" {
		t.Fatalf("%+v", got)
	}
	want := backend.LogLine{Time: at(9, 30).UTC().Format(time.RFC3339), Backend: "radius", Log: "auth", Message: authBob,
		User: "bob", Address: "192.0.2.10", Device: "sw1", Outcome: "reject"}
	if got[0] != want {
		t.Errorf("%+v\nwant %+v", got[0], want)
	}
	if got[1].Message != daemonBob || got[1].Time != at(9, 30).UTC().Format(time.RFC3339) {
		t.Errorf("%+v", got[1])
	}

	// Notes go to standard error, not into the objects.
	out = runLog(t, r, backend.LogFilter{JSON: true, Device: "sw1", Addrs: []string{"192.0.2.10"}}, "tail", "2")
	if got := objs(out); len(got) != 2 || got[0].Message != authAlice1 && got[0].Message != authOld {
		t.Errorf("%+v", got)
	}
	contains(t, r.stderr.String(), "--device cannot be applied to the daemon log")
	out = runLog(t, r, backend.LogFilter{JSON: true}, "search", "bob")
	if got := objs(out); len(got) != 2 {
		t.Errorf("search: %+v", got)
	}
	out = runLog(t, r, backend.LogFilter{JSON: true}, "failures")
	if got := objs(out); len(got) != 2 {
		t.Errorf("failures: %+v", got)
	}
	if out = runLog(t, r, backend.LogFilter{JSON: true, User: "carol"}, "failures"); out != "" {
		t.Errorf("%q", out)
	}
}

const detail = "Fri Oct  2 10:00:00 2026\n\tUser-Name = \"alice\"\n\tNAS-IP-Address = 192.0.2.10\n\tAcct-Status-Type = Start\n\tAcct-Session-Id = \"s1\"\n\n" +
	"Fri Oct  2 10:05:00 2026\n\tUser-Name = \"alice\"\n\tNAS-IP-Address = 192.0.2.10\n\tAcct-Status-Type = Interim-Update\n\tAcct-Session-Id = \"s1\"\n\n" +
	"Fri Oct  2 10:10:00 2026\n\tUser-Name = \"alice\"\n\tNAS-IP-Address = 192.0.2.10\n\tAcct-Status-Type = Stop\n\tAcct-Session-Id = \"s1\"\n\n" +
	"Fri Oct  2 11:00:00 2026\n\tUser-Name = \"bob\"\n\tNAS-IPv6-Address = 2001:db8::1\n\tPacket-Src-IPv6-Address = 2001:db8::1\n\tAcct-Status-Type = Start\n\tAcct-Session-Id = \"s2\"\n\n" +
	"Fri Oct  2 11:30:00 2026\n\tUser-Name = \"carol\"\n\tPacket-Src-IP-Address = 192.0.2.11\n\tAcct-Status-Type = Start\n\tAcct-Session-Id = \"s3\"\n\n"

func runAcct(t *testing.T, r *renv, f backend.LogFilter, args ...string) string {
	t.Helper()
	r.reset()
	r.env.LogFilter = f
	var b strings.Builder
	if err := r.m.Accounting(context.Background(), "tail", args, &b); err != nil {
		t.Fatal(err)
	}
	return strip(b.String())
}

func TestAccountingFilters(t *testing.T) {
	r := newEnv(t)
	r.up()
	writeFile(t, r.m.L.AcctLog, detail)
	sessions := func(out string) string {
		var ids []string
		for _, l := range lines(out, "\tAcct-Session-Id") {
			ids = append(ids, strings.Trim(strings.TrimPrefix(l, "\tAcct-Session-Id = "), `"`))
		}
		return strings.Join(ids, " ")
	}
	for _, c := range []struct {
		name string
		f    backend.LogFilter
		args []string
		want string
	}{
		{"user", backend.LogFilter{User: "alice"}, nil, "s1 s1 s1"},
		{"since", backend.LogFilter{Since: at(10, 6)}, nil, "s1 s2 s3"},
		{"until", backend.LogFilter{Until: at(10, 5)}, nil, "s1 s1"},
		{"device", backend.LogFilter{Device: "sw1", Addrs: []string{"192.0.2.10"}}, nil, "s1 s1 s1"},
		{"device v6 by NAS-IPv6-Address", backend.LogFilter{Device: "rtr1", Addrs: []string{"2001:db8::1"}}, nil, "s2"},
		{"device by Packet-Src-IP-Address", backend.LogFilter{Device: "jsw1", Addrs: []string{"192.0.2.11"}}, nil, "s3"},
		{"login is Start or Stop", backend.LogFilter{Type: backend.TypeLogin}, nil, "s1 s1 s2 s3"},
		{"login of a user", backend.LogFilter{Type: backend.TypeLogin, User: "alice"}, nil, "s1 s1"},
		{"the count limits what is left", backend.LogFilter{Type: backend.TypeLogin}, []string{"2"}, "s2 s3"},
		{"and", backend.LogFilter{User: "alice", Device: "sw1", Addrs: []string{"192.0.2.10"}, Since: at(10, 1)}, nil, "s1 s1"},
	} {
		out := runAcct(t, r, c.f, c.args...)
		if got := sessions(out); got != c.want {
			t.Errorf("%s: %q, want %q\n%s", c.name, got, c.want, out)
		}
		contains(t, out, "\nRecent RADIUS Accounting Records\n")
	}
	out := runAcct(t, r, backend.LogFilter{User: "dave"})
	contains(t, out, "  No matching records.\n")

	// RADIUS accounting has no change or command records: it says so.
	for _, ty := range []string{backend.TypeChange, backend.TypeCommand} {
		out = runAcct(t, r, backend.LogFilter{Type: ty})
		contains(t, out, "  RADIUS accounting has no "+ty+" records")
		notContains(t, out, "Acct-Session-Id")
	}
}

func TestAccountingJSON(t *testing.T) {
	r := newEnv(t)
	r.up()
	writeFile(t, r.m.L.AcctLog, detail)
	r.env.DeviceName = func(a string) string {
		if a == "192.0.2.10" {
			return "sw1"
		}
		return ""
	}
	out := runAcct(t, r, backend.LogFilter{JSON: true, User: "alice", Type: backend.TypeLogin})
	if strings.Contains(out, "Recent") || strings.Count(out, "\n") != 2 {
		t.Fatalf("%q", out)
	}
	var o struct {
		Time       string
		Backend    string
		Log        string
		User       string
		Address    string
		Device     string
		Attributes map[string]string
	}
	first := strings.SplitN(out, "\n", 2)[0]
	if err := json.Unmarshal([]byte(first), &o); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"User-Name": "alice", "NAS-IP-Address": "192.0.2.10", "Acct-Status-Type": "Start", "Acct-Session-Id": "s1"}
	if o.Time != at(10, 0).UTC().Format(time.RFC3339) || o.Backend != "radius" || o.Log != "accounting" || o.User != "alice" ||
		o.Address != "192.0.2.10" || o.Device != "sw1" || !reflect.DeepEqual(o.Attributes, want) {
		t.Errorf("%+v", o)
	}
	// A type RADIUS has none of: a note on standard error, nothing on standard output.
	out = runAcct(t, r, backend.LogFilter{JSON: true, Type: backend.TypeChange})
	if out != "" {
		t.Errorf("%q", out)
	}
	contains(t, r.stderr.String(), "RADIUS accounting has no change records")
}

func TestFollowFiltered(t *testing.T) {
	r := newEnv(t)
	r.up()
	f := backend.LogFilter{User: "alice"}
	src := r.m.FollowFiltered(f)
	if len(src) != 2 ||
		!reflect.DeepEqual(src[0].Argv, []string{"tail", "-F", "-q", "-n", "0", r.m.L.AuthLog}) ||
		!reflect.DeepEqual(src[1].Argv, []string{"tail", "-F", "-q", "-n", "0", r.m.L.DaemonLog}) {
		t.Fatalf("%v", src)
	}
	r.env.LogFilter = f
	if out, ok := src[0].Line(authAlice1); !ok || out != authAlice1 {
		t.Errorf("%v %q", ok, out)
	}
	if _, ok := src[0].Line(authBob); ok {
		t.Error("bob's line")
	}
	if out, ok := src[1].Line(daemonAlice); !ok || out != daemonAlice {
		t.Errorf("%v %q", ok, out)
	}
	if _, ok := src[1].Line(daemonBob); ok {
		t.Error("bob's daemon line")
	}

	// A device: the auth log only.
	f = backend.LogFilter{Device: "sw1", Addrs: []string{"192.0.2.10"}}
	r.env.LogFilter = f
	src = r.m.FollowFiltered(f)
	if len(src) != 1 {
		t.Fatalf("%v", src)
	}
	if _, ok := src[0].Line(authAlice1); !ok {
		t.Error("a line of the device")
	}
	if _, ok := src[0].Line(authAlice2); ok {
		t.Error("a line of another device")
	}

	// --json: an object, with the time the line arrives.
	f = backend.LogFilter{JSON: true}
	r.env.LogFilter = f
	out, ok := r.m.FollowFiltered(f)[0].Line(authBob)
	if !ok || !strings.Contains(out, `"user":"bob"`) || !strings.Contains(out, `"time":"`+r.now.UTC().Format(time.RFC3339)+`"`) {
		t.Errorf("%v %s", ok, out)
	}
	// A window is compared with the arrival: the clock is 12:00.
	f = backend.LogFilter{Until: at(11, 0)}
	r.env.LogFilter = f
	if _, ok := r.m.FollowFiltered(f)[0].Line(authBob); ok {
		t.Error("an entry after --until")
	}
}
