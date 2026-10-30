package cli

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
)

// hostSeen writes a seen cache with sightings of web1 (192.168.1.10, long
// ago, so stale) and web2 (192.168.1.12, an hour ago), both by alice.
func hostSeen(t *testing.T, sb *sandbox) {
	t.Helper()
	now := time.Now()
	sb.seenFrom(t,
		backend.Sighting{Time: now.AddDate(0, 0, -60), Address: "192.168.1.10", User: "bob", Outcome: backend.SightAccept},
		backend.Sighting{Time: now.Add(-time.Hour), Address: "192.168.1.12", User: "alice", Outcome: backend.SightAccept})
}

// 'host list' has the columns and the summary of 'device list': STATE, LAST
// SEEN, BY and NOTICES from the seen cache and the notices, the age of the
// seen data and the heading's count.
func TestHostListColumnsAndSummaryLikeDeviceList(t *testing.T) {
	sb := hostLab(t)
	sb.recordHostAddress("web1", "192.168.1.10")
	hostSeen(t, sb)
	out := plain(sb.run("", []string{"host", "list"}))
	header, _ := hostListRows(out)
	want := "NAME TARGET ADDRESS SCOPE STATE LAST SEEN BY SERVER METHOD USERS NOTICES"
	if strings.Join(header, " ") != want {
		t.Fatalf("header %v, want %s\n%s", header, want, out)
	}
	for _, re := range []string{
		`(?m)^Enrolled Linux hosts \(3\)$`,
		`(?m)^  web2 +root@web2\.example\.net +192\.168\.1\.12 +lab +configured +\S+ \S+ +alice +192\.0\.2\.1 +tacplus +\d+ +-$`,
		`(?m)^  web1 +root@192\.168\.1\.10 +192\.168\.1\.10 +lab +configured stale +\S+ \S+ +bob +192\.0\.2\.1 +tacplus +\d+ +-$`,
		`(?m)^  db1 +root@10\.99\.0\.20 +- +prod +configured +never +- +192\.0\.2\.1 +tacplus +\d+ +-$`,
		`(?m)^  seen data as of \S+ \S+ \(\d+ days old: [^)]*\); stale after \d+ days$`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("host list lacks %s:\n%s", re, out)
		}
	}
	// No seen data at all: the same words as 'device list'.
	sb2 := hostLab(t)
	if out := plain(sb2.run("", []string{"host", "list"})); !strings.Contains(out, "seen data: none (tacctl device scan)") ||
		!regexp.MustCompile(`(?m)^  web2 .* configured +- +- +192\.0\.2\.1 `).MatchString(out) {
		t.Errorf("no seen data:\n%s", out)
	}
}

// A held host is BREAK-GLASS in STATE with or without the stale mark, and a
// notice shows in NOTICES, in the pointer under the table and in the JSON.
func TestHostListStateHoldAndNotices(t *testing.T) {
	sb := hostLab(t)
	sb.recordHostAddress("web1", "192.168.1.10")
	hostSeen(t, sb)
	holdHost(t, sb, "web1", "locked out of sudo")
	sb.write("state/linux-hosts", hostLines+"ubuntu|dba@h.example.net||prod|192.0.2.1|\n", 0o600)
	out := plain(sb.run("", []string{"host", "list"}))
	for _, re := range []string{
		`(?m)^  web1 +\S+ +192\.168\.1\.10 +lab +BREAK-GLASS stale +`,
		`(?m)^  ubuntu +\S+ +- +prod +configured +never +- +\S+ +tacplus +\d+ +generic-name$`,
		`(?m)^  1 open notice\(s\): tacctl device notice list$`,
		`(?m)^  1 host\(s\) held for break-glass: tacctl breakglass list$`,
	} {
		if !regexp.MustCompile(re).MatchString(out) {
			t.Errorf("host list lacks %s:\n%s", re, out)
		}
	}
	js := hostListJSONOf(t, sb.run("", []string{"host", "list", "--json"}))
	u := js["ubuntu"]
	if len(u.Notices) != 1 || u.Notices[0].Kind != "generic-name" || u.Notices[0].Acked || u.State != "configured" || u.Seen != nil {
		t.Errorf("ubuntu %+v", u)
	}
	if w := js["web2"]; w.Seen == nil || w.Seen.LastUser != "alice" || w.Seen.Stale || w.Notices == nil || len(w.Notices) != 0 {
		t.Errorf("web2 %+v seen %+v", w, w.Seen)
	}
	if w := js["web1"]; w.Seen == nil || !w.Seen.Stale || w.Seen.LastUser != "bob" {
		t.Errorf("web1 seen %+v", w.Seen)
	}
}

func hostNamesOf(t *testing.T, out string) []string {
	t.Helper()
	var names []string
	for n := range hostListJSONOf(t, out) {
		names = append(names, n)
	}
	return names
}

// --name, --ip, --scope and --stale narrow the list as the options of
// 'device list' do: comma lists, all options must match, the heading says
// how many there were.
func TestHostListFilters(t *testing.T) {
	sb := hostLab(t)
	sb.recordHostAddress("web1", "192.168.1.10")
	hostSeen(t, sb)
	for _, c := range []struct {
		args []string
		want []string
		head string
	}{
		{[]string{"--name", "WEB"}, []string{"web1", "web2"}, "Enrolled Linux hosts (2), of 3"},
		{[]string{"--name", "db,web2"}, []string{"db1", "web2"}, "Enrolled Linux hosts (2), of 3"},
		{[]string{"--ip", "192.168.1.0/24"}, []string{"web1", "web2"}, "Enrolled Linux hosts (2), of 3"},
		{[]string{"--ip", "192.168.1.12"}, []string{"web2"}, "Enrolled Linux hosts (1), of 3"},
		{[]string{"--ip", "192.168.1.10,192.168.1.12"}, []string{"web1", "web2"}, "Enrolled Linux hosts (2), of 3"},
		{[]string{"--scope", "prod"}, []string{"db1"}, "Enrolled Linux hosts (1), of 3"},
		{[]string{"--scope", "prod,lab"}, []string{"db1", "web1", "web2"}, "Enrolled Linux hosts (3), of 3"},
		// the seen data decides --stale; a host never seen is not stale
		{[]string{"--stale"}, []string{"web1"}, "Enrolled Linux hosts (1), of 1"},
		{[]string{"--stale", "--scope", "lab", "--name", "web"}, []string{"web1"}, "Enrolled Linux hosts (1), of 1"},
		{[]string{"--name", "web", "--scope", "prod"}, nil, "Enrolled Linux hosts (0), of 3"},
	} {
		out := plain(sb.run("", append([]string{"host", "list"}, c.args...)))
		if sb.code != 0 || !strings.Contains(out, c.head+"\n") {
			t.Errorf("%v: %d, heading %q missing:\n%s", c.args, sb.code, c.head, out)
		}
		_, rows := hostListRows(out)
		var got []string
		for n := range rows {
			got = append(got, n)
		}
		js := hostNamesOf(t, sb.run("", append(append([]string{"host", "list"}, c.args...), "--json")))
		if len(got) != len(c.want) || len(js) != len(c.want) {
			t.Errorf("%v: table %v, json %v, want %v", c.args, got, js, c.want)
			continue
		}
		for _, n := range c.want {
			if _, ok := rows[n]; !ok {
				t.Errorf("%v: %s missing from %v", c.args, n, got)
			}
		}
	}
	if out := plain(sb.run("", []string{"host", "list", "--scope", "nowhere"})); !strings.Contains(out, "None match.") {
		t.Errorf("no match:\n%s", out)
	}
	if got := strings.TrimSpace(sb.run("", []string{"host", "list", "--scope", "nowhere", "--json"})); got != "[]" {
		t.Errorf("no match, JSON: %q", got)
	}
}

// An engineer lists, filters and counts the hosts of their own scopes only.
func TestHostListFiltersEngineerOwnScopes(t *testing.T) {
	sb := hostLab(t)
	hostSeen(t, sb)
	out := sb.asEngineer("", "host", "list")
	if !strings.Contains(out, "Enrolled Linux hosts (2)\n") || strings.Contains(out, "db1") {
		t.Errorf("engineer's list:\n%s", out)
	}
	// the count of "of N" is of the engineer's hosts, not of all three
	out = sb.asEngineer("", "host", "list", "--name", "web1")
	if !strings.Contains(out, "Enrolled Linux hosts (1), of 2\n") {
		t.Errorf("engineer --name:\n%s", out)
	}
	// another scope's host is not found, however it is asked for
	for _, args := range [][]string{{"--scope", "prod"}, {"--name", "db1"}, {"--ip", "10.99.0.20"}, {"--ip", "10.99."}} {
		out = sb.asEngineer("", append([]string{"host", "list"}, args...)...)
		if sb.code != 0 || strings.Contains(out, "db1") || !strings.Contains(out, "None match.") {
			t.Errorf("engineer %v: %d\n%s", args, sb.code, out)
		}
		if js := sb.asEngineer("", append(append([]string{"host", "list"}, args...), "--json")...); strings.TrimSpace(js) != "[]" {
			t.Errorf("engineer %v, JSON: %s", args, js)
		}
	}
	out = sb.asEngineer("", "host", "list", "--stale")
	if sb.code != 0 || !strings.Contains(out, "of 0") && !strings.Contains(out, "None match.") {
		t.Errorf("engineer --stale:\n%s", out)
	}
}

// This server's own login shows no scope, and no --scope selects it.
func TestHostListFiltersLeaveTheServersOwnLoginsScopeAlone(t *testing.T) {
	hs := newHostSandbox(t)
	enrolLocal(t, hs)
	hs.run(nil, "host", "list", "--scope", "tacctl")
	out := plain(hs.out.String())
	if hs.code != 0 || strings.Contains(out, "authsrv") || !strings.Contains(out, "None match.") {
		t.Errorf("--scope tacctl: %d\n%s", hs.code, out)
	}
	hs.run(nil, "host", "list", "--name", "authsrv")
	if out = plain(hs.out.String()); !regexp.MustCompile(`(?m)^  authsrv +local +127\.0\.0\.1 +- +configured `).MatchString(out) {
		t.Errorf("the server's own login:\n%s", out)
	}
}

func TestHostListArgumentsOfTheFilters(t *testing.T) {
	sb := hostLab(t)
	for _, args := range [][]string{{"--name"}, {"--ip"}, {"--scope"}, {"--stale=1"}} {
		sb.run("", append([]string{"host", "list"}, args...))
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Usage: tacctl host list [--name <text>] [--ip <addr|cidr|text>] [--scope <scope>] [--stale] [--json]") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
}
