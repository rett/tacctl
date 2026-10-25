package blocks

import (
	"strings"
	"testing"
)

func TestIOSSystemRulesParseGood(t *testing.T) {
	text := "logging host 192.0.2.50\n" +
		"logging host LogHost.Example.NET vrf MGMT\n" +
		"logging trap informational\n" +
		"logging buffered 16384 warnings\n" +
		"logging origin-id hostname\n" +
		"service timestamps log datetime msec localtime show-timezone\n" +
		"service timestamps debug datetime msec\n" +
		"login on-failure log every 3\n" +
		"login on-success log\n" +
		"login delay 3\n" +
		"security passwords min-length 12\n" +
		"security authentication failure rate 5 log\n" +
		"ip ssh version 2\n" +
		"ip ssh time-out 60\n" +
		"ip ssh authentication-retries 3\n" +
		"clock summer-time EDT recurring 2 Sunday March 02:00 first Sunday November 02:00\n"
	b, fs := LintIOSSystem(text, LayerScope)
	for _, f := range fs {
		if f.Severity == SevError {
			t.Fatalf("errors:\n%s", dump(fs))
		}
	}
	if len(b.Rules) != 16 {
		t.Fatalf("%d rules", len(b.Rules))
	}
	st := IOSSystemStatements(b)
	for _, want := range []string{"logging host 192.0.2.50", "logging host loghost.example.net vrf MGMT", "logging buffered 16384 warnings",
		"service timestamps log datetime msec localtime show-timezone", "login on-failure log every 3", "ip ssh version 2",
		"clock summer-time EDT recurring 2 Sunday March 02:00 first Sunday November 02:00"} {
		if !contains(st, want) {
			t.Errorf("no statement %q in %q", want, st)
		}
	}
	// read back, the same block, the same text
	b2, fs2 := LintIOSSystem(b.String(false), LayerScope)
	if HasErrors(fs2) || b2.String(false) != b.String(false) {
		t.Errorf("round trip:\n%s\n%s", b.String(false), b2.String(false))
	}
	// a login delay is noted: it also delays the server's own logins
	if !anyFindingHas(fs, SevNote, "login delay makes every login wait 3 seconds") {
		t.Errorf("no login delay note:\n%s", dump(fs))
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestIOSSystemRulesRefuse(t *testing.T) {
	for _, c := range []struct{ text, want string }{
		{"logging host\n", "this statement is not one of"},
		{"logging console debugging\n", "a block holds"},
		{"logging source-interface Loopback0\n", "a block holds"},
		{"logging trap loud\n", "is not a logging severity"},
		{"logging buffered 100\n", "is not a number from 4096 to 2147483647"},
		{"logging origin-id ip\n", "this statement is not one of"},
		{"service timestamps log datetime\n", "this statement is not one of"},
		{"service timestamps log uptime\n", "this statement is not one of"},
		{"service password-encryption\n", "a block holds"},
		{"login block-for 120 attempts 3 within 60\n", "a block holds"},
		{"login delay 11\n", "is not a number from 1 to 10"},
		{"security passwords min-length 17\n", "is not a number from 1 to 16"},
		{"ip ssh version 1\n", "this statement is not one of"},
		{"ip ssh time-out 200\n", "is not a number from 1 to 120"},
		{"ip ssh authentication-retries 9\n", "is not a number from 0 to 5"},
		{"ip ssh source-interface Loopback0\n", "this statement is not one of"},
		{"ip http server\n", "is not one of domain, name-server"},
		{"clock summer-time EDT recurring first Sunday March 25:00 last Sunday October 02:00\n", "is not a time of day"},
		{"clock summer-time EDT recurring first Sunday Marsh 02:00 last Sunday October 02:00\n", "is not a month name"},
		{"clock summer-time EDT date March 8 2026 02:00 November 1 2026 02:00\n", "this statement is not one of"},
		{"logging host 192.0.2.50\nlogging host 192.0.2.50\n", "is stated twice"},
	} {
		_, fs := LintIOSSystem(c.text, LayerScope)
		if !anyFindingHas(fs, SevError, c.want) {
			t.Errorf("%q: want an error with %q:\n%s", c.text, c.want, dump(fs))
		}
	}
}

func TestIOSSystemRulesLayersAndNoLines(t *testing.T) {
	scope, fs := LintIOSSystem("logging host 192.0.2.50\nlogging host 192.0.2.51\nlogging trap informational\nlogging buffered 16384\nip ssh time-out 60\n"+
		"service timestamps log datetime msec\n", LayerScope)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	dev, fs := LintIOSSystem("logging trap warnings\nlogging buffered 8192 errors\nno logging host 192.0.2.51\nno ip ssh time-out\n"+
		"service timestamps log datetime msec localtime\n", LayerDevice)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	r := ResolveIOSSystem(nil, scope, dev)
	got := strings.Join(IOSSystemStatements(r), "|")
	// the device's trap level, buffered size and timestamps replace the
	// scope's (one identity each), 192.0.2.51 and the ssh time-out are taken out
	want := "logging host 192.0.2.50|logging trap warnings|logging buffered 8192 errors|service timestamps log datetime msec localtime"
	if got != want {
		t.Errorf("resolved:\n%s\nwant\n%s", got, want)
	}
	if s := dev.String(false); !strings.Contains(s, "no logging host 192.0.2.51\n") || !strings.Contains(s, "no ip ssh time-out\n") {
		t.Errorf("the no lines:\n%s", s)
	}
	// one summer-time statement is the identity: 'no clock summer-time' names it
	if _, fs := LintIOSSystem("no clock summer-time\n", LayerDevice); HasErrors(fs) {
		t.Errorf("no clock summer-time refused:\n%s", dump(fs))
	}
	for _, bad := range []string{"no logging\n", "no logging host\n", "no ip ssh time-out 60\n", "no login delay 3\n"} {
		if _, fs := LintIOSSystem(bad, LayerDevice); !HasErrors(fs) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestAdoptIOSSystemRules(t *testing.T) {
	raw := "logging host 192.0.2.50\n" +
		"logging trap informational\n" +
		"logging console debugging\n" +
		"service timestamps log datetime msec localtime show-timezone\n" +
		"login on-failure log every 3\n" +
		"ip ssh version 2\n" +
		"ip ssh server algorithm mac hmac-sha2-256\n" +
		"security passwords min-length 12\n"
	res := AdoptIOSSystem(raw, nil, nil, LayerScope)
	for _, want := range []string{"logging host 192.0.2.50", "logging trap informational", "service timestamps log datetime msec localtime show-timezone",
		"login on-failure log every 3", "ip ssh version 2", "security passwords min-length 12"} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	for _, not := range []string{"logging console", "algorithm"} {
		if strings.Contains(res.Text, not) {
			t.Errorf("the draft holds %q:\n%s", not, res.Text)
		}
	}
	if res.Statements != 6 {
		t.Errorf("%d statements:\n%s", res.Statements, res.Text)
	}
	// stated already by the block: not repeated; another value: left as it is
	same, _ := LintIOSSystem("logging trap informational\nip ssh version 2\nlogin on-failure log\n", LayerScope)
	res = AdoptIOSSystem(raw, same, nil, LayerScope)
	for _, not := range []string{"logging trap", "ip ssh version", "login on-failure"} {
		if strings.Contains(res.Text, not) {
			t.Errorf("the draft repeats %q:\n%s", not, res.Text)
		}
	}
	if !strings.Contains(res.Text, "logging host 192.0.2.50") {
		t.Errorf("the draft lost the host:\n%s", res.Text)
	}
}
