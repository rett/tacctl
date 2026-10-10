package devconf

// Regression tests of the review of WP11.2: one group per finding (H1-H6,
// M1-M7, L1-L5). The names carry the finding.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

func jset(lines ...string) string { return "set version 25.4\n" + strings.Join(lines, "\n") + "\n" }

func resultOf(t *testing.T, vendor string, expected, got devices.Section, visible bool) SectionResult {
	t.Helper()
	r, err := Compare(vendor, expected, got, visible)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasLine(r SectionResult, op byte, text string) bool {
	return slices.Contains(r.Lines, DiffLine{Op: op, Text: text}) ||
		slices.ContainsFunc(r.Lines, func(l DiffLine) bool { return l.Op == op && l.Text == text })
}

// --- H1, H2, M3: position matters where it does ---------------------------------

func TestOrderAuthenticationOrder(t *testing.T) {
	exp := sec(SectionAAA, "set system authentication-order [ password tacplus ]")
	same := resultOf(t, "junos", exp, sec(SectionAAA, "set system authentication-order password", "set system authentication-order tacplus"), true)
	if same.State != StateOK {
		t.Errorf("same order: %s", same.State)
	}
	rev := resultOf(t, "junos", exp, sec(SectionAAA, "set system authentication-order tacplus", "set system authentication-order password"), true)
	if rev.State != StateDiffers || !slices.ContainsFunc(rev.Lines, func(l DiffLine) bool { return l.Op == OpOrder }) {
		t.Errorf("reversed: %s %v", rev.State, rev.Lines)
	}
}

func TestOrderFilterTerms(t *testing.T) {
	exp := sec(SectionMgmtACL,
		"set firewall family inet filter F term a then accept",
		"set firewall family inet filter F term a from protocol tcp",
		"set firewall family inet filter F term b then discard")
	// the statements of a term are a set
	ok := resultOf(t, "junos", exp, sec(SectionMgmtACL,
		"set firewall family inet filter F term a from protocol tcp",
		"set firewall family inet filter F term a then accept",
		"set firewall family inet filter F term b then discard"), true)
	if ok.State != StateOK {
		t.Errorf("same terms: %s %v", ok.State, ok.Lines)
	}
	// the terms are a sequence
	re := resultOf(t, "junos", exp, sec(SectionMgmtACL,
		"set firewall family inet filter F term b then discard",
		"set firewall family inet filter F term a from protocol tcp",
		"set firewall family inet filter F term a then accept"), true)
	if re.State != StateDiffers || !slices.ContainsFunc(re.Lines, func(l DiffLine) bool {
		return l.Op == OpOrder && strings.Contains(l.Text, "firewall family inet filter F") && strings.Contains(l.Text, "a, b") && strings.Contains(l.Text, "b, a")
	}) {
		t.Errorf("reordered: %s %v", re.State, re.Lines)
	}
	// a filter with a term more is a difference of membership, the order
	// of the terms both have is judged on those
	extra := resultOf(t, "junos", exp, sec(SectionMgmtACL,
		"set firewall family inet filter F term a from protocol tcp",
		"set firewall family inet filter F term a then accept",
		"set firewall family inet filter F term x then accept",
		"set firewall family inet filter F term b then discard"), true)
	if extra.State != StateDiffers || slices.ContainsFunc(extra.Lines, func(l DiffLine) bool { return l.Op == OpOrder }) {
		t.Errorf("extra term: %s %v", extra.State, extra.Lines)
	}
}

func TestOrderCiscoACL(t *testing.T) {
	exp := sec(SectionMgmtACL, "ip access-list standard A", " permit 192.0.2.1", " permit 192.0.2.2", " deny any log")
	// a run of one action is a set
	if r := resultOf(t, "ios", exp, sec(SectionMgmtACL, "ip access-list standard A", " permit 192.0.2.2", " permit 192.0.2.1", " deny any log"), true); r.State != StateOK {
		t.Errorf("run reordered: %s %v", r.State, r.Lines)
	}
	// a deny moved before the permits is another policy
	r := resultOf(t, "ios", exp, sec(SectionMgmtACL, "ip access-list standard A", " deny any log", " permit 192.0.2.1", " permit 192.0.2.2"), true)
	if r.State != StateDiffers || !slices.ContainsFunc(r.Lines, func(l DiffLine) bool { return l.Op == OpOrder }) {
		t.Errorf("deny first: %s %v", r.State, r.Lines)
	}
	// permit, deny, permit is not permit, permit, deny
	r = resultOf(t, "ios", exp, sec(SectionMgmtACL, "ip access-list standard A", " permit 192.0.2.1", " deny any log", " permit 192.0.2.2"), true)
	if r.State != StateDiffers {
		t.Errorf("interleaved: %s", r.State)
	}
	// sequence numbers do not count
	if r := resultOf(t, "ios", exp, sec(SectionMgmtACL, "ip access-list standard A", " 10 permit 192.0.2.1", " 20 permit 192.0.2.2", " 30 deny any log"), true); r.State != StateOK {
		t.Errorf("numbered: %s %v", r.State, r.Lines)
	}
}

// --- H3: secret statements are counted ------------------------------------------

func TestSecretStemsAreAMultiset(t *testing.T) {
	exp := secrets(SectionSNMP, []string{"set snmp community managed authorization read-only"}, true)
	one := resultOf(t, "junos", exp, sec(SectionSNMP, "set snmp community other authorization read-only"), true)
	if one.State != StateOK {
		t.Fatalf("one community: %s", one.State)
	}
	two := resultOf(t, "junos", exp, sec(SectionSNMP,
		"set snmp community other authorization read-only", "set snmp community stray authorization read-only"), true)
	if two.State != StateDiffers || ops(two) != "=+" {
		t.Errorf("a stray community with the managed one's options: %s %q", two.State, ops(two))
	}
	if strings.Contains(allText([]SectionResult{two}), "stray") {
		t.Error("the stray's name is shown")
	}
	// the same on IOS
	cexp := secrets(SectionSNMP, []string{"snmp-server community managed RO ACL"}, true)
	c2 := resultOf(t, "ios", cexp, sec(SectionSNMP, "snmp-server community a RO ACL", "snmp-server community b RO ACL"), true)
	if c2.State != StateDiffers || ops(c2) != "=+" {
		t.Errorf("ios: %s %q", c2.State, ops(c2))
	}
	// two expected, one on the device: one is missing
	two2 := secrets(SectionSNMP, []string{"snmp-server community a RO ACL", "snmp-server community b RO ACL"}, true, true)
	c1 := resultOf(t, "ios", two2, sec(SectionSNMP, "snmp-server community a RO ACL"), true)
	if c1.State != StateDiffers || ops(c1) != "=-" {
		t.Errorf("ios missing: %s %q", c1.State, ops(c1))
	}
	// Normalise keeps both and is idempotent
	n, _ := Normalise("junos", sec("x", "set snmp community a authorization read-only", "set snmp community b authorization read-only"))
	n2, _ := Normalise("junos", n)
	if len(n.Lines) != 2 || !slices.Equal(n.Lines, n2.Lines) || !slices.Equal(n.Secret, n2.Secret) {
		t.Errorf("%q %q", n.Lines, n2.Lines)
	}
}

// --- H4: nothing secret reaches an output ---------------------------------------

var strayJunos = []string{
	`set system tacplus-server 192.0.2.9 secret "zq7sentinelj1"`,
	`set system radius-server 192.0.2.8 secret zq7sentinelj2`,
	`set snmp community zq7sentinelj3 authorization read-only`,
	`set snmp trap-group zq7sentinelj4 targets 192.0.2.5`,
	`set snmp v3 usm local-engine user u authentication-sha authentication-key "zq7sentinelj5"`,
	`set snmp v3 snmp-community c1 community-name zq7sentinelj6 security-name u`,
	`set system login user u authentication encrypted-password "$6$zq7sentinelj7$abcdefgh"`,
	`set system login user u authentication ssh-rsa "ssh-rsa AAAAzq7sentinelj8 u@example.net"`,
	`set system accounting destination tacplus "$9$zq7sentinelj9"`,
	`set system tacplus-options pre-shared-key ascii-text zq7sentinelj10 extra`,
	`set system login user v authentication encrypted-password /* SECRET-DATA */`,
}

var strayCisco = []string{
	"snmp-server community zq7sentinelc1 RO",
	"snmp-server host 192.0.2.5 version 2c zq7sentinelc2",
	"snmp-server host 192.0.2.6 zq7sentinelc3",
	"snmp-server host 192.0.2.7 traps version 3 priv zq7sentinelc4",
	"aaa server radius dynamic-author",
	" client 192.0.2.7 server-key 7 zq7sentinelc5",
	"tacacs server T",
	" key 7 zq7sentinelc6",
	"username x privilege 1 secret 9 $9$zq7sentinelc7",
	"radius-server key zq7sentinelc8",
	"snmp-server user u G v3 auth sha zq7sentinelc9 priv aes 128 zq7sentinelc10",
	"tacacs-server host 192.0.2.8 key zq7sentinelc11 timeout 5",
	"aaa something pre-shared-key 7 zq7sentinelc12",
	"snmp-server something $9$zq7sentinelc13 more",
	"username y password zq7sentinelc14",
	"aaa group server radius G",
	" server-private 192.0.2.9 key 7 zq7sentinelc15",
}

func TestStraySecretsNeverReachAnOutput(t *testing.T) {
	const sentinel = "zq7sentinel"
	dir := t.TempDir()
	store := Store{Records: filepath.Join(dir, "devices-config.json"), Dir: filepath.Join(dir, "device-config")}
	for _, c := range []struct {
		vendor, head string
		lines        []string
		expected     []devices.Section
	}{
		{"junos", "set version 25.4\n", strayJunos, expectedSections(t, "juniper/synthetic-lab/expected.txt")},
		{"ios", "version 15.2\n", strayCisco, expectedSections(t, "ios/reference-lab/expected.txt")},
	} {
		raw := c.head + strings.Join(c.lines, "\n") + "\n"
		for _, hint := range [][]devices.Section{nil, c.expected} {
			ex, err := Extract(c.vendor, raw, hint...)
			if err != nil {
				t.Fatal(err)
			}
			var out strings.Builder
			secretStatements := 0
			for name, s := range ex.Sections {
				for i, l := range s.Lines {
					out.WriteString(l + "\n")
					if s.Secret[i] {
						secretStatements++
					}
				}
				// Normalise again, and the compared form it would be hashed from
				n, _ := Normalise(c.vendor, s)
				out.WriteString(strings.Join(n.Lines, "\n"))
				fp, _ := Fingerprint(c.vendor, s)
				out.WriteString(fp + name)
			}
			results, err := CompareAll(c.expected, ex)
			if err != nil {
				t.Fatal(err)
			}
			out.WriteString(allText(results))
			for _, r := range results {
				out.WriteString(strings.Join(r.Notes, "\n"))
			}
			if err := store.SaveSections("dev1", c.vendor, ex.Sections); err != nil {
				t.Fatal(err)
			}
			disk, _ := os.ReadFile(filepath.Join(store.Dir, "dev1.yaml"))
			out.Write(disk)
			// every stray is in a section (a statement nobody classified
			// would pass the leak check for nothing)
			statements := 0
			for _, s := range ex.Sections {
				statements += len(s.Lines)
			}
			// (the three IOS lines that open a submode are not statements)
			if statements < len(c.lines)-3 || secretStatements < 10 && c.vendor == "ios" || secretStatements < 8 && c.vendor == "junos" {
				t.Errorf("%s: %d statements of %d, %d secret", c.vendor, statements, len(c.lines), secretStatements)
			}
			if strings.Contains(out.String(), sentinel) || strings.Contains(out.String(), "AAAAzq7") {
				// find it
				for _, l := range strings.Split(out.String(), "\n") {
					if strings.Contains(l, sentinel) {
						t.Errorf("%s (hinted %v): %q", c.vendor, hint != nil, l)
					}
				}
			}
		}
	}
	// the errors of a pull name no text of the device
	_, err := Extract("junos", "error: syntax error near zq7sentinelE\n")
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Errorf("%v", err)
	}
	_, err = Extract("ios", "% Invalid input zq7sentinelF\n")
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Errorf("%v", err)
	}
	_, _, err = UnwrapNetconf(`<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>bad zq7sentinelG</error-message></rpc-error></rpc-reply>`)
	_ = err // the device's own message is the one thing UnwrapNetconf passes on; it is not configuration text
}

func TestSnmpHostCommunityPlacement(t *testing.T) {
	for in, want := range map[string]string{
		"snmp-server host 192.0.2.5 version 2c COMM":                         "snmp-server host 192.0.2.5 version 2c <secret>",
		"snmp-server host 192.0.2.5 COMM":                                    "snmp-server host 192.0.2.5 <secret>",
		"snmp-server host 192.0.2.5 traps COMM udp-port 162":                 "snmp-server host 192.0.2.5 traps <secret> udp-port 162",
		"snmp-server host 192.0.2.5 informs version 3 priv USER cpu":         "snmp-server host 192.0.2.5 informs version 3 priv <secret> cpu",
		"snmp-server host 192.0.2.5 vrf MGMT version 2c COMM config":         "snmp-server host 192.0.2.5 vrf MGMT version 2c <secret> config",
		"snmp-server host 192.0.2.5 version 1 COMM":                          "snmp-server host 192.0.2.5 version 1 <secret>",
		"aaa server radius dynamic-author > client 192.0.2.7 server-key 7 H": "aaa server radius dynamic-author > client 192.0.2.7 server-key",
	} {
		got := ciscoStems(in)
		if len(got) != 1 || got[0] != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	// a Junos trap group's name is the community
	if got := junosStems("set snmp trap-group tg1 targets 192.0.2.5"); !slices.Equal(got, []string{"set snmp trap-group <secret> targets 192.0.2.5"}) {
		t.Errorf("%q", got)
	}
}

// --- H5: the lo0 application is the operator's step -------------------------------

func TestLo0ApplicationIsANoteNotADifference(t *testing.T) {
	expected := expectedSections(t, "juniper/synthetic-lab/expected.txt")
	for _, c := range []struct {
		file  string
		notes []string
	}{
		{"display-set.txt", nil},
		{"display-set-nolo0.txt", []string{"filter MGMT-ACL is not applied on lo0"}},
	} {
		ex, err := Extract("junos", capture(t, "juniper/synthetic-lab/"+c.file), expected...)
		if err != nil {
			t.Fatal(err)
		}
		rs, err := CompareAll(expected, ex)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rs {
			if r.Name != SectionMgmtACL {
				if len(r.Notes) != 0 {
					t.Errorf("%s [%s] notes %q", c.file, r.Name, r.Notes)
				}
				continue
			}
			if r.State != StateOK {
				t.Errorf("%s: mgmt-acl %s: %v", c.file, r.State, r.Lines)
			}
			if !slices.Equal(r.Notes, c.notes) {
				t.Errorf("%s: notes %q, want %q", c.file, r.Notes, c.notes)
			}
			for _, l := range r.Lines {
				if strings.Contains(l.Text, "lo0") {
					t.Errorf("%s: %q", c.file, l.Text)
				}
			}
		}
	}
	// the filter absent from the device is missing, with no note
	res := resultOf(t, "junos", sec(SectionMgmtACL, "set firewall family inet filter MGMT-ACL term t then accept"),
		sec(SectionMgmtACL), true)
	if res.State != StateMissing || len(res.Notes) != 0 {
		t.Errorf("%s %q", res.State, res.Notes)
	}
	// another filter applied on lo0 is the operator's
	other := resultOf(t, "junos", sec(SectionMgmtACL, "set firewall family inet filter MGMT-ACL term t then accept"),
		sec(SectionMgmtACL, "set firewall family inet filter MGMT-ACL term t then accept",
			"set interfaces lo0 unit 0 family inet filter input PROTECT-RE"), true)
	if other.State != StateOK || !slices.Equal(other.Notes, []string{"filter MGMT-ACL is not applied on lo0"}) {
		t.Errorf("%s %q %v", other.State, other.Notes, other.Lines)
	}
}

// --- H6: only what the device omits is not visible --------------------------------

func TestNotVisibleIsOnlyWhatTheDeviceOmits(t *testing.T) {
	expected := []devices.Section{
		{Name: SectionAAA, Lines: []string{
			"set system tacplus-server 198.18.0.24 secret clear-server-secret",
			"set system tacplus-server 198.18.0.24 single-connection"}, Secret: []bool{true, false}},
		{Name: SectionBreakGlass, Lines: []string{
			"set system login user exampleadmin class RW-CLASS authentication encrypted-password '<HASH>'",
			"set system login user ghost class RW-CLASS authentication encrypted-password '<HASH>'"}, Secret: []bool{true, true}},
	}
	for _, c := range []struct {
		file    string
		visible bool
		unseen  int
		missing int
	}{
		// superuser: nothing is omitted, the absent account's statements are missing
		{"juniper/lab-superuser/display-set.txt", true, 0, 2},
		// engineer: the server's secret is omitted (not visible); the masked
		// account secret still appears, the absent account is missing
		{"juniper/lab-engineer/display-set.txt", false, 1, 2},
	} {
		ex, err := Extract("junos", capture(t, c.file), expected...)
		if err != nil {
			t.Fatal(err)
		}
		if ex.SecretsVisible != c.visible {
			t.Errorf("%s: visible %v", c.file, ex.SecretsVisible)
		}
		rs, _ := CompareAll(expected, ex)
		unseen, missing := 0, 0
		for _, r := range rs {
			unseen += r.NotVisible
			for _, l := range r.Lines {
				if l.Op == OpMissing {
					missing++
				}
				if l.Op == OpNotVisible && !strings.Contains(l.Text, "tacplus-server 198.18.0.24 secret") {
					t.Errorf("%s: %q is not visible", c.file, l.Text)
				}
			}
		}
		if unseen != c.unseen || missing != c.missing {
			t.Errorf("%s: %d not visible, %d missing; want %d and %d", c.file, unseen, missing, c.unseen, c.missing)
		}
	}
}

// --- M1: nothing reversible is stored ---------------------------------------------

func TestStoredSectionsHoldNoSecretValue(t *testing.T) {
	secretsOf := map[string][]string{
		"juniper/lab-superuser/display-set.txt":  {"EXAMPLEHASH", "$9$EXAMPLEEXAMPLE", "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEY", "example-community"},
		"juniper/synthetic-lab/display-set.txt":  {"EXAMPLEHASH", "$9$EXAMPLEEXAMPLE", "STRAYSTRAY", "example-community", "other-example"},
		"ios/reference-lab/running-config.txt":   {"0822455D0A16", "EXAMPLEEXAMPLE", "example-community", "other-example", "example-trap-community"},
		"ios-xe/reference-16/running-config.txt": {"0822455D0A16", "EXAMPLEKEY", "EXAMPLEEXAMPLE"},
		"ios/reference-12x/running-config.txt":   {"0822455D0A16", "EXAMPLEHASH", "example-community"},
		"ios/real-12.4-7200/running-config.txt":  {"EXAMPLEKEY", "$1$EXAMPLE$HASHHASHHASHHASHHASHH.", "zz-lab-ro-community"},
	}
	for rel, values := range secretsOf {
		vendor := "ios"
		if strings.HasPrefix(rel, "juniper") {
			vendor = "junos"
		}
		raw := capture(t, rel)
		for _, v := range values {
			if !strings.Contains(raw, v) {
				t.Fatalf("%s: fixture lacks %q", rel, v)
			}
		}
		ex, err := Extract(vendor, raw)
		if err != nil {
			t.Fatal(err)
		}
		s := newStore(t)
		if err := s.SaveSections("dev", vendor, ex.Sections); err != nil {
			t.Fatal(err)
		}
		disk, err := os.ReadFile(filepath.Join(s.Dir, "dev.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var all strings.Builder
		all.Write(disk)
		for _, sec := range ex.Sections {
			all.WriteString(strings.Join(sec.Lines, "\n"))
		}
		for _, v := range values {
			if strings.Contains(all.String(), v) {
				t.Errorf("%s: %q is in what is kept", rel, v)
			}
		}
		// what is stored compares as what was extracted
		back, err := s.Sections("dev", vendor)
		if err != nil {
			t.Fatal(err)
		}
		for n, sec := range ex.Sections {
			if !slices.Equal(back[n].Lines, sec.Lines) || !slices.Equal(back[n].Secret, sec.Secret) {
				t.Errorf("%s [%s]\n got %q %v\nwant %q %v", rel, n, back[n].Lines, back[n].Secret, sec.Lines, sec.Secret)
			}
		}
	}
	// Whatever is handed to SaveSections is elided: a raw rendering too.
	s := newStore(t)
	raw := map[string]devices.Section{SectionAAA: {Name: SectionAAA, Lines: []string{
		"set system tacplus-server 192.0.2.10 secret clear-value-zz"}}}
	if err := s.SaveSections("dev", "junos", raw); err != nil {
		t.Fatal(err)
	}
	disk, _ := os.ReadFile(filepath.Join(s.Dir, "dev.yaml"))
	if strings.Contains(string(disk), "clear-value-zz") {
		t.Errorf("%s", disk)
	}
}

// --- M2: SecretsVisible --------------------------------------------------------------

func TestSecretsVisibleFromTokensOnly(t *testing.T) {
	for _, c := range []struct {
		name, raw string
		want      bool
	}{
		{"plain", jset("set system host-name a"), true},
		{"masked", jset("set system root-authentication encrypted-password /* SECRET-DATA */"), false},
		{"free text", jset(`set system host-name a`, `set snmp description "see SECRET-DATA in the manual"`), true},
		{"quoted comment", jset(`set snmp contact "/* SECRET-DATA */"`), true},
		{"a hash", jset(`set system root-authentication encrypted-password "$6$salt$hashhash"`), true},
	} {
		ex, err := Extract("junos", c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if ex.SecretsVisible != c.want {
			t.Errorf("%s: %v, want %v", c.name, ex.SecretsVisible, c.want)
		}
	}
	// the caller's knowledge wins
	f, tr := false, true
	ex, _ := ExtractWith("junos", jset("set system host-name a"), Options{SecretsVisible: &f})
	if ex.SecretsVisible {
		t.Error("override to false")
	}
	ex, _ = ExtractWith("junos", jset("set system root-authentication encrypted-password /* SECRET-DATA */"), Options{SecretsVisible: &tr})
	if !ex.SecretsVisible {
		t.Error("override to true")
	}
	ex, _ = ExtractWith("ios", "version 15.2\n", Options{SecretsVisible: &f})
	if ex.SecretsVisible {
		t.Error("override on ios")
	}
}

// --- M4: IOS behaviour taken from knowledge, not a lab ([A]) ------------------------

func TestIOSAddedLinesAreNotStrays(t *testing.T) {
	raw := "version 15.2\n" +
		"aaa new-model\n" +
		"aaa session-id common\n" +
		"enable secret 9 $9$abcdefgh\n" +
		"ip tacacs source-interface Loopback0\n" +
		"privilege exec level 7 clear counters\n" +
		"privilege exec level 7 clear\n" +
		"privilege exec level 7 show\n" +
		"privilege exec level 7 show ip route\n" +
		"privilege exec level 7 show ip\n"
	ex, err := Extract("ios", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Sections[SectionAAA].Lines; !slices.Equal(got, []string{"aaa new-model"}) {
		t.Errorf("aaa = %q", got)
	}
	if got := ex.Sections[SectionRoles].Lines; !slices.Equal(got, []string{
		"privilege exec level 7 clear counters", "privilege exec level 7 show ip route"}) {
		t.Errorf("roles = %q", got)
	}
	// a rendering that carries a parent itself keeps it
	exp := sec(SectionRoles, "privilege exec level 7 show", "privilege exec level 7 show ip route")
	ex, _ = Extract("ios", raw, exp)
	r := resultOf(t, "ios", exp, ex.Sections[SectionRoles], true)
	if !hasLine(r, OpSame, "privilege exec level 7 show") {
		t.Errorf("%v", r.Lines)
	}
	// a rendering that names the source interface claims it
	exp = sec(SectionAAA, "aaa new-model", "ip tacacs source-interface Loopback0")
	ex, _ = Extract("ios", raw, exp)
	if r := resultOf(t, "ios", exp, ex.Sections[SectionAAA], true); r.State != StateOK {
		t.Errorf("claimed source-interface: %s %v", r.State, r.Lines)
	}
}

func TestIOSSnmpUserIsNotShown(t *testing.T) {
	exp := sec(SectionSNMP,
		"snmp-server view V iso included",
		"snmp-server user u G v3 auth sha pw priv aes 128 pw2")
	dev := sec(SectionSNMP, "snmp-server view V iso included")
	r := resultOf(t, "ios", exp, dev, true)
	if r.State != StateOK || len(r.Notes) != 1 || !strings.Contains(r.Notes[0], "snmp-server user") {
		t.Errorf("%s %q %v", r.State, r.Notes, r.Lines)
	}
	for _, l := range r.Lines {
		if l.Op == OpMissing {
			t.Errorf("%q", l.Text)
		}
	}
	// only that line: the section is n/a with the note
	only := resultOf(t, "ios", sec(SectionSNMP, "snmp-server user u G v3 auth sha pw priv aes 128 pw2"), sec(SectionSNMP), true)
	if only.State != StateNA || len(only.Notes) != 1 {
		t.Errorf("%s %q", only.State, only.Notes)
	}
	// a device that does print it is compared
	shown := resultOf(t, "ios", exp, sec(SectionSNMP, "snmp-server view V iso included",
		"snmp-server user u G v3 auth sha x priv aes 128 y"), true)
	if shown.State != StateOK || len(shown.Notes) != 0 {
		t.Errorf("%s %q", shown.State, shown.Notes)
	}
}

// --- M5: a hierarchy tacctl renders nothing for is shown, not judged --------------

func TestInformationalLinesForNotRenderedSections(t *testing.T) {
	r := resultOf(t, "junos", sec(SectionNetconf), sec(SectionNetconf, "set system services netconf ssh"), true)
	if r.State != StateNA || !hasLine(r, OpInfo, "set system services netconf ssh") || r.NotVisible != 0 {
		t.Errorf("%s %v", r.State, r.Lines)
	}
	// a secret there is shown by its stem only
	s := resultOf(t, "junos", sec(SectionSNMP), sec(SectionSNMP, "set snmp community private authorization read-only"), true)
	if s.State != StateNA || !hasLine(s, OpInfo, "set snmp community <secret> authorization read-only (present, not compared)") {
		t.Errorf("%s %v", s.State, s.Lines)
	}
	// and it is not drift for staleness
	rec := &Record{Vendor: "junos", Result: ResultOK}
	got, err := Stale(rec, map[string]devices.Section{SectionNetconf: sec(SectionNetconf, "set system services netconf ssh")}, nil)
	if err != nil || got != StaleOK {
		t.Errorf("%q %v", got, err)
	}
}

// --- M6: display inheritance ---------------------------------------------------------

func TestInheritedStatementsAndGroups(t *testing.T) {
	if _, read, _ := Commands("junos"); read != "show configuration | display inheritance no-comments | display set" {
		t.Errorf("%q", read)
	}
	ex, err := Extract("junos", capture(t, "juniper/synthetic-inherit/display-set.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"set system authentication-order password",
		"set system authentication-order tacplus",
		"set system tacplus-server 192.0.2.10 secret",
		"set system tacplus-server 192.0.2.10 single-connection",
		"set system accounting events login",
		"set system accounting events change-log",
		"set system accounting destination tacplus",
	}
	if got := ex.Sections[SectionAAA].Lines; !slices.Equal(got, want) {
		t.Errorf("aaa = %q", got)
	}
	for n, s := range ex.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, "groups") || strings.Contains(l, "GLOBAL") {
				t.Errorf("[%s] %q", n, l)
			}
		}
	}
	// the inherited statement compares as the rendered one
	exp := sec(SectionAAA, "set system authentication-order [ password tacplus ]",
		"set system tacplus-server 192.0.2.10 secret clear", "set system tacplus-server 192.0.2.10 single-connection",
		"set system accounting events [ login change-log ]", "set system accounting destination tacplus")
	exp.Secret = []bool{false, true, false, false, false}
	if r := resultOf(t, "junos", exp, ex.Sections[SectionAAA], true); r.State != StateOK {
		t.Errorf("%s %v", r.State, r.Lines)
	}
}

// --- M7: a banner is not a refusal ---------------------------------------------------

func TestPercentLineInBannerIsNotARefusal(t *testing.T) {
	raw := "Building configuration...\n\nversion 15.2\nhostname a\n!\nbanner motd ^C\n% Authorized users only\n^C\naaa new-model\n"
	ex, err := Extract("ios", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Sections[SectionAAA].Lines; !slices.Equal(got, []string{"aaa new-model"}) {
		t.Errorf("aaa = %q", got)
	}
	// without any banner too: a '% ' line after the configuration began
	if _, err := Extract("ios", "version 15.2\n% some note\naaa new-model\n"); err != nil {
		t.Errorf("%v", err)
	}
	// at the start it is the device's refusal
	if _, err := Extract("ios", "\n% Invalid input detected at '^' marker.\n"); !errors.Is(err, ErrParse) {
		t.Errorf("%v", err)
	}
	if _, err := Extract("ios", "sw#show running-config\n   ^\n% Invalid input detected\n"); !errors.Is(err, ErrParse) {
		t.Errorf("%v", err)
	}
}

// --- L1: Rename ------------------------------------------------------------------------

func TestStoreRenameErrors(t *testing.T) {
	s := newStore(t)
	if err := os.WriteFile(s.Records, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("a", "b"); err == nil {
		t.Error("a corrupt records file is not reported")
	}

	s = newStore(t)
	put := func(name string) {
		r, _ := s.Load()
		r.Put(name, sampleRecord())
		if err := s.Save(r); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveSections(name, "junos", map[string]devices.Section{SectionAAA: sec(SectionAAA, "set a b "+name)}); err != nil {
			t.Fatal(err)
		}
	}
	put("a")
	// the new name has a sections file (no record): refused, nothing moves
	if err := s.SaveSections("b", "junos", map[string]devices.Section{SectionAAA: sec(SectionAAA, "set b b")}); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("a", "b"); err == nil {
		t.Error("overwrote an existing sections file")
	}
	got, _ := s.Sections("b", "junos")
	if !slices.Equal(got[SectionAAA].Lines, []string{"set b b"}) {
		t.Errorf("b was changed: %q", got[SectionAAA].Lines)
	}
	if r, _ := s.Load(); func() bool { _, ok := r.Of("a"); return !ok }() {
		t.Error("the record of a moved")
	}
	// renaming a device that has nothing is not an error
	if err := s.Rename("zz", "yy"); err != nil {
		t.Errorf("%v", err)
	}
}

// --- L2: warnings ----------------------------------------------------------------------

func TestUnwrapNetconfWarnings(t *testing.T) {
	text, warns, err := UnwrapNetconf(`<rpc-reply><rpc-error><error-severity>warning</error-severity><error-message>statement not found</error-message></rpc-error>` +
		`<configuration-output>set a b
</configuration-output></rpc-reply>`)
	if err != nil || text != "set a b\n" || !slices.Equal(warns, []string{"statement not found"}) {
		t.Errorf("%q %q %v", text, warns, err)
	}
	if _, _, err := UnwrapNetconf(`<rpc-reply><rpc-error><error-severity>error</error-severity><error-message>no</error-message></rpc-error><configuration-output>x</configuration-output></rpc-reply>`); !errors.Is(err, ErrParse) {
		t.Errorf("%v", err)
	}
}

// --- L3: keyword and hash recognition --------------------------------------------------

func TestSecretRecognitionIsNarrow(t *testing.T) {
	// 'permissions secret' is a class bit
	got := junosStems("set system login class C permissions secret", "set system login class C permissions secret-control")
	if !slices.Equal(got, []string{"set system login class C permissions secret", "set system login class C permissions secret-control"}) {
		t.Errorf("%q", got)
	}
	for _, x := range junosCanon([]string{"set system login class C permissions secret"}, nil) {
		if x.secret {
			t.Error("a permission is taken as a secret")
		}
	}
	// text that looks like a hash is text; a hash in an unknown statement
	// is elided and the statement stays
	for in, want := range map[string]string{
		`set system login message "$5$ per unit of $9$ stuff"`: `set system login message "$5$ per unit of $9$ stuff"`,
		`set system foo bar $9$abcdefgh baz`:                   `set system foo bar <secret> baz`,
		`set system foo "$6$salt$hashhash" baz`:                `set system foo <secret> baz`,
		`set system foo "a /* SECRET-DATA */ b"`:               `set system foo "a /* SECRET-DATA */ b"`,
	} {
		if got := junosStems(in); len(got) != 1 || got[0] != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
	// IOS: free text is text
	for _, in := range []string{"snmp-server location Rack key 4", "description link to key room", "snmp-server contact secret admin"} {
		if got := ciscoStems(in); len(got) != 1 || got[0] != in {
			t.Errorf("%q: %q", in, got)
		}
	}
}

// --- L5 ----------------------------------------------------------------------------------

func TestSectionsFileNeedsItsVersion(t *testing.T) {
	s := newStore(t)
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(s.Dir, "dev.yaml"), []byte("aaa: |\n  set a b\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sections("dev", "junos"); err == nil || !strings.Contains(err.Error(), "device config pull") {
		t.Errorf("%v", err)
	}
}

func TestPutCopiesApplied(t *testing.T) {
	r := NewRecords()
	rec := sampleRecord()
	rec.Applied = &Applied{By: "alice", Result: "ok"}
	r.Put("a", rec)
	rec.Applied.By = "mallory"
	got, _ := r.Of("a")
	if got.Applied == nil || got.Applied.By != "alice" {
		t.Errorf("%+v", got.Applied)
	}
}

// --- tests of the tests ------------------------------------------------------------------

// The expected.txt of the fixtures are devices.Managed's goldens, the
// address of the lab scope mapped to a documentation address: they are not
// a second opinion on what Managed renders.
func TestExpectedFixturesAreTheManagedGoldens(t *testing.T) {
	for fixture, golden := range map[string]string{
		"juniper/synthetic-lab/expected.txt": "managed.juniper.lab.txt",
		"ios/reference-lab/expected.txt":     "managed.cisco.lab.txt",
		"ios/reference-12x/expected.txt":     "managed.cisco-legacy.lab.txt",
		"ios-xe/reference-16/expected.txt":   "managed.cisco-radius.lab.txt",
	} {
		data, err := os.ReadFile(filepath.Join("../../tests/fixtures/golden", golden))
		if errors.Is(err, os.ErrNotExist) {
			t.Skip("no managed goldens in this tree")
		}
		if err != nil {
			t.Fatal(err)
		}
		want := strings.ReplaceAll(string(data), "10.0.0.42", "192.0.2.10")
		if got := capture(t, fixture); got != want {
			t.Errorf("%s is not %s with its address mapped", fixture, golden)
		}
	}
}

// What devices.Managed renders, as a device prints it: Junos with its
// lists and blocks expanded and its users split, IOS indented by one space
// with the ACL entries as IOS keeps them and the secrets as IOS stores
// them. Not the walkthrough's own syntax: a device never prints that.
func TestManagedGoldensAsADevicePrintsThem(t *testing.T) {
	files, _ := filepath.Glob("../../tests/fixtures/golden/managed.*.txt")
	if len(files) == 0 {
		t.Skip("no managed goldens in this tree")
	}
	for _, f := range files {
		base := filepath.Base(f)
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		junos := strings.HasPrefix(base, "managed.juniper")
		var expected []devices.Section
		var cur *devices.Section
		var device []string
		for _, l := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(l, "["):
				name, rest, _ := strings.Cut(strings.TrimPrefix(l, "["), "]")
				if strings.TrimSpace(rest) == "not rendered" {
					cur = nil
					continue
				}
				expected = append(expected, devices.Section{Name: name})
				cur = &expected[len(expected)-1]
			case (strings.HasPrefix(l, "| ") || strings.HasPrefix(l, "* ")) && cur != nil:
				cur.Lines = append(cur.Lines, l[2:])
				cur.Secret = append(cur.Secret, l[0] == '*')
				if junos {
					device = append(device, junosAsPrinted(l[2:], l[0] == '*')...)
				} else {
					device = append(device, iosAsPrinted(l[2:], l[0] == '*')...)
				}
			}
		}
		raw := strings.Join(device, "\n")
		vendor := "ios"
		if junos {
			vendor = "junos"
		} else {
			raw = "version 15.2\n" + raw
		}
		ex, err := Extract(vendor, raw, expected...)
		if err != nil {
			t.Errorf("%s: %v", base, err)
			continue
		}
		results, err := CompareAll(expected, ex)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			want := StateOK
			if !slices.ContainsFunc(expected, func(s devices.Section) bool { return s.Name == r.Name && len(s.Lines) > 0 }) {
				want = StateNA
			}
			// IOS does not print an SNMPv3 user: a section of nothing else is n/a
			if r.State == StateNA && want == StateOK && len(r.Notes) > 0 {
				continue
			}
			if r.State != want {
				t.Errorf("%s [%s] %s, want %s:\n%s", base, r.Name, r.State, want, allText([]SectionResult{r}))
			}
		}
	}
}

// junosAsPrinted is a rendered Junos line as 'display set' prints it.
func junosAsPrinted(line string, secret bool) []string {
	switch {
	case strings.Contains(line, "authentication encrypted-password"):
		// 'set system login user U class C authentication encrypted-password H'
		f := strings.Fields(line)
		return []string{strings.Join(f[:7], " "), strings.Join(append(f[:5:5], "authentication", "encrypted-password", `"$6$examplesalt$EXAMPLEHASHEXAMPLEHASH"`), " ")}
	}
	if i := strings.Index(line, "["); i >= 0 {
		j := strings.Index(line, "]")
		var out []string
		for _, w := range strings.Fields(line[i+1 : j]) {
			out = append(out, junosAsPrinted(strings.TrimSpace(line[:i])+" "+w+line[j+1:], secret)...)
		}
		return out
	}
	if i := strings.Index(line, "{"); i >= 0 {
		var out []string
		for _, st := range strings.Split(strings.Trim(strings.TrimSpace(line[i:]), "{} "), ";") {
			if st = strings.TrimSpace(st); st != "" {
				out = append(out, strings.TrimSpace(line[:i])+" "+st)
			}
		}
		return out
	}
	if secret {
		f := strings.Fields(line)
		if i := slices.Index(f, "secret"); i >= 0 {
			return []string{strings.Join(f[:i+1], " ") + ` "$9$EXAMPLEEXAMPLE"`}
		}
		if len(f) > 3 && f[1] == "snmp" && f[2] == "community" {
			f[3] = "device-chose-this-name"
			return []string{strings.Join(f, " ")}
		}
	}
	return []string{line}
}

// iosAsPrinted is a rendered IOS line as 'show running-config' prints it.
func iosAsPrinted(line string, secret bool) []string {
	t := strings.TrimLeft(line, " ")
	indent := len(line) - len(t)
	switch {
	case strings.HasPrefix(t, "remark "):
		return nil
	case strings.HasPrefix(t, "snmp-server user "):
		return nil // running-config does not print it
	case secret && strings.HasPrefix(t, "key "):
		t = "key 7 0822455D0A16"
	case secret && strings.HasPrefix(t, "tacacs-server host "):
		t = t[:strings.Index(t, " key ")] + " key 7 0822455D0A16"
	case secret && strings.HasPrefix(t, "snmp-server community "):
		f := strings.Fields(t)
		f[2] = "device-chose-this-name"
		t = strings.Join(f, " ")
	case secret && strings.HasPrefix(t, "username "):
		f := strings.Fields(t)
		t = strings.Join(f[:5], " ") + " " + f[5] + " $9$EXAMPLEEXAMPLE"
	case strings.HasPrefix(t, "permit ") && strings.HasSuffix(t, " 0.0.0.0"):
		t = strings.TrimSuffix(t, " 0.0.0.0")
	case strings.HasPrefix(t, "permit host "):
		t = "permit " + strings.TrimPrefix(t, "permit host ")
	}
	if indent > 0 {
		return []string{" " + t}
	}
	return []string{t}
}

// The Reader still runs the setup and then the read; the context carries.
func TestReaderPassesTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	read, _ := Reader("junos")
	var seen error
	_, err := read(ctx, runnerFunc(func(c context.Context, _ string) (string, error) {
		seen = c.Err()
		return "set a b\n", nil
	}))
	if err != nil || !errors.Is(seen, context.Canceled) {
		t.Errorf("%v %v", err, seen)
	}
}

type runnerFunc func(context.Context, string) (string, error)

func (f runnerFunc) Run(ctx context.Context, cmd string) (string, error) { return f(ctx, cmd) }
