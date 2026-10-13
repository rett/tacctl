package wti

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const fixtures = "../../../tests/fixtures/devconf/wti"

// body returns a fixture's screen (the text after its '# ---' line) and the
// path its header names ('# path:' of pages/).
func body(t *testing.T, rel string) (path, screen string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtures, rel))
	if err != nil {
		t.Fatal(err)
	}
	s := string(data)
	head, rest, ok := strings.Cut(s, "\n# ---\n")
	if !ok {
		return "", s
	}
	for _, l := range strings.Split(head, "\n") {
		if v, ok := strings.CutPrefix(l, "# path: "); ok {
			path = v
		}
	}
	return path, rest
}

// describe is a parsed screen as the table test's expectations are written.
func describe(p *Parsed) string {
	var parts []string
	switch p.Page.Kind {
	case KindHelp:
		parts = append(parts, "version="+p.Version, "commands="+strconv.Itoa(len(p.Commands)), "config="+strings.Join(p.Config, ","))
	case KindStatus:
		parts = append(parts, "ports="+strconv.Itoa(p.Ports), "inuse="+strconv.Itoa(p.InUse))
	case KindLine:
		parts = append(parts, "site="+p.SiteID)
	case KindUsers:
		parts = append(parts, "names="+strings.Join(p.Names, ","))
	case KindList:
		first, last, empty := p.Entries[0].Slot, p.Entries[len(p.Entries)-1].Slot, 0
		for _, e := range p.Entries {
			if e.Command == "" {
				empty++
			}
		}
		parts = append(parts, "slots="+strconv.Itoa(first)+"-"+strconv.Itoa(last), "empty="+strconv.Itoa(empty))
		for _, e := range p.Entries {
			if e.Command != "" {
				parts = append(parts, strconv.Itoa(e.Slot)+"="+e.Command)
			}
		}
	default:
		for _, f := range p.Fields {
			n := strings.ReplaceAll(f.Item.Key, "{user}", p.User)
			if n == "" {
				n = f.Item.Fact
			}
			if n == "" {
				continue
			}
			parts = append(parts, n+"="+f.Value)
		}
	}
	return strings.Join(parts, "; ")
}

const (
	tacacsFields = "tacacs enable=on; tacacs primary=192.0.2.42; tacacs secondary=; tacacs secret=defined; " +
		"tacacs fallback-timer=15; tacacs fallback-local=on-transport-failure; tacacs port=49; tacacs default-access=on; " +
		"tacacs account-module=enabled; tacacs session-module=enabled; tacacs service-name=wti; tacacs debug=off"
	radiusFields = "radius enable=off; radius primary=; radius primary-secret=; radius secondary=; radius secondary-secret=; " +
		"radius fallback-timer=3; radius fallback-local=off; radius retries=3; radius port=1812; radius accounting-port=1813; " +
		"radius default-access=on; radius onetime-auth=off; radius onetime-timer=5; radius onetime-type=dbm; " +
		"radius session-module=enabled; radius message-authenticator=off; radius debug=off"
	snmpFields = "snmp enable=on; snmp version=v1-v2-only; snmp read-only=yes; snmp system-name=wti.site.exam...; " +
		"snmp contact=Example NOC (...; snmp location=Example City,...; snmp ro-community=ro-community; snmp rw-community=rw-community"
	trapFields   = "snmp trap manager 1=192.0.2.34; snmp trap manager 2=; snmp trap manager 3=; snmp trap manager 4=; snmp trap community=ro-community; snmp trap version=v2; snmp trap engine-id="
	networkOff   = "iptables=off; snmp=on; snmp-trap=on; tacacs=on; radius=off; multiple-logins=on"
	networkOn    = "iptables=on; snmp=on; snmp-trap=on; tacacs=on; radius=off; multiple-logins=on"
	userFields   = "user-name=localadmin; user localadmin level=administrator; user localadmin password=defined; user localadmin keys=; user-port-access=defined; user-services=serial,telnet-ssh,web,outbound; user-callback=; user localadmin api-token="
	emptyList    = "empty=12"
	ruleLines    = "1=-A INPUT -i lo -j ACCEPT; 2=-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; 3=-A INPUT -s 10.1.100.0/23 -p tcp --dport 22 -j ACCEPT; 4=-A INPUT -s 10.0.20.0/24 -p tcp --dport 22 -j ACCEPT; 5=-A INPUT -s 10.0.28.34 -p tcp --dport 22 -j ACCEPT; 6=-A INPUT -s 10.0.28.34 -p udp --dport 161:162 -j ACCEPT; 7=-A INPUT -s 10.0.28.36 -p tcp --dport 22 -j ACCEPT; 8=-A INPUT -s 10.0.28.36 -p udp --dport 161:162 -j ACCEPT; 9=-A INPUT -s 10.0.30.0/24 -p tcp --dport 22 -j ACCEPT; 10=-A INPUT -s 10.0.40.0/24 -p tcp --dport 22 -j ACCEPT; 11=-A INPUT -s 10.0.50.0/24 -p tcp --dport 22 -j ACCEPT; 12=-A INPUT -s 10.0.60.0/24 -p tcp --dport 22 -j ACCEPT"
	rulesPage2   = "13=-A INPUT -s 10.0.70.0/24 -p tcp --dport 22 -j ACCEPT; 14=-A INPUT -s 10.0.90.0/24 -p tcp --dport 22 -j ACCEPT; 15=-A INPUT -s 10.0.120.0/24 -p tcp --dport 22 -j ACCEPT; 16=-A INPUT -s 192.0.2.14 -p udp --dport 161:162 -j ACCEPT; 17=-A INPUT -s 10.1.101.0/24 -p udp --dport 161 -j ACCEPT; 18=-A INPUT -i eth0 -s 10.1.100.0/23 -p icmp -j ACCEPT; 19=-A INPUT -i eth0 -s 10.0.0.0/16 -p icmp -j ACCEPT; 20=-A INPUT -i eth0 -s 192.0.2.14 -p icmp -j ACCEPT; 21=-A INPUT -j DROP; 22=-A OUTPUT -j ACCEPT; 23=-P INPUT DROP; 24=-P OUTPUT DROP"
	defaultTacac = "tacacs-default-access=on; tacacs default-level=viewonly; tacacs-port-access=defined; tacacs default-services=serial,telnet-ssh,web,restful-api"
)

// Every screen of tests/fixtures/devconf/wti and its pages/ is either a page
// of the table, read to these fields, or a title the table does not know.
func TestFixtureScreens(t *testing.T) {
	want := map[string]struct{ page, fields string }{
		"03-help-administrator.txt": {"/H", "version=8.10; commands=30; config=/F,/P,/N,/PNA,/AC,/I,/UFW,/CP,/VPN,/TEL,/WOF"},
		"03-help-superuser.txt":     {"/H", "version=8.10; commands=23; config=/F,/P,/N,/PNA,/AC,/I"},
		"03-help-user.txt":          {"/H", "version=8.10; commands=15; config="},
		"03-help-viewonly.txt":      {"/H", "version=8.10; commands=11; config="},
		"04-network-status.txt":     {"/SN", "ports=32; inuse=2"},
		"05-system-parameters.txt":  {"/F", "lockout=off"},
		"06-network-parameters.txt": {"/N", networkOff},
		"07-tacacs.txt":             {"/N > 28", tacacsFields},
		"08-snmp-access.txt":        {"/N > 25", snmpFields},
		"09-snmp-trap.txt":          {"/N > 26", trapFields},
		"10-iptables.txt":           {"/N > 5", "slots=1-12; " + emptyList},
		"12-radius.txt":             {"/N > 29", radiusFields},
		"16-site-id.txt":            {"/J", "site=wti.site.example.net"},
		"21-accepted-value.txt": {"/N > 26", "snmp trap manager 1=192.0.2.34; snmp trap manager 2=; snmp trap manager 3=; " +
			"snmp trap manager 4=999.999.999.999; snmp trap community=ro-community; snmp trap version=v2; snmp trap engine-id="},
		"26-page-after-change.txt": {"/N > 29", strings.NewReplacer(
			"radius fallback-timer=3", "radius fallback-timer=5", "radius fallback-local=off", "radius fallback-local=on-all-failures",
			"radius retries=3", "radius retries=4", "radius debug=off", "radius debug=on").Replace(radiusFields)},
		"30-iptables-uploaded-page.txt":   {"/N > 5", "slots=1-12; empty=0; " + ruleLines},
		"30-iptables-uploaded-page-2.txt": {"/N > 5", "slots=13-24; empty=0; " + rulesPage2},
		"30-iptables-uploaded-page-3.txt": {"/N > 5", "slots=25-36; empty=11; 25=-P FORWARD DROP"},
		"31-network-iptables-on.txt":      {"/N", networkOn},
		"32-user-directory-view.txt":      {"/F > 1 > 1", "names=localadmin"},
		"33-user-directory-details.txt":   {"/F > 1 > 1 > <name>", userFields},

		"pages/alarm-top.txt":     {},
		"pages/network-top.txt":   {"/N", networkOff},
		"pages/network-25.txt":    {"/N > 25", snmpFields},
		"pages/network-25-4.txt":  {"/N > 25 > 4", "snmp system-name=wti.site.example.net"},
		"pages/network-25-5.txt":  {"/N > 25 > 5", "snmp contact=Example NOC (555) 0100"},
		"pages/network-25-6.txt":  {"/N > 25 > 6", "snmp location=Example City, Example State"},
		"pages/network-26.txt":    {"/N > 26", trapFields},
		"pages/network-28.txt":    {"/N > 28", tacacsFields},
		"pages/network-28-8.txt":  {"/N > 28 > 8", defaultTacac},
		"pages/network-29.txt":    {"/N > 29", radiusFields},
		"pages/network-29-11.txt": {"/N > 29 > 11", "radius-default-access=on; radius default-level=user; radius-port-access=defined; radius default-services=serial,telnet-ssh,web,restful-api"},
		"pages/network-5.txt":     {"/N > 5", "slots=1-12; " + emptyList},
		"pages/system-top.txt":    {"/F", "lockout=off"},
	}
	// 25-9 is the SNMP access page after a refused '9': its header says the
	// page of the V3 users, whose screen is the access page with an error
	// line: refused.
	refused := map[string]error{"pages/network-25-9.txt": ErrPath}

	var files []string
	for _, g := range []string{"*.txt", "pages/*.txt"} {
		m, err := filepath.Glob(filepath.Join(fixtures, g))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range m {
			rel, _ := filepath.Rel(fixtures, f)
			files = append(files, rel)
		}
	}
	if len(files) < 100 {
		t.Fatalf("only %d fixtures found", len(files))
	}
	known := 0
	for _, rel := range files {
		path, screen := body(t, rel)
		p, err := ParseScreen(path, screen)
		w, isPage := want[rel]
		switch {
		case refused[rel] != nil:
			if !errors.Is(err, refused[rel]) {
				t.Errorf("%s: %v, want %v", rel, err, refused[rel])
			}
		case isPage && w.page != "":
			known++
			if err != nil {
				t.Errorf("%s: %v", rel, err)
				continue
			}
			if p.Page.Path != w.page {
				t.Errorf("%s: page %s, want %s", rel, p.Page.Path, w.page)
			}
			if got := describe(p); got != w.fields {
				t.Errorf("%s:\n got %s\nwant %s", rel, got, w.fields)
			}
		default:
			// a prompt, a menu or a page the table does not open
			if !errors.Is(err, ErrUnknownPage) {
				t.Errorf("%s: want ErrUnknownPage, got page=%v err=%v", rel, p != nil, err)
			}
		}
	}
	if known != len(want)-1 {
		t.Errorf("%d screens read, want %d", known, len(want)-1)
	}
}

// The fixtures' headers and the sanitised sentinel: a refused screen's error
// names its title and not one value of it.
func TestErrorsNameTheTitleOnly(t *testing.T) {
	const secret = "SENTINEL-VALUE-1"
	screen := "28\n\nTACACS: [Shared]\n\n1.  Enable:                     On\n2.  Primary host/address:       192.0.2.42\n" +
		"3.  Secondary host/address:\n4.  Secret Word:                " + secret + "\n5.  Fallback Timer:             15 Sec\n" +
		"\nEnter: #<CR> to change,\n"
	_, err := ParseScreen("/N > 28", screen)
	if !errors.Is(err, ErrLayout) {
		t.Fatalf("a secret printed in clear: %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), "192.0.2.42") {
		t.Errorf("the error holds a value: %v", err)
	}
	// an unknown title: only the title
	_, err = ParseScreen("", "\nSOME NEW PAGE: [Shared]\n\n1. Foo:  "+secret+"\n")
	if !errors.Is(err, ErrUnknownPage) || strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "SOME NEW PAGE") {
		t.Errorf("unknown page: %v", err)
	}
	// a long or control-ridden title is cut and made printable
	_, err = ParseScreen("", "X"+strings.Repeat("Y", 200)+"\x07Z: 1\n")
	if !errors.Is(err, ErrUnknownPage) || len(err.Error()) > 200 {
		t.Errorf("long title: %v", err)
	}
}

func TestLayoutRefusals(t *testing.T) {
	_, tac := body(t, "07-tacacs.txt")
	for name, c := range map[string]struct {
		screen string
		want   error
	}{
		"label":      {strings.Replace(tac, "Fallback Timer:", "Fall Back Timer:", 1), ErrLayout},
		"missing":    {strings.Replace(tac, "7.  Authentication Port:        49\n", "", 1), ErrLayout},
		"bad pick":   {strings.Replace(tac, "On (Transport failure)", "Sometimes", 1), ErrLayout},
		"no footer":  {tac[:strings.Index(tac, "Enter:")], ErrLayout},
		"error line": {strings.Replace(tac, "13. Ping Test", "ERROR: Invalid entry.\n13. Ping Test", 1), ErrLayout},
		"number":     {strings.Replace(tac, "Authentication Port:        49", "Authentication Port:        forty", 1), ErrLayout},
	} {
		if _, err := ParseScreen("/N > 28", c.screen); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// a path that is not the page's
	if _, err := ParseScreen("/N > 29", tac); !errors.Is(err, ErrPath) {
		t.Errorf("path: %v", err)
	}
	// the IP tables: a wrapped entry is refused, a slot out of range too
	_, ipt := body(t, "30-iptables-uploaded-page.txt")
	wrapped := strings.Replace(ipt, "12. iptables -A INPUT -s 10.0.60.0/24 -p tcp --dport 22 -j ACCEPT", "12. iptables -A INPUT -s 10.0.60.0/24 -p tcp\n--dport 22 -j ACCEPT", 1)
	if _, err := ParseScreen("", wrapped); !errors.Is(err, ErrLayout) {
		t.Errorf("wrapped entry: %v", err)
	}
	if _, err := ParseScreen("", strings.Replace(ipt, "\n12. ", "\n99. ", 1)); !errors.Is(err, ErrLayout) {
		t.Errorf("slot 99: %v", err)
	}
	// an entry that begins as an address is no slot
	if _, err := ParseScreen("", strings.Replace(ipt, "\n12. iptables", "\n10.0.0.0/24 iptables", 1)); !errors.Is(err, ErrLayout) {
		t.Errorf("address at the margin: %v", err)
	}
}

func TestClean(t *testing.T) {
	got := Clean("Enter: SPACE for page\x08 \x08\x08 \x08\x08 \x08next\r\n\x1b[2Jline\ttwo  \r\nx\x08\x08\x08y\n")
	want := "Enter: SPACE for pnext\nline two\ny\n"
	// the erasures are per line: three backspaces over 'x' leave nothing
	// before 'y', and the newline before it is not erased
	if got != "Enter: SPACE for pnext\nline two\ny\n" {
		t.Errorf("%q, want %q", got, want)
	}
}

func TestHelpLevels(t *testing.T) {
	for file, want := range map[string]struct {
		level     string
		configure bool
	}{
		"03-help-administrator.txt": {LevelAdministrator, true},
		"03-help-superuser.txt":     {LevelSuperUser, true},
		"03-help-user.txt":          {LevelUser, false},
		"03-help-viewonly.txt":      {LevelViewOnly, false},
	} {
		_, screen := body(t, file)
		d, err := ParseDocument("# page: /H\n" + screen)
		if err != nil {
			t.Fatal(err)
		}
		if d.Level() != want.level || d.CanConfigure() != want.configure || d.Version() != Version {
			t.Errorf("%s: level %q configure %v version %q", file, d.Level(), d.CanConfigure(), d.Version())
		}
	}
}

func TestStatusCountsOtherSessions(t *testing.T) {
	_, screen := body(t, "04-network-status.txt")
	d, err := ParseDocument("# page: /SN\n" + screen)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := d.OtherSessions(); !ok || n != 1 {
		t.Errorf("other sessions: %d %v", n, ok)
	}
	// no name is kept anywhere in the parsed page
	if strings.Contains(strings.Join(d.Pages[0].Names, ","), "user1") {
		t.Errorf("a session's user name was kept")
	}
}

func TestParseLine(t *testing.T) {
	for line, want := range map[string]string{
		"tacacs enable on":                          "tacacs enable on",
		"tacacs  secret   hunter2":                  "tacacs secret <secret>",
		"snmp contact \"Example NOC\"":              `snmp contact "Example NOC"`,
		"snmp contact Example NOC":                  `snmp contact "Example NOC"`,
		"iptables 3 iptables -A INPUT -j DROP":      "iptables -A INPUT -j DROP",
		"iptables 3 -A INPUT -j DROP":               "iptables -A INPUT -j DROP",
		"iptables iptables -P INPUT DROP":           "iptables -P INPUT DROP",
		"iptables -A INPUT -i lo -j ACCEPT":         "iptables -A INPUT -i lo -j ACCEPT",
		"snmp trap manager 2 192.0.2.35":            "snmp trap manager 2 192.0.2.35",
		"user localadmin password hunter2":          "user localadmin password <secret>",
		"user \"a b\" level user":                   `user "a b" level user`,
		"user localadmin level administrator":       "user localadmin level administrator",
		"something else entirely":                   "something else entirely",
		"snmp rw-community <other:1>":               "snmp rw-community <other:1>",
		"tacacs default-services serial,telnet-ssh": "tacacs default-services serial,telnet-ssh",
	} {
		c := ParseLine(line)
		if got := c.Raw(); got != want && c.Form != FormCommunity {
			t.Errorf("%q: %q, want %q", line, got, want)
		}
		if again := ParseLine(c.Raw()).Raw(); again != c.Raw() {
			t.Errorf("%q is not idempotent: %q", line, again)
		}
	}
	// a community string is shown as its mark
	if s := ParseLine("snmp ro-community SENTINEL").String(); s != "snmp ro-community <secret>" {
		t.Errorf("String: %q", s)
	}
	if s := ParseLine("snmp ro-community <secret:1>").String(); s != "snmp ro-community <secret:1>" {
		t.Errorf("String of a label: %q", s)
	}
}

func TestPagesTable(t *testing.T) {
	paths := map[string]bool{}
	for _, p := range Pages {
		if paths[p.Path] {
			t.Errorf("page %s twice", p.Path)
		}
		paths[p.Path] = true
		nums := map[int]bool{}
		for _, it := range p.Items {
			if nums[it.Number] {
				t.Errorf("%s: item %d twice", p.Path, it.Number)
			}
			nums[it.Number] = true
			if it.Key != "" && (it.Form == FormUnknown || it.Section == "" || it.Risk == "") {
				t.Errorf("%s item %d: incomplete row", p.Path, it.Number)
			}
			if it.Parse == nil || it.Label == "" {
				t.Errorf("%s item %d: no parser or label", p.Path, it.Number)
			}
		}
	}
	for _, want := range []string{"/H", "/SN", "/N", "/N > 25", "/N > 25 > 4", "/N > 25 > 5", "/N > 25 > 6", "/N > 26", "/N > 28", "/N > 28 > 8", "/N > 29", "/N > 5", "/F", "/J", "/F > 1 > 1", "/F > 1 > 1 > <name>"} {
		if !paths[want] {
			t.Errorf("no row for %s", want)
		}
	}
	if !slices.Contains(TailCommands(), "-P FORWARD DROP") || len(TailCommands()) != 5 {
		t.Errorf("tail: %v", TailCommands())
	}
}

// The prompt rows are the text pages of the SNMP menu's items 4, 5 and 6
// and no other: each is a one-item row of the same number, label and key as
// its menu item, in no secret, and entered with that number.
func TestPromptRowsAreTheTextItemsOfTheSNMPMenu(t *testing.T) {
	var menu *Page
	for i := range Pages {
		if Pages[i].Path == "/N > 25" {
			menu = &Pages[i]
		}
	}
	want := map[string]bool{"/N > 25 > 4": true, "/N > 25 > 5": true, "/N > 25 > 6": true}
	for i := range Pages {
		p := &Pages[i]
		if p.Kind != KindPrompt {
			continue
		}
		if !want[p.Path] {
			t.Errorf("an unexpected prompt row %s", p.Path)
		}
		delete(want, p.Path)
		if p.Required || len(p.Items) != 1 || p.Items[0].Secret {
			t.Errorf("%s: required %v, %d items, secret %v", p.Path, p.Required, len(p.Items), p.Items[0].Secret)
			continue
		}
		it := p.Items[0]
		if !strings.HasSuffix(p.Path, " > "+strconv.Itoa(it.Number)) {
			t.Errorf("%s: item %d is not the key that opens it", p.Path, it.Number)
		}
		found := false
		for _, m := range menu.Items {
			if m.Number == it.Number {
				found = true
				if m.Key != it.Key || m.Label != it.Label || m.Secret || m.Form != it.Form || m.Section != it.Section {
					t.Errorf("%s: %+v is not its menu item %+v", p.Path, it, m)
				}
			}
		}
		if !found {
			t.Errorf("%s: no menu item %d", p.Path, it.Number)
		}
	}
	if len(want) != 0 {
		t.Errorf("no prompt row for %v", want)
	}
}

// promptScreen is a prompt page as the unit prints it after the key and a
// CR: the echo, the title, the limit, the footer, the value, the rule.
func promptScreen(title, value string) string {
	return "4\n" + title + "\nUp to 32 characters are allowed.\nEnter: <SPACE><CR> to clear,\n" +
		"       <text><CR> to change,\n       <ESC> to return to previous menu ... \n" + value +
		"\n--------------------------------\n"
}

func TestParsePrompt(t *testing.T) {
	for name, c := range map[string]struct {
		path, screen, value string
	}{
		"as printed":                           {"/N > 25 > 4", promptScreen("SYSTEM NAME:", "wti.site.example.net"), "wti.site.example.net"},
		"blank lines":                          {"/N > 25 > 4", strings.Replace(promptScreen("SYSTEM NAME:", "x.example.net"), "4\nSYSTEM", "4\n\nSYSTEM", 1), "x.example.net"},
		"no path":                              {"", promptScreen("CONTACT:", "Example NOC (555) 0100"), "Example NOC (555) 0100"},
		"undefined":                            {"/N > 25 > 6", promptScreen("SNMP LOCATION:", "(undefined)"), ""},
		"a value that begins as an error line": {"/N > 25 > 5", promptScreen("CONTACT:", "ERROR: call the desk"), "ERROR: call the desk"},
		"trailing line":                        {"/N > 25 > 4", promptScreen("SYSTEM NAME:", "a.example.net") + "\n", "a.example.net"},
	} {
		p, err := ParseScreen(c.path, c.screen)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if p.Page.Kind != KindPrompt || len(p.Fields) != 1 || p.Fields[0].Value != c.value {
			t.Errorf("%s: %+v", name, p.Fields)
		}
	}
}

func TestParsePromptRefusals(t *testing.T) {
	full := promptScreen("SYSTEM NAME:", "wti.site.example.net")
	for name, c := range map[string]struct {
		screen string
		want   error
	}{
		"no value line":    {strings.Replace(full, "wti.site.example.net\n", "", 1), ErrLayout},
		"blank value":      {strings.Replace(full, "wti.site.example.net\n", "\n", 1), ErrLayout},
		"no rule line":     {strings.Replace(full, "--------------------------------\n", "", 1), ErrLayout},
		"rule not painted": {strings.Replace(full, "--------------------------------", "----", 1), ErrLayout},
		"no footer":        {strings.Replace(full, "<ESC> to return to previous menu ... ", "", 1), ErrLayout},
		"error line above": {strings.Replace(full, "Up to 32", "ERROR: Invalid entry.\nUp to 32", 1), ErrLayout},
		"too long":         {promptScreen("SYSTEM NAME:", strings.Repeat("x", 600)), ErrLayout},
		"another page":     {strings.Replace(full, "SYSTEM NAME:", "NOT A PAGE:", 1), ErrUnknownPage},
	} {
		_, err := ParseScreen("/N > 25 > 4", c.screen)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "wti.site.example.net") {
			t.Errorf("%s: the error holds the value: %v", name, err)
		}
	}
	// the value of one prompt is not another's page
	if _, err := ParseScreen("/N > 25 > 5", full); !errors.Is(err, ErrPath) {
		t.Errorf("a system name page at the contact's path: %v", err)
	}
}

// A prompt's whole value replaces the menu's truncated one, at the menu
// item's place; a document with no prompt keeps the menu's.
func TestStatementsTakeThePromptValue(t *testing.T) {
	_, menu := body(t, "08-snmp-access.txt")
	_, trap := body(t, "09-snmp-trap.txt")
	doc := "# page: /N > 25\n" + menu + "\n# page: /N > 26\n" + trap
	text := func(d string) string {
		parsed, err := ParseDocument(d)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range parsed.Statements() {
			if strings.HasPrefix(s.Key, "snmp system-name") || s.Key == "snmp contact" || s.Key == "snmp location" {
				out = append(out, s.Raw())
			}
		}
		return strings.Join(out, " | ")
	}
	if got, want := text(doc), `snmp system-name wti.site.exam... | snmp contact "Example NOC (..." | snmp location "Example City,..."`; got != want {
		t.Errorf("without prompts:\n got %s\nwant %s", got, want)
	}
	with := doc + "\n# page: /N > 25 > 5\n" + promptScreen("CONTACT:", "Example NOC (555) 0100")
	if got, want := text(with), `snmp system-name wti.site.exam... | snmp contact "Example NOC (555) 0100" | snmp location "Example City,..."`; got != want {
		t.Errorf("one prompt:\n got %s\nwant %s", got, want)
	}
}
