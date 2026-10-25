package blocks

import (
	"strings"
	"testing"
)

// the secrets of the system fixtures: no finding and no elided text may hold
// one.
const (
	sysKey    = "ntpkey-Vx77Lm"
	sysBanner = "BANNER-MARKER-Qz9"
)

const goodSystem = `# the lab's system settings
set system login message <<'EOF'
 Authorized use only. "Quoted" and a \ backslash.
  # not a comment, a banner line
EOF
set system domain-name lab.example.net
set system domain-search lab.example.net
set system domain-search example.net
set system time-zone America/New_York
set system name-server 192.0.2.53
set system name-server 2001:db8::53
set system ntp server 192.0.2.123 prefer version 4 key 7
set system ntp server ntp2.example.net routing-instance mgmt
set system ntp boot-server 192.0.2.124
set system ntp source-address 192.0.2.10
set system ntp authentication-key 7 type md5 value ` + sysKey + `
set system ntp trusted-key 7
delete system domain-search old.example.net
`

func TestSystemParseGood(t *testing.T) {
	// the device-local ntp source-address makes it a device's block
	b, fs := LintSystem(goodSystem, LayerDevice)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if b.Message == nil || b.Message.Line != 2 || b.Message.Lines() != 2 ||
		b.Message.Body != ` Authorized use only. "Quoted" and a \ backslash.`+"\n"+`  # not a comment, a banner line` {
		t.Fatalf("message: %+v", b.Message)
	}
	if b.DomainName.Text != "lab.example.net" || len(b.DomainSearch) != 2 || b.TimeZone.Text != "America/New_York" ||
		len(b.NameServers) != 2 || b.NameServers[1].Text != "2001:db8::53" {
		t.Errorf("values: %+v", b)
	}
	if len(b.NTPServers) != 2 {
		t.Fatalf("ntp servers: %+v", b.NTPServers)
	}
	if s := b.NTPServers[0]; s.Host != "192.0.2.123" || !s.Prefer || s.Version != 4 || s.Key != 7 || s.RoutingInstance != "" {
		t.Errorf("server 1: %+v", s)
	}
	if s := b.NTPServers[1]; s.Host != "ntp2.example.net" || s.Prefer || s.RoutingInstance != "mgmt" {
		t.Errorf("server 2: %+v", s)
	}
	if b.NTPBootServer.Text != "192.0.2.124" || b.NTPSourceAddress.Text != "192.0.2.10" ||
		len(b.NTPKeys) != 1 || b.NTPKeys[0].Type != "md5" || b.NTPKeys[0].Value != sysKey ||
		len(b.NTPTrustedKeys) != 1 || b.NTPTrustedKeys[0].Number != 7 {
		t.Errorf("ntp: %+v", b)
	}
	if len(b.NotManaged) != 1 || b.NotManaged[0].Kind != SysDomainSearch || b.NotManaged[0].Value != "old.example.net" ||
		b.NotManaged[0].Line != 18 {
		t.Errorf("not managed: %+v", b.NotManaged)
	}
	if b.Empty() || !(&SystemBlock{}).Empty() || !(*SystemBlock)(nil).Empty() {
		t.Error("Empty")
	}
}

// Every refusal of the parser, with the line it is on.
func TestSystemParseRefusals(t *testing.T) {
	longName := strings.Repeat("a", 64) + ".example.net"
	for _, tc := range []struct {
		name string
		text string
		line int
		frag string
	}{
		{"not set or delete", "edit system\n", 1, "'set' and 'delete' statements only"},
		{"commit", "commit\n", 1, "'set' and 'delete' statements only"},
		{"other hierarchy", "set snmp location rack-4\n", 1, "only 'set system"},
		{"set alone", "set\n", 1, "only 'set system"},
		{"system alone", "set system\n", 1, "needs login, domain-name"},
		{"unknown leaf", "set system host-name x\n", 1, "word 3 is not one of login"},
		{"services", "set system services ssh\n", 1, "word 3 is not one of login"},
		{"login class", "set system login class x\n", 1, "only 'set system login message'"},
		{"login user", "set system login user bob class super-user\n", 1, "only 'set system login message'"},
		{"message single line", "set system login message \"hello\"\n", 1, "the login message is a heredoc"},
		{"message bare", "set system login message\n", 1, "the login message is a heredoc"},
		{"message unquoted marker", "set system login message <<EOF\nhi\nEOF\n", 1, "<<'EOF' exactly"},
		{"message double-quoted marker", "set system login message <<\"EOF\"\nhi\nEOF\n", 1, "<<'EOF' exactly"},
		{"message dash marker", "set system login message <<-EOF\nhi\nEOF\n", 1, "<<'EOF' exactly"},
		{"message other terminator", "set system login message <<'END'\nhi\nEND\n", 1, "<<'EOF' exactly"},
		{"message trailing words", "set system login message <<'EOF' extra\nhi\nEOF\n", 1, "<<'EOF' exactly"},
		{"message never closed", "set system domain-name a.example.net\nset system login message <<'EOF'\nhi\n", 2, "never closed"},
		{"message indented terminator", "set system login message <<'EOF'\nhi\n EOF\n", 1, "never closed"},
		{"message twice", "set system login message <<'EOF'\na\nEOF\nset system login message <<'EOF'\nb\nEOF\n", 4, "stated twice"},
		{"statement inside no heredoc", "set system login message <<'EOF'\na\nEOF\nset system frob\n", 4, "word 3 is not one of"},
		{"quote", "set system domain-name \"a.example.net\"\n", 1, "a quote is not accepted"},
		{"delete quote", "delete system domain-search \"a\"\n", 1, "a quote is not accepted"},
		{"tab", "set system domain-name\ta.example.net\n", 1, "a tab at column"},
		{"control", "set system domain-name a.example.net\x07\n", 1, "a control character (0x07)"},
		{"non-ascii", "set system domain-name caf\u00e9.example.net\n", 1, "not ASCII"},
		{"long line", "set system domain-name " + strings.Repeat("a", 1000) + "\n", 1, "longer than 1000"},
		{"domain no value", "set system domain-name\n", 1, "takes one value"},
		{"domain two values", "set system domain-name a.example.net b.example.net\n", 1, "takes one value"},
		{"domain twice", "set system domain-name a.example.net\nset system domain-name b.example.net\n", 2, "domain-name is stated twice"},
		{"domain label too long", "set system domain-name " + longName + "\n", 1, "not a host name"},
		{"domain underscore", "set system domain-name a_b.example.net\n", 1, "not a host name"},
		{"domain leading hyphen", "set system domain-name -a.example.net\n", 1, "not a host name"},
		{"domain empty label", "set system domain-name a..example.net\n", 1, "not a host name"},
		{"domain trailing dot", "set system domain-name a.example.net.\n", 1, "not a host name"},
		{"domain numeric", "set system domain-name 999.1.1.1\n", 1, "does not parse as an address"},
		{"domain too long", "set system domain-name " + strings.Repeat("abcdefgh.", 28) + "net\n", 1, "longer than 253"},
		{"domain placeholder", "set system domain-name <secret>\n", 1, "is a placeholder"},
		{"search twice", "set system domain-search a.example.net\nset system domain-search A.EXAMPLE.NET\n", 2, "domain-search 1 is listed twice"},
		{"search bad", "set system domain-search a b\n", 1, "takes one value"},
		{"zone bad", "set system time-zone America/New York\n", 1, "takes one value"},
		{"zone chars", "set system time-zone Amer;ica\n", 1, "not a time zone name"},
		{"zone too long", "set system time-zone " + strings.Repeat("a", 65) + "\n", 1, "not a time zone name"},
		{"zone twice", "set system time-zone UTC\nset system time-zone Europe/Paris\n", 2, "time-zone is stated twice"},
		{"zone placeholder", "set system time-zone <secret:1>\n", 1, "is a placeholder"},
		{"name-server name", "set system name-server dns.example.net\n", 1, "not an IPv4 or IPv6 address"},
		{"name-server noncanonical", "set system name-server 2001:DB8::53\n", 1, "canonical form 2001:db8::53"},
		{"name-server unspecified", "set system name-server 0.0.0.0\n", 1, "not a host address"},
		{"name-server twice", "set system name-server 192.0.2.53\nset system name-server 192.0.2.53\n", 2, "name-server 1 is listed twice"},
		{"name-server placeholder", "set system name-server <secret>\n", 1, "is a placeholder"},
		{"ntp alone", "set system ntp\n", 1, "needs server, boot-server"},
		{"ntp leaf", "set system ntp peer 192.0.2.1\n", 1, "word 4 is not one of server"},
		{"ntp server alone", "set system ntp server\n", 1, "needs an address"},
		{"ntp server bad address", "set system ntp server 192.0.2.999\n", 1, "does not parse as an address"},
		{"ntp server bad v6", "set system ntp server 2001:db8::zz\n", 1, "not an IPv4 or IPv6 address"},
		{"ntp server placeholder", "set system ntp server <secret>\n", 1, "is a placeholder"},
		{"ntp server option", "set system ntp server 192.0.2.1 burst\n", 1, "not one of prefer, version, key, routing-instance"},
		{"ntp version 0", "set system ntp server 192.0.2.1 version 0\n", 1, "version takes 1, 2, 3 or 4"},
		{"ntp version 5", "set system ntp server 192.0.2.1 version 5\n", 1, "version takes 1, 2, 3 or 4"},
		{"ntp version word", "set system ntp server 192.0.2.1 version four\n", 1, "version takes 1, 2, 3 or 4"},
		{"ntp version missing", "set system ntp server 192.0.2.1 version\n", 1, "version takes a value"},
		{"ntp key range", "set system ntp server 192.0.2.1 key 70000\n", 1, "key takes a key number"},
		{"ntp key zero", "set system ntp server 192.0.2.1 key 0\n", 1, "key takes a key number"},
		{"ntp prefer twice", "set system ntp server 192.0.2.1 prefer prefer\n", 1, "prefer is stated twice"},
		{"ntp instance bad", "set system ntp server 192.0.2.1 routing-instance a;b\n", 1, "routing-instance takes a name"},
		{"ntp instance placeholder", "set system ntp server 192.0.2.1 routing-instance <x>\n", 1, "is a placeholder"},
		{"ntp server twice", "set system ntp server 192.0.2.1\nset system ntp server 192.0.2.1\n", 2, "ntp server 1 is listed twice"},
		{"ntp server option twice", "set system ntp server 192.0.2.1 prefer\nset system ntp server 192.0.2.1 prefer\n", 2, "an option is stated twice"},
		{"boot-server twice", "set system ntp boot-server 192.0.2.1\nset system ntp boot-server 192.0.2.2\n", 2, "boot-server is stated twice"},
		{"boot-server bad", "set system ntp boot-server a_b\n", 1, "not a host name"},
		{"source-address name", "set system ntp source-address ntp.example.net\n", 1, "not an IPv4 or IPv6 address"},
		{"source-address twice", "set system ntp source-address 192.0.2.1\nset system ntp source-address 192.0.2.2\n", 2, "source-address is stated twice"},
		{"key short", "set system ntp authentication-key 1 type md5\n", 1, "takes <n> type md5|sha1|sha256 value"},
		{"key value first", "set system ntp authentication-key 1 value k type md5\n", 1, "takes <n> type md5|sha1|sha256 value"},
		{"key number", "set system ntp authentication-key 0 type md5 value k\n", 1, "is a key number from 1 to 65534"},
		{"key number word", "set system ntp authentication-key one type md5 value k\n", 1, "is a key number from 1 to 65534"},
		{"key type", "set system ntp authentication-key 1 type sha512 value k\n", 1, "the type (word 7) is one of md5, sha1, sha256"},
		{"key placeholder", "set system ntp authentication-key 1 type md5 value <secret>\n", 1, "is a placeholder"},
		{"key value char", "set system ntp authentication-key 1 type md5 value a;b\n", 1, "reads specially"},
		{"key twice", "set system ntp authentication-key 1 type md5 value a\nset system ntp authentication-key 1 type sha1 value b\n", 2, "authentication-key 1 is stated twice"},
		{"trusted-key none", "set system ntp trusted-key\n", 1, "takes one key number"},
		{"trusted-key bad", "set system ntp trusted-key 99999\n", 1, "from 1 to 65534"},
		{"trusted-key twice", "set system ntp trusted-key 1\nset system ntp trusted-key 1\n", 2, "trusted-key 1 is listed twice"},
		{"delete other", "delete snmp community x\n", 1, "only 'delete system"},
		{"delete bare", "delete system\n", 1, "only 'delete system"},
		{"delete leaf", "delete system host-name\n", 1, "word 3 is not one of"},
		{"delete login", "delete system login\n", 1, "only 'delete system login message'"},
		{"delete login class", "delete system login class x\n", 1, "only 'delete system login message'"},
		{"delete domain value", "delete system domain-name a.example.net\n", 1, "takes nothing after it"},
		{"delete zone value", "delete system time-zone UTC\n", 1, "takes nothing after it"},
		{"delete search two", "delete system domain-search a.example.net b.example.net\n", 1, "takes one value"},
		{"delete name-server bad", "delete system name-server nope\n", 1, "not an IPv4 or IPv6 address"},
		{"delete ntp leaf", "delete system ntp peer\n", 1, "word 4 is not one of"},
		{"delete boot value", "delete system ntp boot-server 192.0.2.1\n", 1, "takes nothing after it"},
		{"delete key bad", "delete system ntp authentication-key x\n", 1, "not a key number"},
		{"delete server bad", "delete system ntp server a_b\n", 1, "not a host name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := ParseSystem(tc.text)
			if !hasFinding(fs, SevError, tc.line, tc.frag) {
				t.Errorf("want an error at line %d with %q, got:\n%s", tc.line, tc.frag, dump(fs))
			}
		})
	}
}

func TestSystemCheck(t *testing.T) {
	long := strings.Repeat("x", 80)
	var many []string
	for i := 0; i < 15; i++ {
		many = append(many, long)
	}
	body1100 := strings.Join(many, "\n")[:1100]
	for _, tc := range []struct {
		name  string
		text  string
		sev   Severity
		line  int
		frag  string
		quiet bool // no finding at all
	}{
		{name: "empty", text: "set system login message <<'EOF'\nEOF\n", sev: SevError, line: 1, frag: "the login message is empty"},
		{name: "blank only", text: "set system login message <<'EOF'\n\n   \nEOF\n", sev: SevError, line: 1, frag: "the login message is empty"},
		{name: "tab", text: "set system login message <<'EOF'\nok\n\tindented\nEOF\n", sev: SevError, line: 3, frag: "line 2 of the login message holds a tab at column 1"},
		{name: "control", text: "set system login message <<'EOF'\nok\x01\nEOF\n", sev: SevError, line: 2, frag: "line 1 of the login message holds a control character (0x01) at column 3"},
		{name: "carriage return", text: "set system login message <<'EOF'\nok\r\nEOF\n", sev: SevError, line: 2, frag: "a control character (0x0d)"},
		{name: "non-ascii", text: "set system login message <<'EOF'\nsmile \u263a here\nEOF\n", sev: SevError, line: 2, frag: "a character that is not ASCII at column 7"},
		{name: "placeholder", text: "set system login message <<'EOF'\n<message: 2 lines, 30 characters>\nEOF\n", sev: SevError, line: 2, frag: "is a placeholder"},
		{name: "too long", text: "set system login message <<'EOF'\n" + strings.Repeat(strings.Repeat("y", 100)+"\n", 21) + "EOF\n", sev: SevError, line: 1, frag: "at most 2000"},
		{name: "long note", text: "set system login message <<'EOF'\n" + body1100 + "\nEOF\n", sev: SevNote, line: 1, frag: "truncated at 1,023 characters; plan --plain"},
		{name: "short is quiet", text: "set system login message <<'EOF'\nhello\nEOF\n", quiet: true},
		{name: "secret note", text: "set system ntp authentication-key 3 type sha1 value k3\n", sev: SevNote, line: 1, frag: "ntp authentication-key 3 carries a secret"},
		{name: "server key undefined", text: "set system ntp server 192.0.2.1 key 9\n", sev: SevNote, line: 1, frag: "uses key 9, which this block does not define"},
		{name: "trusted undefined", text: "set system ntp trusted-key 4\n", sev: SevNote, line: 1, frag: "trusted-key 4 names a key this block does not define"},
		{name: "server key undefined, trusted key too", text: "set system ntp server 192.0.2.1 key 9\nset system ntp trusted-key 9\n", sev: SevNote, line: 2, frag: "trusted-key 9 names a key this block does not define"},
		{name: "delete note", text: "delete system ntp\n", sev: SevNote, line: 1, frag: "a delete line"},
		{name: "comments only", text: "# nothing\n\n", quiet: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := LintSystem(tc.text, LayerScope)
			if tc.quiet {
				if len(fs) != 0 {
					t.Errorf("want no finding, got:\n%s", dump(fs))
				}
				return
			}
			if !hasFinding(fs, tc.sev, tc.line, tc.frag) {
				t.Errorf("want %s at line %d with %q, got:\n%s", tc.sev, tc.line, tc.frag, dump(fs))
			}
		})
	}
	// A defined key makes the references quiet.
	_, fs := LintSystem("set system ntp authentication-key 9 type md5 value k9\nset system ntp server 192.0.2.1 key 9\nset system ntp trusted-key 9\n", LayerDevice)
	if hasFinding(fs, SevNote, -1, "does not define") {
		t.Errorf("a defined key is reported:\n%s", dump(fs))
	}
}

// A message in a block built in code (a device's, through FromDeviceMessage)
// is checked as the parsed one is, with no line to name.
func TestSystemCheckBuiltMessage(t *testing.T) {
	for _, tc := range []struct {
		body string
		frag string
	}{
		{"line\nEOF\nmore", "line 2 of the login message is EOF alone"},
		{"a\tb", "a tab at column 2"},
		{"", "is empty"},
	} {
		fs := CheckSystem(&SystemBlock{Message: &LoginMessage{Body: tc.body}}, LayerScope)
		if !hasFinding(fs, SevError, 0, tc.frag) {
			t.Errorf("%q: %s", tc.body, dump(fs))
		}
	}
}

// bannerBody is a synthetic 22-line, 1,300-character banner of art: leading
// spaces, quotes, backslashes and * # | characters, one empty line.
func bannerBody(t *testing.T) string {
	t.Helper()
	const lines, total = 22, 1300
	pieces := []string{`*  "Example" \ path # | `, `| '#' \\ "x" * `, `#### \"esc\" ||| `}
	remaining := total - (lines - 1) // the newlines between the lines
	nonEmpty := lines - 1
	var out []string
	for i := 0; i < lines; i++ {
		if i == 10 {
			out = append(out, "")
			continue
		}
		w := remaining / nonEmpty
		remaining -= w
		nonEmpty--
		lead := strings.Repeat(" ", i%5)
		s := lead
		for p := i; len(s) < w; p++ {
			s += pieces[p%len(pieces)]
		}
		s = s[:w-1] + "|"
		out = append(out, s)
	}
	body := strings.Join(out, "\n")
	if len(body) != total || strings.Count(body, "\n") != lines-1 {
		t.Fatalf("banner: %d characters, %d breaks", len(body), strings.Count(body, "\n"))
	}
	return body
}

func TestSystemMessageRoundTrip(t *testing.T) {
	body := bannerBody(t)
	text := "set system login message <<'EOF'\n" + body + "\nEOF\n"
	b, fs := LintSystem(text, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	if b.Message.Body != body {
		t.Fatal("the parsed body differs from the text")
	}
	if !hasFinding(fs, SevNote, 1, "truncated at 1,023 characters") {
		t.Errorf("no note about the pasted line:\n%s", dump(fs))
	}
	st := SystemStatements(b)
	if len(st) != 1 || strings.Contains(st[0], "\n") || !strings.HasPrefix(st[0], MessageStatement+`"`) {
		t.Fatalf("statements: %q", st)
	}
	arg := strings.TrimPrefix(st[0], MessageStatement)
	// Spot checks of the escaping.
	for _, w := range []string{`\n`, `\"Example\"`, `\\ path`, ` | `} {
		if !strings.Contains(arg, w) {
			t.Errorf("the argument lacks %q", w)
		}
	}
	got, err := FromDeviceMessage(arg)
	if err != nil || got != body {
		t.Fatalf("round trip through the device form: %v, identical %v", err, got == body)
	}
	// Without the outer quotes, as an adopt may hold it.
	got, err = FromDeviceMessage(arg[1 : len(arg)-1])
	if err != nil || got != body {
		t.Fatalf("round trip without the quotes: %v", err)
	}
	if DeviceMessage(got) != arg {
		t.Error("DeviceMessage is not the inverse")
	}
	// And through the canonical text.
	b2, fs := ParseSystem(b.String(false))
	if HasErrors(fs) || b2.Message.Body != body || b2.String(false) != b.String(false) {
		t.Errorf("canonical text round trip: %s", dump(fs))
	}
}

func TestFromDeviceMessage(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		bad  string
	}{
		{in: `"a\nb"`, want: "a\nb"},
		{in: `a\nb`, want: "a\nb"},
		{in: `"say \"hi\" \\ done"`, want: `say "hi" \ done`},
		{in: `"  indented\n    more"`, want: "  indented\n    more"},
		{in: `"trailing\n"`, want: "trailing\n"},
		{in: `"\\"`, want: `\`},
		{in: `"a\tb"`, want: "a\tb"},
		{in: `""`, want: ""},
		{in: ``, want: ""},
		{in: `"open`, bad: "not closed"},
		{in: `"`, bad: "not closed"},
		{in: `"ends\"`, bad: "not closed"},
		{in: `a"b`, bad: "quote at character 2 is not escaped"},
		{in: `"a"b"`, bad: "quote at character 2 is not escaped"},
		{in: `ends\`, bad: "backslash at character 5 ends the message"},
		{in: `a\xb`, bad: "escape at character 2"},
		{in: `a\rb`, bad: "escape at character 2"},
	} {
		got, err := FromDeviceMessage(tc.in)
		switch {
		case tc.bad != "":
			if err == nil || !strings.Contains(err.Error(), tc.bad) {
				t.Errorf("%q: want error %q, got %v", tc.in, tc.bad, err)
			}
		case err != nil || got != tc.want:
			t.Errorf("%q: got %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
	// The error never holds the text.
	_, err := FromDeviceMessage(`"` + sysBanner + `\q"`)
	if err == nil || strings.Contains(err.Error(), sysBanner) {
		t.Errorf("error: %v", err)
	}
}

func TestSystemStatementsAndCanonicalText(t *testing.T) {
	// Statements are in the stable order whatever the order of the text.
	b, fs := ParseSystem(`set system ntp trusted-key 7
set system ntp authentication-key 7 type md5 value k7
set system ntp source-address 192.0.2.10
set system ntp boot-server ntp.example.net
set system ntp server 192.0.2.123 routing-instance mgmt key 7 version 3 prefer
set system name-server 192.0.2.53
set system time-zone UTC
set system domain-search a.example.net
set system domain-name example.net
set system login message <<'EOF'
one
two
EOF
delete system ntp server 192.0.2.99
delete system login message
delete system ntp
delete system name-server
delete system ntp trusted-key 3
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	want := []string{
		`set system login message "one\ntwo"`,
		"set system domain-name example.net",
		"set system domain-search a.example.net",
		"set system time-zone UTC",
		"set system name-server 192.0.2.53",
		"set system ntp server 192.0.2.123 prefer version 3 key 7 routing-instance mgmt",
		"set system ntp boot-server ntp.example.net",
		"set system ntp source-address 192.0.2.10",
		"set system ntp authentication-key 7 type md5 value k7",
		"set system ntp trusted-key 7",
	}
	if got := SystemStatements(b); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("statements:\n%s", strings.Join(got, "\n"))
	}
	for _, s := range SystemStatements(b) {
		if strings.HasPrefix(s, "delete") {
			t.Errorf("a delete line in the statements: %s", s)
		}
	}
	if SystemStatements(nil) != nil || SystemStatements(&SystemBlock{}) != nil {
		t.Error("an empty block has statements")
	}
	canon := "set system login message <<'EOF'\none\ntwo\nEOF\n" + strings.Join(want[1:], "\n") + "\n" +
		"delete system ntp server 192.0.2.99\ndelete system login message\ndelete system ntp\n" +
		"delete system name-server\ndelete system ntp trusted-key 3\n"
	if got := b.String(false); got != canon {
		t.Errorf("canonical text:\n%s\nwant:\n%s", got, canon)
	}
	b2, fs := ParseSystem(canon)
	if HasErrors(fs) || b2.String(false) != canon {
		t.Errorf("canonical text is not stable: %s", dump(fs))
	}
	if (*SystemBlock)(nil).String(false) != "" || (&SystemBlock{}).String(true) != "" {
		t.Error("an empty block has text")
	}
	// Every kind of delete line round trips.
	for _, l := range []string{
		"delete system login message", "delete system domain-name", "delete system domain-search",
		"delete system domain-search a.example.net", "delete system time-zone", "delete system name-server",
		"delete system name-server 2001:db8::1", "delete system ntp", "delete system ntp server",
		"delete system ntp server ntp.example.net", "delete system ntp boot-server", "delete system ntp source-address",
		"delete system ntp authentication-key", "delete system ntp authentication-key 5",
		"delete system ntp trusted-key", "delete system ntp trusted-key 5",
	} {
		d, fs := ParseSystem(l + "\n")
		if HasErrors(fs) || d.String(false) != l+"\n" {
			t.Errorf("%s: %q %s", l, d.String(false), dump(fs))
		}
	}
	// Servers stated on several lines are one object.
	m, fs := ParseSystem("set system ntp server 192.0.2.1\nset system ntp server 192.0.2.1 prefer\nset system ntp server 192.0.2.1 version 2 key 4\n")
	if HasErrors(fs) || len(m.NTPServers) != 1 || m.NTPServers[0].Version != 2 || !m.NTPServers[0].Prefer ||
		m.NTPServers[0].Key != 4 || len(m.NTPServers[0].Lines) != 3 {
		t.Errorf("merged server: %+v\n%s", m.NTPServers, dump(fs))
	}
}

func TestSystemElide(t *testing.T) {
	b, fs := ParseSystem(goodSystem)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	el := b.String(true)
	for _, s := range []string{sysKey, "Authorized use only", "banner line"} {
		if strings.Contains(el, s) {
			t.Errorf("elided text holds %q:\n%s", s, el)
		}
	}
	for _, w := range []string{
		"set system login message <<'EOF'\n<message: 2 lines, 82 characters>\nEOF\n",
		"set system ntp authentication-key 7 type md5 value <secret>\n",
		"set system domain-name lab.example.net\n",
		"set system ntp server 192.0.2.123 prefer version 4 key 7\n",
	} {
		if !strings.Contains(el, w) {
			t.Errorf("elided text lacks %q:\n%s", w, el)
		}
	}
	for _, s := range SystemStatements(ElideSystem(b)) {
		if strings.Contains(s, sysKey) || strings.Contains(s, "Authorized") {
			t.Errorf("elided statement %q", s)
		}
	}
	if b.Message.Body == "" || b.NTPKeys[0].Value != sysKey {
		t.Error("ElideSystem changed the block")
	}
	if ElideSystem(nil) != nil {
		t.Error("ElideSystem(nil)")
	}
	// An elided text is not a block: its marks are refused.
	_, fs = LintSystem(el, LayerScope)
	if !HasErrors(fs) || !hasFinding(fs, SevError, -1, "is a placeholder") {
		t.Errorf("an elided text was accepted:\n%s", dump(fs))
	}
	if _, fs := ParseSystem(el); !HasErrors(fs) {
		t.Errorf("the key mark was accepted by Parse:\n%s", dump(fs))
	}
}

func TestIsSecretStatement(t *testing.T) {
	for line, want := range map[string]bool{
		"set system ntp authentication-key 7 type md5 value k7":       true,
		"set system ntp authentication-key 7 type md5 value <secret>": true,
		"  set system ntp authentication-key 1 type sha1 value abc":   true,
		"set system ntp authentication-key 7":                         false,
		"set system ntp trusted-key 7":                                false,
		"set system ntp server 192.0.2.1 key 7":                       false,
		`set system login message "ntp authentication-key value"`:     false,
		"delete system ntp authentication-key 7":                      false,
		"set snmp community x authorization read-only":                false,
		"": false,
		"set system ntp authentication-key 7 type md5 value k7 extra":  true,
		"set system domain-name authentication-key.example.net value":  false,
		"set system ntp boot-server authentication-key.example.net":    false,
		"set security ike policy p pre-shared-key ascii-text secret-x": false,
	} {
		if got := IsSecretStatement(line); got != want {
			t.Errorf("%q: %v, want %v", line, got, want)
		}
	}
}

func TestSystemResolve(t *testing.T) {
	def, fs := ParseSystem(`set system time-zone UTC
set system domain-name example.net
set system domain-search example.net
set system name-server 192.0.2.53
set system ntp server 192.0.2.1
set system ntp server 192.0.2.2 prefer
set system ntp authentication-key 1 type md5 value default-key
set system ntp trusted-key 1
set system login message <<'EOF'
default banner
EOF
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	scope, fs := ParseSystem(`set system time-zone America/Chicago
set system domain-search lab.example.net
set system domain-search EXAMPLE.net
set system name-server 192.0.2.54
set system ntp server 192.0.2.2 version 3
set system ntp server 192.0.2.3
set system ntp boot-server 192.0.2.4
set system ntp authentication-key 1 type sha1 value scope-key
set system ntp trusted-key 2
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	dev, fs := ParseSystem(`set system name-server 192.0.2.55
set system ntp server 192.0.2.5 key 1
delete system ntp server 192.0.2.3
delete system domain-search example.net
delete system login message
delete system domain-name
delete system ntp trusted-key
set system ntp trusted-key 9
`)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}

	got := ResolveSystem(def, scope, nil)
	want := []string{
		`set system login message "default banner"`,
		"set system domain-name example.net",
		"set system domain-search EXAMPLE.net",
		"set system domain-search lab.example.net",
		"set system time-zone America/Chicago",
		"set system name-server 192.0.2.53",
		"set system name-server 192.0.2.54",
		"set system ntp server 192.0.2.1",
		"set system ntp server 192.0.2.2 version 3",
		"set system ntp server 192.0.2.3",
		"set system ntp boot-server 192.0.2.4",
		"set system ntp authentication-key 1 type sha1 value scope-key",
		"set system ntp trusted-key 1",
		"set system ntp trusted-key 2",
	}
	if g := SystemStatements(got); strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("default + scope:\n%s", strings.Join(g, "\n"))
	}
	// With the device: its deletes take the less specific objects out, its
	// own statements come after.
	got = ResolveSystem(def, scope, dev)
	want = []string{
		"set system domain-search lab.example.net",
		"set system time-zone America/Chicago",
		"set system name-server 192.0.2.53",
		"set system name-server 192.0.2.54",
		"set system name-server 192.0.2.55",
		"set system ntp server 192.0.2.1",
		"set system ntp server 192.0.2.2 version 3",
		"set system ntp server 192.0.2.5 key 1",
		"set system ntp boot-server 192.0.2.4",
		"set system ntp authentication-key 1 type sha1 value scope-key",
		"set system ntp trusted-key 9",
	}
	if g := SystemStatements(got); strings.Join(g, "\n") != strings.Join(want, "\n") {
		t.Errorf("default + scope + device:\n%s", strings.Join(g, "\n"))
	}
	if len(got.NotManaged) != 5 {
		t.Errorf("not managed: %+v", got.NotManaged)
	}
	// Inputs are untouched, and the result shares nothing with them.
	if len(scope.NTPServers) != 2 || len(def.NTPServers) != 2 || def.Message == nil || len(dev.NotManaged) != 5 {
		t.Error("ResolveSystem changed an input")
	}
	got.NTPServers[0].Lines[0] = 99
	if def.NTPServers[0].Lines[0] == 99 {
		t.Error("the result shares a lines slice with its input")
	}
	got.Message = nil
	if def.Message == nil {
		t.Error("the result shares the message with its input")
	}
	// 'delete system ntp' takes every ntp statement of the less specific
	// layers, and the layer's own come after it.
	ntp, _ := ParseSystem("delete system ntp\nset system ntp server 192.0.2.77\n")
	r := ResolveSystem(def, scope, ntp)
	if g := strings.Join(SystemStatements(r), "\n"); strings.Contains(g, "192.0.2.1\n") || !strings.Contains(g, "ntp server 192.0.2.77") ||
		strings.Contains(g, "authentication-key") || strings.Contains(g, "boot-server") {
		t.Errorf("delete system ntp:\n%s", g)
	}
	// A delete in the layer of the object keeps the object; the less
	// specific one goes.
	same, _ := ParseSystem("delete system name-server 192.0.2.53\nset system name-server 192.0.2.53\n")
	r = ResolveSystem(def, same, nil)
	if len(r.NameServers) != 1 || r.NameServers[0].Line != 2 {
		t.Errorf("same layer: %+v", r.NameServers)
	}
	// Nothing at all.
	if r := ResolveSystem(nil, nil, nil); !r.Empty() || len(SystemStatements(r)) != 0 {
		t.Errorf("ResolveSystem of nothing: %+v", r)
	}
	if s := strings.Join(SystemStatements(ResolveSystem(nil, scope, nil)), "\n"); !strings.Contains(s, "time-zone America/Chicago") {
		t.Errorf("scope alone: %s", s)
	}
}

// Findings and the elided text never hold the login message or a key.
func TestSystemFindingsNeverHoldAString(t *testing.T) {
	secrets := []string{sysBanner, sysKey, "Vx77Lm", "Qz9"}
	for name, text := range map[string]string{
		"message with a tab":   "set system login message <<'EOF'\nline one " + sysBanner + "\n\t" + sysBanner + "\nEOF\n",
		"message with control": "set system login message <<'EOF'\n" + sysBanner + "\x01\nEOF\n",
		"message not ascii":    "set system login message <<'EOF'\n" + sysBanner + " \u00e9\nEOF\n",
		"message too long":     "set system login message <<'EOF'\n" + strings.Repeat(sysBanner+"\n", 120) + "EOF\n",
		"message long note":    "set system login message <<'EOF'\n" + strings.Repeat(sysBanner+"\n", 60) + "EOF\n",
		"message terminator":   "set system login message <<'EOF'\n" + sysBanner + "\nEOF\nset system frob " + sysBanner + "\n",
		"message never closed": "set system login message <<'EOF'\n" + sysBanner + "\n",
		"message one line":     "set system login message \"" + sysBanner + "\"\n",
		"message bad marker":   "set system login message <<" + sysBanner + "\n",
		"key bad type":         "set system ntp authentication-key 1 type md5x value " + sysKey + "\n",
		"key bad number":       "set system ntp authentication-key 0 type md5 value " + sysKey + "\n",
		"key bad char":         "set system ntp authentication-key 1 type md5 value " + sysKey + ";\n",
		"key twice":            "set system ntp authentication-key 1 type md5 value " + sysKey + "\nset system ntp authentication-key 1 type md5 value " + sysKey + "\n",
		"key extra word":       "set system ntp authentication-key 1 type md5 value " + sysKey + " more\n",
		"key good":             "set system ntp authentication-key 1 type md5 value " + sysKey + "\nset system ntp server 192.0.2.1 key 1\n",
		"key placeholder":      "set system ntp authentication-key 1 type md5 value <" + sysKey + ">\n",
		"key in a comment":     "# " + sysKey + "\nset system frob\n",
		"quoted key":           "set system ntp authentication-key 1 type md5 value \"" + sysKey + "\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			b, fs := LintSystem(text, LayerScope)
			if len(fs) == 0 {
				t.Fatal("no finding at all")
			}
			for _, f := range fs {
				for _, s := range secrets {
					if strings.Contains(f.String(), s) {
						t.Errorf("%q holds %q", f, s)
					}
				}
			}
			if b != nil {
				el := b.String(true)
				for _, s := range secrets {
					if strings.Contains(el, s) {
						t.Errorf("the elided text holds %q:\n%s", s, el)
					}
				}
			}
		})
	}
}

func TestSystemLintOrderAndNoDoubleReport(t *testing.T) {
	_, fs := LintSystem("set system ntp trusted-key 1\nset system frob\n", LayerScope)
	if len(fs) != 1 || fs[0].Line != 2 || fs[0].Severity != SevError {
		t.Errorf("a parse error alone: %s", dump(fs))
	}
	_, fs = LintSystem(goodSystem, LayerScope)
	for i := 1; i < len(fs); i++ {
		if fs[i].Line < fs[i-1].Line {
			t.Errorf("findings out of line order:\n%s", dump(fs))
			break
		}
	}
	for _, text := range []string{"", "# only comments\n\n   \n"} {
		if _, fs := LintSystem(text, LayerDevice); len(fs) != 0 {
			t.Errorf("%q: %s", text, dump(fs))
		}
	}
}

func TestLintBlockDispatch(t *testing.T) {
	d, fs, err := LintBlock(BlockSystem, "set system time-zone UTC\n", LayerScope)
	if err != nil || HasErrors(fs) {
		t.Fatalf("system: %v %s", err, dump(fs))
	}
	if _, ok := d.(*SystemBlock); !ok || strings.Join(StatementsOf(d), "|") != "set system time-zone UTC" {
		t.Errorf("system doc: %T %q", d, StatementsOf(d))
	}
	d, fs, err = LintBlock(BlockSNMP, "set snmp community s1 clients 192.0.2.0/24\n", LayerScope)
	if err != nil || HasErrors(fs) {
		t.Fatalf("snmp: %v %s", err, dump(fs))
	}
	if _, ok := d.(*SNMPBlock); !ok || strings.Join(StatementsOf(d), "|") != "set snmp community s1 clients 192.0.2.0/24" {
		t.Errorf("snmp doc: %T %q", d, StatementsOf(d))
	}
	// A system text is not an snmp block and the other way round.
	if _, fs, _ := LintBlock(BlockSNMP, "set system time-zone UTC\n", LayerScope); !HasErrors(fs) {
		t.Error("a system statement passed the snmp grammar")
	}
	if _, fs, _ := LintBlock(BlockSystem, "set snmp location x\n", LayerScope); !HasErrors(fs) {
		t.Error("an snmp statement passed the system grammar")
	}
	if _, _, err := LintBlock("banner", "", LayerScope); err == nil {
		t.Error("an unknown block was accepted")
	}
	if StatementsOf(nil) != nil {
		t.Error("StatementsOf(nil)")
	}
}
