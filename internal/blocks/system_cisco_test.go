package blocks

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// the secrets of the IOS system fixtures: no finding and no elided text may
// hold one.
const (
	iosKey    = "ntpkey-Ho42Qr"
	iosBanner = "BANNER-MARKER-Wd5"
)

const goodIOSSystem = `# the lab's system settings
! another comment
banner login <<'EOF'
 Authorized use only.
! not a comment, a banner line
# nor this one

  indented, with a blank line above
EOF
ip domain name Lab.Example.Net
ip domain-name lab.example.net.ignored
ip domain list lab.example.net
ip domain-list example.net
clock timezone CET 1
ip name-server 192.0.2.53 2001:db8::53
ip name-server 192.0.2.54
ntp authentication-key 7 md5 ` + iosKey + `
ntp trusted-key 7
ntp server 192.0.2.123 prefer version 4 key 7 source Loopback0
ntp server ntp2.example.net
ntp authenticate
no ip domain list old.example.net
`

func TestIOSSystemParseGood(t *testing.T) {
	// 'ip domain-name' is the legacy spelling of the same statement: stated
	// twice here, it is a refusal; the good text has one
	text := strings.Replace(goodIOSSystem, "ip domain-name lab.example.net.ignored\n", "", 1)
	b, fs := LintIOSSystem(text, LayerScope)
	if HasErrors(fs) {
		t.Fatalf("errors:\n%s", dump(fs))
	}
	wantBanner := " Authorized use only.\n! not a comment, a banner line\n# nor this one\n\n  indented, with a blank line above"
	if b.Banner == nil || b.Banner.Line != 3 || b.Banner.Body != wantBanner || b.Banner.Lines() != 5 {
		t.Fatalf("banner: %+v", b.Banner)
	}
	if b.DomainName.Text != "lab.example.net" || len(b.DomainList) != 2 || b.DomainList[1].Text != "example.net" {
		t.Errorf("domain: %+v %+v", b.DomainName, b.DomainList)
	}
	if z := b.Timezone; z == nil || z.Zone != "CET" || z.Hours != 1 || z.HasMinutes || z.Text() != "clock timezone CET 1" {
		t.Errorf("timezone: %+v", b.Timezone)
	}
	if len(b.NameServers) != 3 || b.NameServers[1].Text != "2001:db8::53" || b.NameServers[2].Text != "192.0.2.54" {
		t.Errorf("name servers: %+v", b.NameServers)
	}
	if len(b.NTPServers) != 2 {
		t.Fatalf("servers: %+v", b.NTPServers)
	}
	if s := b.NTPServers[0]; s.Host != "192.0.2.123" || !s.Prefer || s.Version != 4 || s.Key != 7 || s.Source != "Loopback0" ||
		s.Text() != "ntp server 192.0.2.123 version 4 key 7 source Loopback0 prefer" {
		t.Errorf("server 1: %+v", s)
	}
	if s := b.NTPServers[1]; s.Host != "ntp2.example.net" || s.Prefer || s.Text() != "ntp server ntp2.example.net" {
		t.Errorf("server 2: %+v", s)
	}
	if len(b.NTPKeys) != 1 || b.NTPKeys[0].Number != 7 || b.NTPKeys[0].Type != "md5" || b.NTPKeys[0].Value != iosKey ||
		len(b.NTPTrustedKeys) != 1 || b.NTPAuthenticate == nil {
		t.Errorf("ntp: %+v", b)
	}
	if len(b.NotManaged) != 1 || b.NotManaged[0].Kind != SysDomainSearch || b.NotManaged[0].Value != "old.example.net" {
		t.Errorf("no lines: %+v", b.NotManaged)
	}
	if b.Empty() || !(&IOSSystemBlock{}).Empty() || !(*IOSSystemBlock)(nil).Empty() {
		t.Error("Empty")
	}
	// the legacy spelling alone is the same statement
	b2, fs := ParseIOSSystem("ip domain-name Lab.Example.Net\nip domain-list a.example.net\n")
	if HasErrors(fs) || b2.DomainName.Text != "lab.example.net" || b2.DomainList[0].Text != "a.example.net" {
		t.Errorf("legacy spelling: %+v %v", b2, fs)
	}
}

// Every refusal of the parser, with the line it is on.
func TestIOSSystemParseRefusals(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		line int
		frag string
	}{
		{"unknown statement", "hostname x\n", 1, "'banner login', 'ip', 'clock', 'ntp' and 'no' statements only"},
		{"a set", "set system domain-name x.example.net\n", 1, "statements only"},
		{"banner motd", "banner motd <<'EOF'\nhi\nEOF\n", 1, "only 'banner login' is accepted"},
		{"banner alone", "banner\n", 1, "only 'banner login' is accepted"},
		{"banner one line", "banner login ^Chello^C\n", 1, "the login banner is a heredoc"},
		{"banner bare", "banner login\n", 1, "the login banner is a heredoc"},
		{"banner unquoted marker", "banner login <<EOF\nhi\nEOF\n", 1, "<<'EOF' exactly"},
		{"banner other terminator", "banner login <<'END'\nhi\nEND\n", 1, "<<'EOF' exactly"},
		{"banner trailing words", "banner login <<'EOF' x\nhi\nEOF\n", 1, "<<'EOF' exactly"},
		{"banner never closed", "ip domain name a.example.net\nbanner login <<'EOF'\nhi\n", 2, "never closed"},
		{"banner indented terminator", "banner login <<'EOF'\nhi\n EOF\n", 1, "never closed"},
		{"banner twice", "banner login <<'EOF'\na\nEOF\nbanner login <<'EOF'\nb\nEOF\n", 4, "stated twice"},
		{"after a banner", "banner login <<'EOF'\na\nEOF\nfrob\n", 4, "statements only"},
		{"quote", "ip domain name \"a.example.net\"\n", 1, "a quote is not accepted"},
		{"tab", "ip domain name\ta.example.net\n", 1, "a tab at column"},
		{"control", "ip domain name a.example.net\x07\n", 1, "a control character (0x07)"},
		{"non-ascii", "ip domain name caf\u00e9.example.net\n", 1, "not ASCII"},
		{"long line", "ip domain name " + strings.Repeat("a", 1000) + "\n", 1, "longer than 1000"},
		{"ip alone", "ip\n", 1, "needs domain or name-server"},
		{"ip route", "ip route 0.0.0.0 0.0.0.0 192.0.2.1\n", 1, "word 2 is not one of domain, name-server"},
		{"domain lookup", "ip domain lookup\n", 1, "word 3 is not name or list"},
		{"domain alone", "ip domain\n", 1, "needs name or list"},
		{"domain no value", "ip domain name\n", 1, "takes one value"},
		{"domain two values", "ip domain name a.example.net b.example.net\n", 1, "takes one value"},
		{"domain twice", "ip domain name a.example.net\nip domain-name b.example.net\n", 2, "is stated twice"},
		{"domain vrf no name", "ip domain name vrf\n", 1, "'vrf' takes the name of the vrf"},
		{"domain vrf no value", "ip domain name vrf MGMT\n", 1, "takes one value"},
		{"domain vrf two values", "ip domain name vrf MGMT a.example.net b.example.net\n", 1, "takes one value"},
		{"domain vrf twice", "ip domain name vrf MGMT a.example.net\nip domain-name vrf MGMT b.example.net\n", 2, "is stated twice for one vrf"},
		{"domain vrf label", "ip domain name vrf MGMT a_b.example.net\n", 1, "not a host name"},
		{"domain vrf with a space", "ip domain name vrf \"MG MT\" a.example.net\n", 1, "a quote is not accepted"},
		{"domain vrf split by a blank", "ip domain name vrf MG MT a.example.net\n", 1, "takes one value"},
		{"domain vrf name off the alphabet", "ip domain name vrf MG;MT a.example.net\n", 1, "the vrf name of ip domain name holds a character other than"},
		{"domain vrf placeholder", "ip domain name vrf <vrf> a.example.net\n", 1, "the vrf name of ip domain name holds a character other than"},
		{"domain vrf long", "ip domain name vrf " + strings.Repeat("v", 65) + " a.example.net\n", 1, "is longer than 64"},
		{"domain label", "ip domain name a_b.example.net\n", 1, "not a host name"},
		{"domain placeholder", "ip domain name <secret>\n", 1, "is a placeholder"},
		{"list twice", "ip domain list a.example.net\nip domain-list A.EXAMPLE.NET\n", 2, "is listed twice"},
		{"list vrf no name", "ip domain list vrf\n", 1, "'vrf' takes the name of the vrf"},
		{"list vrf no value", "ip domain list vrf MGMT\n", 1, "takes one value"},
		{"list vrf twice", "ip domain list vrf MGMT a.example.net\nip domain-list vrf MGMT A.EXAMPLE.NET\n", 2, "is listed twice for one vrf"},
		{"list vrf two values", "ip domain list vrf MGMT a.example.net b.example.net\n", 1, "takes one value"},
		{"name-server none", "ip name-server\n", 1, "needs at least one address"},
		{"name-server name", "ip name-server dns.example.net\n", 1, "not an IPv4 or IPv6 address"},
		{"name-server second bad", "ip name-server 192.0.2.53 dns.example.net\n", 1, "address 2 of ip name-server (word 4)"},
		{"name-server twice", "ip name-server 192.0.2.53\nip name-server 192.0.2.54 192.0.2.53\n", 2, "is listed twice"},
		{"name-server twice on a line", "ip name-server 192.0.2.53 192.0.2.53\n", 1, "is listed twice"},
		{"name-server vrf no name", "ip name-server vrf\n", 1, "'vrf' takes the name of the vrf"},
		{"name-server vrf no address", "ip name-server vrf MGMT\n", 1, "needs at least one address (word 5)"},
		{"name-server vrf bad address", "ip name-server vrf MGMT 192.0.2.53 dns.example.net\n", 1, "address 2 of ip name-server (word 6)"},
		{"name-server vrf twice", "ip name-server vrf MGMT 192.0.2.53\nip name-server vrf MGMT 192.0.2.54 192.0.2.53\n", 2, "is listed twice"},
		{"name-server vrf twice on a line", "ip name-server vrf MGMT 192.0.2.53 192.0.2.53\n", 1, "is listed twice"},
		{"name-server vrf name with a space", "ip name-server vrf \"M G\" 192.0.2.53\n", 1, "a quote is not accepted"},
		{"clock summer-time", "clock summer-time EDT recurring\n", 1, "only 'clock timezone'"},
		{"clock alone", "clock\n", 1, "only 'clock timezone'"},
		{"timezone short", "clock timezone CET\n", 1, "takes <zone> <hours> [<minutes>]"},
		{"timezone long", "clock timezone CET 1 0 0\n", 1, "takes <zone> <hours> [<minutes>]"},
		{"timezone zone", "clock timezone 1CET 1\n", 1, "the zone of clock timezone"},
		{"timezone hours", "clock timezone CET 24\n", 1, "whole number from -23 to 23"},
		{"timezone hours word", "clock timezone CET one\n", 1, "whole number from -23 to 23"},
		{"timezone minutes", "clock timezone CET 1 60\n", 1, "whole number from 0 to 59"},
		{"timezone twice", "clock timezone CET 1\nclock timezone UTC 0\n", 2, "is stated twice"},
		{"timezone placeholder", "clock timezone <zone> 1\n", 1, "is a placeholder"},
		{"ntp alone", "ntp\n", 1, "needs server, authentication-key"},
		{"ntp master", "ntp master 3\n", 1, "word 2 is not one of server"},
		{"ntp server none", "ntp server\n", 1, "needs an address or a name"},
		{"ntp server vrf no name", "ntp server vrf\n", 1, "'vrf' takes the name of the vrf"},
		{"ntp server vrf no host", "ntp server vrf MGMT\n", 1, "needs an address or a name (word 5)"},
		{"ntp server vrf bad host", "ntp server vrf MGMT not_a_host\n", 1, "the address of ntp server (word 5)"},
		{"ntp server vrf option", "ntp server vrf MGMT 192.0.2.123 burst\n", 1, "word 6 is not one of prefer, version, key, source"},
		{"ntp server vrf v6", "ntp server vrf MGMT 2001:db8::1\n", 1, "an IPv6 address is not in the grammar"},
		{"ntp server vrf ip word", "ntp server vrf MGMT ip 192.0.2.123\n", 1, "'ip' is not in the grammar"},
		{"ntp server vrf twice", "ntp server vrf MGMT 192.0.2.123\nntp server vrf MGMT 192.0.2.123 prefer\n", 2, "is listed twice"},
		{"ntp server vrf after the host", "ntp server 192.0.2.123 vrf MGMT\n", 1, "not one of prefer, version, key, source"},
		{"ntp server vrf name off the alphabet", "ntp server vrf M/M 192.0.2.123\n", 1, "the vrf name of ntp server holds a character other than"},
		{"ntp server vrf name with a space", "ntp server vrf \"M M\" 192.0.2.123\n", 1, "a quote is not accepted"},
		{"no ntp server vrf bad host", "no ntp server vrf MGMT not_a_host\n", 1, "not a host name"},
		{"no ntp server vrf two hosts", "no ntp server vrf MGMT 192.0.2.1 192.0.2.2\n", 1, "takes one value, or none"},
		{"no ntp server vrf last word", "no ntp server vrf\n", 1, "'vrf' takes the name of the vrf"},
		{"no domain name vrf value", "no ip domain name vrf MGMT a.example.net\n", 1, "takes nothing after it"},
		{"no domain list vrf last word", "no ip domain list vrf\n", 1, "'vrf' takes the name of the vrf"},
		{"no name-server vrf bad", "no ip name-server vrf MGMT dns.example.net\n", 1, "not an IPv4 or IPv6 address"},
		{"ntp server ip", "ntp server ip 192.0.2.123\n", 1, "'ip' is not in the grammar"},
		{"ntp server ipv6 word", "ntp server ipv6 2001:db8::1\n", 1, "'ipv6' is not in the grammar"},
		{"ntp server v6", "ntp server 2001:db8::1\n", 1, "an IPv6 address is not in the grammar"},
		{"ntp server bad host", "ntp server not_a_host\n", 1, "not a host name"},
		{"ntp server option", "ntp server 192.0.2.123 burst\n", 1, "not one of prefer, version, key, source"},
		{"ntp server version", "ntp server 192.0.2.123 version 5\n", 1, "version takes 1, 2, 3 or 4"},
		{"ntp server version none", "ntp server 192.0.2.123 version\n", 1, "version takes a value"},
		{"ntp server key", "ntp server 192.0.2.123 key 0\n", 1, "key takes a key number"},
		{"ntp server source abbreviated", "ntp server 192.0.2.123 source Lo0\n", 1, "has its type abbreviated"},
		{"ntp server prefer twice", "ntp server 192.0.2.123 prefer prefer\n", 1, "prefer is stated twice"},
		{"ntp server twice", "ntp server 192.0.2.123\nntp server 192.0.2.123 prefer\n", 2, "is listed twice"},
		{"ntp key no number", "ntp authentication-key\n", 1, "needs a key number"},
		{"ntp key bad number", "ntp authentication-key abc md5 " + iosKey + "\n", 1, "is a key number from 1 to"},
		{"ntp key no string", "ntp authentication-key 7 md5\n", 1, "takes md5 <string>"},
		{"ntp key type", "ntp authentication-key 7 sha1 " + iosKey + "\n", 1, "takes md5 <string>"},
		{"ntp key placeholder", "ntp authentication-key 7 md5 <secret>\n", 1, "is a placeholder"},
		{"ntp key too long", "ntp authentication-key 7 md5 " + strings.Repeat("a", 33) + "\n", 1, "is longer than 32 characters"},
		{"ntp key char", "ntp authentication-key 7 md5 key;word\n", 1, "reads specially"},
		{"ntp key twice", "ntp authentication-key 7 md5 aaa\nntp authentication-key 7 md5 bbb\n", 2, "is stated twice"},
		{"trusted none", "ntp trusted-key\n", 1, "takes one key number"},
		{"trusted range", "ntp trusted-key 1 - 5\n", 1, "takes one key number"},
		{"trusted bad", "ntp trusted-key x\n", 1, "takes a key number from"},
		{"trusted twice", "ntp trusted-key 7\nntp trusted-key 7\n", 2, "is listed twice"},
		{"authenticate words", "ntp authenticate now\n", 1, "takes nothing after it"},
		{"authenticate twice", "ntp authenticate\nntp authenticate\n", 2, "is stated twice"},
		{"no alone", "no\n", 1, "'no' needs a statement"},
		{"no hostname", "no hostname\n", 1, "takes banner, clock, ip or ntp"},
		{"no banner motd", "no banner motd\n", 1, "only 'no banner login'"},
		{"no banner words", "no banner login x\n", 1, "takes nothing after it"},
		{"no domain name value", "no ip domain name a.example.net\n", 1, "takes nothing after it"},
		{"no ip route", "no ip route 0.0.0.0\n", 1, "a 'no ip' line takes"},
		{"no ip alone", "no ip\n", 1, "needs domain or name-server"},
		{"no name-server bad", "no ip name-server dns.example.net\n", 1, "not an IPv4 or IPv6 address"},
		{"no name-server two", "no ip name-server 192.0.2.1 192.0.2.2\n", 1, "takes one value, or none"},
		{"no ntp server bad", "no ntp server not_a_host\n", 1, "not a host name"},
		{"no ntp key bad", "no ntp authentication-key x\n", 1, "is not a key number"},
		{"no ntp master", "no ntp master\n", 1, "word 3 is not one of server"},
		{"no ntp words", "no ntp x y\n", 1, "word 3 is not one of server"},
		{"no timezone words", "no clock timezone CET\n", 1, "takes nothing after it"},
		{"no summer-time", "no clock summer-time\n", 1, "only 'no clock timezone'"},
		{"a second line", "# ok\nip domain name a.example.net\nfrob\n", 3, "statements only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := ParseIOSSystem(tc.text)
			if !hasFinding(fs, SevError, tc.line, tc.frag) {
				t.Errorf("want an error at line %d with %q, got:\n%s", tc.line, tc.frag, dump(fs))
			}
		})
	}
}

func TestIOSSystemCheck(t *testing.T) {
	long := strings.Repeat("x", 81)
	var twentyOne []string
	for i := 0; i < 21; i++ {
		twentyOne = append(twentyOne, fmt.Sprintf("line %d", i+1))
	}
	all := strings.Join(BannerDelimiters, " ")
	for _, tc := range []struct {
		name  string
		text  string
		layer Layer
		sev   Severity
		line  int
		frag  string
	}{
		{"empty banner", "banner login <<'EOF'\nEOF\n", LayerScope, SevError, 1, "the login banner is empty"},
		{"blank banner", "banner login <<'EOF'\n   \nEOF\n", LayerScope, SevError, 1, "the login banner is empty"},
		{"banner placeholder", "banner login <<'EOF'\n<message: 2 lines, 20 characters>\nEOF\n", LayerScope, SevError, 2, "is a placeholder"},
		{"banner terminator line", "banner login <<'EOF'\nok\nEOF\nEOF\n", LayerScope, SevError, 4, "statements only"},
		{"banner tab", "banner login <<'EOF'\nok\ttab\nEOF\n", LayerScope, SevError, 2, "line 1 of the login banner holds a tab at column 3"},
		{"banner control", "banner login <<'EOF'\nok\x01\nEOF\n", LayerScope, SevError, 2, "a control character (0x01) at column 3"},
		{"banner non-ascii", "banner login <<'EOF'\ncaf\u00e9\nEOF\n", LayerScope, SevError, 2, "a character that is not ASCII at column 4"},
		{"banner column 81", "banner login <<'EOF'\n" + long + "\nEOF\n", LayerScope, SevError, 2, "is 81 characters: at most 80"},
		{"banner 21 lines", "banner login <<'EOF'\n" + strings.Join(twentyOne, "\n") + "\nEOF\n", LayerScope, SevError, 1, "is 21 lines: at most 20"},
		{"banner every delimiter", "banner login <<'EOF'\n" + all + "\nEOF\n", LayerScope, SevError, 1, "holds every delimiter character"},
		{"key with no authenticate", "ntp authentication-key 5 md5 " + iosKey + "\n", LayerScope, SevNote, 1, "'ntp authenticate' is not"},
		{"key is a secret", "ntp authentication-key 5 md5 " + iosKey + "\n", LayerScope, SevNote, 1, "ntp authentication-key 5 carries a secret"},
		{"server key not defined", "ntp server 192.0.2.1 key 9\n", LayerScope, SevNote, 1, "uses key 9, which this block does not define"},
		{"trusted key not defined", "ntp trusted-key 9\n", LayerScope, SevNote, 1, "names a key this block does not define"},
		{"authenticate with no keys", "ntp authenticate\n", LayerScope, SevNote, 1, "needs keys and trusted keys on the device"},
		{"no line", "no ntp server 192.0.2.1\n", LayerScope, SevNote, 1, "a 'no' line"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, fs := LintIOSSystem(tc.text, tc.layer)
			if !hasFinding(fs, tc.sev, tc.line, tc.frag) {
				t.Errorf("want %v at line %d with %q, got:\n%s", tc.sev, tc.line, tc.frag, dump(fs))
			}
		})
	}
	// a text that is fine has no error; 20 lines of 80 characters is the
	// most
	var twenty []string
	for i := 0; i < 20; i++ {
		twenty = append(twenty, strings.Repeat("y", 80))
	}
	if _, fs := LintIOSSystem("banner login <<'EOF'\n"+strings.Join(twenty, "\n")+"\nEOF\n", LayerScope); HasErrors(fs) {
		t.Errorf("20 lines of 80 characters:\n%s", dump(fs))
	}
}

func TestBannerDelimiter(t *testing.T) {
	for _, tc := range []struct{ body, want string }{
		{"plain", "^"},
		{"a ^ in it", "~"},
		{"^ ~", "%"},
		{"^ ~ %", "#"},
		{"^ ~ % #", "@"},
		{"^ ~ % # @", "$"},
		{"^ ~ % # @ $", "&"},
	} {
		d, ok := BannerDelimiter(tc.body)
		if !ok || d != tc.want {
			t.Errorf("%q: %q %v, want %q", tc.body, d, ok, tc.want)
		}
	}
	if _, ok := BannerDelimiter(strings.Join(BannerDelimiters, "")); ok {
		t.Error("every candidate in the text has a delimiter")
	}
	if IOSBannerLines(strings.Join(BannerDelimiters, "")) != nil {
		t.Error("lines of a banner that no delimiter fits")
	}
	got := IOSBannerLines("a\n\n! b")
	if strings.Join(got, "|") != "banner login ^|a||! b|^" {
		t.Errorf("%q", got)
	}
}

// The banner of 20 lines goes through the rendering and back through what a
// device prints: the body is the identity, for the delimiter a person typed
// and for IOS's own '^C'.
func TestIOSBannerRoundTrip(t *testing.T) {
	var lines []string
	for i := 1; i <= 20; i++ {
		switch i {
		case 3:
			lines = append(lines, "")
		case 5:
			lines = append(lines, "! a line that starts with a bang")
		case 7:
			lines = append(lines, "   indented ^ with a caret")
		default:
			lines = append(lines, fmt.Sprintf("%2d %s", i, strings.Repeat("=", 60)))
		}
	}
	body := strings.Join(lines, "\n")
	b, fs := LintIOSSystem("banner login <<'EOF'\n"+body+"\nEOF\n", LayerScope)
	if HasErrors(fs) || b.Banner.Body != body {
		t.Fatalf("lint: %v", fs)
	}
	// the statements typed: the first delimiter the text does not hold
	st := IOSSystemStatements(b)
	if st[0] != "banner login ~" || st[len(st)-1] != "~" || len(st) != 22 {
		t.Fatalf("typed: %q ... %q (%d)", st[0], st[len(st)-1], len(st))
	}
	got, took, ok := DeviceBanner(st)
	if !ok || took != len(st) || got != body {
		t.Errorf("read back %v %d: %q", ok, took, got)
	}
	// as IOS prints it
	dev := append([]string{"banner login ^C"}, lines...)
	dev = append(dev, "^C", "!", "line con 0")
	got, took, ok = DeviceBanner(dev)
	if !ok || took != 22 || got != body {
		t.Errorf("device form %v %d", ok, took)
	}
	// the block's own text is the identity too
	if b2, _ := LintIOSSystem(b.String(false), LayerScope); b2.Banner.Body != body || b2.String(false) != b.String(false) {
		t.Errorf("the canonical text is not stable:\n%s", b.String(false))
	}
}

func TestDeviceBanner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		body  string
		took  int
		ok    bool
	}{
		{"ctrl-c multi", []string{"banner login ^C", "hello", "there", "^C", "!"}, "hello\nthere", 4, true},
		{"printable multi", []string{"banner login #", "hello", "#"}, "hello", 3, true},
		{"one line", []string{"banner login ^Chello^C"}, "hello", 1, true},
		{"text on the opening line", []string{"banner login ^Chello", "there", "^C"}, "hello\nthere", 3, true},
		{"text before the closing", []string{"banner login ^C", "hello", "there^C"}, "hello\nthere", 3, true},
		{"blank lines kept", []string{"banner login ^C", "", "a", "", "^C"}, "\na\n", 5, true},
		{"trailing blanks trimmed", []string{"banner login ^C", "a  ", "^C"}, "a", 3, true},
		{"never closed", []string{"banner login ^C", "a", "b"}, "", 3, false},
		{"not a login banner", []string{"banner motd ^C", "a", "^C"}, "", 1, false},
		{"no delimiter", []string{"banner login"}, "", 1, false},
		{"indented words", []string{"  banner login ^C", "a", "^C"}, "a", 3, true},
	} {
		body, took, ok := DeviceBanner(tc.lines)
		if body != tc.body || took != tc.took || ok != tc.ok {
			t.Errorf("%s: %q %d %v, want %q %d %v", tc.name, body, took, ok, tc.body, tc.took, tc.ok)
		}
	}
	if _, _, ok := DeviceBanner(nil); ok {
		t.Error("no lines")
	}
}

// An IOS 12.x device never prints 'version 3': the dialect leaves it out, and
// only it. Every other version and option stays, and Text is as stated.
func TestIOSNTPServerTextInDialect(t *testing.T) {
	cases := []struct {
		name string
		s    IOSNTPServer
		d    IOSDialect
		want string
	}{
		{"3 under IOS12", IOSNTPServer{Host: "192.0.2.123", Version: 3}, IOS12, "ntp server 192.0.2.123"},
		{"2 under IOS12", IOSNTPServer{Host: "192.0.2.123", Version: 2}, IOS12, "ntp server 192.0.2.123 version 2"},
		{"4 under IOS12", IOSNTPServer{Host: "192.0.2.123", Version: 4}, IOS12, "ntp server 192.0.2.123 version 4"},
		{"3 under modern", IOSNTPServer{Host: "192.0.2.123", Version: 3}, IOSModern, "ntp server 192.0.2.123 version 3"},
		{"unstated under IOS12", IOSNTPServer{Host: "192.0.2.123"}, IOS12, "ntp server 192.0.2.123"},
		{"every option under IOS12", IOSNTPServer{VRF: "MGMT", Host: "192.0.2.123", Version: 3, Key: 5, Source: "Loopback0", Prefer: true}, IOS12,
			"ntp server vrf MGMT 192.0.2.123 key 5 source Loopback0 prefer"},
	}
	for _, c := range cases {
		if got := c.s.textIn(c.d); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if got := (IOSNTPServer{Host: "h", Version: 3}).Text(); got != "ntp server h version 3" {
		t.Errorf("Text: %q", got)
	}
	b, fs := LintIOSSystem("ntp server 192.0.2.123 version 3 prefer\nntp server vrf MGMT 192.0.2.124 version 2\n", LayerScope)
	if HasErrors(fs) {
		t.Fatal(fs)
	}
	if got := strings.Join(IOSSystemStatementsIn(b, IOS12), "|"); got != "ntp server 192.0.2.123 prefer|ntp server vrf MGMT 192.0.2.124 version 2" {
		t.Errorf("IOS12: %q", got)
	}
	if got := strings.Join(IOSSystemStatements(b), "|"); got != "ntp server 192.0.2.123 version 3 prefer|ntp server vrf MGMT 192.0.2.124 version 2" {
		t.Errorf("modern: %q", got)
	}
	// the block's own text is as typed in either dialect
	if got := b.String(false); !strings.Contains(got, "ntp server 192.0.2.123 version 3 prefer\n") {
		t.Errorf("String: %q", got)
	}
}

func TestIOSSystemStatementsAndText(t *testing.T) {
	b, fs := LintIOSSystem(goodIOSSystem, LayerScope)
	if HasErrors(fs) {
		// the good text names the domain twice (both spellings)
		b, fs = LintIOSSystem(strings.Replace(goodIOSSystem, "ip domain-name lab.example.net.ignored\n", "", 1), LayerScope)
		if HasErrors(fs) {
			t.Fatal(dump(fs))
		}
	}
	st := IOSSystemStatements(b)
	want := []string{
		"banner login ~",
		" Authorized use only.",
		"! not a comment, a banner line",
		"# nor this one",
		"",
		"  indented, with a blank line above",
		"~",
		"ip domain name lab.example.net",
		"ip domain list lab.example.net",
		"ip domain list example.net",
		"clock timezone CET 1",
		"ip name-server 192.0.2.53",
		"ip name-server 2001:db8::53",
		"ip name-server 192.0.2.54",
		"ntp authentication-key 7 md5 " + iosKey,
		"ntp trusted-key 7",
		"ntp server 192.0.2.123 version 4 key 7 source Loopback0 prefer",
		"ntp server ntp2.example.net",
		"ntp authenticate",
	}
	// the banner holds no '^', but its first line holds a '!': no delimiter
	// problem, the first candidate is '^'
	want[0], want[6] = "banner login ^", "^"
	if strings.Join(st, "\n") != strings.Join(want, "\n") {
		t.Errorf("statements:\n%s\nwant:\n%s", strings.Join(st, "\n"), strings.Join(want, "\n"))
	}
	units := IOSSystemUnits(b)
	if len(units) != 13 || len(units[0]) != 7 {
		t.Errorf("units: %d, first of %d lines", len(units), len(units[0]))
	}
	// the NTP lines go in the order IOS needs: keys, trusted keys, servers,
	// authenticate last
	text := b.String(false)
	for _, w := range []string{"no ip domain list old.example.net\n", "banner login <<'EOF'\n", "\nEOF\n"} {
		if !strings.Contains(text, w) {
			t.Errorf("the text lacks %q:\n%s", w, text)
		}
	}
	// stable: read back, the same text
	b2, fs := LintIOSSystem(text, LayerScope)
	if HasErrors(fs) || b2.String(false) != text {
		t.Errorf("the canonical text is not stable (%v):\n%s\n---\n%s", fs, text, b2.String(false))
	}
	if (*IOSSystemBlock)(nil).String(false) != "" || (&IOSSystemBlock{}).String(false) != "" || IOSSystemStatements(nil) != nil {
		t.Error("an empty block has no text")
	}
	if !IsIOSSecretStatement("ntp authentication-key 7 md5 x") || IsIOSSecretStatement("ntp trusted-key 7") || IsIOSSecretStatement("ntp authentication-key 7") {
		t.Error("IsIOSSecretStatement")
	}
	if StatementsOf(b) == nil {
		t.Error("StatementsOf")
	}
}

func TestIOSSystemElide(t *testing.T) {
	b, fs := LintIOSSystem("banner login <<'EOF'\n"+iosBanner+"\nsecond line\nEOF\nntp authentication-key 5 md5 "+iosKey+"\nntp trusted-key 5\nip domain name lab.example.net\n", LayerScope)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	el := b.String(true)
	for _, secret := range []string{iosBanner, iosKey, "second line"} {
		if strings.Contains(el, secret) {
			t.Errorf("the elided text holds %q:\n%s", secret, el)
		}
	}
	for _, want := range []string{"<message: 2 lines, ", "ntp authentication-key 5 md5 <secret>", "ip domain name lab.example.net"} {
		if !strings.Contains(el, want) {
			t.Errorf("the elided text lacks %q:\n%s", want, el)
		}
	}
	// an elided text is refused when it is read back
	if _, fs := ParseIOSSystem(el); !HasErrors(fs) {
		t.Errorf("the elided text parses:\n%s", el)
	}
	// the original is untouched
	if b.Banner.Body != iosBanner+"\nsecond line" || b.NTPKeys[0].Value != iosKey {
		t.Errorf("elide changed the block: %+v", b)
	}
	if ElideIOSSystem(nil) != nil {
		t.Error("nil")
	}
}

func TestIOSSystemResolve(t *testing.T) {
	parse := func(text string) *IOSSystemBlock {
		b, fs := LintIOSSystem(text, LayerScope)
		if HasErrors(fs) {
			t.Fatalf("%s:\n%s", text, dump(fs))
		}
		return b
	}
	scope := parse("banner login <<'EOF'\nscope banner\nEOF\nip domain name lab.example.net\nip domain list a.example.net\n" +
		"clock timezone UTC 0\nip name-server 192.0.2.53\nntp server 192.0.2.1 prefer\nntp server 192.0.2.2\n" +
		"ntp authentication-key 5 md5 scopekey\nntp trusted-key 5\nntp authenticate\n")
	dev := parse("banner login <<'EOF'\ndevice banner\nEOF\nip domain list b.example.net\nip name-server 192.0.2.54\n" +
		"ntp server 192.0.2.1 key 5\nntp authentication-key 5 md5 devkey\n" +
		"no ip domain name\nno ip name-server 192.0.2.53\nno ntp server 192.0.2.2\nno ntp authenticate\nno ntp trusted-key\n")
	r := ResolveIOSSystem(nil, scope, dev)
	text := r.String(false)
	for _, want := range []string{"device banner", "ip domain list a.example.net", "ip domain list b.example.net", "clock timezone UTC 0",
		"ip name-server 192.0.2.54", "ntp server 192.0.2.1 key 5\n", "ntp authentication-key 5 md5 devkey"} {
		if !strings.Contains(text, want) {
			t.Errorf("resolved lacks %q:\n%s", want, text)
		}
	}
	typed := strings.Join(IOSSystemStatements(r), "\n")
	for _, gone := range []string{"scope banner", "ip domain name", "ip name-server 192.0.2.53", "ntp server 192.0.2.2", "scopekey",
		"ntp authenticate", "ntp trusted-key", "prefer"} {
		if strings.Contains(typed, gone) {
			t.Errorf("resolved still states %q:\n%s", gone, typed)
		}
	}
	// the inputs are untouched
	if scope.Banner.Body != "scope banner" || len(scope.NTPServers) != 2 || scope.DomainName == nil {
		t.Errorf("the scope's block changed: %+v", scope)
	}
	// a 'no ntp' takes every ntp statement
	r2 := ResolveIOSSystem(nil, scope, parse("no ntp\nip domain list c.example.net\n"))
	if len(r2.NTPServers)+len(r2.NTPKeys)+len(r2.NTPTrustedKeys) != 0 || r2.NTPAuthenticate != nil || len(r2.DomainList) != 2 {
		t.Errorf("no ntp: %+v", r2)
	}
	// a layer's own statements come after its no lines
	r3 := ResolveIOSSystem(nil, scope, parse("no ip domain name\nip domain name dev.example.net\n"))
	if r3.DomainName == nil || r3.DomainName.Text != "dev.example.net" {
		t.Errorf("own statement after its no line: %+v", r3.DomainName)
	}
	// nothing at all
	if r := ResolveIOSSystem(nil, nil, nil); !r.Empty() {
		t.Errorf("empty: %+v", r)
	}
}

func TestIOSSystemFindingsNeverHoldAString(t *testing.T) {
	cases := []string{
		"banner login <<'EOF'\n" + iosBanner + "\tx\nEOF\n",
		"banner login <<'EOF'\n" + iosBanner + strings.Repeat("y", 100) + "\nEOF\n",
		"banner login <<'EOF'\n" + iosBanner + "\x01\nEOF\n",
		"banner login <<'EOF'\n" + iosBanner + " \u00e9\nEOF\n",
		"banner login <<'EOF' " + iosBanner + "\nx\nEOF\n",
		"banner login <<'EOF'\n" + iosBanner + "\n",
		"banner motd " + iosBanner + "\n",
		"ntp authentication-key 5 md5 " + iosKey + ";\n",
		"ntp authentication-key 5 md5 " + iosKey + strings.Repeat("z", 40) + "\n",
		"ntp authentication-key 5 sha1 " + iosKey + "\n",
		"ntp authentication-key x md5 " + iosKey + "\n",
		"ntp authentication-key 5 md5 " + iosKey + " extra\n",
		"ntp authentication-key 5 md5 " + iosKey + "\nntp authentication-key 5 md5 " + iosKey + "\n",
		"ntp server " + iosKey + "_x\n",
		"ip domain name " + iosKey + "_x\n",
	}
	for _, text := range cases {
		_, fs := LintIOSSystem(text, LayerScope)
		if !HasErrors(fs) {
			t.Errorf("no error for %q", text)
		}
		for _, f := range fs {
			if strings.Contains(f.Text, iosKey) || strings.Contains(f.Text, iosBanner) {
				t.Errorf("a finding holds a string: %q (%q)", f, text)
			}
		}
	}
	// the notes of a good block hold none either
	_, fs := LintIOSSystem("banner login <<'EOF'\n"+iosBanner+"\nEOF\nntp authentication-key 5 md5 "+iosKey+"\nntp server 192.0.2.1 key 6\nntp trusted-key 7\n", LayerScope)
	if HasErrors(fs) || len(fs) == 0 {
		t.Fatalf("%v", fs)
	}
	for _, f := range fs {
		if strings.Contains(f.Text, iosKey) || strings.Contains(f.Text, iosBanner) {
			t.Errorf("a note holds a string: %q", f)
		}
	}
}

func TestIOSSystemLintOrderAndNoDoubleReport(t *testing.T) {
	// an error stops the check, so one mistake is not reported twice, and
	// the findings are in line order
	_, fs := LintIOSSystem("ntp authentication-key 5 md5 k\nip domain name a_b\nntp server 192.0.2.1 version 9\n", LayerScope)
	if len(fs) != 2 || fs[0].Line != 2 || fs[1].Line != 3 {
		t.Errorf("%s", dump(fs))
	}
}

func TestIOSSystemTemplate(t *testing.T) {
	for _, layer := range []Layer{LayerScope, LayerDevice} {
		text := TemplateFor(VendorCisco, BlockSystem, layer)
		if !strings.Contains(text, "banner login <<'EOF'") || !strings.Contains(text, "ntp authentication-key") {
			t.Errorf("template:\n%s", text)
		}
		// saved unchanged it states nothing
		b, fs := LintIOSSystem(text, layer)
		if HasErrors(fs) || !b.Empty() {
			t.Errorf("the template is not an empty block: %v %+v", fs, b)
		}
		// the example, uncommented, is a block that passes
		var ex []string
		in := false
		for _, l := range strings.Split(text, "\n") {
			if strings.HasPrefix(l, "# Example") {
				in = true
				continue
			}
			if in && strings.HasPrefix(l, "# ") {
				ex = append(ex, strings.TrimPrefix(l, "# "))
			}
		}
		b, fs = LintIOSSystem(strings.Join(ex, "\n")+"\n", layer)
		if HasErrors(fs) || b.Empty() || b.Banner == nil {
			t.Errorf("the example: %v\n%s", fs, strings.Join(ex, "\n"))
		}
	}
}

func TestAdoptIOSSystem(t *testing.T) {
	raw := strings.Join([]string{
		"ip domain name lab.example.net",
		"ip domain-list example.net",
		"ip domain lookup",
		"ip name-server 192.0.2.53 192.0.2.54",
		"ip name-server vrf MGMT 192.0.2.99",
		"ip domain name vrf MGMT MGMT.example.net",
		"ip domain-list vrf MGMT mgmt.example.net",
		"ip domain name vrf",
		"clock timezone CET 1 0",
		"ntp authentication-key 5 md5 0822455D0A16 7",
		"ntp authentication-key 6 md5 plain-key-text",
		"ntp trusted-key 5",
		"ntp authenticate",
		"ntp server 192.0.2.123 key 5 prefer version 4",
		"ntp server vrf MGMT 192.0.2.77",
		"ntp master 3",
		"banner motd ^C",
		"motd text that is not ours",
		"^C",
		"banner login ^C",
		iosBanner,
		"! looks like a comment",
		"^C",
		"",
	}, "\n")
	res := AdoptIOSSystem(raw, nil, nil)
	for _, want := range []string{
		"banner login <<'EOF'\n" + iosBanner + "\n! looks like a comment\nEOF\n",
		"ip domain name lab.example.net\n",
		"ip domain list example.net\n",
		"clock timezone CET 1 0\n",
		"ip name-server 192.0.2.53\nip name-server 192.0.2.54\n",
		"ntp trusted-key 5\n",
		"ntp server 192.0.2.123 version 4 key 5 prefer\n",
		"ntp authenticate\n",
	} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	// the lines of a vrf are the block's, each an object of its vrf
	for _, want := range []string{"ip name-server vrf MGMT 192.0.2.99\n", "ntp server vrf MGMT 192.0.2.77\n", "ip domain name vrf MGMT mgmt.example.net\n", "ip domain list vrf MGMT mgmt.example.net\n"} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	for _, not := range []string{"0822455D0A16", "plain-key-text", "motd", "lookup", "ntp master", "authentication-key"} {
		if strings.Contains(res.Text, not) {
			t.Errorf("the draft holds %q:\n%s", not, res.Text)
		}
	}
	// the draft is a block that passes the check
	if _, fs := LintIOSSystem(res.Text, LayerScope); HasErrors(fs) {
		t.Errorf("the draft does not lint: %v", fs)
	}
	left := strings.Join(res.Left, "\n")
	for _, w := range []string{"ntp authentication-key 5 holds the device's own key string", "ntp authentication-key 6 holds the device's own key string"} {
		if !strings.Contains(left, w) {
			t.Errorf("left lacks %q:\n%s", w, left)
		}
	}
	if strings.Contains(left+strings.Join(res.Notes, "\n"), "0822455D0A16") || strings.Contains(left+strings.Join(res.Notes, "\n"), iosBanner) {
		t.Errorf("a note holds a value:\n%s", left)
	}
	notes := strings.Join(res.Notes, "\n")
	if !strings.Contains(notes, "outside what an IOS system block takes") {
		t.Errorf("notes:\n%s", notes)
	}
	if res.Statements != 13 {
		t.Errorf("counts: %d", res.Statements)
	}

	// what this block (or the scope's) states is not repeated; another value
	// is a conflict left alone
	same, _ := ParseIOSSystem("ip domain name lab.example.net\nclock timezone UTC 0\nip name-server 192.0.2.53\n" +
		"ip name-server vrf MGMT 192.0.2.99\nip domain name vrf OTHER other.example.net\n")
	up, _ := ParseIOSSystem("ip domain list example.net\nntp server 192.0.2.123 version 4 key 5 prefer\nntp trusted-key 5\n" +
		"ntp server 192.0.2.77\nip domain list vrf MGMT mgmt.example.net\n")
	res = AdoptIOSSystem(raw, same, up)
	for _, not := range []string{"ip domain name lab", "clock timezone", "ip name-server 192.0.2.53", "ip domain list example.net", "ntp server 192.0.2.123", "ntp trusted-key",
		"ip name-server vrf MGMT 192.0.2.99", "ip domain list vrf MGMT"} {
		if strings.Contains(res.Text, not) {
			t.Errorf("repeated %q:\n%s", not, res.Text)
		}
	}
	if !strings.Contains(res.Text, "ip name-server 192.0.2.54") {
		t.Errorf("the other name server is adopted:\n%s", res.Text)
	}
	// the vrf is part of the identity: the server without one stated above
	// is not the vrf's, and the vrf's other domain name is not this one
	for _, want := range []string{"ntp server vrf MGMT 192.0.2.77", "ip domain name vrf MGMT mgmt.example.net"} {
		if !strings.Contains(res.Text, want) {
			t.Errorf("the draft lacks %q:\n%s", want, res.Text)
		}
	}
	if n := strings.Join(res.Notes, "\n"); !strings.Contains(n, "stated already") || !strings.Contains(n, "differing from what this block states") {
		t.Errorf("notes:\n%s", n)
	}
	// nothing to adopt is no text
	if r := AdoptIOSSystem("ip domain lookup\n", nil, nil); r.Text != "" || r.Statements != 0 {
		t.Errorf("%+v", r)
	}
}

func TestTrapSourceIOS(t *testing.T) {
	b, fs := LintIOSSNMP("snmp-server trap-source Loopback0\nsnmp-server host 192.0.2.5 version 2c comm-a\nsnmp-server enable traps config\n", LayerScope)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	if b.TrapSource == nil || b.TrapSource.Text != "Loopback0" || b.TrapSource.Line != 1 || b.Empty() {
		t.Fatalf("%+v", b.TrapSource)
	}
	// rendered after the hosts, before the trap types
	st := IOSSNMPStatements(b)
	if strings.Join(st, "|") != "snmp-server host 192.0.2.5 version 2c comm-a|snmp-server trap-source Loopback0|snmp-server enable traps config" {
		t.Errorf("order: %q", st)
	}
	// the note at the scope level says the interface is shared; the device
	// level does not; the default layer refuses it
	if !hasFinding(fs, SevNote, 1, "the same source interface for every device of the scope") {
		t.Errorf("scope note:\n%s", dump(fs))
	}
	_, fs = LintIOSSNMP("snmp-server trap-source Loopback0\n", LayerDevice)
	if HasErrors(fs) || hasFinding(fs, SevNote, 1, "every device of the scope") {
		t.Errorf("device layer:\n%s", dump(fs))
	}
	if _, fs = LintIOSSNMP("snmp-server trap-source Loopback0\n", LayerDefault); !hasFinding(fs, SevError, 1, "the default block names no trap source") {
		t.Errorf("default layer:\n%s", dump(fs))
	}
	// resolution: the more specific layer's, whole; a 'no' line takes it out
	scope, _ := ParseIOSSNMP("snmp-server trap-source Loopback0\n")
	dev, _ := ParseIOSSNMP("snmp-server trap-source Loopback7\n")
	if r := ResolveIOSSNMP(nil, scope, dev); r.TrapSource == nil || r.TrapSource.Text != "Loopback7" {
		t.Errorf("device over scope: %+v", r.TrapSource)
	}
	no, fs := ParseIOSSNMP("no snmp-server trap-source\n")
	if HasErrors(fs) || len(no.NotManaged) != 1 || no.NotManaged[0].Kind != IOSNoTrapSource {
		t.Fatalf("%+v %v", no, fs)
	}
	if r := ResolveIOSSNMP(nil, scope, no); r.TrapSource != nil {
		t.Errorf("no line: %+v", r.TrapSource)
	}
	// a no line that names another interface leaves the scope's
	noOther, _ := ParseIOSSNMP("no snmp-server trap-source Loopback9\n")
	if r := ResolveIOSSNMP(nil, scope, noOther); r.TrapSource == nil {
		t.Error("a no line of another interface took it out")
	}
	// the text is stable, the 'no' line included
	two, _ := ParseIOSSNMP("snmp-server trap-source Loopback0\nno snmp-server community x1\n")
	if two.String(false) != "snmp-server trap-source Loopback0\nno snmp-server community x1\n" {
		t.Errorf("%q", two.String(false))
	}
	if ElideIOSSNMP(b).TrapSource == nil || ElideIOSSNMP(b).TrapSource.Text != "Loopback0" {
		t.Error("the trap source is no secret")
	}
	// adopt: a device's own, or what the block holds already
	res := AdoptIOSSNMP("snmp-server trap-source Loopback0\n", AdoptOwn{}, nil, nil)
	if res.Text != "snmp-server trap-source Loopback0\n" {
		t.Errorf("adopt: %q", res.Text)
	}
	res = AdoptIOSSNMP("snmp-server trap-source loopback0\n", AdoptOwn{}, scope, nil)
	if res.Text != "" {
		t.Errorf("adopt a repeat: %q", res.Text)
	}
	res = AdoptIOSSNMP("snmp-server trap-source Loopback1\n", AdoptOwn{}, scope, nil)
	if res.Text != "" || !strings.Contains(strings.Join(res.Notes, "\n"), "differing") && !strings.Contains(strings.Join(res.Notes, "\n"), "already with other statements") {
		t.Errorf("adopt a conflict: %q %v", res.Text, res.Notes)
	}
}

func TestInterfaceProblem(t *testing.T) {
	for _, ok := range []string{"Loopback0", "GigabitEthernet0/0/1", "Vlan10", "Port-channel1", "Tunnel0.5", "mgmt0", "TenGigabitEthernet1/1/1"} {
		if why := InterfaceProblem(ok); why != "" {
			t.Errorf("%s: %s", ok, why)
		}
	}
	for _, bad := range []string{"", "Lo0", "lo0", "Gi0/1", "Te1/1", "Fa0/1", "Eth1", "Vl10", "Po1", "Loopback", "0/1", "Loop back0", "Loopback0;", "Loop?0"} {
		if why := InterfaceProblem(bad); why == "" {
			t.Errorf("%q is accepted", bad)
		} else if strings.Contains(why, bad) && bad != "" && bad != "Lo0" && bad != "Loopback" {
			// the examples the reasons give (Loopback0, not Lo0) are no
			// input of the person's
			t.Errorf("the reason holds the input %q: %s", bad, why)
		}
	}
}

func TestTrapSourceJunos(t *testing.T) {
	b, fs := Lint("set snmp trap-options source-address 192.0.2.7\nset snmp trap-options agent-address outgoing-interface\n", LayerScope)
	if HasErrors(fs) || len(b.TrapOptions) != 2 || b.TrapOptions[0].Leaf != "source-address" || b.TrapOptions[0].Args[0] != "192.0.2.7" {
		t.Fatalf("%+v %v", b, fs)
	}
	if st := Statements(b); st[0] != "set snmp trap-options source-address 192.0.2.7" {
		t.Errorf("%q", st)
	}
	if !hasFinding(fs, SevNote, 1, "the same source address for every device of the scope") {
		t.Errorf("scope note:\n%s", dump(fs))
	}
	for _, ok := range []string{"lo0", "2001:db8::7"} {
		b, fs := Lint("set snmp trap-options source-address "+ok+"\n", LayerDevice)
		if HasErrors(fs) || hasFinding(fs, SevNote, 1, "every device of the scope") || len(b.TrapOptions) != 1 {
			t.Errorf("%s: %v", ok, fs)
		}
	}
	if _, fs := Lint("set snmp trap-options source-address 192.0.2.7\n", LayerDefault); !hasFinding(fs, SevError, 1, "the default block names no address") {
		t.Errorf("default layer:\n%s", dump(fs))
	}
	// resolution replaces the leaf whole; a delete line takes it out
	scope, _ := Parse("set snmp trap-options source-address 192.0.2.7\n")
	dev, _ := Parse("set snmp trap-options source-address lo0\n")
	if r := Resolve(nil, scope, dev); len(r.TrapOptions) != 1 || r.TrapOptions[0].Args[0] != "lo0" {
		t.Errorf("device over scope: %+v", r.TrapOptions)
	}
	del, fs := Parse("delete snmp trap-options source-address\n")
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	if r := Resolve(nil, scope, del); len(r.TrapOptions) != 0 {
		t.Errorf("delete: %+v", r.TrapOptions)
	}
	// the template and the grammar say so
	if !strings.Contains(Template(BlockSNMP, LayerScope), "trap-options source-address <address>|lo0") {
		t.Error("template")
	}
}

// The vrf forms: each is an object of its own vrf, rendered as typed, and the
// same value without the vrf is another statement.
func TestIOSSystemVRFForms(t *testing.T) {
	text := "ip domain name lab.example.net\n" +
		"ip domain name vrf MGMT Mgmt.Example.Net\n" +
		"ip domain name vrf OOB.v-1_x oob.example.net\n" +
		"ip domain list example.net\n" +
		"ip domain list vrf MGMT example.net\n" +
		"ip domain-list vrf MGMT b.example.net\n" +
		"ip name-server 192.0.2.53\n" +
		"ip name-server vrf MGMT 192.0.2.53 192.0.2.54\n" +
		"ip name-server vrf OOB.v-1_x 192.0.2.53\n" +
		"ntp server 192.0.2.123 prefer\n" +
		"ntp server vrf MGMT 192.0.2.123 prefer version 3 key 5 source Loopback0\n" +
		"ntp server vrf OOB.v-1_x 192.0.2.123\n" +
		"ntp authentication-key 5 md5 " + iosKey + "\n" +
		"ntp trusted-key 5\n"
	b, fs := LintIOSSystem(text, LayerScope)
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	if len(b.VRFDomainNames) != 2 || b.VRFDomainNames[0].VRF != "MGMT" || b.VRFDomainNames[0].Text != "mgmt.example.net" ||
		b.DomainName == nil || b.DomainName.Text != "lab.example.net" {
		t.Errorf("domain names: %+v %+v", b.DomainName, b.VRFDomainNames)
	}
	if len(b.DomainList) != 1 || len(b.VRFDomainList) != 2 || len(b.NameServers) != 1 || len(b.VRFNameServers) != 3 || len(b.NTPServers) != 3 {
		t.Errorf("lists: %+v", b)
	}
	if s := b.NTPServers[1]; s.VRF != "MGMT" || s.Host != "192.0.2.123" ||
		s.Text() != "ntp server vrf MGMT 192.0.2.123 version 3 key 5 source Loopback0 prefer" {
		t.Errorf("vrf server: %+v %q", s, s.Text())
	}
	want := []string{
		"ip domain name lab.example.net",
		"ip domain name vrf MGMT mgmt.example.net",
		"ip domain name vrf OOB.v-1_x oob.example.net",
		"ip domain list example.net",
		"ip domain list vrf MGMT example.net",
		"ip domain list vrf MGMT b.example.net",
		"ip name-server 192.0.2.53",
		"ip name-server vrf MGMT 192.0.2.53",
		"ip name-server vrf MGMT 192.0.2.54",
		"ip name-server vrf OOB.v-1_x 192.0.2.53",
		"ntp authentication-key 5 md5 " + iosKey,
		"ntp trusted-key 5",
		"ntp server 192.0.2.123 prefer",
		"ntp server vrf MGMT 192.0.2.123 version 3 key 5 source Loopback0 prefer",
		"ntp server vrf OOB.v-1_x 192.0.2.123",
	}
	if got := IOSSystemStatements(b); !slices.Equal(got, want) {
		t.Errorf("statements:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// the canonical text reads back as the same block
	again, fs := ParseIOSSystem(b.String(false))
	if HasErrors(fs) || again.String(false) != b.String(false) {
		t.Errorf("round trip: %v\n%s", fs, b.String(false))
	}
	// one note per vrf, at its first statement
	notes := 0
	_, all := LintIOSSystem(text, LayerScope)
	for _, f := range all {
		if f.Severity == SevNote && strings.Contains(f.Text, "must exist on the device") {
			notes++
		}
	}
	if notes != 2 {
		t.Errorf("vrf notes: %d\n%s", notes, dump(all))
	}
	// a vrf alone is a statement: the block is not empty
	if only, _ := ParseIOSSystem("ip name-server vrf MGMT 192.0.2.53\n"); only.Empty() {
		t.Error("a vrf name server is no statement")
	}
	if only, _ := ParseIOSSystem("no ntp server vrf MGMT\n"); only.Empty() {
		t.Error("a no line is no statement")
	}

	// elided: the key string only
	if el := b.String(true); strings.Contains(el, iosKey) || !strings.Contains(el, "ntp server vrf MGMT 192.0.2.123") {
		t.Errorf("elided:\n%s", el)
	}
}

// A more specific layer's statement replaces the less specific one of the
// same vrf only, and a no line names the vrf it takes out.
func TestIOSSystemVRFResolve(t *testing.T) {
	scope, fs := ParseIOSSystem("ip domain name vrf MGMT a.example.net\nip domain name vrf OOB o.example.net\nip domain name s.example.net\n" +
		"ip domain list vrf MGMT x.example.net\nip domain list vrf MGMT y.example.net\nip domain list x.example.net\n" +
		"ip name-server 192.0.2.1\nip name-server vrf MGMT 192.0.2.1 192.0.2.2\n" +
		"ntp server 192.0.2.9\nntp server vrf MGMT 192.0.2.9 prefer\nntp server vrf OOB 192.0.2.9\n")
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	dev, fs := ParseIOSSystem("ip domain name vrf MGMT b.example.net\nntp server vrf MGMT 192.0.2.9 version 4\n" +
		"no ip domain name vrf OOB\nno ip domain list vrf MGMT y.example.net\nno ip name-server vrf MGMT 192.0.2.2\nno ntp server vrf OOB 192.0.2.9\n")
	if HasErrors(fs) {
		t.Fatal(dump(fs))
	}
	r := ResolveIOSSystem(nil, scope, dev)
	got := strings.Join(IOSSystemStatements(r), "\n")
	want := strings.Join([]string{
		"ip domain name s.example.net",
		"ip domain name vrf MGMT b.example.net",
		"ip domain list x.example.net",
		"ip domain list vrf MGMT x.example.net",
		"ip name-server 192.0.2.1",
		"ip name-server vrf MGMT 192.0.2.1",
		"ntp server 192.0.2.9",
		"ntp server vrf MGMT 192.0.2.9 version 4",
	}, "\n")
	if got != want {
		t.Errorf("resolved:\n%s\nwant:\n%s", got, want)
	}
	if lines := IOSSystemNotManagedLines(r); len(lines) != 4 || lines[0] != "no ip domain name vrf OOB" || lines[3] != "no ntp server vrf OOB 192.0.2.9" {
		t.Errorf("no lines: %q", lines)
	}
	// a no line without the vrf takes the objects without one out, never the
	// vrf's
	plain, _ := ParseIOSSystem("no ip domain name\nno ip domain list\nno ip name-server\nno ntp server 192.0.2.9\n")
	r = ResolveIOSSystem(nil, scope, plain)
	got = strings.Join(IOSSystemStatements(r), "\n")
	for _, w := range []string{"ip domain name vrf MGMT a.example.net", "ip domain list vrf MGMT x.example.net", "ip name-server vrf MGMT 192.0.2.2", "ntp server vrf MGMT 192.0.2.9 prefer"} {
		if !strings.Contains(got, w) {
			t.Errorf("the no line without a vrf took out %q:\n%s", w, got)
		}
	}
	for _, w := range []string{"ip domain name s.example.net", "ip name-server 192.0.2.1\n", "ntp server 192.0.2.9\n"} {
		if strings.Contains(got+"\n", w) {
			t.Errorf("the no line kept %q:\n%s", w, got)
		}
	}
	// the whole list of one vrf, and 'no ntp' everything
	wholeVRF, _ := ParseIOSSystem("no ip domain list vrf MGMT\nno ip name-server vrf MGMT\nno ntp server vrf MGMT\n")
	r = ResolveIOSSystem(nil, scope, wholeVRF)
	got = strings.Join(IOSSystemStatements(r), "\n")
	if strings.Contains(got, "vrf MGMT x.example.net") || strings.Contains(got, "name-server vrf") || strings.Contains(got, "ntp server vrf MGMT") ||
		!strings.Contains(got, "ip domain list x.example.net") || !strings.Contains(got, "ip name-server 192.0.2.1") || !strings.Contains(got, "ntp server vrf OOB 192.0.2.9") {
		t.Errorf("no lines of a vrf:\n%s", got)
	}
	noNTP, _ := ParseIOSSystem("no ntp\n")
	if r = ResolveIOSSystem(nil, scope, noNTP); strings.Contains(strings.Join(IOSSystemStatements(r), "\n"), "ntp server") {
		t.Error("no ntp left a server")
	}
}
