package devconf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

func TestTokenizeRender(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`system host-name example`, `system host-name example`},
		{`snmp location "Rack 4, DC1"`, `snmp location "Rack 4, DC1"`},
		{`snmp location 'Rack 4, DC1'`, `snmp location "Rack 4, DC1"`},
		{`snmp contact "NOC <noc@example.net>"`, `snmp contact "NOC <noc@example.net>"`},
		{`snmp contact NOC`, `snmp contact NOC`},
		{`system tacplus-server 192.0.2.10 secret "$9$abc"`, `system tacplus-server 192.0.2.10 secret $9$abc`},
		{`x "a \"quoted\" word"`, `x "a \"quoted\" word"`},
		{`x ""`, `x ""`},
		{`system root-authentication encrypted-password /* SECRET-DATA */`, `system root-authentication encrypted-password /* SECRET-DATA */`},
		{`  a    b  `, `a b`},
	} {
		if got := renderTokens(tokenize(tc.in)); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.in, got, tc.want)
		}
		// canonical text is a fixed point
		if again := renderTokens(tokenize(tc.want)); again != tc.want {
			t.Errorf("%q: canonical form is not stable: %q", tc.want, again)
		}
	}
}

// junosStems are the canonical statements of lines.
func junosStems(lines ...string) []string {
	var out []string
	for _, x := range uniq(junosCanon(lines, nil)) {
		out = append(out, x.stem)
	}
	return out
}

func TestJunosCanon(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"plain", []string{"set system host-name example"}, []string{"set system host-name example"}},
		{"bracket list", []string{"set system authentication-order [ password tacplus ]"},
			[]string{"set system authentication-order password", "set system authentication-order tacplus"}},
		{"two lists", []string{"set a [ b c ] d [ e f ]"},
			[]string{"set a b d e", "set a b d f", "set a c d e", "set a c d f"}},
		{"brace block", []string{"set firewall family inet filter F term deny then { log; discard; }"},
			[]string{"set firewall family inet filter F term deny then log", "set firewall family inet filter F term deny then discard"}},
		{"list under block", []string{"set x { a [ b c ]; d; }"},
			[]string{"set x a b", "set x a c", "set x d"}},
		{"port list", []string{"set firewall family inet filter F term t from destination-port [ ssh 830 ]"},
			[]string{"set firewall family inet filter F term t from destination-port ssh", "set firewall family inet filter F term t from destination-port 830"}},
		{"user split", []string{"set system login user u class RW authentication encrypted-password '<HASH>'"},
			[]string{"set system login user u class RW", "set system login user u authentication encrypted-password"}},
		{"secret value elided", []string{`set system tacplus-server 192.0.2.10 secret "$9$abc"`},
			[]string{"set system tacplus-server 192.0.2.10 secret"}},
		{"secret clear value elided", []string{"set system radius-server 192.0.2.10 secret lab-secret"},
			[]string{"set system radius-server 192.0.2.10 secret"}},
		{"masked", []string{"set system root-authentication encrypted-password /* SECRET-DATA */"},
			[]string{"set system root-authentication encrypted-password"}},
		{"snmp password becomes key", []string{`set snmp v3 usm local-engine user u authentication-sha authentication-password "pw"`},
			[]string{"set snmp v3 usm local-engine user u authentication-sha authentication-key"}},
		{"snmp key as printed", []string{`set snmp v3 usm local-engine user u authentication-sha authentication-key "$9$x"`},
			[]string{"set snmp v3 usm local-engine user u authentication-sha authentication-key"}},
		{"community name", []string{"set snmp community private authorization read-only"},
			[]string{"set snmp community <secret> authorization read-only"}},
		{"deactivate kept", []string{"deactivate system tacplus-server 192.0.2.10"},
			[]string{"deactivate system tacplus-server 192.0.2.10"}},
		{"ignored words", []string{"protect system login class RW", "annotate system \"x\"", "delete system foo", "# comment", "", "{master:0}"}, nil},
		{"duplicates", []string{"set a b", "set a   b", "set a [ b b ]"}, []string{"set a b"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := junosStems(tc.in...); !slices.Equal(got, tc.want) {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// A secret keyword's value never reaches the stem, whatever it looks like.
func TestJunosSecretValuesNeverInStem(t *testing.T) {
	for _, v := range []string{`"$9$abcdef"`, `$6$salt$hash`, `plain-secret`, `/* SECRET-DATA */`, `"has space"`, `"$1$x$y"`} {
		for _, kw := range []string{"secret", "encrypted-password", "authentication-key", "privacy-key"} {
			line := "set system foo bar " + kw + " " + v
			for _, x := range junosCanon([]string{line}, nil) {
				if !x.secret {
					t.Errorf("%q: not taken as secret", line)
				}
				if strings.ContainsAny(x.stem, "$") || strings.Contains(x.stem, "plain-secret") ||
					strings.Contains(x.stem, "SECRET-DATA") || strings.Contains(x.stem, "space") {
					t.Errorf("%q: stem %q holds the value", line, x.stem)
				}
			}
		}
	}
	// A secret that sits after other leaves keeps them.
	got := junosStems(`set system login user u authentication encrypted-password "$6$h" `)
	if !slices.Equal(got, []string{"set system login user u authentication encrypted-password"}) {
		t.Errorf("got %q", got)
	}
	// A marked line with no keyword loses its last word.
	n, err := Normalise("junos", devices.Section{Lines: []string{"set a b value"}, Secret: []bool{true}})
	if err != nil || !slices.Equal(n.Lines, []string{"set a b <secret>"}) {
		t.Errorf("got %q, %v", n.Lines, err)
	}
	// ... and Normalise of that is itself.
	n2, _ := Normalise("junos", n)
	if !slices.Equal(n2.Lines, n.Lines) {
		t.Errorf("not idempotent: %q", n2.Lines)
	}
}

func TestJunosExtractCaptures(t *testing.T) {
	super, err := Extract("junos", capture(t, "juniper/lab-superuser/display-set.txt"))
	if err != nil {
		t.Fatal(err)
	}
	eng, err := Extract("junos", capture(t, "juniper/lab-engineer/display-set.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !super.SecretsVisible {
		t.Error("the superuser view is taken as masked")
	}
	if eng.SecretsVisible {
		t.Error("the engineer view is taken as visible")
	}
	for _, name := range SectionNames {
		if _, ok := super.Sections[name]; !ok {
			t.Errorf("no %s section", name)
		}
	}
	has := func(ex Extracted, section, line string) bool {
		return slices.Contains(ex.Sections[section].Lines, line)
	}
	for _, c := range []struct{ section, line string }{
		{SectionAAA, "set system authentication-order tacplus"},
		{SectionAAA, "set system tacplus-server 198.18.0.24 single-connection"},
		{SectionAAA, "set system accounting destination tacplus"},
		{SectionRoles, "set system login class RW-CLASS permissions all"},
		{SectionRoles, "set system login user EN-CLASS class EN-CLASS"},
		{SectionSNMP, `set snmp location "example location"`},
		{SectionNetconf, "set system services netconf ssh"},
		{SectionBreakGlass, "set system login user exampleadmin class RW-CLASS"},
	} {
		if !has(super, c.section, c.line) || !has(eng, c.section, c.line) {
			t.Errorf("[%s] lacks %q", c.section, c.line)
		}
	}
	// The server's secret exists in the superuser's view only.
	if !has(super, SectionAAA, `set system tacplus-server 198.18.0.24 secret`) {
		t.Error("the superuser view lacks the server's secret")
	}
	for _, l := range eng.Sections[SectionAAA].Lines {
		if strings.Contains(l, " secret") {
			t.Errorf("the engineer view has %q", l)
		}
	}
	// Nothing the device assigns, and nothing outside the hierarchies.
	for _, sec := range super.Sections {
		for _, l := range sec.Lines {
			if strings.Contains(l, " uid ") || strings.HasPrefix(l, "set interfaces") ||
				strings.HasPrefix(l, "set system syslog") || strings.Contains(l, "root-authentication") ||
				strings.Contains(l, "idle-timeout") {
				t.Errorf("[%s] %q is not a managed statement", sec.Name, l)
			}
		}
	}
	// Secret marks: found by keyword, value kept as the device printed it.
	var marked []string
	for i, l := range super.Sections[SectionBreakGlass].Lines {
		if super.Sections[SectionBreakGlass].Secret[i] {
			marked = append(marked, l)
		}
	}
	if len(marked) != 2 {
		t.Errorf("break-glass secrets: %q", marked)
	}
}

func TestJunosSyntheticLab(t *testing.T) {
	expected := expectedSections(t, "juniper/synthetic-lab/expected.txt")
	for _, c := range []struct{ file, golden string }{
		{"display-set.txt", "result.golden"},
		{"display-set-engineer.txt", "result-engineer.golden"},
	} {
		t.Run(c.file, func(t *testing.T) {
			ex, err := Extract("junos", capture(t, "juniper/synthetic-lab/"+c.file), expected...)
			if err != nil {
				t.Fatal(err)
			}
			results, err := CompareAll(expected, ex)
			if err != nil {
				t.Fatal(err)
			}
			text := resultText(ex, results)
			golden(t, "juniper/synthetic-lab/"+c.golden, text)
			for _, leak := range []string{"lab-secret", "$9$", "$6$", "EXAMPLEHASH", "<HASH>", "STRAY", "example-community", "lab-ro-community"} {
				if strings.Contains(text, leak) {
					t.Errorf("the comparison holds %q", leak)
				}
			}
			states := map[string]State{}
			for _, r := range results {
				states[r.Name] = r.State
			}
			want := map[string]State{SectionAAA: StateDiffers, SectionRoles: StateOK, SectionMgmtACL: StateOK,
				SectionSNMP: StateDiffers, SectionNetconf: StateNA, SectionBreakGlass: StateDiffers}
			for n, s := range want {
				if states[n] != s {
					t.Errorf("[%s] %s, want %s", n, states[n], s)
				}
			}
		})
	}
}

// The operator's own classes, filters and users are not strays when the
// rendering names the objects tacctl owns.
func TestJunosHintNarrowsNamedObjects(t *testing.T) {
	raw := capture(t, "juniper/synthetic-lab/display-set.txt")
	expected := expectedSections(t, "juniper/synthetic-lab/expected.txt")
	hinted, err := Extract("junos", raw, expected...)
	if err != nil {
		t.Fatal(err)
	}
	for _, sec := range hinted.Sections {
		for _, l := range sec.Lines {
			if strings.Contains(l, "permissions") && strings.Contains(l, "OPS-NOC") || strings.Contains(l, "PROTECT-RE") {
				t.Errorf("[%s] %q is the operator's", sec.Name, l)
			}
		}
	}
	// A local user is a stray of the user hierarchy and is shown.
	if !slices.Contains(hinted.Sections[SectionBreakGlass].Lines, "set system login user noc-ro class OPS-NOC") {
		t.Error("break-glass lacks the stray user")
	}
	// Without the rendering the classes and users are all kept, the filters
	// are the default's and the applied ones.
	plain, err := Extract("junos", raw)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(plain.Sections[SectionRoles].Lines, "set system login class OPS-NOC permissions view") {
		t.Error("unhinted roles lack the operator's class")
	}
	for _, l := range plain.Sections[SectionMgmtACL].Lines {
		if strings.Contains(l, "PROTECT-RE") {
			t.Errorf("unhinted mgmt-acl holds %q", l)
		}
	}
	if len(plain.Sections[SectionMgmtACL].Lines) == 0 {
		t.Error("unhinted mgmt-acl lacks the default filter")
	}
}

func TestJunosFilterApplication(t *testing.T) {
	raw := "set version 1\n" +
		"set firewall family inet filter MGMT-ACL term t then accept\n" +
		"set firewall family inet filter OTHER term t then accept\n" +
		"set firewall family inet filter PROTECT term t then accept\n" +
		"set interfaces lo0 unit 0 family inet filter input-list [ PROTECT MGMT-ACL ]\n" +
		"set interfaces ge-0/0/0 unit 0 family inet filter input OTHER\n"
	ex, err := Extract("junos", raw)
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Sections[SectionMgmtACL].Lines
	for _, want := range []string{
		"set firewall family inet filter MGMT-ACL term t then accept",
		"set firewall family inet filter PROTECT term t then accept",
		"set interfaces lo0 unit 0 family inet filter input-list PROTECT",
		"set interfaces lo0 unit 0 family inet filter input-list MGMT-ACL",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("lacks %q in %q", want, got)
		}
	}
	for _, l := range got {
		if strings.Contains(l, "OTHER") || strings.Contains(l, "ge-0/0/0") {
			t.Errorf("holds %q", l)
		}
	}
}

func TestJunosDeactivateAndProtect(t *testing.T) {
	raw := "set system tacplus-server 192.0.2.10 single-connection\n" +
		"deactivate system tacplus-server 192.0.2.10\n" +
		"protect system login class RW-CLASS\n" +
		"set system login class RW-CLASS permissions all\n" +
		"annotate system \"managed\"\n"
	ex, err := Extract("junos", raw)
	if err != nil {
		t.Fatal(err)
	}
	aaa := ex.Sections[SectionAAA].Lines
	if !slices.Contains(aaa, "deactivate system tacplus-server 192.0.2.10") || len(aaa) != 2 {
		t.Errorf("aaa = %q", aaa)
	}
	if got := ex.Sections[SectionRoles].Lines; len(got) != 1 {
		t.Errorf("roles = %q", got)
	}
	// A deactivated statement is a difference against a rendering without it.
	res, err := Compare("junos", devices.Section{Name: SectionAAA, Lines: []string{"set system tacplus-server 192.0.2.10 single-connection"}}, ex.Sections[SectionAAA], true)
	if err != nil {
		t.Fatal(err)
	}
	if res.State != StateDiffers || res.Lines[len(res.Lines)-1].Op != OpExtra {
		t.Errorf("%+v", res)
	}
}

func TestJunosExtractErrors(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"empty", ""},
		{"error line", "error: syntax error, expecting <command>\n"},
		{"syntax error", "                  ^\nsyntax error, expecting <command>.\n"},
		{"prose", "Hello\nthis is a banner\n"},
	} {
		if _, err := Extract("junos", tc.raw); !errors.Is(err, ErrParse) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if _, err := Extract("wti", "set a b"); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("wti: %v", err)
	}
}

// Pager remnants, escapes and CRLF line ends do not reach the statements.
func TestJunosExtractCleansText(t *testing.T) {
	raw := "\x1b[?25l{master:0}\r\nset system host-name a\r\n---(more 50%)---\x1b[K\r\n\r\nset system tacplus-server 192.0.2.10 single-connection\r\n"
	ex, err := Extract("junos", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Sections[SectionAAA].Lines; !slices.Equal(got, []string{"set system tacplus-server 192.0.2.10 single-connection"}) {
		t.Errorf("aaa = %q", got)
	}
}
