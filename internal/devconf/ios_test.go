package devconf

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// ciscoStems are the canonical statements of lines.
func ciscoStems(lines ...string) []string {
	var out []string
	for _, x := range uniq(ciscoCanon(lines, nil)) {
		out = append(out, x.stem)
	}
	return out
}

func TestCiscoCanon(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want []string
	}{
		{"submode joined", []string{"tacacs server TACACS", "  address ipv4 192.0.2.10", "  timeout 5", "aaa new-model"},
			[]string{"tacacs server TACACS > address ipv4 192.0.2.10", "tacacs server TACACS > timeout 5", "aaa new-model"}},
		{"one space indent", []string{"aaa group server tacacs+ G", " server name TACACS", "!", "line vty 0 4", " transport input ssh"},
			[]string{"aaa group server tacacs+ G > server name TACACS", "line vty 0 4 > transport input ssh"}},
		{"comments exit end", []string{"! a note", "", "interface Gi0/1", " description x", " exit", "end"},
			[]string{"interface Gi0/1 > description x"}},
		{"empty submode is a statement", []string{"line con 0", "line vty 0 4", " login local"},
			[]string{"line con 0", "line vty 0 4 > login local"}},
		{"vty ranges merged", []string{"line vty 0 4", " access-class A in", "line vty 5 15", " access-class A in"},
			[]string{"line vty 0 15 > access-class A in"}},
		{"vty partial", []string{"line vty 0 4", " access-class A in", " transport input ssh", "line vty 5 15", " transport input ssh"},
			[]string{"line vty 0 4 > access-class A in", "line vty 0 15 > transport input ssh"}},
		{"vty single and gap", []string{"line vty 0", " x", "line vty 2 3", " x"},
			[]string{"line vty 0 0 > x", "line vty 2 3 > x"}},
		{"acl entries", []string{"ip access-list standard A", " 10 permit host 192.0.2.1", " 20 permit 192.0.2.2 0.0.0.0", " permit 198.51.100.0 0.0.0.255", " remark x", " deny   any log"},
			[]string{"ip access-list standard A > permit 192.0.2.1", "ip access-list standard A > permit 192.0.2.2",
				"ip access-list standard A > permit 198.51.100.0 0.0.0.255", "ip access-list standard A > deny any log"}},
		{"extended acl entry kept", []string{"ip access-list extended B", " 10 permit tcp host 192.0.2.1 any eq 22"},
			[]string{"ip access-list extended B > permit tcp host 192.0.2.1 any eq 22"}},
		{"numbered acl", []string{"access-list 10 permit host 192.0.2.1", "access-list 10 remark x", "access-list 120 permit ip any any"},
			[]string{"access-list 10 permit 192.0.2.1", "access-list 120 permit ip any any"}},
		{"banner skipped", []string{"banner motd ^C", "aaa new-model fake", "^C", "aaa new-model"},
			[]string{"aaa new-model"}},
		{"one line banner", []string{"banner login ^CHello^C", "aaa new-model"}, []string{"aaa new-model"}},
		{"key type", []string{"tacacs server T", " key 7 0822455D0A16", "tacacs server U", " key 6 ABCDEF", "tacacs server V", " key plain"},
			[]string{"tacacs server T > key", "tacacs server U > key", "tacacs server V > key"}},
		{"legacy host key", []string{"tacacs-server host 192.0.2.10 single-connection timeout 5 key 7 0822455D0A16"},
			[]string{"tacacs-server host 192.0.2.10 single-connection timeout 5 key"}},
		{"username", []string{"username a privilege 15 secret 9 $9$abc", "username b privilege 7 algorithm-type scrypt secret $9$abc", "username c password 7 0822", "username d privilege 1 secret 5 $1$x$y"},
			[]string{"username a privilege 15 secret", "username b privilege 7 secret", "username c password", "username d privilege 1 secret"}},
		{"enable", []string{"enable secret 9 $9$abc", "enable secret level 7 5 $1$x$y", "enable password 7 0822"},
			[]string{"enable secret", "enable secret level 7", "enable password"}},
		{"snmp community", []string{"snmp-server community private RO ACL"}, []string{"snmp-server community <secret> RO ACL"}},
		{"snmp v3 user", []string{"snmp-server user u G v3 auth sha pw1 priv aes 128 pw2 access ACL", "snmp-server user v G v3 auth sha256 pw1"},
			[]string{"snmp-server user u G v3 auth sha <secret> priv aes 128 <secret> access ACL", "snmp-server user v G v3 auth sha256"}},
		{"snmp text kept", []string{"snmp-server location Rack 4, DC1"}, []string{"snmp-server location Rack 4, DC1"}},
		{"hash anywhere", []string{"some-command with $9$abcdef trailing"}, []string{"some-command with <secret> trailing"}},
		{"path form read again", []string{"tacacs server T > address ipv4 192.0.2.10", "line vty 0 15 > access-class A in"},
			[]string{"tacacs server T > address ipv4 192.0.2.10", "line vty 0 15 > access-class A in"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ciscoStems(tc.in...)
			if !slices.Equal(got, tc.want) {
				t.Errorf("got\n %q\nwant\n %q", got, tc.want)
			}
			// canonical statements are a fixed point
			if again := ciscoStems(got...); !slices.Equal(again, got) {
				t.Errorf("not a fixed point: %q", again)
			}
		})
	}
}

// A secret's value never reaches a stem, nor survives a second pass.
func TestCiscoSecretValuesNeverInStem(t *testing.T) {
	for _, l := range []string{
		"tacacs server T", " key 7 0822455D0A16", " key 0 sekrit-value", " key sekrit-value",
		"username a privilege 15 secret 9 $9$abcdefghij", "enable secret 5 $1$salt$hashhashhash",
		"snmp-server user u G v3 auth sha sekrit-auth priv aes 128 sekrit-priv",
		"snmp-server community sekrit-community RO",
	} {
		for _, x := range ciscoCanon([]string{l}, nil) {
			if strings.Contains(x.stem, "sekrit") || strings.Contains(x.stem, "$") || strings.Contains(x.stem, "0822") {
				t.Errorf("%q: stem %q holds a value", l, x.stem)
			}
		}
	}
	// The same through Normalise of a marked, keyword-less line.
	n, err := Normalise("ios", devices.Section{Lines: []string{"some thing sekrit"}, Secret: []bool{true}})
	if err != nil || !slices.Equal(n.Lines, []string{"some thing <secret>"}) || !n.Secret[0] {
		t.Errorf("%q %v %v", n.Lines, n.Secret, err)
	}
}

func TestCiscoExtractReferenceTexts(t *testing.T) {
	cases := []struct {
		dir, family string
		wantStates  map[string]State
	}{
		{"ios/reference-lab", "ios", map[string]State{SectionAAA: StateDiffers, SectionRoles: StateOK, SectionMgmtACL: StateOK,
			SectionSNMP: StateDiffers, SectionNetconf: StateNA, SectionBreakGlass: StateDiffers}},
		{"ios/reference-12x", "ios", map[string]State{SectionAAA: StateOK, SectionRoles: StateOK, SectionMgmtACL: StateOK,
			SectionSNMP: StateOK, SectionNetconf: StateNA, SectionBreakGlass: StateOK}},
		// roles: 'monitor capture' and 'clear mac address-table dynamic' are
		// not stored by this image (a permanent '-'); the lines it stores
		// instead are not extra, the rest is the stored form of what was typed.
		{"ios/real-12.4-7200", "ios", map[string]State{SectionAAA: StateOK, SectionRoles: StateDiffers, SectionMgmtACL: StateOK,
			SectionSNMP: StateOK, SectionNetconf: StateNA, SectionBreakGlass: StateOK}},
		{"ios-xe/reference-16", "ios", map[string]State{SectionAAA: StateDiffers, SectionRoles: StateOK, SectionMgmtACL: StateOK,
			SectionSNMP: StateOK, SectionNetconf: StateNA, SectionBreakGlass: StateOK}},
	}
	for _, c := range cases {
		t.Run(c.dir, func(t *testing.T) {
			expected := expectedSections(t, c.dir+"/expected.txt")
			for _, hinted := range []bool{true, false} {
				var hint []devices.Section
				if hinted {
					hint = expected
				}
				ex, err := Extract(c.family, capture(t, c.dir+"/running-config.txt"), hint...)
				if err != nil {
					t.Fatal(err)
				}
				if !ex.SecretsVisible || ex.Vendor != FamilyIOS {
					t.Errorf("visible %v, vendor %q", ex.SecretsVisible, ex.Vendor)
				}
				results, err := CompareAll(expected, ex)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range results {
					if c.wantStates[r.Name] != r.State {
						t.Errorf("hinted=%v [%s] %s, want %s", hinted, r.Name, r.State, c.wantStates[r.Name])
					}
				}
				text := resultText(ex, results)
				if hinted {
					golden(t, c.dir+"/result.golden", text)
				}
				for _, leak := range []string{"lab-secret", "$9$", "$1$", "0822455D0A16", "EXAMPLEKEY", "<TYPE9-HASH>", "<HASH>", "notarealsecret",
					"example-community", "other-example", "example-trap-community", "lab-ro-community"} {
					if strings.Contains(text, leak) {
						t.Errorf("the comparison holds %q", leak)
					}
				}
			}
		})
	}
}

// What IOS prints beside the lines that were typed (the lab 7200, 12.4):
// the stored form of a privilege command the image does not know to the
// end, and the queue length beside the first community.
func TestCiscoImplicitLines(t *testing.T) {
	roles := func(dev ...string) []string {
		got := []string{"privilege exec all level 7 monitor capture", "privilege exec level 7 clear counters"}
		return append(got, dev...)
	}
	for _, tc := range []struct {
		name     string
		section  string
		exp, dev []string
		want     []string // the result's lines, 'op text'
		state    State
	}{
		{"parent kept as stored", SectionRoles, roles(),
			[]string{"privilege exec level 7 monitor", "privilege exec level 7 clear", "privilege exec level 7 clear counters"},
			[]string{"- privilege exec all level 7 monitor capture", "= privilege exec level 7 clear counters"}, StateDiffers},
		{"another level is extra", SectionRoles, roles(),
			[]string{"privilege exec level 15 monitor", "privilege exec level 7 clear counters"},
			[]string{"- privilege exec all level 7 monitor capture", "= privilege exec level 7 clear counters", "+ privilege exec level 15 monitor"}, StateDiffers},
		{"another mode is extra", SectionRoles, roles(),
			[]string{"privilege configure level 7 monitor", "privilege exec level 7 clear counters"},
			[]string{"- privilege exec all level 7 monitor capture", "= privilege exec level 7 clear counters", "+ privilege configure level 7 monitor"}, StateDiffers},
		{"all on the device covers more", SectionRoles, roles(),
			[]string{"privilege exec all level 7 monitor", "privilege exec level 7 clear counters"},
			[]string{"- privilege exec all level 7 monitor capture", "= privilege exec level 7 clear counters", "+ privilege exec all level 7 monitor"}, StateDiffers},
		{"a statement of its own stays", SectionRoles, roles(),
			[]string{"privilege exec level 7 clear counters", "privilege exec level 7 show", "privilege exec all level 7 monitor capture"},
			[]string{"= privilege exec all level 7 monitor capture", "= privilege exec level 7 clear counters", "+ privilege exec level 7 show"}, StateDiffers},
		{"queue length beside the community", SectionSNMP, []string{"snmp-server community c RO ACL"},
			[]string{"snmp-server community zz RO ACL", "snmp-server queue-length 100"},
			[]string{"= snmp-server community <secret> RO ACL (present, not compared)"}, StateOK},
		{"another queue length is extra", SectionSNMP, []string{"snmp-server community c RO ACL"},
			[]string{"snmp-server community zz RO ACL", "snmp-server queue-length 50"},
			[]string{"= snmp-server community <secret> RO ACL (present, not compared)", "+ snmp-server queue-length 50"}, StateDiffers},
		{"queue length without a rendered community", SectionSNMP, []string{"snmp-server location Rack 4"},
			[]string{"snmp-server location Rack 4", "snmp-server queue-length 100"},
			[]string{"= snmp-server location Rack 4", "+ snmp-server queue-length 100"}, StateDiffers},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secret := make([]bool, len(tc.exp))
			for i, l := range tc.exp {
				secret[i] = strings.HasPrefix(l, "snmp-server community ")
			}
			exp := devices.Section{Name: tc.section, Lines: tc.exp, Secret: secret}
			raw := "version 12.4\n" + strings.Join(tc.dev, "\n") + "\n"
			ex, err := Extract("ios", raw, exp)
			if err != nil {
				t.Fatal(err)
			}
			r, err := Compare("ios", exp, ex.Sections[tc.section], true)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, l := range r.Lines {
				got = append(got, string(l.Op)+" "+l.Text)
			}
			slices.Sort(got)
			want := slices.Clone(tc.want)
			slices.Sort(want)
			if !slices.Equal(got, want) || r.State != tc.state {
				t.Errorf("%s\n got  %q\n want %q (%s)", r.State, got, want, tc.state)
			}
			// unhinted extraction, then the same comparison
			ex2, err := Extract("ios", raw)
			if err != nil {
				t.Fatal(err)
			}
			r2, _ := Compare("ios", exp, ex2.Sections[tc.section], true)
			if r2.State != tc.state {
				t.Errorf("unhinted: %s, want %s", r2.State, tc.state)
			}
		})
	}
}

// The stored forms of the lab 7200: a host entry with its mask or without,
// the keyword, trailing blanks and another order of the aaa lines are the
// statements that were typed.
func TestCiscoStoredFormsAreTheTypedOnes(t *testing.T) {
	typed := []string{"aaa authorization exec default local group G if-authenticated", "aaa accounting exec default start-stop group G",
		"ip access-list standard A", " permit 192.0.2.10 0.0.0.0", " permit host 192.0.2.11", " deny any log"}
	stored := []string{"aaa accounting exec default start-stop group G ", "aaa authorization exec default local group G if-authenticated ",
		"ip access-list standard A", " permit 192.0.2.10", " permit 192.0.2.11", " deny   any log"}
	if a, b := ciscoStems(typed...), ciscoStems(stored...); !slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b))) {
		t.Errorf("typed %q\nstored %q", a, b)
	}
	// but a mask on a network is a different statement
	if a, b := ciscoStems(" permit 192.0.2.10 0.0.0.255"), ciscoStems(" permit 192.0.2.10"); slices.Equal(a, b) {
		t.Errorf("a /24 and a host are one: %q", a)
	}
}

func TestCiscoBareDevice(t *testing.T) {
	ex, err := Extract("cisco", capture(t, "ios/reference-bare/running-config.txt"))
	if err != nil {
		t.Fatal(err)
	}
	// 'enable secret' is not a managed statement (Managed renders none):
	// nothing of the device is in a section.
	for n, sec := range ex.Sections {
		if len(sec.Lines) != 0 {
			t.Errorf("[%s] = %q", n, sec.Lines)
		}
	}
	expected := expectedSections(t, "ios/reference-lab/expected.txt")
	results, err := CompareAll(expected, ex)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		want := StateMissing
		if r.Name == SectionNetconf {
			want = StateNA
		}
		if r.State != want {
			t.Errorf("[%s] %s, want %s", r.Name, r.State, want)
		}
	}
}

func TestCiscoExtractErrors(t *testing.T) {
	if _, err := Extract("ios", capture(t, "ios/reference-error/running-config.txt")); !errors.Is(err, ErrParse) {
		t.Errorf("refused command: %v", err)
	}
	for _, raw := range []string{"", "hello\nworld\n"} {
		if _, err := Extract("ios", raw); !errors.Is(err, ErrParse) {
			t.Errorf("%q: %v", raw, err)
		}
	}
}

// The ACL a VTY line names is the management ACL whatever its name, and
// the ACL SNMP names is the SNMP one.
func TestCiscoACLOwnership(t *testing.T) {
	raw := "version 15.2\n" +
		"ip access-list standard OPS-VTY\n permit 192.0.2.1\n" +
		"ip access-list standard OPS-SNMP\n permit 192.0.2.2\n" +
		"ip access-list standard UNRELATED\n permit 192.0.2.3\n" +
		"snmp-server community c RO OPS-SNMP\n" +
		"line vty 0 15\n access-class OPS-VTY in\n"
	ex, err := Extract("ios", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Sections[SectionMgmtACL].Lines; !slices.Equal(got, []string{
		"ip access-list standard OPS-VTY > permit 192.0.2.1", "line vty 0 15 > access-class OPS-VTY in"}) {
		t.Errorf("mgmt-acl = %q", got)
	}
	if got := ex.Sections[SectionSNMP].Lines; !slices.Equal(got, []string{
		"ip access-list standard OPS-SNMP > permit 192.0.2.2", "snmp-server community <secret> RO OPS-SNMP"}) {
		t.Errorf("snmp = %q", got)
	}
}

// The IOS and IOS-XE texts are hand-written from the vendor's references:
// every one says so (plan 7.3) until a user's paste replaces it.
func TestReferenceTextsAreMarked(t *testing.T) {
	for _, rel := range []string{
		"ios/reference-lab/running-config.txt", "ios/reference-lab/expected.txt",
		"ios/reference-bare/running-config.txt", "ios/reference-12x/running-config.txt",
		"ios/reference-12x/expected.txt", "ios/reference-error/running-config.txt",
		"ios-xe/reference-16/running-config.txt", "ios-xe/reference-16/expected.txt",
		"juniper/synthetic-lab/display-set.txt", "juniper/synthetic-lab/display-set-engineer.txt",
	} {
		if got := header(t, rel, "source"); got != "reference" {
			t.Errorf("%s: source = %q, want reference", rel, got)
		}
		if got := header(t, rel, "vendor"); got == "" {
			t.Errorf("%s: no vendor header", rel)
		}
	}
}
