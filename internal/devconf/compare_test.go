package devconf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

func sec(name string, lines ...string) devices.Section {
	return devices.Section{Name: name, Lines: lines}
}

func secrets(name string, lines []string, marks ...bool) devices.Section {
	return devices.Section{Name: name, Lines: lines, Secret: marks}
}

func ops(r SectionResult) string {
	var b strings.Builder
	for _, l := range r.Lines {
		b.WriteByte(l.Op)
	}
	return b.String()
}

func TestCompareStates(t *testing.T) {
	const aaa = SectionAAA
	for _, tc := range []struct {
		name     string
		vendor   string
		expected devices.Section
		got      devices.Section
		visible  bool
		state    State
		ops      string
	}{
		{"ok", "junos", sec(aaa, "set a b", "set c d"), sec(aaa, "set c d", "set a b"), true, StateOK, "=="},
		{"ok with expansion", "junos", sec(aaa, "set a [ b c ]"), sec(aaa, "set a b", "set a c"), true, StateOK, "=="},
		{"ok with quotes", "junos", sec(aaa, "set snmp location 'Rack 4'"), sec(aaa, `set snmp location "Rack 4"`), true, StateOK, "="},
		{"differs missing", "junos", sec(aaa, "set a b", "set c d"), sec(aaa, "set a b"), true, StateDiffers, "=-"},
		{"differs extra", "junos", sec(aaa, "set a b"), sec(aaa, "set a b", "set x y"), true, StateDiffers, "=+"},
		{"missing", "junos", sec(aaa, "set a b", "set c d"), sec(aaa), true, StateMissing, "--"},
		{"n/a lists the device's statements", "junos", sec(aaa), sec(aaa, "set a b"), true, StateNA, "~"},
		{"n/a both", "ios", sec(aaa), sec(aaa), true, StateNA, ""},
		{"cisco ok", "ios", sec(aaa, "tacacs server T", "  address ipv4 192.0.2.1", "  timeout 5"),
			sec(aaa, "tacacs server T", " address ipv4 192.0.2.1", " timeout 5"), true, StateOK, "=="},
		{"cisco acl forms", "ios", sec(aaa, "ip access-list standard A", "  permit host 192.0.2.1", "  permit 192.0.2.2 0.0.0.0", "  remark — note", "  deny   any log"),
			sec(aaa, "ip access-list standard A", " 10 permit 192.0.2.1", " 20 permit 192.0.2.2", " deny any log"), true, StateOK, "==="},
		{"cisco vty union", "ios", sec(aaa, "line vty 0 15", "  access-class A in"),
			sec(aaa, "line vty 0 4", " access-class A in", "line vty 5 15", " access-class A in"), true, StateOK, "="},
		{"cisco acl order", "ios", sec(aaa, "ip access-list standard A", " permit 192.0.2.1", " permit 192.0.2.2"),
			sec(aaa, "ip access-list standard A", " permit 192.0.2.2", " permit 192.0.2.1"), true, StateOK, "=="},
		{"secret same", "junos", secrets(aaa, []string{"set system tacplus-server 192.0.2.1 secret clear"}, true),
			sec(aaa, `set system tacplus-server 192.0.2.1 secret "$9$abc"`), true, StateOK, "="},
		{"secret different value is not a difference", "junos", secrets(aaa, []string{"set system tacplus-server 192.0.2.1 secret one"}, true),
			sec(aaa, `set system tacplus-server 192.0.2.1 secret "$9$other"`), true, StateOK, "="},
		{"secret masked", "junos", secrets(aaa, []string{"set system tacplus-server 192.0.2.1 secret clear"}, true),
			sec(aaa, "set system tacplus-server 192.0.2.1 secret /* SECRET-DATA */"), false, StateOK, "="},
		{"secret absent visible", "junos", secrets(aaa, []string{"set a b", "set system tacplus-server 192.0.2.1 secret clear"}, false, true),
			sec(aaa, "set a b"), true, StateDiffers, "=-"},
		{"secret absent not visible", "junos", secrets(aaa, []string{"set a b", "set system tacplus-server 192.0.2.1 secret clear"}, false, true),
			sec(aaa, "set a b"), false, StateOK, "=?"},
		{"secret absent not visible with a difference", "junos", secrets(aaa, []string{"set a b", "set system tacplus-server 192.0.2.1 secret clear"}, false, true),
			sec(aaa, "set a c"), false, StateDiffers, "-?+"},
		{"only secrets, not visible", "junos", secrets(aaa, []string{"set system tacplus-server 192.0.2.1 secret clear"}, true),
			sec(aaa), false, StateNotVisible, "?"},
		{"only secrets, visible", "junos", secrets(aaa, []string{"set system tacplus-server 192.0.2.1 secret clear"}, true),
			sec(aaa), true, StateMissing, "-"},
		{"secret server of another address", "junos", secrets(aaa, []string{"set system tacplus-server 192.0.2.1 secret clear"}, true),
			sec(aaa, `set system tacplus-server 192.0.2.2 secret "$9$x"`), true, StateDiffers, "-+"},
		{"cisco key 7", "ios", secrets(aaa, []string{"tacacs server T", "  key lab-secret"}, false, true),
			sec(aaa, "tacacs server T", " key 7 0822455D0A16"), true, StateOK, "="},
		{"cisco key 6", "ios", secrets(aaa, []string{"tacacs server T", "  key lab-secret"}, false, true),
			sec(aaa, "tacacs server T", " key 6 ABCDEF"), true, StateOK, "="},
		{"cisco secret 9", "ios", secrets(aaa, []string{"username a privilege 15 secret 9 <TYPE9-HASH>"}, true),
			sec(aaa, "username a privilege 15 secret 9 $9$abcdef"), true, StateOK, "="},
		{"junos user split", "junos", secrets(aaa, []string{"set system login user u class RW authentication encrypted-password '<HASH>'"}, true),
			sec(aaa, "set system login user u class RW", `set system login user u authentication encrypted-password "$6$x"`), true, StateOK, "=="},
		{"community by presence", "junos", secrets(aaa, []string{"set snmp community lab-ro authorization read-only"}, true),
			sec(aaa, "set snmp community other-name authorization read-only"), true, StateOK, "="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Compare(tc.vendor, tc.expected, tc.got, tc.visible)
			if err != nil {
				t.Fatal(err)
			}
			if res.State != tc.state {
				t.Errorf("state %s, want %s (%s)", res.State, tc.state, allText([]SectionResult{res}))
			}
			if got := ops(res); got != tc.ops {
				t.Errorf("ops %q, want %q (%s)", got, tc.ops, allText([]SectionResult{res}))
			}
			if res.Name != aaa {
				t.Errorf("name %q", res.Name)
			}
			// No result line holds a value of a secret.
			for _, l := range res.Lines {
				for _, v := range []string{"clear", "lab-secret", "$9$", "$6$", "0822455D0A16", "ABCDEF", "<HASH>", "<TYPE9-HASH>", "other-name", "lab-ro", "one"} {
					if strings.Contains(l.Text, v) && l.Secret {
						t.Errorf("line %q holds %q", l.Text, v)
					}
				}
			}
		})
	}
}

func TestCompareLineTexts(t *testing.T) {
	res, err := Compare("junos",
		secrets(SectionAAA, []string{"set a b", "set system tacplus-server 192.0.2.1 secret clear", "set system tacplus-server 192.0.2.2 secret clear"}, false, true, true),
		sec(SectionAAA, "set a b", `set system tacplus-server 192.0.2.1 secret "$9$x"`, `set system tacplus-server 192.0.2.3 secret "$9$y"`), true)
	if err != nil {
		t.Fatal(err)
	}
	want := []DiffLine{
		{OpSame, "set a b", false},
		{OpSame, "set system tacplus-server 192.0.2.1 secret (present, not compared)", true},
		{OpMissing, "set system tacplus-server 192.0.2.2 secret (not present)", true},
		{OpExtra, "set system tacplus-server 192.0.2.3 secret (present, not compared)", true},
	}
	if !slices.Equal(res.Lines, want) {
		t.Errorf("got %+v\nwant %+v", res.Lines, want)
	}
	nv, _ := Compare("junos", secrets(SectionAAA, []string{"set system tacplus-server 192.0.2.2 secret clear"}, true),
		sec(SectionAAA), false)
	if len(nv.Lines) != 1 || nv.Lines[0].Op != OpNotVisible || nv.NotVisible != 1 ||
		nv.Lines[0].Text != "set system tacplus-server 192.0.2.2 secret (not visible to this login)" {
		t.Errorf("%+v", nv)
	}
}

func TestCompareUnknownVendor(t *testing.T) {
	if _, err := Compare("wti", sec("aaa", "x"), sec("aaa", "x"), true); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("%v", err)
	}
	if _, err := Normalise("wti", sec("aaa")); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("%v", err)
	}
	if _, err := Fingerprint("wti", sec("aaa")); !errors.Is(err, ErrUnsupportedVendor) {
		t.Errorf("%v", err)
	}
}

func TestFamily(t *testing.T) {
	for in, want := range map[string]string{"junos": FamilyJunos, "Juniper": FamilyJunos, "ios": FamilyIOS, "ios-xe": FamilyIOS, "cisco": FamilyIOS} {
		if got, err := Family(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

// Normalise is idempotent and its output holds no value, on every fixture.
func TestNormaliseFixtures(t *testing.T) {
	for _, c := range []struct{ vendor, rel string }{
		{"junos", "juniper/synthetic-lab/expected.txt"},
		{"ios", "ios/reference-lab/expected.txt"},
		{"ios", "ios/reference-12x/expected.txt"},
		{"ios", "ios/real-12.4-7200/expected.txt"},
		{"ios", "ios-xe/reference-16/expected.txt"},
	} {
		for _, s := range expectedSections(t, c.rel) {
			n1, err := Normalise(c.vendor, s)
			if err != nil {
				t.Fatal(err)
			}
			n2, _ := Normalise(c.vendor, n1)
			if !slices.Equal(n1.Lines, n2.Lines) || !slices.Equal(n1.Secret, n2.Secret) {
				t.Errorf("%s [%s]: not idempotent:\n%q\n%q", c.rel, s.Name, n1.Lines, n2.Lines)
			}
			for _, l := range n1.Lines {
				if strings.Contains(l, "lab-secret") || strings.Contains(l, "<HASH>") || strings.Contains(l, "<TYPE9-HASH>") || strings.Contains(l, "lab-ro-community") {
					t.Errorf("%s [%s]: %q holds a secret", c.rel, s.Name, l)
				}
			}
		}
	}
	// The statements extracted from a device read through Normalise again.
	ex, err := Extract("junos", capture(t, "juniper/lab-superuser/display-set.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range ex.Sections {
		n1, _ := Normalise("junos", s)
		n2, _ := Normalise("junos", n1)
		if !slices.Equal(n1.Lines, n2.Lines) {
			t.Errorf("[%s] not idempotent", name)
		}
		for _, l := range n1.Lines {
			if strings.Contains(l, "$6$") || strings.Contains(l, "$9$") || strings.Contains(l, "example-community") {
				t.Errorf("[%s] %q holds a secret", name, l)
			}
		}
	}
}

// The capture of a superuser and of an engineer, against the same expected
// statements: the engineer's missing server secret is not visible, never
// missing; the superuser's is present.
func TestCompareSuperuserAndEngineerCaptures(t *testing.T) {
	expected := []devices.Section{
		{Name: SectionAAA, Lines: []string{
			"set system authentication-order [ password tacplus ]",
			"set system tacplus-server 198.18.0.24 secret clear-server-secret",
			"set system tacplus-server 198.18.0.24 single-connection",
			"set system accounting events [ login change-log interactive-commands ]",
			"set system accounting destination tacplus",
		}, Secret: []bool{false, true, false, false, false}},
		{Name: SectionRoles, Lines: []string{
			"set system login class RW-CLASS permissions all",
			"set system login user RW-CLASS class RW-CLASS",
			"set system login class OP-CLASS permissions [ clear network trace view view-configuration ]",
			"set system login user OP-CLASS class OP-CLASS",
			"set system login class RO-CLASS permissions [ network view view-configuration ]",
			"set system login user RO-CLASS class RO-CLASS",
			"set system login class EN-CLASS permissions [ clear configure firewall firewall-control interface interface-control network reset rollback routing routing-control snmp system system-control trace view view-configuration ]",
			"set system login user EN-CLASS class EN-CLASS",
		}},
		{Name: SectionBreakGlass, Lines: []string{
			"set system login user exampleadmin class RW-CLASS authentication encrypted-password '<HASH>'",
		}, Secret: []bool{true}},
	}
	super, err := Extract("junos", capture(t, "juniper/lab-superuser/display-set.txt"), expected...)
	if err != nil {
		t.Fatal(err)
	}
	eng, err := Extract("junos", capture(t, "juniper/lab-engineer/display-set.txt"), expected...)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompareAll(expected, super)
	if err != nil {
		t.Fatal(err)
	}
	re, err := CompareAll(expected, eng)
	if err != nil {
		t.Fatal(err)
	}
	states := func(rs []SectionResult) map[string]State {
		m := map[string]State{}
		for _, r := range rs {
			m[r.Name] = r.State
		}
		return m
	}
	// The device's key list has other statements under the same hierarchy
	// (the breakglass user's ssh key), so break-glass differs on both.
	wantSuper := map[string]State{SectionAAA: StateOK, SectionRoles: StateOK, SectionMgmtACL: StateNA,
		SectionSNMP: StateNA, SectionNetconf: StateNA, SectionBreakGlass: StateDiffers}
	if got := states(rs); !maps(got, wantSuper) {
		t.Errorf("superuser: %v", got)
	}
	// The same device, an engineer's login: the same states.
	if got := states(re); !maps(got, wantSuper) {
		t.Errorf("engineer: %v", got)
	}
	var aaaS, aaaE SectionResult
	for _, r := range rs {
		if r.Name == SectionAAA {
			aaaS = r
		}
	}
	for _, r := range re {
		if r.Name == SectionAAA {
			aaaE = r
		}
	}
	if aaaS.NotVisible != 0 || ops(aaaS) != "========" {
		t.Errorf("superuser aaa: %q", ops(aaaS))
	}
	if aaaE.NotVisible != 1 || !strings.Contains(ops(aaaE), "?") || strings.Contains(ops(aaaE), "-") {
		t.Errorf("engineer aaa: %q (%d not visible)", ops(aaaE), aaaE.NotVisible)
	}
	// The caller's override: with secrets taken as visible the omitted
	// statement is a real difference.
	eng.SecretsVisible = true
	over, _ := CompareAll(expected, eng)
	for _, r := range over {
		if r.Name == SectionAAA && (r.State != StateDiffers || !strings.Contains(ops(r), "-")) {
			t.Errorf("override: %s %q", r.State, ops(r))
		}
	}
	for _, r := range [][]SectionResult{rs, re, over} {
		txt := allText(r)
		for _, leak := range []string{"clear-server-secret", "$9$EXAMPLE", "$6$examplesalt", "<HASH>", "AAAAC3Nza"} {
			if strings.Contains(txt, leak) {
				t.Errorf("the comparison holds %q", leak)
			}
		}
	}
}

func maps(a, b map[string]State) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestFingerprint(t *testing.T) {
	a, _ := Fingerprint("junos", sec("aaa", "set a b", "set c d"))
	b, _ := Fingerprint("junos", sec("aaa", "set c d", "set a   b"))
	c, _ := Fingerprint("junos", sec("aaa", "set a b", "set c e"))
	d, _ := Fingerprint("junos", sec("aaa", `set x secret "$9$one"`))
	e, _ := Fingerprint("junos", sec("aaa", `set x secret "$9$two"`))
	// A secret's value is not in the fingerprint: another value is the
	// same statement (the superuser's and the engineer's pulls agree).
	if a != b || a == c || d != e || len(a) != 64 {
		t.Errorf("%s %s %s %s %s", a, b, c, d, e)
	}
}

func TestElide(t *testing.T) {
	got, err := Elide("junos", []string{"set system tacplus-server 192.0.2.1 secret clear", "set a [ b c ]"}, []bool{true, false})
	if err != nil || !slices.Equal(got, []string{"set system tacplus-server 192.0.2.1 secret", "set a b", "set a c"}) {
		t.Errorf("%q %v", got, err)
	}
}

// Everything devices.Managed renders, as a device would print it, reads
// back as the same statements: every golden of tests/fixtures/golden
// (managed.<variant>.<scope>.txt, the WP11.3 output) is taken as the
// device's own text, extracted and compared with itself.
func TestManagedGoldensRoundTrip(t *testing.T) {
	files, err := filepath.Glob("../../tests/fixtures/golden/managed.*.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no managed goldens in this tree")
	}
	for _, f := range files {
		base := filepath.Base(f)
		vendor := "ios"
		if strings.HasPrefix(base, "managed.juniper") {
			vendor = "junos"
		}
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var expected []devices.Section
		var text []string
		if vendor == "ios" {
			text = append(text, "version 15.2")
		}
		var cur *devices.Section
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
				text = append(text, l[2:])
			}
		}
		ex, err := Extract(vendor, strings.Join(text, "\n"), expected...)
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
			if r.State != want {
				t.Errorf("%s [%s] %s, want %s:\n%s", base, r.Name, r.State, want, allText([]SectionResult{r}))
			}
		}
		// and nothing of the walkthrough's secrets is in what is shown
		txt := allText(results)
		for _, leak := range []string{"-secret-0123456789abcdef", "<HASH>", "<TYPE9-HASH>", "lab-ro-community", "auth-pass", "priv-pass"} {
			if strings.Contains(txt, leak) {
				t.Errorf("%s: the comparison holds %q", base, leak)
			}
		}
	}
}
