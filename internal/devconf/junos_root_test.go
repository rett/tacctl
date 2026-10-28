package devconf

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

// The root account as a break-glass entry: the pull reads root's password and
// 'system services ssh root-login' into the breakglass section, the comparison
// checks both by presence and value, and no hash or key is ever kept.

const (
	rootHash = "$6$examplesalt$EXAMPLEROOTHASHEXAMPLEROOTHASHEXAMPLEROOTHASH"
	rootKey  = "AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEROOTKEYEXAMPLEROOTKEYEXAMPLEROOT"
	userHash = "$6$examplesalt$EXAMPLEUSERHASHEXAMPLEUSERHASHEXAMPLEUSERHASH"
)

var (
	rootPasswordLine = `set system root-authentication encrypted-password "` + rootHash + `"`
	rootKeyLine      = `set system root-authentication ssh-ed25519 "ssh-ed25519 ` + rootKey + ` alice@example.net"`
	aliceLine        = `set system login user alice class RW-CLASS authentication encrypted-password "` + userHash + `"`
)

// rootExpected is the rendering of a scope that records root (and, with
// named, alice): the statements as the walkthrough prints them.
func rootExpected(named bool) devices.Section {
	s := devices.Section{Name: SectionBreakGlass,
		Lines:  []string{"set system root-authentication encrypted-password '<HASH>'", "set system services ssh root-login allow"},
		Secret: []bool{true, false}}
	if named {
		s.Lines = append(s.Lines, "set system login user alice class RW-CLASS authentication encrypted-password '<HASH>'")
		s.Secret = append(s.Secret, true)
	}
	return s
}

func rootCompare(t *testing.T, named bool, deviceLines ...string) (SectionResult, Extracted) {
	t.Helper()
	exp := rootExpected(named)
	ex, err := Extract("junos", jset(deviceLines...), exp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compare("junos", exp, ex.Sections[SectionBreakGlass], true)
	if err != nil {
		t.Fatal(err)
	}
	return r, ex
}

func rootLines(r SectionResult) []string {
	var out []string
	for _, l := range r.Lines {
		out = append(out, string(l.Op)+" "+l.Text)
	}
	return out
}

func wantNote(t *testing.T, r SectionResult, sub string) {
	t.Helper()
	for _, n := range r.Notes {
		if strings.Contains(n, sub) {
			return
		}
	}
	t.Errorf("no note with %q: %q", sub, r.Notes)
}

func TestJunosRootBothStatementsRead(t *testing.T) {
	r, ex := rootCompare(t, false, rootPasswordLine, "set system services ssh root-login allow", "set system services ssh protocol-version v2")
	if r.State != StateOK {
		t.Errorf("state %s: %q", r.State, rootLines(r))
	}
	got := rootLines(r)
	for _, want := range []string{
		string(OpSame) + " set system root-authentication encrypted-password (present, not compared)",
		string(OpSame) + " set system services ssh root-login allow",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("lacks %q: %q", want, got)
		}
	}
	// every other leaf under system services ssh is the device's own: not in
	// the section
	for _, l := range ex.Sections[SectionBreakGlass].Lines {
		if strings.Contains(l, "protocol-version") {
			t.Errorf("the section holds %q", l)
		}
	}
	// the same text without the rendering's help: read, kept as marks
	plain, err := Extract("junos", jset(rootPasswordLine, "set system services ssh root-login allow"))
	if err != nil {
		t.Fatal(err)
	}
	bg := plain.Sections[SectionBreakGlass]
	if !slices.Equal(bg.Lines, []string{"set system root-authentication encrypted-password", "set system services ssh root-login allow"}) ||
		!slices.Equal(bg.Secret, []bool{true, false}) {
		t.Errorf("without a rendering: %q %v", bg.Lines, bg.Secret)
	}
}

func TestJunosRootPasswordWithoutAllow(t *testing.T) {
	r, _ := rootCompare(t, false, rootPasswordLine)
	if r.State != StateDiffers {
		t.Errorf("state %s", r.State)
	}
	got := rootLines(r)
	if !slices.Contains(got, string(OpMissing)+" set system services ssh root-login allow") || len(got) != 2 {
		t.Errorf("only the allow statement is missing: %q", got)
	}
	wantNote(t, r, "no root-login statement: Junos refuses root over ssh by default")
}

func TestJunosRootAllowWithoutPassword(t *testing.T) {
	r, _ := rootCompare(t, false, "set system services ssh root-login allow")
	if r.State != StateDiffers {
		t.Errorf("state %s", r.State)
	}
	if got := rootLines(r); !slices.Contains(got, string(OpMissing)+" set system root-authentication encrypted-password (not present)") {
		t.Errorf("%q", got)
	}
}

func TestJunosRootLoginDenied(t *testing.T) {
	for _, c := range []struct{ value, note string }{
		{"deny-password", "root-login is deny-password: root cannot log in over ssh with its password, which break-glass needs"},
		{"deny", "root-login is deny: root cannot log in over ssh"},
	} {
		r, _ := rootCompare(t, false, rootPasswordLine, "set system services ssh root-login "+c.value)
		if r.State != StateDiffers {
			t.Errorf("%s: state %s", c.value, r.State)
		}
		got := rootLines(r)
		if !slices.Contains(got, string(OpMissing)+" set system services ssh root-login allow") ||
			!slices.Contains(got, string(OpExtra)+" set system services ssh root-login "+c.value) {
			t.Errorf("%s: %q", c.value, got)
		}
		wantNote(t, r, c.note)
	}
}

func TestJunosRootKeysOnlyIsNoPassword(t *testing.T) {
	r, ex := rootCompare(t, false, rootKeyLine, "set system services ssh root-login allow")
	if r.State != StateDiffers {
		t.Errorf("state %s", r.State)
	}
	got := rootLines(r)
	if !slices.Contains(got, string(OpMissing)+" set system root-authentication encrypted-password (not present)") {
		t.Errorf("%q", got)
	}
	for _, l := range got {
		if strings.Contains(l, "ssh-ed25519") || strings.Contains(l, rootKey) {
			t.Errorf("a key in the comparison: %q", l)
		}
	}
	wantNote(t, r, "root-authentication holds ssh keys only (not compared) and no password")
	// the key is a mark in the record, its text is nowhere
	for _, l := range ex.Sections[SectionBreakGlass].Lines {
		if strings.Contains(l, rootKey) {
			t.Errorf("the section holds the key: %q", l)
		}
	}
	// with a password as well, the keys are no finding
	r, _ = rootCompare(t, false, rootKeyLine, rootPasswordLine, "set system services ssh root-login allow")
	if r.State != StateOK || len(r.Notes) != 0 {
		t.Errorf("password and key: %s %q %q", r.State, rootLines(r), r.Notes)
	}
}

func TestJunosRootAbsentReadsMissing(t *testing.T) {
	r, _ := rootCompare(t, false, "set system host-name jsw1")
	if r.State != StateMissing {
		t.Errorf("state %s: %q", r.State, rootLines(r))
	}
	got := rootLines(r)
	if len(got) != 2 || got[0] != string(OpMissing)+" set system root-authentication encrypted-password (not present)" {
		t.Errorf("%q", got)
	}
}

// A scope that records root and a named user: each is checked on its own.
func TestJunosRootAndANamedUser(t *testing.T) {
	r, _ := rootCompare(t, true, rootPasswordLine, "set system services ssh root-login allow", aliceLine)
	if r.State != StateOK {
		t.Errorf("both present: %s %q", r.State, rootLines(r))
	}
	r, _ = rootCompare(t, true, rootPasswordLine, "set system services ssh root-login allow")
	if r.State != StateDiffers {
		t.Errorf("alice missing: %s", r.State)
	}
	got := rootLines(r)
	if !slices.Contains(got, string(OpMissing)+" set system login user alice class RW-CLASS") ||
		slices.Contains(got, string(OpMissing)+" set system root-authentication encrypted-password (not present)") {
		t.Errorf("only alice is missing: %q", got)
	}
}

// A scope that does not record root is not told about the device's root.
func TestJunosRootNotRecordedIsLeftAlone(t *testing.T) {
	exp := devices.Section{Name: SectionBreakGlass,
		Lines:  []string{"set system login user alice class RW-CLASS authentication encrypted-password '<HASH>'"},
		Secret: []bool{true}}
	ex, err := Extract("junos", jset(aliceLine, rootPasswordLine, rootKeyLine, "set system services ssh root-login allow"), exp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compare("junos", exp, ex.Sections[SectionBreakGlass], true)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateOK || len(r.Notes) != 0 {
		t.Errorf("%s %q %q", r.State, rootLines(r), r.Notes)
	}
	// and with no break-glass statement at all the section is n/a
	none := devices.Section{Name: SectionBreakGlass}
	r, err = Compare("junos", none, ex.Sections[SectionBreakGlass], true)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range r.Lines {
		if strings.Contains(l.Text, "root") {
			t.Errorf("root listed for a scope that does not record it: %q", l.Text)
		}
	}
}

// Neither the hash nor a key reaches the extraction, the stored record, the
// comparison or a plan; the leaf names stay.
func TestJunosRootSecretsNeverKept(t *testing.T) {
	raw := jset(rootPasswordLine, rootKeyLine, "set system services ssh root-login allow", aliceLine,
		`set system root-authentication ssh-rsa "ssh-rsa `+rootKey+`"`,
		"set system root-authentication encrypted-password /* SECRET-DATA */")
	exp := rootExpected(true)
	ex, err := Extract("junos", raw, exp)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compare("junos", exp, ex.Sections[SectionBreakGlass], true)
	if err != nil {
		t.Fatal(err)
	}
	s := newStore(t)
	if err := s.SaveSections("dev", "junos", ex.Sections); err != nil {
		t.Fatal(err)
	}
	disk, err := os.ReadFile(filepath.Join(s.Dir, "dev.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	all.Write(disk)
	all.WriteString(resultText(ex, []SectionResult{r}))
	for _, sec := range ex.Sections {
		all.WriteString(strings.Join(sec.Lines, "\n"))
	}
	for _, n := range r.Notes {
		all.WriteString(n)
	}
	for _, leak := range []string{rootHash, rootKey, "EXAMPLEROOT", userHash, "$6$", "ssh-ed25519 ", "alice@example.net"} {
		if strings.Contains(all.String(), leak) {
			t.Errorf("%q is in what is kept or shown", leak)
		}
	}
	if !strings.Contains(string(disk), "set system root-authentication encrypted-password") {
		t.Errorf("the stored record lacks root's presence mark:\n%s", disk)
	}
	// what is stored compares as what was extracted
	back, err := s.Sections("dev", "junos")
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Compare("junos", exp, back[SectionBreakGlass], true)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rootLines(r), rootLines(r2)) || r.State != r2.State {
		t.Errorf("the stored section compares differently:\n%q\n%q", rootLines(r), rootLines(r2))
	}
}

// A 'deactivate' of the hierarchy changes nothing for a scope that does not
// record root, and is a finding for one that does.
func TestJunosRootDeactivatedHierarchy(t *testing.T) {
	exp := devices.Section{Name: SectionBreakGlass,
		Lines:  []string{"set system login user alice class RW-CLASS authentication encrypted-password '<HASH>'"},
		Secret: []bool{true}}
	for _, line := range []string{"deactivate system root-authentication", "deactivate system root-authentication encrypted-password",
		"deactivate system services ssh root-login"} {
		ex, err := Extract("junos", jset(aliceLine, rootPasswordLine, line), exp)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Compare("junos", exp, ex.Sections[SectionBreakGlass], true)
		if err != nil {
			t.Fatal(err)
		}
		if r.State != StateOK || len(r.Notes) != 0 {
			t.Errorf("%s, root not recorded: %s %q %q", line, r.State, rootLines(r), r.Notes)
		}
	}
	// a scope that records root: the deactivated password is no password
	r, _ := rootCompare(t, false, "deactivate system root-authentication encrypted-password", "set system services ssh root-login allow")
	if r.State != StateDiffers {
		t.Errorf("deactivated password: %s %q", r.State, rootLines(r))
	}
	got := rootLines(r)
	if !slices.Contains(got, string(OpMissing)+" set system root-authentication encrypted-password (not present)") {
		t.Errorf("a deactivated password counts as present: %q", got)
	}
	r, _ = rootCompare(t, false, rootPasswordLine, "set system services ssh root-login allow", "deactivate system root-authentication")
	if r.State != StateDiffers {
		t.Errorf("deactivated hierarchy: %s %q", r.State, rootLines(r))
	}
}

// Only a real ssh key leaf makes the 'keys only' note: a clear-text password
// leaf, a bare hash and a deactivated key do not, and none of them is a
// password.
func TestJunosRootKeysNoteIsForKeysOnly(t *testing.T) {
	for _, c := range []struct {
		name, line string
		note       bool
	}{
		{"ssh-rsa", `set system root-authentication ssh-rsa "ssh-rsa ` + rootKey + `"`, true},
		{"ssh-ecdsa", `set system root-authentication ssh-ecdsa "ecdsa-sha2-nistp256 ` + rootKey + `"`, true},
		{"plain-text-password", `set system root-authentication plain-text-password-value "` + rootHash + `"`, false},
		{"a bare hash", `set system root-authentication "` + rootHash + `"`, false},
		{"deactivated key", `deactivate system root-authentication ssh-ed25519`, false},
	} {
		r, ex := rootCompare(t, false, c.line, "set system services ssh root-login allow")
		has := false
		for _, n := range r.Notes {
			has = has || strings.Contains(n, "holds ssh keys only")
		}
		if has != c.note {
			t.Errorf("%s: keys-only note %v, want %v (%q)", c.name, has, c.note, r.Notes)
		}
		if got := rootLines(r); !slices.Contains(got, string(OpMissing)+" set system root-authentication encrypted-password (not present)") {
			t.Errorf("%s: read as a password: %q", c.name, got)
		}
		for _, l := range ex.Sections[SectionBreakGlass].Lines {
			if strings.Contains(l, rootKey) || strings.Contains(l, rootHash) {
				t.Errorf("%s: a secret in the section: %q", c.name, l)
			}
		}
	}
}

// root-authentication in a configuration group: the statement is the
// device's own (not in a section), and no key or hash survives the stem rule.
func TestJunosRootAuthenticationInAGroupKeepsNoKey(t *testing.T) {
	for _, line := range []string{
		`set groups G system root-authentication ssh-rsa "ssh-rsa ` + rootKey + ` alice@example.net"`,
		`set groups G system root-authentication encrypted-password "` + rootHash + `"`,
		`set groups G system root-authentication "` + rootHash + `"`,
	} {
		for _, x := range junosCanon([]string{line}, nil, nil) {
			if strings.Contains(x.stem, rootKey) || strings.Contains(x.stem, rootHash) || strings.Contains(x.stem, "alice@example.net") {
				t.Errorf("%q: the stem holds a secret: %q", line, x.stem)
			}
		}
		ex, err := Extract("junos", jset("set system host-name jsw1", line), rootExpected(false))
		if err != nil {
			t.Fatal(err)
		}
		for n, sec := range ex.Sections {
			for _, l := range sec.Lines {
				if strings.Contains(l, rootKey) || strings.Contains(l, rootHash) || strings.Contains(l, " G ") {
					t.Errorf("%q: [%s] %q", line, n, l)
				}
			}
		}
	}
}
