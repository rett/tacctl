package devconf

// The system section (0.2.7): the login message is compared by its body (the
// device's \n-escaped string and the block's heredoc are one body) and never
// kept; host names compare in lower case; a key is compared by its number;
// an NTP server with options is its statements one by one; and a section
// that the rendering does not have is not extracted at all.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devices"
)

// systemRendering is the section a block's text renders, as Managed has it.
func systemRendering(t *testing.T, text string) devices.Section {
	t.Helper()
	b, fs := blocks.LintSystem(text, blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	st := blocks.SystemStatements(blocks.ResolveSystem(nil, b, nil))
	sec := devices.Section{Name: SectionSystem, Lines: st, Secret: make([]bool, len(st)), Block: make([]bool, len(st))}
	for i, l := range st {
		sec.Secret[i] = blocks.IsSecretStatement(l)
		sec.Block[i] = true
	}
	return sec
}

// systemState extracts a device's text against the rendering and compares.
func systemState(t *testing.T, device string, rendering devices.Section) SectionResult {
	t.Helper()
	ex, err := Extract("junos", "set version 25.4R1\nset system host-name example-router\n"+device, rendering)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := CompareAll([]devices.Section{rendering}, ex)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == SectionSystem {
			return r
		}
	}
	t.Fatalf("no system result: %v", rs)
	return SectionResult{}
}

// (e) The message round trip through a pulled device string: whatever the
// body, the device's printing of the statement compares equal to the
// rendering, and a message that differs by one character does not.
func TestSystemMessageRoundTripThroughTheDeviceString(t *testing.T) {
	var long []string
	for i := 0; i < 22; i++ {
		long = append(long, strings.Repeat("=", 56)+" "+strings.Repeat("x", i%3))
	}
	bodies := map[string]string{
		"one line":        "Authorized use only.",
		"leading blanks":  "  *** js1.lab.example.net ***\n    indented",
		"quotes":          `Say "hello" and 'bye'`,
		"backslashes":     `C:\path\n and \\ and a trailing \`,
		"an escape-alike": `a \n b`, // a backslash and an n, not a line break
		"22 lines":        strings.Join(long, "\n"),
		"an empty line":   "first\n\nthird",
		"a word":          "Welcome",
	}
	for name, body := range bodies {
		sec := systemRendering(t, "set system login message <<'EOF'\n"+body+"\nEOF\n")
		if got := sec.Lines[0]; got != blocks.MessageStatement+blocks.DeviceMessage(body) {
			t.Fatalf("%s: the rendered statement %q", name, got)
		}
		// the device prints the message as the one quoted string
		r := systemState(t, "set system login message "+blocks.DeviceMessage(body)+"\n", sec)
		if r.State != StateOK {
			t.Errorf("%s: %s: %v", name, r.State, r.Lines)
		}
		// the compared form holds no word of it
		for _, l := range r.Lines {
			if strings.Contains(l.Text, strings.Fields(body)[0]) && len(strings.Fields(body)[0]) > 3 {
				t.Errorf("%s: a compared line holds the text: %q", name, l.Text)
			}
		}
		// one character more is a difference, and so is a line break for a
		// backslash and an n
		for _, other := range []string{body + "!", strings.Replace(body, "\n", "n", 1), strings.Replace(body, `\n`, "\n", 1)} {
			if other == body {
				continue
			}
			if r := systemState(t, "set system login message "+blocks.DeviceMessage(other)+"\n", sec); r.State != StateDiffers {
				t.Errorf("%s: %q reads %s", name, other, r.State)
			}
		}
	}
	// a device that holds no message: the statement is missing; a quote that
	// is not closed is no message tacctl reads, and still no text is kept
	sec := systemRendering(t, "set system login message <<'EOF'\nhello there\nEOF\n")
	if r := systemState(t, "set system domain-name example.net\n", sec); r.State != StateDiffers && r.State != StateMissing {
		t.Errorf("no message: %s", r.State)
	}
	ex, err := Extract("junos", "set version 1\nset system login message \"unclosed text\\\n", sec)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range ex.Sections[SectionSystem].Lines {
		if strings.Contains(l, "unclosed") {
			t.Errorf("the text is kept: %q", l)
		}
	}
}

// The compared form is stable: reading a stored section again changes
// nothing, for every statement of the section.
func TestSystemStatementsNormaliseToThemselves(t *testing.T) {
	sec := systemRendering(t, "set system login message <<'EOF'\nline \"one\"\n  line \\two\nEOF\n"+
		"set system domain-name Lab.Example.NET\nset system domain-search Lab.Example.NET\nset system time-zone Europe/Berlin\n"+
		"set system name-server 192.0.2.53\nset system ntp server NTP.example.net prefer version 4 key 3 routing-instance mgmt\n"+
		"set system ntp boot-server 192.0.2.123\nset system ntp source-address 192.0.2.250\n"+
		"set system ntp authentication-key 3 type sha1 value ntp-key-0123456789\nset system ntp trusted-key 3\n")
	n, err := Normalise("junos", sec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"", // the message's mark, below
		"set system domain-name lab.example.net",
		"set system domain-search lab.example.net",
		"set system time-zone Europe/Berlin",
		"set system name-server 192.0.2.53",
		"set system ntp server ntp.example.net",
		"set system ntp server ntp.example.net prefer",
		"set system ntp server ntp.example.net version 4",
		"set system ntp server ntp.example.net key 3",
		"set system ntp server ntp.example.net routing-instance mgmt",
		"set system ntp boot-server 192.0.2.123",
		"set system ntp source-address 192.0.2.250",
		"set system ntp authentication-key 3 value",
		"set system ntp trusted-key 3",
	}
	if len(n.Lines) != len(want) {
		t.Fatalf("lines:\n%s", strings.Join(n.Lines, "\n"))
	}
	for i, l := range n.Lines {
		if i == 0 {
			if !strings.HasPrefix(l, `set system login message "<message: 2 lines, 22 characters, id `) {
				t.Errorf("the message mark %q", l)
			}
			continue
		}
		if l != want[i] {
			t.Errorf("line %d %q, want %q", i, l, want[i])
		}
	}
	for i, l := range n.Lines {
		if n.Secret[i] != strings.Contains(l, "authentication-key") {
			t.Errorf("%q: secret %v", l, n.Secret[i])
		}
	}
	again, err := Normalise("junos", n)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(again.Lines, n.Lines) || !slices.Equal(again.Secret, n.Secret) {
		t.Errorf("read again:\n%v\n%v", again.Lines, n.Lines)
	}
	// no key value anywhere
	for _, l := range n.Lines {
		if strings.Contains(l, "ntp-key") {
			t.Errorf("the key value is in %q", l)
		}
	}
}

// The device prints one statement per leaf, in its own order and case: all
// of it reads as the block says.
func TestSystemDeviceTextReadsAsTheBlockSays(t *testing.T) {
	sec := systemRendering(t, "set system domain-name lab.example.net\nset system domain-search lab.example.net\n"+
		"set system name-server 192.0.2.53\nset system time-zone UTC\n"+
		"set system ntp server 192.0.2.123 prefer version 4 key 1\nset system ntp authentication-key 1 type md5 value ntp-key-0123456789\n"+
		"set system ntp trusted-key 1\n")
	device := `set system domain-name LAB.example.net
set system domain-search lab.EXAMPLE.net
set system time-zone UTC
set system name-server 192.0.2.53
set system ntp authentication-key 1 type md5
set system ntp authentication-key 1 value "$9$EXAMPLEKEYEXAMPLE"
set system ntp trusted-key 1
set system ntp server 192.0.2.123 key 1
set system ntp server 192.0.2.123 version 4
set system ntp server 192.0.2.123 prefer
`
	r := systemState(t, device, sec)
	if r.State != StateOK || r.Unmanaged != 0 {
		t.Errorf("%s %d: %v", r.State, r.Unmanaged, r.Lines)
	}
	// the key's type is not compared; its value is never in a line
	r = systemState(t, strings.Replace(device, "1 type md5", "1 type sha1", 1), sec)
	if r.State != StateOK {
		t.Errorf("another key type: %s %v", r.State, r.Lines)
	}
	for _, l := range r.Lines {
		if strings.Contains(l.Text, "EXAMPLEKEY") {
			t.Errorf("the value is in %q", l.Text)
		}
	}
	// a key of another number is no key of this one
	r = systemState(t, strings.ReplaceAll(device, "authentication-key 1", "authentication-key 2"), sec)
	if r.State != StateDiffers {
		t.Errorf("another key number: %s", r.State)
	}
	// the server without its options: the options are missing
	r = systemState(t, strings.ReplaceAll(device, "set system ntp server 192.0.2.123 prefer\n", ""), sec)
	if r.State != StateDiffers {
		t.Errorf("no prefer: %s", r.State)
	}
}

// A section the rendering does not have is not extracted, not compared and
// not in the results: the device's own login message, domain and NTP are no
// business of a scope with no system block.
func TestSystemSectionOnlyWhereRendered(t *testing.T) {
	device := "set version 25.4R1\nset system host-name example-router\nset system domain-name example.net\nset system ntp server 192.0.2.123\n" +
		"set system login message \"hello\"\nset system time-zone UTC\n"
	ex, err := Extract("junos", device)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := ex.Sections[SectionSystem]; ok {
		t.Errorf("a system section with no rendering: %v", s)
	}
	for n, s := range ex.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, "ntp") || strings.Contains(l, "domain-name") || strings.Contains(l, "login message") || strings.Contains(l, "time-zone") {
				t.Errorf("[%s] holds %q", n, l)
			}
		}
	}
	rs, err := CompareAll(nil, ex)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == SectionSystem {
			t.Errorf("a system result: %+v", r)
		}
	}
	// with a rendering the section is there, even with nothing on the device
	sec := systemRendering(t, "set system time-zone UTC\n")
	ex, err = Extract("junos", "set version 25.4R1\nset system host-name example-router\n", sec)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := ex.Sections[SectionSystem]; !ok || len(s.Lines) != 0 {
		t.Errorf("the section: %v %v", s, ok)
	}
	// an IOS device has the section where an IOS rendering has it, and none
	// otherwise (a Junos rendering is no IOS system section's)
	ios, err := Extract("ios", "hostname r1\n!\nntp server 192.0.2.123\n")
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := ios.Sections[SectionSystem]; ok {
		t.Errorf("an IOS extraction with no rendering has a system section: %v", s)
	}
	ios, err = Extract("ios", "hostname r1\n!\nntp server 192.0.2.123\n", devices.Section{Name: SectionSystem, Lines: []string{"ip domain name lab.example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := ios.Sections[SectionSystem]; !ok || len(s.Lines) != 1 || s.Lines[0] != "ntp server 192.0.2.123" {
		t.Errorf("an IOS extraction with a rendering: %v %v", s, ok)
	}
}
