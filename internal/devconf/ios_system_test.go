package devconf

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devices"
)

// the values of the IOS system fixtures: no compared form, record or report
// may hold one.
const (
	iosSysKey    = "iosntpkey-Zk81"
	iosSysBanner = "IOSBANNER-MARKER-Jt3"
)

// iosSystemRendering is the system section of a rendering made from a block's
// text, as devices.Managed makes it: the lines typed, the keys secret, every
// line the block's.
func iosSystemRendering(t *testing.T, text string) devices.Section {
	t.Helper()
	b, fs := blocks.LintIOSSystem(text, blocks.LayerScope)
	if blocks.HasErrors(fs) {
		t.Fatalf("the block: %v", fs)
	}
	st := blocks.IOSSystemStatements(blocks.ResolveIOSSystem(nil, b, nil))
	sec := devices.Section{Name: SectionSystem, Lines: st, Secret: make([]bool, len(st)), Block: make([]bool, len(st))}
	for i, l := range st {
		sec.Secret[i] = blocks.IsIOSSecretStatement(l)
		sec.Block[i] = true
	}
	return sec
}

// iosSystemState extracts a device's text against the rendering and compares.
func iosSystemState(t *testing.T, device string, rendering devices.Section) SectionResult {
	t.Helper()
	ex, err := Extract("ios", "version 15.2\nhostname r1.example.net\n!\n"+device, rendering)
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

const iosSysBlock = `banner login <<'EOF'
` + iosSysBanner + `
! a second line
EOF
ip domain name lab.example.net
ip domain list lab.example.net
ip domain list example.net
clock timezone CET 1
ip name-server 192.0.2.53
ip name-server 192.0.2.54
ntp authentication-key 5 md5 ` + iosSysKey + `
ntp trusted-key 5
ntp server 192.0.2.123 version 4 key 5 prefer
ntp server ntp2.example.net
ntp authenticate
`

// The device as a person typed it and IOS prints it.
const iosSysDevice = `banner exec ^C
exec text
^C
banner login ^C
` + iosSysBanner + `
! a second line
^C
ip domain name lab.example.net
ip domain list lab.example.net
ip domain list example.net
clock timezone CET 1 0
ip name-server 192.0.2.53 192.0.2.54
ntp authentication-key 5 md5 0822455D0A16 7
ntp authenticate
ntp trusted-key 5
ntp server 192.0.2.123 key 5 prefer version 4
ntp server NTP2.example.net
!
line con 0
`

func TestIOSSystemSectionIsOKWhenTheDeviceHasIt(t *testing.T) {
	sec := iosSystemRendering(t, iosSysBlock)
	r := iosSystemState(t, iosSysDevice, sec)
	if r.State != StateOK || r.Unmanaged != 0 {
		t.Fatalf("%s (+%d): %v", r.State, r.Unmanaged, r.Lines)
	}
	// the compared form holds no word of the banner and no key
	for _, l := range r.Lines {
		if strings.Contains(l.Text, iosSysBanner) || strings.Contains(l.Text, iosSysKey) || strings.Contains(l.Text, "0822455D0A16") ||
			strings.Contains(l.Text, "second line") {
			t.Errorf("a compared line holds a value: %q", l.Text)
		}
	}
	var banner, key bool
	for _, l := range r.Lines {
		banner = banner || strings.HasPrefix(l.Text, "banner login <message: 2 lines, ")
		key = key || l.Text == "ntp authentication-key 5 (present, not compared)" && l.Secret
	}
	if !banner || !key {
		t.Errorf("banner %v key %v: %v", banner, key, r.Lines)
	}
	// the extraction holds none either
	ex, err := Extract("ios", "version 15.2\nhostname r1\n"+iosSysDevice, sec)
	if err != nil {
		t.Fatal(err)
	}
	for n, s := range ex.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, iosSysBanner) || strings.Contains(l, "0822455D0A16") || strings.Contains(l, "second line") {
				t.Errorf("[%s] holds %q", n, l)
			}
		}
	}
	// and a device that prints '^C' or a printable delimiter is the same
	for _, banner := range []string{
		"banner login #\n" + iosSysBanner + "\n! a second line\n#\n",
		"banner login ^C" + iosSysBanner + "\n! a second line\n^C\n",
		"banner login ^C\n" + iosSysBanner + "\n! a second line^C\n",
	} {
		dev := strings.Replace(iosSysDevice, "banner login ^C\n"+iosSysBanner+"\n! a second line\n^C\n", banner, 1)
		if r := iosSystemState(t, dev, sec); r.State != StateOK {
			t.Errorf("%q: %s: %v", banner, r.State, r.Lines)
		}
	}
}

func TestIOSSystemStoredForms(t *testing.T) {
	sec := iosSystemRendering(t, "clock timezone CET 1\nip domain name Lab.Example.Net\nip domain list lab.example.net\n"+
		"ntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\nntp authenticate\n")
	for name, dev := range map[string]string{
		"15.x timezone with minutes":   "clock timezone CET 1 0\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\nntp authenticate\n",
		"12.4 timezone without":        "clock timezone CET 1\nip domain-name lab.example.net\nip domain-list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\nntp authenticate\n",
		"options in another order":     "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 prefer key 5 source Loopback0 version 4\nntp trusted-key 5\nntp authenticate\n",
		"an interface in lower case":   "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 key 5 prefer source loopback0 version 4\nntp trusted-key 5\nntp authenticate\n",
		"a plus sign on the hours":     "clock timezone CET +1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 key 5 prefer source Loopback0 version 4\nntp trusted-key 5\nntp authenticate\n",
		"a host name in capital":       "clock timezone CET 1\nip domain name LAB.EXAMPLE.NET\nip domain list Lab.Example.Net\nntp server 192.0.2.123 key 5 prefer source Loopback0 version 4\nntp trusted-key 5\nntp authenticate\n",
		"the key of its number only":   "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 key 5 prefer source Loopback0 version 4\nntp trusted-key 5\nntp authenticate\nntp authentication-key 9 md5 x 7\n",
		"a vrf form is the device own": "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 key 5 prefer source Loopback0 version 4\nntp trusted-key 5\nntp authenticate\nntp server vrf MGMT 192.0.2.77\nip name-server vrf MGMT 192.0.2.88\nip domain name vrf MGMT other.example.net\n",
	} {
		r := iosSystemState(t, dev, sec)
		if r.State != StateOK {
			t.Errorf("%s: %s: %v", name, r.State, r.Lines)
		}
	}
	// and a difference in a value is a difference
	for name, dev := range map[string]string{
		"another zone":    "clock timezone CET 2\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\nntp authenticate\n",
		"another minutes": "clock timezone CET 1 30\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\nntp authenticate\n",
		"no prefer":       "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0\nntp trusted-key 5\nntp authenticate\n",
		"another source":  "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback1 prefer\nntp trusted-key 5\nntp authenticate\n",
		"no authenticate": "clock timezone CET 1\nip domain name lab.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\n",
		"another domain":  "clock timezone CET 1\nip domain name other.example.net\nip domain list lab.example.net\nntp server 192.0.2.123 version 4 key 5 source Loopback0 prefer\nntp trusted-key 5\nntp authenticate\n",
	} {
		r := iosSystemState(t, dev, sec)
		if r.State != StateDiffers {
			t.Errorf("%s: %s: %v", name, r.State, r.Lines)
		}
	}
}

func TestIOSSystemUnmanagedAndMissing(t *testing.T) {
	sec := iosSystemRendering(t, "ip domain name lab.example.net\nip domain list lab.example.net\nip name-server 192.0.2.53\n"+
		"ntp server 192.0.2.123 prefer\nntp authentication-key 5 md5 "+iosSysKey+"\n")
	// what the device holds beside the block's statements is its own
	dev := "ip domain name lab.example.net\nip domain list lab.example.net\nip domain list example.net\n" +
		"ip name-server 192.0.2.53 198.51.100.53\nntp server 192.0.2.123 prefer\nntp server 198.51.100.123\n" +
		"ntp authentication-key 5 md5 0822 7\nntp authentication-key 6 md5 1234 7\nntp trusted-key 6\nntp master 3\nntp source Loopback0\nntp authenticate\n"
	r := iosSystemState(t, dev, sec)
	if r.State != StateOK || r.Unmanaged != 8 {
		t.Fatalf("%s (+%d): %v", r.State, r.Unmanaged, r.Lines)
	}
	if got := r.StateText(); got != "ok (+8 unmanaged)" {
		t.Errorf("%q", got)
	}
	// a device with none of it
	r = iosSystemState(t, "ntp master 3\n", sec)
	if r.State != StateDiffers && r.State != StateMissing {
		t.Errorf("lacks all: %s", r.State)
	}
	missing := 0
	for _, l := range r.Lines {
		if l.Op == OpMissing {
			missing++
		}
	}
	if missing != 5 {
		t.Errorf("%d missing: %v", missing, r.Lines)
	}
	// a server of the same host with other options is a difference, not the
	// device's own
	r = iosSystemState(t, dev+"ntp server 192.0.2.123 version 3\n", sec)
	_ = r
	r = iosSystemState(t, strings.Replace(dev, "ntp server 192.0.2.123 prefer\n", "ntp server 192.0.2.123 version 3\n", 1), sec)
	if r.State != StateDiffers {
		t.Errorf("a server with other options: %s: %v", r.State, r.Lines)
	}
	for _, l := range r.Lines {
		if l.Op == OpExtra && strings.HasPrefix(l.Text, "ntp server 192.0.2.123 ") && l.Unmanaged {
			t.Errorf("the same host with other options is unmanaged: %q", l.Text)
		}
	}
}

// The section exists only where the rendering has it.
func TestIOSSystemSectionOnlyWhereRendered(t *testing.T) {
	device := "version 15.2\nhostname r1\nip domain name example.net\nntp server 192.0.2.123\nbanner login ^Chello^C\nclock timezone UTC 0\n"
	ex, err := Extract("ios", device)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ex.Sections[SectionSystem]; ok {
		t.Error("a system section with no rendering")
	}
	for n, s := range ex.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, "ntp") || strings.Contains(l, "domain") || strings.Contains(l, "banner") || strings.Contains(l, "timezone") {
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
	// a record of an older tacctl (no system section) is not compared
	sec := iosSystemRendering(t, "ip domain name lab.example.net\n")
	rs, err = CompareAll([]devices.Section{sec}, ex)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		if r.Name == SectionSystem && (r.State != StateNA || len(r.Notes) == 0) {
			t.Errorf("an unread section: %+v", r)
		}
	}
}

// A banner with a body that holds what the grammar of the device's text has
// no business with (a statement, a section header, a comment) is text.
func TestIOSBannerBodyIsText(t *testing.T) {
	sec := iosSystemRendering(t, "banner login <<'EOF'\nsnmp-server community leak RO\naaa new-model\n  line vty 0 4\n!\n\nlast\nEOF\n")
	dev := "banner login ^C\nsnmp-server community leak RO\naaa new-model\n  line vty 0 4\n!\n\nlast\n^C\naaa authentication login default local\n"
	ex, err := Extract("ios", "version 15.2\nhostname r1\n"+dev, sec)
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Sections[SectionSNMP].Lines; len(got) != 0 {
		t.Errorf("the banner's text is SNMP: %v", got)
	}
	for _, l := range ex.Sections[SectionAAA].Lines {
		if l == "aaa new-model" {
			t.Errorf("the banner's text is AAA: %v", ex.Sections[SectionAAA].Lines)
		}
	}
	if r := iosSystemState(t, dev, sec); r.State != StateOK {
		t.Errorf("%s: %v", r.State, r.Lines)
	}
	// the rendering's labels do not take the community of a banner line
	if m, err := CommunityLabels(FamilyIOS, sec.Lines); err != nil || len(m) != 0 {
		t.Logf("labels of the rendering: %v %v", m, err)
	}
}

func TestIOSTrapSourceStoredForm(t *testing.T) {
	sec := devices.Section{Name: SectionSNMP, Lines: []string{"snmp-server trap-source Loopback0"}, Secret: []bool{false}, Block: []bool{true}}
	for dev, want := range map[string]State{
		"snmp-server trap-source Loopback0\n": StateOK,
		"snmp-server trap-source loopback0\n": StateOK,
		"snmp-server trap-source Loopback1\n": StateDiffers,
		"snmp-server location x\n":            StateMissing,
	} {
		ex, err := Extract("ios", "version 15.2\nhostname r1\n"+dev, sec)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Compare("ios", sec, ex.Sections[SectionSNMP], true)
		if err != nil {
			t.Fatal(err)
		}
		if r.State != want && (want != StateMissing || r.State != StateDiffers) {
			t.Errorf("%q: %s, want %s: %v", dev, r.State, want, r.Lines)
		}
	}
	// the device's own, with the rendering stating none, is unmanaged
	empty := devices.Section{Name: SectionSNMP, Lines: []string{"snmp-server location Rack 1"}, Secret: []bool{false}}
	ex, err := Extract("ios", "version 15.2\nhostname r1\nsnmp-server trap-source Loopback0\nsnmp-server location Rack 1\n", empty)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Compare("ios", empty, ex.Sections[SectionSNMP], true)
	if err != nil {
		t.Fatal(err)
	}
	if r.State != StateOK || r.Unmanaged != 1 {
		t.Errorf("the device's own trap source: %s (+%d): %v", r.State, r.Unmanaged, r.Lines)
	}
}

// IOS prints no 'clock timezone' line for the default zone: a rendered
// 'clock timezone UTC 0' is there on a device that has none, and missing
// on a device with another zone.
func TestIOSDefaultTimezoneIsImplicit(t *testing.T) {
	rendering := iosSystemRendering(t, "clock timezone UTC 0\n")
	if r := iosSystemState(t, "ip domain name lab.example.net\n", rendering); r.State != StateOK {
		t.Errorf("a device with no zone line: %+v", r)
	}
	if r := iosSystemState(t, "clock timezone PST -8 0\n", rendering); r.State == StateOK {
		t.Errorf("a device with another zone reads ok: %+v", r)
	}
	if r := iosSystemState(t, "clock timezone UTC 0 0\n", rendering); r.State != StateOK {
		t.Errorf("a device that prints the line: %+v", r)
	}
}
