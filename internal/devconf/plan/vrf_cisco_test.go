package plan

// 0.2.8: the vrf forms of the IOS system block ('ntp server vrf', 'ip
// name-server vrf', 'ip domain name|list vrf') and the vrf, informs and port
// forms of the snmp block's trap hosts. The vrf is part of the object, a
// replaced single value is the vrf's own, and the undo of a host is its line
// up to its udp-port.

import (
	"slices"
	"strings"
	"testing"
)

func vrfBackout(d Delta) []string {
	var out []string
	for _, l := range iosBackout(d) {
		s := l.Shown()
		if l.Op == OpNo {
			s = "no " + s
		}
		out = append(out, s)
	}
	return out
}

// The device that holds none of it: every statement is typed as written, the
// vrf's lines apart from the lines without it, the back-out takes each away
// as the device takes it, and a host's undo is its line up to the udp-port.
func TestIOSVRFNewDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-vrf-new")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip domain name lab.example.net",
		"ip domain name vrf MGMT mgmt.example.net",
		"ip domain list lab.example.net",
		"ip domain list vrf MGMT mgmt.example.net",
		"ip name-server 192.0.2.53",
		"ip name-server vrf MGMT 192.0.2.53",
		"ip name-server vrf MGMT 192.0.2.54",
		"ntp server 192.0.2.123 prefer",
		"ntp server vrf MGMT 192.0.2.123 version 3 prefer",
		"ntp server vrf OOB ntp2.example.net",
	}
	if got := lines(d, "system"); !slices.Equal(got, want) {
		t.Errorf("the system lines:\n%q\nwant\n%q", got, want)
	}
	wantSNMP := []string{
		"snmp-server host 192.0.2.61 vrf MGMT version 2c <secret:2>",
		"snmp-server host 192.0.2.62 informs version 2c <secret:2>",
		"snmp-server host 192.0.2.63 version 2c <secret:2> udp-port 1162 config",
	}
	if got := lines(d, "snmp"); !slices.Equal(got, wantSNMP) {
		t.Errorf("the snmp lines:\n%q\nwant\n%q", got, wantSNMP)
	}
	// the undo is the statement as the device takes it: a vrf's single value
	// and list entries by their vrf, every host by its entry
	undo := vrfBackout(d)
	for _, w := range []string{
		"no ip domain name vrf MGMT",
		"no ip domain name",
		"no ip domain list vrf MGMT mgmt.example.net",
		"no ip domain list lab.example.net",
		"no ip name-server vrf MGMT 192.0.2.53",
		"no ip name-server vrf MGMT 192.0.2.54",
		"no ip name-server 192.0.2.53",
		"no ntp server vrf MGMT 192.0.2.123",
		"no ntp server vrf OOB ntp2.example.net",
		"no ntp server 192.0.2.123",
		"no snmp-server host 192.0.2.61 vrf MGMT version 2c <secret:2>",
		"no snmp-server host 192.0.2.62 informs version 2c <secret:2>",
		"no snmp-server host 192.0.2.63 version 2c <secret:2> udp-port 1162",
	} {
		if !slices.Contains(undo, w) {
			t.Errorf("the back-out lacks %q:\n%s", w, strings.Join(undo, "\n"))
		}
	}
	// the paste holds the community by value, the report by label
	var hosts []Line
	for _, l := range d.Lines {
		if strings.HasPrefix(l.Text, "snmp-server host ") {
			hosts = append(hosts, l)
		}
	}
	if len(hosts) != 3 {
		t.Fatalf("hosts: %+v", hosts)
	}
	for _, h := range hosts {
		if !h.HasValue || !strings.Contains(h.Text, "poller-traps") {
			t.Errorf("the host is not typed by value: %+v", h)
		}
		// the undo is the line up to its udp-port: the types are no part of
		// the entry's identity, and a 'no' that names them removes only them
		want := strings.TrimSuffix(h.Text, " config")
		if len(h.Undo) != 1 || h.Undo[0].Op != OpNo || h.Undo[0].Text != want || !h.Undo[0].HasValue ||
			strings.Contains(h.Undo[0].Shown(), "poller-traps") {
			t.Errorf("the undo of %q: %+v", h.Text, h.Undo)
		}
	}
	// the owned rows of the lines
	for _, tc := range []struct{ text, row string }{
		{"ip domain name vrf MGMT mgmt.example.net", "ios.system.domain-name"},
		{"ip domain list vrf MGMT mgmt.example.net", "ios.system.domain-list"},
		{"ip name-server vrf MGMT 192.0.2.53", "ios.system.name-server"},
		{"ntp server vrf MGMT 192.0.2.123 version 3 prefer", "ios.system.ntp-server"},
	} {
		if got := iosRowID("system", Line{Op: OpLine, Text: tc.text}); got != tc.row {
			t.Errorf("%q is row %q, want %q", tc.text, got, tc.row)
		}
	}
	// the region is a safe paste
	var texts []string
	for _, rl := range RegionLines(d, f.header(), Wrapper{}) {
		texts = append(texts, rl.Text)
	}
	if err := CheckRegion("ios", texts); err != nil {
		t.Errorf("the region: %v", err)
	}
}

// The device holds the same values without the vrf, another value in the
// vrf, and another vrf's own lines: the vrf's lines are typed, a vrf's single
// value is replaced in place (its old value typed again by the back-out), the
// device's lines without the vrf are kept, and so are the other vrf's.
func TestIOSVRFStrayDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-vrf-stray")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{
		"ip domain name vrf MGMT mgmt.example.net", "ip domain list vrf MGMT mgmt.example.net", "ip name-server vrf MGMT 192.0.2.53",
		"ntp server 192.0.2.123 prefer", "ntp server vrf MGMT 192.0.2.123 version 3 prefer", "ntp server vrf OOB ntp2.example.net",
	} {
		wantLine(t, d, "system", w)
	}
	// a line the device holds is not typed again: its vrf is the same
	noLine(t, d, "system", "ip name-server vrf MGMT 192.0.2.54")
	noLine(t, d, "system", "ip domain name lab.example.net")
	noLine(t, d, "system", "no ")
	for _, k := range []string{"ip domain name vrf OTHER other.example.net", "ip domain list vrf OTHER other.example.net",
		"ip domain list mgmt.example.net", "ip name-server vrf OTHER 198.51.100.53", "ip name-server 192.0.2.54",
		"ntp server vrf OTHER 198.51.100.123"} {
		wantKept(t, d, "system", k)
	}
	// the hosts: an entry is its address, vrf, kind, udp-port and community, so
	// the vrf's host is typed beside the device's host without the vrf, and
	// the device's traps entry and its entry on the default port stay; the
	// types of the entry the device has are replaced in place
	for _, w := range []string{
		"snmp-server host 192.0.2.61 vrf MGMT version 2c <secret:2>",
		"snmp-server host 192.0.2.62 informs version 2c <secret:2>",
		"snmp-server host 192.0.2.63 version 2c <secret:2> udp-port 1162 config",
	} {
		wantLine(t, d, "snmp", w)
	}
	wantKept(t, d, "snmp", "snmp-server host 192.0.2.61 version 2c <secret:2>")
	wantKept(t, d, "snmp", "snmp-server host 192.0.2.62 version 2c <secret:2>")
	wantKept(t, d, "snmp", "snmp-server host 192.0.2.63 version 2c <secret:2>")
	wantKept(t, d, "snmp", "snmp-server host 192.0.2.64 vrf OTHER version 2c")
	undo := vrfBackout(d)
	for _, w := range []string{
		// replaced in place (the types): the device's line typed again
		"snmp-server host 192.0.2.62 informs version 2c <secret:2> config",
		"snmp-server host 192.0.2.63 version 2c <secret:2> udp-port 1162",
		// added: taken away by its entry, without the types
		"no snmp-server host 192.0.2.61 vrf MGMT version 2c <secret:2>",
		// the vrf's old value typed again, the added line taken away by vrf
		"ip domain name vrf MGMT old.example.net",
		"no ip domain list vrf MGMT mgmt.example.net",
		"no ip name-server vrf MGMT 192.0.2.53",
		"no ntp server vrf OOB ntp2.example.net",
		"ntp server vrf MGMT 192.0.2.123",
	} {
		if !slices.Contains(undo, w) {
			t.Errorf("the back-out lacks %q:\n%s", w, strings.Join(undo, "\n"))
		}
	}
	// the rendered lines were not satisfied by the lines without the vrf: the
	// first item of each kind is a '-', not a '+'
	if sp := d.Of("system"); sp.State != StatePlanned {
		t.Errorf("system: %s", sp.State)
	}
}

// The device after the paste, in the stored forms of IOS 15.6 (one name
// server line per address, two blanks before the trap types): nothing is
// planned and the section reads as the device's own beside the block's.
func TestIOSVRFMatchedDevice(t *testing.T) {
	f := fixtureNamed(t, "cisco.synthetic-vrf")
	exp, cur, plain := f.load(t)
	d, err := Plan(f.vendor, exp, cur, plain, f.options())
	if err != nil {
		t.Fatal(err)
	}
	if got := lines(d, "system"); len(got) != 0 {
		t.Errorf("the system lines: %q", got)
	}
	if got := lines(d, "snmp"); len(got) != 0 {
		t.Errorf("the snmp lines: %q", got)
	}
}
