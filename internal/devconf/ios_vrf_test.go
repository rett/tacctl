package devconf

// 0.2.8: the vrf forms of the IOS system block and the vrf and informs forms
// of the snmp block's trap hosts. The vrf is part of the object: a line with
// it is satisfied by no line without it, and the other way round. The stored
// forms are the ones read back on IOS 15.6(2)T and IOS-XE 16.7.1.

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devices"
)

const iosVRFBlock = `ip domain name lab.example.net
ip domain name vrf MGMT mgmt.example.net
ip domain list vrf MGMT mgmt.example.net
ip name-server 192.0.2.53
ip name-server vrf MGMT 192.0.2.53
ip name-server vrf MGMT 192.0.2.54
ntp server 192.0.2.123
ntp server vrf MGMT 192.0.2.123 prefer version 3
`

func stateOf(r SectionResult) string {
	var out []string
	for _, l := range r.Lines {
		if l.Op != OpSame {
			out = append(out, string(l.Op)+" "+l.Text)
		}
	}
	return string(r.State) + " (+" + string(rune('0'+r.Unmanaged)) + ")\n" + strings.Join(out, "\n")
}

// The device as IOS 15.6 stores the block, and as IOS-XE 16.7 does: a vrf's
// name servers on one line there, one line per address on 15.6.
func TestIOSVRFSystemStoredForms(t *testing.T) {
	rendering := iosSystemRendering(t, iosVRFBlock)
	for name, device := range map[string]string{
		"15.6": `ip domain name lab.example.net
ip domain name vrf MGMT mgmt.example.net
ip domain list vrf MGMT mgmt.example.net
ip name-server 192.0.2.53
ip name-server vrf MGMT 192.0.2.53
ip name-server vrf MGMT 192.0.2.54
ntp server 192.0.2.123
ntp server vrf MGMT 192.0.2.123 prefer version 3
`,
		"16.7": `ip domain name lab.example.net
ip domain name vrf MGMT mgmt.example.net
ip domain list vrf MGMT mgmt.example.net
ip name-server 192.0.2.53
ip name-server vrf MGMT 192.0.2.53 192.0.2.54
ntp server 192.0.2.123
ntp server vrf MGMT 192.0.2.123 prefer version 3
`,
		"the other order of the options and the legacy spellings": `ip domain-name lab.example.net
ip domain-name vrf MGMT MGMT.example.net
ip domain-list vrf MGMT mgmt.example.net
ip name-server 192.0.2.53
ip name-server vrf MGMT 192.0.2.54 192.0.2.53
ntp server 192.0.2.123
ntp server vrf MGMT 192.0.2.123 version 3 prefer
`,
	} {
		t.Run(name, func(t *testing.T) {
			r := iosSystemState(t, device, rendering)
			if r.State != StateOK || r.Unmanaged != 0 {
				t.Errorf("%s", stateOf(r))
			}
		})
	}
}

// A line with a vrf is not satisfied by the line without it, and the other
// way round; the line of another vrf is the device's own.
func TestIOSVRFIsPartOfTheObject(t *testing.T) {
	rendering := iosSystemRendering(t, iosVRFBlock)
	// the values without the vrf: the vrf's lines are missing, and the
	// device's lines without the vrf are the rendering's own
	r := iosSystemState(t, `ip domain name lab.example.net
ip domain list mgmt.example.net
ip name-server 192.0.2.53 192.0.2.54
ntp server 192.0.2.123
ntp server 192.0.2.123 prefer version 3
`, rendering)
	if r.State != StateDiffers {
		t.Fatalf("%s", stateOf(r))
	}
	var missing []string
	for _, l := range r.Lines {
		if l.Op == OpMissing {
			missing = append(missing, l.Text)
		}
	}
	for _, want := range []string{
		"ip domain name vrf MGMT mgmt.example.net", "ip domain list vrf MGMT mgmt.example.net",
		"ip name-server vrf MGMT 192.0.2.53", "ip name-server vrf MGMT 192.0.2.54", "ntp server vrf MGMT 192.0.2.123 prefer version 3",
	} {
		if !slices.Contains(missing, want) {
			t.Errorf("missing lacks %q: %q", want, missing)
		}
	}
	if len(missing) != 5 {
		t.Errorf("missing: %q", missing)
	}

	// the rendering without the vrf, the device with it only
	plain := iosSystemRendering(t, "ip name-server 192.0.2.53\nntp server 192.0.2.123\nip domain name lab.example.net\n")
	r = iosSystemState(t, "ip name-server vrf MGMT 192.0.2.53\nntp server vrf MGMT 192.0.2.123\nip domain name vrf MGMT lab.example.net\n", plain)
	if r.State != StateDiffers || r.Unmanaged != 3 {
		t.Errorf("%s", stateOf(r))
	}
	for _, l := range r.Lines {
		if l.Op == OpMissing {
			continue
		}
		if l.Op != OpExtra || !l.Unmanaged {
			t.Errorf("a device line of a vrf is not the device's own: %+v", l)
		}
	}

	// a vrf the rendering does not name is the device's own, and so is
	// every statement of a vrf the rendering states nothing of
	r = iosSystemState(t, `ip domain name lab.example.net
ip domain name vrf MGMT mgmt.example.net
ip domain name vrf OTHER other.example.net
ip domain list vrf MGMT mgmt.example.net
ip domain list vrf MGMT another.example.net
ip domain list vrf OTHER other.example.net
ip name-server 192.0.2.53
ip name-server vrf MGMT 192.0.2.53 192.0.2.54 192.0.2.55
ip name-server vrf OTHER 198.51.100.53
ntp server 192.0.2.123
ntp server vrf MGMT 192.0.2.123 prefer version 3
ntp server vrf MGMT 198.51.100.123
ntp server vrf OTHER 192.0.2.123
`, rendering)
	if r.State != StateOK || r.Unmanaged != 7 {
		t.Errorf("%s", stateOf(r))
	}

	// a rendering that states only a vrf's domain name leaves the global one
	// to the device
	vrfOnly := iosSystemRendering(t, "ip domain name vrf MGMT mgmt.example.net\n")
	r = iosSystemState(t, "ip domain name lab.example.net\nip domain name vrf MGMT mgmt.example.net\n", vrfOnly)
	if r.State != StateOK || r.Unmanaged != 1 {
		t.Errorf("the device's own domain name beside a vrf's: %s", stateOf(r))
	}
	// and the other way round
	globalOnly := iosSystemRendering(t, "ip domain name lab.example.net\n")
	r = iosSystemState(t, "ip domain name lab.example.net\nip domain name vrf MGMT mgmt.example.net\n", globalOnly)
	if r.State != StateOK || r.Unmanaged != 1 {
		t.Errorf("the device's own domain name of a vrf: %s", stateOf(r))
	}

	// the same host with other options in the same vrf is a difference, and
	// so is another domain name of the vrf
	r = iosSystemState(t, `ip domain name lab.example.net
ip domain name vrf MGMT old.example.net
ip domain list vrf MGMT mgmt.example.net
ip name-server 192.0.2.53
ip name-server vrf MGMT 192.0.2.53 192.0.2.54
ntp server 192.0.2.123
ntp server vrf MGMT 192.0.2.123
`, rendering)
	if r.State != StateDiffers {
		t.Fatalf("%s", stateOf(r))
	}
	var extra, miss []string
	for _, l := range r.Lines {
		switch {
		case l.Op == OpExtra && !l.Unmanaged:
			extra = append(extra, l.Text)
		case l.Op == OpMissing:
			miss = append(miss, l.Text)
		}
	}
	if !slices.Equal(miss, []string{"ip domain name vrf MGMT mgmt.example.net", "ntp server vrf MGMT 192.0.2.123 prefer version 3"}) ||
		!slices.Equal(extra, []string{"ip domain name vrf MGMT old.example.net", "ntp server vrf MGMT 192.0.2.123"}) {
		t.Errorf("missing %q, extra %q", miss, extra)
	}
}

// 'ip name-server' of a vrf is one statement per address, whatever the
// release prints: a line with several addresses and the same addresses on
// separate lines compare as one.
func TestIOSVRFNameServersExpand(t *testing.T) {
	ex, err := Extract("cisco", "hostname r1\nip name-server vrf MGMT 192.0.2.53 192.0.2.54\nip name-server 192.0.2.7\nend\n", devices.Section{Name: SectionSystem, Lines: []string{"ip name-server vrf MGMT 192.0.2.53"}, Secret: []bool{false}, Block: []bool{true}})
	if err != nil {
		t.Fatal(err)
	}
	got := ex.Sections[SectionSystem].Lines
	want := []string{"ip name-server vrf MGMT 192.0.2.53", "ip name-server vrf MGMT 192.0.2.54", "ip name-server 192.0.2.7"}
	for _, w := range want {
		if !slices.Contains(got, w) {
			t.Errorf("the extraction lacks %q:\n%s", w, strings.Join(got, "\n"))
		}
	}
}

// --- the snmp block's trap hosts ---------------------------------------------

func iosHostRendering(lines ...string) devices.Section {
	sec := devices.Section{Name: SectionSNMP, Lines: lines}
	for _, l := range lines {
		sec.Secret = append(sec.Secret, strings.HasPrefix(l, "snmp-server host ") || strings.HasPrefix(l, "snmp-server community "))
		sec.Block = append(sec.Block, true)
	}
	return sec
}

// The trap hosts of a vrf and of the informs kind, and a host with a port
// and types: the device prints them as IOS 15.6 does (two blanks before the
// types after a port), and each is an entry of its own, satisfied by its own
// line only: the same address as traps and as informs, or on two ports, is
// two entries.
func TestIOSVRFTrapHosts(t *testing.T) {
	r := iosHostRendering(
		"snmp-server host 192.0.2.61 vrf MGMT version 2c poller-traps",
		"snmp-server host 192.0.2.62 informs version 2c poller-traps",
		"snmp-server host 192.0.2.63 version 2c poller-traps udp-port 1162 config",
		"snmp-server host 192.0.2.64 vrf MGMT informs version 2c poller-traps",
	)
	compare := func(device string) SectionResult {
		t.Helper()
		ex, err := Extract("cisco", "hostname r1\n"+device+"end\n", r)
		if err != nil {
			t.Fatal(err)
		}
		res, err := Compare("cisco", r, ex.Sections[SectionSNMP], true)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	same := compare(`snmp-server host 192.0.2.61 vrf MGMT version 2c poller-traps
snmp-server host 192.0.2.62 informs version 2c poller-traps
snmp-server host 192.0.2.63 version 2c poller-traps udp-port 1162  config
snmp-server host 192.0.2.64 vrf MGMT informs version 2c poller-traps
`)
	if same.State != StateOK || same.Unmanaged != 0 {
		t.Errorf("as IOS 15.6 prints them: %s", stateOf(same))
	}
	// no line of the extraction holds the community
	ex, _ := Extract("cisco", "hostname r1\nsnmp-server host 192.0.2.61 vrf MGMT version 2c poller-traps\nend\n", r)
	for _, l := range ex.Sections[SectionSNMP].Lines {
		if strings.Contains(l, "poller-traps") {
			t.Errorf("the extraction holds a string: %q", l)
		}
	}

	// the same hosts without the vrf, as traps, or on the default port: every
	// line is missing, and the device's own are other entries
	other := compare(`snmp-server host 192.0.2.61 version 2c poller-traps
snmp-server host 192.0.2.62 version 2c poller-traps
snmp-server host 192.0.2.63 version 2c poller-traps
snmp-server host 192.0.2.64 informs version 2c poller-traps
`)
	if other.State != StateDiffers {
		t.Fatalf("%s", stateOf(other))
	}
	missing, unmanaged, owned := 0, 0, 0
	for _, l := range other.Lines {
		switch {
		case l.Op == OpMissing:
			missing++
		case l.Op == OpExtra && l.Unmanaged:
			unmanaged++
		case l.Op == OpExtra:
			owned++
		}
	}
	if missing != 4 || unmanaged != 4 || owned != 0 {
		t.Errorf("missing %d, unmanaged %d, owned extras %d:\n%s", missing, unmanaged, owned, stateOf(other))
	}

	// the device holds the traps entry too: the informs line is satisfied and
	// the traps entry is its own
	pair := compare(`snmp-server host 192.0.2.61 vrf MGMT version 2c poller-traps
snmp-server host 192.0.2.62 informs version 2c poller-traps
snmp-server host 192.0.2.62 version 2c poller-traps
snmp-server host 192.0.2.63 version 2c poller-traps udp-port 1162  config
snmp-server host 192.0.2.63 version 2c poller-traps
snmp-server host 192.0.2.64 vrf MGMT informs version 2c poller-traps
`)
	if pair.State != StateOK || pair.Unmanaged != 2 {
		t.Errorf("a traps and an informs entry of one address:\n%s", stateOf(pair))
	}

	// the version and the types are attributes of the entry: another one is a
	// difference of that entry, not another entry
	attrs := compare(`snmp-server host 192.0.2.61 vrf MGMT poller-traps
snmp-server host 192.0.2.62 informs version 2c poller-traps
snmp-server host 192.0.2.63 version 2c poller-traps udp-port 1162 ospf
snmp-server host 192.0.2.64 vrf MGMT informs version 2c poller-traps
`)
	if attrs.State != StateDiffers || attrs.Unmanaged != 0 {
		t.Errorf("%s", stateOf(attrs))
	}
	miss, extra := 0, 0
	for _, l := range attrs.Lines {
		switch l.Op {
		case OpMissing:
			miss++
		case OpExtra:
			extra++
		}
	}
	if miss != 2 || extra != 2 {
		t.Errorf("missing %d, extra %d:\n%s", miss, extra, stateOf(attrs))
	}

	// a host in another vrf is the device's own
	own := compare(`snmp-server host 192.0.2.61 vrf MGMT version 2c poller-traps
snmp-server host 192.0.2.62 informs version 2c poller-traps
snmp-server host 192.0.2.63 version 2c poller-traps udp-port 1162 config
snmp-server host 192.0.2.64 vrf MGMT informs version 2c poller-traps
snmp-server host 192.0.2.61 vrf OTHER version 2c poller-traps
snmp-server host 192.0.2.61 vrf OTHER version 2c device-traps
`)
	if own.State != StateOK || own.Unmanaged != 2 {
		t.Errorf("%s", stateOf(own))
	}
}
