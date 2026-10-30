package cli

import (
	"reflect"
	"strings"
	"testing"
)

// The pull records the addresses of the device's interfaces, read from the
// configuration it already has (D314): no other command is sent, the
// addresses are in no output, no audit line and no JSON document of the
// pull, and a later pull replaces them.

func TestPullRecordsInterfaceAddresses(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	text := "set interfaces lo0 unit 0 family inet address 192.0.2.250/32\n" +
		"set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 virtual-address 198.51.100.254\n" +
		b.expected("lab-j")
	b.serve("juniper", text)
	for _, args := range [][]string{{"device", "config", "pull", "lab-j"}, {"device", "config", "pull", "lab-j", "--json"}} {
		out := b.run(args...)
		if b.sb.code != 0 {
			t.Fatalf("%v: %d %s", args, b.sb.code, b.sb.stderr())
		}
		if strings.Contains(out, "198.51.100.254") || strings.Contains(b.sb.stderr(), "198.51.100.254") {
			t.Errorf("%v shows an interface address:\n%s", args, out)
		}
	}
	for _, l := range b.auditLines("device config pull") {
		if strings.Contains(l, "192.0.2.250") || strings.Contains(l, "198.51.100") {
			t.Errorf("audit line: %s", l)
		}
	}
	rec, _ := b.records().Of("lab-j")
	if rec == nil || rec.Interfaces == nil || !rec.Interfaces.Visible {
		t.Fatalf("record %+v", rec)
	}
	want := map[string][]string{"ge-0/0/0.0": {"198.51.100.1", "198.51.100.254"}, "lo0.0": {"192.0.2.250"}}
	if !reflect.DeepEqual(rec.Interfaces.Addresses, want) {
		t.Errorf("addresses %v, want %v", rec.Interfaces.Addresses, want)
	}

	// a login that cannot see the interfaces: the next pull says so, and
	// keeps no address of the last
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-j")
	rec, _ = b.records().Of("lab-j")
	if rec == nil || rec.Interfaces == nil || rec.Interfaces.Visible || len(rec.Interfaces.Addresses) != 0 {
		t.Errorf("a pull with no interface keeps %+v", rec.Interfaces)
	}
}

func TestPullRecordsIOSInterfacesAndSources(t *testing.T) {
	b := newPullBox(t)
	b.ciscoDevice("")
	exp := b.expected("lab-c")
	// the statements land before the tail of the rendering
	text := strings.Replace(exp, "end\n", "interface Loopback0\n ip address 192.0.2.250 255.255.255.255\n!\n"+
		"interface GigabitEthernet0/0\n ip address 198.51.100.1 255.255.255.0\n!\nip radius source-interface Loopback9\nend\n", 1)
	b.serve("cisco", text)
	b.version(ciscoVersionModern)
	b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	rec, _ := b.records().Of("lab-c")
	if rec == nil || rec.Interfaces == nil || !rec.Interfaces.Visible {
		t.Fatalf("record %+v", rec)
	}
	if got := rec.Interfaces.Addresses["gigabitethernet0/0"]; !reflect.DeepEqual(got, []string{"198.51.100.1"}) {
		t.Errorf("addresses %v", rec.Interfaces.Addresses)
	}
	if rec.Interfaces.Sources["radius"] != "Loopback9" {
		t.Errorf("sources %v", rec.Interfaces.Sources)
	}
}
