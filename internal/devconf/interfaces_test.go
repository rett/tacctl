package devconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The interface addresses a pull records (D314) are read from the text the
// pull already has: Junos 'display set' and IOS 'show running-config'.

const junosInterfacesText = `set version 21.4R3
set system host-name jsw1
set system tacplus-server 192.0.2.10 secret "$9$abc"
set interfaces lo0 unit 0 family inet address 192.0.2.250/32
set interfaces lo0 unit 0 family inet6 address 2001:db8::250/128
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 virtual-address 198.51.100.254
set interfaces ge-0/0/0 unit 0 family inet address 198.51.100.1/24 vrrp-group 1 priority 200
set interfaces ge-0/0/0 unit 0 family inet6 address 2001:DB8:0:1::1/64 vrrp-inet6-group 1 virtual-inet6-address 2001:db8:0:1::fe
set interfaces ge-0/0/1 unit 10 family inet address 203.0.113.1/24 primary
set interfaces ge-0/0/2 unit 0 family inet dhcp
set interfaces ge-0/0/3 unit 0 family ethernet-switching
set interfaces fxp0 unit 0 family inet address 10.0.0.5/24
deactivate interfaces ge-0/0/1 unit 10 family inet address 203.0.113.1/24
set interfaces ge-0/0/4 unit 0 family inet address 10.0.4.1/24
deactivate interfaces ge-0/0/4 unit 0
set interfaces ge-0/0/5 unit 0 family inet address 10.0.5.1/24
deactivate interfaces ge-0/0/5
set interfaces ge-0/0/6 unit 0 family inet address 10.0.6.1/24
deactivate interfaces ge-0/0/6 unit 0 family inet
set interfaces ge-0/0/7 unit 0 family inet address 10.0.7.1/24 vrrp-group 3 virtual-address 10.0.7.254
deactivate interfaces ge-0/0/7 unit 0 family inet address 10.0.7.1/24 vrrp-group 3
`

func TestJunosInterfaceAddresses(t *testing.T) {
	ext, err := Extract("juniper", junosInterfacesText)
	if err != nil {
		t.Fatal(err)
	}
	got := ext.Interfaces
	if got == nil || !got.Visible {
		t.Fatalf("no interface addresses: %+v", got)
	}
	want := map[string][]string{
		"lo0.0":      {"192.0.2.250", "2001:db8::250"},
		"ge-0/0/0.0": {"198.51.100.1", "198.51.100.254", "2001:db8:0:1::1", "2001:db8:0:1::fe"},
		"ge-0/0/2.0": {dynamicAddress},
		"fxp0.0":     {"10.0.0.5"},
		// the virtual address of a deactivated group is no address of the
		// device, its own address is
		"ge-0/0/7.0": {"10.0.7.1"},
	}
	// the sorted order is the canonical text's
	for k := range want {
		sortStrings(want[k])
	}
	if !reflect.DeepEqual(got.Addresses, want) {
		t.Errorf("addresses\n got %v\nwant %v", got.Addresses, want)
	}
	if len(got.Sources) != 0 {
		t.Errorf("a Junos device has no source interfaces: %v", got.Sources)
	}
}

func sortStrings(s []string) {
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
}

// The Junos forms of an address the device obtains or derives by itself are
// recorded as such, never as an address: no source can be told wrong then.
func TestJunosDynamicAddressForms(t *testing.T) {
	text := `set version 21.4R3
set interfaces ge-0/0/0 unit 0 family inet dhcp
set interfaces ge-0/0/1 unit 0 family inet dhcp-client
set interfaces ge-0/0/2 unit 0 family inet6 dhcpv6-client
set interfaces pp0 unit 0 family inet negotiate-address
set interfaces ge-0/0/3 unit 0 family inet6 address 2001:db8:0:3::/64 eui-64
deactivate interfaces ge-0/0/3 unit 1
set interfaces ge-0/0/3 unit 1 family inet6 address 2001:db8:0:5::/64 eui-64
`
	ext, err := Extract("juniper", text)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"ge-0/0/0.0": {dynamicAddress}, "ge-0/0/1.0": {dynamicAddress}, "ge-0/0/2.0": {dynamicAddress},
		"pp0.0": {dynamicAddress}, "ge-0/0/3.0": {dynamicAddress}}
	if !ext.Interfaces.Visible || !reflect.DeepEqual(ext.Interfaces.Addresses, want) {
		t.Errorf("addresses %v, want %v", ext.Interfaces.Addresses, want)
	}
}

// A login that cannot see the interfaces gets a text without them: the
// record says so, so that nothing is checked against it.
func TestInterfaceAddressesNotVisible(t *testing.T) {
	ext, err := Extract("juniper", "set version 21.4R3\nset system host-name jsw1\nset system tacplus-server 192.0.2.10 single-connection\n")
	if err != nil {
		t.Fatal(err)
	}
	if ext.Interfaces == nil || ext.Interfaces.Visible || len(ext.Interfaces.Addresses) != 0 {
		t.Errorf("a text with no interface: %+v", ext.Interfaces)
	}
	ext, err = Extract("cisco", "hostname rtr1\n!\naaa new-model\ntacacs server TACACS\n address ipv4 192.0.2.10\nend\n")
	if err != nil {
		t.Fatal(err)
	}
	if ext.Interfaces == nil || ext.Interfaces.Visible {
		t.Errorf("a text with no interface: %+v", ext.Interfaces)
	}
}

const iosInterfacesText = `hostname rtr1
!
aaa new-model
!
interface Loopback0
 ip address 192.0.2.250 255.255.255.255
 ipv6 address 2001:DB8::250/128
!
interface GigabitEthernet0/0
 description uplink
 ip address 198.51.100.1 255.255.255.0
 ip address 198.51.100.2 255.255.255.0 secondary
 ipv6 address 2001:DB8:0:1::1/64
 ipv6 address FE80::1 link-local
 duplex auto
!
interface GigabitEthernet0/1
 no ip address
 shutdown
!
interface GigabitEthernet0/2
 ip address dhcp
!
interface GigabitEthernet0/3
 ip unnumbered Loopback0
!
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
 ip vrf forwarding MGMT
!
interface Serial0/0.1 point-to-point
 ip address 10.0.20.1 255.255.255.252
!
interface ATM0/0.1 multipoint
 ip address 10.0.21.1 255.255.255.252
!
interface GigabitEthernet0/4
 ipv6 address 2001:DB8:0:4::/64 eui-64
!
ip tacacs source-interface Loopback0
ip radius source-interface GigabitEthernet0/9
tacacs server TACACS
 address ipv4 192.0.2.10
end
`

func TestIOSInterfaceAddresses(t *testing.T) {
	ext, err := Extract("cisco", iosInterfacesText)
	if err != nil {
		t.Fatal(err)
	}
	got := ext.Interfaces
	if got == nil || !got.Visible {
		t.Fatalf("no interface addresses: %+v", got)
	}
	want := map[string][]string{
		"loopback0":          {"192.0.2.250", "2001:db8::250"},
		"gigabitethernet0/0": {"198.51.100.1", "198.51.100.2", "2001:db8:0:1::1", "fe80::1"},
		"gigabitethernet0/2": {dynamicAddress},
		"gigabitethernet0/3": {dynamicAddress},
		"vlan10":             {"10.0.10.1"},
		// the name is the first word of the line: a subinterface's line goes on
		// with its type
		"serial0/0.1": {"10.0.20.1"},
		"atm0/0.1":    {"10.0.21.1"},
		// the prefix of an EUI-64 address is not an address of the device
		"gigabitethernet0/4": {dynamicAddress},
	}
	for k := range want {
		sortStrings(want[k])
	}
	if !reflect.DeepEqual(got.Addresses, want) {
		t.Errorf("addresses\n got %v\nwant %v", got.Addresses, want)
	}
	if !reflect.DeepEqual(got.Sources, map[string]string{"tacacs": "Loopback0", "radius": "GigabitEthernet0/9"}) {
		t.Errorf("sources %v", got.Sources)
	}
}

// The facts are kept in the record, not in the sections file: an older
// release's sections reader takes every key of that file for a section, and
// its record decoder (encoding/json, no DisallowUnknownFields, in every
// release since the store exists) ignores a key it does not know. So the
// rollback has nothing to undo (a pull repeats the key).
func TestInterfaceFactsAreInTheRecordOnly(t *testing.T) {
	dir := t.TempDir()
	st := Store{Records: filepath.Join(dir, "devices-config.json"), Dir: filepath.Join(dir, "device-config")}
	recs := NewRecords()
	facts := &InterfaceFacts{Visible: true, Addresses: map[string][]string{"lo0.0": {"192.0.2.250"}}}
	recs.Put("jsw1", Record{Vendor: "juniper", Result: ResultOK, Interfaces: facts})
	// Put keeps a copy
	facts.Addresses["lo0.0"][0] = "changed"
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(st.Records)
	if !strings.Contains(string(data), `"interfaces"`) || !strings.Contains(string(data), "192.0.2.250") {
		t.Fatalf("the record file:\n%s", data)
	}
	back, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := back.Of("jsw1"); rec == nil || rec.Interfaces == nil || !rec.Interfaces.Visible || rec.Interfaces.Addresses["lo0.0"][0] != "192.0.2.250" {
		t.Errorf("record %+v", rec)
	}
	// a record of an older tacctl has none, and writes none
	recs.Put("old", Record{Vendor: "juniper", Result: ResultOK})
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Devices map[string]map[string]json.RawMessage `json:"devices"`
	}
	data, _ = os.ReadFile(st.Records)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Devices["old"]["interfaces"]; ok {
		t.Errorf("a record with no facts writes the key: %s", data)
	}
	// the sections file does not carry them
	if err := st.SaveSections("jsw1", "juniper", nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(st.Dir, "jsw1.yaml")); strings.Contains(string(b), "192.0.2.250") || strings.Contains(string(b), "interfaces") {
		t.Errorf("the sections file:\n%s", b)
	}
}
