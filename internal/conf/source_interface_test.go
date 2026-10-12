package conf

import (
	"strings"
	"testing"
)

// cisco.source_interface.<scope> takes the long interface name IOS prints:
// an abbreviation (lo0, gi0/1) is stored by IOS in the long form, so a
// device would compare different for ever (0.2.5, D119).
func TestSourceInterfaceIsTheLongName(t *testing.T) {
	s := NewSchema(DefaultBackends)
	const path = "cisco.source_interface.lab"
	for _, v := range []string{
		"Loopback0", "Loopback10", "GigabitEthernet0/0", "GigabitEthernet0/0/1", "TenGigabitEthernet1/0/1",
		"FortyGigabitEthernet1/1/1", "FastEthernet0/1", "Ethernet0/0", "Serial0/0/0:0", "Vlan100", "Port-channel1",
		"Port-channel1.100", "Tunnel0", "BVI1", "Management0/0",
	} {
		if msg := s.Validate(path, v, false); msg != "" {
			t.Errorf("%q: %s", v, msg)
		}
	}
	for _, v := range []string{
		"lo0", "Lo0", "gi0/1", "Gi0/1", "g0/0", "te1/0/1", "Fa0/1", "Po1", "Vl100", "Tu0", "loopback0", "LOOPBACK0",
		"gigabitethernet0/0", "Loopback", "GigabitEthernet", "Loopback0 ", " Loopback0", "Loopback 0", "Loopback0;",
		"Loopback-0", "0/0", "Loopback0\r", "Loopbacké0", "Nope0",
		// no final newline either: the rule is new, with no history of accepting one
		"Loopback0\n", "GigabitEthernet0/0\n", "Loopback0\n\n",
	} {
		msg := s.Validate(path, v, false)
		if msg == "" {
			t.Errorf("%q is accepted", v)
			continue
		}
		if !strings.Contains(msg, "write the full interface name") || !strings.Contains(msg, "Loopback0 or GigabitEthernet0/0") {
			t.Errorf("%q: the message does not name the form expected: %q", v, msg)
		}
	}
	if msg := s.Validate(path, 7, false); msg == "" {
		t.Error("an integer is accepted")
	}
}
