package scrub

import (
	"strings"
	"testing"
)

// A Junos answer as a device prints it, with made-up values.
const junosSample = `fpc0:
--------------------------------------------------------------------------
Hostname: core-sw1.corp.example.org
Model: ex4200-24t
Junos: 15.1R6-S4.2
JUNOS Base OS boot [15.1R6-S4.2]
Current user: 'RW-CLASS' login: 'jdoe' class 'RW-CLASS'
Permissions:
    view-configuration-- Can view all configuration (not including secrets)
0   2026-10-14 12:12:17 AKDT by jdoe via cli commit confirmed, rollback in 3mins
    fix the uplink for Building 7
1   2026-10-14 12:09:15 AKDT by root via other
Chassis                                BQ0210512345      EX4200-24T
Virtual Chassis ID: 0123.4567.89ab
Mgmt 10.20.30.40/24 gw 10.20.30.1 mask 255.255.255.0 lo 127.0.0.1
mac 00:1b:63:84:45:e6 v6 2001:470:1f0b::7 time 13:11:00
`

func TestApplyReplacesWhatNamesTheDeviceAndKeepsTheShape(t *testing.T) {
	s := New()
	s.Learn(Host, "core-sw1")
	out := s.ApplyAll([]string{junosSample})[0]
	for _, real := range []string{"core-sw1", "corp.example.org", "jdoe", "RW-CLASS", "AKDT", "BQ0210512345", "0123.4567.89ab",
		"10.20.30.40", "10.20.30.1", "00:1b:63:84:45:e6", "2001:470:1f0b::7", "Building 7"} {
		if strings.Contains(out, real) {
			t.Errorf("%q is still in the output:\n%s", real, out)
		}
	}
	for _, kept := range []string{"ex4200-24t", "15.1R6-S4.2", "JUNOS Base OS boot [15.1R6-S4.2]", "255.255.255.0", "127.0.0.1", "13:11:00",
		"not including secrets", "by root via other", "<comment removed>", "EX4200-24T", "rollback in 3mins"} {
		if !strings.Contains(out, kept) {
			t.Errorf("%q is gone from the output:\n%s", kept, out)
		}
	}
	if leaks := s.Leaks(out); len(leaks) > 0 {
		t.Errorf("leaks %v", leaks)
	}
}

func TestTheSameRealValueIsTheSameExample(t *testing.T) {
	s := New()
	out := s.ApplyAll([]string{"a 10.1.1.1 b 10.1.1.2 c 10.1.1.1", "again 10.1.1.2 and 10.1.1.1"})
	if !strings.HasPrefix(out[0], "a 192.0.2.1 b 192.0.2.2 c 192.0.2.1") || out[1] != "again 192.0.2.2 and 192.0.2.1" {
		t.Errorf("%q", out)
	}
}

func TestANameLearnedInALaterTextIsReplacedInTheEarlierOne(t *testing.T) {
	out := New().ApplyAll([]string{"core-sw9 is the uplink", "Hostname: core-sw9\n"})
	if strings.Contains(out[0], "core-sw9") || strings.Contains(out[1], "core-sw9") {
		t.Errorf("%q", out)
	}
}

func TestSecretsAreRemoved(t *testing.T) {
	s := New()
	in := strings.Join([]string{
		"snmp-server community s3cretRO RO 12",
		"enable secret 9 $9$aBcDeF123",
		`set system root-authentication encrypted-password "$1$abcd$EFGH"`,
		"Secret Word: hunter2hunter2",
		"tacacs-server key 7 0822455D0A16",
		"ssh-rsa " + strings.Repeat("A", 60),
	}, "\n")
	out := s.ApplyAll([]string{in})[0]
	for _, secret := range []string{"s3cretRO", "aBcDeF123", "abcd$EFGH", "hunter2hunter2", "0822455D0A16", strings.Repeat("A", 60)} {
		if strings.Contains(out, secret) {
			t.Errorf("%q survived:\n%s", secret, out)
		}
	}
	for _, p := range s.Pairs() {
		for _, secret := range []string{"s3cretRO", "aBcDeF123", "hunter2hunter2"} {
			if strings.Contains(p.Real, secret) {
				t.Errorf("a secret is in the map: %+v", p)
			}
		}
	}
}

func TestImageNamesAndReleasesAreNotSerialNumbers(t *testing.T) {
	in := "Cisco IOS Software, C3750 Software (C3750-IPSERVICESK9-M), Version 15.0(2)SE11\nVersion 16.9.4 JUNOS 21.4R3-S3.4"
	if out := New().ApplyAll([]string{in})[0]; out != in {
		t.Errorf("changed:\n%s", out)
	}
}

func TestExampleValuesAreNotReplacedAgain(t *testing.T) {
	in := "sw1.example.net 192.0.2.7 198.51.100.9 2001:db8::5 alice@example.net"
	if out := New().ApplyAll([]string{in})[0]; out != in {
		t.Errorf("changed: %s", out)
	}
}

func TestLeaksSeesAValueThatWasNotReplaced(t *testing.T) {
	s := New()
	s.Learn(Host, "edge-r7")
	if got := s.Leaks("the edge-r7 box"); len(got) != 1 {
		t.Errorf("leaks %v", got)
	}
	if got := s.Leaks("the " + s.Learn(Host, "edge-r7") + " box"); len(got) != 0 {
		t.Errorf("leaks %v", got)
	}
}

func TestACiscoClockZoneAndTimeZonesAreUTC(t *testing.T) {
	in := "clock timezone PST -8 0\n*Mar  1 08:14:55.123 PST\n12:18:03 CEST\nzone America/Anchorage"
	out := New().ApplyAll([]string{in})[0]
	for _, gone := range []string{"PST", "CEST", "Anchorage", "-8"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q in %q", gone, out)
		}
	}
	if !strings.Contains(out, "clock timezone UTC 0") || !strings.Contains(out, "08:14:55.123 UTC") {
		t.Errorf("%q", out)
	}
}

func TestMapHoldsTheRealValues(t *testing.T) {
	s := New()
	s.ApplyAll([]string{"Hostname: core-sw1\nby jdoe via cli\n10.9.9.9"})
	var kinds []string
	for _, p := range s.Pairs() {
		kinds = append(kinds, string(p.Kind)+":"+p.Real+"="+p.Example)
	}
	want := []string{"host:core-sw1=sw1", "ipv4:10.9.9.9=192.0.2.1", "user:jdoe=alice"}
	for _, w := range want {
		found := false
		for _, k := range kinds {
			found = found || k == w
		}
		if !found {
			t.Errorf("%q not in %v", w, kinds)
		}
	}
}
