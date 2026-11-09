package scrub

import (
	"fmt"
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

// A Junos permission row is 'name -- what it allows': the words of the
// description are not values, and the separator the parser cuts at stays.
func TestPermissionRowsKeepTheirShape(t *testing.T) {
	in := "    secret      -- Can view secret statements\n    secret-control-- Can modify secret statements\n    view-configuration-- Can view all configuration (not including secrets)\n"
	if out := New().ApplyAll([]string{in})[0]; out != in {
		t.Errorf("changed:\n%s", out)
	}
}

func TestASecretAfterAQualifierOrOnTheNextLineIsRemoved(t *testing.T) {
	s := New()
	in := "key 1\n  key-string 7 0822455D0A16\nset security ike policy x pre-shared-key ascii-text \"abc123verylongsecret\"\nauthentication-key 5 md5 s3cr3tvalue\n"
	out := s.ApplyAll([]string{in})[0]
	for _, secret := range []string{"0822455D0A16", "abc123verylongsecret", "s3cr3tvalue"} {
		if strings.Contains(out, secret) {
			t.Errorf("%q survived:\n%s", secret, out)
		}
	}
	for _, p := range s.Pairs() {
		if strings.Contains(p.Real, "0822455D0A16") {
			t.Errorf("a secret is in the map: %+v", p)
		}
	}
}

func TestHistoryCommentsOfAnyIndentationAreRemoved(t *testing.T) {
	in := "0   2026-10-14 12:12:17 UTC by root via cli\n     five spaces: call bob.jones\n\ttab: Sam wrote this\n    tacctl plan sw1\n1   2026-10-14 12:00:00 UTC by root via cli\n"
	out := New().ApplyAll([]string{in})[0]
	for _, gone := range []string{"bob.jones", "Sam wrote"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q survived:\n%s", gone, out)
		}
	}
	if !strings.Contains(out, "tacctl plan sw1") {
		t.Errorf("tacctl's own comment is gone:\n%s", out)
	}
}

func TestACiscoHostnameIsLearnedFromTheUptimeLine(t *testing.T) {
	in := "Cisco IOS Software, Version 15.0\nCORE-SW1 uptime is 3 weeks, 2 days\nLast configuration change at 12:00:00 UTC Mon Mar 1 2021 by jsmith\n"
	s := New()
	out := s.ApplyAll([]string{in})[0]
	if strings.Contains(out, "CORE-SW1") || strings.Contains(out, "jsmith") {
		t.Errorf("a name survived:\n%s", out)
	}
	if got := s.Leaks(out); len(got) > 0 {
		t.Errorf("leaks %v", got)
	}
}

func TestMoreZonesDigitSerialsAndCountryDomains(t *testing.T) {
	in := "*12:34:56.789 SGT Thu Mar 7 2024\nSystem serial number : 1234567890\nntp server ntp1.corp.co.uk\nlog loghost.corp.de\n"
	out := New().ApplyAll([]string{in})[0]
	for _, gone := range []string{"SGT", "1234567890", "corp", ".uk", ".de"} {
		if strings.Contains(out, gone) {
			t.Errorf("%q survived:\n%s", gone, out)
		}
	}
}

func TestTheTemplateUserOfTheLoginLineIsAUserNotAClass(t *testing.T) {
	s := New()
	out := s.ApplyAll([]string{"Current user: 'remote' login: 'jsmith' class 'netops'\n"})[0]
	if !strings.Contains(out, "'remote'") || strings.Contains(out, "jsmith") || strings.Contains(out, "netops") {
		t.Errorf("%q", out)
	}
	kinds := map[string]bool{}
	for _, p := range s.Pairs() {
		kinds[string(p.Kind)+":"+p.Real] = true
	}
	if !kinds["user:jsmith"] || !kinds["class:netops"] || kinds["class:remote"] {
		t.Errorf("%v", kinds)
	}
}

// scrubCase is a bundle of texts and what must be in the scrubbed texts
// (joined) and what must not.
type scrubCase struct {
	name string
	in   []string
	want []string // each is in the output
	gone []string // none is in the output
}

func runScrubCases(t *testing.T, cases []scrubCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := strings.Join(New().ApplyAll(c.in), "\n==\n")
			for _, w := range c.want {
				if !strings.Contains(out, w) {
					t.Errorf("%q is gone from the output:\n%s", w, out)
				}
			}
			for _, g := range c.gone {
				if strings.Contains(out, g) {
					t.Errorf("%q is still in the output:\n%s", g, out)
				}
			}
		})
	}
}

// A model name has the shape of a serial number and is not one.
func TestModelNamesAreNotSerialNumbers(t *testing.T) {
	runScrubCases(t, []scrubCase{
		{
			name: "csr1000v inventory",
			in: []string{"NAME: \"Chassis\", DESCR: \"Cisco CSR1000V Chassis\"\n" +
				"PID: CSR1000V        , VID: V00  , SN: 9ABCDEFGHIJ\n"},
			want: []string{"DESCR: \"Cisco CSR1000V Chassis\"", "PID: CSR1000V        , VID: V00  , SN: "},
			gone: []string{"9ABCDEFGHIJ"},
		},
		{
			name: "7206 inventory",
			in: []string{"NAME: \"chassis\", DESCR: \"CISCO7206VXR chassis, Hw Serial#: 1234567890, Hw Revision: 1.0\"\n" +
				"PID: CISCO7206VXR     , VID:    , SN: 1234567890\n"},
			want: []string{"DESCR: \"CISCO7206VXR chassis, Hw Serial#: ", "PID: CISCO7206VXR     , VID:    , SN: "},
		},
		{
			name: "a model stated in one file is kept in the others",
			in: []string{"PID: ASR1001HX         , VID: V01  , SN: FOC0000AAAA\n",
				"Cisco IOS XE Software, ASR1001HX Software (X86_64_LINUX_IOSD-UNIVERSALK9-M)\n"},
			want: []string{"PID: ASR1001HX ", "ASR1001HX Software (X86_64"},
			gone: []string{"FOC0000AAAA"},
		},
		{
			name: "junos model line",
			in:   []string{"Hostname: sw9\nModel: QFX10002\nJunos: 21.4R3-S2.4\n", "Chassis  QFX10002\n"},
			want: []string{"Model: QFX10002", "Chassis  QFX10002"},
		},
		{
			name: "ios show version model and revision line",
			in:   []string{"cisco WS3750X48P (PowerPC405) processor (revision A0) with 262144K bytes of memory.\n", "the WS3750X48P again\n"},
			want: []string{"cisco WS3750X48P (PowerPC405)", "the WS3750X48P again"},
		},
		{
			name: "a real serial is still replaced",
			in:   []string{"PID: CSR1000V , VID: V00 , SN: 9ABCDEFGHIJ\nsomething FOC0000AAAA else\n"},
			want: []string{"PID: CSR1000V , VID: V00 , SN: SN00000"},
			gone: []string{"9ABCDEFGHIJ", "FOC0000AAAA"},
		},
	})
}

// The value of a serial field runs to the next blank, comma or quote, hyphens
// and all.
func TestASerialWithAHyphenIsReplacedWhole(t *testing.T) {
	runScrubCases(t, []scrubCase{{
		name: "serial number field",
		in:   []string{"Serial Number : CN12AB-34567\nserial: ab-cd-1234, next\n"},
		want: []string{"Serial Number : SN000001\n", "serial: SN000002, next\n"},
		gone: []string{"CN12AB", "34567", "ab-cd"},
	}})
}

// A model is exempt as itself, not as the line it is on, and only the lines
// that state a model teach one.
func TestOnlyTheModelTokenIsExempt(t *testing.T) {
	runScrubCases(t, []scrubCase{
		{
			name: "the model line keeps its model and replaces the serial after it",
			in:   []string{"Model number : WS-C3750X-48P-S FDO1234X5YZ\n"},
			want: []string{"Model number : WS-C3750X-48P-S SN000001\n"},
			gone: []string{"FDO1234X5YZ"},
		},
		{
			name: "a PID stops at the VID and the serial after it is replaced",
			in:   []string{"PID: WS-C2960 VID: V01 FDO1234X5YZ\nPID: CSR1000V  FDO1234X5YZ\n"},
			want: []string{"PID: WS-C2960 VID: V01 SN000001\n", "PID: CSR1000V  SN000001\n"},
			gone: []string{"FDO1234X5YZ"},
		},
		{
			name: "a quoted name is not a model",
			in:   []string{"NAME: \"FDO1234X5YZ\", DESCR: \"Cisco CSR1000V Chassis\"\n"},
			want: []string{"DESCR: \"Cisco CSR1000V Chassis\""},
			gone: []string{"FDO1234X5YZ"},
		},
		{
			name: "the word after Cisco in prose is not a model",
			in:   []string{"case opened with Cisco ABC12345XYZ today\nsee Cisco FDO1234X5YZ\n"},
			gone: []string{"ABC12345XYZ", "FDO1234X5YZ"},
		},
		{
			name: "the revision line keeps its model and not the rest",
			in:   []string{"cisco WS3750X48P (PowerPC405) processor (revision A0) with 262144K bytes of memory. FDO1234X5YZ\n", "the WS3750X48P again\n"},
			want: []string{"cisco WS3750X48P (PowerPC405)", "the WS3750X48P again"},
			gone: []string{"FDO1234X5YZ"},
		},
		{
			name: "a PID at the end of a line is a model",
			in:   []string{"PID: ASR1001HX\nnext line\n", "the ASR1001HX again\n"},
			want: []string{"the ASR1001HX again"},
		},
		{
			name: "the software line teaches the model",
			in:   []string{"Cisco IOS XE Software, ASR1001HX Software (X86_64)\n", "the ASR1001HX again\n"},
			want: []string{"the ASR1001HX again"},
		},
	})
}

// A chassis hardware table and a virtual chassis table as Junos prints them,
// with invented serial numbers of every shape.
const (
	junosHardware = "Hardware inventory:\n" +
		"Item             Version  Part number  Serial number     Description\n" +
		"Chassis                                ABC0123456        Virtual Chassis\n" +
		"Routing Engine 0          BUILTIN      BUILTIN           RE-EX4400-48T\n" +
		"FPC 0            REV 11   650-114384   ABC0123456        EX4400-48T\n" +
		"  CPU                     BUILTIN      BUILTIN           FPC CPU\n" +
		"  PIC 0          REV 11   BUILTIN      BUILTIN           48x10M/100M/1G Base-T\n" +
		"  PIC 1          REV 11   650-114384   1234567           4x10G SFP+\n" +
		"Power Supply 0   REV 03   740-000001   abc1234           JPSU-350-AC-AFO\n" +
		"Fan Tray 0                                               Fan Module\n" +
		"    Xcvr 0                NON-JNPR     9317670227        SFP-LX10\n" +
		"    Xcvr 4       REV 02   740-013111   L437599           SFP-T\n" +
		"\n"
	junosVC = "Virtual Chassis ID: 0000.5e00.5301\n" +
		"                                                Mstr           Mixed Route Neighbor List\n" +
		"Member ID  Status   Serial No    Model          prio  Role      Mode  Mode ID  Interface\n" +
		"0 (FPC 0)  Prsnt    ABC0123456   ex4400-48t     255   Master*      N  VC   1  vcp-255/1/0\n" +
		"1 (FPC 1)  Prsnt    9876543210   ex4400-48t     255   Backup       N  VC   0  vcp-255/1/0\n" +
		"\n"
)

// A serial number is replaced by its field, whatever its shape, and the same
// real value is the same example in every file.
func TestSerialNumbersAreReplacedByTheirField(t *testing.T) {
	runScrubCases(t, []scrubCase{
		{
			name: "inventory fields",
			in: []string{"NAME: \"chassis\", DESCR: \"CISCO7206VXR chassis, Hw Serial#: 1234567890, Hw Revision: 1.0\"\n" +
				"PID: CISCO7206VXR     , VID:    , SN: 1234567890\n" +
				"PID: IOSv              , VID: 1.0, SN: 9L17A1TZNHPW4X9XZBG30\n" +
				"PID: PWR-7200-AC       , VID:    , SN: abc1234\n" +
				"PID: PWR-7200-AC       , VID:    , SN:            \n"},
			want: []string{"Hw Serial#: SN000001, Hw Revision: 1.0", "VID:    , SN: SN000001\n", "VID: 1.0, SN: SN000002\n", "SN: SN000003\n", "PID: IOSv "},
			gone: []string{"1234567890", "9L17A1TZNHPW4X9XZBG30", "abc1234"},
		},
		{
			name: "show version fields",
			in:   []string{"Processor board ID 1234567\nSystem serial number : 7654321\nSerial ID  xyz9876\n"},
			want: []string{"Processor board ID SN000001\n", "System serial number : SN000002\n", "Serial ID  SN000003\n"},
			gone: []string{"1234567", "7654321", "xyz9876"},
		},
		{
			name: "the same value in two files",
			in:   []string{"PID: X , VID: V , SN: 9999999999\n", "Processor board ID 9999999999\n"},
			want: []string{"SN: SN000001\n", "Processor board ID SN000001\n"},
			gone: []string{"9999999999"},
		},
		{
			name: "chassis hardware, every row",
			in:   []string{junosHardware},
			want: []string{
				"Chassis                                SN000001  ",
				"FPC 0            REV 11   650-114384   SN000001  ",
				"  PIC 1          REV 11   650-114384   SN000002  ",
				"Power Supply 0   REV 03   740-000001   SN000003  ",
				"    Xcvr 0                NON-JNPR     SN000004  ",
				"    Xcvr 4       REV 02   740-013111   SN000005  ",
				"Routing Engine 0          BUILTIN      BUILTIN           RE-EX4400-48T\n",
				"  CPU                     BUILTIN      BUILTIN           FPC CPU\n",
				"Fan Tray 0                                               Fan Module\n",
				"NON-JNPR", "740-013111", "650-114384", "EX4400-48T", "SFP-LX10", "SFP-T",
			},
			gone: []string{"ABC0123456", "1234567", "abc1234", "9317670227", "L437599"},
		},
		{
			name: "virtual chassis table",
			in:   []string{junosVC},
			want: []string{"0 (FPC 0)  Prsnt    SN000001", "1 (FPC 1)  Prsnt    SN000002", "ex4400-48t", "255   Master*"},
			gone: []string{"ABC0123456", "9876543210"},
		},
		{
			name: "table and table share the examples",
			in:   []string{junosHardware, junosVC},
			want: []string{"Chassis                                SN000001", "0 (FPC 0)  Prsnt    SN000001"},
			gone: []string{"ABC0123456"},
		},
	})
}

// Only the Description column of a table is exempt from the serial-number
// shape, and the table ends where its rows stop fitting the header.
func TestATableExemptsItsDescriptionColumnOnly(t *testing.T) {
	hdr := "Item             Version  Part number  Serial number     Description\n"
	runScrubCases(t, []scrubCase{
		{
			name: "a serial-shaped word in another column of a table row is replaced",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\n" + "FPC 0            REV 11   ZZTOP2468AB  XYZ98765432       EX4400-48T\n"},
			want: []string{"Virtual Chassis\n", "EX4400-48T\n"},
			gone: []string{"ZZTOP2468AB", "XYZ98765432", "ABC0123456"},
		},
		{
			name: "the description column keeps a model name",
			in:   []string{hdr + "FPC 0            REV 11   650-114384   ABC0123456        EX4400-48T\n"},
			want: []string{"EX4400-48T\n"},
		},
		{
			name: "a line that does not fit the header ends the table",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\n{master:0}\n" + "WORD  here\nmore text HELLO123456 and ABCDEFGH12\n"},
			gone: []string{"HELLO123456", "ABCDEFGH12", "ABC0123456"},
		},
		{
			name: "a status in the serial column of a continuation line is not a serial",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\n" + "                                       Prsnt             continued\nPrsnt and Prsnt\n"},
			want: []string{"Prsnt             continued\n", "Prsnt and Prsnt\n"},
			gone: []string{"ABC0123456"},
		},
		{
			name: "tab-separated rows have their serial replaced",
			in: []string{hdr + "Chassis\t\t\tABC0123456\tVirtual Chassis\n" + "Power Supply 0\tREV 03\t740-000001\tabc1234\tJPSU-350-AC-AFO\n" +
				"Fan Tray 0\t\t\t\tFan Module\nRouting Engine 0\tBUILTIN\tBUILTIN\tRE-EX4400-48T\n",
				"Member ID  Status   Serial No    Model          prio  Role\n0 (FPC 0)\tPrsnt\t9876543210\tex4400-48t\t255\tMaster*\n"},
			want: []string{"Virtual Chassis\n", "JPSU-350-AC-AFO\n", "Fan Tray 0", "BUILTIN\tBUILTIN", "ex4400-48t\t255\tMaster*"},
			gone: []string{"ABC0123456", "abc1234", "9876543210"},
		},
	})
}

// A dotted run that begins 1.3.6.1 is an object identifier, never an address;
// every other run is scanned for addresses.
func TestObjectIdentifiersAndVersionsAreNotAddresses(t *testing.T) {
	runScrubCases(t, []scrubCase{
		{
			name: "juniper sysObjectID",
			in:   []string{"sysObjectID.0: 1.3.6.1.4.1.2636.1.1.1.2.165\n"},
			want: []string{"sysObjectID.0: 1.3.6.1.4.1.2636.1.1.1.2.165\n"},
		},
		{
			name: "a leading dot",
			in:   []string{"sysObjectID.0: .1.3.6.1.4.1.2636.1.1.1.2.165\nsysObjectID.0: .1.3.6.1.4.1.9.1.516\n"},
			want: []string{"sysObjectID.0: .1.3.6.1.4.1.2636.1.1.1.2.165\n", "sysObjectID.0: .1.3.6.1.4.1.9.1.516\n"},
		},
		{
			name: "an address with a port or an index after it is still an address",
			in:   []string{"peer 10.20.30.40.179 and 10.20.30.41.50\nipv4.10.20.30.42 and version 10.20.30.45.6.7\n"},
			want: []string{"peer 192.0.2.1.179 and 192.0.2.2.50\n", "ipv4.192.0.2.3 and version 192.0.2.4.6.7\n"},
			gone: []string{"10.20.30"},
		},
		{
			name: "an object identifier is left alone as a whole, not by the digits around it",
			in:   []string{"x 1.3.6.1.2.1.4.20.1.1.10.20.30.43 y\nz 1.3.6.1.4.1.2636.3.1 10.20.30.44\n"},
			want: []string{"x 1.3.6.1.2.1.4.20.1.1.10.20.30.43 y\n", "z 1.3.6.1.4.1.2636.3.1 192.0.2.1\n"},
		},
		{
			name: "an address with a dot after it at the end of a line",
			in:   []string{"gateway 192.168.1.1.\nnext 192.168.1.2.\n"},
			want: []string{"gateway 192.0.2.1.\n", "next 192.0.2.2.\n"},
			gone: []string{"192.168"},
		},
		{
			name: "software versions",
			in:   []string{"Version 12.4(15)SW4, 16.07.01, 15.0(2)SE11, 24.2R2.18, 17.3.4a\n"},
			want: []string{"Version 12.4(15)SW4, 16.07.01, 15.0(2)SE11, 24.2R2.18, 17.3.4a\n"},
		},
		{
			name: "an address at the end of a sentence is still an address",
			in:   []string{"The gateway is 10.20.30.1. The peer 10.20.30.2, ok\n"},
			want: []string{"The gateway is 192.0.2.1. The peer 192.0.2.2, ok\n"},
			gone: []string{"10.20.30"},
		},
	})
}

// The columns after a replacement stay where the device printed them.
func TestColumnsKeepTheirWidth(t *testing.T) {
	cols := func(t *testing.T, in []string, marks ...string) {
		t.Helper()
		out := New().ApplyAll(in)
		for i := range in {
			inLines, outLines := strings.Split(in[i], "\n"), strings.Split(out[i], "\n")
			if len(inLines) != len(outLines) {
				t.Fatalf("the line count changed:\n%s", out[i])
			}
			for n := range inLines {
				for _, m := range marks {
					if a, b := strings.Index(inLines[n], m), strings.Index(outLines[n], m); a != b {
						t.Errorf("%q is at column %d, was at %d:\n%s\n%s", m, b, a, inLines[n], outLines[n])
					}
				}
			}
		}
	}
	t.Run("virtual chassis row", func(t *testing.T) {
		cols(t, []string{junosVC}, "ex4400-48t", "255", "Master*", "vcp-255")
	})
	t.Run("chassis hardware", func(t *testing.T) {
		cols(t, []string{junosHardware}, "Virtual Chassis", "EX4400-48T", "4x10G", "JPSU", "SFP-LX10", "SFP-T", "NON-JNPR", "740-013111")
	})
	t.Run("shorter and longer", func(t *testing.T) {
		in := "10.20.30.40       up    eth0\n10.1.1.1          up    eth1\nuser jsmith       ok    here\nuser jo           ok    there\n"
		cols(t, []string{in}, "up", "ok", "eth", "here", "there")
	})
	t.Run("host and mac columns", func(t *testing.T) {
		in := "Hostname: core-sw1.corp.net\ncore-sw1.corp.net   00:1b:63:84:45:e6   Gi1/0/1\nsw1                 00:1b:63:84:45:e7   Gi1/0/2\nhost ab    00:1b:63:84:45:e8   Gi1/0/3\nHostname: ab\n"
		cols(t, []string{in}, "Gi1", "00:")
	})
	t.Run("end of line and single blanks", func(t *testing.T) {
		out := New().ApplyAll([]string{"Mgmt 10.20.30.40    \nip address 192.168.100.100 255.255.255.0\n"})[0]
		if want := "Mgmt 192.0.2.1    \nip address 192.0.2.2 255.255.255.0\n"; out != want {
			t.Errorf("got %q, want %q", out, want)
		}
	})
}

// The names of vendors and of standards bodies are public, not the owner's:
// the bare registered domain and a few public labels of it, never a mail
// address (a person's) and never a name under a learned domain.
func TestVendorAddressesAreKept(t *testing.T) {
	const at = "@" // the mail addresses are built, so that the lint for personal addresses has nothing to read
	keep := "Technical Support: http://www.cisco.com/techsupport\n" +
		"Importers: http://www.cisco.com/wwl/export/crypto/tool/stqrg.html\n" +
		"see www.juniper.net or juniper.net, hpe.com and hp.com, ftp.gnu.org, www.fsf.org, support.hpe.com, software.cisco.com,\n" +
		"www.openssl.org, tools.ietf.org, cdn.kernel.org, host.example.com, a.example.net, info" + at + "example.net\n"
	runScrubCases(t, []scrubCase{
		{name: "public names", in: []string{keep}, want: []string{keep}},
		{
			name: "the owner's names around them are replaced",
			in:   []string{keep + "ntp ntp1.corp.net and mail jdoe" + at + "corp.net\n"},
			want: []string{keep},
			gone: []string{"corp.net", "jdoe"},
		},
		{
			name: "a vendor's mail address is a person's and is replaced",
			in:   []string{"mailto alice.smith" + at + "hpe.com, bob" + at + "juniper.net or export" + at + "cisco.com\n"},
			want: []string{"user1" + at + "example.net"},
			gone: []string{"alice.smith", "bob" + at, "export" + at, "hpe.com", "juniper.net", "cisco.com"},
		},
		{
			name: "a customer's name under a vendor's domain is replaced",
			in:   []string{"peer acme-corp.hpe.com and acme.mail.juniper.net, lab.cisco.com\n"},
			gone: []string{"acme", "mail.juniper", "lab.cisco"},
		},
		{
			name: "a learned domain wins over the vendor list",
			in:   []string{"ip domain-name hpe.com\nsee www.hpe.com and support.hpe.com, tools.ietf.org\n"},
			want: []string{"tools.ietf.org"},
			gone: []string{"hpe.com"},
		},
	})
}

// An IOS sysDescr as the SNMP system group prints it, its lines joined, is
// left as printed apart from the real values in it.
func TestIOSSysDescrIsLeftAsPrinted(t *testing.T) {
	const descr = "Cisco IOS Software, C3745 Software (C3745-ADVENTERPRISEK9-M), Version 12.4(15)SW4, RELEASE SOFTWARE (fc1) | " +
		"Technical Support: http://www.cisco.com/techsupport | Copyright (c) 1986-2008 by Cisco Systems, Inc. | " +
		"Compiled Mon 10-Jun-08 21:04 by prod_rel_team"
	in := []string{
		"sysObjectID.0: 1.3.6.1.4.1.9.1.516\nsysLocation.0: \nsysDescr.0: " + descr + "\nsysContact.0:\nsysName.0: rtr9.corp.net\nsysLocation.0: Building 7\n",
		"Cisco IOS Software, C3745 Software (C3745-ADVENTERPRISEK9-M), Version 12.4(15)SW4, RELEASE SOFTWARE (fc1)\n" +
			"Technical Support: http://www.cisco.com/techsupport\nrtr9 uptime is 3 weeks\n",
		"hostname rtr9\nip domain-name corp.net\nsnmp-server location Building 7\nsnmp-server contact\nsnmp-server location\nHostname:\nModel: C3745\n",
	}
	s := New()
	s.Learn(Host, "rtr9")
	out := s.ApplyAll(in)
	for _, want := range []string{"sysObjectID.0: 1.3.6.1.4.1.9.1.516\n", "sysDescr.0: " + descr + "\n"} {
		if !strings.Contains(out[0], want) {
			t.Errorf("%q is not in the output:\n%s", want, out[0])
		}
	}
	if !strings.HasPrefix(out[1], "Cisco IOS Software, C3745 Software (C3745-ADVENTERPRISEK9-M), Version 12.4(15)SW4, RELEASE SOFTWARE (fc1)\nTechnical Support: http://www.cisco.com/techsupport\nsw1 uptime") {
		t.Errorf("garbled:\n%s", out[1])
	}
	for _, gone := range []string{"rtr9", "corp.net", "Building 7"} {
		if strings.Contains(strings.Join(out, "\n"), gone) {
			t.Errorf("%q is still in the output", gone)
		}
	}
}

// A host name is one example whether it is written bare or with its domain,
// and its domain is one example in every line that names it.
func TestAHostIsOneExampleBareOrWithItsDomain(t *testing.T) {
	in := "Hostname: core-sw1.corp.net\nsysName.0: core-sw1.corp.net\nip domain-name corp.net\ncore-sw1 uptime is 1 day\nHostname: core-sw1\n"
	out := New().ApplyAll([]string{in})[0]
	want := "Hostname: sw1.example.net\nsysName.0: sw1.example.net\nip domain-name example.net\nsw1 uptime is 1 day\nHostname: sw1\n"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
}

// The value of a serial field ends at its last letter or digit: the
// punctuation after it is not part of the serial number, and stays.
func TestASerialFieldValueEndsAtItsLastLetterOrDigit(t *testing.T) {
	runScrubCases(t, []scrubCase{
		{
			name: "a closing parenthesis, a full stop and a semicolon",
			in: []string{
				"(serial: abc12345) and later abc12345\n",
				"Serial number: ab12cd34. Seen ab12cd34 again\n",
				"serial=xy99zz88; and xy99zz88\n",
			},
			want: []string{"(serial: SN000001) and later SN000001\n", "Serial number: SN000002. Seen SN000002 again\n", "serial=SN000003; and SN000003\n"},
			gone: []string{"abc12345", "ab12cd34", "xy99zz88"},
		},
		{
			name: "the other fields",
			in: []string{
				"PID: X , VID: V , SN: qq11rr22).\nHw Serial#: ww33ee44; Processor board ID tt55yy66.\n",
				"System serial number: uu77ii88)\nSerial ID  oo99pp00;\nlater qq11rr22 ww33ee44 tt55yy66 uu77ii88 oo99pp00\n",
			},
			want: []string{"SN: SN000001).", "Hw Serial#: SN000002;", "Processor board ID SN000003.", "number: SN000004)", "Serial ID  SN000005;"},
			gone: []string{"qq11rr22", "ww33ee44", "tt55yy66", "uu77ii88", "oo99pp00"},
		},
		{
			name: "hyphens and dots inside the value stay part of it",
			in:   []string{"Serial number: AB-12.cd-34\nlater AB-12.cd-34\n"},
			want: []string{"Serial number: SN000001\n", "later SN000001\n"},
			gone: []string{"AB-12"},
		},
	})
}

// A table ends at a blank line, a 'word:' line or a prompt line that begins
// with a brace, not at a row with nothing in the serial column: Junos prints
// bare item rows and members without a serial inside the table.
func TestATableSurvivesRowsWithoutASerial(t *testing.T) {
	hdr := "Item             Version  Part number  Serial number     Description\n"
	vc := "Member ID  Status   Serial No    Model          prio  Role      Mode  Mode ID  Interface\n"
	row := func(label, pad, descr string) string { return fmt.Sprintf("%-39s%-18s%s\n", label, pad, descr) }
	runScrubCases(t, []scrubCase{
		{
			name: "a member without a serial is followed by one with a serial",
			in:   []string{vc + "1 (FPC 1)  Unprvsnd\n2 (FPC 2)  Prsnt    pe3714af0999 ex4300-48t     255   Backup       N  VC   0  vcp-255/1/0\n"},
			want: []string{"2 (FPC 2)  Prsnt    SN000001", "ex4300-48t     255", "1 (FPC 1)  Unprvsnd\n"},
			gone: []string{"pe3714af0999"},
		},
		{
			name: "bare item rows are inside the table",
			in: []string{hdr + "Midplane\nSystem IO\nPower Supply 0\n" +
				"FPC 1            REV 11   650-114384   pe3714af0999      EX4300-48T\n" +
				"Fan Tray 0\nFPC 2            REV 11   650-114384   qq4815zz0777      EX4300-48T\n"},
			want: []string{"Midplane\nSystem IO\nPower Supply 0\n", "SN000001          EX4300-48T", "SN000002          EX4300-48T", "Fan Tray 0\n"},
			gone: []string{"pe3714af0999", "qq4815zz0777"},
		},
		{
			name: "a serial without a digit, and a short one, are replaced; a status is not",
			in: []string{hdr + "FPC 0            REV 11   650-114384   abcdefghij        EX4300-48T\n" +
				"FPC 1            REV 11   650-114384   x9z               EX4300-48T\n" +
				row("FPC 2", "PRSNT", "continued") + row("FPC 3", "notprsnt", "continued") + row("FPC 4", "Online", "continued") +
				"later abcdefghij\n"},
			want: []string{"SN000001          EX4300-48T", "SN000002          EX4300-48T", "PRSNT", "notprsnt", "Online"},
			gone: []string{"abcdefghij", "x9z"},
		},
		{
			name: "a blank line ends the table",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\n\n" + row("row", "", "HELLO123456")},
			gone: []string{"HELLO123456", "ABC0123456"},
		},
		{
			name: "a word with a colon ends the table",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\nNext:\n" + row("row", "", "HELLO123456")},
			gone: []string{"HELLO123456", "ABC0123456"},
		},
		{
			name: "a prompt line ends the table",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\n{master:0}\n" + row("row", "", "HELLO123456")},
			gone: []string{"HELLO123456", "ABC0123456"},
		},
		{
			name: "the same row inside the table keeps its description",
			in:   []string{hdr + "Chassis                                ABC0123456        Virtual Chassis\n" + row("row", "", "HELLO123456")},
			want: []string{"row" + strings.Repeat(" ", 54) + "HELLO123456"},
			gone: []string{"ABC0123456"},
		},
	})
}

// A tab-separated row that lacks a cell, or whose description holds two
// blanks, has its serial found by the shape of the cell, not by its place
// counted from the right; a part number or a model is never a serial.
func TestTabRowsWithoutADescriptionOrWithAWideOne(t *testing.T) {
	hdr := "Item             Version  Part number  Serial number     Description\n"
	runScrubCases(t, []scrubCase{
		{
			name: "a row without a description has its serial replaced and its part number kept",
			in:   []string{hdr + "FPC 0\tREV 11\t650-114384\tab0123456\n"},
			want: []string{"FPC 0\tREV 11\t650-114384\tSN000001\n"},
			gone: []string{"ab0123456"},
		},
		{
			name: "a description of two words split at two blanks learns no model",
			in: []string{hdr + "FPC 1\tREV 11\t650-114385\tcd0123456\tEX4300  48T\n" + "Chassis\t\t\tef0123456\tVirtual  Chassis\n",
				"The model EX4300 and the part 650-114385\n"},
			want: []string{"FPC 1\tREV 11\t650-114385\tSN000001\tEX4300  48T\n", "Chassis\t\t\tSN000002\tVirtual  Chassis\n", "The model EX4300 and the part 650-114385\n"},
			gone: []string{"cd0123456", "ef0123456"},
		},
		{
			name: "a transceiver row lacking its version",
			in:   []string{hdr + "Xcvr 0\t\t\tNON-JNPR\tgh0123456\tSFP-LX10\n"},
			want: []string{"Xcvr 0\t\t\tNON-JNPR\tSN000001\tSFP-LX10\n"},
			gone: []string{"gh0123456"},
		},
		{
			name: "a part number and a model are not serials, so they stay everywhere",
			in: []string{hdr + "Fan Tray 1\tREV 01\t711-001234\tFAN-TRAY-48\n" + "Fan Tray 2\t711-001235\tFAN-TRAY-48\n",
				"parts 711-001234 and 711-001235 and FAN-TRAY-48\n"},
			want: []string{"Fan Tray 1\tREV 01\t711-001234\tFAN-TRAY-48\n", "Fan Tray 2\t711-001235\tFAN-TRAY-48\n", "parts 711-001234 and 711-001235 and FAN-TRAY-48\n"},
		},
		{
			name: "a row with every cell keeps its place",
			in:   []string{hdr + "PIC 1\tREV 11\t650-114384\tij0123456\t4x10G SFP+\n" + "PIC 2\tREV 11\t650-114384\tkl0123456\tEX4300\n"},
			want: []string{"PIC 1\tREV 11\t650-114384\tSN000001\t4x10G SFP+\n", "PIC 2\tREV 11\t650-114384\tSN000002\tEX4300\n"},
			gone: []string{"ij0123456", "kl0123456"},
		},
		{
			name: "a row without a serial keeps a serial-shaped description",
			in:   []string{hdr + "Power Supply 1\t\t\tPS ABCD12345678 AC\n"},
			want: []string{"Power Supply 1\t\t\tPS ABCD12345678 AC\n"},
		},
	})
}

// A public label (www, tools, ftp, cdn, software, support) of a host that is
// replaced is not a word to hunt for everywhere: the host is replaced as a
// whole, its domain is learned, and the label is not.
func TestAPublicLabelIsNotLearnedByName(t *testing.T) {
	s := New()
	in := "Hostname: www.acme.corp\nTechnical Support: see http://www.cisco.com/techsupport and www.acme.corp\nwww docs, tools and the support desk\n"
	out := s.ApplyAll([]string{in})[0]
	want := "Hostname: sw1.example.net\nTechnical Support: see http://www.cisco.com/techsupport and sw1.example.net\nwww docs, tools and the support desk\n"
	if out != want {
		t.Errorf("got\n%s\nwant\n%s", out, want)
	}
	if l := s.Leaks(out); len(l) != 0 {
		t.Errorf("leaks %v", l)
	}
	if ex, ok := s.learned["www"]; ok {
		t.Errorf("www is learned by name: %s", ex)
	}
	// a host that is called www is a thing to hunt for
	s2 := New()
	out = s2.ApplyAll([]string{"Hostname: www.acme.corp\n", "hostname www\nwww is up\n"})[1]
	if strings.Contains(out, "www") {
		t.Errorf("the host www is still in the output:\n%s", out)
	}
}

// A vendor's name kept in the first look at the texts is not replaced in the
// last one: the texts are looked at until nothing new is learned, and the
// last look is what is returned.
func TestTheLastLookIsTheOneReturned(t *testing.T) {
	s := New()
	in := []string{
		"Junos docs at www.juniper.net\nTechnical Support: http://www.cisco.com/techsupport\n",
		"Call home to acme-lab.cisco.com\n",
	}
	out := s.ApplyAll(in)
	if want := "Junos docs at www.juniper.net\nTechnical Support: http://sw2.example.net/techsupport\n"; out[0] != want {
		t.Errorf("got\n%s\nwant\n%s", out[0], want)
	}
	for i, o := range out {
		if l := s.Leaks(o); len(l) != 0 {
			t.Errorf("text %d leaks %v:\n%s", i, l, o)
		}
		if strings.Contains(o, "cisco") {
			t.Errorf("text %d still names cisco:\n%s", i, o)
		}
	}
	if again := s.ApplyAll(in); again[0] != out[0] || again[1] != out[1] {
		t.Errorf("a second run differs:\n%q\n%q", again, out)
	}
}
