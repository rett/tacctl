package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/testpty"
)

// The vendor from the device by SNMP (0.2.17 D260): 'device add', 'device
// check', 'device vendor --from-device' and 'device discover --snmp' with a
// stub getter. The sysDescr texts are synthetic (see internal/snmp's
// TestDetectVendor), except idWTI, which is a capture of a lab device.

var (
	idIOS     = snmp.Identity{ObjectID: "1.3.6.1.4.1.9.1.9999", Descr: "Cisco IOS Software, SYNTHETIC test platform, Version 0.0(0)"}
	idCisco9  = snmp.Identity{ObjectID: "1.3.6.1.4.1.9.1.9997", Descr: "Cisco SYNTHETIC security appliance, Version 0.0"}
	idJunos   = snmp.Identity{ObjectID: "1.3.6.1.4.1.2636.1.1.1.9999", Descr: "SYNTHETIC router, kernel JUNOS 0.0"}
	idWTI     = snmp.Identity{ObjectID: "1.3.6.1.4.1.2634.1.8", Descr: "Linux localhost 5.4.0 #1 Tue Mar 24 13:05:15 PDT 2026 armv7l"}
	idUnknown = snmp.Identity{ObjectID: "1.3.6.1.4.1.99999.1", Descr: "SYNTHETIC appliance"}
)

// ttyBox gives the sandbox a terminal and returns the side the answers are
// typed into.
func ttyBox(t *testing.T, sb *sandbox) func(string) {
	t.Helper()
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	sb.tty = slave
	return func(s string) {
		t.Helper()
		if _, err := master.WriteString(s); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDeviceAddVendorDetection(t *testing.T) {
	sb := newSandbox(t, true)
	sb.snmp = &stubSNMP{
		names: map[string]string{"192.0.2.1": "sw1", "192.0.2.2": "sw2", "192.0.2.3": "sw3", "192.0.2.4": "fw4", "192.0.2.5": "rtr5",
			"192.0.2.7": "rtr7", "192.0.2.8": "pdu8"},
		ids: map[string]snmp.Identity{"192.0.2.1": idIOS, "192.0.2.2": idIOS, "192.0.2.3": idIOS, "192.0.2.4": idCisco9, "192.0.2.5": idJunos,
			"192.0.2.7": idJunos, "192.0.2.8": idWTI},
	}
	says := "  The device says it is Cisco IOS Software, vendor cisco (SNMP sysObjectID 1.3.6.1.4.1.9.1.9999, " +
		"sysDescr 'Cisco IOS Software, SYNTHETIC test platform, Version 0.0(0)').\n"
	// --vendor agrees: the line, nothing more.
	out := sb.dev("", "add", "sw1", "192.0.2.1", "--no-host-key", "--vendor", "cisco")
	if sb.code != 0 || !strings.Contains(out, says) || strings.Contains(out, "!") {
		t.Errorf("agreeing: %d %q", sb.code, out)
	}
	// --vendor disagrees: a warning with the fix; registered as given.
	out = sb.dev("", "add", "sw2", "192.0.2.2", "--no-host-key", "--vendor", "juniper")
	if sb.code != 0 || !strings.Contains(out, says+"  ! It is registered as juniper: tacctl device vendor sw2 cisco\n") ||
		!strings.Contains(sb.devices(), "sw2: {address: 192.0.2.2, vendor: juniper}") {
		t.Errorf("disagreeing: %d %q\n%s", sb.code, out, sb.devices())
	}
	// No --vendor, no terminal: only printed; registered as other.
	out = sb.dev("", "add", "sw3", "192.0.2.3", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "registered: 192.0.2.3, other.") || !strings.Contains(out, says+"  ! It is registered as other: tacctl device vendor sw3 cisco\n") {
		t.Errorf("absent --vendor: %d %q", sb.code, out)
	}
	// An enterprise-9 answer that is not IOS names no vendor.
	out = sb.dev("", "add", "fw4", "192.0.2.4", "--no-host-key")
	if !strings.Contains(out, "  The device names no vendor tacctl reads: Cisco device, sysDescr not recognised as IOS or IOS-XE (SNMP sysObjectID 1.3.6.1.4.1.9.1.9997, ") ||
		strings.Contains(out, "!") {
		t.Errorf("enterprise 9, not IOS: %q", out)
	}
	// Junos is named: agreeing, the line only.
	out = sb.dev("", "add", "rtr5", "192.0.2.5", "--no-host-key", "--vendor", "juniper")
	if sb.code != 0 || !strings.Contains(out, "  The device says it is Junos, vendor juniper (SNMP sysObjectID 1.3.6.1.4.1.2636.1.1.1.9999, "+
		"sysDescr 'SYNTHETIC router, kernel JUNOS 0.0').\n") || strings.Contains(out, "!") {
		t.Errorf("Junos agreeing: %d %q", sb.code, out)
	}
	// Junos and WTI left at other: the warning with the fix, and the notice.
	out = sb.dev("", "add", "rtr7", "192.0.2.7", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "registered: 192.0.2.7, other.") || !strings.Contains(out, "  The device says it is Junos, vendor juniper (") ||
		!strings.Contains(out, "  ! It is registered as other: tacctl device vendor rtr7 juniper\n") {
		t.Errorf("Junos left at other: %d %q", sb.code, out)
	}
	out = sb.dev("", "add", "pdu8", "192.0.2.8", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "  The device says it is WTI, vendor wti (SNMP sysObjectID 1.3.6.1.4.1.2634.1.8, sysDescr 'Linux localhost 5.4.0 ") ||
		!strings.Contains(out, "  ! It is registered as other: tacctl device vendor pdu8 wti\n") {
		t.Errorf("WTI left at other: %d %q", sb.code, out)
	}
	// The vendor named is kept: sw2 and sw3 have the notice, sw1 not.
	out = sb.dev("", "notice", "list")
	for _, want := range []string{
		"vendor-differs: 192.0.2.2 says it is cisco (SNMP, read ", "registered juniper; set it from the device: 'tacctl device vendor sw2 --from-device'",
		"vendor-differs: 192.0.2.3 says it is cisco",
		"vendor-differs: 192.0.2.7 says it is juniper", "vendor-differs: 192.0.2.8 says it is wti",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("notices lack %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "192.0.2.1 says") || strings.Contains(out, "192.0.2.5 says") {
		t.Errorf("a matching vendor raised a notice:\n%s", out)
	}
	// It cannot be acknowledged.
	sb.dev("", "notice", "sw3", "ack", "vendor-differs")
	if sb.code == 0 {
		t.Error("vendor-differs acknowledged")
	}
	// A device that does not answer: nothing about the vendor.
	out = sb.dev("", "add", "sw6", "192.0.2.6", "--no-host-key")
	if sb.code != 0 || strings.Contains(out, "vendor") && strings.Contains(out, "says") {
		t.Errorf("no answer: %d %q", sb.code, out)
	}
}

// At a terminal, without --vendor: one y/N, default no.
func TestDeviceAddVendorQuestion(t *testing.T) {
	sb := newSandbox(t, true)
	sb.snmp = &stubSNMP{names: map[string]string{"192.0.2.1": "sw1", "192.0.2.2": "sw2"},
		ids: map[string]snmp.Identity{"192.0.2.1": idIOS, "192.0.2.2": idIOS}}
	typeIn := ttyBox(t, sb)
	typeIn("y\n")
	out := sb.dev("", "add", "sw1", "192.0.2.1", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "registered: 192.0.2.1, cisco.") || !strings.Contains(sb.stderr(), "  Register it as cisco? [y/N]: ") ||
		strings.Contains(out, "!") {
		t.Errorf("taken: %d %q %q", sb.code, out, sb.stderr())
	}
	if strings.Count(out, "The device says it is") != 1 {
		t.Errorf("the vendor line twice:\n%s", out)
	}
	typeIn("\n")
	out = sb.dev("", "add", "sw2", "192.0.2.2", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "registered: 192.0.2.2, other.") || !strings.Contains(out, "! It is registered as other: tacctl device vendor sw2 cisco") {
		t.Errorf("declined: %d %q", sb.code, out)
	}
}

// 'device add <address>': the vendor folded into the name's question, and a
// name asked for when the device gives none that can be offered.
func TestDeviceAddOfferedNameAndVendor(t *testing.T) {
	sb := newSandbox(t, true)
	usage := "Usage: tacctl device add [<name>] <address> [options]"
	stub := &stubSNMP{names: map[string]string{"192.0.2.10": "SW10.site-a.example", "192.0.2.11": "WTI"},
		ids: map[string]snmp.Identity{"192.0.2.10": idIOS, "192.0.2.11": idUnknown}}
	sb.snmp = stub
	// Without a terminal a name that cannot be discovered is refused, after
	// the name read alone.
	sb.dev("", "add", "192.0.2.11")
	sb.expect(1, "", "No name given; the device calls itself 'WTI' (SNMP sysName), but it is a generic name.")
	sb.expect(1, "", usage)
	if n := stub.calls.Load(); n != 1 {
		t.Errorf("%d reads before the refusal, want 1 (the name)", n)
	}
	sb.dev("", "add", "192.0.2.12")
	sb.expect(1, "", "No name given, and no SNMP answer from 192.0.2.12 to offer one.")
	if sb.devices() != "" {
		t.Fatalf("registered without a name:\n%s", sb.devices())
	}
	typeIn := ttyBox(t, sb)
	typeIn("y\n")
	out := sb.dev("", "add", "192.0.2.10", "--no-host-key")
	if sb.code != 0 || !strings.Contains(sb.stderr(), "Register 192.0.2.10 as 'sw10.site-a.example' (cisco)? [y/N]: ") ||
		!strings.Contains(out, "Device 'sw10.site-a.example' registered: 192.0.2.10, cisco.") || strings.Contains(sb.stderr(), "Register it as") {
		t.Errorf("folded: %d %q %q", sb.code, out, sb.stderr())
	}
	// With --vendor the question is the name's alone.
	sb.dev("", "remove", "sw10.site-a.example", "-y")
	typeIn("y\n")
	sb.dev("", "add", "192.0.2.10", "--no-host-key", "--vendor", "cisco")
	if sb.code != 0 || !strings.Contains(sb.stderr(), "Register 192.0.2.10 as 'sw10.site-a.example'? [y/N]: ") {
		t.Errorf("--vendor: %d %q", sb.code, sb.stderr())
	}
	// A generic sysName: the name is asked for, and checked as the add's.
	typeIn("pdu1\n")
	out = sb.dev("", "add", "192.0.2.11", "--no-host-key", "--vendor", "wti")
	if sb.code != 0 || !strings.Contains(out, "No name given; the device calls itself 'WTI' (SNMP sysName), but it is a generic name.") ||
		!strings.Contains(sb.stderr(), "The name to register 192.0.2.11 under (Enter registers nothing): ") ||
		!strings.Contains(out, "Device 'pdu1' registered: 192.0.2.11, wti.") ||
		!strings.Contains(out, "The device names no vendor tacctl reads: an unknown enterprise (99999)") {
		t.Errorf("typed: %d %q %q", sb.code, out, sb.stderr())
	}
	typeIn("switch\n")
	sb.dev("", "add", "192.0.2.12", "--no-host-key")
	sb.expect(1, "", "'switch' is a generic name")
	typeIn("\n")
	out = sb.dev("", "add", "192.0.2.12", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "Cancelled; nothing was registered.") || strings.Contains(sb.devices(), "192.0.2.12") {
		t.Errorf("Enter: %d %q", sb.code, out)
	}
	// A name typed after no answer: the device is not asked again.
	typeIn("sw12\n")
	before := stub.calls.Load()
	out = sb.dev("", "add", "192.0.2.12", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "Device 'sw12' registered: 192.0.2.12, other.") || stub.calls.Load()-before != 1 {
		t.Errorf("typed after no answer: %d, %d reads, %q", sb.code, stub.calls.Load()-before, out)
	}
}

// --pull without --vendor: refused once the device was read, before
// anything is registered, when no vendor the pull reads is taken.
func TestDeviceAddPullWaitsForTheVendor(t *testing.T) {
	sb := newSandbox(t, true)
	stub := &stubSNMP{names: map[string]string{"192.0.2.1": "sw1"}, ids: map[string]snmp.Identity{"192.0.2.1": idIOS}}
	sb.snmp = stub
	sb.cfgRun("", []string{"device", "add", "sw1", "192.0.2.1", "--no-host-key", "--pull"}, nil, "SUDO_USER=alice")
	sb.expect(1, "", "--pull reads the configuration, which needs --vendor cisco, juniper or wti.")
	if stub.calls.Load() == 0 || sb.devices() != "" {
		t.Errorf("reads %d, registry:\n%s", stub.calls.Load(), sb.devices())
	}
	// --vendor other is refused before anything is read. The first command
	// returned at its refusal with the device's location still being read in
	// the background: let that read end before the reads are counted.
	waitReadsQuiet(stub)
	before := stub.calls.Load()
	sb.cfgRun("", []string{"device", "add", "sw1", "192.0.2.1", "--no-host-key", "--vendor", "other", "--pull"}, nil, "SUDO_USER=alice")
	sb.expect(1, "", "--pull reads the configuration, which needs --vendor cisco, juniper or wti.")
	if stub.calls.Load() != before {
		t.Error("--vendor other --pull read the device")
	}
}

func TestDeviceCheckVendorRow(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw1", "192.0.2.1", "--no-host-key", "--no-lookup", "--vendor", "cisco")
	sb.dev("", "add", "sw2", "192.0.2.2", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw3", "192.0.2.3", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw4", "192.0.2.4", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw5", "192.0.2.5", "--no-host-key", "--no-lookup")
	sb.snmp = &stubSNMP{names: map[string]string{"192.0.2.1": "sw1", "192.0.2.2": "sw2", "192.0.2.3": "sw3", "192.0.2.5": "sw5"},
		ids:    map[string]snmp.Identity{"192.0.2.1": idIOS, "192.0.2.2": idIOS, "192.0.2.3": idUnknown},
		idErrs: map[string]error{"192.0.2.5": &snmp.AnswerError{Why: "the agent answered with error-status 5"}}}
	out := plain(sb.cfgRun("", []string{"device", "check", "--all"}, nil))
	for _, want := range []string{
		"Vendor:      cisco  (match: Cisco IOS Software)\n",
		"Vendor:      differs: device says cisco (Cisco IOS Software), registered other (tacctl device vendor sw2 --from-device)\n",
		"Vendor:      unknown: an unknown enterprise (99999) (SNMP sysObjectID 1.3.6.1.4.1.99999.1, sysDescr 'SYNTHETIC appliance')\n",
		"Vendor:      no answer\n",
		"Vendor:      the answer could not be read (the agent answered with error-status 5)\n",
		"Registered as other, the device names a vendor (1)\n",
		"  sw2  cisco (Cisco IOS Software): tacctl device vendor sw2 --from-device\n",
		"vendor-differs: 192.0.2.2 says it is cisco",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check lacks %q:\n%s", want, out)
		}
	}
	var js []map[string]any
	if err := json.Unmarshal([]byte(sb.cfgRun("", []string{"device", "check", "--all", "--json"}, nil)), &js); err != nil || len(js) != 5 {
		t.Fatalf("--json: %v %q", err, sb.out.String())
	}
	if js[0]["vendor_detected"] != "cisco" || js[0]["vendor_reason"] != "Cisco IOS Software" ||
		js[2]["vendor_detected"] != nil || js[2]["vendor_reason"] != "an unknown enterprise (99999)" ||
		js[3]["vendor_detected"] != nil || js[3]["vendor_error"] != "no answer" ||
		js[4]["vendor_error"] != "the answer could not be read (the agent answered with error-status 5)" {
		t.Errorf("--json: %v", js)
	}
	// One device: no report at the end.
	if out = plain(sb.cfgRun("", []string{"device", "check", "sw2"}, nil)); strings.Contains(out, "Registered as other") {
		t.Errorf("check <name> has the --all report:\n%s", out)
	}
}

func TestDeviceVendorFromDevice(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw1", "192.0.2.1", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "fw2", "192.0.2.2", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw3", "192.0.2.3", "--no-host-key", "--no-lookup", "--vendor", "cisco")
	sb.dev("", "add", "sw4", "192.0.2.4", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "rtr5", "192.0.2.5", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "pdu6", "192.0.2.6", "--no-host-key", "--no-lookup")
	sb.snmp = &stubSNMP{ids: map[string]snmp.Identity{"192.0.2.1": idIOS, "192.0.2.2": idCisco9, "192.0.2.3": idIOS,
		"192.0.2.5": idJunos, "192.0.2.6": idWTI}}
	vendorOf := func(name string) string {
		t.Helper()
		sb.dev("", "vendor", name)
		return strings.TrimSpace(sb.out.String())
	}
	// An ambiguous read is refused with the reason; nothing changes.
	sb.dev("", "vendor", "fw2", "--from-device", "-y")
	sb.expect(1, "", "The device names no vendor tacctl reads: Cisco device, sysDescr not recognised as IOS or IOS-XE (SNMP sysObjectID 1.3.6.1.4.1.9.1.9997")
	sb.expect(1, "", "Set it by hand: tacctl device vendor fw2 cisco|juniper|wti|other")
	if v := vendorOf("fw2"); v != "other" {
		t.Errorf("fw2 is %q", v)
	}
	// No answer.
	sb.dev("", "vendor", "sw4", "--from-device", "-y")
	sb.expect(1, "", "The vendor of 'sw4' (192.0.2.4) was not read: no answer. Nothing was changed.")
	// Already the device's.
	sb.dev("", "vendor", "sw3", "--from-device")
	sb.expect(0, "Device 'sw3' vendor is already cisco (Cisco IOS Software); nothing to change.", "")
	// Without a terminal or -y: refused, and the read is kept for the notice.
	sb.dev("", "vendor", "sw1", "--from-device")
	sb.expect(1, "  Device:   cisco (Cisco IOS Software; SNMP sysObjectID 1.3.6.1.4.1.9.1.9999", "Give -y to set the vendor of 'sw1' to cisco without a terminal.")
	if out := sb.dev("", "notice", "list"); !strings.Contains(out, "vendor-differs: 192.0.2.1 says it is cisco") {
		t.Errorf("notices:\n%s", out)
	}
	// -y sets it through the setter; the notice is gone.
	out := sb.dev("", "vendor", "sw1", "--from-device", "-y")
	if sb.code != 0 || !strings.Contains(out, "Device 'sw1' vendor set to cisco.") || vendorOf("sw1") != "cisco" {
		t.Errorf("-y: %d %q", sb.code, out)
	}
	if out := sb.dev("", "notice", "list"); strings.Contains(out, "192.0.2.1 says") {
		t.Errorf("notice after the set:\n%s", out)
	}
	// Junos and WTI are set the same way.
	out = sb.dev("", "vendor", "rtr5", "--from-device", "-y")
	if sb.code != 0 || !strings.Contains(out, "Device 'rtr5' vendor set to juniper.") || vendorOf("rtr5") != "juniper" {
		t.Errorf("Junos: %d %q", sb.code, out)
	}
	out = sb.dev("", "vendor", "pdu6", "--from-device", "-y")
	if sb.code != 0 || !strings.Contains(out, "Device 'pdu6' vendor set to wti.") || vendorOf("pdu6") != "wti" {
		t.Errorf("WTI: %d %q", sb.code, out)
	}
	// The usage of the flag.
	sb.dev("", "vendor", "sw1", "-y")
	sb.expect(1, "", "-y answers the question of --from-device.")
	sb.dev("", "vendor", "sw1", "cisco", "--from-device")
	sb.expect(1, "", "--from-device takes the device's name only.")
	// At a terminal: 'y' sets it.
	sb.dev("", "vendor", "sw1", "other")
	typeIn := ttyBox(t, sb)
	typeIn("y\n")
	out = sb.dev("", "vendor", "sw1", "--from-device")
	if sb.code != 0 || !strings.Contains(sb.stderr(), "Set the vendor to the device's? [y/N]: ") || vendorOf("sw1") != "cisco" {
		t.Errorf("terminal: %d %q %q", sb.code, out, sb.stderr())
	}
}

// 'device discover --snmp': the name and the vendor read into the add
// lines; without --snmp nothing is contacted.
func TestDeviceDiscoverSNMP(t *testing.T) {
	sb, script, _ := scanSandbox(t)
	stub := &stubSNMP{names: map[string]string{"203.0.113.50": "Edge-SW5.example", "203.0.113.77": "WTI"},
		ids: map[string]snmp.Identity{"203.0.113.50": idIOS, "203.0.113.77": idUnknown}}
	sb.snmp = stub
	out := sb.devScan("", script, "discover")
	if stub.calls.Load() != 0 || !strings.Contains(out, "    tacctl device add <name> 203.0.113.77\n") {
		t.Errorf("discover without --snmp: %d reads\n%s", stub.calls.Load(), out)
	}
	out = sb.devScan("", script, "discover", "--snmp")
	for _, want := range []string{
		"    tacctl device add edge-sw5.example 203.0.113.50 --vendor cisco\n",
		"    tacctl device add <name> 203.0.113.77    # SNMP: sysName 'WTI' is no name to offer; vendor: an unknown enterprise (99999)\n",
	} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("discover --snmp lacks %q:\n%s", want, out)
		}
	}
	sb.snmp = &stubSNMP{}
	out = sb.devScan("", script, "discover", "--snmp")
	if !strings.Contains(out, "    tacctl device add edge-sw5 203.0.113.50    # SNMP: no answer\n") {
		t.Errorf("no answer:\n%s", out)
	}
}

// A vendor change marks the last pull 'needs pull': diff and plan say to
// pull again instead of reading it in the new vendor's shape.
func TestVendorChangeNeedsPull(t *testing.T) {
	b := newPullBox(t)
	b.serve("juniper", "set system host-name x\n")
	b.addPull("192.168.1.20", "lab-j", "192.168.1.20", "--vendor", "juniper", "--no-lookup", "--pull")
	if b.sb.code != 0 {
		t.Fatalf("add --pull: %d %q", b.sb.code, b.sb.stderr())
	}
	b.run("device", "vendor", "lab-j", "cisco")
	if b.sb.code != 0 {
		t.Fatalf("vendor: %d %q", b.sb.code, b.sb.stderr())
	}
	if out := b.run("device", "config", "list"); !strings.Contains(out, "needs pull (vendor changed)") {
		t.Errorf("list:\n%s", out)
	}
	if out := b.run("device", "config", "list", "--stale"); !strings.Contains(out, "lab-j") {
		t.Errorf("list --stale:\n%s", out)
	}
	out := b.run("device", "config", "diff", "lab-j")
	if !strings.Contains(out, "needs pull (vendor changed): the last pull read it as juniper; pull it again: tacctl device config pull lab-j") {
		t.Errorf("diff: %d %q", b.sb.code, out)
	}
	out = b.run("device", "config", "plan", "lab-j")
	if !strings.Contains(out+b.sb.stderr(), "needs pull (the vendor changed: the last pull read it as juniper)") {
		t.Errorf("plan: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	// A failed pull keeps the vendor of the stored sections, and the mark.
	b.pw.pw = "not-the-password"
	b.run("device", "config", "pull", "lab-j")
	if rec, ok := b.records().Of("lab-j"); !ok || rec.Vendor != "juniper" || rec.Result == "ok" {
		t.Errorf("after a failed pull: %+v", rec)
	}
	if out := b.run("device", "config", "diff", "lab-j"); !strings.Contains(out, "needs pull (vendor changed): the last pull read it as juniper") {
		t.Errorf("diff after a failed pull: %q", out)
	}
	// So does an apply's record (a failed or a settled apply writes it).
	inv := b.invoke()
	run := &applyRun{inv: inv, store: inv.configStore()}
	if err := run.writeApplied(devreg.Entry{Device: devreg.Device{Name: "lab-j", Address: "192.168.1.20", Vendor: "cisco"}},
		devconf.Applied{At: inv.app.Knobs.Now(), By: "alice", Result: "failed"}); err != nil {
		t.Fatal(err)
	}
	if rec, ok := b.records().Of("lab-j"); !ok || rec.Vendor != "juniper" || rec.Applied == nil {
		t.Errorf("after an apply record: %+v", rec)
	}
	if out := b.run("device", "config", "diff", "lab-j"); !strings.Contains(out, "needs pull (vendor changed)") {
		t.Errorf("diff after an apply record: %q", out)
	}
	b.pw.pw = testPassword
	// Back to the vendor of the pull: compared again.
	b.run("device", "vendor", "lab-j", "juniper")
	if out := b.run("device", "config", "list"); strings.Contains(out, "needs pull") {
		t.Errorf("list after the vendor came back:\n%s", out)
	}
}

// waitReadsQuiet waits until the stub has been asked nothing for a while: a
// read that a command started and left running when it returned is done.
func waitReadsQuiet(stub *stubSNMP) {
	last, quiet := stub.calls.Load(), 0
	for i := 0; i < 200 && quiet < 5; i++ {
		time.Sleep(10 * time.Millisecond)
		if n := stub.calls.Load(); n != last {
			last, quiet = n, 0
		} else {
			quiet++
		}
	}
}
