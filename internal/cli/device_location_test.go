package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snmp"
	"github.com/rett/tacctl/internal/testpty"
)

// The device's own location (CHANGELOG 110): 'device add' stores the
// sysLocation it reads, 'device check' compares it, and 'device location
// <name> --from-device' stores it on request. The stub answers by address.

func TestDeviceAddReadsTheLocation(t *testing.T) {
	sb := newSandbox(t, true)
	stub := &stubSNMP{
		names: map[string]string{"10.99.0.1": "sw1", "10.99.0.2": "sw2", "10.99.0.3": "sw3", "10.99.0.4": "sw4", "10.99.0.5": "sw5"},
		locs:  map[string]string{"10.99.0.1": "  Site A, row 3  ", "10.99.0.2": "", "10.99.0.4": "Where? Here"},
	}
	sb.snmp = stub
	// Reported: stored, and said so.
	out := sb.dev("", "add", "sw1", "10.99.0.1", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "  Location: Site A, row 3 (read from the device)\n") ||
		!strings.Contains(sb.devices(), "location: 'Site A, row 3'") {
		t.Errorf("reported: %d %q\n%s", sb.code, out, sb.devices())
	}
	// Reported empty, no terminal: one hint line, nothing stored.
	out = sb.dev("", "add", "sw2", "10.99.0.2", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "  Location not set: tacctl device location sw2 '<text>'\n") || !strings.Contains(sb.devices(), "sw2: {address: 10.99.0.2, vendor: other}") {
		t.Errorf("empty: %d %q\n%s", sb.code, out, sb.devices())
	}
	// No answer to the location: nothing said.
	out = sb.dev("", "add", "sw3", "10.99.0.3", "--no-host-key")
	if sb.code != 0 || strings.Contains(out, "  Location") {
		t.Errorf("no answer: %d %q", sb.code, out)
	}
	// A value the registry rejects: shown, skipped.
	out = sb.dev("", "add", "sw4", "10.99.0.4", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "! The device reports the location 'Where? Here', which is not stored: The location may not contain '?'") ||
		!strings.Contains(out, "Location not set: tacctl device location sw4 '<text>'") || strings.Contains(sb.devices(), "Where") {
		t.Errorf("rejected: %d %q\n%s", sb.code, out, sb.devices())
	}
	// --snmp-location and --no-lookup read none.
	before := stub.calls.Load()
	out = sb.dev("", "add", "sw5", "10.99.0.5", "--no-host-key", "--snmp-location", "Mine")
	if sb.code != 0 || strings.Contains(out, "read from the device") || !strings.Contains(sb.devices(), "location: Mine") {
		t.Errorf("--snmp-location: %d %q", sb.code, out)
	}
	if got := stub.calls.Load() - before; got != 1 {
		t.Errorf("--snmp-location: %d reads, want 1 (the name)", got)
	}
	before = stub.calls.Load()
	sb.dev("", "add", "sw6", "10.99.0.6", "--no-host-key", "--no-lookup")
	if stub.calls.Load() != before {
		t.Error("--no-lookup read the device")
	}
	// SNMP not set up: no location line, no failure.
	sb.snmp = nil
	out = sb.dev("", "add", "sw7", "10.99.0.7", "--no-host-key")
	if sb.code != 0 || strings.Contains(out, "  Location") {
		t.Errorf("no SNMP: %d %q", sb.code, out)
	}
}

func TestDeviceAddOffersALocationAtATerminal(t *testing.T) {
	sb := newSandbox(t, true)
	sb.snmp = &stubSNMP{
		names: map[string]string{"10.99.0.1": "sw1", "10.99.0.2": "sw2", "10.99.0.3": "sw3"},
		locs:  map[string]string{"10.99.0.1": "", "10.99.0.2": "", "10.99.0.3": ""},
	}
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	sb.tty = slave
	// An answer is stored.
	if _, err := master.WriteString("Site D, shelf 1\n"); err != nil {
		t.Fatal(err)
	}
	out := sb.dev("", "add", "sw1", "10.99.0.1", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "  The device reports no location (sysLocation is empty).\n") || !strings.Contains(out, "  Location: Site D, shelf 1\n") ||
		!strings.Contains(sb.devices(), "location: 'Site D, shelf 1'") || !strings.Contains(sb.stderr(), "Enter one to store, or leave blank to skip: ") {
		t.Errorf("answered: %d %q %q\n%s", sb.code, out, sb.stderr(), sb.devices())
	}
	// Blank skips.
	if _, err := master.WriteString("\n"); err != nil {
		t.Fatal(err)
	}
	out = sb.dev("", "add", "sw2", "10.99.0.2", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "  Location not set: tacctl device location sw2 '<text>'\n") || !strings.Contains(sb.devices(), "sw2: {address: 10.99.0.2, vendor: other}") {
		t.Errorf("blank: %d %q", sb.code, out)
	}
	// An answer the registry rejects is not stored and does not fail the add.
	if _, err := master.WriteString("what?\n"); err != nil {
		t.Fatal(err)
	}
	out = sb.dev("", "add", "sw3", "10.99.0.3", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "! Not stored: The location may not contain '?'") || !strings.Contains(sb.devices(), "sw3: {address") {
		t.Errorf("rejected: %d %q", sb.code, out)
	}
}

func TestDeviceCheckLocationRow(t *testing.T) {
	sb := newSandbox(t, true)
	for i, loc := range []string{"Site A", "Site B", "", "Site D", "", "Site F"} {
		args := []string{"add", "sw" + string(rune('1'+i)), "10.99.0." + string(rune('1'+i)), "--no-host-key", "--no-lookup"}
		if loc != "" {
			args = append(args, "--snmp-location", loc)
		}
		sb.dev("", args...)
	}
	names := map[string]string{}
	for _, a := range []string{"10.99.0.1", "10.99.0.2", "10.99.0.3", "10.99.0.4", "10.99.0.5"} {
		names[a] = "x"
	}
	sb.snmp = &stubSNMP{names: names, locs: map[string]string{
		"10.99.0.1": "site a", "10.99.0.2": "Site Z", "10.99.0.3": "Site C", "10.99.0.4": "", "10.99.0.5": "",
	}}
	out := plain(sb.cfgRun("", []string{"device", "check", "--all"}, nil))
	for _, want := range []string{
		"Location:    site a  (match)\n",
		"Location:    differs: device 'Site Z', registry 'Site B'\n",
		"Location:    Site C  (device only: tacctl device location sw3 --from-device)\n",
		"Location:    Site D  (registry only: the device reports none)\n",
		"Location:    not set on the device or in the registry\n",
		"Location:    no answer\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("check lacks %q:\n%s", want, out)
		}
	}
	// Nothing is written.
	if got := sb.devices(); strings.Contains(got, "Site Z") || strings.Contains(got, "Site C") {
		t.Errorf("check wrote:\n%s", got)
	}
	var js []map[string]any
	if err := json.Unmarshal([]byte(sb.cfgRun("", []string{"device", "check", "--all", "--json"}, nil)), &js); err != nil || len(js) != 6 {
		t.Fatalf("--json: %v %d", err, len(js))
	}
	if js[0]["syslocation"] != "site a" || js[0]["syslocation_match"] != true || js[1]["syslocation_match"] != false ||
		js[2]["syslocation_match"] != nil || js[3]["syslocation"] != nil || js[3]["syslocation_error"] != "empty" ||
		js[5]["syslocation_error"] != "no answer" {
		t.Errorf("--json: %v", js)
	}
	// Without SNMP the reason stands in.
	sb.snmp = nil
	out = plain(sb.cfgRun("", []string{"device", "check", "sw1"}, nil))
	if !strings.Contains(out, "Location:    - (SNMP is not configured ('tacctl config snmp'))\n") {
		t.Errorf("not configured:\n%s", out)
	}
	// A name that does not answer is not asked for the location again.
	stub := &stubSNMP{}
	sb.snmp = stub
	sb.cfgRun("", []string{"device", "check", "sw1"}, nil)
	if stub.calls.Load() != 1 {
		t.Errorf("%d reads of a silent device, want 1", stub.calls.Load())
	}
}

func TestDeviceLocationFromDevice(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw1", "10.99.0.1", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw2", "10.99.0.2", "--no-host-key", "--no-lookup", "--snmp-location", "Old place")
	sb.dev("", "add", "sw3", "10.99.0.3", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw4", "10.99.0.4", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw5", "10.99.0.5", "--no-host-key", "--no-lookup", "--snmp-location", "Same")
	// SNMP not set up.
	sb.dev("", "location", "sw1", "--from-device")
	sb.expect(1, "", "Cannot read the location of 'sw1' from the device: SNMP is not configured ('tacctl config snmp').")
	sb.snmp = &stubSNMP{locs: map[string]string{"10.99.0.1": "Site A, row 3", "10.99.0.2": "New place", "10.99.0.3": "", "10.99.0.5": "Same", "10.99.0.6": "x?"},
		locErrs: map[string]error{"10.99.0.4": &snmp.ReportError{Name: "wrongDigest"}}}
	// Stored.
	sb.dev("", "location", "sw1", "--from-device")
	sb.expect(0, "Device 'sw1' location set to Site A, row 3 (read from the device).", "")
	if got := sb.dev("", "location", "sw1"); got != "Site A, row 3\n" {
		t.Errorf("location: %q", got)
	}
	// Empty: refused with the reason.
	sb.dev("", "location", "sw3", "--from-device")
	sb.expect(1, "", "reports no location (its sysLocation is empty). Nothing was changed.")
	sb.expect(1, "", "Set one with: tacctl device location sw3 '<text>'")
	// A report: the reason.
	sb.dev("", "location", "sw4", "--from-device")
	sb.expect(1, "", "No SNMP answer from 10.99.0.4 (wrongDigest (wrong authentication passphrase or protocol)), so the location of 'sw4' was not read.")
	// The same value: nothing to do.
	sb.dev("", "location", "sw5", "--from-device")
	sb.expect(0, "location is already 'Same'; nothing to change.", "")
	// A different one, no terminal, no -y: both shown, refused.
	out := sb.dev("", "location", "sw2", "--from-device")
	if !strings.Contains(out, "  Registry: Old place\n  Device:   New place\n") {
		t.Errorf("both values: %q", out)
	}
	sb.expect(1, "", "Give -y to replace it with the device's.")
	if got := sb.dev("", "location", "sw2"); got != "Old place\n" {
		t.Errorf("changed without -y: %q", got)
	}
	sb.dev("", "location", "sw2", "--from-device", "-y")
	sb.expect(0, "location set to New place (read from the device).", "")
	// Argument errors.
	sb.dev("", "location", "sw2", "text", "--from-device")
	sb.expect(1, "", "--from-device takes the device's name only.")
	sb.dev("", "location", "sw2", "-y")
	sb.expect(1, "", "-y answers the question of --from-device.")
	sb.dev("", "location", "nope", "--from-device")
	sb.expect(1, "", "Device 'nope' not found.")
	// A value the registry rejects.
	sb.dev("", "add", "sw6", "10.99.0.6", "--no-host-key", "--no-lookup")
	sb.dev("", "location", "sw6", "--from-device")
	sb.expect(1, "", "reports the location 'x?', which the registry does not accept")
	// At a terminal: asked.
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	defer func() { _ = master.Close(); _ = slave.Close() }()
	sb.tty = slave
	sb.snmp.(*stubSNMP).locs["10.99.0.2"] = "Newer place"
	if _, err := master.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	sb.dev("", "location", "sw2", "--from-device")
	sb.expect(0, "Aborted.", "Replace the registry's location with the device's? [y/N]: ")
	if got := sb.dev("", "location", "sw2"); got != "New place\n" {
		t.Errorf("declined but changed: %q", got)
	}
	if _, err := master.WriteString("y\n"); err != nil {
		t.Fatal(err)
	}
	sb.dev("", "location", "sw2", "--from-device")
	sb.expect(0, "location set to Newer place", "")
}

func TestDeviceLocationFromDeviceEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	sb.snmp = &stubSNMP{locs: map[string]string{"192.168.1.1": "Lab room", "10.99.0.1": "Prod room"}}
	sb.asEngineer("", "device", "location", "lab-sw", "--from-device")
	if sb.code != 0 || !strings.Contains(sb.out.String(), "location set to Lab room") {
		t.Errorf("own scope: %d %q %q", sb.code, sb.out.String(), sb.stderr())
	}
	sb.asEngineer("", "device", "location", "prod-sw", "--from-device")
	sb.expect(1, "", "Device 'prod-sw' not found.")
}
