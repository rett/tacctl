package devices

import (
	"strings"
	"testing"
)

// A device's own settings (D72 of docs/plans/0.2.4-plan.md) are said as
// such in the comments of the step: whose credentials, and whose ranges.
// The comment lines are the only difference to the scope's rendering.
func TestSNMPStepNamesTheDevicesOwnSettings(t *testing.T) {
	own := v2cAll
	own.CredFrom, own.RangesFrom = "device", "device"
	own.Ranges = []string{"192.0.2.0/24"}
	for vendor, build := range snmpBuilders() {
		got := build(own).Text
		scope := build(v2cAll).Text
		if !strings.Contains(got, "Credentials: this device's own (tacctl device snmp core-sw1 show --reveal).") {
			t.Errorf("%s: no note of the device's own credentials:\n%s", vendor, got)
		}
		if vendor != "wti" && !strings.Contains(got, "this device's own ranges") {
			t.Errorf("%s: no note of the device's own ranges:\n%s", vendor, got)
		}
		if strings.Contains(got, "Credentials: this scope's own") || strings.Contains(scope, "this device's own") {
			t.Errorf("%s: the notes are mixed up:\n%s\n---\n%s", vendor, got, scope)
		}
	}
	// The unnamed device says <name>; nothing else of the text changes.
	own.DeviceName = ""
	if got := CiscoSNMP(own).Text; !strings.Contains(got, "tacctl device snmp <name> show --reveal") {
		t.Errorf("unnamed:\n%s", got)
	}
	// The scope's text is what it was.
	if got := CiscoSNMP(v2cAll).Text; !strings.Contains(got, "the scope's ranges, then everything else") ||
		!strings.Contains(got, "Credentials: this scope's own (tacctl scope snmp lab show --reveal).") {
		t.Errorf("scope text:\n%s", got)
	}
}
