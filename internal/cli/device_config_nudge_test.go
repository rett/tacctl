package cli

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// The nudge and --apply of the registry setters (device_config_nudge.go):
// a setter that changes what is rendered says, from the stored pull alone,
// that the device's configuration would change; --apply is the superuser's
// and refuses before it changes anything.

const nudgeLine = "The configuration of lab-j would change: tacctl device config apply lab-j --check"

func TestSettersNudgeFromTheStoredPull(t *testing.T) {
	b := planBoxJunos(t)
	// no pull record: nothing is said
	out := b.run("device", "location", "lab-j", "Row 1")
	if b.sb.code != 0 || strings.Contains(out, "would change") {
		t.Fatalf("no pull: %d %q", b.sb.code, out)
	}
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	calls := len(b.sb.runner.Calls())
	// the nudge reads the stored pull: a dial of the device fails the test
	b.sb.hooks.deviceDial = func(context.Context, string, string) (net.Conn, error) {
		t.Error("a setter dialled the device")
		return nil, errors.New("no network in a nudge")
	}
	for _, args := range [][]string{
		{"device", "location", "lab-j", "Row 3"},
		{"device", "description", "lab-j", "Core", "switch"},
		{"device", "location", "lab-j", "clear"},
	} {
		out := b.run(args...)
		if b.sb.code != 0 || strings.Count(out, "would change") != 1 || !strings.Contains(out, nudgeLine+"\n") {
			t.Errorf("%v: %d %q", args, b.sb.code, out)
		}
	}
	// the nudge dials nothing: the fake runner saw no ssh and no network
	for _, c := range b.sb.runner.Calls()[calls:] {
		if c.Name != "logger" && c.Name != "ip" && c.Name != "id" {
			t.Errorf("the nudge ran %s %v", c.Name, c.Args)
		}
	}
	// a value that is already set changes nothing, and says nothing
	out = b.run("device", "description", "lab-j", "Core", "switch")
	if b.sb.code != 0 || strings.Contains(out, "would change") {
		t.Errorf("same value: %d %q", b.sb.code, out)
	}
	// what is not rendered says nothing about the configuration
	for _, args := range [][]string{
		{"device", "port", "lab-j", "2222"},
		{"device", "hostname", "lab-j", "lab-j.example.net"},
		{"device", "legacy-ssh", "lab-j", "enable"},
	} {
		out := b.run(args...)
		if b.sb.code != 0 || strings.Contains(out, "would change") {
			t.Errorf("%v: %d %q", args, b.sb.code, out)
		}
	}
	// a rename says the device's own host name is not planned
	out = b.run("device", "rename", "lab-j", "lab-j2")
	if b.sb.code != 0 || !strings.Contains(out, "The device's own host name is unchanged: tacctl does not plan it.") ||
		strings.Contains(out, "would change") {
		t.Errorf("rename: %d %q", b.sb.code, out)
	}
}

func TestSettersSayNothingWhenThePullAgrees(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
	b.serve("juniper", b.expected("lab-j"))
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	out := b.run("device", "location", "lab-j", "Row 3")
	if b.sb.code != 0 || strings.Contains(out, "would change") {
		t.Errorf("%d %q", b.sb.code, out)
	}
}

// --apply is refused before the registry is changed: no terminal, a lower
// tier, a device apply does not write to, and with no value.
func TestSetterApplyRefusesBeforeChanging(t *testing.T) {
	b := planBoxJunos(t)
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"device", "location", "lab-j", "Row 9", "--apply"}, "no terminal to confirm on"},
		{[]string{"device", "description", "lab-j", "Row 9", "--apply"}, "no terminal to confirm on"},
		{[]string{"device", "address", "lab-j", "192.168.1.99", "--apply"}, "no terminal to confirm on"},
		{[]string{"device", "location", "lab-j", "--apply"}, "--apply goes with a value to set"},
		{[]string{"device", "location", "lab-j", "--from-device", "--apply"}, "nothing to apply"},
		{[]string{"device", "config-syntax", "lab-j", "--apply"}, "--apply goes with a value to set"},
	} {
		b.run(c.args...)
		if b.sb.code == 0 || !strings.Contains(b.sb.stderr(), c.want) {
			t.Errorf("%v: %d %q (want %q)", c.args, b.sb.code, b.sb.stderr(), c.want)
		}
		if loc := strings.TrimSpace(b.run("device", "location", "lab-j")); loc != "-" {
			t.Errorf("%v changed the location: %q", c.args, loc)
		}
		if a := strings.TrimSpace(b.run("device", "address", "lab-j")); a != "192.168.1.20" {
			t.Errorf("%v changed the address: %q", c.args, a)
		}
	}
	// an unchanged value applies nothing (and needs no terminal)
	b.run("device", "description", "lab-j", "same")
	if out := b.run("device", "description", "lab-j", "same", "--apply"); b.sb.code != 0 || !strings.Contains(out, "Nothing changed, so nothing was applied.") {
		t.Errorf("unchanged: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
}

// asAlice runs tacctl as alice, a superuser, with no terminal.
func asAlice(sb *sandbox, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun("", args, nil, "SUDO_USER=alice"))
}

func TestSetterApplyRefusesNonJunosAndLowerTiers(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw-c", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "pdu-w", "192.168.1.7", "--vendor", "wti", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"device", "location", "sw-c", "Row 3", "--apply"}, "apply writes to Junos devices only in this release"},
		{[]string{"device", "location", "pdu-w", "Row 3", "--apply"}, "apply is not available for WTI units"},
		{[]string{"device", "config-syntax", "sw-c", "ios12", "--apply"}, "apply writes to Junos devices only in this release"},
	} {
		asAlice(sb, c.args...)
		if sb.code == 0 || !strings.Contains(sb.stderr(), c.want) || !strings.Contains(sb.stderr(), "Nothing was changed.") {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
	}
	if out := asAlice(sb, "device", "location", "sw-c"); strings.TrimSpace(out) != "-" {
		t.Errorf("location changed: %q", out)
	}
	if got := sb.devices(); strings.Contains(got, "Row 3") || strings.Contains(got, "ios12") {
		t.Errorf("registry changed:\n%s", got)
	}

	// an engineer: the setter is theirs, --apply is not
	eb := engineerSandbox(t)
	eb.asEngineer("", "device", "location", "lab-sw", "Row 3", "--apply")
	if eb.code == 0 || !strings.Contains(eb.stderr(), "which is for the superuser tier; yours is engineer. Nothing was changed.") {
		t.Errorf("engineer: %d %q", eb.code, eb.stderr())
	}
	if out := eb.asEngineer("", "device", "location", "lab-sw"); strings.TrimSpace(out) != "-" {
		t.Errorf("engineer changed the location: %q", out)
	}
}

// scopeWrites classifies a scope command line as a write of what the
// devices are rendered from.
func TestScopeWrites(t *testing.T) {
	for _, c := range []struct {
		verb string
		args []string
		want bool
	}{
		{"prefixes", []string{"lab", "add", "10.0.0.0/8"}, true},
		{"prefixes", []string{"lab", "remove", "10.0.0.0/8"}, true},
		{"prefixes", []string{"lab", "list"}, false},
		{"prefixes", []string{"lab"}, false},
		{"secret", []string{"lab", "set", "x"}, true},
		{"secret", []string{"lab", "generate"}, true},
		{"secret", []string{"lab", "show"}, false},
		{"mgmt-acl", []string{"lab", "add", "10.0.0.0/8"}, true},
		{"mgmt-acl", []string{"lab", "list"}, false},
		{"mgmt-acl", []string{"lab", "cisco-name"}, false},
		{"mgmt-acl", []string{"lab", "cisco-name", "ACL"}, true},
		{"snmp", []string{"lab", "show"}, false},
		{"snmp", []string{"lab", "community", "x"}, true},
		{"snmp", []string{"lab", "clients", "list"}, false},
		{"snmp", []string{"lab", "clients", "add", "10.0.0.0/8"}, true},
		{"snmp", []string{"lab", "clear"}, true},
		{"snmp", []string{"lab", "test", "sw"}, false},
		{"block", []string{"lab", "juniper", "list"}, false},
		{"block", []string{"lab", "juniper", "set", "snmp"}, true},
		{"block", []string{"lab", "cisco", "remove", "snmp"}, true},
		{"aaa-order", []string{"lab"}, false},
		{"aaa-order", []string{"lab", "local-first"}, true},
		{"protocols", []string{"lab", "list"}, false},
		{"protocols", []string{"lab", "set", "tacacs"}, true},
	} {
		if got := scopeWrites(c.verb, c.args); got != c.want {
			t.Errorf("scope %s %v: %v, want %v", c.verb, c.args, got, c.want)
		}
	}
}

func TestScopeChangeNudgesWhenAStoredPullWouldChange(t *testing.T) {
	b := planBoxJunos(t)
	const scope = "lab" // the box's device is covered by lab's prefix
	want := "The configuration of devices in scope " + scope + " would change: tacctl device config apply --scope " + scope + " --check"
	// not pulled: nothing
	out := b.run("scope", "mgmt-acl", scope, "add", "203.0.113.0/24")
	if b.sb.code != 0 || strings.Contains(out, "would change") {
		t.Fatalf("no pull: %d %q", b.sb.code, out)
	}
	if out := b.run("device", "config", "pull", "lab-j"); b.sb.code != 0 {
		t.Fatalf("pull: %d %s %s", b.sb.code, out, b.sb.stderr())
	}
	out = b.run("scope", "mgmt-acl", scope, "add", "203.0.114.0/24")
	if b.sb.code != 0 || strings.Count(out, "would change") != 1 || !strings.Contains(out, want+"\n") {
		t.Errorf("write: %d %q", b.sb.code, out)
	}
	// a read says nothing
	out = b.run("scope", "mgmt-acl", scope, "list")
	if b.sb.code != 0 || strings.Contains(out, "would change") {
		t.Errorf("read: %d %q", b.sb.code, out)
	}
}
