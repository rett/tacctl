package cli

import (
	"strings"
	"testing"
)

// 'device config show' (CHANGELOG 109) in-process: the device's data block,
// then the walkthrough 'config <vendor> --scope <scope> --name <device>'
// prints, from the same code.
func TestDeviceConfigShow(t *testing.T) {
	sb := newSandbox(t, true)
	// The SNMP step carries the device's values once the scope has SNMP set up.
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "version", "v2c")
	sb.dev("", "add", "sw-c", "192.168.1.5", "--vendor", "cisco", "--no-host-key", "--no-lookup",
		"--snmp-location", "Site A, rack 4", "--description", "core switch")
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup", "--snmp-location", "Site B, row 2")
	sb.dev("", "add", "pdu-w", "192.168.1.7", "--vendor", "wti", "--no-host-key", "--no-lookup", "--snmp-location", "Site C, cage 9")
	for _, c := range []struct{ name, vendor, loc string }{
		{"sw-c", "cisco", "Site A, rack 4"}, {"sw-j", "juniper", "Site B, row 2"}, {"pdu-w", "wti", "Site C, cage 9"},
	} {
		out := plain(sb.cfgRun("", []string{"device", "config", "show", c.name}, route))
		want := plain(sb.cfgRun("", []string{"config", c.vendor, "--scope", "lab", "--name", c.name}, route))
		sb.cfgRun("", []string{"device", "config", "show", c.name}, route)
		sb.expect(0, "Device "+c.name, "")
		if !strings.HasSuffix(out, want) || strings.Count(out, "\n") <= strings.Count(want, "\n") {
			t.Errorf("%s: the output is not the data block and then the walkthrough:\n%s", c.name, out)
		}
		block := strings.TrimSuffix(out, want)
		for _, w := range []string{"Name:         " + c.name + "\n", "Vendor:       " + c.vendor + "\n",
			"Scope:        lab  (via prefix 192.168.0.0/16)\n", "Location:     " + c.loc + "\n"} {
			if !strings.Contains(block, w) {
				t.Errorf("%s: the data block lacks %q:\n%s", c.name, w, block)
			}
		}
		if !strings.Contains(want, c.loc) {
			t.Errorf("%s: the walkthrough does not carry the location %q", c.name, c.loc)
		}
	}
	if out := sb.dev("", "show", "sw-c"); !strings.Contains(out, "core switch") {
		t.Fatalf("device show: %q", out)
	}
	if out := plain(sb.cfgRun("", []string{"device", "config", "show", "sw-c"}, route)); !strings.Contains(out, "Description:  core switch\n") {
		t.Errorf("no description in:\n%s", out)
	}
	// --legacy, --protocol, --server and --source reach the walkthrough.
	got := plain(sb.cfgRun("", []string{"device", "config", "show", "sw-c", "--legacy", "--server", "192.0.2.77", "--source", "192.0.2.9"}, route))
	want := plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "sw-c", "--legacy", "--server", "192.0.2.77", "--source", "192.0.2.9"}, route))
	if !strings.HasSuffix(got, want) || !strings.Contains(got, "192.0.2.77") {
		t.Errorf("flags not passed on:\n%s", got)
	}
	got = plain(sb.cfgRun("", []string{"device", "config", "show", "sw-j", "--protocol", "tacacs"}, route))
	want = plain(sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--name", "sw-j", "--protocol", "tacacs"}, route))
	if !strings.HasSuffix(got, want) {
		t.Errorf("--protocol not passed on:\n%s", got)
	}
}

func TestDeviceConfigShowRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "web1|root@192.0.2.10||lab|192.0.2.1|\n", 0o600)
	sb.dev("", "add", "sw-j", "192.168.1.6", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-o", "192.168.1.8", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "sw-x", "198.51.100.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"sw-o"}, "Device 'sw-o' has vendor 'other', and only cisco, juniper and wti have a walkthrough."},
		{[]string{"sw-o"}, "Set the vendor with: tacctl device vendor sw-o cisco|juniper|wti"},
		{[]string{"web1"}, "'web1' is an enrolled Linux host; it has no device walkthrough. See: tacctl host show web1"},
		{[]string{"sw-x"}, "Device 'sw-x' (198.51.100.5) is in no scope: no scope's prefixes cover its address."},
		{[]string{"sw-x"}, "Add them with: tacctl scope prefixes <scope> add <cidr>"},
		{[]string{"sw-j", "--legacy"}, "--legacy (IOS 12.x syntax) applies to Cisco devices; 'sw-j' is a juniper device."},
		{[]string{"nope"}, "Device 'nope' not found."},
		{[]string{}, "Usage: tacctl device config show <name>"},
		{[]string{"sw-j", "--protocol", "bogus"}, "Unknown protocol 'bogus'"},
		{[]string{"sw-j", "--frob"}, "Unknown option: '--frob'"},
	} {
		out := plain(sb.cfgRun("", append([]string{"device", "config", "show"}, c.args...), route))
		sb.expect(1, "", c.err)
		if out != "" {
			t.Errorf("%v: printed %q", c.args, out)
		}
	}
	// A refusal inside the walkthrough prints no data block either (RADIUS is
	// not enabled).
	if out := plain(sb.cfgRun("", []string{"device", "config", "show", "sw-j", "--protocol", "radius"}, route)); sb.code != 1 || out != "" {
		t.Errorf("radius: %d %q %q", sb.code, out, sb.stderr())
	}
}

func TestDeviceConfigUsage(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{{"device", "config"}, {"device", "config", "help"}, {"device", "config", "--help"}} {
		out := plain(sb.cfgRun("", args, route))
		if sb.code != 0 || !strings.Contains(out, "Usage: tacctl device config <subcommand> [arguments]") ||
			!strings.Contains(out, "show <name> [--protocol tacacs|radius] [--legacy] [--server <address|name>] [--source <address>]") {
			t.Errorf("%v: %d %q", args, sb.code, out)
		}
		for _, banned := range []string{"pull", "diff", "apply", "0.2.4", "0.2.5"} {
			if strings.Contains(out, banned) {
				t.Errorf("%v: the usage mentions %q", args, banned)
			}
		}
	}
	out := plain(sb.cfgRun("", []string{"device", "config", "frob"}, route))
	sb.expect(1, "Usage: tacctl device config <subcommand>", "Unknown subcommand: 'frob'")
	if out == "" {
		t.Error("no usage")
	}
	// The family's own usage lists it.
	if out := sb.dev("", ""); !strings.Contains(out, "config show <name>") {
		t.Errorf("device usage lacks config show:\n%s", out)
	}
}

func TestDeviceConfigShowTiers(t *testing.T) {
	sb := engineerSandbox(t)
	out := sb.asEngineer("", "device", "config", "show", "lab-sw")
	if sb.code != 0 || !strings.Contains(out, "Device lab-sw") || !strings.Contains(out, "Cisco IOS / IOS-XE Configuration  (scope: lab") {
		t.Errorf("engineer: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.asEngineer("", "device", "config", "show", "prod-sw")
	sb.expect(1, "", "Device 'prod-sw' not found.")
	// bob's group is an operator without the engineer setting.
	sb.write("state/tacctl.yaml", "{}\n", 0o600)
	sb.asUser("bob", "tac-operator", "device", "config", "show", "lab-sw")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl device config' is not permitted for the operator tier.") {
		t.Errorf("operator: %d %q", sb.code, sb.stderr())
	}
}
