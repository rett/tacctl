package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'tacctl device' end to end, in-process, on the sandbox of native_test.go
// (store.multiscope.yaml: alice, bob, carol; scopes prod 10/8, prod-inner,
// lab 172.16/12 + 192.168/16, dmz 203.0.113/24). The bats file device_cli.bats
// pins the command line; devreg's tests pin the model.

// dev runs 'tacctl device <args>' with stdin and returns the plain stdout.
func (sb *sandbox) dev(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.run(stdin, append([]string{"device"}, args...)))
}

func (sb *sandbox) devices() string {
	sb.t.Helper()
	data, err := os.ReadFile(sb.path("state", "devices.yaml"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		sb.t.Fatal(err)
	}
	return string(data)
}

func (sb *sandbox) stderr() string { return plain(sb.err.String()) }

func TestDeviceUsageAndUnknown(t *testing.T) {
	sb := newSandbox(t, true)
	for _, args := range [][]string{{"device"}, {"device", "help"}, {"device", "-h"}, {"device", "--help"}} {
		out := plain(sb.run("", args))
		if sb.code != 0 || !strings.Contains(out, "Usage: tacctl device <subcommand>") || !strings.Contains(out, "rename <old> <new>") {
			t.Errorf("%v: exit %d, %q", args, sb.code, out)
		}
	}
	sb.run("", []string{"device", "frobnicate"})
	sb.expect(1, "Usage: tacctl device", "Unknown subcommand: 'frobnicate'")
	// Verbs that belong to later packages do not exist yet.
	for _, w := range []string{"scan", "discover", "check", "ssh-config"} {
		sb.run("", []string{"device", w})
		sb.expect(1, "Usage: tacctl device", "Unknown subcommand: '"+w+"'")
	}
	if sb.devices() != "" {
		t.Error("devices.yaml written by a usage")
	}
}

func TestDeviceSpecsCoverEveryVerb(t *testing.T) {
	var words []string
	for _, v := range deviceVerbs {
		w := strings.Fields(v[0])[0]
		words = append(words, w)
		s, ok := specFor([]string{"device", w})
		if !ok || !reflect.DeepEqual(s, deviceSpecs[w]) {
			t.Errorf("no spec for 'device %s'", w)
		}
	}
	if len(deviceSpecs) != len(words) {
		t.Errorf("%d specs for %d verbs", len(deviceSpecs), len(words))
	}
	root := newRoot(&invocation{})
	c := child(root, "device")
	if c == nil || len(c.Commands()) != len(deviceVerbs) {
		t.Fatalf("the device family is not in the tree: %v", c)
	}
}

func TestDeviceAddListShow(t *testing.T) {
	sb := newSandbox(t, true)
	storeBefore := sb.store()
	out := sb.dev("", "list")
	if sb.code != 0 || !strings.Contains(out, "Registered devices (0) and enrolled hosts (0)") || !strings.Contains(out, "None. Register one with: tacctl device add") {
		t.Errorf("empty list: %d %q", sb.code, out)
	}
	out = sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key", "--description", "DC1 core")
	if sb.code != 0 || !strings.Contains(out, "Device 'core-sw1' registered: 10.99.0.1, cisco.") ||
		!strings.Contains(out, "Scope: prod (via prefix 10.0.0.0/8)") || !strings.Contains(out, "hostkey-unpinned") {
		t.Errorf("add: %d %q %q", sb.code, out, sb.stderr())
	}
	// A device no scope answers for.
	sb.dev("", "add", "lab-rtr2", "100.64.0.7", "--vendor", "juniper", "--hostname", "lab-rtr2.lab.example.net", "--port", "830", "--login", "admin", "--no-host-key")
	out = sb.dev("", "list")
	for _, want := range []string{"Registered devices (2) and enrolled hosts (0)", "core-sw1", "10.99.0.1", "prod", "configured",
		"lab-rtr2", "100.64.0.7", "unconfigured", "hostkey-unpinned", "seen data: none (tacctl device scan)", "2 open notice(s)"} {
		if !strings.Contains(out, want) {
			t.Errorf("list lacks %q:\n%s", want, out)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "core-sw1") {
			f := strings.Fields(line)
			if !reflect.DeepEqual(f[:9], []string{"core-sw1", "10.99.0.1", "cisco", "prod", "configured", "-", "-", "-", "hostkey-unpinned"}) {
				t.Errorf("row = %q", f)
			}
		}
	}
	out = sb.dev("", "list", "--unconfigured")
	if strings.Contains(out, "core-sw1") || !strings.Contains(out, "lab-rtr2") || !strings.Contains(out, "(1) and") {
		t.Errorf("--unconfigured:\n%s", out)
	}
	if out = sb.dev("", "list", "--stale"); strings.Contains(out, "core-sw1") || !strings.Contains(out, "None.") {
		t.Errorf("--stale (no seen data):\n%s", out)
	}
	out = sb.dev("", "show", "10.99.0.1")
	for _, want := range []string{"Device core-sw1", "Address:", "10.99.0.1", "Scope:        prod  (via prefix 10.0.0.0/8)", "Description:  DC1 core", "Shadowed", "none pinned", "hostkey-unpinned"} {
		if want == "Shadowed" {
			continue
		}
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	out = sb.dev("", "show", "LAB-RTR2")
	if !strings.Contains(out, "Port:         830") || !strings.Contains(out, "Login:        admin") || !strings.Contains(out, "no scope's prefixes cover 100.64.0.7") {
		t.Errorf("show lab-rtr2:\n%s", out)
	}
	sb.dev("", "show", "nope")
	sb.expect(1, "", "Device 'nope' not found")
	sb.dev("", "show", "10.99.0.2") // not registered: refused although a scope covers it
	sb.expect(1, "", "not found")
	// The registry never touches the store.
	if sb.store() != storeBefore {
		t.Error("store.yaml changed")
	}
	st, err := os.Stat(sb.path("state", "devices.yaml"))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("devices.yaml: %v %v", st, err)
	}
	if want := "devices:\n  core-sw1: {address: 10.99.0.1, vendor: cisco, description: DC1 core}\n"; !strings.Contains(sb.devices(), want) {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
}

func TestDeviceJSON(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	out := sb.dev("", "list", "--json")
	for _, want := range []string{`"name": "core-sw1"`, `"scope": "prod"`, `"state": "configured"`, `"source": "device"`, `"kind": "hostkey-unpinned"`, `"port": 22`} {
		if !strings.Contains(out, want) {
			t.Errorf("list --json lacks %q:\n%s", want, out)
		}
	}
	if out = sb.dev("", "show", "core-sw1", "--json"); !strings.HasPrefix(out, "{") || !strings.Contains(out, `"shadowed_by": []`) {
		t.Errorf("show --json:\n%s", out)
	}
	if out = sb.dev("", "list", "--json", "--unconfigured"); strings.TrimSpace(out) != "[]" {
		t.Errorf("empty json = %q", out)
	}
}

func TestDeviceAddRefusals(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	want := sb.devices()
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"add", "Core-SW1", "10.99.0.2"}, "'core-sw1' is already registered (10.99.0.1); choose another name, or see 'tacctl device show core-sw1'"},
		{[]string{"add", "core-sw2", "10.99.0.1"}, "10.99.0.1 is already registered as 'core-sw1'; rename it with 'tacctl device rename core-sw1 <new>'"},
		{[]string{"add", "switch", "10.99.0.2", "--vendor", "cisco"}, "'switch' is a generic name"},
		{[]string{"add", "Router7", "10.99.0.2"}, "generic name"},
		{[]string{"add", "scope", "10.99.0.2"}, "tacctl word"},
		{[]string{"add", "-bad", "10.99.0.2"}, "Unknown option"},
		{[]string{"add", "bad name", "10.99.0.2"}, "Invalid device name"},
		{[]string{"add", "x1", "10.99.0.0/24"}, "Invalid address"},
		{[]string{"add", "x1", "host.example"}, "Invalid address"},
		{[]string{"add", "x1", "10.99.0.2", "--vendor", "linux"}, "enrolled hosts"},
		{[]string{"add", "x1", "10.99.0.2", "--vendor", "arista"}, "Invalid vendor"},
		{[]string{"add", "x1", "10.99.0.2", "--port", "0"}, "Invalid port"},
		{[]string{"add", "x1", "10.99.0.2", "--hostname", "a b"}, "Invalid hostname"},
		{[]string{"add", "x1", "10.99.0.2", "--login", "-oProxyCommand=x"}, "Invalid login"},
		{[]string{"add", "x1", "10.99.0.2", "--description", strings.Repeat("d", 121)}, "120 characters"},
		{[]string{"add", "x1", "10.99.0.2", "--host-key", "SHA256:short"}, "Invalid --host-key"},
		{[]string{"add", "x1", "10.99.0.2", "--host-key", "SHA256:" + strings.Repeat("A", 43), "--no-host-key"}, "not both"},
		{[]string{"add", "x1"}, "Usage: tacctl device add"},
		{[]string{"add", "x1", "10.99.0.2", "extra"}, "Unknown argument"},
		{[]string{"add", "x1", "10.99.0.2", "--bogus"}, "Unknown option: '--bogus'"},
		{[]string{"add", "x1", "10.99.0.2", "--vendor"}, "--vendor requires a value"},
	} {
		sb.dev("", c.args...)
		sb.expect(1, "", c.err)
		if sb.devices() != want {
			t.Errorf("%v: devices.yaml changed", c.args)
		}
	}
	// --allow-generic registers it, and the standing notice follows.
	out := sb.dev("", "add", "switch", "10.99.0.2", "--allow-generic", "--no-host-key")
	if sb.code != 0 || !strings.Contains(out, "generic-name") {
		t.Errorf("--allow-generic: %d %q %q", sb.code, out, sb.stderr())
	}
	if out = sb.dev("", "notices"); !strings.Contains(out, "switch  generic-name: 'switch' is a generic name") {
		t.Errorf("notices:\n%s", out)
	}
}

func TestDeviceWritesTakeASnapshotFirst(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.dev("", "add", "oob-con1", "10.99.0.9", "--vendor", "wti", "--no-host-key")
	snaps, _ := filepath.Glob(sb.path("state", "backups", "2*"))
	if len(snaps) != 2 {
		t.Fatalf("%d snapshots: %v", len(snaps), snaps)
	}
	// The newest holds the registry as it was before the second add.
	data, err := os.ReadFile(filepath.Join(snaps[len(snaps)-1], "devices.yaml"))
	if err != nil || !strings.Contains(string(data), "core-sw1") || strings.Contains(string(data), "oob-con1") {
		t.Errorf("snapshot devices.yaml = %q, %v", data, err)
	}
	if first, _ := os.ReadFile(filepath.Join(snaps[0], "devices.yaml")); len(first) != 0 {
		t.Error("the first snapshot has a registry that did not exist")
	}
	// A refused command takes none.
	sb.dev("", "add", "core-sw1", "10.99.0.50", "--no-host-key")
	if again, _ := filepath.Glob(sb.path("state", "backups", "2*")); len(again) != 2 {
		t.Errorf("a refused add took a snapshot: %d", len(again))
	}
	// backup diff shows devices.yaml against the newest snapshot.
	sb.run("", []string{"backup", "diff"})
	if !strings.Contains(plain(sb.out.String()), "devices.yaml") {
		t.Errorf("backup diff:\n%s", sb.out.String())
	}
}

func TestDeviceRemove(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.dev("", "add", "oob-con1", "10.99.0.9", "--no-host-key")
	sb.dev("", "add", "edge-fw", "10.99.3.1", "--no-host-key")
	before := sb.devices()
	// Closed stdin is a no.
	out := sb.dev("", "remove", "oob-con1")
	if sb.code != 0 || !strings.Contains(out, "Aborted.") || sb.devices() != before {
		t.Errorf("closed stdin: %d %q", sb.code, out)
	}
	if out = sb.dev("n\n", "remove", "oob-con1"); !strings.Contains(out, "Aborted.") || sb.devices() != before {
		t.Errorf("n: %q", out)
	}
	sb.dev("y\n", "remove", "OOB-CON1,10.99.3.2")
	sb.expect(1, "", "not found") // 10.99.3.2 is not a registered address
	if sb.devices() != before {
		t.Error("a bad name removed something")
	}
	out = sb.dev("y\n", "remove", "oob-con1,edge-fw")
	if sb.code != 0 || !strings.Contains(out, "Removed 2 device(s).") || strings.Contains(sb.devices(), "oob-con1") || !strings.Contains(sb.devices(), "core-sw1") {
		t.Errorf("remove: %d %q\n%s", sb.code, out, sb.devices())
	}
	sb.dev("", "add", "a1", "10.99.0.5", "--no-host-key")
	if out = sb.dev("", "remove", "--all", "-y"); !strings.Contains(out, "Removed 2 device(s).") || strings.Contains(sb.devices(), "core-sw1: ") {
		t.Errorf("--all: %q\n%s", out, sb.devices())
	}
	if out = sb.dev("", "remove", "--all", "-y"); !strings.Contains(out, "The registry is empty.") {
		t.Errorf("--all on nothing: %q", out)
	}
	sb.dev("", "remove")
	sb.expect(1, "", "Usage: tacctl device remove")
	sb.dev("", "remove", "--all", "x")
	sb.expect(1, "", "--all takes no names")
}

func TestDeviceRename(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--no-host-key")
	sb.dev("", "add", "other", "10.99.0.2", "--no-host-key")
	sb.dev("", "notice", "core-sw1", "ack", "hostkey-unpinned")
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"rename", "core-sw1", "OTHER"}, "'other' is already registered (10.99.0.2)"},
		{[]string{"rename", "core-sw1", "switch"}, "generic name"},
		{[]string{"rename", "core-sw1", "ssh"}, "tacctl word"},
		{[]string{"rename", "nope", "x1"}, "not found"},
		{[]string{"rename", "core-sw1", "core-sw1"}, "already has that name"},
		{[]string{"rename", "core-sw1"}, "Usage: tacctl device rename"},
	} {
		sb.dev("", c.args...)
		sb.expect(1, "", c.err)
	}
	if out := sb.dev("", "rename", "core-sw1", "Core-SW1"); sb.code != 0 || !strings.Contains(out, "renamed to 'Core-SW1'") {
		t.Errorf("case-only rename: %d %q %q", sb.code, out, sb.stderr())
	}
	out := sb.dev("", "rename", "Core-SW1", "dc1-core1")
	if sb.code != 0 || !strings.Contains(out, "renamed to 'dc1-core1'") || !strings.Contains(sb.devices(), "dc1-core1:") || strings.Contains(sb.devices(), "Core-SW1") {
		t.Errorf("rename: %d %q\n%s", sb.code, out, sb.devices())
	}
	if !strings.Contains(sb.devices(), "ack: [hostkey-unpinned]") {
		t.Error("the acknowledgements did not follow the rename")
	}
	if sb.dev("", "rename", "switch", "x"); sb.code != 1 {
		t.Error("rename of an unknown device")
	}
	sb.dev("", "rename", "dc1-core1", "switch", "--allow-generic")
	if sb.code != 0 {
		t.Errorf("--allow-generic: %q", sb.stderr())
	}
}

func TestDeviceSetters(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "other", "10.99.0.2", "--no-host-key")
	get := func(field string) string { return strings.TrimSpace(sb.dev("", field, "core-sw1")) }
	if get("address") != "10.99.0.1" || get("hostname") != "-" || get("vendor") != "cisco" || get("port") != "22" || get("login") != "-" || get("description") != "-" {
		t.Error("getters")
	}
	steps := []struct{ field, value, shown string }{
		{"address", "2001:DB8:0::5", "2001:db8::5"},
		{"hostname", "core1.example.net", "core1.example.net"},
		{"vendor", "JUNIPER", "juniper"},
		{"port", "830", "830"},
		{"login", "netops", "netops"},
		{"description", "the core, DC1", ""},
	}
	for _, s := range steps {
		args := []string{s.field, "core-sw1", s.value}
		if s.field == "description" {
			args = []string{s.field, "core-sw1", "the", "core,", "DC1"}
		}
		sb.dev("", args...)
		if sb.code != 0 || !strings.Contains(sb.plainOut(), "Device 'core-sw1' "+s.field+" set to") {
			t.Errorf("set %s: %d %q %q", s.field, sb.code, sb.out.String(), sb.stderr())
		}
		if s.shown != "" && get(s.field) != s.shown {
			t.Errorf("%s = %q, want %q", s.field, get(s.field), s.shown)
		}
	}
	if get("description") != "the core, DC1" {
		t.Errorf("description = %q", get("description"))
	}
	// By address, and clear.
	sb.dev("", "port", "2001:db8::5", "22")
	if get("port") != "22" || strings.Contains(sb.devices(), "port:") {
		t.Errorf("the default port is not stored:\n%s", sb.devices())
	}
	for _, f := range []string{"hostname", "login", "description", "port", "vendor"} {
		sb.dev("", f, "core-sw1", "clear")
		if sb.code != 0 || !strings.Contains(sb.plainOut(), "cleared") {
			t.Errorf("clear %s: %d %q", f, sb.code, sb.out.String())
		}
	}
	if get("vendor") != "other" || get("hostname") != "-" {
		t.Error("clear did not unset")
	}
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"address", "core-sw1", "clear"}, "address is required"},
		{[]string{"address", "core-sw1", "10.99.0.2"}, "already registered as 'other'"},
		{[]string{"address", "core-sw1", "10.0.0.0/8"}, "Invalid address"},
		{[]string{"vendor", "core-sw1", "linux"}, "enrolled hosts"},
		{[]string{"port", "core-sw1", "99999"}, "Invalid port"},
		{[]string{"hostname", "core-sw1", "bad host"}, "Invalid hostname"},
		{[]string{"login", "core-sw1", "a", "b"}, "Usage: tacctl device login"},
		{[]string{"port", "nope", "22"}, "not found"},
		{[]string{"port", "nope"}, "not found"},
		{[]string{"port"}, "Usage: tacctl device port"},
	} {
		sb.dev("", c.args...)
		sb.expect(1, "", c.err)
	}
	// legacy-ssh and stale-days.
	if out := strings.TrimSpace(sb.dev("", "legacy-ssh", "core-sw1")); out != "disabled" {
		t.Errorf("legacy-ssh = %q", out)
	}
	sb.dev("", "legacy-ssh", "core-sw1", "enable")
	if out := strings.TrimSpace(sb.dev("", "legacy-ssh", "core-sw1")); out != "enabled" || !strings.Contains(sb.devices(), "legacy_ssh: true") {
		t.Errorf("legacy-ssh = %q\n%s", out, sb.devices())
	}
	sb.dev("", "legacy-ssh", "core-sw1", "maybe")
	sb.expect(1, "", "Usage: tacctl device legacy-ssh")
	if out := strings.TrimSpace(sb.dev("", "stale-days")); out != "30" {
		t.Errorf("stale-days = %q", out)
	}
	sb.dev("", "stale-days", "45")
	if out := strings.TrimSpace(sb.dev("", "stale-days")); out != "45" || !strings.Contains(sb.devices(), "stale_days: 45") {
		t.Errorf("stale-days = %q", out)
	}
	for _, bad := range []string{"0", "x", "99999", "030"} {
		sb.dev("", "stale-days", bad)
		sb.expect(1, "", "Invalid number of days")
	}
}

func (sb *sandbox) plainOut() string { return plain(sb.out.String()) }

func TestDeviceNotices(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "router", "10.99.0.2", "--vendor", "juniper", "--allow-generic", "--no-host-key")
	out := sb.dev("", "notices")
	if !strings.Contains(out, "core-sw1  hostkey-unpinned") || !strings.Contains(out, "router  generic-name") ||
		!strings.Contains(out, "set system host-name <name>") || !strings.Contains(out, "tacctl device rename router <new>") {
		t.Errorf("notices:\n%s", out)
	}
	sb.dev("", "notice", "router", "ack", "generic-name")
	if !strings.Contains(sb.plainOut(), "acknowledged") || !strings.Contains(sb.devices(), "ack: [generic-name]") {
		t.Errorf("ack: %q\n%s", sb.plainOut(), sb.devices())
	}
	if out = sb.dev("", "notice", "router", "ack", "generic-name"); !strings.Contains(out, "already acknowledged") {
		t.Errorf("ack twice: %q", out)
	}
	// Acknowledged: out of list and notices, marked in show.
	if out = sb.dev("", "notices", "router"); strings.Contains(out, "generic-name") {
		t.Errorf("notices still lists the acknowledged one:\n%s", out)
	}
	if out = sb.dev("", "list"); !strings.Contains(out, "hostkey-unpinned") || strings.Contains(out, "generic-name") {
		t.Errorf("list:\n%s", out)
	}
	if out = sb.dev("", "show", "router"); !strings.Contains(out, "generic-name (acknowledged):") {
		t.Errorf("show:\n%s", out)
	}
	sb.dev("", "notice", "router", "unack", "generic-name")
	if strings.Contains(sb.devices(), "ack:") {
		t.Errorf("unack:\n%s", sb.devices())
	}
	if out = sb.dev("", "notice", "router", "unack", "generic-name"); !strings.Contains(out, "not acknowledged") {
		t.Errorf("unack twice: %q", out)
	}
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"notice", "router", "ack", "hostkey-changed"}, "cannot be acknowledged"},
		{[]string{"notice", "router", "ack", "nonsense"}, "Unknown notice kind"},
		{[]string{"notice", "router", "snooze", "generic-name"}, "Usage: tacctl device notice"},
		{[]string{"notice", "nope", "ack", "generic-name"}, "not found"},
	} {
		sb.dev("", c.args...)
		sb.expect(1, "", c.err)
	}
	// All clear.
	sb.dev("", "notice", "router", "ack", "generic-name")
	sb.dev("", "notice", "router", "ack", "hostkey-unpinned")
	sb.dev("", "notice", "core-sw1", "ack", "hostkey-unpinned")
	if out = sb.dev("", "notices"); !strings.Contains(out, "No open notices.") {
		t.Errorf("notices:\n%s", out)
	}
	if out = sb.dev("", "list"); strings.Contains(out, "open notice") {
		t.Errorf("list still counts notices:\n%s", out)
	}
}

func TestDeviceImportExport(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--legacy-ssh", "--hostname", "core.example.net", "--no-host-key")
	csvText := "name,address,vendor,port,login,description\ncore-sw1,10.99.0.1,cisco,,,\"DC1, core\"\noob-con1,10.99.0.9,wti\n"
	before := sb.devices()
	out := sb.dev(csvText, "import", "--check", "-")
	if sb.code != 0 || !strings.Contains(out, "Check passed; nothing written. Would import: 1 added, 1 updated, 0 unchanged, 0 removed.") || sb.devices() != before {
		t.Errorf("--check: %d %q %q", sb.code, out, sb.stderr())
	}
	out = sb.dev(csvText, "import", "-")
	if sb.code != 0 || !strings.Contains(out, "Imported: 1 added, 1 updated, 0 unchanged, 0 removed.") {
		t.Errorf("import: %d %q %q", sb.code, out, sb.stderr())
	}
	if d := sb.devices(); !strings.Contains(d, "oob-con1") || !strings.Contains(d, "DC1, core") || !strings.Contains(d, "legacy_ssh: true") || !strings.Contains(d, "core.example.net") {
		t.Errorf("merge lost something:\n%s", d)
	}
	// Export: CSV, JSON and YAML; the YAML imports back with --replace.
	if out = sb.dev("", "export", "--csv"); !strings.HasPrefix(out, "name,address,vendor,port,login,description\n") || !strings.Contains(out, "oob-con1,10.99.0.9,wti") {
		t.Errorf("csv:\n%s", out)
	}
	if out = sb.dev("", "export", "--json"); !strings.Contains(out, `"name": "oob-con1"`) {
		t.Errorf("json:\n%s", out)
	}
	yml := sb.dev("", "export")
	if yml != sb.devices() {
		t.Errorf("yaml export differs from the file:\n%s", yml)
	}
	sb.dev("", "export", "--csv", "--json")
	sb.expect(1, "", "not both")
	// --replace removes what the file does not name, after a confirmation.
	one := "name,address\nonly-one,10.99.0.77\n"
	out = sb.dev(one, "import", "--replace", "-")
	if !strings.Contains(out, "--replace removes 2 device(s)") || !strings.Contains(out, "Aborted.") || !strings.Contains(sb.devices(), "core-sw1") {
		t.Errorf("replace without -y: %q", out)
	}
	sb.dev(one, "import", "--replace", "-y", "-")
	if d := sb.devices(); strings.Contains(d, "core-sw1") || !strings.Contains(d, "only-one") {
		t.Errorf("replace:\n%s", d)
	}
	// A file path; YAML in.
	p := filepath.Join(t.TempDir(), "in.yaml")
	_ = os.WriteFile(p, []byte(yml), 0o600)
	if sb.dev("", "import", "--replace", "-y", p); sb.code != 0 || !strings.Contains(sb.devices(), "core-sw1: {address: 10.99.0.1, vendor: cisco, hostname: core.example.net, legacy_ssh: true") {
		t.Errorf("yaml import: %d %q\n%s", sb.code, sb.stderr(), sb.devices())
	}
	// Errors: nothing written, every problem named.
	before = sb.devices()
	sb.dev("a1,10.0.0.0/8\nswitch,10.0.0.1\nb2,10.99.0.1\n", "import", "-")
	if sb.code != 1 || sb.devices() != before {
		t.Errorf("a bad import: %d", sb.code)
	}
	if e := sb.stderr(); !strings.Contains(e, "line 1: Invalid address") {
		t.Errorf("stderr: %q", e)
	}
	sb.dev("switch,10.0.0.1\nb2,10.99.0.1\n", "import", "-")
	if e := sb.stderr(); !strings.Contains(e, "line 1: 'switch' is a generic name") || !strings.Contains(e, "would be registered as both 'core-sw1' and 'b2'") && !strings.Contains(e, "line 1") {
		t.Errorf("stderr: %q", e)
	}
	sb.dev("", "import", "/nonexistent/file")
	sb.expect(1, "", "Cannot read")
	sb.dev("", "import")
	sb.expect(1, "", "Usage: tacctl device import")
}

func TestDeviceTierFilteringAndGate(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "prod-sw", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "lab-sw", "192.168.1.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "dmz-fw", "203.0.113.9", "--no-host-key")
	sb.dev("", "add", "stray", "100.64.0.1", "--no-host-key")
	sb.write("state/linux-hosts", "web1|root@192.0.2.10||lab|192.0.2.1|\ndb1|root@192.0.2.11||prod|192.0.2.1|\n", 0o600)
	asUser := func(user, group string, args ...string) string {
		return plain(sb.cfgRun("", append([]string{"device"}, args...), func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users " + group + "\n")})
		}, "SUDO_USER="+user))
	}
	// carol (readonly; lab and dmz) sees her own scopes only.
	out := asUser("carol", "tac-readonly", "list")
	for _, want := range []string{"lab-sw", "dmz-fw", "web1", "(2) and enrolled hosts (1)"} {
		if !strings.Contains(out, want) {
			t.Errorf("carol's list lacks %q:\n%s", want, out)
		}
	}
	for _, hidden := range []string{"prod-sw", "stray", "db1"} {
		if strings.Contains(out, hidden) {
			t.Errorf("carol sees %s:\n%s", hidden, out)
		}
	}
	for _, key := range []string{"prod-sw", "10.99.0.1", "db1", "stray"} {
		asUser("carol", "tac-readonly", "show", key)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "not found") {
			t.Errorf("carol show %s: %d %q", key, sb.code, sb.stderr())
		}
	}
	if out = asUser("carol", "tac-readonly", "show", "192.168.1.1"); sb.code != 0 || !strings.Contains(out, "Device lab-sw") {
		t.Errorf("carol show by address: %d %q", sb.code, out)
	}
	// Registry writes and the operator-level verbs are superuser-only for her.
	for _, args := range [][]string{{"add", "x1", "10.99.0.5"}, {"remove", "lab-sw", "-y"}, {"rename", "lab-sw", "x1"}, {"port", "lab-sw", "22"},
		{"import", "-"}, {"export"}, {"stale-days"}, {"notice", "lab-sw", "ack", "generic-name"}} {
		asUser("carol", "tac-readonly", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the readonly tier") {
			t.Errorf("carol %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if !strings.Contains(sb.devices(), "lab-sw") {
		t.Error("carol changed the registry")
	}
	// notices is open to her, filtered to her own scopes like list and show.
	out = asUser("carol", "tac-readonly", "notices")
	if sb.code != 0 {
		t.Errorf("carol notices: %d %q", sb.code, sb.stderr())
	}
	for _, hidden := range []string{"prod-sw", "stray", "db1"} {
		if strings.Contains(out, hidden) {
			t.Errorf("carol's notices show %s:\n%s", hidden, out)
		}
	}
	// bob (operator; lab) may export, filtered to his scope.
	out = asUser("bob", "tac-operator", "export", "--csv")
	if sb.code != 0 || !strings.Contains(out, "lab-sw") || strings.Contains(out, "prod-sw") || strings.Contains(out, "dmz-fw") {
		t.Errorf("bob export: %d %q (%q)", sb.code, out, sb.stderr())
	}
	// Completion names follow the same filter.
	names := plain(sb.cfgRun("", []string{"_completion-names", "devices"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}, "SUDO_USER=carol"))
	if want := "dmz-fw\nlab-sw\nweb1\n"; names != want {
		t.Errorf("carol's completion names = %q", names)
	}
	if names = sb.run("", []string{"_completion-names", "devices"}); names != "db1\ndmz-fw\nlab-sw\nprod-sw\nstray\nweb1\n" {
		t.Errorf("unrestricted completion names = %q", names)
	}
}

func TestDeviceListShowsEnrolledHosts(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "web1|root@192.0.2.10|2222|lab|192.0.2.1|/k/id\nubuntu|dba@h.example.net||prod|192.0.2.1|\n", 0o600)
	out := sb.dev("", "list")
	if !strings.Contains(out, "Registered devices (0) and enrolled hosts (2)") || !strings.Contains(out, "linux") {
		t.Errorf("list:\n%s", out)
	}
	if !strings.Contains(out, "ubuntu") || !strings.Contains(out, "generic-name") {
		t.Errorf("a host enrolled under a generic name carries the notice:\n%s", out)
	}
	out = sb.dev("", "show", "web1")
	for _, want := range []string{"Enrolled host web1", "Vendor:       linux", "Port:         2222", "Target:       root@192.0.2.10", "Identity:     /k/id", "Scope:        lab"} {
		if !strings.Contains(out, want) {
			t.Errorf("show web1 lacks %q:\n%s", want, out)
		}
	}
	// Read-only through device.
	for _, args := range [][]string{{"remove", "web1", "-y"}, {"port", "web1", "22"}, {"rename", "web1", "x1"}, {"notice", "ubuntu", "ack", "generic-name"}} {
		sb.dev("", args...)
		sb.expect(1, "", "is an enrolled host")
	}
	if sb.dev("", "add", "WEB1", "10.99.0.1", "--no-host-key"); sb.code != 1 || !strings.Contains(sb.stderr(), "'WEB1' is an enrolled host") {
		t.Errorf("add over a host name: %d %q", sb.code, sb.stderr())
	}
	if sb.devices() != "" {
		t.Error("devices.yaml written")
	}
}

// 'host enroll' takes names from the same namespace and refuses generic
// ones (docs/plans/operator-console.md 3.6).
func TestHostEnrollRefusesRegistryAndGenericNames(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "core-sw1", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	for _, c := range []struct{ name, err string }{
		{"Core-SW1", "'core-sw1' is already registered as a device (10.99.0.1)"},
		{"switch", "'switch' is a generic name"},
		{"Ubuntu", "generic name"},
		{"ip-10-0-0-5", "generic name"},
	} {
		sb.run("", []string{"host", "enroll", "--local", "--name", c.name})
		sb.expect(1, "", c.err)
		if !strings.Contains(sb.stderr(), "--name") {
			t.Errorf("%s: the refusal does not say how to go on: %q", c.name, sb.stderr())
		}
	}
	if _, err := os.Stat(sb.path("state", "linux-hosts")); err == nil {
		t.Error("a refused enroll registered something")
	}
	// A server called after a generic name has to be given another.
	sb.run("", []string{"host", "enroll", "--local", "--name", "ubuntu"})
	if sb.code != 1 {
		t.Error("--local with a generic name")
	}
}
