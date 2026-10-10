package cli

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/snmp"
)

// 'device snmp' (D72 of docs/plans/0.2.4-plan.md) on the sandbox of
// native_test.go. The bats file device_snmp_override.bats pins the command
// line.

// devSNMP runs 'tacctl device snmp <args>' as the superuser.
func (sb *sandbox) devSNMP(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, append([]string{"device", "snmp"}, args...), nil))
}

// The resolution is the device's value, then its scope's, then the default's,
// then the built-in, setting by setting, and every view says which.
func TestDeviceSNMPResolutionAndLabels(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "lab-sw2", "192.168.1.2", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	plainRegistry := sb.devices()

	// Nothing set anywhere; reading writes nothing.
	out := sb.devSNMP("", "lab-sw1")
	for _, want := range []string{"SNMP for device 'lab-sw1'", "scope:      lab  (via prefix 192.168.0.0/16)", "version:    not set",
		"port:       161  (built-in)", "timeout:    2 s, one retry  (built-in)", "community:  not set",
		"order:      the device's own setting, then its scope's, then the default's, then the built-in"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("show lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	if sb.devices() != plainRegistry {
		t.Errorf("a read wrote the registry:\n%s", sb.devices())
	}
	if out = sb.devSNMP("", "lab-sw1", "show"); out != sb.devSNMP("", "lab-sw1") {
		t.Errorf("'show' and no verb differ:\n%s", out)
	}

	// The default, then the scope's over it.
	sb.cfgRun("def-community-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	sb.cfgRun("", []string{"config", "snmp", "port", "1161"}, nil)
	sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "timeout", "4")
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24")
	out = sb.devSNMP("", "lab-sw1", "show", "--reveal")
	for _, want := range []string{"version:    v2c (the community)  (scope lab)", "port:       1161  (default)",
		"timeout:    4 s, one retry  (scope lab)", "community:  scope-community-1  (scope lab)", "198.51.100.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("scope over default: lacks %q:\n%s", want, out)
		}
	}
	if sb.devices() != plainRegistry {
		t.Errorf("a read wrote the registry:\n%s", sb.devices())
	}

	// The device's own: version, port, timeout, clients; the registry only.
	sb.devSNMP("", "lab-sw1", "version", "v3")
	sb.said(0, "SNMP version of device 'lab-sw1' set to v3.")
	sb.devSNMP("", "lab-sw1", "port", "2161")
	sb.devSNMP("", "lab-sw1", "timeout", "7")
	sb.devSNMP("", "lab-sw1", "clients", "add", "192.0.2.0/24,192.0.2.7/32")
	sb.said(0, "Added 2 allowed SNMP client range(s) to device 'lab-sw1': 192.0.2.0/24 192.0.2.7/32")
	sb.said(0, "The device's own list replaces the scope's 1 range(s) for this device.")
	reg := sb.devices()
	for _, want := range []string{"snmp:", "version: v3", "port: 2161", "timeout: 7", "192.0.2.0/24"} {
		if !strings.Contains(reg, want) {
			t.Errorf("devices.yaml lacks %q:\n%s", want, reg)
		}
	}
	if strings.Contains(reg, "community") || strings.Contains(reg, "scope-community-1") {
		t.Errorf("devices.yaml holds a credential:\n%s", reg)
	}
	out = sb.devSNMP("", "lab-sw1", "show")
	for _, want := range []string{"version:    v3 (the user, authPriv)  (device)", "port:       2161  (device)",
		"timeout:    7 s, one retry  (device)", "the ranges below  (device)", "192.0.2.0/24", "192.0.2.7/32",
		"community:  set  (scope lab)", "v3 user:    not set  (not set)"} {
		if !strings.Contains(out, want) {
			t.Errorf("device over scope: lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "198.51.100.0/24") || strings.Contains(out, "scope-community-1") {
		t.Errorf("the scope's clients or a secret in the device's show:\n%s", out)
	}
	// A sibling of the same scope is untouched.
	out = sb.devSNMP("", "lab-sw2")
	if !strings.Contains(out, "version:    v2c (the community)  (scope lab)") || !strings.Contains(out, "port:       1161  (default)") ||
		!strings.Contains(out, "198.51.100.0/24") {
		t.Errorf("lab-sw2:\n%s", out)
	}
	// The one-value reads say where it comes from.
	for args, want := range map[string]string{"version": "v3  (device)", "port": "2161  (device)", "timeout": "7  (device)"} {
		if out = sb.devSNMP("", "lab-sw1", args); !strings.Contains(out, want) {
			t.Errorf("%s: %q", args, out)
		}
	}
	if out = sb.devSNMP("", "lab-sw2", "timeout"); !strings.Contains(out, "4  (scope lab)") {
		t.Errorf("lab-sw2 timeout: %q", out)
	}

	// The v3 user and its passphrases: a file of the device's own (0600, in
	// a 0700 directory), the version v3, and never printed but by --reveal.
	sb.devSNMP("dev-auth-pass-1\ndev-priv-pass-1\n", "lab-sw1", "v3-user", "carol", "--stdin")
	sb.said(0, "SNMPv3 user and passphrases of device 'lab-sw1' set")
	file := sb.path("state", "snmp", "devices", "lab-sw1.yaml")
	if fi, err := os.Stat(file); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("device file: %v %v", fi, err)
	}
	for _, d := range []string{sb.path("state", "snmp"), sb.path("state", "snmp", "devices")} {
		if fi, err := os.Stat(d); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: %v %v", d, fi, err)
		}
	}
	for _, secret := range []string{"dev-auth-pass-1", "dev-priv-pass-1"} {
		if strings.Contains(sb.devices(), secret) || strings.Contains(sb.overrides(), secret) {
			t.Errorf("%q reached devices.yaml or tacctl.yaml", secret)
		}
	}
	out = sb.devSNMP("", "lab-sw1", "show")
	if strings.Contains(out, "dev-auth-pass-1") || !strings.Contains(out, "v3 user:    carol  (device)") ||
		!strings.Contains(out, "v3 passphrases: auth set, priv set  (device)") ||
		!strings.Contains(out, "Credentials: "+file+" (0600; 'show --reveal' prints them)") {
		t.Errorf("v3 show:\n%s", out)
	}
	out = sb.devSNMP("", "lab-sw1", "show", "--reveal")
	if !strings.Contains(out, "auth dev-auth-pass-1, priv dev-priv-pass-1  (device)") {
		t.Errorf("v3 --reveal:\n%s", out)
	}
	// The protocols are the scope's or the default's.
	if !strings.Contains(out, "v3 auth:    sha  (built-in); priv: aes128  (built-in)") {
		t.Errorf("v3 protocols:\n%s", out)
	}
	// The v2c community likewise.
	sb.devSNMP("dev-community-1\n", "lab-sw1", "community", "--stdin")
	sb.said(0, "SNMP community of device 'lab-sw1' set")
	out = sb.devSNMP("", "lab-sw1", "show", "--reveal")
	if !strings.Contains(out, "version:    v2c (the community)  (device)") || !strings.Contains(out, "community:  dev-community-1  (device)") {
		t.Errorf("community --reveal:\n%s", out)
	}
	if strings.Contains(sb.devSNMP("", "lab-sw1", "show"), "dev-community-1") {
		t.Error("plain show printed the community")
	}

	// device show: the resolved values and where each comes from, no secret.
	out = sb.dev("", "show", "lab-sw1")
	for _, want := range []string{"SNMP:", "version v2c (device), port 2161 (device), timeout 7 s (device)",
		"credentials: community set (device)", "clients: 2 range(s) of the device's own (device), after the tacctl server"} {
		if !strings.Contains(out, want) {
			t.Errorf("device show lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dev-community-1") {
		t.Errorf("device show printed the community:\n%s", out)
	}
	out = sb.dev("", "show", "lab-sw2")
	if !strings.Contains(out, "version v2c (scope lab), port 1161 (default), timeout 4 s (scope lab)") ||
		!strings.Contains(out, "credentials: community set (scope lab)") || !strings.Contains(out, "clients: 1 range(s) (scope lab), after the tacctl server") {
		t.Errorf("device show lab-sw2:\n%s", out)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(sb.run("", []string{"device", "show", "lab-sw1", "--json"})), &js); err != nil {
		t.Fatal(err)
	}
	sn, _ := js["snmp"].(map[string]any)
	if sn == nil || sn["version_from"] != "device" || sn["port"] != float64(2161) || sn["community"] != true || sn["community_from"] != "device" ||
		sn["clients_from"] != "device" || sn["own_settings"] != true || sn["own_credentials"] != true {
		t.Errorf("show --json snmp: %v", js["snmp"])
	}
	if raw := sb.out.String(); strings.Contains(raw, "dev-community-1") || strings.Contains(raw, "dev-auth-pass-1") {
		t.Errorf("show --json printed a secret:\n%s", raw)
	}
	// An enrolled-nothing 'list --json' keeps its shape: no snmp key.
	if raw := sb.run("", []string{"device", "list", "--json"}); strings.Contains(raw, `"snmp"`) {
		t.Errorf("list --json has an snmp key:\n%s", raw)
	}

	// scope snmp show: the order and which devices set their own.
	out = sb.scopeSNMP("", "lab", "show")
	if !strings.Contains(out, "order:      a device's own setting first (tacctl device snmp <name>), then the scope's, then the default's, then the built-in") ||
		!strings.Contains(out, "devices with settings of their own: lab-sw1 (version, port, timeout, clients, community, v3-user)") {
		t.Errorf("scope snmp show:\n%s", out)
	}
	if strings.Contains(out, "dev-community-1") || strings.Contains(out, "carol") {
		t.Errorf("scope snmp show printed a device's secret:\n%s", out)
	}
	// 'device snmp' of other things.
	sb.devSNMP("", "nosuch")
	sb.said(1, "Device 'nosuch' not found.")
	sb.devSNMP("", "lab-sw1", "version", "v1")
	sb.said(1, "Unknown version 'v1': v2c or v3.")
	sb.devSNMP("", "lab-sw1", "port", "0")
	sb.said(1, "Invalid UDP port '0': expected 1-65535.")
	sb.devSNMP("", "lab-sw1", "timeout", "11")
	sb.said(1, "Invalid timeout '11': expected 1-10.")
	sb.devSNMP("", "lab-sw1", "clients", "add", "0.0.0.0/0")
	sb.said(1, "would allow every address")
	sb.devSNMP("", "lab-sw1", "bogus")
	sb.said(1, "Unknown subcommand: 'bogus'")
	sb.devSNMP("x\n", "lab-sw1", "community", "--stdin", "extra")
	if sb.code != 1 {
		t.Errorf("extra argument: %d", sb.code)
	}
	sb.devSNMP("")
	sb.said(1, "Usage: tacctl device snmp <name>")

	// clear: the map and the file go; the registry is as it was.
	sb.devSNMP("", "lab-sw1", "clear")
	sb.said(0, "SNMP settings, credentials and allowed clients of device 'lab-sw1' removed")
	if sb.devices() != plainRegistry {
		t.Errorf("clear left the registry changed:\n%s", sb.devices())
	}
	// The device's file and its directory go; the scope's file stays.
	for _, p := range []string{file, sb.path("state", "snmp", "devices")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", p, err)
		}
	}
	if _, err := os.Stat(sb.path("state", "snmp", "lab.yaml")); err != nil {
		t.Errorf("the scope's file went with the device's: %v", err)
	}
	sb.devSNMP("", "lab-sw1", "clear")
	sb.said(0, "has no SNMP settings of its own; nothing was changed.")
	if out = sb.devSNMP("", "lab-sw1"); !strings.Contains(out, "version:    v2c (the community)  (scope lab)") {
		t.Errorf("after clear:\n%s", out)
	}
	out = sb.scopeSNMP("", "lab", "show")
	if strings.Contains(out, "devices with settings of their own") {
		t.Errorf("scope snmp show still lists a device:\n%s", out)
	}
}

// Clients: a device's own list replaces its scope's; removing the last one
// gives it back.
func TestDeviceSNMPClients(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24")
	out := sb.devSNMP("", "lab-sw1", "clients")
	if !strings.Contains(out, "198.51.100.0/24  (scope lab)") || !strings.Contains(out, "the scope's list applies") {
		t.Errorf("list:\n%s", out)
	}
	sb.devSNMP("", "lab-sw1", "clients", "remove", "192.0.2.0/24")
	sb.said(0, "lists no SNMP client ranges of its own")
	sb.devSNMP("", "lab-sw1", "clients", "add", "192.0.2.0/24")
	sb.devSNMP("", "lab-sw1", "clients", "add", "192.0.2.0/24,10.0.0.0/8")
	sb.said(0, "Added 1 allowed SNMP client range(s) to device 'lab-sw1': 10.0.0.0/8")
	sb.said(0, "(Already present, unchanged: 192.0.2.0/24)")
	sb.devSNMP("", "lab-sw1", "clients", "add", "192.0.2.0/24")
	sb.said(0, "No new ranges to add")
	out = sb.devSNMP("", "lab-sw1", "clients", "list")
	if strings.Contains(out, "198.51.100.0/24") || !strings.Contains(out, "2. 192.0.2.0/24  (device)") || !strings.Contains(out, "3. 10.0.0.0/8  (device)") ||
		!strings.Contains(out, "4. 0.0.0.0/0 refused") {
		t.Errorf("list:\n%s", out)
	}
	sb.devSNMP("", "lab-sw1", "clients", "remove", "192.0.2.0/24,10.0.0.0/8")
	sb.said(0, "The device lists none of its own now: its scope's list applies again.")
	if out = sb.devSNMP("", "lab-sw1", "clients"); !strings.Contains(out, "198.51.100.0/24  (scope lab)") {
		t.Errorf("list after:\n%s", out)
	}
	if strings.Contains(sb.devices(), "snmp") {
		t.Errorf("an emptied map was kept:\n%s", sb.devices())
	}
	// The limit is the scope's.
	var many []string
	for i := 0; i < 33; i++ {
		many = append(many, "10.1."+strconv.Itoa(i)+".0/24")
	}
	sb.devSNMP("", "lab-sw1", "clients", "add", strings.Join(many, ","))
	sb.said(1, "A device lists at most 32 client ranges")
	if strings.Contains(sb.devices(), "snmp") {
		t.Errorf("a refused add wrote:\n%s", sb.devices())
	}
}

// The credentials file follows the device: a rename moves it, a removal
// drops it, and a new device never picks up a stranger's.
func TestDeviceSNMPFileFollowsTheDevice(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "lab-sw2", "192.168.1.2", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.devSNMP("c-one\n", "lab-sw1", "community", "--stdin")
	sb.devSNMP("c-two\n", "lab-sw2", "community", "--stdin")
	from, to := sb.path("state", "snmp", "devices", "lab-sw1.yaml"), sb.path("state", "snmp", "devices", "core-1.yaml")
	sb.dev("", "rename", "lab-sw1", "core-1")
	sb.expect(0, "renamed to 'core-1'", "")
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Errorf("old file left: %v", err)
	}
	if fi, err := os.Stat(to); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("new file: %v %v", fi, err)
	}
	if out := sb.devSNMP("", "core-1", "show", "--reveal"); !strings.Contains(out, "community:  c-one  (device)") {
		t.Errorf("after rename:\n%s", out)
	}
	// A spelling change keeps it.
	sb.dev("", "rename", "core-1", "CORE-1")
	if out := sb.devSNMP("", "CORE-1", "show", "--reveal"); !strings.Contains(out, "community:  c-one  (device)") {
		t.Errorf("after a spelling change:\n%s", out)
	}
	// A rename onto a leftover is refused and changes nothing.
	sb.write("state/snmp/devices/other.yaml", "version: 1\ncommunity: stranger\n", 0o600)
	sb.dev("", "rename", "CORE-1", "other")
	if sb.code == 0 || !strings.Contains(sb.stderr(), "SNMP credentials for a device named 'other' are already on disk") {
		t.Errorf("rename onto a leftover: %d %q", sb.code, sb.stderr())
	}
	if !strings.Contains(sb.devices(), "CORE-1") || strings.Contains(sb.devices(), "other") {
		t.Errorf("the refused rename changed the registry:\n%s", sb.devices())
	}
	// A new device of that name is refused too.
	sb.dev("", "add", "other", "192.168.1.9", "--no-host-key", "--no-lookup")
	if sb.code == 0 || !strings.Contains(sb.stderr(), "SNMP credentials for a device named 'other' are already on disk") ||
		strings.Contains(sb.devices(), "192.168.1.9") {
		t.Errorf("add onto a leftover: %d %q", sb.code, sb.stderr())
	}
	if err := os.Remove(sb.path("state", "snmp", "devices", "other.yaml")); err != nil {
		t.Fatal(err)
	}
	// Removal drops the file (and the directories with the last).
	sb.dev("y\n", "remove", "CORE-1", "-y")
	if _, err := os.Stat(to); !os.IsNotExist(err) {
		t.Errorf("file left after remove: %v", err)
	}
	sb.dev("", "remove", "--all", "-y")
	for _, p := range []string{sb.path("state", "snmp", "devices"), sb.path("state", "snmp")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s left: %v", p, err)
		}
	}
	// import --replace drops the files of what it removes.
	sb.dev("", "add", "a1", "192.168.1.1", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "a2", "192.168.1.2", "--no-host-key", "--no-lookup")
	sb.devSNMP("c-a2\n", "a2", "community", "--stdin")
	sb.run("a1,192.168.1.1\n", []string{"device", "import", "-", "--replace", "-y"})
	sb.expect(0, "1 removed", "")
	if _, err := os.Stat(sb.path("state", "snmp", "devices", "a2.yaml")); !os.IsNotExist(err) {
		t.Errorf("a removed device's file left: %v", err)
	}
	// Anything but a name that fits a file is refused when it would need
	// one, and the registry does not change.
	long := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + "." + strings.Repeat("c", 60) + "." + strings.Repeat("d", 60) + ".example"
	sb.dev("", "add", long, "192.168.1.3", "--no-host-key", "--no-lookup", "--allow-generic")
	sb.devSNMP("x\n", long, "community", "--stdin")
	sb.said(1, "too long to hold SNMP credentials")
	// Such a device is still shown and read with the scope's settings.
	if out := sb.devSNMP("", long); sb.code != 0 || !strings.Contains(out, "SNMP for device '"+long+"'") {
		t.Errorf("show of a long name: %d %q %q", sb.code, out, sb.stderr())
	}
	if out := sb.dev("", "show", long); sb.code != 0 || strings.Contains(out, "cannot be read") {
		t.Errorf("device show of a long name: %d %q", sb.code, out)
	}
}

// The snapshots hold the devices' credentials, in their modes, and a restore
// brings them back (and takes away what the snapshot lacks).
func TestDeviceSNMPFilesAreInSnapshots(t *testing.T) {
	sb := renderedSandbox(t)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.devSNMP("dev-community-9\n", "lab-sw1", "community", "--stdin")
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	sb.run("", []string{"group", "add", "extra", "5", "EXTRA-CLASS"})
	sb.expect(0, "Group 'extra' added", "")
	ids := (&invocation{app: newHarness(t, nil, sb.env...).app}).snapshotIDs()
	if len(ids) == 0 {
		t.Fatal("no snapshot")
	}
	id := ids[0]
	for rel, mode := range map[string]os.FileMode{"snmp": 0o700, "snmp/devices": 0o700, "snmp/devices/lab-sw1.yaml": 0o600, "snmp/lab.yaml": 0o600} {
		st, err := os.Stat(sb.path("state/backups/" + id + "/" + rel))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("snapshot %s: %v %v (want %v)", rel, st, err, mode)
		}
	}
	if got := sb.read("state/backups/" + id + "/snmp/devices/lab-sw1.yaml"); !strings.Contains(got, "dev-community-9") {
		t.Errorf("snapshot's device file: %q", got)
	}
	// Change the credential, add another, then restore.
	sb.devSNMP("changed-3\n", "lab-sw1", "community", "--stdin")
	sb.dev("", "add", "lab-sw2", "192.168.1.2", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.devSNMP("sw2-comm\n", "lab-sw2", "community", "--stdin")
	sb.run("y\n", []string{"backup", "restore", id})
	sb.expect(0, "Restored snapshot "+id+".", "")
	if got := sb.read("state/snmp/devices/lab-sw1.yaml"); !strings.Contains(got, "dev-community-9") {
		t.Errorf("lab-sw1.yaml after the restore: %q", got)
	}
	if _, err := os.Stat(sb.path("state/snmp/devices/lab-sw2.yaml")); !os.IsNotExist(err) {
		t.Errorf("a file the snapshot lacks stayed: %v", err)
	}
	if st, err := os.Stat(sb.path("state/snmp/devices/lab-sw1.yaml")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode: %v %v", st, err)
	}
	if got := sb.read("state/snmp/lab.yaml"); !strings.Contains(got, "lab-community-9") {
		t.Errorf("lab.yaml after the restore: %q", got)
	}
}

// The engineer reads the SNMP settings of the devices of their own scopes
// (with --reveal logged) and changes nothing; another scope's device does not
// exist for them; and no registry write of theirs carries settings in or
// out.
func TestDeviceSNMPEngineer(t *testing.T) {
	sb := engineerSandbox(t)
	sb.devSNMP("lab-dev-comm-1\n", "lab-sw", "community", "--stdin")
	sb.devSNMP("", "lab-sw", "port", "2161")
	sb.devSNMP("prod-dev-comm-1\n", "prod-sw", "community", "--stdin")
	logged := func(dev string) int {
		return sb.runner.Count("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=snmp-device name="+dev+" by=bob")
	}
	out := sb.asEngineer("", "device", "snmp", "lab-sw")
	if sb.code != 0 || strings.Contains(out, "lab-dev-comm-1") || !strings.Contains(out, "community:  set  (device)") || logged("lab-sw") != 0 {
		t.Errorf("show: %d %q (logged %d)", sb.code, out, logged("lab-sw"))
	}
	out = sb.asEngineer("", "device", "snmp", "lab-sw", "show", "--reveal")
	if sb.code != 0 || !strings.Contains(out, "community:  lab-dev-comm-1  (device)") || logged("lab-sw") != 1 {
		t.Errorf("show --reveal: %d %q (logged %d)", sb.code, out, logged("lab-sw"))
	}
	for _, argv := range sb.runner.Argvs() {
		if strings.Contains(argv, "lab-dev-comm-1") {
			t.Errorf("the secret reached a command: %q", argv)
		}
	}
	for _, args := range [][]string{{"clients", "list"}, {"clients"}, {"version"}, {"port"}, {"timeout"}} {
		sb.asEngineer("", append([]string{"device", "snmp", "lab-sw"}, args...)...)
		if sb.code != 0 {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// device show carries the labels, no secret, for the engineer too.
	out = sb.asEngineer("", "device", "show", "lab-sw")
	if sb.code != 0 || !strings.Contains(out, "credentials: community set (device)") || strings.Contains(out, "lab-dev-comm-1") {
		t.Errorf("device show: %d %q", sb.code, out)
	}
	// Another scope's device is not found; nothing is logged.
	for _, args := range [][]string{{}, {"show", "--reveal"}, {"clients", "list"}} {
		sb.asEngineer("", append([]string{"device", "snmp", "prod-sw"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-sw' not found.") {
			t.Errorf("prod-sw %v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if logged("prod-sw") != 0 {
		t.Error("a refused reveal was logged as a read")
	}
	// Setting and clearing are the superuser's; nothing changes.
	before, file := sb.devices(), sb.read("state/snmp/devices/lab-sw.yaml")
	for _, args := range [][]string{{"community", "--stdin"}, {"v3-user", "x", "--stdin"}, {"version", "v3"}, {"clients", "add", "192.0.2.0/24"},
		{"clients", "remove", "192.0.2.0/24"}, {"port", "162"}, {"timeout", "3"}, {"clear"}} {
		sb.asEngineer("x\n", append([]string{"device", "snmp", "lab-sw"}, args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads a device's SNMP settings") ||
			sb.devices() != before || sb.read("state/snmp/devices/lab-sw.yaml") != file {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	// The engineer's other registry writes neither set nor drop settings.
	imp := "version: 1\ndevices:\n  lab-sw: {address: 192.168.1.1, vendor: cisco, snmp: {version: v3}}\n"
	sb.asEngineer(imp, "device", "import", "-")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A device's SNMP settings are not the engineer tier's to change") || sb.devices() != before {
		t.Errorf("import with a map: %d %q", sb.code, sb.stderr())
	}
	imp = "version: 1\ndevices:\n  lab-new: {address: 192.168.1.5, vendor: cisco, snmp: {port: 1161}}\n"
	sb.asEngineer(imp, "device", "import", "-")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A device's SNMP settings are not the engineer tier's to change") || strings.Contains(sb.devices(), "lab-new") {
		t.Errorf("import of a new device with a map: %d %q", sb.code, sb.stderr())
	}
	// Without a map, the device keeps its own: nothing is dropped.
	imp = "version: 1\ndevices:\n  lab-sw: {address: 192.168.1.1, vendor: cisco, description: moved}\n"
	sb.asEngineer(imp, "device", "import", "-")
	if sb.code != 0 || !strings.Contains(sb.devices(), "description: moved") || !strings.Contains(sb.devices(), "port: 2161") {
		t.Errorf("import without a map: %d %q\n%s", sb.code, sb.stderr(), sb.devices())
	}
	// A rename carries the settings and the file; a removal is theirs to do.
	sb.asEngineer("", "device", "rename", "lab-sw", "lab-core")
	if sb.code != 0 || !strings.Contains(sb.read("state/snmp/devices/lab-core.yaml"), "lab-dev-comm-1") || !strings.Contains(sb.devices(), "port: 2161") {
		t.Errorf("rename: %d %q", sb.code, sb.stderr())
	}
	sb.asEngineer("y\n", "device", "remove", "lab-core", "-y")
	if sb.code != 0 {
		t.Errorf("remove: %d %q", sb.code, sb.stderr())
	}
	if _, err := os.Stat(sb.path("state/snmp/devices/lab-core.yaml")); !os.IsNotExist(err) {
		t.Errorf("file left after the engineer's remove: %v", err)
	}
	// The superuser's file of another scope's device was never touched.
	if !strings.Contains(sb.read("state/snmp/devices/prod-sw.yaml"), "prod-dev-comm-1") {
		t.Error("prod-sw's file changed")
	}
}

// The sysName and location lookups, 'device check' and 'device add', read a
// device with the settings of its own: here its community and port are the
// right ones and its scope's and the default's are wrong.
func TestSNMPLookupUsesTheDevicesOwnSettings(t *testing.T) {
	sb := newSandbox(t, true)
	a := &snmp.Agent{SysName: "sw1.site-a.example", SysLocation: "Rack 4", Community: "device-right"}
	conn, err := a.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	port := strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
	// The loopback is in scope dmz; the scope and the default are wrong.
	store := strings.Replace(sb.store(), "prefixes: [203.0.113.0/24]", "prefixes: [203.0.113.0/24, 127.0.0.0/8]", 1)
	sb.write("state/store.yaml", store, 0o600)
	sb.cfgRun("default-wrong\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	sb.cfgRun("", []string{"config", "snmp", "timeout", "1"}, nil)
	sb.scopeSNMP("scope-wrong\n", "dmz", "community", "--stdin")
	sb.scopeSNMP("", "dmz", "port", "9")
	sb.cfgRun("", []string{"device", "add", "sw1", "127.0.0.1", "--no-host-key", "--no-lookup"}, nil)
	check := func() string {
		return plain(sb.cfgRun("", []string{"device", "check", "sw1"}, nil))
	}
	if out := check(); !strings.Contains(out, "SNMP name:   no answer") {
		t.Errorf("scope settings:\n%s", out)
	}
	sb.devSNMP("device-right\n", "sw1", "community", "--stdin")
	sb.devSNMP("", "sw1", "port", port)
	sb.devSNMP("", "sw1", "timeout", "1")
	out := check()
	for _, want := range []string{"SNMP:        version v2c (device), port " + port + " (device), timeout 1 s (device)", "SNMP creds:  community set (device)",
		"SNMP name:   sw1.site-a.example  (match)", "Location:"} {
		if !strings.Contains(out, want) {
			t.Errorf("device check lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "device-right") {
		t.Errorf("device check printed the community:\n%s", out)
	}
	var js []map[string]any
	if err := json.Unmarshal([]byte(sb.cfgRun("", []string{"device", "check", "sw1", "--json"}, nil)), &js); err != nil || len(js) != 1 ||
		js[0]["sysname"] != "sw1.site-a.example" {
		t.Fatalf("--json: %v %v", err, js)
	}
	if sn, _ := js[0]["snmp"].(map[string]any); sn == nil || sn["community_from"] != "device" || sn["port_from"] != "device" || sn["community"] != true {
		t.Errorf("--json snmp: %v", js[0]["snmp"])
	}
	// device location --from-device reads it the same way.
	sb.dev("", "location", "sw1", "--from-device")
	sb.expect(0, "location set to Rack 4 (read from the device)", "")
	// The scope's test is the scope's own settings: it does not answer.
	sb.scopeSNMP("", "dmz", "test", "127.0.0.1")
	sb.said(1, "No answer from 127.0.0.1")
	// Cleared, the device is read with its scope's again.
	sb.devSNMP("", "sw1", "clear")
	if out := check(); !strings.Contains(out, "SNMP name:   no answer") {
		t.Errorf("after clear:\n%s", out)
	}
}

// The walkthrough of a registered device (config <vendor> --name, device
// config show) renders its own credentials and ranges, and says whose they
// are; an engineer's read of them is logged as the device's.
func TestWalkthroughUsesTheDevicesOwnSNMP(t *testing.T) {
	sb := engineerSandbox(t)
	sb.cfgRun("def-comm-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24")
	sb.scopeSNMP("", "lab", "contact", "NOC")
	sb.devSNMP("lab-dev-comm-1\n", "lab-sw", "community", "--stdin")
	sb.devSNMP("", "lab-sw", "clients", "add", "192.0.2.0/24")
	route := func(r *fake.Runner) {
		r.On([]string{"ip", "-4", "route", "get", "1.0.0.0"}, execx.Result{Stdout: []byte("1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0\n")})
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
	}
	out := plain(sb.cfgRun("", []string{"device", "config", "show", "lab-sw"}, route, "SUDO_USER=bob"))
	for _, want := range []string{"snmp-server community lab-dev-comm-1 RO TACCTL-SNMP", "Credentials: this device's own (tacctl device snmp lab-sw show --reveal).",
		"Allowed clients: the tacctl server first, this device's own ranges, then everything else", "permit 192.0.2.0 0.0.0.255",
		"SNMP:", "credentials: community set (device)"} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("device config show lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	if strings.Contains(out, "198.51.100.0") || strings.Contains(out, "def-comm-1") {
		t.Errorf("the scope's clients or the default's community reached a device that sets its own:\n%s", out)
	}
	if n := sb.runner.Count("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=snmp-device name=lab-sw by=bob"); n != 1 {
		t.Errorf("device reveal logged %d times", n)
	}
	// Without a registered device named, the scope's settings render.
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route, "SUDO_USER=bob"))
	if !strings.Contains(out, "snmp-server community def-comm-1 RO") || strings.Contains(out, "lab-dev-comm-1") || !strings.Contains(out, "198.51.100.0") {
		t.Errorf("scope walkthrough:\n%s", out)
	}
}

// The SNMP section of a pull and a diff is compared with the device's own
// settings over its scope's (D72): a device that sets its own client ranges
// is expected to have those, not the scope's.
func TestPullSNMPSectionUsesTheDevicesOwnSettings(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j1", "192.168.1.20", "juniper"}, [3]string{"lab-j2", "192.168.1.21", "juniper"})
	b.run("scope", "snmp", "lab", "version", "v2c")
	b.sb.cfgRun("scope-community-9\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route)
	b.run("scope", "snmp", "lab", "clients", "add", "198.51.100.0/24")
	b.run("scope", "snmp", "lab", "contact", "NOC")
	b.sb.cfgRun("dev-community-9\n", []string{"device", "snmp", "lab-j1", "community", "--stdin"}, route)
	b.run("device", "snmp", "lab-j1", "clients", "add", "192.0.2.0/24")
	sib, own := b.expected("lab-j2"), b.expected("lab-j1")
	if !strings.Contains(own, "192.0.2.0/24") || strings.Contains(own, "198.51.100.0/24") ||
		!strings.Contains(sib, "198.51.100.0/24") || strings.Contains(sib, "192.0.2.0/24") {
		t.Fatalf("the expected text does not use the device's own ranges:\n--- lab-j1\n%s\n--- lab-j2\n%s", own, sib)
	}
	// The community's value is the device's own in the rendering.
	if !strings.Contains(own, "dev-community-9") || strings.Contains(own, "scope-community-9") || !strings.Contains(sib, "scope-community-9") {
		t.Errorf("communities:\n%s\n---\n%s", own, sib)
	}
	// A device that has what the device's own settings say is ok; one with
	// the scope's ranges differs in the SNMP section.
	b.serve("juniper", own)
	out := b.run("device", "config", "pull", "lab-j1")
	if b.sb.code != 0 || !strings.Contains(out, "lab-j1  ok via netconf") {
		t.Errorf("own text, pull: %d\n%s", b.sb.code, out)
	}
	b.serve("juniper", sib)
	out = b.run("device", "config", "diff", "lab-j1", "--pull", "--section", "snmp")
	if !strings.Contains(out, "192.0.2.0/24") || !strings.Contains(out, "198.51.100.0/24") || !strings.Contains(out, "differs") {
		t.Errorf("scope text against the device's own settings:\n%s", out)
	}
	// The sibling is compared with the scope's.
	out = b.run("device", "config", "pull", "lab-j2")
	if b.sb.code != 0 || !strings.Contains(out, "lab-j2  ok via netconf") {
		t.Errorf("sibling: %d\n%s", b.sb.code, out)
	}
	// Nothing of a secret is in the stored sections or the diff.
	data, _ := os.ReadFile(b.sb.path("var-lib/device-config/lab-j1.yaml"))
	noSecrets(t, "the sections file", string(data), "dev-community-9", "scope-community-9")
	noSecrets(t, "the diff", out, "dev-community-9", "scope-community-9")
	// A device's own credentials file that cannot be read is that device's
	// problem, not a comparison against the scope's.
	b.sb.write("state/snmp/devices/lab-j1.yaml", "version: 1\nbogus: yes\n", 0o600)
	out = b.run("device", "config", "pull", "lab-j1", "lab-j2")
	if b.sb.code != 1 || !strings.Contains(out, "lab-j1  failed: cannot build the expected configuration: the device's own SNMP settings cannot be read") || !strings.Contains(out, "lab-j2  ok via netconf") {
		t.Errorf("unreadable file: %d\n%s", b.sb.code, out)
	}
}
