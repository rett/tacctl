package cli

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/snmpcred"
)

// 'device clone' (0.2.23, D307): a copy of a device's intent registered at a
// bench address, with the bench /32 added to the scope first; nothing that
// belongs to the one device that is there comes along.

const (
	cloneSrc = "jsw1.lab.example.net"
	cloneNew = "jsw2.lab.example.net"
	cloneKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	// the sources' passphrases never appear in an output or a log line
	cloneAuth, clonePriv = "example-auth-passphrase", "example-priv-passphrase"
)

// cloneFixture is a Junos device with everything the registry, the SNMP
// credentials, the blocks and the records can hold of it.
func cloneFixture(t *testing.T) *sandbox {
	t.Helper()
	sb := renderedSandbox(t)
	sb.blocksDeviceFixture(cloneSrc, devBlocksKey)
	for _, args := range [][]string{
		{"description", cloneSrc, "Core", "switch"}, {"location", cloneSrc, "Rack", "4,", "DC1"},
		{"hostname", cloneSrc, "jsw1.example.net"}, {"port", cloneSrc, "2222"}, {"timeout-scale", cloneSrc, "2"},
		{"netconf", cloneSrc, "enable"}, {"notice", cloneSrc, "ack", "hostkey-unpinned"},
	} {
		sb.dev("", args...)
		sb.expect(0, "", "")
	}
	sb.devSNMP("example-community\n", cloneSrc, "community", "--stdin")
	sb.devSNMP(cloneAuth+"\n"+clonePriv+"\n", cloneSrc, "v3-user", "add", "monitor", "--default", "--stdin")
	sb.devSNMP(cloneAuth+"2\n"+clonePriv+"2\n", cloneSrc, "v3-user", "add", "backup", "--stdin")
	sb.devSNMP("", cloneSrc, "port", "1161")
	sb.write("state/devices.yaml", strings.Replace(sb.devices(), "    ack: [hostkey-unpinned]\n", "    host_keys: ["+cloneKey+"]\n    ack: [hostkey-unpinned]\n", 1), 0o600)
	sb.write("var-lib/devices-config.json", `{"version":1,"updated":"2026-10-09T12:00:00Z","devices":{
"`+cloneSrc+`":{"vendor":"juniper","transport":"ssh","pulled":"2026-10-09T12:00:00Z","by":"alice","result":"ok","secrets_visible":true,"sections":{"aaa":{"state":"ok"}}}}}`, 0o600)
	return sb
}

func TestDeviceCloneCopiesTheIntent(t *testing.T) {
	sb := cloneFixture(t)
	before := sb.devices()
	snaps := sb.snapshots()
	srcSNMP := sb.read("state/snmp/devices/" + cloneSrc + ".yaml")
	records := sb.read("var-lib/devices-config.json")

	out := sb.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	if sb.code != 0 {
		t.Fatalf("clone: %d %q %q", sb.code, out, sb.stderr())
	}
	audited := auditLines(sb.runner)
	for _, want := range []string{"Staging address 192.0.2.77/32 added to scope 'lab'", "Device '" + cloneNew + "' registered as a copy of '" + cloneSrc + "': 192.0.2.77, juniper, scope lab.",
		"Copied:     the registry settings, the SNMP credentials (2 v3 users), 2 configuration block files",
		"Not copied: the address, name, DNS name, host keys, acknowledged notices, break-glass hold and configuration record of '" + cloneSrc + "'",
		"tacctl device rename " + cloneNew + " " + cloneSrc + " --replace"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	// The registry: the plain fields, the SNMP settings, the NETCONF
	// setting and the timing scale; not the DNS name, the host keys or the
	// acknowledged notices. The original is as it was.
	want := before + "  " + cloneNew + ":\n    address: 192.0.2.77\n    vendor: juniper\n    port: 2222\n    description: Core switch\n" +
		"    location: Rack 4, DC1\n    snmp: {version: v2c, port: 1161}\n    netconf: {state: enable}\n    timeout_scale: 2\n"
	if got := sb.devices(); got != want {
		t.Errorf("devices.yaml:\n%s\nwant\n%s", got, want)
	}

	// The credentials file is the original's, users and default included,
	// of its own under the new name; the original's is untouched.
	got := sb.read("state/snmp/devices/" + cloneNew + ".yaml")
	if got != srcSNMP || !strings.Contains(got, "default: monitor") || !strings.Contains(got, "name: backup") || !strings.Contains(got, "community") {
		t.Errorf("the clone's credentials:\n%s\nthe original's:\n%s", got, srcSNMP)
	}
	if fi, err := os.Stat(sb.path("state", "snmp", "devices", cloneNew+".yaml")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("credentials file: %v %v", fi, err)
	}
	if sb.read("state/snmp/devices/"+cloneSrc+".yaml") != srcSNMP {
		t.Error("the original's credentials changed")
	}

	// The blocks: the files (0600, in 0700 directories) and the manifest.
	newDir := "state/blocks/_devices/" + cloneNew + "/juniper/"
	oldDir := "state/blocks/_devices/" + cloneSrc + "/juniper/"
	for _, b := range []string{"snmp", "system"} {
		if sb.read(newDir+b) != sb.read(oldDir+b) || sb.read(newDir+b) == "" {
			t.Errorf("block %s: %q, the original's %q", b, sb.read(newDir+b), sb.read(oldDir+b))
		}
		if fi, err := os.Stat(sb.path(newDir + b)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("block file %s: %v %v", b, fi, err)
		}
	}
	if fi, err := os.Stat(sb.path(newDir)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("blocks directory: %v %v", fi, err)
	}
	if o := sb.overrides(); !strings.Contains(o, devBlocksKey) || !strings.Contains(o, "  jsw2~lab~example~net:\n    juniper:\n    - snmp\n    - system\n") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}

	// The bench address is a /32 of the scope, and the staging line names
	// the clone; the pull record is the original's alone.
	if st := sb.read("state/staging"); !strings.HasPrefix(st, "192.0.2.77/32|lab|device|"+cloneNew+"|") {
		t.Errorf("staging:\n%s", st)
	}
	if m := plain(sb.run("", []string{"scope", "show", "lab"})); !strings.Contains(m, "192.0.2.77/32") {
		t.Errorf("scope lab:\n%s", m)
	}
	if sb.read("var-lib/devices-config.json") != records {
		t.Error("the pull records changed")
	}

	// One snapshot of the state before any of it, and an audit line of
	// names and counts.
	if sb.snapshots() != snaps+1 {
		t.Errorf("snapshots: %d, was %d", sb.snapshots(), snaps)
	}
	if !strings.Contains("\n"+strings.Join(audited, "\n"), "\ndevice clone from="+cloneSrc+" to="+cloneNew+" address=192.0.2.77 scope=lab snmp_users=2 block_files=2 count=1 by=") {
		t.Errorf("audit lines %q", audited)
	}
	for _, s := range []string{cloneAuth, clonePriv, "example-community"} {
		if strings.Contains(out, s) || strings.Contains(strings.Join(audited, "\n"), s) {
			t.Errorf("%q is printed or logged", s)
		}
	}

	// The clone is a device of its own from now on: a second clone of the
	// clone, and the original, carry on.
	sb.dev("", "clone", cloneNew, "jsw3.lab.example.net", "--staging", "192.0.2.78")
	sb.expect(0, "", "")
	if !strings.Contains(sb.read("state/snmp/devices/jsw3.lab.example.net.yaml"), "default: monitor") {
		t.Error("a clone of a clone has no credentials")
	}
}

// A device without credentials, blocks or settings is cloned as well: no
// file is made for what there is none of.
func TestDeviceCloneOfAPlainDevice(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	sb.dev("", "clone", "lab-sw1", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "Copied:     the registry settings\n", "")
	if !strings.Contains(sb.devices(), "  lab-sw2: {address: 192.0.2.77, vendor: cisco}\n") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}
	for _, p := range []string{"state/snmp", "state/blocks"} {
		if sb.fileExists(p) {
			t.Errorf("%s was made", p)
		}
	}
	// A staging address its scope covers already is no staging: the clone
	// is registered, and no /32 is added.
	sb.dev("", "clone", "lab-sw1", "lab-sw3", "--staging", "192.168.1.3")
	sb.expect(0, "no staging address is needed", "")
	if strings.Contains(sb.read("state/staging"), "192.168.1.3") {
		t.Errorf("staging:\n%s", sb.read("state/staging"))
	}
}

// Every refusal changes nothing: the registry, the files, the scope and the
// staging file are as they were, and no snapshot is taken for a refusal that
// needs no change.
func TestDeviceCloneRefusals(t *testing.T) {
	sb := cloneFixture(t)
	sb.dev("", "add", "lab-sw9", "192.168.1.9", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	state := func() string {
		return sb.devices() + "|" + sb.overrides() + "|" + sb.read("state/store.yaml") + "|" + strings.Join(sb.leftovers("snmp/devices/*"), ",") + "|" + strings.Join(sb.leftovers("blocks/_devices/*"), ",")
	}
	was, snaps := state(), sb.snapshots()
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"clone", cloneSrc, cloneNew}, "--staging <bench-ip> is required"},
		{[]string{"clone", cloneSrc, cloneNew, "--staging", "2001:db8::1"}, "--staging takes the device's bench IPv4 address"},
		{[]string{"clone", cloneSrc, cloneNew, "--staging", "192.0.2.0/24"}, "--staging takes the device's bench IPv4 address"},
		{[]string{"clone", cloneSrc, cloneNew, "--staging", "bench"}, "--staging takes the device's bench IPv4 address"},
		{[]string{"clone", cloneSrc, cloneSrc, "--staging", "192.0.2.77"}, "is the device to copy"},
		{[]string{"clone", cloneSrc, "JSW1.lab.example.net", "--staging", "192.0.2.77"}, "is the device to copy"},
		{[]string{"clone", cloneSrc, "lab-sw9", "--staging", "192.0.2.77"}, "'lab-sw9' is already registered"},
		{[]string{"clone", cloneSrc, "Lab-Sw9", "--staging", "192.0.2.77"}, "already registered"},
		{[]string{"clone", cloneSrc, "Jsw2.lab.example.net", "--staging", "192.0.2.77"}, "lower case"},
		{[]string{"clone", cloneSrc, "switch1", "--staging", "192.0.2.77"}, "generic name"},
		{[]string{"clone", cloneSrc, "bad name", "--staging", "192.0.2.77"}, "name"},
		{[]string{"clone", cloneSrc, cloneNew, "--staging", "192.168.1.9"}, "already registered as 'lab-sw9'"},
		{[]string{"clone", cloneSrc, cloneNew, "--staging", "192.168.1.20"}, "already registered as '" + cloneSrc + "'"},
		{[]string{"clone", "nosuch", cloneNew, "--staging", "192.0.2.77"}, "Device 'nosuch' not found"},
		{[]string{"clone", cloneSrc, "--staging", "192.0.2.77"}, "Usage: tacctl device clone"},
		{[]string{"clone", cloneSrc, cloneNew, "x", "--staging", "192.0.2.77"}, "Usage: tacctl device clone"},
		{[]string{"clone", cloneSrc, cloneNew, "--stage", "192.0.2.77"}, "Unknown option: '--stage'"},
	} {
		sb.dev("", c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.msg) {
			t.Errorf("%v: %d %q, want %q", c.args, sb.code, sb.stderr(), c.msg)
		}
		if state() != was || sb.snapshots() != snaps {
			t.Errorf("%v: something changed", c.args)
		}
	}
	// A staging address that another scope answers is taken from it only by
	// the verbs that say so: refused, after nothing but the snapshot.
	sb.dev("", "clone", cloneSrc, cloneNew, "--staging", "10.99.0.77")
	if sb.code == 0 && !strings.Contains(sb.read("state/staging"), "10.99.0.77/32|lab|") {
		t.Errorf("staging a prod address: %d\n%s", sb.code, sb.read("state/staging"))
	}

	// Leftovers of an earlier device of the name are refused, as for 'add'.
	sb2 := cloneFixture(t)
	sb2.write("state/snmp/devices/"+cloneNew+".yaml", "version: 2\ncommunity: example-leftover\n", 0o600)
	was2 := sb2.devices()
	sb2.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	if sb2.code != 1 || !strings.Contains(sb2.stderr(), "SNMP credentials for a device named '"+cloneNew+"' are already on disk") || sb2.devices() != was2 || sb2.fileExists("state/staging") {
		t.Errorf("a leftover credentials file: %d %q", sb2.code, sb2.stderr())
	}
	sb3 := cloneFixture(t)
	if err := os.MkdirAll(sb3.path("state", "blocks", "_devices", cloneNew), 0o700); err != nil {
		t.Fatal(err)
	}
	was3 := sb3.devices()
	sb3.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	if sb3.code != 1 || !strings.Contains(sb3.stderr(), "Configuration blocks for a device named '"+cloneNew+"' are already on disk") || sb3.devices() != was3 || sb3.fileExists("state/staging") {
		t.Errorf("a leftover blocks directory: %d %q", sb3.code, sb3.stderr())
	}
}

// A device no scope answers has no scope to stage the bench address in.
func TestDeviceCloneOfADeviceNoScopeAnswers(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lost-sw1", "198.51.100.5", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	was := sb.devices()
	sb.dev("", "clone", "lost-sw1", "lost-sw2", "--staging", "192.0.2.77")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "which no scope answers") || sb.devices() != was || sb.fileExists("state/staging") {
		t.Errorf("%d %q", sb.code, sb.stderr())
	}
}

// A write that fails after the registry's takes the registry line, the files
// and the staging address back: the clone is all or nothing.
func TestDeviceCloneIsAllOrNothing(t *testing.T) {
	sb := cloneFixture(t)
	was, prefixes := sb.devices(), plain(sb.run("", []string{"scope", "show", "lab"}))
	// A directory where the credentials file goes appears after the checks
	// and before the registry's write: the file cannot be written.
	once := true
	sb.hooks.deviceWriteStep = func() {
		if once {
			once = false
			if err := os.MkdirAll(sb.path("state", "snmp", "devices", cloneNew+".yaml"), 0o700); err != nil {
				t.Error(err)
			}
		}
	}
	sb.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The clone was not made. Nothing was kept.") {
		t.Fatalf("%d %q", sb.code, sb.stderr())
	}
	if sb.devices() != was || sb.fileExists("state/staging") || sb.fileExists("state/blocks/_devices/"+cloneNew) ||
		strings.Contains(sb.overrides(), "jsw2~lab") || plain(sb.run("", []string{"scope", "show", "lab"})) != prefixes {
		t.Errorf("something of the clone is left:\n%s\n%s", sb.devices(), sb.read("state/staging"))
	}
	// The same run, with nothing in the way, makes the clone.
	sb.hooks.deviceWriteStep = nil
	sb.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	sb.expect(0, "", "")
}

// The snapshot of a clone holds the state before it: none of the clone.
func TestDeviceCloneSnapshotIsTheStateBefore(t *testing.T) {
	sb := cloneFixture(t)
	before := map[string]bool{}
	for _, id := range snapshot.IDs(sb.path("state", "backups")) {
		before[id] = true
	}
	sb.dev("", "clone", cloneSrc, cloneNew, "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	n := 0
	for _, id := range snapshot.IDs(sb.path("state", "backups")) {
		if before[id] {
			continue
		}
		n++
		reg, err := os.ReadFile(sb.path("state", "backups", id, "devices.yaml"))
		if err != nil || strings.Contains(string(reg), cloneNew) {
			t.Errorf("snapshot %s: %v\n%s", id, err, reg)
		}
	}
	if n != 1 {
		t.Errorf("%d new snapshots, want one", n)
	}
}

// An engineer clones a device of their own scopes, the SNMP credentials
// included (they read them today); another scope's device is not found, and
// a bench address another scope answers is refused, naming the scope.
func TestEngineerCloneInOwnScopes(t *testing.T) {
	sb := engineerSandbox(t)
	sb.devSNMP("example-community\n", "lab-sw", "community", "--stdin")
	sb.devSNMP(cloneAuth+"\n"+clonePriv+"\n", "lab-sw", "v3-user", "add", "monitor", "--default", "--stdin")
	sb.devSNMP("", "lab-sw", "port", "1161")
	srcSNMP := sb.read("state/snmp/devices/lab-sw.yaml")
	if srcSNMP == "" {
		t.Fatal("no credentials")
	}

	out := sb.asEngineer("", "device", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	if sb.code != 0 || !strings.Contains(out, "Device 'lab-sw2' registered as a copy of 'lab-sw'") || !strings.Contains(out, "the SNMP credentials (1 v3 user)") {
		t.Fatalf("clone: %d %q %q", sb.code, out, sb.stderr())
	}
	if sb.read("state/snmp/devices/lab-sw2.yaml") != srcSNMP || !strings.Contains(sb.devices(), "  lab-sw2:\n    address: 192.0.2.77\n    vendor: cisco\n    snmp: {version: v2c, port: 1161}\n") {
		t.Errorf("the copy:\n%s\n%s", sb.read("state/snmp/devices/lab-sw2.yaml"), sb.devices())
	}
	if !strings.HasPrefix(sb.read("state/staging"), "192.0.2.77/32|lab|device|lab-sw2|") {
		t.Errorf("staging: %q", sb.read("state/staging"))
	}
	if line := auditLine(sb.runner, "device clone from=lab-sw to=lab-sw2 address=192.0.2.77 scope=lab snmp_users=1 block_files=0 count=1 by=bob"); line == "" {
		t.Errorf("audit lines: %q", auditLines(sb.runner))
	}
	for _, s := range []string{cloneAuth, clonePriv, "example-community"} {
		if strings.Contains(out, s) || strings.Contains(strings.Join(auditLines(sb.runner), "\n"), s) {
			t.Errorf("%q is printed or logged", s)
		}
	}

	was := sb.devices() + sb.read("state/staging")
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"clone", "prod-sw", "prod-sw2", "--staging", "192.0.2.78"}, "Device 'prod-sw' not found"},
		{[]string{"clone", "web1", "web2", "--staging", "192.0.2.78"}, "Device 'web1' not found"},
		{[]string{"clone", "lab-sw", "lab-sw3", "--staging", "10.99.0.78"}, "is answered by scope 'prod', which is not one of yours"},
		{[]string{"clone", "lab-sw", "lab-sw3", "--staging", "192.0.2.10"}, "is not available for staging"},
	} {
		sb.asEngineer("", append([]string{"device"}, c.args...)...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.msg) {
			t.Errorf("%v: %d %q, want %q", c.args, sb.code, sb.stderr(), c.msg)
		}
		if sb.devices()+sb.read("state/staging") != was {
			t.Errorf("%v changed something", c.args)
		}
	}
	// The exception for the copied settings is the clone's alone: an
	// engineer's registration of a new device with the same settings is
	// still refused.
	sb.asEngineer("version: 1\ndevices:\n  lab-new: {address: 192.168.1.5, vendor: cisco, snmp: {version: v2c, port: 1161}}\n", "device", "import", "-")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A device's SNMP settings are not the engineer tier's to change") || strings.Contains(sb.devices(), "lab-new") {
		t.Errorf("import of a new device with settings: %d %q", sb.code, sb.stderr())
	}
}

// cloneCreds reads a device's credentials file as the store does.
func cloneCreds(t *testing.T, sb *sandbox, name string) snmpcred.Creds {
	t.Helper()
	c, err := snmpcred.LoadDevice(sb.path("state", "snmp"), name)
	if err != nil {
		t.Fatal(err)
	}
	c.Format = 0
	return c
}

// The copied credentials file is written as the registry line the copy gets
// allows (snmpcred.Store.Mapped): a file that fits version 1 stays version 1
// when the copy carries the source's snmp: entry, and a device without the
// entry (a version 2 pool file counts in force without one) has a version 2
// file that is copied without loss, whatever it holds.
func TestDeviceCloneWritesTheFileThatTheCopysEntryAllows(t *testing.T) {
	// (a) an entry, one user that is the default: version 1 on both.
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.devSNMP("example-community\n", "lab-sw1", "community", "--stdin")
	sb.devSNMP(cloneAuth+"\n"+clonePriv+"\n", "lab-sw1", "v3-user", "add", "monitor", "--default", "--stdin")
	sb.devSNMP("", "lab-sw1", "port", "1161")
	src := sb.read("state/snmp/devices/lab-sw1.yaml")
	if !strings.Contains(src, "version: 1\n") {
		t.Fatalf("the source file is not version 1:\n%s", src)
	}
	sb.dev("", "clone", "lab-sw1", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	if got := sb.read("state/snmp/devices/lab-sw2.yaml"); got != src {
		t.Errorf("the copy of a version 1 file:\n%s\nsource:\n%s", got, src)
	}
	if !reflect.DeepEqual(cloneCreds(t, sb, "lab-sw2"), cloneCreds(t, sb, "lab-sw1")) {
		t.Error("the copy does not parse back equal")
	}
	if !strings.Contains(sb.devices(), "  lab-sw2:\n    address: 192.0.2.77\n    vendor: cisco\n    snmp: {version: v2c, port: 1161}\n") {
		t.Errorf("devices.yaml:\n%s", sb.devices())
	}

	// (b) no entry, a version 2 file that would fit version 1: both stay version 2.
	sb = newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	v2 := "# tacctl SNMP credentials of one device (D72). Secret: 0600, never printed.\nversion: 2\ncommunity: example-community\nusers:\n- {name: monitor, auth_passphrase: " + cloneAuth + ", priv_passphrase: " + clonePriv + "}\ndefault: monitor\n"
	sb.write("state/snmp/devices/lab-sw1.yaml", v2, 0o600)
	sb.dev("", "clone", "lab-sw1", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "(1 v3 user)", "")
	if got := sb.read("state/snmp/devices/lab-sw2.yaml"); !strings.Contains(got, "version: 2\n") || strings.Contains(got, "version: 1\n") {
		t.Errorf("the copy of a version 2 file with no entry:\n%s", got)
	}
	if !reflect.DeepEqual(cloneCreds(t, sb, "lab-sw2"), cloneCreds(t, sb, "lab-sw1")) {
		t.Errorf("the copy does not parse back equal:\n%s", sb.read("state/snmp/devices/lab-sw2.yaml"))
	}
	if !strings.Contains(sb.devices(), "  lab-sw2: {address: 192.0.2.77, vendor: cisco}\n") {
		t.Errorf("the copy has an entry:\n%s", sb.devices())
	}

	// (c) no entry, a pool of two users and a default that is not the first,
	// and a user whose default names the scope's: users and default exactly.
	sb = newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	pool := "version: 2\nusers:\n- {name: monitor, auth_passphrase: " + cloneAuth + ", priv_passphrase: " + clonePriv + "}\n- {name: backup, auth_passphrase: " + cloneAuth + "2, priv_passphrase: " + clonePriv + "2}\ndefault: backup\n"
	sb.write("state/snmp/devices/lab-sw1.yaml", pool, 0o600)
	sb.dev("", "clone", "lab-sw1", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "(2 v3 users)", "")
	got, want := cloneCreds(t, sb, "lab-sw2"), cloneCreds(t, sb, "lab-sw1")
	if !reflect.DeepEqual(got, want) || got.Default != "backup" || len(got.Users) != 2 || got.Users[0].Name != "monitor" {
		t.Errorf("the pool:\n%s", sb.read("state/snmp/devices/lab-sw2.yaml"))
	}

	// (d) no entry, a default that names a user of the scope's pool (no user of
	// its own): the file is copied as it is.
	sb = newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.write("state/snmp/devices/lab-sw1.yaml", "version: 2\ndefault: scope-user\n", 0o600)
	sb.dev("", "clone", "lab-sw1", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	if got := cloneCreds(t, sb, "lab-sw2"); got.Default != "scope-user" || len(got.Users) != 0 || !reflect.DeepEqual(got, cloneCreds(t, sb, "lab-sw1")) {
		t.Errorf("a default of another level:\n%s", sb.read("state/snmp/devices/lab-sw2.yaml"))
	}
}
