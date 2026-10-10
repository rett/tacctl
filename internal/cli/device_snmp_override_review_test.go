package cli

import (
	"encoding/json"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/snmp"
)

// The review round of WP11.7 (D72): the snapshot a credential change takes
// holds the old credential, a file that cannot be parsed can be repaired, a
// restore makes the devices' files match the restored registry, the SNMPv3
// user's name is the engineer tier's, and a reveal is logged for each level
// the secrets come from.

func (sb *sandbox) snapIDs() map[string]bool {
	sb.t.Helper()
	out := map[string]bool{}
	for _, id := range snapshot.IDs(sb.path("state", "backups")) {
		out[id] = true
	}
	return out
}

// snapHolds reports whether a snapshot not in before has rel with want in
// it (and, when also is set, devices.yaml with it).
func (sb *sandbox) snapHolds(before map[string]bool, rel, want, alsoDevices string) bool {
	sb.t.Helper()
	for id := range sb.snapIDs() {
		if before[id] {
			continue
		}
		data, err := os.ReadFile(sb.path("state", "backups", id, rel))
		if err != nil || !strings.Contains(string(data), want) {
			continue
		}
		if alsoDevices != "" {
			reg, err := os.ReadFile(sb.path("state", "backups", id, "devices.yaml"))
			if err != nil || !strings.Contains(string(reg), alsoDevices) {
				continue
			}
		}
		return true
	}
	return false
}

// m1: the snapshot is taken before the file is written or removed.
func TestDeviceSNMPSnapshotHoldsTheOldCredential(t *testing.T) {
	sb := renderedSandbox(t)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	file := "snmp/devices/lab-sw1.yaml"
	sb.devSNMP("old-community-1\n", "lab-sw1", "community", "--stdin")

	// Replacing the community.
	before := sb.snapIDs()
	sb.devSNMP("new-community-2\n", "lab-sw1", "community", "--stdin")
	sb.said(0, "SNMP community of device 'lab-sw1' set")
	if !sb.snapHolds(before, file, "old-community-1", "snmp:") {
		t.Errorf("no snapshot of a community change holds the old file and the registry as they were (%d new)", len(sb.snapIDs())-len(before))
	}

	// Replacing it with a v3 user: the file the snapshot holds is the old one.
	before = sb.snapIDs()
	sb.devSNMP("v3-auth-pass-1\nv3-priv-pass-1\n", "lab-sw1", "v3-user", "carol", "--stdin")
	sb.said(0, "SNMPv3 user and passphrases of device 'lab-sw1' set")
	if !sb.snapHolds(before, file, "new-community-2", "version: v2c") {
		t.Errorf("no snapshot of a v3-user change holds the old file")
	}

	// clear.
	before = sb.snapIDs()
	sb.devSNMP("", "lab-sw1", "clear")
	sb.said(0, "removed: its scope's")
	if !sb.snapHolds(before, file, "v3-auth-pass-1", "snmp:") {
		t.Errorf("no snapshot of a clear holds the file that was removed")
	}
	if _, err := os.Stat(sb.path("state", file)); !os.IsNotExist(err) {
		t.Errorf("the file is left: %v", err)
	}

	// A credentials file with no map: clear takes a snapshot of it too.
	sb.write("state/"+file, "version: 1\ncommunity: stray-community-3\n", 0o600)
	before = sb.snapIDs()
	sb.devSNMP("", "lab-sw1", "clear")
	sb.said(0, "removed: its scope's")
	if !sb.snapHolds(before, file, "stray-community-3", "") {
		t.Errorf("no snapshot of a clear of a lone file holds it")
	}
	if _, err := os.Stat(sb.path("state", file)); !os.IsNotExist(err) {
		t.Errorf("the lone file is left: %v", err)
	}
	// Nothing to clear takes no snapshot.
	before = sb.snapIDs()
	sb.devSNMP("", "lab-sw1", "clear")
	sb.said(0, "nothing was changed")
	if got := sb.snapIDs(); len(got) != len(before) {
		t.Errorf("a clear of nothing took a snapshot")
	}
}

// m2: a credentials file that cannot be parsed is repaired with tacctl.
func TestDeviceSNMPUnreadableFileIsRepairable(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.dev("", "add", "lab-sw2", "192.168.1.2", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	file := "state/snmp/devices/lab-sw1.yaml"
	bad := "version: 1\nbogus: [unclosed\n"
	// The map gates the file: with the device's settings in place the file
	// is read, and read as unreadable.
	sb.devSNMP("", "lab-sw1", "version", "v2c")
	sb.write(file, bad, 0o600)

	// Reads name the file, say how to remove it, and fail.
	for _, args := range [][]string{{"lab-sw1"}, {"lab-sw1", "port"}, {"lab-sw1", "clients"}} {
		sb.devSNMP("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "lab-sw1.yaml") ||
			!strings.Contains(sb.stderr(), "Remove the unreadable file with: tacctl device snmp lab-sw1 clear") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if out := sb.dev("", "show", "lab-sw1"); sb.code != 0 || !strings.Contains(out, "SNMP:") || !strings.Contains(out, "cannot be read") ||
		!strings.Contains(out, "tacctl device snmp lab-sw1 clear") {
		t.Errorf("device show: %d\n%s", sb.code, out)
	}
	// The scope lists it rather than skipping it.
	if out := sb.scopeSNMP("", "lab", "show"); !strings.Contains(out, "lab-sw1 (credentials file unreadable: tacctl device snmp lab-sw1 clear)") {
		t.Errorf("scope snmp show:\n%s", out)
	}
	// The sibling is unaffected.
	if out := sb.devSNMP("", "lab-sw2"); sb.code != 0 || !strings.Contains(out, "SNMP for device 'lab-sw2'") {
		t.Errorf("lab-sw2: %d %q", sb.code, out)
	}

	// clear never parses it.
	sb.devSNMP("", "lab-sw1", "clear")
	sb.said(0, "removed: its scope's")
	if _, err := os.Stat(sb.path(file)); !os.IsNotExist(err) {
		t.Errorf("the file is left: %v", err)
	}
	if out := sb.devSNMP("", "lab-sw1"); sb.code != 0 || !strings.Contains(out, "SNMP for device 'lab-sw1'") {
		t.Errorf("after clear: %d %q", sb.code, out)
	}

	// community and v3-user replace it, saying so, and the file is good.
	for _, tc := range []struct {
		stdin string
		args  []string
		want  string
	}{
		{"fresh-community-1\n", []string{"lab-sw1", "community", "--stdin"}, "community:  fresh-community-1  (device)"},
		{"fresh-auth-pass-1\nfresh-priv-pass-1\n", []string{"lab-sw1", "v3-user", "carol", "--stdin"}, "auth fresh-auth-pass-1, priv fresh-priv-pass-1  (device)"},
	} {
		sb.devSNMP("", "lab-sw1", "version", "v2c")
		sb.write(file, bad, 0o600)
		sb.devSNMP(tc.stdin, tc.args...)
		if sb.code != 0 || !strings.Contains(sb.stderr()+sb.plainOut(), "was unreadable") || !strings.Contains(sb.stderr()+sb.plainOut(), "it is replaced") {
			t.Errorf("%v: %d out %q err %q", tc.args, sb.code, sb.plainOut(), sb.stderr())
		}
		if out := sb.devSNMP("", "lab-sw1", "show", "--reveal"); !strings.Contains(out, tc.want) {
			t.Errorf("%v: show lacks %q:\n%s", tc.args, tc.want, out)
		}
	}
	if fi, err := os.Stat(sb.path(file)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("repaired file: %v %v", fi, err)
	}
}

// m3: the devices' files follow the registry of the snapshot restored.
func TestRestoreMakesDeviceFilesMatchTheSnapshot(t *testing.T) {
	file := "state/snmp/devices/sw1.yaml"
	t.Run("a snapshot with no credentials directory", func(t *testing.T) {
		sb := renderedSandbox(t)
		sb.dev("", "add", "sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
		sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
		// The scope's file is not in the snapshot either: remove it, so the
		// snapshot to come holds no credentials directory at all.
		sb.scopeSNMP("", "lab", "clear")
		sb.run("", []string{"group", "add", "extra", "5", "EXTRA-CLASS"})
		sb.expect(0, "Group 'extra' added", "")
		ids := snapshot.IDs(sb.path("state", "backups"))
		id := ids[0]
		if _, err := os.Stat(sb.path("state", "backups", id, "snmp")); !os.IsNotExist(err) {
			t.Fatalf("the snapshot has a credentials directory: %v", err)
		}
		sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
		sb.devSNMP("dev-community-1\n", "sw1", "community", "--stdin")
		if _, err := os.Stat(sb.path(file)); err != nil {
			t.Fatal(err)
		}
		sb.run("y\n", []string{"backup", "restore", id})
		sb.expect(0, "Restored snapshot "+id+".", "")
		if _, err := os.Stat(sb.path(file)); !os.IsNotExist(err) {
			t.Errorf("the device's file is left: %v", err)
		}
		if _, err := os.Stat(sb.path("state", "snmp", "devices")); !os.IsNotExist(err) {
			t.Errorf("the devices directory is left: %v", err)
		}
		// sw1 resolves to its scope's settings again: the scope's own file
		// is left alone by a snapshot with no credentials directory.
		if out := sb.devSNMP("", "sw1", "show", "--reveal"); !strings.Contains(out, "community:  scope-community-1  (scope lab)") ||
			strings.Contains(out, "dev-community-1") {
			t.Errorf("after restore:\n%s", out)
		}
	})
	t.Run("a snapshot with scope files and no device files", func(t *testing.T) {
		sb := renderedSandbox(t)
		sb.dev("", "add", "sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
		sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
		sb.run("", []string{"group", "add", "extra", "5", "EXTRA-CLASS"})
		id := snapshot.IDs(sb.path("state", "backups"))[0]
		sb.devSNMP("dev-community-1\n", "sw1", "community", "--stdin")
		sb.run("y\n", []string{"backup", "restore", id})
		sb.expect(0, "Restored snapshot "+id+".", "")
		if _, err := os.Stat(sb.path(file)); !os.IsNotExist(err) {
			t.Errorf("the device's file is left: %v", err)
		}
		if got := sb.read("state/snmp/lab.yaml"); !strings.Contains(got, "scope-community-1") {
			t.Errorf("the scope's file: %q", got)
		}
	})
}

// m4: below the engineer tier the SNMPv3 user's name is not printed.
func TestSNMPUserNameIsTheEngineersToRead(t *testing.T) {
	sb := newSandbox(t, true)
	// The loopback is in scope lab, so a check probes nothing outside.
	sb.write("state/store.yaml", strings.Replace(sb.store(), "prefixes: [172.16.0.0/12, 192.168.0.0/16]", "prefixes: [172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8]", 1), 0o600)
	sb.dev("", "add", "sw1", "127.0.0.1", "--no-host-key", "--no-lookup")
	sb.devSNMP("auth-pass-user-1\npriv-pass-user-1\n", "sw1", "v3-user", "svc-reader", "--stdin")
	sb.cfgRun("", []string{"config", "snmp", "timeout", "1"}, nil)

	ops := func(args ...string) string {
		return plain(sb.cfgRun("", args, idAs("bob", "tac-users"), "SUDO_USER=bob"))
	}
	ro := func(args ...string) string {
		return plain(sb.cfgRun("", args, idAs("carol", "tac-users"), "SUDO_USER=carol"))
	}
	// Superuser (root here): the name.
	if out := sb.dev("", "show", "sw1"); !strings.Contains(out, "v3 user svc-reader, passphrases set (device)") {
		t.Errorf("superuser device show:\n%s", out)
	}
	// Operator: device show and device check, text and JSON.
	for who, run := range map[string]func(...string) string{"operator": ops, "readonly": ro} {
		out := run("device", "show", "sw1")
		if sb.code != 0 || strings.Contains(out, "svc-reader") || !strings.Contains(out, "v3 user set, passphrases set (device)") {
			t.Errorf("%s device show: %d\n%s", who, sb.code, out)
		}
		raw := run("device", "show", "sw1", "--json")
		var js map[string]any
		if err := json.Unmarshal([]byte(raw), &js); err != nil {
			t.Fatalf("%s: %v\n%s", who, err, raw)
		}
		sn, _ := js["snmp"].(map[string]any)
		if _, has := sn["v3_user"]; has || sn["v3_user_set"] != true || strings.Contains(raw, "svc-reader") {
			t.Errorf("%s device show --json snmp: %v", who, sn)
		}
	}
	out := ops("device", "check", "sw1")
	if sb.code != 0 || strings.Contains(out, "svc-reader") || !strings.Contains(out, "v3 user set, passphrases set (device)") {
		t.Errorf("operator device check: %d\n%s", sb.code, out)
	}
	raw := ops("device", "check", "sw1", "--json")
	var cj []map[string]any
	if err := json.Unmarshal([]byte(raw), &cj); err != nil || len(cj) != 1 {
		t.Fatalf("check --json: %v\n%s", err, raw)
	}
	if sn, _ := cj[0]["snmp"].(map[string]any); strings.Contains(raw, "svc-reader") || sn["v3_user_set"] != true {
		t.Errorf("operator device check --json: %s", raw)
	}
	// Engineer: the name, in all four.
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	en := func(args ...string) string { return sb.asEngineer("", args...) }
	if out := en("device", "show", "sw1"); sb.code != 0 || !strings.Contains(out, "v3 user svc-reader, passphrases set (device)") {
		t.Errorf("engineer device show: %d\n%s", sb.code, out)
	}
	if raw := en("device", "show", "sw1", "--json"); !strings.Contains(raw, `"v3_user": "svc-reader"`) || !strings.Contains(raw, `"v3_user_set": true`) {
		t.Errorf("engineer device show --json:\n%s", raw)
	}
	if out := en("device", "check", "sw1"); sb.code != 0 || !strings.Contains(out, "v3 user svc-reader, passphrases set (device)") {
		t.Errorf("engineer device check: %d\n%s", sb.code, out)
	}
}

// m5: an engineer's reveal is logged for each level a printed secret comes
// from.
func TestDeviceSNMPRevealIsLoggedPerLevel(t *testing.T) {
	sb := engineerSandbox(t)
	count := func(kind, name string) int {
		return sb.runner.Count("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind="+kind+" name="+name+" by=bob")
	}
	reveal := func() string {
		out := sb.asEngineer("", "device", "snmp", "lab-sw", "show", "--reveal")
		if sb.code != 0 {
			t.Fatalf("reveal: %d %q", sb.code, sb.stderr())
		}
		return out
	}
	// Everything inherited from the default: one line, the default's.
	sb.cfgRun("def-community-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	out := reveal()
	if !strings.Contains(out, "community:  def-community-1  (default)") || count("snmp-default", "default") != 1 ||
		count("snmp", "lab") != 0 || count("snmp-device", "lab-sw") != 0 {
		t.Errorf("default only: logged default=%d scope=%d device=%d\n%s", count("snmp-default", "default"), count("snmp", "lab"), count("snmp-device", "lab-sw"), out)
	}
	// The community from the scope, the v3 user from the device: two lines.
	sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
	sb.devSNMP("dev-auth-pass-1\ndev-priv-pass-1\n", "lab-sw", "v3-user", "carol", "--stdin")
	out = reveal()
	if !strings.Contains(out, "community:  scope-community-1  (scope lab)") || !strings.Contains(out, "auth dev-auth-pass-1, priv dev-priv-pass-1  (device)") ||
		count("snmp", "lab") != 1 || count("snmp-device", "lab-sw") != 1 || count("snmp-default", "default") != 0 {
		t.Errorf("scope and device: logged default=%d scope=%d device=%d\n%s", count("snmp-default", "default"), count("snmp", "lab"), count("snmp-device", "lab-sw"), out)
	}
	// A plain show logs nothing; nothing secret to print logs nothing.
	sb.asEngineer("", "device", "snmp", "lab-sw", "show")
	if count("snmp", "lab")+count("snmp-device", "lab-sw")+count("snmp-default", "default") != 0 {
		t.Error("a plain show was logged")
	}
	for _, argv := range sb.runner.Argvs() {
		for _, secret := range []string{"scope-community-1", "dev-auth-pass-1", "def-community-1"} {
			if strings.Contains(argv, secret) {
				t.Errorf("%q reached a command: %q", secret, argv)
			}
		}
	}
}

// An engineer's import: a copy of a device's map on another address is
// refused; the same address and map under another name, with the old name
// left out of a --replace, is a rename and is allowed; without --replace the
// address is taken.
func TestEngineerImportCannotCopyAMapOntoADevice(t *testing.T) {
	sb := engineerSandbox(t)
	sb.devSNMP("", "lab-sw", "version", "v3")
	sb.devSNMP("", "lab-sw", "port", "2161")
	before := sb.devices()
	imp := func(replace bool, doc string) {
		args := []string{"device", "import", "-"}
		if replace {
			args = append(args, "--replace", "-y")
		}
		sb.asEngineer(doc, args...)
	}
	const head = "version: 1\ndevices:\n"
	// Another address: a copy of the settings, not a rename.
	imp(false, head+"  lab-copy: {address: 192.168.1.50, vendor: cisco, snmp: {version: v3, port: 2161}}\n")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A device's SNMP settings are not the engineer tier's to change") || sb.devices() != before {
		t.Errorf("copy at another address: %d %q", sb.code, sb.stderr())
	}
	// The same address with lab-sw still registered: the address is taken.
	imp(false, head+"  lab-copy: {address: 192.168.1.1, vendor: cisco, snmp: {version: v3, port: 2161}}\n")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "192.168.1.1 would be registered as both") || sb.devices() != before {
		t.Errorf("copy at the same address: %d %q", sb.code, sb.stderr())
	}
	// Another device's settings on a device of theirs that has none.
	sb.dev("", "add", "lab-rtr", "192.168.1.2", "--no-host-key", "--no-lookup")
	before = sb.devices()
	imp(false, head+"  lab-rtr: {address: 192.168.1.2, vendor: other, snmp: {version: v3, port: 2161}}\n")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "not the engineer tier's to change") || sb.devices() != before {
		t.Errorf("a map onto a device: %d %q", sb.code, sb.stderr())
	}
	// A rename: lab-sw's address and map under a new name, lab-sw and
	// nothing else of theirs dropped by --replace.
	doc := head + "  lab-core: {address: 192.168.1.1, vendor: cisco, snmp: {version: v3, port: 2161}}\n" +
		"  lab-rtr: {address: 192.168.1.2, vendor: other}\n  prod-sw: {address: 10.99.0.1, vendor: cisco}\n"
	imp(true, doc)
	if sb.code != 0 || !strings.Contains(sb.devices(), "lab-core") || strings.Contains(sb.devices(), "lab-sw:") {
		t.Errorf("rename by import: %d %q\n%s", sb.code, sb.stderr(), sb.devices())
	}
}

// import --replace drops the configuration records of the devices it
// removes, as 'device remove' does.
func TestImportReplaceForgetsTheConfigurationRecord(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j1", "192.168.1.20", "juniper"}, [3]string{"lab-j2", "192.168.1.21", "juniper"})
	b.serve("juniper", b.expected("lab-j1"))
	b.run("device", "config", "pull", "lab-j1", "lab-j2")
	if _, ok := b.records().Of("lab-j2"); !ok {
		t.Fatalf("no record for lab-j2 after the pull: %q", b.sb.stderr())
	}
	sections := b.sb.path("var-lib", "device-config", "lab-j2.yaml")
	if _, err := os.Stat(sections); err != nil {
		t.Fatalf("no sections file: %v", err)
	}
	out := plain(b.sb.cfgRun("lab-j1,192.168.1.20,juniper\n", []string{"device", "import", "-", "--replace", "-y"}, route, "SUDO_USER=alice"))
	if b.sb.code != 0 || !strings.Contains(out, "1 removed") {
		t.Fatalf("import: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if _, ok := b.records().Of("lab-j2"); ok {
		t.Error("the record of a device the import removed is left")
	}
	if _, err := os.Stat(sections); !os.IsNotExist(err) {
		t.Errorf("the sections file is left: %v", err)
	}
	if _, ok := b.records().Of("lab-j1"); !ok {
		t.Error("the kept device lost its record")
	}
}

// The map gates a device's own credentials: a file with no map beside it (a
// rollback to 0.2.3 removes the map and keeps the file, a stray one) is
// ignored by every reader, and said once where a device is shown.
const orphanFile = "version: 1\ncommunity: orphan-community-1\nv3:\n  user: orphan-user\n  auth_passphrase: orphan-auth-pass-1\n  priv_passphrase: orphan-priv-pass-1\n"

const orphanNoteText = "credentials file present but the device has no settings of its own (ignored): tacctl device snmp lab-sw1 clear removes it, or set its settings"

func TestOrphanCredentialsFileIsIgnoredByEveryReader(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "port", "1161")
	sb.scopeSNMP("", "lab", "timeout", "4")
	sb.scopeSNMP("", "lab", "clients", "add", "198.51.100.0/24")
	sb.scopeSNMP("", "lab", "contact", "NOC")
	file := "state/snmp/devices/lab-sw1.yaml"
	sb.write(file, orphanFile, 0o600)
	noOrphan := func(what, out string) {
		t.Helper()
		for _, s := range []string{"orphan-community-1", "orphan-user", "orphan-auth-pass-1", "orphan-priv-pass-1"} {
			if strings.Contains(out, s) {
				t.Errorf("%s: the ignored file's %q is used or printed:\n%s", what, s, out)
			}
		}
	}

	// device snmp show: the scope's values, labelled, and the note.
	out := sb.devSNMP("", "lab-sw1", "show", "--reveal")
	for _, want := range []string{"version:    v2c (the community)  (scope lab)", "port:       1161  (scope lab)", "timeout:    4 s, one retry  (scope lab)",
		"community:  scope-community-1  (scope lab)", "198.51.100.0/24", "Note:       " + orphanNoteText} {
		if sb.code != 0 || !strings.Contains(out, want) {
			t.Errorf("device snmp show lacks %q (exit %d):\n%s", want, sb.code, out)
		}
	}
	noOrphan("device snmp show", out)
	if strings.Contains(out, "v3 user:") {
		t.Errorf("a v3 user of the ignored file is shown:\n%s", out)
	}
	// device show, text and JSON.
	out = sb.dev("", "show", "lab-sw1")
	for _, want := range []string{"version v2c (scope lab), port 1161 (scope lab), timeout 4 s (scope lab)", "credentials: community set (scope lab)", orphanNoteText} {
		if !strings.Contains(out, want) {
			t.Errorf("device show lacks %q:\n%s", want, out)
		}
	}
	noOrphan("device show", out)
	var js map[string]any
	if err := json.Unmarshal([]byte(sb.run("", []string{"device", "show", "lab-sw1", "--json"})), &js); err != nil {
		t.Fatal(err)
	}
	sn, _ := js["snmp"].(map[string]any)
	if sn == nil || sn["own_credentials"] != false || sn["ignored_credentials_file"] != true || sn["community_from"] != "scope" || sn["version_from"] != "scope" {
		t.Errorf("show --json snmp: %v", sn)
	}
	noOrphan("device show --json", sb.out.String())
	// The walkthrough of the device (device config show) and by --name.
	route := func(r *fake.Runner) {
		r.On([]string{"ip", "-4", "route", "get", "1.0.0.0"}, execx.Result{Stdout: []byte("1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0\n")})
	}
	out = plain(sb.cfgRun("", []string{"device", "config", "show", "lab-sw1"}, route))
	if sb.code != 0 || !strings.Contains(out, "snmp-server community scope-community-1 RO TACCTL-SNMP") ||
		!strings.Contains(out, "Credentials: this scope's own") || !strings.Contains(out, "198.51.100.0") || !strings.Contains(out, orphanNoteText) {
		t.Errorf("device config show: %d\n%s", sb.code, out)
	}
	noOrphan("device config show", out)
	out = plain(sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--name", "lab-sw1"}, route))
	if !strings.Contains(out, "snmp-server community scope-community-1 RO TACCTL-SNMP") || strings.Contains(out, "this device's own") {
		t.Errorf("config cisco --name:\n%s", out)
	}
	noOrphan("config cisco --name", out)
	// scope snmp show lists no device with settings of its own.
	if out = sb.scopeSNMP("", "lab", "show", "--reveal"); strings.Contains(out, "devices with settings of their own") {
		t.Errorf("scope snmp show lists the ignored file's device:\n%s", out)
	}
	// The file is not parsed while it is ignored: a broken one is no error.
	sb.write(file, "version: 1\nbogus: [unclosed\n", 0o600)
	if out = sb.devSNMP("", "lab-sw1"); sb.code != 0 || !strings.Contains(out, orphanNoteText) {
		t.Errorf("a broken ignored file: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.write(file, orphanFile, 0o600)

	// Settings of its own bring it into force, and the verb says so.
	sb.devSNMP("", "lab-sw1", "port", "2161")
	sb.said(0, "The credentials file of 'lab-sw1', ignored until now, is in force")
	out = sb.devSNMP("", "lab-sw1", "show", "--reveal")
	if !strings.Contains(out, "community:  orphan-community-1  (device)") || !strings.Contains(out, "port:       2161  (device)") ||
		!strings.Contains(out, "v3 user:    orphan-user  (device)") || strings.Contains(out, orphanNoteText) {
		t.Errorf("in force:\n%s", out)
	}
	// clear takes it with the map.
	sb.devSNMP("", "lab-sw1", "clear")
	if _, err := os.Stat(sb.path(file)); !os.IsNotExist(err) {
		t.Errorf("the file is left: %v", err)
	}

	// community replaces an ignored file, saying so, and does not carry the
	// ignored file's v3 user into the new one.
	sb.write(file, orphanFile, 0o600)
	sb.devSNMP("fresh-community-2\n", "lab-sw1", "community", "--stdin")
	if sb.code != 0 || !strings.Contains(sb.stderr()+sb.plainOut(), "was ignored, the device having no settings of its own; it is replaced") {
		t.Errorf("community over an ignored file: %d %q %q", sb.code, sb.plainOut(), sb.stderr())
	}
	if strings.Contains(sb.stderr()+sb.plainOut(), "is in force") {
		t.Error("community said an ignored file came into force")
	}
	data := sb.read(file)
	if !strings.Contains(data, "fresh-community-2") || strings.Contains(data, "orphan-user") || strings.Contains(data, "orphan-community-1") {
		t.Errorf("the file after community:\n%s", data)
	}
}

// The expected configuration of a pull does not take an ignored file's
// credentials, and takes them once the device has settings.
func TestOrphanCredentialsFileIsNotInThePullExpectation(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j1", "192.168.1.20", "juniper"})
	b.run("scope", "snmp", "lab", "version", "v2c")
	b.sb.cfgRun("scope-community-9\n", []string{"scope", "snmp", "lab", "community", "--stdin"}, route)
	b.sb.write("state/snmp/devices/lab-j1.yaml", "version: 1\ncommunity: orphan-community-9\n", 0o600)
	if exp := b.expected("lab-j1"); !strings.Contains(exp, "scope-community-9") || strings.Contains(exp, "orphan-community-9") {
		t.Errorf("an ignored file in the expectation:\n%s", exp)
	}
	b.run("device", "snmp", "lab-j1", "port", "2161")
	if exp := b.expected("lab-j1"); !strings.Contains(exp, "orphan-community-9") || strings.Contains(exp, "scope-community-9") {
		t.Errorf("the file in force is not in the expectation:\n%s", exp)
	}
}

// The name lookup of device check reads an ignored file's device with its
// scope's settings.
func TestOrphanCredentialsFileIsNotUsedByTheLookup(t *testing.T) {
	sb := newSandbox(t, true)
	a := &snmp.Agent{SysName: "sw1.site-a.example", Community: "scope-right"}
	conn, err := a.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	port := strconv.Itoa(conn.LocalAddr().(*net.UDPAddr).Port)
	sb.write("state/store.yaml", strings.Replace(sb.store(), "prefixes: [203.0.113.0/24]", "prefixes: [203.0.113.0/24, 127.0.0.0/8]", 1), 0o600)
	sb.cfgRun("", []string{"config", "snmp", "timeout", "1"}, nil)
	sb.scopeSNMP("scope-right\n", "dmz", "community", "--stdin")
	sb.scopeSNMP("", "dmz", "port", port)
	sb.cfgRun("", []string{"device", "add", "sw1", "127.0.0.1", "--no-host-key", "--no-lookup"}, nil)
	sb.write("state/snmp/devices/sw1.yaml", "version: 1\ncommunity: orphan-wrong\n", 0o600)
	out := plain(sb.cfgRun("", []string{"device", "check", "sw1"}, nil))
	if !strings.Contains(out, "SNMP name:   sw1.site-a.example  (match)") || !strings.Contains(out, "community set (scope dmz)") ||
		strings.Contains(out, "orphan-wrong") {
		t.Errorf("device check with an ignored file:\n%s", out)
	}
}

// After a rollback to 0.2.3 (the map is removed, the file stays) and a
// re-upgrade, the device resolves to its scope's values; its settings bring
// the file back.
func TestRollbackThenUpgradeKeepsTheFileIgnoredUntilSettingsReturn(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.scopeSNMP("scope-community-1\n", "lab", "community", "--stdin")
	sb.scopeSNMP("", "lab", "port", "1161")
	sb.devSNMP("dev-community-1\n", "lab-sw1", "community", "--stdin")
	sb.devSNMP("", "lab-sw1", "port", "2161")
	sb.devSNMP("", "lab-sw1", "clients", "add", "192.0.2.0/24")
	if out := sb.devSNMP("", "lab-sw1", "show", "--reveal"); !strings.Contains(out, "community:  dev-community-1  (device)") ||
		!strings.Contains(out, "port:       2161  (device)") {
		t.Fatalf("before the rollback:\n%s", out)
	}
	// What the rollback to 0.2.3 does to the registry: the maps go.
	cleared, err := devreg.RollbackSNMP(sb.path("state", "devices.yaml"), nil)
	if err != nil || len(cleared) != 1 {
		t.Fatalf("RollbackSNMP: %v %v", cleared, err)
	}
	if _, err := os.Stat(sb.path("state", "snmp", "devices", "lab-sw1.yaml")); err != nil {
		t.Fatalf("the file did not stay: %v", err)
	}
	// The re-upgrade: the scope's values, labelled, and the note.
	out := sb.devSNMP("", "lab-sw1", "show", "--reveal")
	for _, want := range []string{"community:  scope-community-1  (scope lab)", "port:       1161  (scope lab)", "Note:       " + orphanNoteText} {
		if !strings.Contains(out, want) {
			t.Errorf("after the re-upgrade lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "dev-community-1") || strings.Contains(out, "192.0.2.0/24") {
		t.Errorf("the device's old settings are in force:\n%s", out)
	}
	if out = sb.dev("", "show", "lab-sw1"); !strings.Contains(out, "credentials: community set (scope lab)") || !strings.Contains(out, orphanNoteText) {
		t.Errorf("device show:\n%s", out)
	}
	// Settings bring the file back into force.
	sb.devSNMP("", "lab-sw1", "version", "v2c")
	out = sb.devSNMP("", "lab-sw1", "show", "--reveal")
	if !strings.Contains(out, "community:  dev-community-1  (device)") {
		t.Errorf("settings did not bring the file into force:\n%s", out)
	}
}
