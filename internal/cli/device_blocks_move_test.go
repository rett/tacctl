package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snapshot"
)

// A device's own configuration blocks (0.2.7, B8a): the files under
// StateDir/blocks/_devices/<name> and the blocks_device.<name~>.<vendor> keys
// of tacctl.yaml follow the device's rename, go with its removal (after the
// confirmation says so), come back with a restore, and a name that has
// leftovers is not taken over.

const (
	devBlocksOld = "jsw1.lab.example.net"
	devBlocksNew = "jsw9.lab.example.net"
	devBlocksKey = "blocks_device:\n  jsw1~lab~example~net:\n    juniper:\n    - snmp\n    - system\n"
)

// blocksDeviceFixture registers the device and gives it two blocks in force.
func (sb *sandbox) blocksDeviceFixture(name, key string) {
	sb.t.Helper()
	sb.dev("", "add", name, "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	sb.write("state/tacctl.yaml", sb.overrides()+key, 0o640)
	dir := "state/blocks/_devices/" + strings.ToLower(name) + "/juniper"
	for _, d := range []string{"state/blocks", "state/blocks/_devices", "state/blocks/_devices/" + strings.ToLower(name), dir} {
		if err := os.MkdirAll(sb.path(d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
		if err := os.Chmod(sb.path(d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
	}
	sb.write(dir+"/snmp", "set snmp community jsw1-extra authorization read-only\nset snmp community jsw1-extra clients 192.0.2.0/24\n", 0o600)
	sb.write(dir+"/system", "set system time-zone UTC\n", 0o600)
}

func TestDeviceBlocksFollowRenameRemoveAndRestore(t *testing.T) {
	sb := renderedSandbox(t)
	sb.blocksDeviceFixture(devBlocksOld, devBlocksKey)
	oldDir := "state/blocks/_devices/" + devBlocksOld + "/juniper/"
	newDir := "state/blocks/_devices/" + devBlocksNew + "/juniper/"

	// A change of spelling keeps everything where it is: a name from before,
	// with upper case, is fixed by renaming it to lower case.
	sb.write("state/devices.yaml", strings.Replace(sb.devices(), "  "+devBlocksOld+":", "  JSW1.lab.example.net:", 1), 0o600)
	sb.dev("", "rename", "JSW1.lab.example.net", devBlocksOld)
	sb.expect(0, "renamed to", "")
	if got := sb.read(oldDir + "snmp"); !strings.Contains(got, "jsw1-extra") {
		t.Errorf("a respelling lost the block: %q", got)
	}
	if !strings.Contains(sb.overrides(), devBlocksKey) {
		t.Errorf("a respelling changed the keys:\n%s", sb.overrides())
	}

	sb.dev("", "rename", devBlocksOld, devBlocksNew)
	sb.expect(0, "renamed to", "")
	if got := sb.read(newDir + "snmp"); !strings.Contains(got, "jsw1-extra") {
		t.Errorf("the block did not follow the rename: %q", got)
	}
	if st, err := os.Stat(sb.path(newDir + "snmp")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode of the block: %v %v", st, err)
	}
	if st, err := os.Stat(sb.path(newDir)); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("mode of the directory: %v %v", st, err)
	}
	if _, err := os.Stat(sb.path("state/blocks/_devices/" + devBlocksOld)); !os.IsNotExist(err) {
		t.Errorf("the old directory is left: %v", err)
	}
	if o := sb.overrides(); strings.Contains(o, "jsw1~lab") || !strings.Contains(o, "blocks_device:\n  jsw9~lab~example~net:\n    juniper:\n    - snmp\n    - system\n") {
		t.Errorf("tacctl.yaml after the rename:\n%s", o)
	}
	// The snapshot the rename took first holds the files under the old name.
	id := (&invocation{app: newHarness(t, nil, sb.env...).app, hooks: newTestHooks()}).snapshotIDs()[0]
	if _, err := os.Stat(sb.path("state/backups/" + id + "/blocks/_devices/jsw1.lab.example.net/juniper/snmp")); err != nil {
		t.Errorf("the snapshot lacks the block: %v", err)
	}
	if got := sb.read("state/backups/" + id + "/tacctl.yaml"); !strings.Contains(got, "jsw1~lab~example~net") {
		t.Errorf("the snapshot's tacctl.yaml:\n%s", got)
	}

	// Removal: the confirmation says the blocks go with the device; a no
	// leaves everything; a yes takes files and keys.
	sb.run("n\n", []string{"device", "remove", devBlocksNew})
	sb.expect(0, "configuration blocks of "+devBlocksNew+" (they may hold community strings) are removed with the device(s)", "")
	sb.expect(0, "Aborted.", "")
	if _, err := os.Stat(sb.path(newDir + "snmp")); err != nil {
		t.Errorf("an aborted removal took the block: %v", err)
	}
	sb.run("y\n", []string{"device", "remove", devBlocksNew})
	sb.expect(0, "the snapshot taken first holds them", "")
	sb.expect(0, "Removed 1 device(s).", "")
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("blocks left after the removal: %v", err)
	}
	if strings.Contains(sb.overrides(), "blocks_device") {
		t.Errorf("keys left after the removal:\n%s", sb.overrides())
	}
	id = (&invocation{app: newHarness(t, nil, sb.env...).app, hooks: newTestHooks()}).snapshotIDs()[0]
	for rel, mode := range map[string]os.FileMode{
		"blocks/_devices": 0o700, "blocks/_devices/" + devBlocksNew + "/juniper": 0o700, "blocks/_devices/" + devBlocksNew + "/juniper/snmp": 0o600,
	} {
		st, err := os.Stat(sb.path("state/backups/" + id + "/" + rel))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("snapshot %s: %v %v (want %v)", rel, st, err, mode)
		}
	}

	// Something the snapshot lacks goes with the restore; the device's
	// blocks and keys come back with it.
	if err := os.MkdirAll(sb.path("state/blocks/_devices/other/juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/_devices/other/juniper/snmp", "set snmp community other authorization read-only\n", 0o600)
	sb.run("y\n", []string{"backup", "restore", id})
	sb.expect(0, "Restored snapshot "+id+".", "")
	if got := sb.read(newDir + "system"); got != "set system time-zone UTC\n" {
		t.Errorf("system block after the restore: %q", got)
	}
	if st, err := os.Stat(sb.path(newDir)); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("directory mode after the restore: %v %v", st, err)
	}
	if _, err := os.Stat(sb.path("state/blocks/_devices/other")); !os.IsNotExist(err) {
		t.Errorf("a block the snapshot lacks stayed: %v", err)
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks_device:\n  jsw9~lab~example~net:\n") {
		t.Errorf("the manifest was not restored:\n%s", o)
	}
}

// A device with no blocks is removed with no word about them.
func TestDeviceRemoveWithoutBlocksSaysNothingOfThem(t *testing.T) {
	sb := newSandbox(t, true)
	sb.dev("", "add", "sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	sb.run("y\n", []string{"device", "remove", "sw1"})
	sb.expect(0, "Removed 1 device(s).", "")
	if strings.Contains(sb.plainOut()+sb.stderr(), "configuration blocks") {
		t.Errorf("a note about blocks:\n%s", sb.plainOut())
	}
}

// A name that finds the blocks of an earlier device, on disk or in
// tacctl.yaml, is refused before anything changes: an add, an import and the
// new name of a rename.
func TestLeftoverDeviceBlocksAreNotTakenOver(t *testing.T) {
	sb := newSandbox(t, true)
	if err := os.MkdirAll(sb.path("state/blocks/_devices/jsw5.lab.example.net/juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/_devices/jsw5.lab.example.net/juniper/snmp", "set snmp community x authorization read-only\n", 0o600)
	before := sb.devices()
	sb.dev("", "add", "jsw5.lab.example.net", "192.168.1.50", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.expect(1, "", "Configuration blocks for a device named 'jsw5.lab.example.net' are already on disk: "+sb.path("state/blocks/_devices/jsw5.lab.example.net"))
	if sb.devices() != before {
		t.Errorf("the refused device was added:\n%s", sb.devices())
	}
	sb.run("jsw5.lab.example.net,192.168.1.50,juniper\n", []string{"device", "import", "-", "--no-host-key"})
	if sb.code == 0 || sb.devices() != before {
		t.Errorf("import over a leftover: %d %q\n%s", sb.code, sb.stderr(), sb.devices())
	}

	// A rename onto the leftover.
	sb.dev("", "add", "jsw1.lab.example.net", "192.168.1.20", "--vendor", "juniper", "--no-host-key", "--no-lookup")
	sb.expect(0, "", "")
	before = sb.devices()
	sb.dev("", "rename", "jsw1.lab.example.net", "jsw5.lab.example.net")
	sb.expect(1, "", "Configuration blocks for a device named 'jsw5.lab.example.net' are already on disk")
	if sb.devices() != before {
		t.Errorf("the refused rename was applied:\n%s", sb.devices())
	}
	if got := sb.read("state/blocks/_devices/jsw5.lab.example.net/juniper/snmp"); !strings.Contains(got, "community x") {
		t.Errorf("the leftover was changed: %q", got)
	}

	// Keys with no files are a leftover too.
	sb.write("state/tacctl.yaml", sb.overrides()+"blocks_device:\n  jsw6~lab~example~net:\n    juniper:\n    - system\n", 0o640)
	sb.dev("", "rename", "jsw1.lab.example.net", "jsw6.lab.example.net")
	sb.expect(1, "", "tacctl.yaml lists configuration blocks (blocks_device.jsw6~lab~example~net) for a device named 'jsw6.lab.example.net'")
	if sb.devices() != before {
		t.Errorf("the refused rename was applied:\n%s", sb.devices())
	}

	// With the leftovers out of the way both go through.
	if err := os.RemoveAll(sb.path("state/blocks")); err != nil {
		t.Fatal(err)
	}
	sb.write("state/tacctl.yaml", strings.Replace(sb.overrides(), "blocks_device:\n  jsw6~lab~example~net:\n    juniper:\n    - system\n", "", 1), 0o640)
	sb.dev("", "rename", "jsw1.lab.example.net", "jsw6.lab.example.net")
	sb.expect(0, "renamed to", "")
}

// A rename whose files cannot be moved puts the keys back, so tacctl.yaml
// and the directory never disagree about the name, and says so.
func TestDeviceBlocksRenameThatCannotMoveFilesPutsTheKeysBack(t *testing.T) {
	sb := newSandbox(t, true)
	sb.blocksDeviceFixture(devBlocksOld, devBlocksKey)
	// A directory at the new name that the rename would have refused up
	// front (the leftover check is the registry's; here it is the carry's
	// own refusal that is under test).
	if err := os.MkdirAll(sb.path("state/blocks/_devices/"+devBlocksNew), 0o700); err != nil {
		t.Fatal(err)
	}
	h := newHarness(t, nil, sb.env...)
	(&invocation{app: h.app, hooks: newTestHooks()}).blocksDeviceCarry(devBlocksOld, devBlocksNew)
	if w := plain(h.out.String()); !strings.Contains(w, "were not carried over to '"+devBlocksNew+"'") || !strings.Contains(w, "already on disk") ||
		!strings.Contains(w, "still kept under the old name") {
		t.Errorf("the warning:\n%s", w)
	}
	if o := sb.overrides(); !strings.Contains(o, devBlocksKey) || strings.Contains(o, "jsw9~lab") {
		t.Errorf("the keys were not put back:\n%s", o)
	}
	if _, err := os.Stat(sb.path("state/blocks/_devices/" + devBlocksOld + "/juniper/snmp")); err != nil {
		t.Errorf("the files moved: %v", err)
	}
}

// The snapshot every configuration write takes holds the device blocks.
func TestConfigWriteSnapshotHoldsDeviceBlocks(t *testing.T) {
	sb := newSandbox(t, true)
	sb.blocksDeviceFixture(devBlocksOld, devBlocksKey)
	sb.run("", []string{"group", "add", "extra", "5", "EXTRA-CLASS"})
	sb.expect(0, "Group 'extra' added", "")
	ids := snapshot.IDs(sb.path("state", "backups"))
	if len(ids) == 0 {
		t.Fatal("no snapshot")
	}
	if _, err := os.Stat(sb.path("state/backups/" + ids[0] + "/blocks/_devices/" + devBlocksOld + "/juniper/system")); err != nil {
		t.Errorf("a config write's snapshot lacks the device's block: %v", err)
	}
}
