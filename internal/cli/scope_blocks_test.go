package cli

import (
	"os"
	"strings"
	"testing"
)

// The configuration blocks of a scope (0.2.7): the list in force in
// tacctl.yaml and the files under StateDir/blocks follow the scope's rename,
// go with its removal, come back with a restore, and a name that has
// leftovers is not taken over.

const blocksManifest = "blocks:\n  dmz:\n    juniper:\n    - snmp\n    - system\n"

func (sb *sandbox) blocksFixture() {
	sb.t.Helper()
	sb.write("state/tacctl.yaml", sb.overrides()+blocksManifest, 0o640)
	for _, d := range []string{"state/blocks", "state/blocks/dmz", "state/blocks/dmz/juniper"} {
		if err := os.MkdirAll(sb.path(d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
		if err := os.Chmod(sb.path(d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
	}
	sb.write("state/blocks/dmz/juniper/snmp", "set snmp community dmz-extra authorization read-only\nset snmp community dmz-extra clients 192.0.2.0/24\n", 0o600)
	sb.write("state/blocks/dmz/juniper/system", "set system time-zone UTC\n", 0o600)
}

func TestScopeBlocksFollowRenameRemoveAndRestore(t *testing.T) {
	sb := renderedSandbox(t)
	sb.blocksFixture()

	sb.run("", []string{"scope", "rename", "dmz", "edge"})
	sb.expect(0, "Scope renamed: dmz -> edge", "")
	if got := sb.read("state/blocks/edge/juniper/snmp"); !strings.Contains(got, "dmz-extra") {
		t.Errorf("the block did not follow the rename: %q", got)
	}
	if st, err := os.Stat(sb.path("state/blocks/edge/juniper/snmp")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("mode of the block: %v %v", st, err)
	}
	if _, err := os.Stat(sb.path("state/blocks/dmz")); !os.IsNotExist(err) {
		t.Errorf("the old directory is left: %v", err)
	}
	if o := sb.overrides(); strings.Contains(o, "dmz:") || !strings.Contains(o, "blocks:\n  edge:\n    juniper:\n    - snmp\n    - system\n") {
		t.Errorf("tacctl.yaml after the rename:\n%s", o)
	}

	// The removal takes the files and the keys; the snapshot it took first
	// holds both, and a restore puts them back.
	sb.run("y\n", []string{"scope", "remove", "edge", "--force"})
	sb.expect(0, "Scope 'edge' removed.", "")
	if _, err := os.Stat(sb.path("state/blocks")); !os.IsNotExist(err) {
		t.Errorf("blocks left after the removal: %v", err)
	}
	if strings.Contains(sb.overrides(), "blocks") {
		t.Errorf("keys left after the removal:\n%s", sb.overrides())
	}
	id := (&invocation{app: newHarness(t, nil, sb.env...).app, hooks: newTestHooks()}).snapshotIDs()[0]
	for rel, mode := range map[string]os.FileMode{"blocks": 0o700, "blocks/edge": 0o700, "blocks/edge/juniper": 0o700, "blocks/edge/juniper/snmp": 0o600} {
		st, err := os.Stat(sb.path("state/backups/" + id + "/" + rel))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("snapshot %s: %v %v (want %v)", rel, st, err, mode)
		}
	}

	// Something the snapshot lacks goes with the restore.
	if err := os.MkdirAll(sb.path("state/blocks/other/juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/other/juniper/snmp", "set snmp community other authorization read-only\n", 0o600)
	sb.run("y\n", []string{"backup", "restore", id})
	sb.expect(0, "Restored snapshot "+id+".", "")
	if got := sb.read("state/blocks/edge/juniper/system"); got != "set system time-zone UTC\n" {
		t.Errorf("system block after the restore: %q", got)
	}
	if st, err := os.Stat(sb.path("state/blocks/edge/juniper")); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("directory mode after the restore: %v %v", st, err)
	}
	if _, err := os.Stat(sb.path("state/blocks/other")); !os.IsNotExist(err) {
		t.Errorf("a block the snapshot lacks stayed: %v", err)
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks:\n  edge:\n") {
		t.Errorf("the manifest was not restored:\n%s", o)
	}
}

func TestLeftoverBlocksAreNotTakenOver(t *testing.T) {
	sb := newSandbox(t, true)
	if err := os.MkdirAll(sb.path("state/blocks/newscope/juniper"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.write("state/blocks/newscope/juniper/snmp", "set snmp community x authorization read-only\n", 0o600)
	sb.run("", []string{"scope", "add", "newscope", "--prefixes", "198.51.100.0/24"})
	sb.expect(1, "", "Configuration blocks for a scope named 'newscope' are already on disk: "+sb.path("state/blocks/newscope"))
	if o := sb.read("state/store.yaml"); strings.Contains(o, "newscope") {
		t.Errorf("the refused scope was added:\n%s", o)
	}

	// A rename of a scope with blocks onto a name that has a directory.
	for _, d := range []string{"state/blocks/lab/juniper", "state/blocks/renamed/juniper"} {
		if err := os.MkdirAll(sb.path(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sb.write("state/blocks/lab/juniper/snmp", "set snmp community lab-c authorization read-only\n", 0o600)
	sb.write("state/blocks/renamed/juniper/snmp", "leftover\n", 0o600)
	sb.run("", []string{"scope", "rename", "lab", "renamed"})
	sb.expect(1, "", "Configuration blocks for a scope named 'renamed' are already on disk")
	if o := sb.read("state/store.yaml"); strings.Contains(o, "renamed") {
		t.Errorf("the refused rename was applied:\n%s", o)
	}
	if got := sb.read("state/blocks/renamed/juniper/snmp"); got != "leftover\n" {
		t.Errorf("the leftover was overwritten: %q", got)
	}

	// With the leftover out of the way both go through.
	if err := os.RemoveAll(sb.path("state/blocks/newscope")); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"scope", "add", "newscope", "--prefixes", "198.51.100.0/24"})
	sb.expect(0, "Scope 'newscope' added.", "")
}

// A scope called 'devices' is legal (the devices' own blocks are kept under
// '_devices', which is no scope name), and its rename and removal leave the
// devices' blocks alone.
func TestScopeNamedDevicesBesideDeviceBlocks(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "add", "devices", "--prefixes", "198.51.100.0/24"})
	sb.expect(0, "Scope 'devices' added.", "")
	for _, d := range []string{"state/blocks/devices/juniper", "state/blocks/_devices/js1.lab.example.net/juniper"} {
		if err := os.MkdirAll(sb.path(d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sb.write("state/blocks/devices/juniper/snmp", "# the scope's\n", 0o600)
	sb.write("state/blocks/_devices/js1.lab.example.net/juniper/snmp", "# the device's\n", 0o600)
	sb.write("state/tacctl.yaml", sb.overrides()+"blocks:\n  devices:\n    juniper:\n    - snmp\nblocks_device:\n  js1~lab~example~net:\n    juniper:\n    - snmp\n", 0o640)

	sb.run("", []string{"scope", "rename", "devices", "edge"})
	sb.expect(0, "Scope renamed: devices -> edge", "")
	if got := sb.read("state/blocks/edge/juniper/snmp"); got != "# the scope's\n" {
		t.Errorf("the scope's block: %q", got)
	}
	if got := sb.read("state/blocks/_devices/js1.lab.example.net/juniper/snmp"); got != "# the device's\n" {
		t.Errorf("the device's block: %q", got)
	}
	if o := sb.overrides(); !strings.Contains(o, "blocks:\n  edge:\n    juniper:\n    - snmp\n") || !strings.Contains(o, "blocks_device:\n  js1~lab~example~net:\n") {
		t.Errorf("tacctl.yaml after the rename:\n%s", o)
	}
	sb.run("y\n", []string{"scope", "remove", "edge", "--force"})
	sb.expect(0, "Scope 'edge' removed.", "")
	if got := sb.read("state/blocks/_devices/js1.lab.example.net/juniper/snmp"); got != "# the device's\n" {
		t.Errorf("the device's block after the scope's removal: %q", got)
	}
	if o := sb.overrides(); strings.Contains(o, "edge") || !strings.Contains(o, "blocks_device:") {
		t.Errorf("tacctl.yaml after the removal:\n%s", o)
	}
}
