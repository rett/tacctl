package cli

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snmpcred"
)

// A device's credentials file follows its snmp: entry (snmpReconcile): a
// version 1 file counts only beside an entry, and the older releases ignore it
// without one, so a device whose entry is emptied (its last client range
// removed, a registry import that drops the key) must not be left with a
// version 1 file that silently hands it to another level's user; and a device
// that gains an entry gets a version 1 file when the content fits it.

func reconcileSandbox(t *testing.T) (*sandbox, snmpcred.Store) {
	t.Helper()
	sb := newSandbox(t, true)
	sb.dev("", "add", "lab-sw1", "192.168.1.1", "--vendor", "cisco", "--no-host-key", "--no-lookup")
	st := snmpcred.Store{File: sb.path("state", "snmp.yaml"), Dir: sb.path("state", "snmp")}
	// The config's user is the one a device must never fall back to.
	if err := st.Save(snmpcred.Level{Kind: snmpcred.LevelDefault}, snmpcred.Creds{Users: []snmpcred.User{{Name: "alice", AuthPass: "alice-auth-pass", PrivPass: "alice-priv-pass"}}, Default: "alice"}); err != nil {
		t.Fatal(err)
	}
	sb.write("state/tacctl.yaml", "snmp:\n  version: v3\n", 0o600)
	return sb, st
}

func TestSNMPFileFollowsTheEntryWhenItIsEmptied(t *testing.T) {
	sb, st := reconcileSandbox(t)
	file := "state/snmp/devices/lab-sw1.yaml"
	dev := snmpcred.Level{Kind: snmpcred.LevelDevice, Name: "lab-sw1"}
	// The entry exists through a client range only; the device's own user fits
	// version 1 and is saved as such.
	sb.devSNMP("", "lab-sw1", "clients", "add", "198.51.100.0/24")
	st.Mapped = func(string) bool { return true }
	if err := st.Save(dev, snmpcred.Creds{Users: []snmpcred.User{{Name: "bob", AuthPass: "bob-auth-pass", PrivPass: "bob-priv-pass"}}, Default: "bob"}); err != nil {
		t.Fatal(err)
	}
	if got := sb.read(file); !strings.Contains(got, "version: 1") {
		t.Fatalf("not version 1:\n%s", got)
	}
	out := sb.devSNMP("", "lab-sw1", "clients", "remove", "198.51.100.0/24")
	if strings.Contains(sb.devices(), "snmp:") {
		t.Fatalf("the entry is still there:\n%s", sb.devices())
	}
	// It is said, not silent: the device's own file stays in force.
	if !strings.Contains(out, "'lab-sw1' has no snmp: entry now: its own credentials file stays in force") {
		t.Errorf("the rewrite of the file is not said:\n%s", out)
	}
	// The entry is gone: the file is version 2, which counts without one, never
	// a version 1 orphan the older releases ignore.
	if got := sb.read(file); !strings.Contains(got, "version: 2") || !strings.Contains(got, "bob") {
		t.Errorf("after: not version 2:\n%s", got)
	}
}

// A device that has no entry holds a version 2 file; when it gets one the file
// that fits version 1 becomes version 1, and one that does not stays version 2.
func TestSNMPFileBecomesVersionOneWhenTheDeviceGetsAnEntry(t *testing.T) {
	sb, st := reconcileSandbox(t)
	file := "state/snmp/devices/lab-sw1.yaml"
	dev := snmpcred.Level{Kind: snmpcred.LevelDevice, Name: "lab-sw1"}
	user := func(n string) snmpcred.User {
		return snmpcred.User{Name: n, AuthPass: n + "-auth-pass", PrivPass: n + "-priv-pass"}
	}
	if err := st.Save(dev, snmpcred.Creds{Users: []snmpcred.User{user("bob")}, Default: "bob"}); err != nil {
		t.Fatal(err)
	}
	if got := sb.read(file); !strings.Contains(got, "version: 2") {
		t.Fatalf("a device with no entry has a version 1 file:\n%s", got)
	}
	sb.devSNMP("", "lab-sw1", "version", "v3")
	if got := sb.read(file); !strings.Contains(got, "version: 1") || !strings.Contains(got, "name: bob") && !strings.Contains(got, "user: bob") {
		t.Errorf("not version 1 once the device has an entry:\n%s", got)
	}
	// a pool of two stays version 2
	sb.devSNMP("", "lab-sw1", "clear")
	if err := st.Save(dev, snmpcred.Creds{Users: []snmpcred.User{user("bob"), user("dave")}, Default: "bob"}); err != nil {
		t.Fatal(err)
	}
	sb.devSNMP("", "lab-sw1", "version", "v3")
	if got := sb.read(file); !strings.Contains(got, "version: 2") {
		t.Errorf("a pool of two is not version 2:\n%s", got)
	}
	// a leftover version 1 file with no entry stays ignored when an unrelated
	// registry change happens (its entry did not change)
	sb.devSNMP("", "lab-sw1", "clear")
	sb.write(file, "version: 1\ncommunity: stray-community\n", 0o600)
	sb.dev("", "description", "lab-sw1", "x")
	if got := sb.read(file); !strings.Contains(got, "version: 1") {
		t.Errorf("an ignored leftover was rewritten:\n%s", got)
	}
}

// The community verb writes the registry first and the file after, in the
// format the entry allows: a registry write that fails leaves the old file as
// it was, in force.
func TestSNMPCommunityLeavesTheFileWhenTheRegistryWriteFails(t *testing.T) {
	sb, st := reconcileSandbox(t)
	file := "state/snmp/devices/lab-sw1.yaml"
	user := func(n string) snmpcred.User {
		return snmpcred.User{Name: n, AuthPass: n + "-auth-pass", PrivPass: n + "-priv-pass"}
	}
	if err := st.Save(snmpcred.Level{Kind: snmpcred.LevelDevice, Name: "lab-sw1"}, snmpcred.Creds{Users: []snmpcred.User{user("bob"), user("dave")}, Default: "bob"}); err != nil {
		t.Fatal(err)
	}
	before := sb.read(file)
	// the device is removed behind the verb's back, as the registry write begins
	sb.hooks.deviceWriteStep = func() {
		if err := os.WriteFile(sb.path("state", "devices.yaml"), []byte("version: 1\ndevices: {}\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	sb.devSNMP("a-community\n", "lab-sw1", "community", "--stdin")
	sb.hooks.deviceWriteStep = nil
	if sb.code != 1 {
		t.Fatalf("exit %d, want 1: %q", sb.code, sb.stderr())
	}
	if got := sb.read(file); got != before {
		t.Errorf("the file changed although the registry write failed:\n%s", got)
	}
	if strings.Contains(sb.read(file), "a-community") {
		t.Errorf("the community was written")
	}
}

// A file that cannot be brought in step is a warning that names the command
// that writes it again. Without an entry a version 1 file is ignored, so the
// device would use another level's user: the verb exits 1 (its registry write
// happened). A version 2 file that stays version 2 is still in force: exit 0.
func TestSNMPReconcileFailureNamesTheCommandAndFailsWhenTheFileIsIgnored(t *testing.T) {
	sb, st := reconcileSandbox(t)
	file := "state/snmp/devices/lab-sw1.yaml"
	dev := snmpcred.Level{Kind: snmpcred.LevelDevice, Name: "lab-sw1"}
	lock := func(on bool) {
		sb.hooks.snmpReconcileSave = nil
		if on {
			sb.hooks.snmpReconcileSave = func(string) error { return errors.New("Cannot write the file: no space left on device") }
		}
	}
	t.Cleanup(func() { sb.hooks.snmpReconcileSave = nil })
	bob := snmpcred.Creds{Users: []snmpcred.User{{Name: "bob", AuthPass: "bob-auth-pass", PrivPass: "bob-priv-pass"}}, Default: "bob"}

	// The entry is emptied and the file cannot be saved as version 2.
	sb.devSNMP("", "lab-sw1", "clients", "add", "198.51.100.0/24")
	st.Mapped = func(string) bool { return true }
	if err := st.Save(dev, bob); err != nil {
		t.Fatal(err)
	}
	lock(true)
	out := sb.devSNMP("", "lab-sw1", "clients", "remove", "198.51.100.0/24")
	lock(false)
	if sb.code != 1 {
		t.Errorf("exit %d, want 1: %q %q", sb.code, out, sb.stderr())
	}
	if strings.Contains(sb.devices(), "snmp:") {
		t.Errorf("the registry write did not happen:\n%s", sb.devices())
	}
	for _, want := range []string{"could not be saved as version 2", "it is ignored", "tacctl device snmp lab-sw1 v3-user bob"} {
		if !strings.Contains(out, want) {
			t.Errorf("the warning lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "stays in force") {
		t.Errorf("says the file stays in force although it was not written:\n%s", out)
	}
	if got := sb.read(file); !strings.Contains(got, "version: 1") {
		t.Fatalf("the file changed:\n%s", got)
	}
	// The command it names writes the file again, in step with the entry.
	sb.devSNMP("bob-auth-pass\nbob-priv-pass\n", "lab-sw1", "v3-user", "bob", "--stdin")
	if sb.code != 0 {
		t.Fatalf("the named command: exit %d: %q", sb.code, sb.stderr())
	}
	got := sb.read(file)
	if strings.Contains(got, "version: 1") && !strings.Contains(sb.devices(), "snmp:") {
		t.Errorf("still a version 1 file without an entry:\n%s", got)
	}

	// An entry appears and a version 2 file cannot become version 1: it stays
	// version 2, in force; the verb exits 0 and warns.
	sb.devSNMP("", "lab-sw1", "clear")
	if err := st.Save(dev, bob); err != nil {
		t.Fatal(err)
	}
	st.Mapped = func(string) bool { return false }
	if err := st.Save(dev, bob); err != nil {
		t.Fatal(err)
	}
	before := sb.read(file)
	lock(true)
	out = sb.devSNMP("", "lab-sw1", "version", "v3")
	lock(false)
	if sb.code != 0 {
		t.Errorf("exit %d, want 0: %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(out, "could not be brought in step") || !strings.Contains(out, "tacctl device snmp lab-sw1 v3-user bob") {
		t.Errorf("no warning with the command:\n%s", out)
	}
	if got := sb.read(file); got != before || !strings.Contains(got, "version: 2") {
		t.Errorf("the file changed:\n%s", got)
	}
}
