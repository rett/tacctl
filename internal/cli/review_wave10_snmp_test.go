package cli

// WP10.8a, A5 and B10: the SNMP credential files and the snapshots,
// rollbacks and scope names around them.

import (
	"os"
	"strings"
	"testing"
)

// A5: the per-scope credential files (and the default snmp.yaml) are part
// of a snapshot, in their modes, and 'backup restore' brings them back.
func TestSnapshotsHoldTheSNMPCredentials(t *testing.T) {
	sb := renderedSandbox(t)
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	sb.said(0, "SNMP community of scope 'lab' set")
	sb.cfgRun("default-community-1\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	// Any change snapshots the state it starts from.
	sb.run("", []string{"group", "add", "extra", "5", "EXTRA-CLASS"})
	sb.expect(0, "Group 'extra' added", "")
	ids := (&invocation{app: newHarness(t, nil, sb.env...).app}).snapshotIDs()
	if len(ids) == 0 {
		t.Fatal("no snapshot")
	}
	id := ids[0]
	for rel, mode := range map[string]os.FileMode{"snmp": 0o700, "snmp/lab.yaml": 0o600, "snmp.yaml": 0o600} {
		st, err := os.Stat(sb.path("state/backups/" + id + "/" + rel))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("snapshot %s: %v %v (want %v)", rel, st, err, mode)
		}
	}
	if got := sb.read("state/backups/" + id + "/snmp/lab.yaml"); !strings.Contains(got, "lab-community-9") {
		t.Errorf("snapshot's lab.yaml: %q", got)
	}

	// The scope's credentials go with 'scope snmp clear'; the default changes.
	sb.scopeSNMP("", "lab", "clear")
	sb.cfgRun("changed-default-2\n", []string{"config", "snmp", "community", "--stdin"}, nil)
	if _, err := os.Stat(sb.path("state/snmp/lab.yaml")); !os.IsNotExist(err) {
		t.Fatalf("lab.yaml left: %v", err)
	}
	sb.run("y\n", []string{"backup", "restore", id})
	sb.expect(0, "Restored snapshot "+id+".", "")
	if got := sb.read("state/snmp/lab.yaml"); !strings.Contains(got, "lab-community-9") {
		t.Errorf("lab.yaml after the restore: %q", got)
	}
	if got := sb.read("state/snmp.yaml"); !strings.Contains(got, "default-community-1") {
		t.Errorf("snmp.yaml after the restore: %q", got)
	}
	if st, err := os.Stat(sb.path("state/snmp/lab.yaml")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("lab.yaml mode: %v %v", st, err)
	}
	if st, err := os.Stat(sb.path("state/snmp")); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("snmp directory mode: %v %v", st, err)
	}
}

// B10: a credentials file the name has (kept by a rollback of an older
// release, restored by hand) is not picked up by a new scope of that name,
// and a rename does not write over one.
func TestLeftoverSNMPCredentialsAreNotTakenOver(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/snmp/newscope.yaml", "community: leftover\n", 0o600)
	sb.run("", []string{"scope", "add", "newscope", "--prefixes", "198.51.100.0/24"})
	sb.expect(1, "", "SNMP credentials for a scope named 'newscope' are already on disk: "+sb.path("state/snmp/newscope.yaml"))
	if o := sb.read("state/store.yaml"); strings.Contains(o, "newscope") {
		t.Errorf("the refused scope was added:\n%s", o)
	}
	// A rename of a scope with credentials onto a name that has a file.
	sb.scopeSNMP("lab-community-9\n", "lab", "community", "--stdin")
	sb.write("state/snmp/renamed.yaml", "community: leftover\n", 0o600)
	sb.run("", []string{"scope", "rename", "lab", "renamed"})
	sb.expect(1, "", "SNMP credentials for a scope named 'renamed' are already on disk")
	if o := sb.read("state/store.yaml"); strings.Contains(o, "renamed") {
		t.Errorf("the refused rename was applied:\n%s", o)
	}
	if got := sb.read("state/snmp/lab.yaml"); !strings.Contains(got, "lab-community-9") {
		t.Errorf("lab.yaml: %q", got)
	}
	if got := sb.read("state/snmp/renamed.yaml"); !strings.Contains(got, "leftover") {
		t.Errorf("renamed.yaml was overwritten: %q", got)
	}
	// With the leftover out of the way both go through.
	if err := os.Remove(sb.path("state/snmp/newscope.yaml")); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"scope", "add", "newscope", "--prefixes", "198.51.100.0/24"})
	sb.expect(0, "Scope 'newscope' added.", "")
}

// A snapshot with no credentials directory (taken before there was one)
// leaves the live files alone; one with a directory makes the live one match
// it (a file it lacks goes with the tacctl.yaml that named it).
func TestRestoreSNMPCredentialsAgainstASnapshotWithoutThem(t *testing.T) {
	sb := renderedSandbox(t)
	minimal := fixture(t, "store.minimal.yaml")
	sb.mkSnapshot("20200101_000000_001", minimal, "")
	sb.mkSnapshot("20200101_000000_002", minimal, "")
	sb.write("state/backups/20200101_000000_002/snmp/lab.yaml", "community: from-snapshot\n", 0o600)
	sb.write("state/snmp/lab.yaml", "community: live\n", 0o600)
	sb.write("state/snmp/prod.yaml", "community: live-prod\n", 0o600)

	sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if got := sb.read("state/snmp/lab.yaml"); !strings.Contains(got, "live") {
		t.Errorf("a snapshot without credentials changed them: %q", got)
	}
	sb.run("y\n", []string{"backup", "restore", "20200101_000000_002"})
	sb.expect(0, "Restored snapshot 20200101_000000_002.", "")
	if got := sb.read("state/snmp/lab.yaml"); !strings.Contains(got, "from-snapshot") {
		t.Errorf("lab.yaml: %q", got)
	}
	if _, err := os.Stat(sb.path("state/snmp/prod.yaml")); !os.IsNotExist(err) {
		t.Errorf("prod.yaml, which the snapshot lacks, is still there: %v", err)
	}
}
