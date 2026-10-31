package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The way back: the rollback drops the users, 'backup recover' puts them back
// from the snapshot it kept, and only them. sw2's choice of the config's bob
// comes back in the same run that restores bob; the dry run counts and names
// levels, never a user or a passphrase; the audit line holds counts and the
// ids; a second run has nothing to do.
func TestRollbackThenRecoverSNMPUsers(t *testing.T) {
	hs := rollback0221State(t)
	snmpPoolState(hs)
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	id := filepath.Base(newestSnapshot(t, hs))

	hs.run(nil, "backup", "recover", id, "--only", "snmp-users", "--dry-run")
	hs.expect(0, "This was a dry run", "")
	dry := hs.all()
	for _, want := range []string{"the config: restore 1 user", "device 'sw1': restore 1 user", "device 'sw2': restore its default", "device 'sw3': restore 1 user; restore its default"} {
		if !strings.Contains(dry, want) {
			t.Errorf("the recover dry run lacks %q:\n%s", want, dry)
		}
	}
	for _, secret := range []string{"bob", "monitor", "erin", "pool-auth-pass"} {
		if strings.Contains(dry, secret) {
			t.Errorf("the recover dry run shows %q:\n%s", secret, dry)
		}
	}
	r := hs.runner()
	hs.run(r, "backup", "recover", id, "--only", "snmp-users", "--yes")
	hs.expect(0, "Recovered 5 items from snapshot "+id+".", "")
	if line := auditLine(r, "backup recover"); !strings.Contains(line, "kinds=snmp-users") || !strings.Contains(line, "restored=5") || strings.Contains(line, "bob") {
		t.Errorf("the recover audit line: %q", line)
	}
	if out := plain(hs.run(nil, "config", "snmp", "v3-user", "list")); !strings.Contains(out, "bob") || !strings.Contains(out, "alice  default") {
		t.Errorf("config pool after the recovery:\n%s", out)
	}
	hs.run(nil, "device", "snmp", "sw2", "v3-user", "list")
	hs.expect(0, "default: bob (a user of another level's pool)", "")
	hs.run(nil, "device", "snmp", "sw3", "v3-user", "list")
	hs.expect(0, "erin  default", "")
	hs.run(nil, "device", "snmp", "sw1", "v3-user", "list")
	hs.expect(0, "monitor", "")
	// A second recovery has nothing to restore.
	hs.run(nil, "backup", "recover", id, "--only", "snmp-users", "--yes")
	hs.expect(0, "Nothing to recover.", "")
}

// The recovery skips what cannot come back and says which, by level and
// count: a device that is gone, a name another pool a device can see holds
// now (the config's, as the membership is now); a default that the level has
// now is never overwritten; a default that named a user of the level's own
// pool is not given to another level's user of the same name.
func TestRecoverSNMPUsersSkipsAndNeverOverwritesADefault(t *testing.T) {
	hs := rollback0221State(t)
	snmpPoolState(hs)
	pw := "pool-auth-pass\npool-priv-pass\n"
	hs.step(pw, "scope", "snmp", "lab", "v3-user", "add", "erin", "--stdin")
	hs.run(hs.runner(), "rollback", "0.2.22", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	id := filepath.Base(newestSnapshot(t, hs))
	// After the rollback: sw1 is removed, the config takes the name erin,
	// and the scope's default is another user than the snapshot's.
	hs.stdin = "y\n"
	hs.run(nil, "device", "remove", "sw1")
	hs.stdin = ""
	hs.expect(0, "", "")
	hs.step(pw, "config", "snmp", "v3-user", "add", "erin", "--stdin")
	hs.step(pw, "scope", "snmp", "lab", "v3-user", "add", "dave", "--default", "--stdin")

	hs.run(nil, "backup", "recover", id, "--only", "snmp-users", "--dry-run")
	hs.expect(0, "This was a dry run", "")
	out := hs.all()
	for _, want := range []string{"the config: restore 1 user", "skip 1, the name is held by the config", "device 'sw1': skip 2, no longer exists",
		"device 'sw2': restore its default", "device 'sw3': skip 1, its default: the user it chose is not there; skip 1, the name is held by the config"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	hs.run(nil, "backup", "recover", id, "--only", "snmp-users", "--yes")
	hs.expect(0, "Recovered 2 items from snapshot "+id+".", "")
	// The scope's default is still the user chosen after the rollback.
	if got := plain(hs.run(nil, "scope", "snmp", "lab", "v3-user", "default")); strings.TrimSpace(got) != "dave" {
		t.Errorf("the scope's default: %q", got)
	}
	// sw3 was not handed the config's erin.
	if b, _ := os.ReadFile(hs.path("state", "snmp", "devices", "sw3.yaml")); strings.Contains(string(b), "default: erin") {
		t.Errorf("sw3 chose the config's erin:\n%s", b)
	}
}
