package cli

// 'user rename' carries the Linux UID: the ledger line moves with the name,
// under the apply lock after the pre-change snapshot, and the enrolled hosts
// are told what their next sync does (docs/plans/0.2.14-plan.md D205).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const renameLedger = "# range 80000-89999\nalice:80001\nbob:80002\n"

// The line moves in place, once, inside the one apply: the snapshot taken
// first holds the ledger as it was.
func TestUserRenameMovesTheLedgerLineUnderTheApply(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", renameLedger, 0o600)
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(0, "[INFO] User renamed: alice -> zed\n[INFO] UID 80001 follows the rename (linux-uids).\n", "")
	if got, want := sb.read("state/linux-uids"), "# range 80000-89999\nzed:80001\nbob:80002\n"; got != want {
		t.Errorf("ledger %q, want %q", got, want)
	}
	snaps, _ := filepath.Glob(filepath.Join(sb.dir, "state", "backups", "*", "linux-uids"))
	if len(snaps) != 1 {
		t.Fatalf("snapshots %q", snaps)
	}
	if b, _ := os.ReadFile(snaps[0]); string(b) != renameLedger {
		t.Errorf("the snapshot holds %q, not the ledger as it was", b)
	}
	if !strings.Contains(sb.store(), "  zed:\n") || strings.Contains(sb.store(), "  alice:\n") {
		t.Errorf("store:\n%s", sb.store())
	}
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("no restart: %q", sb.runner.Argvs())
	}
	// Renamed again, and back.
	sb.run("", []string{"user", "rename", "zed", "alice"})
	sb.expect(0, "UID 80001 follows the rename", "")
	if sb.read("state/linux-uids") != renameLedger {
		t.Errorf("ledger %q", sb.read("state/linux-uids"))
	}
}

// With enrolled hosts that list the user, the next sync is named; a host of
// a scope without the user does not count.
func TestUserRenameNamesTheHostsThatRenameTheAccount(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", renameLedger, 0o600)
	sb.write("state/linux-hosts", "web1|web1||lab|192.0.2.1|\nweb2|web2||prod|192.0.2.2|\nweb3|web3||dmz|192.0.2.3|\n", 0o600)
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(0, "[INFO] UID 80001 follows the rename (linux-uids).\n"+
		"[WARN] The account 'alice' is renamed to 'zed' on 2 enrolled hosts at each host's next sync, home kept where it is: tacctl host sync web1 web2\n", "")
	// One host; none.
	sb.write("state/linux-hosts", "web1|web1||lab|192.0.2.1|\n", 0o600)
	sb.run("", []string{"user", "rename", "zed", "yan"})
	sb.expect(0, "[WARN] The account 'zed' is renamed to 'yan' on 1 enrolled host at each host's next sync, home kept where it is: tacctl host sync web1", "")
	sb.write("state/linux-hosts", "web3|web3||dmz|192.0.2.3|\n", 0o600)
	sb.run("", []string{"user", "rename", "yan", "xan"})
	sb.expect(0, "UID 80001 follows the rename", "")
	if strings.Contains(plain(sb.out.String()), "enrolled host") {
		t.Errorf("a host without the user is named: %q", sb.out.String())
	}
}

// A disabled user counts too: its account is expired on the host and renamed
// all the same.
func TestUserRenameCountsHostsOfADisabledUser(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", renameLedger, 0o600)
	sb.write("state/linux-hosts", "web1|web1||lab|192.0.2.1|\n", 0o600)
	sb.run("", []string{"user", "disable", "alice"})
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(0, "[WARN] The account 'alice' is renamed to 'zed' on 1 enrolled host at each host's next sync, home kept where it is: tacctl host sync web1\n", "")
}

// A user with no line in the ledger (never sent to a host) renames as it
// did: nothing about a UID, and the ledger is not made.
func TestUserRenameWithoutALedgerLineSaysNothingOfTheUID(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-hosts", "web1|web1||lab|192.0.2.1|\n", 0o600)
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(0, "[INFO] User renamed: alice -> zed\n", "")
	if out := plain(sb.out.String()); strings.Contains(out, "follows") || strings.Contains(out, "enrolled") {
		t.Errorf("output %q", out)
	}
	if _, err := os.Stat(sb.path("state/linux-uids")); err == nil {
		t.Error("the ledger was made")
	}
	sb.write("state/linux-uids", "bob:80002\n", 0o600)
	sb.run("", []string{"user", "rename", "zed", "yan"})
	sb.expect(0, "", "")
	if sb.read("state/linux-uids") != "bob:80002\n" {
		t.Errorf("ledger %q", sb.read("state/linux-uids"))
	}
}

// A new name that has a number already keeps it: the ledger is not
// changed, and the warning says what the hosts do.
func TestUserRenameOntoANameWithAUIDWarns(t *testing.T) {
	sb := newSandbox(t, true)
	const ledger = "# range 80000-89999\nalice:80001\nzed:80007\n"
	sb.write("state/linux-uids", ledger, 0o600)
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(0, "[INFO] User renamed: alice -> zed\n"+
		"[WARN] 'zed' already has UID 80007 in linux-uids; the account 'alice' (UID 80001) is removed on hosts and 'zed' created with 80007\n", "")
	if strings.Contains(plain(sb.out.String()), "follows") {
		t.Errorf("output %q", sb.out.String())
	}
	if sb.read("state/linux-uids") != ledger {
		t.Errorf("ledger %q", sb.read("state/linux-uids"))
	}
}

// A ledger that cannot be written leaves the user renamed (the store is
// rendered), names the snapshot that holds the state before, and exits 1.
func TestUserRenameLedgerFailureNamesTheSnapshot(t *testing.T) {
	sb := newSandbox(t, true)
	// A directory where the file should be: it can be neither read nor
	// replaced.
	if err := os.Mkdir(sb.path("state/linux-uids"), 0o700); err != nil {
		t.Fatal(err)
	}
	sb.run("", []string{"user", "rename", "alice", "zed"})
	sb.expect(1, "[INFO] User renamed: alice -> zed\n", "User renamed, but linux-uids could not be rewritten: ")
	snaps, _ := filepath.Glob(filepath.Join(sb.dir, "state", "backups", "*", "store.yaml"))
	if len(snaps) != 1 {
		t.Fatalf("snapshots %q", snaps)
	}
	id := filepath.Base(filepath.Dir(snaps[0]))
	if want := "Restore snapshot " + id + " (tacctl backup restore " + id + ")"; !strings.Contains(sb.err.String(), want) {
		t.Errorf("stderr %q lacks %q", sb.err.String(), want)
	}
	if !strings.Contains(sb.store(), "  zed:\n") || !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("the rename was not applied:\n%s", sb.store())
	}
}

// A server that is not enrolled holds no accounts: renaming a user says
// nothing of tiers or of syncing it.
func TestUserRenameOnAServerThatIsNotEnrolledSaysNothingOfTiers(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/linux-uids", renameLedger, 0o600)
	sb.run("", []string{"user", "rename", "alice", "zed"})
	if sb.code != 0 || strings.Contains(sb.stderr(), "keeps the groups") || strings.Contains(sb.stderr(), "host sync") {
		t.Errorf("exit %d\n%s", sb.code, sb.stderr())
	}
}
