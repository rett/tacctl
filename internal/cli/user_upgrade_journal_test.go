package cli

import (
	"os"
	"strings"
	"testing"
)

// An upgrade that stopped after it renamed a user in the store leaves its
// journal, and the next upgrade moves the ledger line and the console settings
// of the renamed person to the new name. Until then a verb that removes, adds
// or renames a user of that name is refused with the way on: a user removed
// and added again under the name would be given the other person's settings.
// Other names, and every verb when there is no journal, are as before.
func TestUserVerbsWaitForAnUnfinishedUpgradeRename(t *testing.T) {
	sb := renderedSandbox(t)
	sb.write("state/upgrade-renames", "# renames\nbob.smith bob\ncarol.jones carol_jones\n", 0o600)
	before := sb.read("state/store.yaml")
	const wantBob = "The upgrade's rename of user bob.smith to bob is not finished: run 'tacctl upgrade' first. Nothing was changed."

	sb.asAlice("y\n", "user", "remove", "bob")
	sb.expect(1, "", wantBob)
	sb.asAlice("", "user", "rename", "bob", "bobby")
	sb.expect(1, "", wantBob)
	sb.asAlice("", "user", "rename", "carol", "carol_jones")
	sb.expect(1, "", "The upgrade's rename of user carol.jones to carol_jones is not finished: run 'tacctl upgrade' first. Nothing was changed.")
	sb.asAlice("", "user", "add", "carol_jones", "operator", "--hash", testHash, "--scopes", "lab")
	sb.expect(1, "", "The upgrade's rename of user carol.jones to carol_jones is not finished: run 'tacctl upgrade' first. Nothing was changed.")
	if sb.read("state/store.yaml") != before {
		t.Error("a refused verb changed the store")
	}

	// a name the journal does not name is not held back
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", testHash, "--scopes", "lab")
	sb.expect(0, "User 'dave' added", "")
	sb.asAlice("", "user", "rename", "dave", "davey")
	sb.expect(0, "User renamed: dave -> davey", "")

	// the entry goes with the journal: nothing is refused after that
	if err := os.Remove(sb.path("state", "upgrade-renames")); err != nil {
		t.Fatal(err)
	}
	sb.asAlice("y\n", "user", "remove", "bob")
	sb.expect(0, "User 'bob' removed.", "")
}

// An import puts users into the store from outside, so it waits for the
// unfinished rename of any user; a check writes nothing and does not.
func TestStoreImportWaitsForAnUnfinishedUpgradeRename(t *testing.T) {
	sb := renderedSandbox(t)
	sb.write("import.yaml", sb.read("state/store.yaml"), 0o600)
	sb.write("state/upgrade-renames", "bob.smith bob\n", 0o600)
	before := sb.read("state/store.yaml")

	sb.asAlice("", "store", "import", "--replace", "--force", sb.path("import.yaml"))
	sb.expect(1, "", "The upgrade's rename of user bob.smith to bob is not finished: run 'tacctl upgrade' first. Nothing was changed.")
	if sb.read("state/store.yaml") != before {
		t.Error("a refused import changed the store")
	}
	sb.asAlice("", "store", "import", "--check", sb.path("import.yaml"))
	if sb.code == 1 && strings.Contains(sb.stderr(), "not finished") {
		t.Errorf("--check was refused: %q", sb.stderr())
	}
}

// A restore replaces the store, the ledger and console.yaml together, so the
// journal of renames that described the state before it goes: none of its
// entries is pending in what came back.
func TestBackupRestoreForgetsTheUpgradesJournal(t *testing.T) {
	sb := renderedSandbox(t)
	sb.mkSnapshot("20200101_000000_001", sb.read("state/store.yaml"), "")
	sb.write("state/upgrade-renames", "bob.smith bob\n", 0o600)

	sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if _, err := os.Stat(sb.path("state", "upgrade-renames")); err == nil {
		t.Error("the journal is left after a restore")
	}
	sb.asAlice("y\n", "user", "remove", "bob")
	sb.expect(0, "User 'bob' removed.", "")
}
