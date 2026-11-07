package cli

import (
	"strings"
	"testing"
)

// A snapshot of 0.2.25 or earlier can hold a user whose name has a period
// (0.2.20 and 0.2.21 allowed one), and 'tacctl upgrade' advises restoring one
// when its rename fails. The restore reads such a snapshot, puts its store
// back, renders nothing (no renderer writes the name), says what to run, and
// then the store reads while every write is refused.
func dottedSnapshot(t *testing.T, sb *sandbox, id string) string {
	t.Helper()
	live := sb.read("state/store.yaml")
	st := strings.Replace(live, "\n  bob:", "\n  bob.smith:", 1)
	if st == live {
		t.Fatalf("no bob in the sandbox store:\n%s", live)
	}
	sb.mkSnapshot(id, st, "")
	return st
}

func TestBackupRestoreReadsASnapshotWithADottedUser(t *testing.T) {
	sb := renderedSandbox(t)
	st := dottedSnapshot(t, sb, "20200101_000000_001")
	artifact := sb.read("etc/tacquito.yaml")
	records := sb.read("state/rendered.json")

	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if sb.read("state/store.yaml") != st {
		t.Error("the store is not the snapshot's")
	}
	if sb.read("etc/tacquito.yaml") != artifact || sb.read("state/rendered.json") != records {
		t.Error("a restore of a dotted user rendered")
	}
	// said before the question and after the restore, with the way on
	for _, want := range []string{"holds 1 user whose name has a period (bob.smith)", "nothing is rendered", "Run 'tacctl upgrade' to rename the user"} {
		if n := strings.Count(out, want); n != 2 {
			t.Errorf("%q is said %d times, want 2 (before the question and after the restore):\n%s", want, n, out)
		}
	}
	if l := sb.leftovers(".restore.*"); len(l) != 0 {
		t.Errorf("left behind: %q", l)
	}
	// the store reads, every write is refused with the way out
	sb.asAlice("", "user", "list")
	sb.expect(0, "bob.smith", "")
	sb.asAlice("", "user", "disable", "carol")
	sb.expect(1, "", "'tacctl upgrade' renames such a user")
}

// What else is wrong with a snapshot's store is still refused, and so is a
// dotted snapshot that would need a backend rendered.
func TestBackupRestoreStillRefusesWhatElseIsInvalid(t *testing.T) {
	sb := renderedSandbox(t)
	live := sb.read("state/store.yaml")
	sb.mkSnapshot("20250101_000000_001", strings.Replace(live, "\n  bob:", "\n  bo b.smith:", 1), "")
	sb.mkSnapshot("20250101_000000_002", strings.Replace(live, "\n  bob:", "\n  bob.smith:", 1), "backends:\n  enabled: [tacacs, radius]\n")
	before := sb.liveState()
	sb.run("y\n", []string{"backup", "restore", "20250101_000000_001"})
	sb.expect(1, "", "invalid name")
	sb.expect(1, "", "its store.yaml is not valid. Nothing was changed.")
	sb.run("y\n", []string{"backup", "restore", "20250101_000000_002"})
	sb.expect(1, "", "enables backend 'radius' and holds users whose name has a period (bob.smith), so nothing could be rendered")
	if after := sb.liveState(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
}

// 'backup recover' reads such a snapshot too, says that its dotted users are
// not recovered, and recovers the rest; no user with a period gets into the
// live store.
func TestBackupRecoverReadsASnapshotWithADottedUser(t *testing.T) {
	sb, id := recoverSandbox(t)
	// the sandbox's snapshot (four addresses) with carol become carol.jones
	snap := sb.read("state/backups/" + id + "/store.yaml")
	snap = strings.Replace(snap, "\n  carol:", "\n  carol.jones:", 1)
	sb.mkSnapshot("20200101_000000_001", snap, "")
	before := sb.read("state/store.yaml")

	out := plain(sb.asAlice("", "backup", "recover", "20200101_000000_001", "--dry-run"))
	for _, want := range []string{"holds 1 user whose name has a period (carol.jones)", "That user is skipped: 'tacctl upgrade' renames it",
		"carol.jones: skip, the name has a period, so it is not recovered"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	sb.asAlice("", "backup", "recover", "20200101_000000_001", "--yes")
	sb.expect(0, "Recovered ", "")
	after := sb.read("state/store.yaml")
	if strings.Contains(after, "carol.jones") {
		t.Errorf("a user with a period is in the store:\n%s", after)
	}
	if before == after {
		t.Error("nothing was recovered, but alice had an address to get back")
	}
}
