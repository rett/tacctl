package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
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
	for _, want := range []string{"holds 1 user whose name has a period (bob.smith)", "nothing is rendered", "Run 'tacctl upgrade' to rename the user", "also updates tacctl if its branch has a newer release"} {
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

// The console.yaml of such a snapshot can hold settings of the user whose name
// has a period, which the console's reader refuses: a restore that installed it
// as it is would leave the file unreadable, the console's policy would fail and
// every user below the superuser would be held at the password change. The
// file installed lacks those keys, keeps every other setting and the settings
// of the other users, and the restore names what it dropped.
func TestBackupRestoreDropsTheConsoleKeysOfADottedUser(t *testing.T) {
	sb := renderedSandbox(t)
	dottedSnapshot(t, sb, "20200101_000000_001")
	sb.write("state/backups/20200101_000000_001/console.yaml", `version: 1
users: {bob.smith: enable, carol: disable}
settings:
  idle_timeout: 12
  system_shell_users: {bob.smith: 'enable:operator', carol: disable, dave.x: disable}
  password_cache_users: {bob.smith: true, carol: true}
`, 0o600)

	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	f, err := console.Load(sb.path("state", "console.yaml"))
	if err != nil {
		t.Fatalf("the console settings cannot be read after the restore: %v\n%s", err, sb.read("state/console.yaml"))
	}
	if on, had := f.SystemShellUsers["carol"]; f.Idle != 12 || on || !had || len(f.SystemShellUsers) != 1 ||
		!f.PasswordCacheUsers["carol"] || len(f.PasswordCacheUsers) != 1 || f.IgnoredUsers["carol"] || len(f.IgnoredUsers) != 1 {
		t.Errorf("the settings kept are not the snapshot's without the dotted keys: %+v", f)
	}
	// each dropped key is named, before the question and after the restore
	for _, want := range []string{
		"will drop console setting of user bob.smith: system shell enable:operator",
		"will drop console setting of user bob.smith: password cache on",
		"will drop console setting of user bob.smith: 'users' override enable",
		"will drop console setting of user dave.x: system shell disable",
		"dropped console setting of user bob.smith: system shell enable:operator",
		"dropped console setting of user bob.smith: password cache on",
		"dropped console setting of user bob.smith: 'users' override enable",
		"dropped console setting of user dave.x: system shell disable",
	} {
		if n := strings.Count(out, want); n != 1 {
			t.Errorf("%q is said %d times, want 1:\n%s", want, n, out)
		}
	}
	if n := strings.Count(out, "is set again after 'tacctl upgrade' has renamed the user"); n != 2 {
		t.Errorf("the way on is said %d times, want 2:\n%s", n, out)
	}
}

// A snapshot whose console.yaml has no such key is installed byte for byte, and
// one that cannot be read refuses the restore before anything changes.
func TestBackupRestoreOfADottedSnapshotKeepsAPlainConsoleFile(t *testing.T) {
	sb := renderedSandbox(t)
	dottedSnapshot(t, sb, "20200101_000000_001")
	plainFile := "version: 1\nsettings:\n  idle_timeout: 7\n  system_shell_users: {carol: disable}\n"
	sb.write("state/backups/20200101_000000_001/console.yaml", plainFile, 0o600)
	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if sb.read("state/console.yaml") != plainFile || strings.Contains(out, "console setting") {
		t.Errorf("the file was rewritten or a drop was said:\n%s\n%s", sb.read("state/console.yaml"), out)
	}

	// a name the rule refuses that has no period cannot be written, and a file
	// that is no YAML cannot be read
	for i, text := range []string{
		"version: 1\nsettings: {system_shell_users: {bob.smith: disable, 'bo b': disable}}\n",
		"version: 1\nsettings: [\n",
	} {
		id := "2020010" + string(rune('2'+i)) + "_000000_001"
		sb.mkSnapshot(id, sb.read("state/backups/20200101_000000_001/store.yaml"), "")
		sb.write("state/backups/"+id+"/console.yaml", text, 0o600)
		before := sb.liveState()
		sb.run("y\n", []string{"backup", "restore", id})
		sb.expect(1, "", "Snapshot "+id+" cannot be restored: its console.yaml cannot be read. Nothing was changed.")
		if sb.liveState() != before || sb.read("state/console.yaml") != plainFile {
			t.Error("a refused restore changed the state")
		}
	}
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
