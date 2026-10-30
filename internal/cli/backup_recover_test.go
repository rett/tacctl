package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// recoverSandbox has a snapshot that holds an address for alice, bob, carol
// and dave, and a live state where alice and dave have none, bob is gone
// (renamed: robert keeps its address), carol has another address and erin holds dave's: one address
// to restore, three users skipped for the three reasons. It returns the
// snapshot's id.
func recoverSandbox(t *testing.T) (*sandbox, string) {
	t.Helper()
	sb := newSandbox(t, true)
	h, err := hash.Generate("CorrectHorse99", 4)
	if err != nil {
		t.Fatal(err)
	}
	sb.asAlice("", "user", "add", "dave", "operator", "--hash", h, "--scopes", "lab", "--no-change-required")
	sb.expect(0, "", "")
	for _, u := range []string{"alice", "bob", "carol", "dave"} {
		sb.asAlice("", "user", "email", u, u+"@example.net")
		sb.expect(0, "", "")
	}
	sb.asAlice("", "user", "disable", "dave") // the snapshot before it holds the four addresses
	sb.expect(0, "", "")
	ids := snapshotIDsOf(sb)
	id := ids[len(ids)-1]
	if b, _ := os.ReadFile(sb.path("state", "backups", id, "store.yaml")); strings.Count(string(b), "email:") != 4 {
		t.Fatalf("the snapshot does not hold the four addresses:\n%s", b)
	}
	sb.asAlice("", "user", "email", "alice", "clear")
	sb.asAlice("", "user", "email", "dave", "clear")
	sb.asAlice("", "user", "rename", "bob", "robert")
	sb.asAlice("", "user", "email", "carol", "carol2@example.net")
	sb.expect(0, "", "")
	sb.asAlice("", "user", "add", "erin", "operator", "--hash", h, "--scopes", "lab", "--no-change-required", "--email", "dave@example.net")
	sb.expect(0, "", "")
	return sb, id
}

// 'backup recover' lists what it would restore and skips, naming users and
// never an address; --dry-run changes nothing; the recovery sets the one
// address that can be set, keeps the current address of a user who has one,
// skips a user who is gone and an address another user holds, and says so.
func TestBackupRecoverEmail(t *testing.T) {
	sb, id := recoverSandbox(t)
	before := tree(t, sb.dir)

	out := sb.asAlice("", "backup", "recover", id, "--dry-run")
	sb.expect(0, "This was a dry run: nothing was changed.", "")
	for _, want := range []string{"Recover from snapshot " + id, "email addresses:", "alice: restore", "bob: skip, no longer exists",
		"carol: skip, has a different address now, kept", "dave: skip, the address belongs to user 'erin' now"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(strings.ToLower(out), "example.net") {
		t.Errorf("the dry run shows an address:\n%s", out)
	}
	if !reflectEqual(before, tree(t, sb.dir)) {
		t.Errorf("the dry run changed %q", changedFiles(before, tree(t, sb.dir)))
	}

	// not confirmed: nothing changes
	sb.asAlice("n\n", "backup", "recover", id)
	sb.expect(0, "Cancelled.", "")
	if got := emailOf(t, sb, "alice"); got != "" {
		t.Errorf("a cancelled recovery set %q", got)
	}

	snaps := len(snapshotIDsOf(sb))
	sb.asAlice("y\n", "backup", "recover", id)
	sb.expect(0, "Recovered 1 item from snapshot "+id+".", "")
	if !strings.Contains(sb.stderr()+sb.out.String(), "3 items were skipped") {
		t.Errorf("no word of the skipped items:\n%s%s", sb.out.String(), sb.stderr())
	}
	for u, want := range map[string]string{"alice": "alice@example.net", "carol": "carol2@example.net", "dave": "", "erin": "dave@example.net", "robert": "bob@example.net"} {
		if got := emailOf(t, sb, u); got != want {
			t.Errorf("%s: %q, want %q", u, got, want)
		}
	}
	if n := len(snapshotIDsOf(sb)); n != snaps+1 {
		t.Errorf("snapshots %d -> %d: the current state is taken first", snaps, n)
	}
	if n := sb.runner.Count("systemctl", "restart"); n != 0 {
		t.Errorf("a recovery restarted a backend %d times", n)
	}
	pre := snapshotIDsOf(sb)
	wantDetail(t, "backup recover", auditCalls(sb.runner), "auth.info",
		"backup recover id="+id+" pre="+pre[len(pre)-1]+" kinds=email restored=1 skipped=3 by=alice")
	noLoggerHas(t, "backup recover", sb.runner, "example.net", "alice@", "Example")
	// the snapshot being read is still there
	if _, err := os.Stat(sb.path("state", "backups", id, "store.yaml")); err != nil {
		t.Errorf("the snapshot being read is gone: %v", err)
	}

	// again: nothing is left to restore
	sb.asAlice("", "backup", "recover", id, "--yes")
	sb.expect(0, "Nothing to recover.", "")
	if sb.asAlice("", "user", "email", "alice") != "alice@example.net\n" {
		t.Error("the address is gone")
	}
}

// --yes asks nothing, and the kinds are checked before anything is read: a
// reserved kind is refused as not available yet, an unknown one as unknown,
// a list repeats nothing.
func TestBackupRecoverKinds(t *testing.T) {
	sb, id := recoverSandbox(t)
	before := tree(t, sb.dir)
	for _, c := range []struct {
		only, want string
	}{
		{"snmp-users", "'snmp-users' is not available yet"},
		{"email,snmp-users", "'snmp-users' is not available yet"},
		{"bogus", "Unknown kind 'bogus'. Kinds: email, snmp-users."},
		{",", "Usage: tacctl backup recover"},
	} {
		sb.asAlice("", "backup", "recover", id, "--only", c.only, "--yes")
		sb.expect(1, "", c.want)
	}
	if !reflectEqual(before, tree(t, sb.dir)) {
		t.Errorf("a refusal changed %q", changedFiles(before, tree(t, sb.dir)))
	}
	sb.asAlice("", "backup", "recover", id, "--only", "email,email", "--yes")
	sb.expect(0, "Recovered 1 item", "")
	if got := emailOf(t, sb, "alice"); got != "alice@example.net" {
		t.Errorf("alice %q", got)
	}
	// the option may be written with an equals sign
	sb.asAlice("", "backup", "recover", id, "--only=email", "--dry-run")
	sb.expect(0, "Nothing to recover.", "")
}

// The refusals before the snapshot is read.
func TestBackupRecoverRefusals(t *testing.T) {
	sb, id := recoverSandbox(t)
	before := tree(t, sb.dir)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"backup", "recover"}, "Usage: tacctl backup recover <snapshot>"},
		{[]string{"backup", "recover", id, id}, "Usage: tacctl backup recover <snapshot>"},
		{[]string{"backup", "recover", id, "--bogus"}, "Unknown option '--bogus'"},
		{[]string{"backup", "recover", id, "--only"}, "Usage: tacctl backup recover <snapshot>"},
		{[]string{"backup", "recover", "20200101_000000_000"}, "Backup not found: 20200101_000000_000"},
		{[]string{"backup", "recover", "../x"}, "Backup not found"},
	} {
		sb.asAlice("", c.args...)
		sb.expect(1, "", c.want)
	}
	if !reflectEqual(before, tree(t, sb.dir)) {
		t.Errorf("a refusal changed %q", changedFiles(before, tree(t, sb.dir)))
	}
}

// A snapshot taken before any address was set recovers nothing, and says so.
func TestBackupRecoverFromASnapshotWithoutAddresses(t *testing.T) {
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "disable", "bob")
	sb.expect(0, "", "")
	ids := snapshotIDsOf(sb)
	if len(ids) == 0 {
		t.Fatal("no snapshot")
	}
	before := tree(t, sb.dir)
	sb.asAlice("", "backup", "recover", ids[0], "--yes")
	sb.expect(0, "the snapshot holds none", "")
	if out := sb.out.String(); !strings.Contains(out, "Nothing to recover.") {
		t.Errorf("output:\n%s", out)
	}
	if !reflectEqual(before, tree(t, sb.dir)) {
		t.Errorf("changed %q", changedFiles(before, tree(t, sb.dir)))
	}
}

// The list of kinds is the one place: the spec, the completion and the
// messages follow it.
func TestBackupRecoverKindsAreOneList(t *testing.T) {
	spec := backupSpecs["recover"]
	var only Flag
	for _, f := range spec.Flags {
		if f.Names[0] == "--only" {
			only = f
		}
	}
	if only.Kind != "email|snmp-users"+KindList {
		t.Errorf("--only kind %q", only.Kind)
	}
	if recoverKindsLine() != "Kinds: email, snmp-users." {
		t.Errorf("%q", recoverKindsLine())
	}
	reserved := 0
	for _, k := range recoverKinds {
		if k.reserved {
			reserved++
			if k.plan != nil {
				t.Errorf("%s is reserved and has a plan", k.name)
			}
		} else if k.plan == nil {
			t.Errorf("%s has no plan", k.name)
		}
	}
	if reserved != 1 {
		t.Errorf("%d reserved kinds", reserved)
	}
}

// A snapshot is recovered from where an id is looked up: backups/, else a
// kept copy, so the data of a snapshot that a retention pruned is still
// recovered; a kept copy is named, and 'backup unkeep' removes it.
func TestBackupRecoverFromAKeptCopy(t *testing.T) {
	sb, id := recoverSandbox(t)
	sb.asAlice("", "backup", "keep", id, "--note", "the addresses")
	sb.expect(0, "", "")
	// the retention pruned the snapshot
	if err := os.RemoveAll(sb.path("state", "backups", id)); err != nil {
		t.Fatal(err)
	}
	out := sb.asAlice("", "backup", "recover", id, "--dry-run")
	sb.expect(0, "alice: restore", "")
	if !strings.Contains(out, "(a kept copy, "+sb.path("state", "backups-kept", id)+")") {
		t.Errorf("the dry run does not name the kept copy:\n%s", out)
	}
	sb.asAlice("", "backup", "recover", id, "--yes")
	sb.expect(0, "Recovered 1 item from snapshot "+id+".", "")
	if got := emailOf(t, sb, "alice"); got != "alice@example.net" {
		t.Errorf("alice %q", got)
	}
	if !strings.Contains(sb.out.String()+sb.stderr(), "'tacctl backup unkeep "+id+"' removes it") {
		t.Errorf("no word of unkeep:\n%s%s", sb.out.String(), sb.stderr())
	}
	if _, err := os.Stat(sb.path("state", "backups-kept", id, "store.yaml")); err != nil {
		t.Errorf("the kept copy was removed: %v", err)
	}
}
