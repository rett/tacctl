package cli

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/snapshot"
)

// snapshotIDsOf are the snapshot ids of the sandbox, oldest first.
func snapshotIDsOf(sb *sandbox) []string {
	m, _ := filepath.Glob(sb.path("state", "backups", "2*"))
	var ids []string
	for _, p := range m {
		ids = append(ids, filepath.Base(p))
	}
	sort.Strings(ids)
	return ids
}

// keptSandbox has one snapshot (the state before bob was disabled).
func keptSandbox(t *testing.T) (*sandbox, string) {
	t.Helper()
	sb := newSandbox(t, true)
	sb.asAlice("", "user", "disable", "bob")
	sb.expect(0, "", "")
	ids := snapshotIDsOf(sb)
	if len(ids) != 1 {
		t.Fatalf("snapshots %v", ids)
	}
	return sb, ids[0]
}

// 'backup keep' copies a snapshot, with its manifest, to backups-kept/ with a
// note and who kept it; 'backup list' shows it; keeping it again says so and a
// new note replaces the note; the note is in no audit line.
func TestBackupKeepAndList(t *testing.T) {
	sb, id := keptSandbox(t)
	dir := sb.path("state", "backups-kept", id)
	const note = "before the 0.2.23 upgrade"
	sb.asAlice("", "backup", "keep", id, "--note", note)
	sb.expect(0, "Snapshot "+id+" kept in "+dir, "")
	for _, f := range []string{"store.yaml", "manifest", "kept"} {
		if st, err := os.Stat(filepath.Join(dir, f)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("the directory: %v %v", st, err)
	}
	a, _ := os.ReadFile(filepath.Join(sb.path("state", "backups", id), "store.yaml"))
	b, _ := os.ReadFile(filepath.Join(dir, "store.yaml"))
	if string(a) != string(b) {
		t.Error("the kept store.yaml differs from the snapshot's")
	}
	info := snapshot.ReadKept(dir)
	if info.Note != note || info.User != "alice" || info.SID == "" || info.At == "" {
		t.Errorf("the record: %+v", info)
	}
	wantDetail(t, "backup keep", auditCalls(sb.runner), "auth.info", "backup keep id="+id+" note=yes already=no by=alice")
	noLoggerHas(t, "backup keep", sb.runner, note, "upgrade")
	if line := auditLine(sb.runner, "cmd start "); !strings.HasSuffix(line, `args="`+id+` --note <redacted>"`) {
		t.Errorf("the start line: %s", line)
	}

	out := sb.asAlice("", "backup", "list")
	if !strings.Contains(out, "snapshot, kept") || !strings.Contains(out, "NOTE") || !strings.Contains(out, note) {
		t.Errorf("backup list:\n%s", out)
	}

	// again: nothing changes; a note replaces the note
	sb.asAlice("", "backup", "keep", id)
	sb.expect(0, "is kept already.", "")
	if wroteAudit(sb.runner) {
		t.Errorf("a keep that changed nothing wrote a line: %q", auditLines(sb.runner))
	}
	sb.asAlice("", "backup", "keep", id, "--note", "second note")
	sb.expect(0, "its note is replaced", "")
	// the record is that of whoever set the note last
	if got := snapshot.ReadKept(dir); got.Note != "second note" || got.User != "alice" || got.SID == "" || got.SID == info.SID {
		t.Errorf("after the new note: %+v", got)
	}
	wantDetail(t, "backup keep note", auditCalls(sb.runner), "auth.info", "backup keep id="+id+" note=yes already=yes by=alice")
	noLoggerHas(t, "backup keep note", sb.runner, "second note")

	// a note is checked, and a word that is no option is not echoed in a log
	sb.asAlice("", "backup", "keep", id, "--note", strings.Repeat("x", 201))
	sb.expect(1, "", "A note is at most 200 characters")
	for _, bad := range []string{"two\nlines", "tab\there", "right\u202eleft", "zero\u200bwidth", "bad\xffbyte", "nbsp\u00a0here", "bell\a"} {
		sb.asAlice("", "backup", "keep", id, "--note", bad)
		sb.expect(1, "", "A note is at most 200 characters")
	}
	if _, err := os.Stat(sb.path("state", "backups-kept", id, "kept")); err == nil {
		if got := snapshot.ReadKept(sb.path("state", "backups-kept", id)); got.Note != "second note" {
			t.Errorf("a refused note changed the record: %+v", got)
		}
	}
	sb.asAlice("", "backup", "keep", id, "SURPLUS", "words")
	sb.expect(1, "", "Usage: tacctl backup keep")
	noLoggerHas(t, "backup keep surplus", sb.runner, "SURPLUS", "words")
	if wroteAudit(sb.runner) {
		t.Errorf("a usage error wrote a line: %q", auditLines(sb.runner))
	}
}

// The refusals: an id that is no snapshot id, one that does not exist.
func TestBackupKeepRefusals(t *testing.T) {
	sb, _ := keptSandbox(t)
	before := tree(t, sb.dir)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"backup", "keep"}, "Usage: tacctl backup keep"},
		{[]string{"backup", "keep", "20200101_000000_000"}, "Backup not found: 20200101_000000_000"},
		{[]string{"backup", "keep", "../backups-kept"}, "Backup not found"},
		{[]string{"backup", "keep", ".."}, "Backup not found"},
		{[]string{"backup", "keep", "x", "--note"}, "Usage: tacctl backup keep"},
		{[]string{"backup", "keep", "x", "--bogus"}, "Usage: tacctl backup keep"},
		{[]string{"backup", "unkeep"}, "Usage: tacctl backup unkeep"},
		{[]string{"backup", "unkeep", "20200101_000000_000", "--yes"}, "is not kept"},
		{[]string{"backup", "unkeep", "../backups", "--yes"}, "is not kept"},
		{[]string{"backup", "unkeep", ".", "--yes"}, "is not kept"},
	} {
		sb.asAlice("", c.args...)
		sb.expect(1, "", c.want)
	}
	if !reflectEqual(before, tree(t, sb.dir)) {
		t.Errorf("a refusal changed %q", changedFiles(before, tree(t, sb.dir)))
	}
}

// A kept snapshot outlives its original: after more than the retention of
// later snapshots the original is gone from backups/, the copy is listed as
// kept only, and diff, restore and the names Tab offers find it.
func TestKeptSnapshotOutlivesTheRetention(t *testing.T) {
	sb, id := keptSandbox(t)
	sb.asAlice("", "backup", "keep", id, "--note", "the state with bob enabled")
	sb.expect(0, "", "")
	for i := 0; i < snapshot.Retention+2; i++ {
		sb.asAlice("", "user", "enable", "bob")
		sb.asAlice("", "user", "disable", "bob")
	}
	if _, err := os.Stat(sb.path("state", "backups", id)); err == nil {
		t.Fatalf("the retention did not prune snapshot %s (%d left)", id, len(snapshotIDsOf(sb)))
	}
	if _, err := os.Stat(sb.path("state", "backups-kept", id, "store.yaml")); err != nil {
		t.Fatalf("the kept copy is gone: %v", err)
	}
	if n := len(snapshotIDsOf(sb)); n != snapshot.Retention {
		t.Errorf("%d snapshots in backups/, want %d", n, snapshot.Retention)
	}
	out := sb.asAlice("", "backup", "list")
	if !strings.Contains(out, id) || !strings.Contains(out, "kept only") || !strings.Contains(out, "the state with bob enabled") {
		t.Errorf("backup list:\n%s", out)
	}
	if got := sb.asAlice("", "_completion-names", "backups"); !strings.Contains(got, id) {
		t.Errorf("the names do not offer the kept id:\n%s", got)
	}
	// diff and restore find it
	out = sb.asAlice("", "backup", "diff", id)
	sb.expect(0, "snapshot "+id, "")
	if !strings.Contains(out, "store.yaml") {
		t.Errorf("diff:\n%s", out)
	}
	if !strings.Contains(emailOrStatus(t, sb, "bob"), "disabled") {
		t.Fatalf("bob is not disabled before the restore")
	}
	sb.asAlice("y\n", "backup", "restore", id)
	sb.expect(0, "Restored snapshot "+id+".", "")
	if got := emailOrStatus(t, sb, "bob"); strings.Contains(got, "disabled") {
		t.Errorf("the restore of the kept copy left bob disabled:\n%s", got)
	}
	// a restore does not touch backups-kept/
	if _, err := os.Stat(sb.path("state", "backups-kept", id, "kept")); err != nil {
		t.Errorf("the restore touched the kept copy: %v", err)
	}
}

// emailOrStatus is 'user show' of a user.
func emailOrStatus(t *testing.T, sb *sandbox, user string) string {
	t.Helper()
	return sb.asAlice("", "user", "show", user)
}

// 'backup unkeep' asks, says when the copy is the only one, and removes it.
func TestBackupUnkeep(t *testing.T) {
	sb, id := keptSandbox(t)
	sb.asAlice("", "backup", "keep", id)
	sb.expect(0, "", "")
	dir := sb.path("state", "backups-kept", id)

	sb.asAlice("n\n", "backup", "unkeep", id)
	sb.expect(0, "Cancelled.", "")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("a cancelled unkeep removed the copy: %v", err)
	}
	if strings.Contains(sb.out.String(), "only copy") {
		t.Errorf("the original is there, but the verb says the copy is the only one:\n%s", sb.out.String())
	}
	sb.asAlice("y\n", "backup", "unkeep", id)
	sb.expect(0, "The kept copy of snapshot "+id+" is removed.", "")
	if _, err := os.Stat(dir); err == nil {
		t.Error("the copy is still there")
	}
	if _, err := os.Stat(sb.path("state", "backups", id, "store.yaml")); err != nil {
		t.Errorf("unkeep touched the original: %v", err)
	}
	wantDetail(t, "backup unkeep", auditCalls(sb.runner), "auth.info", "backup unkeep id="+id+" only-copy=no by=alice")
	if out := sb.asAlice("", "backup", "list"); strings.Contains(out, "kept") || strings.Contains(out, "NOTE") {
		t.Errorf("backup list still shows a kept snapshot:\n%s", out)
	}

	// the only copy
	sb.asAlice("", "backup", "keep", id)
	if err := os.RemoveAll(sb.path("state", "backups", id)); err != nil {
		t.Fatal(err)
	}
	sb.asAlice("n\n", "backup", "unkeep", id)
	sb.expect(0, "the kept copy is the only copy", "")
	sb.asAlice("", "backup", "unkeep", id, "--yes")
	sb.expect(0, "is removed.", "")
	wantDetail(t, "backup unkeep only", auditCalls(sb.runner), "auth.info", "backup unkeep id="+id+" only-copy=yes by=alice")
	sb.asAlice("", "backup", "unkeep", id, "--yes")
	sb.expect(1, "", "is not kept")
}
