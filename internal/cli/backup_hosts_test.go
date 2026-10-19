package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// 0.2.14 WP14.7 (D188-D196): a snapshot holds the host registry, the host
// records, the staging addresses and the UID ledger; 'backup restore' puts
// them back when the snapshot knows them and says what it does to the hosts
// first; 'backup diff' shows them; the host verbs that write the registry
// take a snapshot first.

// snapshotDirs are the snapshot directories of the sandbox, oldest first.
func (sb *sandbox) snapshotDirs() []string {
	sb.t.Helper()
	m, err := filepath.Glob(filepath.Join(sb.dir, "state", "backups", "2*"))
	if err != nil {
		sb.t.Fatal(err)
	}
	slices.Sort(m)
	return m
}

// readIn is the file name of directory dir, "<absent>" when it is not there.
func readIn(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return "<absent>"
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func (sb *sandbox) hostState() map[string]string {
	state := filepath.Join(sb.dir, "state")
	m := map[string]string{}
	for _, n := range []string{"linux-hosts", "staging", "linux-uids"} {
		m[n] = readIn(sb.t, state, n)
	}
	for _, n := range []string{"web1.json", "web2.json"} {
		m["hosts/"+n] = readIn(sb.t, filepath.Join(state, "hosts"), n)
	}
	return m
}

const (
	liveRegistry = "web1|web1||lab|192.0.2.1|\nweb2|web2||lab|192.0.2.1|\n"
	liveLedger   = "# range 80000-89999\nalice:80000\nbob:80001\ncarol:80002\n"
	snapRegistry = "web1|web1||ops|192.0.2.1|\nweb3|web3||lab|192.0.2.1|\n"
	snapLedger   = "# range 80000-89999\nalice:80000\nbob:80009\n"
)

// hostsSandbox is a rendered sandbox with the live host files and two
// snapshots: one of 0.2.13 (no linux-hosts) and one that knows the hosts.
func hostsSandbox(t *testing.T) *sandbox {
	sb := renderedSandbox(t)
	minimal := fixture(t, "store.minimal.yaml")
	sb.write("state/linux-hosts", liveRegistry, 0o600)
	sb.write("state/hosts/web1.json", "{\"live\":1}\n", 0o600)
	sb.write("state/hosts/web2.json", "{\"live\":2}\n", 0o600)
	sb.write("state/staging", "192.0.2.9/32|lab|host|web2|2026-01-01\n", 0o600)
	sb.write("state/linux-uids", liveLedger, 0o600)

	sb.mkSnapshot("20200101_000000_001", minimal, "")
	sb.mkSnapshot("20200101_000000_002", minimal, "")
	d := "state/backups/20200101_000000_002/"
	sb.write(d+"linux-hosts", snapRegistry, 0o600)
	sb.write(d+"hosts/web1.json", "{\"snap\":1}\n", 0o600)
	sb.write(d+"hosts/web3.json", "{\"snap\":3}\n", 0o600)
	sb.write(d+"linux-uids", snapLedger, 0o600)
	return sb
}

// A snapshot that does not know the hosts leaves all of it alone, and says
// so before the question.
func TestBackupRestoreOfASnapshotWithoutLinuxHostsLeavesTheHostsAlone(t *testing.T) {
	sb := hostsSandbox(t)
	before := sb.hostState()
	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if got := sb.hostState(); !mapsEqual(got, before) {
		t.Errorf("the host files changed:\n%v\nwant\n%v", got, before)
	}
	want := "This snapshot does not know the hosts (taken by 0.2.13 or older)"
	if !strings.Contains(out, want) {
		t.Errorf("no note:\n%s", out)
	}
	if strings.Contains(out, "Enrolled hosts change") {
		t.Errorf("a note of changes for a restore that changes nothing:\n%s", out)
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// A snapshot that knows them puts the registry, the records, staging and the
// ledger back; a record it lacks goes; the note before the question names the
// hosts and the users, and the pre-restore snapshot makes it undoable.
func TestBackupRestoreOfASnapshotWithLinuxHostsPutsTheHostFilesBack(t *testing.T) {
	sb := hostsSandbox(t)
	before := sb.hostState()
	snapsBefore := len(sb.snapshotDirs())

	// Declined: the note is there, nothing changed.
	out := plain(sb.run("n\n", []string{"backup", "restore", "20200101_000000_002"}))
	sb.expect(0, "Cancelled.", "")
	if !mapsEqual(sb.hostState(), before) {
		t.Error("a declined restore changed the host files")
	}
	for _, want := range []string{
		"Enrolled hosts change (tacctl host list): come back: web3; go: web2; registered differently: web1.",
		"The hosts themselves are not touched.",
		"'tacctl host sync <name>'", "'tacctl host show <name> --check'", "'tacctl host unenroll <name>' again",
		"'tacctl host unenroll <name> --force' after that",
		"forgets or changes the number of: bob (80001 becomes 80009), carol (80002, dropped).",
		"may stop on a UID mismatch",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the note lacks %q:\n%s", want, out)
		}
	}
	if i, j := strings.Index(out, "Enrolled hosts change"), strings.Index(out, "Cancelled."); i < 0 || j < i {
		t.Errorf("the note is not before the question:\n%s", out)
	}
	if len(sb.snapshotDirs()) != snapsBefore {
		t.Error("a declined restore made a snapshot")
	}

	out = plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_002"}))
	sb.expect(0, "Restored snapshot 20200101_000000_002.", "")
	got := sb.hostState()
	want := map[string]string{
		"linux-hosts":     snapRegistry,
		"staging":         "<absent>",
		"linux-uids":      snapLedger,
		"hosts/web1.json": "{\"snap\":1}\n",
		"hosts/web2.json": "<absent>",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	for _, rel := range []string{"state/linux-hosts", "state/linux-uids", "state/hosts/web1.json"} {
		if st, err := os.Stat(sb.path(rel)); err != nil || st.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v", rel, st, err)
		}
	}
	if st, err := os.Stat(sb.path("state/hosts")); err != nil || st.Mode().Perm() != 0o700 {
		t.Errorf("hosts directory: %v %v", st, err)
	}
	if _, err := os.Stat(sb.path("state/hosts/web3.json")); err != nil {
		t.Errorf("web3's record did not come back: %v", err)
	}
	// The note is repeated after the restore.
	if strings.Count(out, "Enrolled hosts change") != 2 {
		t.Errorf("the note is not repeated after the restore:\n%s", out)
	}
	if l := sb.leftovers("hosts/*.tacctl-new"); len(l) != 0 {
		t.Errorf("left behind: %q", l)
	}

	// The pre-restore snapshot holds the live host files: restoring it undoes
	// the restore.
	dirs := sb.snapshotDirs()
	if len(dirs) != snapsBefore+1 {
		t.Fatalf("%d snapshots, want %d", len(dirs), snapsBefore+1)
	}
	pre := dirs[len(dirs)-1]
	if readIn(t, pre, "linux-hosts") != liveRegistry || readIn(t, pre, "linux-uids") != liveLedger ||
		readIn(t, pre, "staging") == "<absent>" || readIn(t, filepath.Join(pre, "hosts"), "web2.json") != "{\"live\":2}\n" {
		t.Errorf("the pre-restore snapshot lacks the live host files: %s", pre)
	}
	sb.run("y\n", []string{"backup", "restore", filepath.Base(pre)})
	sb.expect(0, "Restored snapshot "+filepath.Base(pre)+".", "")
	if got := sb.hostState(); !mapsEqual(got, before) {
		t.Errorf("the undo did not bring the host files back:\n%v\nwant\n%v", got, before)
	}
}

// A snapshot taken with no registry holds an empty linux-hosts: restoring it
// empties a live registry, removes the records, staging and the ledger it
// lacks, and creates no registry where there was none.
func TestBackupRestoreOfAnEmptyRegistrySnapshot(t *testing.T) {
	sb := hostsSandbox(t)
	sb.write("state/backups/20200101_000000_001/linux-hosts", "", 0o600)
	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	got := sb.hostState()
	if got["linux-hosts"] != "" || got["staging"] != "<absent>" || got["linux-uids"] != "<absent>" ||
		got["hosts/web1.json"] != "<absent>" || got["hosts/web2.json"] != "<absent>" {
		t.Errorf("host files: %v", got)
	}
	if _, err := os.Stat(sb.path("state/hosts")); !os.IsNotExist(err) {
		t.Errorf("the empty records directory is left: %v", err)
	}
	if !strings.Contains(out, "go: web1, web2") || !strings.Contains(out, "alice (80000, dropped), bob (80001, dropped), carol (80002, dropped)") {
		t.Errorf("note:\n%s", out)
	}

	// No registry now and none in the snapshot: none is made.
	_ = os.Remove(sb.path("state/linux-hosts"))
	sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot", "")
	if _, err := os.Stat(sb.path("state/linux-hosts")); !os.IsNotExist(err) {
		t.Errorf("a registry was made: %v", err)
	}
}

// A restore that changes nothing of the hosts has no note about them.
func TestBackupRestoreWithTheSameHostsSaysNothingOfThem(t *testing.T) {
	sb := hostsSandbox(t)
	d := "state/backups/20200101_000000_001/"
	sb.write(d+"linux-hosts", liveRegistry, 0o600)
	sb.write(d+"linux-uids", liveLedger, 0o600)
	out := plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	sb.expect(0, "Restored snapshot", "")
	if strings.Contains(out, "Enrolled hosts change") || strings.Contains(out, "UID ledger") || strings.Contains(out, "does not know") {
		t.Errorf("a note for a restore that changes no host:\n%s", out)
	}
	// The ledger's range record is part of the file, and a change of it is said.
	sb = hostsSandbox(t)
	sb.write("state/backups/20200101_000000_001/linux-hosts", liveRegistry, 0o600)
	sb.write("state/backups/20200101_000000_001/linux-uids", "# range 70000-79999\nalice:70000\nbob:80001\ncarol:80002\n", 0o600)
	out = plain(sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"}))
	if !strings.Contains(out, "alice (80000 becomes 70000)") ||
		!strings.Contains(out, "The range the ledger is numbered for changes from 80000-89999 to 70000-79999.") {
		t.Errorf("range note:\n%s", out)
	}
}

// D196: the diff adds the host entries, each only where one side has it.
func TestBackupDiffShowsTheHostFiles(t *testing.T) {
	sb := hostsSandbox(t)
	diffs := func(args ...string) string {
		sb.run("", args)
		return strings.Join(sb.runner.Argvs(), "\n")
	}
	id := "20200101_000000_002"
	got := diffs("backup", "diff", id)
	for _, label := range []string{"linux-hosts", "hosts/web1.json", "hosts/web2.json", "hosts/web3.json", "staging", "linux-uids"} {
		if !strings.Contains(got, "--label snapshot/"+id+"/"+label+" --label current/"+label+" ") {
			t.Errorf("no diff of %s:\n%s", label, got)
		}
	}
	// A snapshot with none of it, against a server with none: the diff is as
	// it was.
	for _, rel := range []string{"state/linux-hosts", "state/staging", "state/linux-uids", "state/hosts/web1.json", "state/hosts/web2.json"} {
		_ = os.Remove(sb.path(rel))
	}
	sb.write("state/backups/20200101_000000_001/linux-hosts", "", 0o600)
	out := plain(sb.run("", []string{"backup", "diff", "20200101_000000_001"}))
	for _, name := range []string{"linux-hosts", "hosts/", "staging", "linux-uids"} {
		if strings.Contains(out, name) {
			t.Errorf("the diff names %s with none on either side:\n%s", name, out)
		}
	}
	// One side only: staging is named when only the live server has it.
	sb.write("state/staging", "192.0.2.9/32|lab|host|web2|2026-01-01\n", 0o600)
	if got := diffs("backup", "diff", "20200101_000000_001"); !strings.Contains(got, "current/staging") || strings.Contains(got, "current/linux-uids") {
		t.Errorf("one side only:\n%s", got)
	}
}

// A snapshot of 0.2.13 or older does not know the hosts: a restore of it
// leaves the live host files alone, so the diff does not list them as only in
// the current state. One line says so, when there are host files.
func TestBackupDiffOfASnapshotThatPredatesTheHostFiles(t *testing.T) {
	sb := hostsSandbox(t)
	const line = "  host files: not in this snapshot (it predates 0.2.14)"
	old := "20200101_000000_001" // no linux-hosts in it
	out := plain(sb.run("", []string{"backup", "diff", old}))
	if !strings.Contains(out, line) {
		t.Errorf("no line:\n%s", out)
	}
	if argv := strings.Join(sb.runner.Argvs(), "\n"); strings.Contains(argv, "current/linux-hosts") || strings.Contains(argv, "current/hosts/") ||
		strings.Contains(argv, "current/staging") || strings.Contains(argv, "current/linux-uids") {
		t.Errorf("the live host files were diffed:\n%s", argv)
	}
	// The snapshot that knows them is diffed as before, without the line.
	if out := plain(sb.run("", []string{"backup", "diff", "20200101_000000_002"})); strings.Contains(out, "predates") {
		t.Errorf("the line is there for a snapshot that knows the hosts:\n%s", out)
	}
	// No host files at all: nothing to say.
	for _, rel := range []string{"state/linux-hosts", "state/staging", "state/linux-uids", "state/hosts/web1.json", "state/hosts/web2.json"} {
		_ = os.Remove(sb.path(rel))
	}
	if out := plain(sb.run("", []string{"backup", "diff", old})); strings.Contains(out, "host files") {
		t.Errorf("a line for a server with no hosts:\n%s", out)
	}
}

// D191: enroll (and so move) and unenroll take a snapshot before the registry
// changes; sync does not.
func TestHostVerbsSnapshotBeforeTheRegistryChanges(t *testing.T) {
	hs := newHostSandbox(t)
	n0 := len(hs.snapshotDirs())

	hs.run(nil, "host", "enroll", "admin@web1.example.net", "--scope", "lab", "--allow-uid-mismatch", "--remove-home", "--build-on-host")
	hs.expect(0, "Host 'web1' enrolled.", "")
	dirs := hs.snapshotDirs()
	if len(dirs) <= n0 {
		t.Fatalf("enroll took no snapshot (%d before, %d after)", n0, len(dirs))
	}
	last := dirs[len(dirs)-1]
	if got := readIn(t, last, "linux-hosts"); got != "" {
		t.Errorf("the enroll snapshot has the new registry: %q", got)
	}
	if got := readIn(t, last, "linux-uids"); !strings.Contains(got, "alice:80000") {
		t.Errorf("the enroll snapshot lacks the ledger the script was numbered from: %q", got)
	}
	if hs.registry() == "" {
		t.Fatal("not enrolled")
	}

	// sync: no snapshot, though it writes the host's record.
	n1 := len(hs.snapshotDirs())
	hs.run(nil, "host", "sync", "web1")
	hs.expect(0, "web1: synced", "")
	if n := len(hs.snapshotDirs()); n != n1 {
		t.Errorf("sync took a snapshot (%d before, %d after)", n1, n)
	}

	// move: the snapshot has the host in the scope it leaves.
	hs.run(nil, "host", "move", "web1", "prod", "-y")
	hs.expect(0, "Host 'web1' enrolled", "")
	dirs = hs.snapshotDirs()
	if len(dirs) <= n1 {
		t.Fatalf("move took no snapshot")
	}
	if got := readIn(t, dirs[len(dirs)-1], "linux-hosts"); !strings.Contains(got, "|lab|") || strings.Contains(got, "|prod|") {
		t.Errorf("the move snapshot: %q", got)
	}
	if !strings.Contains(hs.registry(), "|prod|") {
		t.Fatalf("not moved: %q", hs.registry())
	}

	// unenroll: the snapshot has the host in the registry and its record.
	n2 := len(hs.snapshotDirs())
	hs.run(nil, "host", "unenroll", "web1")
	hs.expect(0, "Host 'web1' unenrolled.", "")
	dirs = hs.snapshotDirs()
	if len(dirs) <= n2 {
		t.Fatalf("unenroll took no snapshot")
	}
	last = dirs[len(dirs)-1]
	if got := readIn(t, last, "linux-hosts"); !strings.Contains(got, "web1|") {
		t.Errorf("the unenroll snapshot: %q", got)
	}
	if got := readIn(t, filepath.Join(last, "hosts"), "web1.json"); got == "<absent>" {
		t.Error("the unenroll snapshot lacks the host's record")
	}
	if hs.registry() != "" {
		t.Errorf("registry %q", hs.registry())
	}

	// And a restore of that snapshot brings the host back, named in the note.
	hs.stdin = "y\n"
	out := plain(hs.run(nil, "backup", "restore", filepath.Base(last)))
	hs.expect(0, "Restored snapshot "+filepath.Base(last)+".", "")
	if !strings.Contains(out, "come back: web1") || !strings.Contains(hs.registry(), "web1|") {
		t.Errorf("the restore did not bring the host back (%q):\n%s", hs.registry(), out)
	}
	if _, err := os.Stat(hs.path("state/hosts/web1.json")); err != nil {
		t.Errorf("the record did not come back: %v", err)
	}
}
