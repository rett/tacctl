package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 'backup', its 'config diff|restore' aliases, 'status', 'log', 'backend
// list|status' and 'store show|import' end to end in the sandbox
// (native_test.go). The bats files (backup, store_cli, backend_cli,
// status_and_scope_lookup, e2e/log) and the corpora backup.txt, store.txt
// and log.txt pin the bytes against 0.1.16; these pin the wiring and the
// failure paths the bats suite reaches only by overriding bash functions.

// sandboxRADIUS keeps the RADIUS module inside the sandbox (not installed).
func sandboxRADIUS(sb *sandbox) {
	for _, d := range []string{"raddb", "radius-log", "radius-share", "logrotate.d"} {
		if err := os.MkdirAll(filepath.Join(sb.dir, d), 0o700); err != nil {
			sb.t.Fatal(err)
		}
	}
	sb.env = append(sb.env,
		"TACCTL_RADIUS_DIR="+filepath.Join(sb.dir, "raddb"),
		"TACCTL_RADIUS_LOG="+filepath.Join(sb.dir, "radius-log"),
		"TACCTL_RADIUS_BIN="+filepath.Join(sb.dir, "radius-bin", "radiusd"),
		"TACCTL_RADIUS_DICT="+filepath.Join(sb.dir, "radius-share", "dictionary"),
		"TACCTL_LOGROTATE_DIR="+filepath.Join(sb.dir, "logrotate.d"),
	)
}

func (sb *sandbox) write(rel, text string, mode os.FileMode) {
	sb.t.Helper()
	p := sb.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		sb.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), mode); err != nil {
		sb.t.Fatal(err)
	}
}

func (sb *sandbox) read(rel string) string {
	sb.t.Helper()
	data, err := os.ReadFile(sb.path(rel))
	if err != nil {
		sb.t.Fatal(err)
	}
	return string(data)
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("../../tests/fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// mkSnapshot makes snapshot directory id by hand, holding store (and
// tacctl.yaml when not "").
func (sb *sandbox) mkSnapshot(id, store, tacctl string) {
	sb.t.Helper()
	sb.write("state/backups/"+id+"/store.yaml", store, 0o600)
	if tacctl != "" {
		sb.write("state/backups/"+id+"/tacctl.yaml", tacctl, 0o600)
	}
}

// liveState is backup.bats' state_files: the four files a restore must
// leave as they were when it fails.
func (sb *sandbox) liveState() string {
	var b strings.Builder
	for _, rel := range []string{"state/store.yaml", "state/tacctl.yaml", "etc/tacquito.yaml", "state/rendered.json"} {
		data, err := os.ReadFile(sb.path(rel))
		if err != nil {
			fmt.Fprintf(&b, "%s absent\n", rel)
			continue
		}
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s %s\n", rel, hex.EncodeToString(sum[:]))
	}
	return b.String()
}

func (sb *sandbox) leftovers(pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(sb.dir, "state", pattern))
	return m
}

// rendered: the sandbox store rendered (tacquito.yaml, rendered.json) and a
// tacctl.yaml with an override, as after a few commands.
func renderedSandbox(t *testing.T) *sandbox {
	sb := newSandbox(t, true)
	sandboxRADIUS(sb)
	sb.run("", []string{"config", "render"})
	sb.expect(0, "Rendered", "")
	sb.run("", []string{"config", "bcrypt-cost", "11"})
	sb.expect(0, "Bcrypt cost set to 11", "")
	return sb
}

func TestBackupRestoreSnapshotRoundTripAndKeepsWhatItReads(t *testing.T) {
	sb := renderedSandbox(t)
	minimal := fixture(t, "store.minimal.yaml")
	// Thirty snapshots; the oldest is the one restored, so the pre-restore
	// snapshot makes thirty-one and retention must spare it.
	for i := 1; i <= 30; i++ {
		sb.mkSnapshot(fmt.Sprintf("20200101_000000_%03d", i), "# filler\n", "")
	}
	sb.mkSnapshot("20200101_000000_001", minimal, "")

	sb.run("n\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Cancelled.", "")
	if sb.read("state/store.yaml") == minimal {
		t.Fatal("declined restore changed the store")
	}

	out := sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	for _, want := range []string{"  Restoring snapshot: 20200101_000000_001\n", "Diff: current store and tacctl.yaml vs snapshot 20200101_000000_001"} {
		if !strings.Contains(plain(out), want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if sb.read("state/store.yaml") != minimal {
		t.Error("store is not the snapshot's")
	}
	if _, err := os.Stat(sb.path("state/tacctl.yaml")); !os.IsNotExist(err) {
		t.Error("a snapshot without tacctl.yaml must remove the live one")
	}
	if st, err := os.Stat(sb.path("state/store.yaml")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("store mode: %v %v", st, err)
	}
	if _, err := os.Stat(sb.path("state/backups/20200101_000000_001")); err != nil {
		t.Error("retention took the snapshot the restore read")
	}
	ids := (&invocation{app: newHarness(t, nil, sb.env...).app}).snapshotIDs()
	if len(ids) != 31 {
		t.Errorf("%d snapshots, want 31", len(ids))
	}
	if !sb.runner.Called("systemctl", "restart", "tacquito") {
		t.Errorf("no restart: %q", sb.runner.Argvs())
	}
	// The diff ran through diff -u with the snapshot's labels.
	if !sb.runner.Called("diff", "-u", "--label", "snapshot/20200101_000000_001/store.yaml", "--label", "current/store.yaml", "--color=always") {
		t.Errorf("diff call: %q", sb.runner.Argvs())
	}
	if l := sb.leftovers(".restore.*"); len(l) != 0 {
		t.Errorf("left behind: %q", l)
	}
}

// A writer that fails half way (the live store cannot be replaced) puts
// store.yaml and tacctl.yaml back; no artifact changed.
func TestBackupRestoreAWriterThatFailsPutsEveryFileBack(t *testing.T) {
	sb := renderedSandbox(t)
	sb.mkSnapshot("20250101_000000_000", fixture(t, "store.minimal.yaml"), "")
	if err := os.Mkdir(sb.path("state/store.yaml.tacctl-new"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := sb.liveState()
	sb.run("y\n", []string{"backup", "restore", "20250101_000000_000"})
	sb.expect(1, "", "Snapshot 20250101_000000_000 was not restored: ")
	sb.expect(1, "", "could not be rendered from it. Store, tacctl.yaml and ")
	if after := sb.liveState(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
	if l := sb.leftovers(".restore.*"); len(l) != 0 {
		t.Errorf("left behind: %q", l)
	}
}

func TestBackupRestoreRefusesBeforeTouchingAnything(t *testing.T) {
	sb := renderedSandbox(t)
	valid := fixture(t, "store.minimal.yaml")
	sb.mkSnapshot("20250101_000000_001", "users: [this is not a store\n", "")
	broken := strings.Replace(fixture(t, "store.multiscope.yaml"), "group: operator", "group: nosuchgroup", 1)
	if !strings.Contains(broken, "nosuchgroup") {
		t.Fatal("fixture changed")
	}
	sb.mkSnapshot("20250101_000000_002", broken, "")
	sb.mkSnapshot("20250101_000000_003", valid, "bcrypt:\n  cost: 99\n")
	sb.mkSnapshot("20250101_000000_004", valid, "backends:\n  enabled: [tacacs, radius]\n")
	if err := os.MkdirAll(sb.path("state/backups/20250101_000000_005"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := sb.liveState()
	cases := []struct{ id, err string }{
		{"20250101_000000_001", "its store.yaml is not valid. Nothing was changed."},
		{"20250101_000000_002", "tacctl store: "},
		{"20250101_000000_003", "  tacctl.yaml: bcrypt.cost: "},
		{"20250101_000000_004", "enables backend 'radius', which is not installed here. Run 'tacctl backend enable radius' first. Nothing was changed."},
		{"20250101_000000_005", "Snapshot 20250101_000000_005 has no store.yaml. Nothing was changed."},
	}
	for _, c := range cases {
		sb.run("y\n", []string{"backup", "restore", c.id})
		sb.expect(1, "", c.err)
	}
	if after := sb.liveState(); after != before {
		t.Errorf("state changed:\n%s\n%s", before, after)
	}
	if n := len((&invocation{app: newHarness(t, nil, sb.env...).app}).snapshotIDs()); n != 5 {
		t.Errorf("%d snapshots: a refused restore took one", n)
	}
}

func TestBackupRestoreArguments(t *testing.T) {
	sb := renderedSandbox(t)
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"backup", "restore"}, "Usage: tacctl backup restore <timestamp> [--legacy]"},
		{[]string{"backup", "restore", "a", "b"}, "Only one timestamp may be given."},
		{[]string{"backup", "restore", "a", "--frob"}, "Unknown option '--frob'. Usage: tacctl backup restore <timestamp> [--legacy]"},
		{[]string{"config", "restore", "19990101_000000"}, "Backup not found: 19990101_000000"},
		{[]string{"backup", "restore", "../store.yaml", "--legacy"}, "Old-style backup not found: ../store.yaml"},
		{[]string{"backup", "diff", "../store.yaml"}, "Backup not found: ../store.yaml"},
		{[]string{"backup", "diff"}, "No snapshots found."},
	} {
		sb.run("", c.args)
		sb.expect(1, "", c.err)
	}
	sb.write("state/backups/tacquito.yaml.20250101_000000", "# old\n", 0o600)
	sb.run("y\n", []string{"backup", "restore", "20250101_000000"})
	sb.expect(1, "", "20250101_000000 is an old-style backup. Restore it with: tacctl backup restore 20250101_000000 --legacy")
	sb.run("", []string{"backup"})
	sb.expect(1, "Usage: tacctl backup <subcommand> [arguments]", "")
}

func TestBackupListOrderSizesAndCompletionNames(t *testing.T) {
	sb := renderedSandbox(t)
	for _, id := range []string{"20260101_000000_000", "20260301_000000_000", "20260201_000000_000", "20260201_000000_000-10", "20260201_000000_000-9"} {
		sb.mkSnapshot(id, "x\n", "")
	}
	old := map[string]string{
		"state/backups/tacquito.yaml.20250101_000000":                  "2025-01-01T00:00:00Z",
		"state/backups/legacy/tacquito.yaml.pre-store.20250601_000000": "2025-06-01T00:00:00Z",
		"state/backups/legacy/tacquito.yaml.drift.20250301_000000":     "2025-03-01T00:00:00Z",
	}
	for rel, ts := range old {
		sb.write(rel, "a\n", 0o600)
		mt, _ := time.Parse(time.RFC3339, ts)
		if err := os.Chtimes(sb.path(rel), mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	sb.write("state/backups/notes.txt", "x\n", 0o600)
	sb.write("state/backups/legacy/tacctl.yaml.20250101-000000", "x\n", 0o600)
	if err := os.Symlink(sb.path("state/backups/20260101_000000_000"), sb.path("state/backups/20270101_000000_000")); err != nil {
		t.Fatal(err)
	}

	want := []string{"20260301_000000_000", "20260201_000000_000-10", "20260201_000000_000-9", "20260201_000000_000",
		"20260101_000000_000", "pre-store.20250601_000000", "drift.20250301_000000", "20250101_000000"}
	out := plain(sb.run("", []string{"backup", "list"}))
	sb.expect(0, "  TIMESTAMP", "")
	var got []string
	for _, l := range strings.Split(out, "\n") {
		if f := strings.Fields(l); len(f) == 3 && (f[1] == "snapshot" || f[1] == "old-style") {
			got = append(got, f[0])
			if f[2] == "" || f[2] == "0" {
				t.Errorf("no size: %q", l)
			}
		}
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("list order:\n got %q\nwant %q", got, want)
	}
	names := sb.run("", []string{"_completion-names", "backups"})
	if names != strings.Join(want, "\n")+"\n" {
		t.Errorf("completion names: %q", names)
	}
	for i := 0; i < 60; i++ {
		sb.mkSnapshot(fmt.Sprintf("20200101_000000_%03d", i), "x\n", "")
	}
	if n := strings.Count(sb.run("", []string{"_completion-names", "backups"}), "\n"); n != 50 {
		t.Errorf("%d completion names, want 50", n)
	}
}

func TestDuHumanIsDuDashH(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 512: "512", 1023: "1023", 1024: "1.0K", 4096: "4.0K",
		9 * 1024: "9.0K", 9*1024 + 1: "9.1K", 10 * 1024: "10K", 12 * 1024: "12K", 10*1024 + 1: "11K",
		1024 * 1024: "1.0M", 1024*1024 - 1: "1.0M", 10 * 1024 * 1024: "10M"} {
		if got := duHuman(n); got != want {
			t.Errorf("duHuman(%d) = %q, want %q", n, got, want)
		}
	}
	if duSH("/nonexistent/x") != "" {
		t.Error("du of a missing path must print nothing")
	}
}

// Without a store: the old-style file is copied back as it always was,
// after an old-style backup of the file it replaces; tacquito restarts.
func TestBackupRestoreWithoutAStoreCopiesTheOldFileBack(t *testing.T) {
	sb := newSandbox(t, false)
	sandboxRADIUS(sb)
	live := fixture(t, "tacquito.minimal.yaml")
	sb.write("etc/tacquito.yaml", live, 0o640)
	sb.write("state/backups/tacquito.yaml.20250101_000000", "# older config\n", 0o600)
	sb.mkSnapshot("20260101_000000_000", "x\n", "")
	// 30 old-style backups already: the one made now makes 31, the oldest goes.
	for i := 0; i < 30; i++ {
		rel := fmt.Sprintf("state/backups/tacquito.yaml.2000%04d_000000", i)
		sb.write(rel, "# filler\n", 0o600)
		mt := time.Date(2000, 1, 1, 0, 0, i, 0, time.UTC)
		_ = os.Chtimes(sb.path(rel), mt, mt)
	}

	sb.run("y\n", []string{"backup", "diff", "20260101_000000_000"})
	sb.expect(1, "", "Snapshot 20260101_000000_000 holds the store, which is not initialised here.")
	sb.run("y\n", []string{"backup", "restore", "20260101_000000_000"})
	sb.expect(1, "", "Snapshot 20260101_000000_000 holds the store, which is not initialised here.")

	sb.run("n\n", []string{"backup", "restore", "20250101_000000"})
	sb.expect(0, "Cancelled.", "")
	sb.run("y\n", []string{"backup", "restore", "20250101_000000", "--legacy"})
	sb.expect(0, "Config restored from backup 20250101_000000.", "")
	if sb.read("etc/tacquito.yaml") != "# older config\n" {
		t.Error("tacquito.yaml was not restored")
	}
	if st, _ := os.Stat(sb.path("etc/tacquito.yaml")); st.Mode().Perm() != 0o640 {
		t.Errorf("mode %v", st.Mode())
	}
	if !sb.runner.Called("systemctl", "restart", "tacquito") || !sb.runner.Called("diff", "--color=always") {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
	m, _ := filepath.Glob(sb.path("state/backups/tacquito.yaml.*"))
	kept := 0
	for _, f := range m {
		if data, _ := os.ReadFile(f); string(data) == live {
			kept++
		}
	}
	if len(m) != 30 || kept != 1 {
		t.Errorf("%d old-style files (want 30), %d holding the replaced config (want 1)", len(m), kept)
	}
	if _, err := os.Stat(sb.path("state/backups/tacquito.yaml.20000000_000000")); !os.IsNotExist(err) {
		t.Error("the oldest old-style file was not pruned")
	}
	if _, err := os.Stat(sb.path("state/store.yaml")); !os.IsNotExist(err) {
		t.Error("a store was created behind the importer's back")
	}
}

func TestBackupRestoreLegacyRunsTheImportCheckFirst(t *testing.T) {
	sb := renderedSandbox(t)
	sb.write("state/backups/tacquito.yaml.19990101_000000", fixture(t, "legacy.unrepresentable.yaml"), 0o600)
	before := sb.liveState()
	sb.run("y\n", []string{"backup", "restore", "19990101_000000", "--legacy"})
	sb.expect(1, "Checking that the store can take", "Old-style backup 19990101_000000 cannot be restored: the importer's check failed (see above). Nothing was changed.")
	sb.expect(1, "", "To import it anyway: 'tacctl store import --replace ")
	if sb.liveState() != before {
		t.Error("a refused legacy restore changed the state")
	}

	sb.write("state/backups/legacy/tacquito.yaml.pre-store.20250101_000000", fixture(t, "golden/tacquito.minimal.rendered.yaml"), 0o600)
	out := sb.run("y\n", []string{"backup", "restore", "--legacy", "pre-store.20250101_000000"})
	sb.expect(0, "Restored old-style backup pre-store.20250101_000000.", "")
	for _, want := range []string{"Check passed. Nothing was written.", "Restoring old-style backup: pre-store.20250101_000000"} {
		if !strings.Contains(plain(out), want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(out, "Store written to") {
		t.Error("the import's own report must not be shown")
	}
	if strings.Contains(sb.read("state/store.yaml"), "alice") {
		t.Error("store is not the old-style file's")
	}
}

func TestStoreShowAndImportArguments(t *testing.T) {
	sb := newSandbox(t, true)
	for _, c := range []struct {
		args        []string
		code        int
		stdout, err string
	}{
		{[]string{"store", "show", "--bogus"}, 2, "", "Usage: tacctl store show [--json]"},
		{[]string{"store", "import", "--bogus"}, 2, "", "Unknown option '--bogus'. Usage: tacctl store import [--check|--force] [--replace] [<file>]"},
		{[]string{"store", "import", "-"}, 2, "", "Unknown option '-'."},
		{[]string{"store", "import", "a", "b"}, 2, "", "Only one file may be given."},
		{[]string{"store", "import", "/nonexistent"}, 1, "", "Cannot import: /nonexistent not found."},
		{[]string{"store"}, 0, "show [--json]", ""},
		{[]string{"store", "-h"}, 0, "import [--check|--force] [--replace] [<file>]", ""},
		{[]string{"store", "frobnicate"}, 1, "rollback", "Unknown store subcommand 'frobnicate'."},
		{[]string{"store", "show", "--json", "ignored"}, 0, `"version": 1`, ""},
	} {
		sb.run("", c.args)
		sb.expect(c.code, c.stdout, c.err)
	}
	// No preflight: with neither file 'store show' is model_load's error.
	sb = newSandbox(t, false)
	sb.run("", []string{"store", "show"})
	sb.expect(1, "", "No store at ")
	if strings.Contains(sb.err.String(), "Config not found") {
		t.Error("store ran preflight")
	}
	// 'store rollback' is native too (WP3.3a), and also runs no preflight.
	sb.run("", []string{"store", "rollback"})
	sb.expect(1, "", "There is no store at ")
}

// devices.yaml (0.2.1) rides along: a snapshot that holds one brings it
// back, one that does not (a 0.2.0 snapshot) leaves the live registry
// alone, and 'backup diff' names it only when either side has one.
func TestBackupDiffAndRestoreHandleDevicesYAML(t *testing.T) {
	sb := renderedSandbox(t)
	minimal := fixture(t, "store.minimal.yaml")
	sb.mkSnapshot("20200101_000000_001", minimal, "")
	sb.mkSnapshot("20200101_000000_002", minimal, "")
	sb.write("state/backups/20200101_000000_002/devices.yaml", "version: 1\ndevices:\n  a: {}\n", 0o600)

	// No registry anywhere: the diff does not mention it.
	out := sb.run("", []string{"backup", "diff", "20200101_000000_001"})
	if strings.Contains(plain(out), "devices.yaml") {
		t.Errorf("diff names devices.yaml with none on either side:\n%s", out)
	}
	// A snapshot without one leaves the live registry alone.
	sb.write("state/devices.yaml", "version: 1\ndevices:\n  live: {}\n", 0o600)
	out = sb.run("", []string{"backup", "diff", "20200101_000000_001"})
	if !strings.Contains(plain(out), "devices.yaml") {
		t.Errorf("diff does not name the live devices.yaml:\n%s", out)
	}
	sb.run("y\n", []string{"backup", "restore", "20200101_000000_001"})
	sb.expect(0, "Restored snapshot 20200101_000000_001.", "")
	if got := sb.read("state/devices.yaml"); !strings.Contains(got, "live") {
		t.Errorf("a snapshot without devices.yaml changed the registry: %q", got)
	}
	// A snapshot with one replaces it, 0600.
	sb.run("y\n", []string{"backup", "restore", "20200101_000000_002"})
	sb.expect(0, "Restored snapshot 20200101_000000_002.", "")
	if got := sb.read("state/devices.yaml"); !strings.Contains(got, "  a: {}") {
		t.Errorf("devices.yaml not restored: %q", got)
	}
	if st, err := os.Stat(sb.path("state/devices.yaml")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("devices.yaml mode: %v %v", st, err)
	}
}
