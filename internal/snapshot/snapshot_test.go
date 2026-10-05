package snapshot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// Ported from tests/integration/backup.bats, the snapshot and retention
// tests (lines 78-260 and the backup_snapshot part of 349-356). What a
// mutation around the snapshot does (refusal, one snapshot per command) is
// tested with StoreApply in internal/backend; listing, diffing and
// restoring are the 'backup' command's (WP2.4d).

type env struct {
	t      *testing.T
	state  string
	s      *Snapshotter
	stdout *bytes.Buffer
}

func newEnv(t *testing.T) *env {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	p := paths.Resolve(paths.NewEnv([]string{"TACCTL_STATE_DIR=" + state}), "", func(string) bool { return false })
	e := &env{t: t, state: state, stdout: &bytes.Buffer{}}
	e.s = New(p, "0.2.0-test", nil, ui.Output{Stdout: e.stdout, Stderr: e.stdout})
	e.s.Chown = nil
	e.write("store.yaml", "version: 1\n")
	return e
}

func (e *env) write(name, text string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.state, name), []byte(text), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) appendTo(name, text string) {
	e.t.Helper()
	f, err := os.OpenFile(filepath.Join(e.state, name), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = f.WriteString(text)
	_ = f.Close()
}

func (e *env) backups() string { return filepath.Join(e.state, "backups") }

// take is Take that must succeed.
func (e *env) take() string {
	e.t.Helper()
	id, err := e.s.Take()
	if err != nil {
		e.t.Fatalf("Take: %v", err)
	}
	return id
}

// snapshots is the snapshot ids, oldest first (the bats helper).
func (e *env) snapshots() []string {
	ids := IDs(e.backups())
	slices.Reverse(ids)
	return ids
}

// mkSnapshot is the bats mk_snapshot: a snapshot directory made by hand.
func (e *env) mkSnapshot(id, store string) {
	e.t.Helper()
	d := filepath.Join(e.backups(), id)
	if err := os.MkdirAll(d, 0o700); err != nil {
		e.t.Fatal(err)
	}
	if store == "" {
		store = "# hand-made snapshot " + id
	}
	if err := os.WriteFile(filepath.Join(d, "store.yaml"), []byte(store+"\n"), 0o600); err != nil {
		e.t.Fatal(err)
	}
}

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func TestSnapshotHoldsStoreTacctlYAMLAndManifestRootOnly(t *testing.T) {
	e := newEnv(t)
	e.write("tacctl.yaml", "bcrypt:\n  cost: 11\n")
	id := e.take()
	if id == "" {
		t.Fatal("no snapshot taken")
	}
	snap := filepath.Join(e.backups(), id)
	if m := mode(t, snap); m != 0o700 {
		t.Fatalf("snapshot dir mode %v", m)
	}
	for _, f := range []string{"store.yaml", "tacctl.yaml", "manifest"} {
		if m := mode(t, filepath.Join(snap, f)); m != 0o600 {
			t.Fatalf("%s mode %v", f, m)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(snap, "tacctl.yaml")); !strings.Contains(string(got), "11") {
		t.Fatalf("tacctl.yaml %q", got)
	}
	if got, _ := os.ReadFile(filepath.Join(snap, "store.yaml")); string(got) != "version: 1\n" {
		t.Fatalf("store.yaml %q", got)
	}
	if want := "\033[0;32m[INFO]\033[0m Config snapshot saved to " + snap + "\n"; e.stdout.String() != want {
		t.Fatalf("output %q", e.stdout)
	}
	// The backups directory it created is 0750.
	if m := mode(t, e.backups()); m != 0o750 {
		t.Fatalf("backups dir mode %v", m)
	}
}

func TestSnapshotManifestCarriesVersionAndRenderedOfThatMoment(t *testing.T) {
	e := newEnv(t)
	first := e.take()
	e.write("rendered.json", "{\n  \"/etc/tacquito/tacquito.yaml\": \"abc\"\n}\n")
	e.appendTo("store.yaml", "# changed\n")
	second := e.take()
	var m struct {
		Version  string            `json:"tacctl_version"`
		Created  string            `json:"created"`
		Rendered map[string]string `json:"rendered"`
	}
	data, _ := os.ReadFile(filepath.Join(e.backups(), second, "manifest"))
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.2.0-test" || m.Created == "" || m.Rendered["/etc/tacquito/tacquito.yaml"] != "abc" {
		t.Fatalf("manifest %s", data)
	}
	// The snapshot before the very first render records none.
	data, _ = os.ReadFile(filepath.Join(e.backups(), first, "manifest"))
	if !strings.Contains(string(data), "\"rendered\": {},") {
		t.Fatalf("first manifest %s", data)
	}
}

func TestSnapshotWithoutTacctlYAMLHasNone(t *testing.T) {
	e := newEnv(t)
	id := e.take()
	if _, err := os.Lstat(filepath.Join(e.backups(), id, "tacctl.yaml")); err == nil {
		t.Fatal("tacctl.yaml in the snapshot")
	}
	if _, err := os.Stat(filepath.Join(e.backups(), id, "manifest")); err != nil {
		t.Fatal(err)
	}
}

func TestSnapshotWithoutStoreTakesNothing(t *testing.T) {
	e := newEnv(t)
	_ = os.Remove(filepath.Join(e.state, "store.yaml"))
	if id := e.take(); id != "" {
		t.Fatalf("took %s", id)
	}
	if _, err := os.Stat(e.backups()); err == nil {
		t.Fatal("backups dir created")
	}
}

func TestSnapshotThatCannotBeMadeIsAnErrorAndLeavesNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permissions do not bind root")
	}
	e := newEnv(t)
	if err := os.MkdirAll(e.backups(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(e.backups(), 0o500); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(e.backups(), 0o700) }()
	_, err := e.s.Take()
	if err == nil || err.Error() != "Cannot create a snapshot in "+e.backups()+"." {
		t.Fatalf("got %v", err)
	}
	if e.stdout.Len() != 0 {
		t.Fatalf("printed %q", e.stdout)
	}
}

func TestSnapshotFaultLeavesNoStrayTemporaryDirectory(t *testing.T) {
	e := newEnv(t)
	e.s.Fault = func(p string) error {
		if p == FaultTake {
			return errors.New("injected")
		}
		return nil
	}
	_, err := e.s.Take()
	if err == nil || err.Error() != "Cannot write a snapshot in "+e.backups()+"." {
		t.Fatalf("got %v", err)
	}
	entries, _ := os.ReadDir(e.backups())
	if len(entries) != 0 {
		t.Fatalf("left %v", entries)
	}
}

func TestSnapshotNamesTakenGetANumericSuffix(t *testing.T) {
	e := newEnv(t)
	e.s.Now = fixedClock(time.Date(1999, 1, 1, 0, 0, 0, 0, time.Local))
	var ids []string
	for i := range 3 {
		e.appendTo("store.yaml", strings.Repeat("#", i+1)+"\n")
		ids = append(ids, e.take())
	}
	want := []string{"19990101_000000_000", "19990101_000000_000-1", "19990101_000000_000-2"}
	if !slices.Equal(ids, want) || !slices.Equal(e.snapshots(), want) {
		t.Fatalf("ids %v, on disk %v", ids, e.snapshots())
	}
	// Three distinct pre-change states, so three distinct contents.
	a, _ := os.ReadFile(filepath.Join(e.backups(), want[0], "store.yaml"))
	b, _ := os.ReadFile(filepath.Join(e.backups(), want[1], "store.yaml"))
	if bytes.Equal(a, b) {
		t.Fatal("same content")
	}
}

func TestSnapshotIDIsLocalTimeWithTruncatedMilliseconds(t *testing.T) {
	e := newEnv(t)
	e.s.Now = fixedClock(time.Date(2026, 10, 3, 14, 5, 6, 789_999_999, time.Local))
	if id := e.take(); id != "20261003_140506_789" {
		t.Fatalf("id %s", id)
	}
	data, _ := os.ReadFile(filepath.Join(e.backups(), "20261003_140506_789", "manifest"))
	want := time.Date(2026, 10, 3, 14, 5, 6, 0, time.Local).UTC().Format("2006-01-02T15:04:05Z")
	if !strings.Contains(string(data), `"created": "`+want+`"`) {
		t.Fatalf("manifest %s", data)
	}
}

func TestSnapshotsInQuickSuccessionEachGetTheirOwn(t *testing.T) {
	e := newEnv(t)
	for i := range 3 {
		e.appendTo("store.yaml", strings.Repeat("#", i+1)+"\n")
		e.take()
	}
	ids := e.snapshots()
	if len(ids) != 3 || len(slices.Compact(slices.Clone(ids))) != 3 {
		t.Fatalf("ids %v", ids)
	}
}

func TestSnapshotNothingIsAddedWhileTheFilesEqualTheNewest(t *testing.T) {
	e := newEnv(t)
	for range 3 {
		e.take()
	}
	if n := len(e.snapshots()); n != 1 {
		t.Fatalf("%d snapshots", n)
	}
	// A change to either canonical file makes the next one real.
	e.appendTo("store.yaml", "# note\n")
	e.take()
	if n := len(e.snapshots()); n != 2 {
		t.Fatalf("%d snapshots", n)
	}
	e.write("tacctl.yaml", "bcrypt:\n  cost: 11\n")
	e.take()
	if n := len(e.snapshots()); n != 3 {
		t.Fatalf("%d snapshots", n)
	}
	if id := e.take(); id != "" || len(e.snapshots()) != 3 {
		t.Fatalf("took %q", id)
	}
	// tacctl.yaml removed again: the newest has one, so a new one is taken.
	_ = os.Remove(filepath.Join(e.state, "tacctl.yaml"))
	e.take()
	if n := len(e.snapshots()); n != 4 {
		t.Fatalf("%d snapshots", n)
	}
}

func TestSnapshotHoldSuppressesTakeUntilReleased(t *testing.T) {
	e := newEnv(t)
	release := e.s.Hold()
	inner := e.s.Hold()
	if id := e.take(); id != "" {
		t.Fatalf("took %s while held", id)
	}
	if err := e.s.Hook(); err != nil || !e.s.Held() {
		t.Fatal(err)
	}
	inner()
	inner() // a second release of one hold is a no-op
	if !e.s.Held() {
		t.Fatal("released by the inner hold")
	}
	release()
	if e.s.Held() {
		t.Fatal("still held")
	}
	if err := e.s.Hook(); err != nil || len(e.snapshots()) != 1 {
		t.Fatalf("%v %v", err, e.snapshots())
	}
}

func TestRetentionKeepsTheNewest30AndNothingElseIsTouched(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 35; i++ {
		e.mkSnapshot("20200101_000000_0"+twoDigits(i), "")
	}
	keepDirs := []string{"legacy", "disabled", "password-dates", "20200101_000000_000.keep"}
	for _, d := range keepDirs {
		if err := os.MkdirAll(filepath.Join(e.backups(), d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	files := []string{
		"legacy/tacquito.yaml.pre-store.20250101_000000",
		"legacy/tacquito.yaml.drift.20250101_000001",
		"tacquito.yaml.20250101_000002",
		"disabled/bob.hash",
		"password-dates/alice.date",
		"notes.txt",
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(e.backups(), f), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	e.s.Now = fixedClock(time.Date(2026, 10, 3, 1, 2, 3, 0, time.Local))
	newID := e.take()
	ids := e.snapshots()
	if len(ids) != 30 || ids[len(ids)-1] != newID {
		t.Fatalf("ids %v", ids)
	}
	for i := 1; i <= 6; i++ {
		if _, err := os.Stat(filepath.Join(e.backups(), "20200101_000000_0"+twoDigits(i))); err == nil {
			t.Fatalf("snapshot %d kept", i)
		}
	}
	for _, i := range []int{7, 35} {
		if _, err := os.Stat(filepath.Join(e.backups(), "20200101_000000_0"+twoDigits(i))); err != nil {
			t.Fatalf("snapshot %d removed", i)
		}
	}
	for _, f := range append(keepDirs, files...) {
		if _, err := os.Stat(filepath.Join(e.backups(), f)); err != nil {
			t.Fatalf("%s touched: %v", f, err)
		}
	}
}

func TestRetentionNeverDeletesTheSnapshotJustTakenEvenWhenTheClockRanBackwards(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 35; i++ {
		e.mkSnapshot("20300101_000000_0"+twoDigits(i), "")
	}
	// A name older than every existing one.
	e.s.Now = fixedClock(time.Date(1999, 1, 1, 0, 0, 0, 0, time.Local))
	if id := e.take(); id != "19990101_000000_000" {
		t.Fatalf("id %s", id)
	}
	if _, err := os.Stat(filepath.Join(e.backups(), "19990101_000000_000", "store.yaml")); err != nil {
		t.Fatal(err)
	}
	// 36 snapshots -> 30: six removed, none of them the new one.
	if n := len(e.snapshots()); n != 30 {
		t.Fatalf("%d snapshots", n)
	}
}

func TestRetentionNeverDeletesTheSnapshotARestoreReadsFrom(t *testing.T) {
	e := newEnv(t)
	for i := 1; i <= 30; i++ {
		e.mkSnapshot("20200101_000000_0"+twoDigits(i), "")
	}
	e.s.KeepID = "20200101_000000_001"
	e.take()
	if _, err := os.Stat(filepath.Join(e.backups(), e.s.KeepID)); err != nil {
		t.Fatal("the restore's snapshot was removed")
	}
	if n := len(e.snapshots()); n != 31 {
		t.Fatalf("%d snapshots", n)
	}
}

func TestIDsAreSnapshotDirectoriesOnlyNewestFirst(t *testing.T) {
	e := newEnv(t)
	for _, id := range []string{
		"20260101_000000_000", "20260101_000000_000-2", "20260101_000000_000-10",
		"20260101_000000", "20251231_235959_999", "20260101_000000_001",
	} {
		e.mkSnapshot(id, "")
	}
	_ = os.WriteFile(filepath.Join(e.backups(), "20270101_000000_000"), nil, 0o600) // a file
	_ = os.Symlink(filepath.Join(e.backups(), "20260101_000000_001"), filepath.Join(e.backups(), "20280101_000000_000"))
	_ = os.MkdirAll(filepath.Join(e.backups(), "legacy"), 0o700)
	got := IDs(e.backups())
	want := []string{
		"20260101_000000_001", "20260101_000000_000-10", "20260101_000000_000-2",
		"20260101_000000_000", "20260101_000000", "20251231_235959_999",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
	if IDs(filepath.Join(e.state, "nope")) != nil {
		t.Fatal("ids of a missing dir")
	}
}

func TestValidIDAndCompare(t *testing.T) {
	for id, ok := range map[string]bool{
		"20260101_000000_000": true, "20260101_000000": true, "20260101_000000_000-3": true,
		"20260101_000000-3": true, "2026010_000000": false, "20260101_000000_00": false,
		"20260101_000000_000.keep": false, "legacy": false, "20260101_000000_000-": false,
	} {
		if ValidID(id) != ok {
			t.Errorf("ValidID(%q) = %v", id, !ok)
		}
	}
	if Compare("a", "a") != 0 || Compare("20260101_000000_000-2", "20260101_000000_000-10") != -1 ||
		Compare("20260101_000000_001", "20260101_000000_000-10") != 1 {
		t.Error("Compare")
	}
}

func TestManifestMatchesPythonJSONDumps(t *testing.T) {
	// Expected texts: the manifest program of lib/service.sh (0.1.16) run
	// by python3 with created fixed to 2026-10-03T12:00:00Z.
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	cases := []struct{ name, content, want string }{
		{"mapping", "{\n  \"/etc/b\": \"x\",\n  \"/etc/a\": \"y\\u00fc\"\n}\n",
			"{\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": {\n    \"/etc/a\": \"y\\u00fc\",\n    \"/etc/b\": \"x\"\n  },\n  \"tacctl_version\": \"v1\"\n}\n"},
		{"nested", `[1, 2.5, {"z": null, "a": [true]}, [], {}]`,
			"{\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": [\n    1,\n    2.5,\n    {\n      \"a\": [\n        true\n      ],\n      \"z\": null\n    },\n    [],\n    {}\n  ],\n  \"tacctl_version\": \"v1\"\n}\n"},
		{"not JSON", "nope",
			"{\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": null,\n  \"tacctl_version\": \"v1\"\n}\n"},
		{"absent", "",
			"{\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": {},\n  \"tacctl_version\": \"v1\"\n}\n"},
		{"not UTF-8", "{\"a\": \"\xff\"}",
			"{\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": null,\n  \"tacctl_version\": \"v1\"\n}\n"},
	}
	for _, c := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_")+".json")
		if c.name != "absent" {
			if err := os.WriteFile(p, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if got := string(Manifest(p, "v1", now)); got != c.want {
			t.Errorf("%s:\ngot  %q\nwant %q", c.name, got, c.want)
		}
	}
	// A directory where the file should be is an OSError: null.
	if got := string(Manifest(dir, "v1", now)); !strings.Contains(got, `"rendered": null`) {
		t.Errorf("directory: %q", got)
	}
}

func TestNewTakesThePathsAndVersion(t *testing.T) {
	p := paths.Resolve(paths.NewEnv([]string{"TACCTL_STATE_DIR=/x"}), "", func(string) bool { return false })
	s := New(p, "", nil, ui.Output{})
	if s.StoreFile != "/x/store.yaml" || s.Overrides != "/x/tacctl.yaml" || s.Rendered != "/x/rendered.json" ||
		s.BackupDir != "/x/backups" || s.Chown == nil {
		t.Fatalf("%+v", s)
	}
	// No version: the manifest says "unknown", as get_version does.
	e := newEnv(t)
	e.s.Version = ""
	id := e.take()
	data, _ := os.ReadFile(filepath.Join(e.backups(), id, "manifest"))
	if !strings.Contains(string(data), `"tacctl_version": "unknown"`) {
		t.Fatalf("manifest %s", data)
	}
	chownTacquito(filepath.Join(e.backups(), id)) // best effort: no error to see
}

func twoDigits(i int) string { return fmt.Sprintf("%02d", i) }

func TestSnapshotHoldsDevicesYAMLWhenItExists(t *testing.T) {
	e := newEnv(t)
	// Absent: nothing to do, no file in the snapshot.
	first := e.take()
	if _, err := os.Lstat(filepath.Join(e.backups(), first, "devices.yaml")); err == nil {
		t.Fatal("devices.yaml in a snapshot taken without one")
	}
	e.write("devices.yaml", "version: 1\ndevices: {}\n")
	second := e.take()
	if second == "" {
		t.Fatal("a new devices.yaml did not make a snapshot")
	}
	snap := filepath.Join(e.backups(), second, "devices.yaml")
	if m := mode(t, snap); m != 0o600 {
		t.Fatalf("devices.yaml mode %v", m)
	}
	if got, _ := os.ReadFile(snap); string(got) != "version: 1\ndevices: {}\n" {
		t.Fatalf("devices.yaml %q", got)
	}
	// Equal to the newest: nothing new; changed or removed: a new one.
	if id := e.take(); id != "" {
		t.Fatalf("took %q", id)
	}
	e.appendTo("devices.yaml", "# note\n")
	if id := e.take(); id == "" {
		t.Fatal("a changed devices.yaml made no snapshot")
	}
	_ = os.Remove(filepath.Join(e.state, "devices.yaml"))
	if id := e.take(); id == "" {
		t.Fatal("a removed devices.yaml made no snapshot")
	}
}

func TestSnapshotHoldsConsoleYAMLWhenItExists(t *testing.T) {
	e := newEnv(t)
	first := e.take()
	if _, err := os.Lstat(filepath.Join(e.backups(), first, "console.yaml")); err == nil {
		t.Fatal("console.yaml in a snapshot taken without one")
	}
	e.write("console.yaml", "version: 1\n")
	second := e.take()
	if second == "" {
		t.Fatal("a new console.yaml did not make a snapshot")
	}
	snap := filepath.Join(e.backups(), second, "console.yaml")
	if m := mode(t, snap); m != 0o600 {
		t.Fatalf("console.yaml mode %v", m)
	}
	if got, _ := os.ReadFile(snap); string(got) != "version: 1\n" {
		t.Fatalf("console.yaml %q", got)
	}
	if id := e.take(); id != "" {
		t.Fatalf("took %q", id)
	}
	e.appendTo("console.yaml", "# note\n")
	if id := e.take(); id == "" {
		t.Fatal("a changed console.yaml made no snapshot")
	}
	_ = os.Remove(filepath.Join(e.state, "console.yaml"))
	if id := e.take(); id == "" {
		t.Fatal("a removed console.yaml made no snapshot")
	}
}
