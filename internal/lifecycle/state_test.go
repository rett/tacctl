package lifecycle_test

// tests/integration/state_migrate.bats: StateMigrate moves tacctl-owned
// state from TACCTL_ETC into TACCTL_STATE_DIR and leaves symlinks at the
// old paths. It runs on every install and upgrade, so it must be
// idempotent, and it must heal the rollback case where older code replaced
// a symlink with a regular file.

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

type senv struct {
	t        *testing.T
	w        string
	etc      string
	state    string
	config   string
	out, err bytes.Buffer
	now      time.Time
}

// newSenv: the harness pre-creates the state dir; these tests start
// without it.
func newSenv(t *testing.T) *senv {
	t.Helper()
	w := t.TempDir()
	s := &senv{t: t, w: w, etc: filepath.Join(w, "etc"), state: filepath.Join(w, "state"),
		now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)}
	s.config = filepath.Join(s.etc, "tacquito.yaml")
	if err := os.MkdirAll(s.etc, 0o700); err != nil {
		t.Fatal(err)
	}
	return s
}

// migrate is state_migrate; the output is what it printed (colours removed).
func (s *senv) migrate() (string, error) {
	s.out.Reset()
	s.err.Reset()
	err := lifecycle.StateMigrate(lifecycle.StateOptions{
		Etc: s.etc, StateDir: s.state, Out: ui.Output{Stdout: &s.out, Stderr: &s.err},
		// A clock that moves, as date does between runs.
		Now: func() time.Time { s.now = s.now.Add(time.Second); return s.now },
	})
	return plain(s.out.String() + s.err.String()), err
}

func (s *senv) mustMigrate() string {
	s.t.Helper()
	out, err := s.migrate()
	if err != nil {
		s.t.Fatalf("state migrate: %v\n%s", err, out)
	}
	return out
}

func (s *senv) write(path, text string) {
	s.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		s.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		s.t.Fatal(err)
	}
}

func (s *senv) read(path string) string {
	s.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		s.t.Fatal(err)
	}
	return string(data)
}

func (s *senv) ago(path string, d time.Duration) {
	s.t.Helper()
	at := time.Now().Add(-d)
	if err := os.Chtimes(path, at, at); err != nil {
		s.t.Fatal(err)
	}
}

// seedLegacy lays down state the way a pre-state-dir release left it.
func (s *senv) seedLegacy() {
	s.write(filepath.Join(s.etc, "tacctl.yaml"), "bcrypt:\n  cost: 10\n")
	s.write(filepath.Join(s.etc, "linux-hosts"), "host1|10.0.0.1|22|lab\n")
	s.write(filepath.Join(s.etc, "linux-uids"), "alice:20000\n")
	s.write(filepath.Join(s.etc, "backups", "tacquito.yaml.20250101-000000"), "old snapshot\n")
	s.write(filepath.Join(s.etc, "backups", "password-dates", "alice.date"), "2025-01-01\n")
	s.write(filepath.Join(s.etc, "backups", "disabled", "bob.hash"), "hash\n")
	s.write(filepath.Join(s.etc, "templates", "cisco.template"), "custom cisco\n")
	s.write(s.config, "daemon config\n")
}

// treeState fingerprints both trees: path, type, mtime, symlink target.
func (s *senv) treeState() string {
	var lines []string
	for _, root := range []string{s.etc, s.state} {
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			target, _ := os.Readlink(p)
			lines = append(lines, fmt.Sprintf("%s %v %d %s", p, fi.Mode().Type(), fi.ModTime().UnixNano(), target))
			return nil
		})
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// pointsIntoState: <etc>/<name> is a symlink to the state-dir copy.
func (s *senv) pointsIntoState(name string) {
	s.t.Helper()
	target, err := os.Readlink(filepath.Join(s.etc, name))
	if err != nil || target != filepath.Join(s.state, name) {
		s.t.Errorf("%s: link %q (%v), want %s", name, target, err, filepath.Join(s.state, name))
	}
}

func (s *senv) links(dir string) []string {
	var out []string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			out = append(out, p)
		}
		return nil
	})
	return out
}

func (s *senv) legacyWith(namePrefix, content string) []string {
	m, _ := filepath.Glob(filepath.Join(s.state, "backups", "legacy", namePrefix+"*"))
	var out []string
	for _, f := range m {
		if data, err := os.ReadFile(f); err == nil && (content == "" || string(data) == content) {
			out = append(out, f)
		}
	}
	return out
}

func permOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// --- paths ---

func TestStatePathsLiveInTheStateDirTheDaemonConfigStays(t *testing.T) {
	p := paths.Resolve(paths.NewEnv([]string{"TACCTL_ETC=/e", "TACCTL_STATE_DIR=/s"}), "", nil)
	for got, want := range map[string]string{
		p.Overrides: "/s/tacctl.yaml", p.LinuxUIDs: "/s/linux-uids", p.LinuxHosts: "/s/linux-hosts",
		p.BackupDir: "/s/backups", p.PWDatesDir: "/s/backups/password-dates", p.Templates: "/s/templates",
		p.Config: "/e/tacquito.yaml",
	} {
		if got != want {
			t.Errorf("%s, want %s", got, want)
		}
	}
	o := lifecycle.StateOptionsFrom(p, ui.Output{}, nil, false)
	if o.Etc != "/e" || o.StateDir != "/s" {
		t.Error(o)
	}
	if d := paths.Resolve(paths.NewEnv(nil), "", nil); d.StateDir != "/etc/tacctl" {
		t.Errorf("default state dir %s", d.StateDir)
	}
}

// --- fresh system ---

func TestStateFreshSystemCreatesA0700StateDirAndLinksNothing(t *testing.T) {
	s := newSenv(t)
	if out := s.mustMigrate(); out != "" {
		t.Errorf("output %q", out)
	}
	if permOf(t, s.state) != 0o700 {
		t.Error("state dir mode")
	}
	if l := s.links(s.etc); len(l) != 0 {
		t.Error(l)
	}
}

func TestStateFreshSystemAMissingOldDirectoryIsNotCreated(t *testing.T) {
	s := newSenv(t)
	_ = os.RemoveAll(s.etc)
	s.mustMigrate()
	if exists(s.etc) || !exists(s.state) {
		t.Error("directories")
	}
}

func TestStateFreshSystemTightensALooseStateDir(t *testing.T) {
	s := newSenv(t)
	if err := os.MkdirAll(s.state, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(s.state, 0o755)
	s.mustMigrate()
	if permOf(t, s.state) != 0o700 {
		t.Error("state dir mode")
	}
}

// --- existing system ---

func TestStateLegacySystemEveryItemMovesAndTheOldPathBecomesASymlink(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	out := s.mustMigrate()
	for _, item := range lifecycle.StateItems {
		s.pointsIntoState(item)
		if st, err := os.Lstat(filepath.Join(s.state, item)); err != nil || st.Mode()&os.ModeSymlink != 0 {
			t.Errorf("%s in the state dir: %v", item, err)
		}
		has(t, out, "[INFO] State migrated: "+filepath.Join(s.etc, item)+" -> "+filepath.Join(s.state, item))
	}
	if s.read(filepath.Join(s.state, "tacctl.yaml")) != "bcrypt:\n  cost: 10\n" ||
		s.read(filepath.Join(s.state, "linux-uids")) != "alice:20000\n" {
		t.Error("content")
	}
	for _, f := range []string{"backups/tacquito.yaml.20250101-000000", "backups/password-dates/alice.date",
		"backups/disabled/bob.hash", "templates/cisco.template"} {
		if !exists(filepath.Join(s.state, f)) {
			t.Error(f)
		}
	}
	if permOf(t, s.state) != 0o700 {
		t.Error("mode")
	}
}

func TestStateLegacySystemTheDaemonConfigAndUnknownFilesStay(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.write(filepath.Join(s.etc, "README.md"), "readme\n")
	s.mustMigrate()
	for _, f := range []string{s.config, filepath.Join(s.etc, "README.md")} {
		if st, err := os.Lstat(f); err != nil || !st.Mode().IsRegular() {
			t.Error(f)
		}
	}
	if exists(filepath.Join(s.state, "tacquito.yaml")) || exists(filepath.Join(s.state, "README.md")) {
		t.Error("moved")
	}
}

func TestStateLegacySystemTheOldPathsStillReadThrough(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	if s.read(filepath.Join(s.etc, "linux-hosts")) != "host1|10.0.0.1|22|lab\n" ||
		!exists(filepath.Join(s.etc, "backups", "password-dates", "alice.date")) ||
		!exists(filepath.Join(s.etc, "templates", "cisco.template")) {
		t.Error("read-through")
	}
}

func TestStateLegacySystemOnlyTheItemsPresentMove(t *testing.T) {
	s := newSenv(t)
	s.write(filepath.Join(s.etc, "tacctl.yaml"), "bcrypt:\n  cost: 10\n")
	s.mustMigrate()
	s.pointsIntoState("tacctl.yaml")
	if exists(filepath.Join(s.etc, "linux-hosts")) || exists(filepath.Join(s.state, "linux-hosts")) {
		t.Error("linux-hosts")
	}
}

// --- idempotence ---

func TestStateIdempotentASecondRunChangesAndPrintsNothing(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	before := s.treeState()
	if out := s.mustMigrate(); out != "" {
		t.Errorf("output %q", out)
	}
	if s.treeState() != before {
		t.Error("tree changed")
	}
}

func TestStateIdempotentAFreshSystemRunTwiceIsStable(t *testing.T) {
	s := newSenv(t)
	s.mustMigrate()
	before := s.treeState()
	if out := s.mustMigrate(); out != "" || s.treeState() != before {
		t.Errorf("output %q or tree changed", out)
	}
}

// --- half-migrated ---

func TestStateHalfMigratedItemsGetTheirLinkBack(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	_ = os.MkdirAll(s.state, 0o700)
	for _, it := range []string{"tacctl.yaml", "backups"} {
		if err := os.Rename(filepath.Join(s.etc, it), filepath.Join(s.state, it)); err != nil {
			t.Fatal(err)
		}
	}
	s.mustMigrate()
	for _, item := range lifecycle.StateItems {
		s.pointsIntoState(item)
	}
	if s.read(filepath.Join(s.state, "tacctl.yaml")) != "bcrypt:\n  cost: 10\n" ||
		!exists(filepath.Join(s.state, "backups", "tacquito.yaml.20250101-000000")) {
		t.Error("content")
	}
	// Nothing was displaced, so no legacy backup was made.
	if exists(filepath.Join(s.state, "backups", "legacy")) {
		t.Error("legacy dir made")
	}
}

func TestStateHalfMigratedConvergesToTheCleanState(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	_ = os.MkdirAll(s.state, 0o700)
	if err := os.Rename(filepath.Join(s.etc, "linux-uids"), filepath.Join(s.state, "linux-uids")); err != nil {
		t.Fatal(err)
	}
	s.mustMigrate()
	before := s.treeState()
	if out := s.mustMigrate(); out != "" || s.treeState() != before {
		t.Errorf("output %q or tree changed", out)
	}
}

func TestStateHalfMigratedOldDataIsMergedIntoAnExistingStateDir(t *testing.T) {
	s := newSenv(t)
	s.write(filepath.Join(s.etc, "backups", "tacquito.yaml.1"), "a\n")
	s.write(filepath.Join(s.state, "backups", "tacquito.yaml.2"), "b\n")
	old := filepath.Join(s.etc, "backups", "password-dates", "alice.date")
	s.write(old, "old\n")
	s.ago(old, 2*time.Hour)
	s.write(filepath.Join(s.state, "backups", "password-dates", "alice.date"), "new\n")
	s.mustMigrate()
	s.pointsIntoState("backups")
	if !exists(filepath.Join(s.state, "backups", "tacquito.yaml.1")) || !exists(filepath.Join(s.state, "backups", "tacquito.yaml.2")) {
		t.Error("merge")
	}
	// The newer file won; the other is kept in legacy/.
	if s.read(filepath.Join(s.state, "backups", "password-dates", "alice.date")) != "new\n" {
		t.Error("newer lost")
	}
	if len(s.legacyWith("backups_password-dates_alice.date.", "old\n")) != 1 {
		t.Error("displaced copy missing")
	}
}

// --- regressed after rollback ---

func TestStateRollbackWritingThroughTheSymlinkLeavesItAlone(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	f, err := os.OpenFile(filepath.Join(s.etc, "linux-hosts"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("host2|10.0.0.2|22|lab\n")
	_ = f.Close()
	if out := s.mustMigrate(); out != "" {
		t.Errorf("output %q", out)
	}
	s.pointsIntoState("linux-hosts")
	if !strings.Contains(s.read(filepath.Join(s.state, "linux-hosts")), "host2|10.0.0.2|22|lab") {
		t.Error("lost")
	}
}

// renameOver is what conf_set of the previous release does: write a temp
// file, rename it over the old path (the symlink becomes a regular file).
func (s *senv) renameOver(name, text string) {
	s.t.Helper()
	tmp := filepath.Join(s.etc, name+".tmp")
	s.write(tmp, text)
	if err := os.Rename(tmp, filepath.Join(s.etc, name)); err != nil {
		s.t.Fatal(err)
	}
}

func TestStateRollbackAFileReplacedByRenameWinsAndTheOtherIsKept(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	s.ago(filepath.Join(s.state, "tacctl.yaml"), time.Hour)
	s.renameOver("tacctl.yaml", "bcrypt:\n  cost: 14\n")
	out := s.mustMigrate()
	s.pointsIntoState("tacctl.yaml")
	if s.read(filepath.Join(s.state, "tacctl.yaml")) != "bcrypt:\n  cost: 14\n" {
		t.Error("newer content lost")
	}
	kept := s.legacyWith("tacctl.yaml.", "bcrypt:\n  cost: 10\n")
	if len(kept) != 1 {
		t.Fatal("displaced copy missing")
	}
	has(t, out, "[WARN] State migration: tacctl.yaml existed in both places; the displaced copy is "+kept[0])
	has(t, out, "[INFO] State migrated: "+filepath.Join(s.etc, "tacctl.yaml")+" -> "+filepath.Join(s.state, "tacctl.yaml"))
	if !strings.HasPrefix(filepath.Base(kept[0]), "tacctl.yaml."+s.now.Format("20060102")+"-") {
		t.Errorf("name %s", kept[0])
	}
}

func TestStateRollbackAfterHealingASecondRunIsANoOp(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	s.ago(filepath.Join(s.state, "linux-uids"), time.Hour)
	s.renameOver("linux-uids", "alice:20000\nbob:20001\n")
	s.mustMigrate()
	before := s.treeState()
	if out := s.mustMigrate(); out != "" || s.treeState() != before {
		t.Errorf("output %q or tree changed", out)
	}
	if s.read(filepath.Join(s.state, "linux-uids")) != "alice:20000\nbob:20001\n" {
		t.Error("content")
	}
}

func TestStateRollbackSeveralRoundsKeepTheNewestAndEveryDisplacedCopy(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	for i := 1; i <= 3; i++ {
		s.ago(filepath.Join(s.state, "tacctl.yaml"), time.Duration(10-i)*time.Minute)
		s.renameOver("tacctl.yaml", fmt.Sprintf("round: %d\n", i))
		s.mustMigrate()
		s.pointsIntoState("tacctl.yaml")
		if s.read(filepath.Join(s.state, "tacctl.yaml")) != fmt.Sprintf("round: %d\n", i) {
			t.Errorf("round %d", i)
		}
	}
	if n := len(s.legacyWith("tacctl.yaml.", "")); n != 3 {
		t.Errorf("%d displaced copies", n)
	}
}

func TestStateRollbackAnOldPathFileThatIsNotNewerLoses(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	_ = os.Remove(filepath.Join(s.etc, "linux-hosts"))
	s.write(filepath.Join(s.etc, "linux-hosts"), "stale|1.1.1.1|22|lab\n")
	s.ago(filepath.Join(s.etc, "linux-hosts"), 24*time.Hour)
	s.mustMigrate()
	s.pointsIntoState("linux-hosts")
	if s.read(filepath.Join(s.state, "linux-hosts")) != "host1|10.0.0.1|22|lab\n" {
		t.Error("stale won")
	}
	if len(s.legacyWith("linux-hosts.", "stale|1.1.1.1|22|lab\n")) != 1 {
		t.Error("stale copy not kept")
	}
}

func TestStateRollbackAnIdenticalFileIsReplacedByTheLinkWithoutABackup(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	_ = os.Remove(filepath.Join(s.etc, "linux-uids"))
	s.write(filepath.Join(s.etc, "linux-uids"), s.read(filepath.Join(s.state, "linux-uids")))
	s.mustMigrate()
	s.pointsIntoState("linux-uids")
	if exists(filepath.Join(s.state, "backups", "legacy")) {
		t.Error("backup made")
	}
}

func TestStateRollbackADirectoryRecreatedAtTheOldPathIsMergedBack(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	_ = os.Remove(filepath.Join(s.etc, "templates"))
	s.write(filepath.Join(s.etc, "templates", "juniper.template"), "added by old code\n")
	s.mustMigrate()
	s.pointsIntoState("templates")
	if !exists(filepath.Join(s.state, "templates", "cisco.template")) || !exists(filepath.Join(s.state, "templates", "juniper.template")) {
		t.Error("merge")
	}
}

// --- never follow symlinks, never move into itself ---

func TestStateSymlinksALinkElsewhereIsLeftAlone(t *testing.T) {
	s := newSenv(t)
	target := filepath.Join(s.w, "elsewhere", "hosts")
	s.write(target, "operator file\n")
	if err := os.Symlink(target, filepath.Join(s.etc, "linux-hosts")); err != nil {
		t.Fatal(err)
	}
	out := s.mustMigrate()
	has(t, out, "[WARN] State migration: "+filepath.Join(s.etc, "linux-hosts")+" is a symlink elsewhere; left alone")
	if l, _ := os.Readlink(filepath.Join(s.etc, "linux-hosts")); l != target {
		t.Error("link changed")
	}
	if s.read(target) != "operator file\n" || exists(filepath.Join(s.state, "linux-hosts")) {
		t.Error("target touched")
	}
}

func TestStateSymlinksADanglingLinkIsNotFollowedOrReplaced(t *testing.T) {
	s := newSenv(t)
	nowhere := filepath.Join(s.w, "nowhere")
	if err := os.Symlink(nowhere, filepath.Join(s.etc, "linux-uids")); err != nil {
		t.Fatal(err)
	}
	s.mustMigrate()
	if st, err := os.Lstat(filepath.Join(s.etc, "linux-uids")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Error("link replaced")
	}
	if exists(nowhere) || exists(filepath.Join(s.state, "linux-uids")) {
		t.Error("followed")
	}
}

func TestStateSymlinksALinkInsideAnOldDirectoryMovesAsALink(t *testing.T) {
	s := newSenv(t)
	outside := filepath.Join(s.w, "outside")
	s.write(filepath.Join(outside, "file"), "x\n")
	if err := os.MkdirAll(filepath.Join(s.etc, "templates"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(s.etc, "templates", "linked")); err != nil {
		t.Fatal(err)
	}
	s.write(filepath.Join(s.state, "templates", "cisco.template"), "kept\n")
	s.mustMigrate()
	if st, err := os.Lstat(filepath.Join(s.state, "templates", "linked")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Error("not moved as a link")
	}
	if s.read(filepath.Join(outside, "file")) != "x\n" {
		t.Error("target touched")
	}
	s.pointsIntoState("templates")
}

func TestStateSymlinksASymlinkedStateDirEntryIsNotReplaced(t *testing.T) {
	s := newSenv(t)
	real := filepath.Join(s.w, "real")
	_ = os.MkdirAll(real, 0o700)
	_ = os.MkdirAll(s.state, 0o700)
	if err := os.Symlink(real, filepath.Join(s.state, "templates")); err != nil {
		t.Fatal(err)
	}
	s.write(filepath.Join(s.etc, "templates", "a.template"), "x\n")
	out := s.mustMigrate()
	has(t, out, "is a symlink; "+filepath.Join(s.etc, "templates")+" left alone")
	if st, _ := os.Lstat(filepath.Join(s.state, "templates")); st.Mode()&os.ModeSymlink == 0 {
		t.Error("replaced")
	}
	if !exists(filepath.Join(s.etc, "templates", "a.template")) || exists(filepath.Join(real, "a.template")) {
		t.Error("moved")
	}
}

func TestStateSelfMoveTheDaemonDirAsStateDirIsANoOp(t *testing.T) {
	s := newSenv(t)
	s.state = s.etc
	_ = os.Chmod(s.etc, 0o755)
	s.seedLegacy()
	if out := s.mustMigrate(); out != "" {
		t.Errorf("output %q", out)
	}
	if permOf(t, s.etc) != 0o755 || len(s.links(s.etc)) != 0 || !exists(filepath.Join(s.etc, "tacctl.yaml")) {
		t.Error("touched")
	}
}

func TestStateSelfMoveThroughASymlinkToTheDaemonDirIsANoOp(t *testing.T) {
	s := newSenv(t)
	alias := filepath.Join(s.w, "etc-alias")
	if err := os.Symlink(s.etc, alias); err != nil {
		t.Fatal(err)
	}
	s.state = alias
	s.seedLegacy()
	if out := s.mustMigrate(); out != "" || len(s.links(s.etc)) != 0 {
		t.Errorf("output %q / links %v", out, s.links(s.etc))
	}
}

func TestStateSelfMoveANestedStateDirMigratesWithoutMovingIntoItself(t *testing.T) {
	s := newSenv(t)
	s.state = filepath.Join(s.etc, "state")
	s.seedLegacy()
	s.mustMigrate()
	s.pointsIntoState("backups")
	s.pointsIntoState("tacctl.yaml")
	if !exists(filepath.Join(s.state, "backups", "password-dates")) {
		t.Error("backups")
	}
	if out := s.mustMigrate(); out != "" {
		t.Errorf("second run %q", out)
	}
}

// --- failures and the migrated layout ---

func TestStateAnItemThatCannotMoveIsReportedAndTheOthersStillMove(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	s := newSenv(t)
	s.seedLegacy()
	// Nothing can leave the daemon's directory: every move fails.
	_ = os.Chmod(s.etc, 0o500)
	defer func() { _ = os.Chmod(s.etc, 0o700) }()
	out, err := s.migrate()
	if err == nil {
		t.Fatal("no error")
	}
	_ = os.Chmod(s.etc, 0o700)
	has(t, out, "[ERROR] State migration failed for backups")
	has(t, out, "[ERROR] State migration failed for linux-uids")
}

func TestStateTheMigratedLayoutWorksWithConfSet(t *testing.T) {
	s := newSenv(t)
	s.seedLegacy()
	s.mustMigrate()
	c := conf.Load(filepath.Join(s.state, "tacctl.yaml"), []string{"tacacs", "radius"})
	c.Owner = nil
	if err := c.Set("bcrypt.cost", "14"); err != nil {
		t.Fatal(err)
	}
	s.pointsIntoState("tacctl.yaml")
	if !strings.Contains(s.read(filepath.Join(s.state, "tacctl.yaml")), "cost: 14") {
		t.Error("not written into the state dir")
	}
}
