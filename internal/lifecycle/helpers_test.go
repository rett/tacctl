package lifecycle_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/tacacs"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// The environment of the bats files these tests come from
// (tests/helpers/tmpenv.bash with chown, systemctl and logger stubbed): a
// sandbox under a temp dir, a scripted runner, the TACACS+ module behind
// a registry of its own, TMPDIR private (and checked empty at the end).

var fixDir = filepath.Join("..", "..", "tests", "fixtures")

const testHash = "24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

type tenv struct {
	t      *testing.T
	w      string
	p      paths.Paths
	run    *fake.Runner
	be     *backend.Env
	set    *backend.Set
	b      *tacacs.Backend
	wired  *wired
	env    *lifecycle.Env
	stdout *bytes.Buffer
	stderr *bytes.Buffer
}

func newTenv(t *testing.T) *tenv {
	t.Helper()
	w := t.TempDir()
	e := &tenv{t: t, w: w, run: &fake.Runner{}, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	for _, d := range []string{"etc", "state/backups/password-dates", "log", "bin", "systemd", "tmp"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", filepath.Join(w, "tmp"))
	t.Cleanup(func() {
		if left, _ := os.ReadDir(filepath.Join(w, "tmp")); len(left) != 0 {
			t.Errorf("TMPDIR not empty: %v", left)
		}
	})
	vars := []string{
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_LOG=" + filepath.Join(w, "log"),
		"TACCTL_BIN=" + filepath.Join(w, "bin"),
		"TACCTL_SYSTEMD_DIR=" + filepath.Join(w, "systemd"),
		"TACCTL_OVERRIDE_DIR=" + filepath.Join(w, "systemd", "tacquito.service.d"),
		"TACCTL_SETTLE_SECONDS=0",
	}
	e.p = paths.Resolve(paths.NewEnv(vars), "", func(string) bool { return false })
	e.run.On([]string{"systemctl"}, execx.Result{})
	e.run.On([]string{"logger"}, execx.Result{})
	reg := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	out := ui.Output{Stdout: e.stdout, Stderr: e.stderr}
	snaps := snapshot.New(e.p, "0.2.0-test", nil, out)
	snaps.Chown = nil
	e.be = &backend.Env{
		Paths:     e.p,
		Conf:      conf.Load(e.p.Overrides, reg.IDs()),
		Runner:    e.run,
		Out:       out,
		Stdin:     strings.NewReader(""),
		Now:       time.Now,
		Snapshots: snaps,
	}
	e.be.Conf.Owner = nil
	e.b = tacacs.New(e.be)
	e.b.Chown = func(string) {}
	e.wired = &wired{Backend: e.b}
	if err := reg.Add(backend.TACACS, func(*backend.Env) backend.Backend { return e.wired }); err != nil {
		t.Fatal(err)
	}
	e.set = backend.NewSet(reg, e.be)
	e.env = lifecycle.NewEnv(e.be, nil, false)
	e.env.Chown = func(string) {}
	return e
}

func (e *tenv) write(path, text string, mode os.FileMode) {
	e.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), mode); err != nil {
		e.t.Fatal(err)
	}
}

func (e *tenv) read(path string) string {
	e.t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		e.t.Fatal(err)
	}
	return string(data)
}

func fixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixDir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// placeFixture is place_fixture: the file as tacquito.yaml, no store.
func (e *tenv) placeFixture(name string) {
	e.t.Helper()
	e.write(e.p.Config, fixture(e.t, name), 0o640)
}

// loadFixture is load_fixture: the file as tacquito.yaml and its strict
// import as the store (the store file only).
func (e *tenv) loadFixture(name string) {
	e.t.Helper()
	e.placeFixture(name)
	var o bytes.Buffer
	err := store.Import(ui.Output{Stdout: &o, Stderr: &o}, store.ImportOptions{
		Src: filepath.Join(fixDir, name), StorePath: e.p.StoreFile, ConfigPath: e.p.Config,
		LegacyDir: filepath.Join(e.p.BackupDir, "legacy"),
	})
	if err != nil {
		e.t.Fatalf("import %s: %v\n%s", name, err, o.String())
	}
}

// fakeTacquito is fake_tacquito <serve|fatal>: a daemon binary whose
// load-smoke (scripted on the runner) serves, or rejects the config.
func (e *tenv) fakeTacquito(mode string) {
	e.t.Helper()
	bin := filepath.Join(e.p.Bin, "tacquito")
	e.write(bin, "#!/bin/sh\n", 0o755)
	switch mode {
	case "serve":
		e.run.On([]string{bin}, execx.Result{Stderr: []byte("INFO: main.go:135: serve on 127.0.0.1:40001\n" +
			"INFO: loader.go:241: updated all providers from config source\n")})
	case "fatal":
		e.run.On([]string{bin}, execx.Result{Stderr: []byte("FATAL: main.go:98: error fetching config; loader failed\n")})
	}
}

// output is everything printed so far, colours removed; reset forgets it.
func (e *tenv) output() string { return plain(e.stdout.String() + e.stderr.String()) }

func (e *tenv) reset() {
	e.stdout.Reset()
	e.stderr.Reset()
	e.run.Reset()
}

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

func plain(s string) string { return ansi.ReplaceAllString(s, "") }

func sha(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func has(t *testing.T, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Errorf("output lacks %q:\n%s", want, out)
	}
}

func hasNot(t *testing.T, out, want string) {
	t.Helper()
	if strings.Contains(out, want) {
		t.Errorf("output has %q:\n%s", want, out)
	}
}

// systemctlCalled reports whether systemctl was run since the last reset.
func (e *tenv) systemctlCalled() bool { return e.run.Called("systemctl") }

// preStoreFiles are the regular pre-store copies under backups/legacy.
func (e *tenv) preStoreFiles() []string {
	m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, "legacy", "tacquito.yaml.pre-store.*"))
	var out []string
	for _, f := range m {
		if st, err := os.Lstat(f); err == nil && st.Mode().IsRegular() {
			out = append(out, f)
		}
	}
	return out
}

func (e *tenv) legacyFiles() []string {
	m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, "legacy", "*"))
	return m
}

var ctx = context.Background()

// wired is the TACACS+ module with its 'upgrade config' phase wired to
// ConfigSyncExisting, as WP3.3b's lifecycle phases will have it (until
// then the module's phases are no-ops): install over an existing store
// runs that phase.
type wired struct {
	*tacacs.Backend
	phases []backend.Phase
	synced bool
}

func (w *wired) Upgrade(ctx context.Context, phase backend.Phase, _ string) error {
	w.phases = append(w.phases, phase)
	if phase == backend.PhaseConfig {
		changed, err := w.ConfigSyncExisting(ctx)
		w.synced = changed
		return err
	}
	return nil
}

// upgradeSync is the part of an upgrade that runs before the gate:
// StateMigrate, then ConfigSyncExisting (whose 'changed' it returns).
func (e *tenv) upgradeSync() bool {
	e.t.Helper()
	if err := lifecycle.StateMigrate(lifecycle.StateOptionsFrom(e.p, e.be.Out, nil, false)); err != nil {
		e.t.Fatal(err)
	}
	e.be.Conf.Reload()
	changed, err := lifecycle.ConfigSyncExisting(ctx, e.env, lifecycle.SyncOptions{})
	if err != nil {
		e.t.Fatalf("config sync: %v\n%s", err, e.output())
	}
	return changed
}

// flip is upgrade_store_flip; the output so far is forgotten first.
func (e *tenv) flip() lifecycle.FlipResult {
	e.reset()
	return lifecycle.UpgradeStoreFlip(ctx, e.env)
}

// storeImport is a manual 'tacctl store import' of the live config (the
// pre-store copy is kept), its output dropped.
func (e *tenv) storeImport() {
	e.t.Helper()
	var o bytes.Buffer
	err := store.Import(ui.Output{Stdout: &o, Stderr: &o}, store.ImportOptions{
		StorePath: e.p.StoreFile, ConfigPath: e.p.Config, DatesDir: e.p.PWDatesDir,
		DisabledDir: filepath.Join(e.p.BackupDir, "disabled"), LegacyDir: filepath.Join(e.p.BackupDir, "legacy"),
	})
	if err != nil {
		e.t.Fatalf("store import: %v\n%s", err, o.String())
	}
}

// userAdd is 'tacctl user add <name> superuser --hash <h> --scopes lab'
// through StoreApply.
func (e *tenv) userAdd(name string) {
	e.t.Helper()
	_, err := e.set.StoreApply(ctx, backend.ApplyOptions{}, func() error {
		_, err := store.Mutate(e.p.StoreFile, e.be.MutateOptions(), func(s *store.Store) error {
			return s.UserSet(name, "group=superuser", "scopes=lab", "hash="+testHash)
		})
		return err
	})
	if err != nil {
		e.t.Fatalf("user add %s: %v\n%s", name, err, e.output())
	}
}
