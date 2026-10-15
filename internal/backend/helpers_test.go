package backend_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/applylock"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/paths"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

var fixDir = filepath.Join("..", "..", "tests", "fixtures")

// tenv is the test environment of tests/integration/backend_mutation.bats:
// a state tree under a temp dir, a TMPDIR of its own (so a leaked staging
// directory is visible), the TACACS+ render (the real one, behind a small
// test module: the real module is WP2.2's) and a stand-in 'fake' backend.
type tenv struct {
	t        *testing.T
	w        string
	tmp      string
	p        paths.Paths
	reg      *backend.Registry
	env      *backend.Env
	set      *backend.Set
	tac      *tacacsTest
	fake     *faketest.Backend
	stdout   *safeBuf
	stderr   *safeBuf
	faults   map[string]bool
	fakeConf string
	// lock is this invocation's apply lock (Env.ApplyLock and the Conf's
	// hook); lockCtx is what a Conf write waits with (nil: Background).
	lock    *applylock.Lock
	lockCtx context.Context
}

// safeBuf is a buffer a test may read while a command it started in a
// goroutine writes.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *safeBuf) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Len()
}

func (s *safeBuf) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

func newTenv(t *testing.T) *tenv { return newTenvAt(t, t.TempDir()) }

// newTenvAt is a test environment on the tree w. Two of them on one tree are
// two tacctl processes: each has its own Env, Conf, backends, output and
// apply lock, and they share the files.
func newTenvAt(t *testing.T, w string) *tenv {
	t.Helper()
	e := &tenv{t: t, w: w, stdout: &safeBuf{}, stderr: &safeBuf{}, faults: map[string]bool{}}
	for _, d := range []string{"etc", "state", "systemd/tacquito.service.d", "log", "tmp", "fake"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.tmp = filepath.Join(w, "tmp")
	t.Setenv("TMPDIR", e.tmp)
	e.p = paths.Resolve(paths.NewEnv([]string{
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_LOG=" + filepath.Join(w, "log"),
		"TACCTL_OVERRIDE_DIR=" + filepath.Join(w, "systemd", "tacquito.service.d"),
		"TACCTL_SYSTEMD_DIR=" + filepath.Join(w, "systemd"),
	}), "", func(string) bool { return false })
	e.fakeConf = filepath.Join(w, "etc", "fake.conf")
	e.reg = backend.NewRegistry(backend.TACACS, backend.RADIUS)
	e.tac = &tacacsTest{}
	e.fake = faketest.New("fake", e.fakeConf, filepath.Join(w, "fake"))
	if err := e.reg.Add("fake", faketest.Factory(e.fake)); err != nil {
		t.Fatal(err)
	}
	if err := e.reg.Add(backend.TACACS, e.tac.factory); err != nil {
		t.Fatal(err)
	}
	out := ui.Output{Stdout: e.stdout, Stderr: e.stderr}
	snaps := snapshot.New(e.p, "0.2.0-test", nil, out)
	snaps.Chown = nil
	e.env = &backend.Env{
		Paths:     e.p,
		Conf:      conf.Load(e.p.Overrides, e.reg.IDs()),
		Out:       out,
		Now:       time.Now,
		Fault:     e.fault,
		Snapshots: snaps,
	}
	e.env.Conf.Owner = nil
	// What the App wires: one reentrant lock, for the transactions and for
	// every write of tacctl.yaml.
	e.lock = applylock.New(e.p.StateDir)
	e.env.ApplyLock = e.lock
	e.env.Conf.Lock = e.confLock
	e.set = backend.NewSet(e.reg, e.env)
	return e
}

// confLock is conf.Config.Lock.
func (e *tenv) confLock() (func(), error) {
	ctx := e.lockCtx
	if ctx == nil {
		ctx = context.Background()
	}
	return e.lock.Acquire(ctx, func() { e.env.Out.Info(backend.WaitingMsg) })
}

func (e *tenv) fault(point string) error {
	if e.faults[point] {
		return errors.New("injected fault " + point)
	}
	return nil
}

// withStore is the setup of backend_mutation.bats: the multiscope store,
// tacquito.yaml rendered from it with tacacs alone, then tacacs and fake
// enabled.
func (e *tenv) withStore(enabled string) {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(fixDir, "store.multiscope.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.p.StoreFile, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
	if err := e.set.ConfigRender(context.Background(), false); err != nil {
		e.t.Fatalf("config render: %v: %s", err, e.stderr)
	}
	if enabled != "" {
		e.enable(enabled)
	}
	e.reset()
}

// enable writes backends.enabled by hand, as the bats tests do.
func (e *tenv) enable(list string) {
	e.t.Helper()
	if err := os.WriteFile(e.p.Overrides, []byte("backends:\n  enabled: ["+list+"]\n"), 0o640); err != nil {
		e.t.Fatal(err)
	}
	e.env.Conf.Reload()
}

// reset forgets the calls and output so far.
func (e *tenv) reset() {
	e.tac.mu.Lock()
	e.tac.calls = nil
	e.tac.mu.Unlock()
	e.fake.ResetCalls()
	e.stdout.Reset()
	e.stderr.Reset()
}

// userSet is a writer making one store write (store_user_set).
func (e *tenv) userSet(name string, fields ...string) func() error {
	return func() error {
		_, err := store.Mutate(e.p.StoreFile, e.env.MutateOptions(), func(s *store.Store) error {
			return s.UserSet(name, fields...)
		})
		return err
	}
}

func (e *tenv) apply(writer func() error) (backend.Result, error) {
	return e.set.StoreApply(context.Background(), backend.ApplyOptions{}, writer)
}

// state is the bats state(): one line per canonical file and artifact.
func (e *tenv) state() string {
	var b strings.Builder
	for _, f := range []string{e.p.StoreFile, e.p.Overrides, e.p.Config, e.dropIn(), e.fakeConf, e.p.Rendered} {
		data, err := os.ReadFile(f)
		if err != nil {
			b.WriteString(filepath.Base(f) + " absent\n")
			continue
		}
		sum := sha256.Sum256(data)
		b.WriteString(filepath.Base(f) + " " + hex.EncodeToString(sum[:]) + "\n")
	}
	return b.String()
}

func (e *tenv) dropIn() string { return rtacacs.DropIn(rtacacs.PathsFrom(e.p), "default") }

// noLeftovers is the bats no_leftovers().
func (e *tenv) noLeftovers() {
	e.t.Helper()
	if ents, _ := os.ReadDir(e.tmp); len(ents) != 0 {
		e.t.Errorf("TMPDIR not empty: %v", ents)
	}
	for _, pat := range []string{".apply.*", ".restore.*", ".enable.*"} {
		if m, _ := filepath.Glob(filepath.Join(e.p.StateDir, pat)); len(m) != 0 {
			e.t.Errorf("left %v", m)
		}
	}
	_ = filepath.Walk(filepath.Join(e.w, "etc"), func(p string, _ os.FileInfo, _ error) error {
		if strings.HasSuffix(p, ".tacctl-new") {
			e.t.Errorf("left %s", p)
		}
		return nil
	})
}

func (e *tenv) check(path string) string {
	e.t.Helper()
	w, err := rendered.Check(e.p.Rendered, path)
	if err != nil {
		e.t.Fatal(err)
	}
	return w
}

func (e *tenv) snapshots() []string { return snapshot.IDs(e.p.BackupDir) }

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func appendFile(t *testing.T, p, text string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(text)
	_ = f.Close()
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	if got := backend.ExitCode(err); got != code {
		t.Fatalf("exit status %d (%v), want %d", got, err, code)
	}
}

// tacacsTest is a test module over the real TACACS+ render steps
// (internal/render/tacacs), the default listener only: enough of the
// TACACS+ backend for the mutation machinery to be tested against what
// the bats tests used. Its service calls are recorded, not run.
type tacacsTest struct {
	env *backend.Env
	r   *rtacacs.Renderer
	// calls is every call so far; read it directly only when no other
	// goroutine is running, else through callList and called.
	calls []string
	mu    sync.Mutex
	// onRestart, when set, runs at the start of every restart (a test
	// that holds a restart open).
	onRestart func()
}

func (b *tacacsTest) record(call string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, call)
}

func (b *tacacsTest) callList() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.calls)
}

func (b *tacacsTest) factory(env *backend.Env) backend.Backend {
	b.env = env
	b.r = &rtacacs.Renderer{
		Paths:  rtacacs.PathsFrom(env.Paths),
		Conf:   env.Conf,
		Load:   rtacacs.DefaultLoader,
		Chown:  func(string) {},
		Now:    env.Now,
		Stderr: env.Out.Stderr,
	}
	return b
}

func (b *tacacsTest) ID() string { return backend.TACACS }
func (b *tacacsTest) Describe() backend.Description {
	return backend.Description{Protocol: "tacacs", Impl: "tacquito", Units: []string{"tacquito.service"},
		User: "tacquito", ConfigDir: b.env.Paths.Etc, LogDir: b.env.Paths.Log, ImportCmd: "tacctl store import --replace"}
}
func (b *tacacsTest) Installed() bool                                      { return true }
func (b *tacacsTest) Install(context.Context, backend.Phase, string) error { return nil }
func (b *tacacsTest) Upgrade(context.Context, backend.Phase, string) error { return nil }
func (b *tacacsTest) Uninstall(context.Context, backend.Phase, bool) error { return nil }
func (b *tacacsTest) Artifacts() []string {
	return []string{b.r.Paths.Config, rtacacs.DropIn(b.r.Paths, "default")}
}
func (b *tacacsTest) RenderCheck(context.Context) (string, error)       { return b.r.Check(true) }
func (b *tacacsTest) RenderNotes(context.Context)                       {}
func (b *tacacsTest) Listeners() backend.ListenerOps                    { return nil }
func (b *tacacsTest) SecretConstraints() backend.Constraints            { return backend.Constraints{} }
func (b *tacacsTest) LastLogin(context.Context, string) (string, error) { return "never", nil }
func (b *tacacsTest) Status(context.Context, backend.StatusPart, io.Writer) error {
	return backend.ErrUnsupported
}
func (b *tacacsTest) Log(context.Context, string, []string, io.Writer) error {
	return backend.ErrUnsupported
}
func (b *tacacsTest) Accounting(context.Context, string, []string, io.Writer) error {
	return backend.ErrUnsupported
}
func (b *tacacsTest) DeviceVars(context.Context, string, string) (map[string]string, error) {
	return nil, nil
}

func (b *tacacsTest) RenderGate(context.Context) backend.GateResult {
	b.record("gate")
	switch b.r.Gate() {
	case rtacacs.GateOK:
		return backend.GateOK
	case rtacacs.GateAdopt:
		return backend.GateAdopt
	case rtacacs.GateRefused:
		return backend.GateRefused
	}
	return backend.GateFailed
}

func (b *tacacsTest) RenderStage(_ context.Context, dir string, force bool) error {
	b.record("stage")
	err := b.r.Stage(dir, force, true)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, rtacacs.ErrRefused):
		return backend.ErrRefused
	}
	return backend.ErrFailed
}

func (b *tacacsTest) RenderCommit(_ context.Context, dir string) (bool, error) {
	b.record("commit")
	changed, err := b.r.CommitConfig(dir)
	if err != nil {
		return false, backend.ErrFailed
	}
	units, err := b.r.CommitUnits(dir)
	if err != nil {
		return false, backend.ErrFailed
	}
	return changed || len(units) > 0, nil
}

func (b *tacacsTest) Service(_ context.Context, action backend.ServiceAction, listener string) (string, error) {
	b.record(strings.TrimSpace("service " + string(action) + " " + listener))
	if action == backend.ServiceRestart && b.onRestart != nil {
		b.onRestart()
	}
	return "", nil
}

func (b *tacacsTest) called(line string) bool { return slices.Contains(b.callList(), line) }

func (b *tacacsTest) restarted() bool { return b.called("service restart") }

// addFake registers one more stand-in (before the first use of the Set);
// tacctl.yaml is re-read with the larger registry.
func (e *tenv) addFake(id string) *faketest.Backend {
	e.t.Helper()
	b := faketest.New(id, filepath.Join(e.w, "etc", id+".conf"), filepath.Join(e.w, id))
	if err := e.reg.Add(id, faketest.Factory(b)); err != nil {
		e.t.Fatal(err)
	}
	e.env.Conf = conf.Load(e.p.Overrides, e.reg.IDs())
	e.env.Conf.Owner = nil
	e.env.Conf.Lock = e.confLock
	return b
}
