package radius_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/backend/radius"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

const fixtures = "../../../tests/fixtures/"

var ansi = regexp.MustCompile("\x1b\\[[0-9;]*m")

// strip is sed 's/\x1b\[[0-9;]*m//g'.
func strip(s string) string { return ansi.ReplaceAllString(s, "") }

// renv is the test environment of tests/integration/radius.bats: a state
// tree and a FreeRADIUS layout under a temp dir (the package "installed": the
// daemon binary, raddb, the log directory, the package's main dictionary), a
// TMPDIR of its own so that a leaked staging directory is visible, the RADIUS
// module on a fake runner that plays systemctl with state ($SD in the bats
// stub), ss, ps and the daemon, and a stand-in 'tacacs' backend beside it.
type renv struct {
	t      *testing.T
	w      string
	tmp    string
	p      paths.Paths
	family string
	reg    *backend.Registry
	env    *backend.Env
	set    *backend.Set
	m      *radius.Module
	tac    *faketest.Backend
	run    *fake.Runner
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	now    time.Time

	mu        sync.Mutex
	active    map[string]bool // units that are running
	enabled   map[string]bool // units enabled at boot
	failStart bool            // a start or restart leaves the unit inactive ('fail-start')
	failCheck bool            // the daemon's -C rejects the config ('fail-check')
	checks    []checkSeen     // what the daemon found at each -C
	chowns    []string        // "<path>" of every Chown the module made
	sleeps    []time.Duration
}

// checkSeen is what the stub daemon saw when it was run with -C ('ls -la
// "$dir"' in the bats stub).
type checkSeen struct {
	Argv      []string
	Dir, DDir string
	DirMode   os.FileMode
	DDirMode  os.FileMode
	FileModes map[string]os.FileMode
	ConfData  string
}

type option func(*renv)

// rhel selects the RHEL-family layout.
func rhel(r *renv) { r.family = "rhel" }

func newEnv(t *testing.T, opts ...option) *renv {
	t.Helper()
	w := t.TempDir()
	r := &renv{
		t: t, w: w, family: "debian",
		stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
		active: map[string]bool{}, enabled: map[string]bool{},
		now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.Local),
	}
	for _, o := range opts {
		o(r)
	}
	for _, d := range []string{"etc", "state/backups", "systemd", "log", "tmp", "logrotate.d", "radius-share", "tacfake"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	r.tmp = filepath.Join(w, "tmp")
	t.Setenv("TMPDIR", r.tmp)
	if err := os.WriteFile(filepath.Join(w, "radius-share", "dictionary"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	env := paths.NewEnv([]string{
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_LOG=" + filepath.Join(w, "log"),
		"TACCTL_BIN=" + filepath.Join(w, "bin"),
		"TACCTL_SYSTEMD_DIR=" + filepath.Join(w, "systemd"),
		"TACCTL_OVERRIDE_DIR=" + filepath.Join(w, "systemd", "tacquito.service.d"),
		"TACCTL_LOGROTATE_DIR=" + filepath.Join(w, "logrotate.d"),
		"TACCTL_SETTLE_SECONDS=0",
		"TACCTL_RADIUS_FAMILY=" + r.family,
		"TACCTL_RADIUS_DIR=" + filepath.Join(w, "raddb"),
		"TACCTL_RADIUS_LOG=" + filepath.Join(w, "radius-log"),
		"TACCTL_RADIUS_BIN=" + filepath.Join(w, "radius-bin", "radiusd"),
		"TACCTL_RADIUS_DICT=" + filepath.Join(w, "radius-share", "dictionary"),
		// Not used by the RADIUS module; sandboxed all the same, so that no
		// path of the environment is a host default (hostDefaults).
		"TACCTL_SUDOERS_FILE=" + filepath.Join(w, "sudoers.d", "tacctl"),
		"TACCTL_TIER_SUDOERS_FILE=" + filepath.Join(w, "sudoers.d", "tacctl-tiers"),
		"TACQUITO_SRC=" + filepath.Join(w, "tacquito-src"),
		"TACCTL_LINUX_DIR=" + filepath.Join(w, "linux"),
		"TACCTL_TREE=" + filepath.Join(w, "tree"),
	})
	r.p = paths.Resolve(env, "", func(string) bool { return false })
	// 'uninstall data --keep-logs' archives under /root in production.
	archive := radius.LogArchiveDir
	radius.LogArchiveDir = filepath.Join(w, "root")
	t.Cleanup(func() { radius.LogArchiveDir = archive })
	r.run = &fake.Runner{}
	r.script()

	r.reg = backend.NewRegistry(backend.TACACS, backend.RADIUS)
	r.tac = faketest.New(backend.TACACS, filepath.Join(w, "etc", "tacquito.yaml"), filepath.Join(w, "tacfake"))
	if err := r.reg.Add(backend.TACACS, faketest.Factory(r.tac)); err != nil {
		t.Fatal(err)
	}
	if err := r.reg.Add(backend.RADIUS, func(e *backend.Env) backend.Backend {
		m := radius.NewModule(e, r.family)
		m.Apply = func(ctx context.Context, o backend.ApplyOptions, wr func() error) (backend.Result, error) {
			return r.set.StoreApply(ctx, o, wr)
		}
		m.Sleep = func(_ context.Context, d time.Duration) { r.sleeps = append(r.sleeps, d) }
		m.Chown = func(path string) { r.chowns = append(r.chowns, path) }
		r.m = m
		return m
	}); err != nil {
		t.Fatal(err)
	}
	out := ui.Output{Stdout: r.stdout, Stderr: r.stderr}
	snaps := snapshot.New(r.p, "0.2.0-test", func() time.Time { return r.now }, out)
	snaps.Chown = nil
	cfg := conf.Load(r.p.Overrides, r.reg.IDs())
	cfg.Owner = nil
	r.env = &backend.Env{
		Paths: r.p, Conf: cfg, Runner: r.run, Out: out,
		Now:       func() time.Time { return r.now },
		Snapshots: snaps,
	}
	r.set = backend.NewSet(r.reg, r.env)
	if _, err := r.set.Get(backend.RADIUS); err != nil {
		t.Fatal(err)
	}
	if bad := hostDefaults(r.p, r.m.L, w); len(bad) != 0 {
		t.Fatalf("the test environment leaves host paths: %v", bad)
	}
	r.packagePresent()
	return r
}

// packagePresent is package_present: the daemon (a file the stub runner
// stands in for) and its directories, no unit state.
func (r *renv) packagePresent() {
	r.t.Helper()
	bin := r.m.L.Bin
	for _, d := range []string{filepath.Dir(bin), r.m.L.Dir, r.m.L.LogDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			r.t.Fatal(err)
		}
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil {
		r.t.Fatal(err)
	}
}

// script installs the fake runner's rules: systemctl with state, ss, ps and
// the daemon.
func (r *renv) script() {
	r.run.OnFunc([]string{"systemctl"}, func(c execx.Cmd) (execx.Result, error) {
		return r.systemctl(c.Args), nil
	})
	r.run.On([]string{"ps"}, execx.Result{Stdout: []byte("2048\n")})
	r.run.OnFunc([]string{"ss"}, func(c execx.Cmd) (execx.Result, error) {
		r.mu.Lock()
		defer r.mu.Unlock()
		if slices.Contains(c.Args, "-ulnp") {
			if r.active["freeradius"] || r.active["radiusd"] {
				return execx.Result{Stdout: []byte("UNCONN 0 0 0.0.0.0:1812 0.0.0.0:*\nUNCONN 0 0 0.0.0.0:1813 0.0.0.0:*\n")}, nil
			}
			return execx.Result{}, nil
		}
		return execx.Result{Stdout: []byte("LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))\n")}, nil
	})
	bin := filepath.Join(r.w, "radius-bin", "radiusd")
	r.run.Func(func(c execx.Cmd) bool { return c.Name == bin }, func(c execx.Cmd) (execx.Result, error) {
		return r.daemon(c)
	})
}

// systemctl is the bats stub, verb by verb.
func (r *renv) systemctl(args []string) execx.Result {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(args) == 0 {
		return execx.Result{}
	}
	verb := args[0]
	var units []string
	now := false
	for _, a := range args[1:] {
		switch {
		case a == "--now":
			now = true
		case strings.HasPrefix(a, "-"):
		default:
			units = append(units, strings.TrimSuffix(a, ".service"))
		}
	}
	u := ""
	if len(units) > 0 {
		u = units[0]
	}
	switch verb {
	case "is-active":
		if r.active[u] {
			return execx.Result{Stdout: []byte("active\n")}
		}
		return execx.Result{Stdout: []byte("inactive\n"), Code: 3}
	case "is-enabled":
		if r.enabled[u] {
			return execx.Result{Stdout: []byte("enabled\n")}
		}
		return execx.Result{Stdout: []byte("disabled\n"), Code: 1}
	case "start", "restart":
		if r.failStart {
			delete(r.active, u)
			return execx.Result{Code: 1}
		}
		r.active[u] = true
	case "stop":
		delete(r.active, u)
	case "enable":
		r.enabled[u] = true
		if now {
			r.active[u] = true
		}
	case "disable":
		delete(r.enabled, u)
		if now {
			delete(r.active, u)
		}
	case "show":
		if slices.Contains(args, "--property=MainPID") {
			if r.active[u] {
				return execx.Result{Stdout: []byte("MainPID=4242\n")}
			}
			return execx.Result{Stdout: []byte("MainPID=0\n")}
		}
		return execx.Result{Stdout: []byte("ActiveEnterTimestamp=Fri 2026-10-02 10:00:00 UTC\n")}
	}
	return execx.Result{}
}

// daemon is the stub radiusd of the bats install_pkg.
func (r *renv) daemon(c execx.Cmd) (execx.Result, error) {
	dir, ddir, name := "", "", ""
	for i := 0; i < len(c.Args); i++ {
		switch c.Args[i] {
		case "-d":
			i++
			dir = c.Args[i]
		case "-D":
			i++
			ddir = c.Args[i]
		case "-n":
			i++
			name = c.Args[i]
		}
	}
	seen := checkSeen{Argv: slices.Clone(c.Args), Dir: dir, DDir: ddir, FileModes: map[string]os.FileMode{}}
	if st, err := os.Stat(dir); err == nil {
		seen.DirMode = st.Mode().Perm()
	}
	if st, err := os.Stat(ddir); err == nil {
		seen.DDirMode = st.Mode().Perm()
	}
	for _, f := range []string{filepath.Join(dir, name+".conf"), filepath.Join(dir, name+".users"), filepath.Join(ddir, "dictionary")} {
		if st, err := os.Stat(f); err == nil {
			seen.FileModes[filepath.Base(f)] = st.Mode().Perm()
		}
	}
	if data, err := os.ReadFile(filepath.Join(dir, name+".conf")); err == nil {
		seen.ConfData = string(data)
	}
	r.mu.Lock()
	r.checks = append(r.checks, seen)
	failCheck := r.failCheck
	r.mu.Unlock()
	if _, err := os.ReadFile(filepath.Join(dir, name+".conf")); err != nil {
		return execx.Result{Stdout: []byte("Error: cannot read " + dir + "/" + name + ".conf\n"), Code: 1}, nil
	}
	if _, err := os.ReadFile(filepath.Join(dir, name+".users")); err != nil {
		return execx.Result{Stdout: []byte("Error: cannot read " + dir + "/" + name + ".users\n"), Code: 1}, nil
	}
	if failCheck {
		return execx.Result{Stdout: []byte("Fri Oct  2 10:00:00 2026 : Error: " + dir + "/" + name + ".conf[12]: Parse error\n"), Code: 1}, nil
	}
	return execx.Result{}, nil
}

func (r *renv) isActive(unit string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.active[unit]
}

func (r *renv) isEnabled(unit string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.enabled[unit]
}

func (r *renv) setActive(unit string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if on {
		r.active[unit] = true
	} else {
		delete(r.active, unit)
	}
}

func (r *renv) setEnabled(unit string, on bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if on {
		r.enabled[unit] = true
	} else {
		delete(r.enabled, unit)
	}
}

func (r *renv) setFailStart(on bool) { r.mu.Lock(); r.failStart = on; r.mu.Unlock() }
func (r *renv) setFailCheck(on bool) { r.mu.Lock(); r.failCheck = on; r.mu.Unlock() }

// useStore is load_store_fixture.
func (r *renv) useStore(name string) {
	r.t.Helper()
	data, err := os.ReadFile(fixtures + name)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(r.p.StoreFile, data, 0o600); err != nil {
		r.t.Fatal(err)
	}
}

// enableList writes backends.enabled by hand.
func (r *renv) enableList(list string) {
	r.t.Helper()
	if err := os.WriteFile(r.p.Overrides, []byte("backends:\n  enabled: ["+list+"]\n"), 0o640); err != nil {
		r.t.Fatal(err)
	}
	r.env.Conf.Reload()
}

// up is setup() followed by radius_up: the radius store fixture, both
// backends enabled and rendered, the drop-in installed, the unit enabled and
// running, and the calls and output forgotten.
func (r *renv) up() {
	r.t.Helper()
	r.useStore("store.radius.yaml")
	r.enableList("tacacs, radius")
	r.tac.Render = tacRender
	ctx := context.Background()
	if _, err := r.m.Service(ctx, backend.ServiceEnable, ""); err != nil {
		r.t.Fatalf("service enable: %v\n%s", err, r.stderr)
	}
	if err := r.set.ConfigRender(ctx, false); err != nil {
		r.t.Fatalf("config render: %v\n%s", err, r.stderr)
	}
	if _, err := r.m.Service(ctx, backend.ServiceStart, ""); err != nil {
		r.t.Fatalf("service start: %v", err)
	}
	r.reset()
}

// reset forgets the calls, the output and the chowns so far.
func (r *renv) reset() {
	r.run.Reset()
	r.tac.ResetCalls()
	r.stdout.Reset()
	r.stderr.Reset()
	r.chowns = nil
	r.checks = nil
	r.sleeps = nil
}

// out is everything written, colours stripped (the bats `output`).
func (r *renv) out() string { return strip(r.stdout.String() + r.stderr.String()) }

// apply is store_apply with a writer.
func (r *renv) apply(writer func() error) (backend.Result, error) {
	return r.set.StoreApply(context.Background(), backend.ApplyOptions{}, writer)
}

// mutate is a store_mutate writer.
func (r *renv) mutate(fn func(s *store.Store) error) func() error {
	return func() error {
		_, err := store.Mutate(r.p.StoreFile, r.env.MutateOptions(), fn)
		return err
	}
}

// userSet is store_user_set.
func (r *renv) userSet(name string, fields ...string) func() error {
	return r.mutate(func(s *store.Store) error { return s.UserSet(name, fields...) })
}

// state is the bats state(): one line per canonical file and artifact.
func (r *renv) state() string {
	var b strings.Builder
	for _, f := range []string{r.p.StoreFile, r.p.Overrides, r.p.Config, r.m.L.Conf, r.m.L.Users, r.m.L.Dict, r.p.Rendered} {
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

// noLeftovers is the bats no_leftovers().
func (r *renv) noLeftovers() {
	r.t.Helper()
	if ents, _ := os.ReadDir(r.tmp); len(ents) != 0 {
		r.t.Errorf("TMPDIR not empty: %v", ents)
	}
	for _, pat := range []string{".apply.*", ".restore.*", ".enable.*", ".radius-listen.*"} {
		if m, _ := filepath.Glob(filepath.Join(r.p.StateDir, pat)); len(m) != 0 {
			r.t.Errorf("left %v", m)
		}
	}
	_ = filepath.Walk(r.m.L.Dir, func(p string, _ os.FileInfo, _ error) error {
		if strings.Contains(filepath.Base(p), ".tacctl-check.") || strings.HasSuffix(p, ".tacctl-new") {
			r.t.Errorf("left %s", p)
		}
		return nil
	})
}

func (r *renv) read(path string) string {
	r.t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func (r *renv) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// has reports whether some line of the file starts with prefix (grep -q '^...').
func (r *renv) hasLine(path, prefix string) bool {
	for _, l := range strings.Split(r.read(path), "\n") {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func (r *renv) mode(path string) os.FileMode {
	r.t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		r.t.Fatal(err)
	}
	return st.Mode().Perm()
}

// calls is the systemctl and daemon calls so far, one line each, as the
// bats CALLS_LOG has them.
func (r *renv) calls() []string { return r.run.Argvs() }

// called is stub_called: some call matches the regexp.
func (r *renv) called(pattern string) bool { return r.run.CalledRegexp(pattern) }

// restarts counts 'systemctl restart <unit>'.
func (r *renv) restarts(unit string) int { return r.run.Count("systemctl", "restart", unit) }

// wantErr checks the exit status an error stands for.
func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	if got := backend.ExitCode(err); got != code {
		t.Fatalf("exit status %d (%v), want %d", got, err, code)
	}
}

func contains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("missing %q in:\n%s", want, got)
	}
}

func notContains(t *testing.T, got, bad string) {
	t.Helper()
	if strings.Contains(got, bad) {
		t.Errorf("unexpected %q in:\n%s", bad, got)
	}
}

// tacRender is what the stand-in TACACS+ backend renders: every user (and
// whether it can log in) and every scope with its secret, so that a change
// TACACS+ sees changes its artifact, as tacquito.yaml does.
func tacRender(s *store.Store) []byte {
	m := model.FromStore(s)
	var b strings.Builder
	for _, u := range m.Users {
		fmt.Fprintf(&b, "user %s disabled=%v\n", u.Name, u.IsDisabled())
	}
	for _, sc := range m.Scopes {
		fmt.Fprintf(&b, "scope %s %s\n", sc.Name, sc.Secret)
	}
	return []byte(b.String())
}

// failedResult is a command that fails.
func failedResult() execx.Result { return execx.Result{Code: 1} }

func writeFile(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o640); err != nil {
		t.Fatal(err)
	}
}

// scopeSet is a store_scope_set writer body.
func scopeSet(name string, fields ...string) func(s *store.Store) error {
	return func(s *store.Store) error { return s.ScopeSet(name, fields...) }
}
