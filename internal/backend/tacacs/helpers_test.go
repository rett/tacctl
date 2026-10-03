package tacacs

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
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	rtacacs "github.com/rett/tacctl/internal/render/tacacs"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/ui"
)

var (
	fixDir    = filepath.Join("..", "..", "..", "tests", "fixtures")
	sharedDir = filepath.Join("..", "..", "..", "config", "backends", "tacacs")
)

// tenv is the environment of the bats files this package's tests come
// from (tests/helpers/tmpenv.bash with systemctl stubbed): a state tree
// under a temp dir, the default listener's drop-in directory inside the
// unit directory (TACCTL_SYSTEMD_DIR), TACCTL_SETTLE_SECONDS=0, a scripted
// runner, and the module behind a registry of its own (so that 'config
// render' and StoreApply run the real machinery over it).
type tenv struct {
	t      *testing.T
	w      string
	p      paths.Paths
	run    *fake.Runner
	env    *backend.Env
	set    *backend.Set
	b      *Backend
	stdout *bytes.Buffer
	stderr *bytes.Buffer
	sleeps []time.Duration
}

func newTenv(t *testing.T, extraEnv ...string) *tenv {
	t.Helper()
	w := t.TempDir()
	e := &tenv{t: t, w: w, run: &fake.Runner{}, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	for _, d := range []string{"etc", "state", "log", "bin", "systemd", "tmp"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", filepath.Join(w, "tmp"))
	vars := append([]string{
		"TACCTL_ETC=" + filepath.Join(w, "etc"),
		"TACCTL_STATE_DIR=" + filepath.Join(w, "state"),
		"TACCTL_LOG=" + filepath.Join(w, "log"),
		"TACCTL_BIN=" + filepath.Join(w, "bin"),
		"TACCTL_SYSTEMD_DIR=" + filepath.Join(w, "systemd"),
		"TACCTL_OVERRIDE_DIR=" + filepath.Join(w, "systemd", "tacquito.service.d"),
		"TACCTL_SETTLE_SECONDS=0",
	}, extraEnv...)
	e.p = paths.Resolve(paths.NewEnv(vars), "", func(string) bool { return false })
	reg := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	out := ui.Output{Stdout: e.stdout, Stderr: e.stderr}
	snaps := snapshot.New(e.p, "0.2.0-test", nil, out)
	snaps.Chown = nil
	e.env = &backend.Env{
		Paths:     e.p,
		Conf:      conf.Load(e.p.Overrides, reg.IDs()),
		Runner:    e.run,
		Out:       out,
		Stdin:     strings.NewReader(""),
		Now:       time.Now,
		Snapshots: snaps,
	}
	e.env.Conf.Owner = nil
	e.b = New(e.env)
	e.b.Chown = func(string) {}
	e.b.Sleep = func(_ context.Context, d time.Duration) { e.sleeps = append(e.sleeps, d) }
	if err := reg.Add(backend.TACACS, func(*backend.Env) backend.Backend { return e.b }); err != nil {
		t.Fatal(err)
	}
	e.set = backend.NewSet(reg, e.env)
	return e
}

// withStore places tests/fixtures/<name> as the store (load_store_fixture).
func (e *tenv) withStore(name string) *tenv {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(fixDir, name))
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(e.p.StoreFile, data, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return e
}

// render is 'tacctl config render [--force]'; the output so far is
// forgotten afterwards.
func (e *tenv) render(force bool) {
	e.t.Helper()
	if err := e.set.ConfigRender(context.Background(), force); err != nil {
		e.t.Fatalf("config render: %v\n%s", err, e.stderr)
	}
	e.reset()
}

// reset forgets the calls and the output so far.
func (e *tenv) reset() {
	e.run.Reset()
	e.stdout.Reset()
	e.stderr.Reset()
	e.sleeps = nil
}

// stdin feeds the prompts.
func (e *tenv) stdin(s string) {
	e.env.Stdin = strings.NewReader(s)
	e.env.Prompter = nil
}

// writeOverrides writes tacctl.yaml by hand and has the view follow.
func (e *tenv) writeOverrides(text string) {
	e.t.Helper()
	writeFile(e.t, e.p.Overrides, text)
	e.env.Conf.Reload()
}

// legacyDropIn writes the hand-managed drop-in of an install from before
// the listener model, holding KEY=VALUE settings.
func (e *tenv) legacyDropIn(kv ...string) {
	e.t.Helper()
	text := "[Service]\n"
	for _, s := range kv {
		text += "Environment=\"" + s + "\"\n"
	}
	writeFile(e.t, e.b.overrideFile(), text)
}

func (e *tenv) dropIn(name string) string { return rtacacs.DropIn(e.b.paths(), name) }

// failActive makes 'systemctl is-active' fail for units matching re
// (systemctl_fails_for).
func (e *tenv) failActive(re string) {
	rx := regexp.MustCompile(re)
	e.run.Func(func(c execx.Cmd) bool {
		return c.Name == "systemctl" && len(c.Args) > 0 && c.Args[0] == "is-active" && rx.MatchString(strings.Join(c.Argv(), " "))
	}, func(execx.Cmd) (execx.Result, error) { return execx.Result{Code: 3}, nil })
}

// called is stub_called: some call's argv, space-joined, matches re.
func (e *tenv) called(re string) bool { return e.run.CalledRegexp(re) }

func (e *tenv) countCalls(re string) int {
	rx := regexp.MustCompile(re)
	n := 0
	for _, a := range e.run.Argvs() {
		if rx.MatchString(a) {
			n++
		}
	}
	return n
}

// state is a checksum line per file (sha256sum), "absent" for a missing one.
func state(files ...string) string {
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			b.WriteString(f + " absent\n")
			continue
		}
		sum := sha256.Sum256(data)
		b.WriteString(f + " " + hex.EncodeToString(sum[:]) + "\n")
	}
	return b.String()
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func writeFile(t *testing.T, p, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func hasLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

func mustLine(t *testing.T, text, line string) {
	t.Helper()
	if !hasLine(text, line) {
		t.Fatalf("no line %q in\n%s", line, text)
	}
}

func mustContain(t *testing.T, text, sub string) {
	t.Helper()
	if !strings.Contains(text, sub) {
		t.Fatalf("no %q in\n%s", sub, text)
	}
}

func mustNotContain(t *testing.T, text, sub string) {
	t.Helper()
	if strings.Contains(text, sub) {
		t.Fatalf("unexpected %q in\n%s", sub, text)
	}
}

// mustMatchLine: some line matches re (assert_line --regexp).
func mustMatchLine(t *testing.T, text, re string) {
	t.Helper()
	rx := regexp.MustCompile(re)
	for _, l := range strings.Split(text, "\n") {
		if rx.MatchString(l) {
			return
		}
	}
	t.Fatalf("no line matching %q in\n%s", re, text)
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	if got := backend.ExitCode(err); got != code {
		t.Fatalf("exit status %d (%v), want %d", got, err, code)
	}
}

// recorded reports whether rendered.json records path.
func (e *tenv) recorded(path string) bool {
	e.t.Helper()
	w, err := rendered.Check(e.p.Rendered, path)
	if err != nil {
		e.t.Fatal(err)
	}
	return w == rendered.OK
}

// envOf is the value of Environment="<key>=..." in a drop-in.
func envOf(t *testing.T, path, key string) string {
	t.Helper()
	val := ""
	for _, l := range strings.Split(readFile(t, path), "\n") {
		if v, ok := strings.CutPrefix(l, `Environment="`+key+"="); ok {
			val = strings.TrimSuffix(v, `"`)
		}
	}
	return val
}

// noKeep: no rollback copies left in the state directory.
func (e *tenv) noKeep() {
	e.t.Helper()
	if m, _ := filepath.Glob(filepath.Join(e.p.StateDir, ".units.*")); len(m) != 0 {
		e.t.Fatalf("left %v", m)
	}
}

func (e *tenv) snapshots() []string { return snapshot.IDs(e.p.BackupDir) }
