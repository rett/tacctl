package store_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

const fixtures = "../../tests/fixtures/"

// hashA is the hex of '$2b$12$' + 53 'A' (store.bats HASH_A).
var hashA = "24326224313224" + strings.Repeat("41", 53)

// builtins is store.bats' BUILTINS block.
const builtins = `groups:
  readonly:  {priv_lvl: 1,  juniper_class: RO-CLASS, builtin: true}
  operator:  {priv_lvl: 7,  juniper_class: OP-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}`

// env is a scratch state directory with a store path in it.
type env struct {
	t    *testing.T
	dir  string
	path string
	now  time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return &env{t: t, dir: dir, path: filepath.Join(dir, "store.yaml"),
		now: time.Date(2026, 10, 3, 12, 0, 0, 0, time.Local)}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// useFixture is use_store_fixture: copy a store fixture into place, 0600.
func (e *env) useFixture(name string) {
	e.t.Helper()
	if err := os.WriteFile(e.path, readFile(e.t, fixtures+name), 0o600); err != nil {
		e.t.Fatal(err)
	}
	if err := os.Chmod(e.path, 0o600); err != nil {
		e.t.Fatal(err)
	}
}

// mutate is store_mutate with the given op; it returns the error report
// as 0.1.16 prints it ("" on success).
func (e *env) mutate(fn func(*store.Store) error) string {
	e.t.Helper()
	_, err := store.Mutate(e.path, store.MutateOptions{Now: func() time.Time { return e.now }}, fn)
	if err != nil {
		return store.Report(err)
	}
	return ""
}

func (e *env) mustMutate(fn func(*store.Store) error) {
	e.t.Helper()
	if msg := e.mutate(fn); msg != "" {
		e.t.Fatalf("mutation failed: %s", msg)
	}
}

func userSet(name string, f ...string) func(*store.Store) error {
	return func(s *store.Store) error { return s.UserSet(name, f...) }
}

func groupSet(name string, f ...string) func(*store.Store) error {
	return func(s *store.Store) error { return s.GroupSet(name, f...) }
}

func scopeSet(name string, f ...string) func(*store.Store) error {
	return func(s *store.Store) error { return s.ScopeSet(name, f...) }
}

// get is the model_<kind> accessor on the store at e.path: the output
// (lines joined by newlines) and the status.
func (e *env) get(kind string, args ...string) (string, int) {
	e.t.Helper()
	s, err := store.Load(e.path)
	if err != nil {
		e.t.Fatalf("load: %v", err)
	}
	lines, code, err := model.Get(s, kind, args...)
	if err != nil {
		return store.Report(err), 1
	}
	return strings.Join(lines, "\n"), code
}

func (e *env) mustGet(kind string, args ...string) string {
	e.t.Helper()
	out, code := e.get(kind, args...)
	if code != 0 {
		e.t.Fatalf("model_%s %v: status %d: %s", kind, args, code, out)
	}
	return out
}

// validateYAML is store.bats validate_yaml: write the body and validate
// it, returning the 'tacctl store: ' lines and whether it is valid.
func (e *env) validateYAML(body string) (string, bool) {
	e.t.Helper()
	p := filepath.Join(filepath.Dir(e.dir), "candidate.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		e.t.Fatal(err)
	}
	return validateFile(p)
}

func validateFile(p string) (string, bool) {
	errs, err := store.ValidateFile(p)
	if err != nil {
		return store.Report(err), false
	}
	var out []string
	for _, m := range errs {
		out = append(out, "tacctl store: "+m)
	}
	return strings.Join(out, "\n"), len(errs) == 0
}

func contains(t *testing.T, out, want string) {
	t.Helper()
	if !strings.Contains(out, want) {
		t.Errorf("output does not contain %q:\n%s", want, out)
	}
}

func refute(t *testing.T, out, unwanted string) {
	t.Helper()
	if strings.Contains(out, unwanted) {
		t.Errorf("output contains %q:\n%s", unwanted, out)
	}
}

func equal(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return statIno(st)
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, ".store.*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}
