package app

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// The registry needs a module for the enabled-list checks; a do-nothing
// factory is enough (the services never call one).
func init() {
	if !backend.Default().Has(backend.TACACS) {
		backend.Register(backend.TACACS, func(*backend.Env) backend.Backend { return nil })
	}
}

func newServiceApp(t *testing.T, stdin string, env ...string) (*App, *bytes.Buffer, *bytes.Buffer, *fake.Runner) {
	t.Helper()
	w := t.TempDir()
	for _, d := range []string{"etc", "state"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	r := &fake.Runner{}
	a := New(nil, paths.NewEnv(append([]string{"TACCTL_ETC=" + w + "/etc", "TACCTL_STATE_DIR=" + w + "/state"}, env...)),
		"", 0, Stdio{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb}, r)
	return a, &out, &errb, r
}

func write(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestServicesAreMadeOnce(t *testing.T) {
	a, _, _, _ := newServiceApp(t, "y\nn\n")
	c, p, sn, e, set := a.Conf(), a.Prompter(), a.Snapshots(), a.BackendEnv(), a.Backends()
	if c != a.Conf() || p != a.Prompter() || sn != a.Snapshots() || e != a.BackendEnv() || set != a.Backends() {
		t.Fatal("a service was made twice")
	}
	env := a.BackendEnv()
	if env.Prompter != a.Prompter() || env.Prompt() != a.Prompter() || env.Conf != a.Conf() || env.Snapshots != a.Snapshots() {
		t.Fatal("the backend Env does not share the App's services")
	}
	// One buffer: two prompts, one from each side, read two lines.
	if !a.Prompter().Confirm("? ") || env.Prompt().Confirm("? ") {
		t.Error("prompts do not share stdin")
	}
	if a.Backends().Env != env || a.MutateOptions().Snapshot == nil {
		t.Error("Backends or MutateOptions not wired to the Env")
	}
	if a.Tunables().BcryptCost != 12 {
		t.Errorf("Tunables %+v", a.Tunables())
	}
}

func TestPrompterWithoutStdin(t *testing.T) {
	a, _, _, _ := newServiceApp(t, "")
	a.Stdin = nil
	if a.Prompter().Confirm("? ") {
		t.Error("no stdin answered yes")
	}
}

func TestWarnConfOnce(t *testing.T) {
	a, out, errb, _ := newServiceApp(t, "")
	write(t, a.Paths.Overrides, "a: [\n")
	a.WarnConf()
	a.WarnConf()
	if n := strings.Count(errb.String(), "[WARN]"); n != 1 || out.Len() != 0 ||
		!strings.Contains(errb.String(), "tacctl.yaml: could not parse "+a.Paths.Overrides) {
		t.Errorf("warning: %q", errb.String())
	}
	b, _, errb2, _ := newServiceApp(t, "")
	b.WarnConf()
	if errb2.Len() != 0 {
		t.Errorf("a missing tacctl.yaml warned: %q", errb2.String())
	}
}

func TestPreflight(t *testing.T) {
	a, out, errb, _ := newServiceApp(t, "")
	if err := a.Preflight(); !errors.Is(err, ui.ErrReported) ||
		errb.String() != "\033[0;31m[ERROR]\033[0m Config not found: no store at "+a.Paths.StoreFile+" and no "+a.Paths.Config+". Is tacctl installed? (tacctl install)\n" {
		t.Errorf("nothing: %v %q", err, errb.String())
	}
	errb.Reset()
	write(t, a.Paths.StoreFile, "version: 1\n")
	if err := a.Preflight(); err != nil || out.Len() != 0 ||
		errb.String() != "\033[1;33m[WARN]\033[0m TACACS+ is enabled and "+a.Paths.Config+" is missing; 'tacctl config render' writes it again.\n" {
		t.Errorf("store, no tacquito.yaml: %v %q", err, errb.String())
	}
	errb.Reset()
	write(t, a.Paths.Config, "x")
	if err := a.Preflight(); err != nil || errb.Len() != 0 {
		t.Errorf("both: %v %q", err, errb.String())
	}
	// Legacy mode: tacquito.yaml only.
	c, _, errc, _ := newServiceApp(t, "")
	write(t, c.Paths.Config, "x")
	if err := c.Preflight(); err != nil || errc.Len() != 0 {
		t.Errorf("legacy: %v %q", err, errc.String())
	}
	// TACACS+ not enabled: no warning.
	d, _, errd, _ := newServiceApp(t, "")
	write(t, d.Paths.StoreFile, "version: 1\n")
	write(t, d.Paths.Overrides, "backends:\n  enabled: [radius]\n")
	_ = d.Preflight()
	if errd.Len() != 0 {
		t.Errorf("radius only: %q", errd.String())
	}
}

func TestLoadModelAndPaths(t *testing.T) {
	a, _, _, _ := newServiceApp(t, "")
	var ns *model.NoSourceError
	if _, err := a.LoadModel(); !errors.As(err, &ns) {
		t.Errorf("no source: %v", err)
	}
	p := a.ModelPaths()
	if p.Store != a.Paths.StoreFile || p.Config != a.Paths.Config || p.DatesDir != a.Paths.PWDatesDir ||
		p.DisabledDir != filepath.Join(a.Paths.BackupDir, "disabled") {
		t.Errorf("ModelPaths %+v", p)
	}
	data, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	write(t, a.Paths.StoreFile, string(data))
	m, err := a.LoadModel()
	if err != nil || m.User("alice") == nil {
		t.Errorf("store: %v", err)
	}
}

func TestLogger(t *testing.T) {
	a, _, _, r := newServiceApp(t, "")
	r.Fail([]string{"logger"}, 1, "no journal")
	a.Logger(context.Background(), "auth.info", "hello world")
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "hello world") {
		t.Errorf("calls %q", r.Argvs())
	}
}

func TestKnobsAreLoaded(t *testing.T) {
	a, _, _, _ := newServiceApp(t, "", "TACCTL_TEST_RANDOM=zz")
	if TestKnobs != (a.KnobsErr != nil) {
		t.Errorf("TestKnobs %v, KnobsErr %v", TestKnobs, a.KnobsErr)
	}
}
