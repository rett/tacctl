package tacacs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
)

// The TACACS+ module's own tests of tests/unit/backend.bats (WP2.1 ported
// the registry and the machinery; these are the module's verbs) and the
// contract test over the real module.

func TestContract(t *testing.T) {
	e := newTenv(t)
	faketest.CheckContract(t, e.b)
	if !backend.Default().Has(backend.TACACS) {
		t.Fatal("the module did not register itself")
	}
	b, err := backend.NewSet(backend.Default(), e.env).Get(backend.TACACS)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b.(*Backend); !ok || b.ID() != "tacacs" {
		t.Fatalf("the registry makes %T", b)
	}
}

// "backend_describe: one value by key".
func TestDescribe(t *testing.T) {
	e := newTenv(t)
	d := e.b.Describe()
	want := backend.Description{Protocol: "tacacs", Impl: "tacquito", Units: []string{"tacquito.service"}, User: "tacquito",
		ConfigDir: e.p.Etc, LogDir: e.p.Log, ImportCmd: "tacctl store import --replace"}
	if d.Protocol != want.Protocol || d.Impl != want.Impl || !slices.Equal(d.Units, want.Units) || d.User != want.User ||
		d.ConfigDir != want.ConfigDir || d.LogDir != want.LogDir || d.ImportCmd != want.ImportCmd {
		t.Fatalf("%+v\nwant %+v", d, want)
	}
}

// "tacacs artifacts: the rendered tacquito.yaml, then the default
// listener's drop-in".
func TestArtifacts(t *testing.T) {
	e := newTenv(t)
	dropin := filepath.Join(e.p.OverrideDir, "tacctl.conf")
	if got := e.b.Artifacts(); !slices.Equal(got, []string{e.p.Config, dropin}) {
		t.Fatalf("artifacts %v", got)
	}
	if got := e.set.AllArtifactNames(); got != e.p.Config+", "+dropin {
		t.Fatalf("names %q", got)
	}
}

// "tacacs artifacts: an install whose hand-managed drop-in is still there
// has no rendered one".
func TestArtifactsNotConverted(t *testing.T) {
	e := newTenv(t)
	e.legacyDropIn("TACQUITO_LEVEL=30")
	if got := e.b.Artifacts(); !slices.Equal(got, []string{e.p.Config}) {
		t.Fatalf("artifacts %v", got)
	}
}

// "tacacs installed: needs the daemon binary and the unit file".
func TestInstalled(t *testing.T) {
	e := newTenv(t)
	if e.b.Installed() {
		t.Fatal("installed with nothing")
	}
	writeFile(t, e.b.serviceFile(), "")
	if e.b.Installed() {
		t.Fatal("installed without the binary")
	}
	writeFile(t, e.b.tacquitoBin(), "#!/bin/sh\n")
	if e.b.Installed() {
		t.Fatal("installed with a binary that is not executable")
	}
	if err := os.Chmod(e.b.tacquitoBin(), 0o755); err != nil {
		t.Fatal(err)
	}
	if !e.b.Installed() {
		t.Fatal("not installed")
	}
}

// "tacacs last_login: newest cmd=login of the user in the accounting log,
// else never", and listeners.bats "last login ... read every listener's
// accounting log".
func TestLastLogin(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	if got, _ := e.b.LastLogin(ctx, "alice"); got != "never" {
		t.Fatalf("got %q", got)
	}
	writeFile(t, e.p.AcctLog, `2026/04/20 09:00:00 {"User":"alice","Args":["cmd=login"]}
2026/04/21 10:11:12 {"User":"alice","Args":["cmd=login"]}
2026/04/22 08:00:00 {"User":"alice","Args":["cmd=logout"]}
2026/04/23 08:00:00 {"User":"bob","Args":["cmd=login"]}
`)
	if got, _ := e.b.LastLogin(ctx, "alice"); got != "2026-04-21 10:11:12" {
		t.Fatalf("got %q", got)
	}
	if got := e.set.LastLogin(ctx, "alice"); got != "2026-04-21 10:11:12" {
		t.Fatalf("backends_last_login %q", got)
	}
	if got := e.set.LastLogin(ctx, "carol"); got != "never" {
		t.Fatalf("carol %q", got)
	}
	// Another listener's log holds a newer login.
	writeFile(t, filepath.Join(e.p.Log, "accounting-mgmt.log"), `2026/05/02 08:00:00 {"User":"alice","Args":["cmd=login"]}`+"\n")
	if got, _ := e.b.LastLogin(ctx, "alice"); got != "2026-05-02 08:00:00" {
		t.Fatalf("got %q", got)
	}
	// "al" is not alice.
	if got, _ := e.b.LastLogin(ctx, "al"); got != "never" {
		t.Fatalf("got %q", got)
	}
}

// "tacacs secret_constraints and device_vars: no limit, no variables".
func TestSecretConstraintsAndDeviceVars(t *testing.T) {
	e := newTenv(t)
	if c := e.b.SecretConstraints(); c.MaxLen != 0 || c.Charset != "" {
		t.Fatalf("%+v", c)
	}
	v, err := e.b.DeviceVars(context.Background(), "cisco", "lab")
	if err != nil || len(v) != 0 {
		t.Fatalf("%v %v", v, err)
	}
}

// "tacacs status and log: an unknown part is refused (2)", writing nothing.
func TestUnknownPartsAreRefused(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	var w recorder
	for name, err := range map[string]error{
		"status nope":     e.b.Status(ctx, "nope", &w),
		"status summary":  e.b.Status(ctx, backend.StatusSummary, &w),
		"log nope":        e.b.Log(ctx, "nope", nil, &w),
		"accounting nope": e.b.Accounting(ctx, "nope", nil, &w),
	} {
		if !errors.Is(err, backend.ErrUnsupported) || backend.ExitCode(err) != 2 {
			t.Fatalf("%s: %v", name, err)
		}
	}
	_, err := e.b.Service(ctx, "frobnicate", "")
	wantCode(t, err, 2)
	if w.n != 0 || e.stdout.Len() != 0 || e.stderr.Len() != 0 || len(e.run.Calls()) != 0 {
		t.Fatalf("wrote %d %q %q %v", w.n, e.stdout, e.stderr, e.run.Argvs())
	}
}

type recorder struct{ n int }

func (r *recorder) Write(p []byte) (int, error) {
	r.n += len(p)
	return len(p), nil
}
