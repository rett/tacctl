package faketest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

var ctx = context.Background()

func newFake(t *testing.T) (*Backend, *backend.Env, *bytes.Buffer) {
	t.Helper()
	w := t.TempDir()
	p := paths.Resolve(paths.NewEnv([]string{"TACCTL_STATE_DIR=" + w, "TACCTL_ETC=" + w}), "", func(string) bool { return false })
	stderr := &bytes.Buffer{}
	env := &backend.Env{Paths: p, Out: ui.Output{Stdout: io.Discard, Stderr: stderr}}
	b := New("", filepath.Join(w, "fake.conf"), filepath.Join(w, "fakestate"))
	Factory(b)(env)
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "tests", "fixtures", "store.multiscope.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.StoreFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return b, env, stderr
}

func TestFakeRendersUserNamesAndRecordsThem(t *testing.T) {
	b, env, _ := newFake(t)
	if b.ID() != "fake" {
		t.Fatal(b.ID())
	}
	dir := t.TempDir()
	if err := b.RenderStage(ctx, dir, false); err != nil {
		t.Fatal(err)
	}
	staged, _ := os.ReadFile(filepath.Join(dir, StagedName))
	if string(staged) != "alice\nbob\ncarol\n" {
		t.Fatalf("staged %q", staged)
	}
	if changed, err := b.RenderCommit(ctx, dir); err != nil || !changed {
		t.Fatalf("%v %v", changed, err)
	}
	if w, _ := rendered.Check(env.Paths.Rendered, b.Conf); w != rendered.OK {
		t.Fatal(w)
	}
	if changed, err := b.RenderCommit(ctx, dir); err != nil || changed {
		t.Fatalf("second commit %v %v", changed, err)
	}
	b.Render = func(*store.Store) []byte { return []byte("custom\n") }
	if err := b.RenderStage(ctx, dir, true); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(b.Calls(), ","); got != "stage,commit,commit,stage --force" {
		t.Fatal(got)
	}
	if !b.Called("commit") || b.Called("gate") {
		t.Fatal("Called")
	}
	b.ResetCalls()
	if len(b.Calls()) != 0 {
		t.Fatal("ResetCalls")
	}
}

func TestFakeFailureKnobs(t *testing.T) {
	b, env, stderr := newFake(t)
	b.Gate = backend.GateRefused
	if b.RenderGate(ctx) != backend.GateRefused {
		t.Fatal("gate")
	}
	b.Fail = "stage"
	if err := b.RenderStage(ctx, t.TempDir(), false); !errors.Is(err, backend.ErrFailed) ||
		!strings.Contains(stderr.String(), "fake: cannot express this model") {
		t.Fatalf("%v %q", err, stderr)
	}
	b.Fail = "refuse"
	if err := b.RenderStage(ctx, t.TempDir(), false); !errors.Is(err, backend.ErrRefused) {
		t.Fatal(err)
	}
	b.Fail = "commit"
	if _, err := b.RenderCommit(ctx, t.TempDir()); !errors.Is(err, backend.ErrFailed) {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(b.Conf); string(data) != "half a fake render\n" {
		t.Fatalf("%q", data)
	}
	if data, _ := os.ReadFile(env.Paths.Rendered); string(data) != "{}\n" {
		t.Fatalf("%q", data)
	}
	// A store that cannot be read fails the stage.
	b.Fail = ""
	_ = os.WriteFile(env.Paths.StoreFile, []byte(": : :\n"), 0o600)
	if err := b.RenderStage(ctx, t.TempDir(), false); !errors.Is(err, backend.ErrFailed) {
		t.Fatal(err)
	}
	if _, err := b.RenderCommit(ctx, filepath.Join(t.TempDir(), "nothing staged")); err == nil {
		t.Fatal("commit of nothing")
	}
	// Without an Env it cannot render.
	if err := New("x", "/x", t.TempDir()).RenderStage(ctx, t.TempDir(), false); err == nil {
		t.Fatal("rendered without an Env")
	}
}

func TestFakeLifecycleAndService(t *testing.T) {
	b, _, stderr := newFake(t)
	if b.Installed() || b.Active() != "inactive" || b.Boot() != "" {
		t.Fatal("fresh state")
	}
	for _, p := range backend.InstallPhases {
		if err := b.Install(ctx, p, "/tree"); err != nil {
			t.Fatal(err)
		}
	}
	if !b.Installed() || b.Active() != "active" || b.Boot() != "enabled" {
		t.Fatalf("after install: %v %s %s", b.Installed(), b.Active(), b.Boot())
	}
	if !b.Called("install start /tree") {
		t.Fatal(b.Calls())
	}
	b.PhaseFail = backend.PhaseFiles
	if err := b.Install(ctx, backend.PhaseFiles, "/tree"); !errors.Is(err, backend.ErrFailed) ||
		!strings.Contains(stderr.String(), "fake: files failed") {
		t.Fatalf("%v %q", err, stderr)
	}
	if b.Upgrade(ctx, backend.PhaseFinish, "") != nil || b.Uninstall(ctx, backend.PhaseData, true) != nil {
		t.Fatal("upgrade/uninstall")
	}
	if s, err := b.Service(ctx, backend.ServiceIsActive, ""); s != "active" || err != nil {
		t.Fatal(s, err)
	}
	if _, err := b.Service(ctx, backend.ServiceStop, ""); err != nil || b.Active() != "inactive" {
		t.Fatal(err)
	}
	if s, err := b.Service(ctx, backend.ServiceIsActive, ""); s != "inactive" || backend.ExitCode(err) != 3 {
		t.Fatal(s, err)
	}
	b.StartFails = true
	_, _ = b.Service(ctx, backend.ServiceRestart, "auth")
	if b.Active() != "failed" || !b.Called("service restart auth") {
		t.Fatal(b.Active(), b.Calls())
	}
	b.StopFails = true
	if _, err := b.Service(ctx, backend.ServiceStop, ""); !errors.Is(err, backend.ErrFailed) {
		t.Fatal(err)
	}
	_, _ = b.Service(ctx, backend.ServiceDisable, "")
	if b.Boot() != "disabled" {
		t.Fatal(b.Boot())
	}
	_, _ = b.Service(ctx, backend.ServiceEnable, "")
	if b.Boot() != "enabled" {
		t.Fatal(b.Boot())
	}
	if s, _ := b.Service(ctx, backend.ServiceSince, ""); s == "" {
		t.Fatal("since")
	}
	if s, _ := b.Service(ctx, backend.ServicePID, ""); s != "777" {
		t.Fatal("pid")
	}
	b.SetInstalled(false)
	if b.Installed() {
		t.Fatal("SetInstalled(false)")
	}
}

func TestFakeReports(t *testing.T) {
	b, _, _ := newFake(t)
	var w bytes.Buffer
	for _, p := range []backend.StatusPart{backend.StatusService, backend.StatusConfig, backend.StatusAccounting, backend.StatusActivity} {
		if err := b.Status(ctx, p, &w); err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(w.String(), "Fake config:") || !strings.Contains(w.String(), "quiet") {
		t.Fatalf("%q", w.String())
	}
	if err := b.Status(ctx, backend.StatusSummary, &w); !errors.Is(err, backend.ErrUnsupported) {
		t.Fatal(err)
	}
	w.Reset()
	_ = b.Log(ctx, "tail", []string{"5"}, &w)
	_ = b.Accounting(ctx, "tail", nil, &w)
	if w.String() != "fake log tail 5\nfake accounting tail\n" {
		t.Fatalf("%q", w.String())
	}
	ls, err := b.Listeners().List()
	if err != nil || len(ls) != 2 || ls[0] != (backend.Listener{Name: "auth", Network: "udp", Address: ":1812"}) {
		t.Fatal(ls, err)
	}
	b.Listen6 = true
	if ls, _ := b.Listeners().List(); ls[0].Network != "udp6" {
		t.Fatal(ls)
	}
	if _, err := b.Listeners().Show(ctx, "auth"); !errors.Is(err, backend.ErrUnsupported) {
		t.Fatal(err)
	}
	if b.Listeners().Set(ctx, "a", "udp", ":1") == nil || b.Listeners().Reset(ctx, "a") == nil {
		t.Fatal("set/reset")
	}
	if s, _ := b.LastLogin(ctx, "alice"); s != "never" {
		t.Fatal(s)
	}
	b.LastLoginAt = "2026-01-01 00:00:00"
	if s, _ := b.LastLogin(ctx, "alice"); s != b.LastLoginAt {
		t.Fatal(s)
	}
	if b.SecretConstraints() != (backend.Constraints{}) {
		t.Fatal("constraints")
	}
	if v, err := b.DeviceVars(ctx, "cisco", "lab"); v != nil || err != nil {
		t.Fatal(v, err)
	}
	if c, _ := b.RenderCheck(ctx); c != rendered.Current {
		t.Fatal(c)
	}
	b.Check = rendered.Drift
	if c, _ := b.RenderCheck(ctx); c != rendered.Drift {
		t.Fatal(c)
	}
	b.RenderNotes(ctx)
	if d := b.Describe(); d.Protocol != "fake" || d.LogDir != b.Dir {
		t.Fatal(d)
	}
	if New("x", "/x", "/d").out().Stdout != io.Discard {
		t.Fatal("out without an Env")
	}
}

func TestCheckContractPassesTheStandIn(t *testing.T) {
	b, _, _ := newFake(t)
	CheckContract(t, b)
}

// broken breaks every rule CheckContract checks.
type broken struct{ *Backend }

func (broken) ID() string                                           { return "tacacss" }
func (broken) Describe() backend.Description                        { return backend.Description{} }
func (broken) Artifacts() []string                                  { return []string{"rel/path", "rel/path"} }
func (broken) Install(context.Context, backend.Phase, string) error { return errors.New("x") }
func (broken) Upgrade(context.Context, backend.Phase, string) error { return errors.New("x") }
func (broken) Uninstall(context.Context, backend.Phase, bool) error { return errors.New("x") }
func (broken) Status(_ context.Context, _ backend.StatusPart, w io.Writer) error {
	_, _ = io.WriteString(w, "oops")
	return nil
}

type collect struct {
	testing.TB
	errs []string
}

func (c *collect) Helper()                        {}
func (c *collect) Errorf(format string, a ...any) { c.errs = append(c.errs, fmt.Sprintf(format, a...)) }

func TestCheckContractFindsEveryBreach(t *testing.T) {
	b, _, _ := newFake(t)
	c := &collect{TB: t}
	CheckContract(c, broken{b})
	want := []string{"not a valid registry id", "no protocol", "not an absolute path", "listed twice",
		"install of an unknown phase", "upgrade of an unknown phase", "uninstall of an unknown phase",
		"status nope", "wrote 4 bytes"}
	all := strings.Join(c.errs, "\n")
	for _, w := range want {
		if !strings.Contains(all, w) {
			t.Errorf("no %q in:\n%s", w, all)
		}
	}
}
