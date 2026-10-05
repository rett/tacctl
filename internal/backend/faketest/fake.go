// Package faketest is a stand-in backend for tests of the backend
// machinery and of the commands built on it: the 'fake' backend of
// tests/integration/backend_mutation.bats and backend_cli.bats as a Go
// type. It renders one artifact (the store's user names, one per line,
// sorted), records it in rendered.json as a module does, keeps its service
// state in a directory, and logs every call. Its knobs are fields:
//
//	Gate       its RenderGate's answer (FAKE_GATE)
//	Fail       "stage" | "commit": the render step that fails (FAKE_FAIL);
//	           "refuse": its stage refuses, as for drift without force
//	PhaseFail  an install phase that fails (FAKE_PHASE_FAIL)
//	StartFails a start or restart leaves the service not active (FAKE_START=failed)
//	StopFails  'service stop' fails (FAKE_STOP_FAIL)
//	Check      what its RenderCheck returns (FAKE_CHECK; default current)
//	Listen6    its auth listener is udp6 (FAKE_LISTEN6)
//	Sights     the sightings its log holds (backend.Sighter), in order;
//	           SightErr fails the read
//
// CheckContract runs the checks every module must pass (the contract test
// of tests/unit/backend.bats) over any Backend.
package faketest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// StagedName is the file RenderStage writes in its directory.
const StagedName = "fake.conf"

// Backend is the stand-in. Make it with New; set the knobs before use.
type Backend struct {
	// Name is the registry id (default "fake").
	Name string
	// Conf is the artifact it renders (FAKE_CONF).
	Conf string
	// Dir holds its state: installed, active, boot (FAKE_DIR).
	Dir string
	// Env is set by Factory when a Set makes the backend.
	Env *backend.Env

	Gate       backend.GateResult
	Fail       string
	PhaseFail  backend.Phase
	StartFails bool
	StopFails  bool
	Check      string
	Listen6    bool
	// LastLoginAt is what LastLogin returns ("" is "never").
	LastLoginAt string
	// Sights are the sightings its log holds, in log order; Sightings
	// resumes after the ones it returned before. SightErr fails it.
	Sights   []backend.Sighting
	SightErr error

	// Render, when set, replaces the rendering of the artifact (default:
	// the user names).
	Render func(s *store.Store) []byte
	// OnStage, when set, runs at the start of every RenderStage (to look at
	// the other backends' artifacts at that moment).
	OnStage func(dir string)

	mu  sync.Mutex
	log []string
}

// New is a stand-in with id name rendering conf, its state under dir.
func New(name, conf, dir string) *Backend {
	return &Backend{Name: name, Conf: conf, Dir: dir}
}

// Factory registers b: a Set gets b itself, with the Set's Env.
func Factory(b *Backend) backend.Factory {
	return func(env *backend.Env) backend.Backend {
		b.Env = env
		return b
	}
}

var _ backend.Backend = (*Backend)(nil)

func (b *Backend) note(format string, a ...any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log = append(b.log, fmt.Sprintf(format, a...))
}

// Calls is every call so far, one line each (FAKE_LOG): "gate", "stage"
// or "stage --force", "commit", "service <action>[ <listener>]",
// "install <phase> <tree>", ...
func (b *Backend) Calls() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.log...)
}

// ResetCalls empties the call log.
func (b *Backend) ResetCalls() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.log = nil
}

// Called reports whether line is in the call log.
func (b *Backend) Called(line string) bool {
	for _, l := range b.Calls() {
		if l == line {
			return true
		}
	}
	return false
}

func (b *Backend) out() ui.Output {
	if b.Env == nil {
		return ui.Output{Stdout: io.Discard, Stderr: io.Discard}
	}
	return b.Env.Out
}

func (b *Backend) state(name string) string {
	data, err := os.ReadFile(filepath.Join(b.Dir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func (b *Backend) setState(name, value string) {
	_ = os.MkdirAll(b.Dir, 0o755)
	_ = os.WriteFile(filepath.Join(b.Dir, name), []byte(value+"\n"), 0o644)
}

func (b *Backend) up() {
	if b.StartFails {
		b.setState("active", "failed")
	} else {
		b.setState("active", "active")
	}
}

// SetInstalled marks it installed (or not).
func (b *Backend) SetInstalled(on bool) {
	if on {
		b.setState("installed", "")
	} else {
		_ = os.Remove(filepath.Join(b.Dir, "installed"))
	}
}

// Active is its service state word (inactive when never started).
func (b *Backend) Active() string {
	if s := b.state("active"); s != "" {
		return s
	}
	return "inactive"
}

// Boot is its boot-time state ("enabled", "disabled" or "").
func (b *Backend) Boot() string { return b.state("boot") }

// ID implements backend.Backend.
func (b *Backend) ID() string {
	if b.Name == "" {
		return "fake"
	}
	return b.Name
}

// Describe implements backend.Backend.
func (b *Backend) Describe() backend.Description {
	return backend.Description{Protocol: "fake", Impl: "faked", Units: []string{"fake.service"}, LogDir: b.Dir}
}

// Installed implements backend.Backend.
func (b *Backend) Installed() bool {
	_, err := os.Stat(filepath.Join(b.Dir, "installed"))
	return err == nil
}

// Install implements backend.Backend: 'account' marks it installed,
// 'start' enables and starts it; PhaseFail fails that phase.
func (b *Backend) Install(_ context.Context, phase backend.Phase, tree string) error {
	b.note("install %s %s", phase, tree)
	if b.PhaseFail != "" && phase == b.PhaseFail {
		b.out().Error("fake: " + string(phase) + " failed")
		return backend.ErrFailed
	}
	switch phase {
	case backend.PhaseAccount:
		b.SetInstalled(true)
	case backend.PhaseStart:
		b.setState("boot", "enabled")
		b.up()
	}
	return nil
}

// Upgrade implements backend.Backend (nothing to do).
func (b *Backend) Upgrade(context.Context, backend.Phase, string) error { return nil }

// Uninstall implements backend.Backend (nothing to do).
func (b *Backend) Uninstall(context.Context, backend.Phase, bool) error { return nil }

// Artifacts implements backend.Backend.
func (b *Backend) Artifacts() []string { return []string{b.Conf} }

// RenderCheck implements backend.Backend.
func (b *Backend) RenderCheck(context.Context) (string, error) {
	if b.Check != "" {
		return b.Check, nil
	}
	return rendered.Current, nil
}

// RenderGate implements backend.Backend.
func (b *Backend) RenderGate(context.Context) backend.GateResult {
	b.note("gate")
	return b.Gate
}

// RenderStage implements backend.Backend.
func (b *Backend) RenderStage(_ context.Context, dir string, force bool) error {
	if force {
		b.note("stage --force")
	} else {
		b.note("stage")
	}
	if b.OnStage != nil {
		b.OnStage(dir)
	}
	switch b.Fail {
	case "stage":
		b.out().Error("fake: cannot express this model")
		return backend.ErrFailed
	case "refuse":
		b.out().Error("fake: " + b.Conf + " was edited since tacctl rendered it")
		return backend.ErrRefused
	}
	if b.Env == nil {
		return errors.New("fake: no Env")
	}
	st, err := store.Load(b.Env.Paths.StoreFile)
	if err != nil {
		b.out().Error(err.Error())
		return backend.ErrFailed
	}
	var text []byte
	if b.Render != nil {
		text = b.Render(st)
	} else {
		text = UserNames(st)
	}
	return os.WriteFile(filepath.Join(dir, StagedName), text, 0o600)
}

// UserNames is the default render: model_users, one name per line.
func UserNames(st *store.Store) []byte {
	var names []string
	if v, ok := st.Doc().Get("users"); ok {
		if m, ok := v.(*yamlpy.Map); ok {
			names = m.Keys()
		}
	}
	sort.Strings(names)
	var buf bytes.Buffer
	for _, n := range names {
		buf.WriteString(n + "\n")
	}
	return buf.Bytes()
}

// RenderCommit implements backend.Backend. Fail "commit" is the worst
// case: its artifact and the records are damaged, then it fails.
func (b *Backend) RenderCommit(_ context.Context, dir string) (bool, error) {
	b.note("commit")
	if b.Fail == "commit" {
		_ = os.WriteFile(b.Conf, []byte("half a fake render\n"), 0o644)
		if b.Env != nil {
			_ = os.WriteFile(b.Env.Paths.Rendered, []byte("{}\n"), 0o600)
		}
		return false, backend.ErrFailed
	}
	staged, err := os.ReadFile(filepath.Join(dir, StagedName))
	if err != nil {
		return false, err
	}
	if live, err := os.ReadFile(b.Conf); err == nil && bytes.Equal(live, staged) {
		return false, nil
	}
	if err := os.WriteFile(b.Conf, staged, 0o644); err != nil {
		return false, err
	}
	if err := rendered.Record(b.Env.Paths.Rendered, b.Conf); err != nil {
		return false, err
	}
	return true, nil
}

// RenderNotes implements backend.Backend (silent).
func (b *Backend) RenderNotes(context.Context) {}

// Service implements backend.Backend.
func (b *Backend) Service(_ context.Context, action backend.ServiceAction, listener string) (string, error) {
	if listener != "" {
		b.note("service %s %s", action, listener)
	} else {
		b.note("service %s", action)
	}
	switch action {
	case backend.ServiceStart, backend.ServiceRestart, backend.ServiceReload:
		b.up()
	case backend.ServiceStop:
		if b.StopFails {
			return "", backend.ErrFailed
		}
		b.setState("active", "inactive")
	case backend.ServiceEnable:
		b.setState("boot", "enabled")
	case backend.ServiceDisable:
		b.setState("boot", "disabled")
	case backend.ServiceIsActive:
		s := b.Active()
		if s != "active" {
			return s, &backend.Error{Code: 3, Reason: "not active"}
		}
		return s, nil
	case backend.ServiceSince:
		return "Fri 2026-10-02 10:00:00 UTC", nil
	case backend.ServicePID:
		return "777", nil
	default:
		return "", backend.ErrUnsupported
	}
	return "", nil
}

// Listeners implements backend.Backend.
func (b *Backend) Listeners() backend.ListenerOps { return listeners{b} }

type listeners struct{ b *Backend }

func (l listeners) List() ([]backend.Listener, error) {
	auth := backend.Listener{Name: "auth", Network: "udp", Address: ":1812"}
	if l.b.Listen6 {
		auth = backend.Listener{Name: "auth", Network: "udp6", Address: "[::]:1812"}
	}
	return []backend.Listener{auth, {Name: "acct", Network: "udp", Address: ":1813"}}, nil
}

func (l listeners) Show(context.Context, string) (string, error) { return "", backend.ErrUnsupported }

func (l listeners) Set(context.Context, string, string, string) error { return backend.ErrUnsupported }

func (l listeners) Reset(context.Context, string) error { return backend.ErrUnsupported }

// Status implements backend.Backend.
func (b *Backend) Status(_ context.Context, part backend.StatusPart, w io.Writer) error {
	var s string
	switch part {
	case backend.StatusService:
		s = "  " + ui.Bold + "Fake service:" + ui.NC + "         " + b.Active() + "\n"
	case backend.StatusConfig:
		s = "  " + ui.Bold + "Fake config:" + ui.NC + "          " + b.Conf + "\n"
	case backend.StatusAccounting:
		s = "  Fake accounting:      0 entries\n"
	case backend.StatusActivity:
		s = "\n  Fake activity:        quiet\n"
	default:
		return backend.ErrUnsupported
	}
	_, err := io.WriteString(w, s)
	return err
}

// Log implements backend.Backend: "fake log <sub> <args>" for tail,
// search, failures and clear.
func (b *Backend) Log(_ context.Context, sub string, args []string, w io.Writer) error {
	switch sub {
	case "tail", "search", "failures", "clear":
	default:
		return backend.ErrUnsupported
	}
	_, err := io.WriteString(w, strings.TrimSpace("fake log "+sub+" "+strings.Join(args, " "))+"\n")
	return err
}

// Accounting implements backend.Backend: "fake accounting tail <args>".
func (b *Backend) Accounting(_ context.Context, sub string, args []string, w io.Writer) error {
	if sub != "tail" {
		return backend.ErrUnsupported
	}
	_, err := io.WriteString(w, strings.TrimSpace("fake accounting "+sub+" "+strings.Join(args, " "))+"\n")
	return err
}

// LastLogin implements backend.Backend.
func (b *Backend) LastLogin(context.Context, string) (string, error) {
	if b.LastLoginAt == "" {
		return "never", nil
	}
	return b.LastLoginAt, nil
}

// SecretConstraints implements backend.Backend.
func (b *Backend) SecretConstraints() backend.Constraints { return backend.Constraints{} }

// DeviceVars implements backend.Backend.
func (b *Backend) DeviceVars(context.Context, string, string) (map[string]string, error) {
	return nil, nil
}

var _ backend.Sighter = (*Backend)(nil)

// Sightings implements backend.Sighter over Sights: from resume ('n=<k>',
// the k sightings returned before) or, without one, those at or after
// since (every one when since is zero). It logs "sightings <resume>".
func (b *Backend) Sightings(_ context.Context, since time.Time, resume string) ([]backend.Sighting, string, string, error) {
	b.note("sightings %s", resume)
	if b.SightErr != nil {
		return nil, resume, "", b.SightErr
	}
	b.mu.Lock()
	all := append([]backend.Sighting(nil), b.Sights...)
	b.mu.Unlock()
	from := 0
	if k, err := strconv.Atoi(strings.TrimPrefix(resume, "n=")); err == nil && strings.HasPrefix(resume, "n=") && k <= len(all) {
		from = k
	}
	var out []backend.Sighting
	for _, s := range all[from:] {
		if resume == "" && !since.IsZero() && s.Time.Before(since) {
			continue
		}
		out = append(out, s)
	}
	var first, last time.Time
	if len(out) > 0 {
		first, last = out[0].Time, out[len(out)-1].Time
	}
	return out, "n=" + strconv.Itoa(len(all)), backend.TimeWindow("fake log", first, last, len(out)), nil
}
