package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// Ports of the enable and disable tests of tests/integration/backend_cli.bats:
// the stand-in second backend 'fake' (internal/backend/faketest) beside a
// stand-in 'tacacs' that renders the store's user names into tacquito.yaml
// and records it, as the real one does. The CLI half (argument handling,
// the registered verbs) is TestBackendEnableDisableCLI; the RADIUS module
// under these commands is tests/integration/radius.bats, which runs against
// the binary.
//
// What must hold whichever step of enable fails, and wherever:
//   - backends.enabled (tacctl.yaml), the store, every rendered artifact and
//     rendered.json are as they were;
//   - no staging or keep directory is left behind.

const testTree = "/src/tacctl"

type swEnv struct {
	t        *testing.T
	w, tmp   string
	p        paths.Paths
	reg      *backend.Registry
	env      *backend.Env
	set      *backend.Set
	tac      *faketest.Backend
	fake     *faketest.Backend
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	fakeConf string
}

// newSwEnv is the setup of backend_cli.bats: the multiscope store,
// tacquito.yaml rendered from it with tacacs alone (installed, running),
// the stand-in not installed.
func newSwEnv(t *testing.T) *swEnv {
	t.Helper()
	w := t.TempDir()
	e := &swEnv{t: t, w: w, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}}
	for _, d := range []string{"etc", "state", "tmp", "fake", "tac"} {
		if err := os.MkdirAll(filepath.Join(w, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	e.tmp = filepath.Join(w, "tmp")
	t.Setenv("TMPDIR", e.tmp)
	e.p = paths.Resolve(paths.NewEnv(sandboxPathEnv(w)), "", func(string) bool { return false }).Reroot(w)
	e.fakeConf = filepath.Join(w, "etc", "fake.conf")
	e.reg = backend.NewRegistry(backend.TACACS, backend.RADIUS)
	e.tac = faketest.New(backend.TACACS, e.p.Config, filepath.Join(w, "tac"))
	e.fake = faketest.New("fake", e.fakeConf, filepath.Join(w, "fake"))
	for _, b := range []*faketest.Backend{e.tac, e.fake} {
		if err := e.reg.Add(b.ID(), faketest.Factory(b)); err != nil {
			t.Fatal(err)
		}
	}
	out := ui.Output{Stdout: e.stdout, Stderr: e.stderr}
	snaps := snapshot.New(e.p, "0.2.0-test", nil, out)
	snaps.Chown = nil
	cfg := conf.Load(e.p.Overrides, e.reg.IDs())
	cfg.Owner = nil
	e.env = &backend.Env{Paths: e.p, Conf: cfg, Out: out, Now: time.Now, Snapshots: snaps}
	e.set = backend.NewSet(e.reg, e.env)

	data, err := os.ReadFile("../../tests/fixtures/store.multiscope.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.p.StoreFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	e.tac.SetInstalled(true)
	if err := e.set.ConfigRender(context.Background(), false); err != nil {
		t.Fatalf("config render: %v\n%s", err, e.stderr)
	}
	e.reset()
	return e
}

func (e *swEnv) reset() {
	e.tac.ResetCalls()
	e.fake.ResetCalls()
	e.stdout.Reset()
	e.stderr.Reset()
}

// run is 'tc cmd_backend_<verb> args...' with stdin: the exit status;
// the output is in e.out().
func (e *swEnv) run(stdin, verb string, args ...string) int {
	e.t.Helper()
	e.stdout.Reset()
	e.stderr.Reset()
	s := &switcher{ctx: context.Background(), set: e.set, out: e.env.Out,
		prompt: ui.NewPrompter(strings.NewReader(stdin), e.env.Out), tree: testTree, wait: func(time.Duration) {}}
	var err error
	if verb == "enable" {
		err = s.enable(args)
	} else {
		err = s.disable(args)
	}
	return exitCode(err, e.env.Out)
}

// out is everything written, colours stripped.
func (e *swEnv) out() string { return plain(e.stdout.String() + e.stderr.String()) }

// fakeUp is fake_up: the stand-in installed, enabled, rendered, running.
func (e *swEnv) fakeUp() {
	e.t.Helper()
	e.fake.SetInstalled(true)
	if code := e.run("", "enable", "fake", "-y"); code != 0 {
		e.t.Fatalf("fake_up: %d\n%s", code, e.out())
	}
	e.reset()
}

// state is the bats state(): one line per canonical file and artifact.
func (e *swEnv) state() string {
	var b strings.Builder
	for _, f := range []string{e.p.StoreFile, e.p.Overrides, e.p.Config, e.fakeConf, e.p.Rendered} {
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

// noLeftovers is no_leftovers().
func (e *swEnv) noLeftovers() {
	e.t.Helper()
	if ents, _ := os.ReadDir(e.tmp); len(ents) != 0 {
		e.t.Errorf("TMPDIR not empty: %v", ents)
	}
	for _, pat := range []string{".apply.*", ".enable.*", ".disable.*"} {
		if m, _ := filepath.Glob(filepath.Join(e.p.StateDir, pat)); len(m) != 0 {
			e.t.Errorf("left %v", m)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(e.p.Etc, "*.tacctl-new")); len(m) != 0 {
		e.t.Errorf("left %v", m)
	}
}

// enabledNow is enabled_now: backends.enabled as tacctl.yaml says it now.
func (e *swEnv) enabledNow() string {
	ids := conf.Load(e.p.Overrides, e.reg.IDs()).GetList("backends.enabled")
	if len(ids) == 0 {
		ids = backend.DefaultEnabled
	}
	return strings.Join(ids, " ")
}

func (e *swEnv) want(code, wantCode int) {
	e.t.Helper()
	if code != wantCode {
		e.t.Fatalf("exit %d, want %d\n%s", code, wantCode, e.out())
	}
}

func (e *swEnv) has(want string) {
	e.t.Helper()
	if !strings.Contains(e.out(), want) {
		e.t.Errorf("missing %q in:\n%s", want, e.out())
	}
}

func (e *swEnv) hasNot(bad string) {
	e.t.Helper()
	if strings.Contains(e.out(), bad) {
		e.t.Errorf("unexpected %q in:\n%s", bad, e.out())
	}
}

func (e *swEnv) exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func countOf(calls []string, line string) int {
	n := 0
	for _, c := range calls {
		if c == line {
			n++
		}
	}
	return n
}

func TestBackendEnableOrder(t *testing.T) {
	e := newSwEnv(t)
	e.want(e.run("", "enable", "fake", "-y"), 0)
	e.has("[INFO] Backend 'fake' is enabled and running.\n")
	if e.enabledNow() != "tacacs fake" {
		t.Errorf("enabled %q", e.enabledNow())
	}
	if data, _ := os.ReadFile(e.fakeConf); !strings.Contains(string(data), "bob\n") {
		t.Errorf("fake.conf %q", data)
	}
	want := []string{"install build " + testTree, "install files " + testTree, "install account " + testTree,
		"gate", "stage", "commit", "install start " + testTree, "service is-active"}
	if got := e.fake.Calls(); !slices.Equal(got, want) {
		t.Errorf("calls %q", got)
	}
	// Recorded for drift, and the running tacquito was not touched.
	if w, _ := rendered.Check(e.p.Rendered, e.fakeConf); w != rendered.OK {
		t.Errorf("fake.conf is %s", w)
	}
	if e.tac.Called("service restart") {
		t.Error("tacquito restarted")
	}
	e.noLeftovers()
}

func TestBackendEnablePromptNo(t *testing.T) {
	e := newSwEnv(t)
	before := e.state()
	e.want(e.run("n\n", "enable", "fake"), 0)
	e.has("  Backend 'fake' is not installed. Enabling it installs faked\n  (packages, a service account, its service unit), then renders its config and starts it.\n")
	e.has("[INFO] Cancelled. Nothing was changed.")
	if e.state() != before || len(e.fake.Calls()) != 0 || e.fake.Installed() {
		t.Error("something was touched")
	}
	// An empty stdin (no terminal) is a no, not a yes.
	e.want(e.run("", "enable", "fake"), 0)
	if e.fake.Installed() {
		t.Error("installed on an empty stdin")
	}
}

func TestBackendEnablePromptYes(t *testing.T) {
	e := newSwEnv(t)
	e.want(e.run("y\n", "enable", "fake"), 0)
	if e.enabledNow() != "tacacs fake" {
		t.Errorf("enabled %q", e.enabledNow())
	}
}

func TestBackendEnableInstalledIsRestarted(t *testing.T) {
	e := newSwEnv(t)
	e.fake.SetInstalled(true)
	e.want(e.run("", "enable", "fake"), 0)
	e.hasNot("is not installed. Enabling it installs")
	calls := e.fake.Calls()
	for _, c := range calls {
		if strings.HasPrefix(c, "install ") {
			t.Errorf("installed again: %q", calls)
		}
	}
	if !slices.Contains(calls, "service enable") || !slices.Contains(calls, "service restart") {
		t.Errorf("calls %q", calls)
	}
	if e.fake.Boot() != "enabled" || e.enabledNow() != "tacacs fake" {
		t.Error("not enabled")
	}
}

func TestBackendEnableUnchangedIsStarted(t *testing.T) {
	e := newSwEnv(t)
	e.fake.SetInstalled(true)
	e.want(e.run("", "enable", "fake"), 0)
	e.want(e.run("", "disable", "fake", "-y"), 0)
	e.reset()
	// Its artifact is still there and still what the store renders.
	e.want(e.run("", "enable", "fake"), 0)
	calls := e.fake.Calls()
	if !slices.Contains(calls, "service enable") || !slices.Contains(calls, "service start") || slices.Contains(calls, "service restart") {
		t.Errorf("calls %q", calls)
	}
}

func TestBackendEnableAlreadyEnabled(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 0)
	e.has("[INFO] Backend 'fake' is already enabled.")
	if e.state() != before || len(e.fake.Calls()) != 0 {
		t.Error("something changed")
	}
}

func TestBackendEnableBadArguments(t *testing.T) {
	e := newSwEnv(t)
	before := e.state()
	for _, c := range []struct {
		args []string
		msg  string
	}{
		{[]string{"ldap", "-y"}, "[ERROR] Unknown backend 'ldap' (known: tacacs fake).\n"},
		{nil, "[ERROR] Missing backend id (known: tacacs fake).\n"},
		{[]string{"fake", "extra", "-y"}, "[ERROR] Usage: tacctl backend enable <id> [-y]\n"},
		{[]string{"--bogus", "fake"}, "[ERROR] Unknown option '--bogus'. Usage: tacctl backend enable <id> [-y]\n"},
	} {
		e.want(e.run("", "enable", c.args...), 1)
		if got := plain(e.stderr.String()); got != c.msg || e.stdout.Len() != 0 {
			t.Errorf("%q: stderr %q stdout %q", c.args, got, e.stdout)
		}
	}
	if e.state() != before {
		t.Error("something changed")
	}
}

func TestBackendEnableWithoutStore(t *testing.T) {
	e := newSwEnv(t)
	if err := os.Remove(e.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 1)
	e.has(store.NotInitialisedMsg)
	if e.state() != before || len(e.fake.Calls()) != 0 {
		t.Error("something was touched")
	}
}

func TestBackendEnableInstallStepFails(t *testing.T) {
	e := newSwEnv(t)
	e.fake.PhaseFail = backend.PhaseFiles
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 1)
	e.has("[ERROR] fake: files failed\n")
	e.has("[ERROR] Backend 'fake': install step 'files' failed (exit 1).\n")
	e.has("[ERROR] Backend 'fake' was not enabled. tacctl.yaml, the store and every rendered file are as they were; what the install did stays on this machine.\n")
	if e.state() != before || e.fake.Called("gate") {
		t.Error("went on after the install")
	}
	e.noLeftovers()
}

func TestBackendEnableGateRefuses(t *testing.T) {
	e := newSwEnv(t)
	e.fake.Gate = backend.GateRefused
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 3)
	e.has("[ERROR] Backend 'fake' was not enabled. tacctl.yaml, the store and every rendered file are as they were; the install stays on this machine.\n")
	if e.state() != before || !e.fake.Installed() || e.fake.Called("stage") {
		t.Error("state")
	}
	e.noLeftovers()
}

func TestBackendEnableGateAdopts(t *testing.T) {
	e := newSwEnv(t)
	e.fake.Gate = backend.GateAdopt
	e.want(e.run("", "enable", "fake", "-y"), 0)
	if !e.fake.Called("stage --force") || e.enabledNow() != "tacacs fake" {
		t.Errorf("calls %q", e.fake.Calls())
	}
}

// A hand-edited artifact of an enabled backend refuses the enable (exit 3)
// before anything is written: its gate refuses.
func TestBackendEnableEnabledBackendEdited(t *testing.T) {
	e := newSwEnv(t)
	e.fake.SetInstalled(true)
	e.tac.Gate = backend.GateRefused
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 3)
	e.has("was not enabled")
	if e.state() != before {
		t.Error("something changed")
	}
	e.noLeftovers()
}

func TestBackendEnableStageFails(t *testing.T) {
	e := newSwEnv(t)
	e.fake.Fail = "stage"
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 1)
	e.has("fake: cannot express this model")
	// The new backend's artifact is named among those that could not be
	// rendered.
	e.has(e.fakeConf + " could not be rendered")
	e.has("was not enabled")
	if e.state() != before || e.tac.Called("service restart") {
		t.Error("state")
	}
	e.noLeftovers()
}

func TestBackendEnableCommitFails(t *testing.T) {
	e := newSwEnv(t)
	e.fake.Fail = "commit"
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 1)
	if e.state() != before || e.exists(e.fakeConf) {
		t.Errorf("not undone:\n%s", e.out())
	}
	e.noLeftovers()
}

func TestBackendEnableStartStepFails(t *testing.T) {
	e := newSwEnv(t)
	e.fake.PhaseFail = backend.PhaseStart
	before := e.state()
	e.want(e.run("", "enable", "fake", "-y"), 1)
	e.has("[ERROR] Backend 'fake': install step 'start' failed (exit 1).\n")
	e.has("[WARN] Backend 'fake' did not come up (service unknown); undoing the change.\n")
	e.has("[ERROR] Backend 'fake' was not enabled. tacctl.yaml and every rendered file are back as they were, the service is stopped and disabled; the install stays on this machine.\n")
	if e.state() != before || e.exists(e.fakeConf) || e.enabledNow() != "tacacs" {
		t.Error("not undone")
	}
	// Stopped and disabled, and the install stays.
	if !e.fake.Called("service stop") || !e.fake.Called("service disable") || !e.fake.Installed() {
		t.Errorf("calls %q", e.fake.Calls())
	}
	e.noLeftovers()
}

func TestBackendEnableNotActiveIsUndone(t *testing.T) {
	e := newSwEnv(t)
	e.fake.SetInstalled(true)
	e.fake.StartFails = true
	before := e.state()
	e.want(e.run("", "enable", "fake"), 1)
	e.has("did not come up (service failed)")
	e.hasNot("the install stays")
	if e.state() != before || e.exists(e.fakeConf) || e.fake.Boot() != "disabled" {
		t.Error("not undone")
	}
	e.noLeftovers()
	// Nothing is stuck: with the fault gone the same command works.
	e.fake.StartFails = false
	e.want(e.run("", "enable", "fake"), 0)
	if e.enabledNow() != "tacacs fake" {
		t.Error("not enabled")
	}
}

// An undo restarts the backends the render had restarted, onto what they
// had.
func TestBackendEnableUndoRestartsTheOthers(t *testing.T) {
	e := newSwEnv(t)
	e.fake.SetInstalled(true)
	e.fake.StartFails = true
	// A change that makes tacquito's render differ is not what enable does,
	// so force it: tacquito.yaml is missing, so the enable's render
	// recreates it.
	for _, f := range []string{e.p.Config, e.p.Rendered} {
		if err := os.Remove(f); err != nil {
			t.Fatal(err)
		}
	}
	e.want(e.run("", "enable", "fake"), 1)
	// Restarted once by the render, once more by the undo.
	if n := countOf(e.tac.Calls(), "service restart"); n != 2 {
		t.Errorf("tacquito restarted %d times: %q", n, e.tac.Calls())
	}
	if e.exists(e.p.Config) {
		t.Error("tacquito.yaml not put back (absent)")
	}
}

// The keep copy of tacctl.yaml is put back as it was, and an absent one
// stays absent.
func TestBackendEnableUndoPutsTacctlYamlBack(t *testing.T) {
	e := newSwEnv(t)
	if err := e.env.Conf.Set("bcrypt.cost", "12"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(e.p.Overrides)
	e.fake.SetInstalled(true)
	e.fake.StartFails = true
	e.want(e.run("", "enable", "fake"), 1)
	if after, _ := os.ReadFile(e.p.Overrides); !bytes.Equal(after, before) {
		t.Errorf("tacctl.yaml %q, was %q", after, before)
	}
	if got, _ := e.set.Enabled(); !slices.Equal(got, []string{"tacacs"}) {
		t.Errorf("the invocation still sees %v", got)
	}
}

// --- disable --------------------------------------------------------------------

func TestBackendDisableConfirms(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	e.want(e.run("y\n", "disable", "fake"), 0)
	e.has("\n  This takes backend 'fake' out of backends.enabled and stops and disables its service.\n" +
		"  Clients of that protocol can no longer authenticate. Its package and rendered files stay on this machine;\n" +
		"  'tacctl backend enable fake' brings it back.\n")
	e.has("[INFO] Backend 'fake' is disabled: removed from backends.enabled, service stopped and disabled.\n")
	e.has("[INFO] Left in place: its package and " + e.fakeConf + " (not rendered any more).\n")
	if e.enabledNow() != "tacacs" || !e.fake.Called("service stop") || !e.fake.Called("service disable") || e.fake.Boot() != "disabled" {
		t.Errorf("calls %q", e.fake.Calls())
	}
	if !e.exists(e.fakeConf) || !e.fake.Installed() {
		t.Error("files removed")
	}
	if w, _ := rendered.Check(e.p.Rendered, e.fakeConf); w != rendered.OK {
		t.Errorf("record %s", w)
	}
	e.noLeftovers()
}

func TestBackendDisablePromptNo(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	before := e.state()
	e.want(e.run("n\n", "disable", "fake"), 0)
	e.has("[INFO] Cancelled. Nothing was changed.")
	if e.state() != before || e.fake.Called("service stop") {
		t.Error("something changed")
	}
	e.want(e.run("", "disable", "fake"), 0)
	if e.enabledNow() != "tacacs fake" {
		t.Error("disabled on an empty stdin")
	}
}

func TestBackendDisableYes(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	e.want(e.run("", "disable", "fake", "-y"), 0)
	e.hasNot("Cancelled")
	if e.enabledNow() != "tacacs" {
		t.Error("not disabled")
	}
}

func TestBackendDisableLastIsRefused(t *testing.T) {
	e := newSwEnv(t)
	before := e.state()
	e.want(e.run("", "disable", "tacacs", "-y"), 1)
	if got := plain(e.stderr.String()); got != "[ERROR] Backend 'tacacs' is the only enabled backend. With none enabled nothing would serve the store.\n"+
		"[ERROR] Enable another first ('tacctl backend enable <id>'), or remove tacctl's daemons with 'tacctl uninstall'.\n" {
		t.Errorf("stderr %q", got)
	}
	if e.state() != before || e.tac.Called("service stop") || e.tac.Called("service disable") {
		t.Error("something changed")
	}
}

func TestBackendDisableTacacsWithoutStore(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	if err := os.Remove(e.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	before := e.state()
	e.want(e.run("", "disable", "tacacs", "-y"), 1)
	e.has("[ERROR] Backend 'tacacs' cannot be disabled while there is no store: " + e.p.Config +
		" is still the source of truth and tacquito the only thing serving it.\n[ERROR] " + store.NotInitialisedMsg + "\n")
	if e.state() != before || e.tac.Called("service stop") {
		t.Error("something changed")
	}
}

// Another backend can be disabled without a store (tacctl.yaml only).
func TestBackendDisableLegacyMode(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	if err := os.Remove(e.p.StoreFile); err != nil {
		t.Fatal(err)
	}
	e.want(e.run("", "disable", "fake", "-y"), 0)
	if e.enabledNow() != "tacacs" || !e.fake.Called("service stop") || e.fake.Called("gate") {
		t.Errorf("calls %q", e.fake.Calls())
	}
	e.noLeftovers()
}

func TestBackendDisableTacacsWhenAnotherStays(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	yaml, _ := os.ReadFile(e.p.Config)
	e.want(e.run("", "disable", "tacacs", "-y"), 0)
	if e.enabledNow() != "fake" || !e.tac.Called("service stop") || !e.tac.Called("service disable") {
		t.Errorf("calls %q", e.tac.Calls())
	}
	if after, _ := os.ReadFile(e.p.Config); !bytes.Equal(after, yaml) {
		t.Error("tacquito.yaml changed")
	}
}

func TestBackendDisableNotEnabledOrUnknown(t *testing.T) {
	e := newSwEnv(t)
	e.want(e.run("", "disable", "fake", "-y"), 0)
	e.has("[INFO] Backend 'fake' is not enabled. Nothing to do.")
	e.want(e.run("", "disable", "ldap", "-y"), 1)
	e.has("[ERROR] Unknown backend 'ldap' (known: tacacs fake).")
	e.want(e.run("", "disable", "--yes", "fake", "tacacs"), 1)
	e.has("[ERROR] Usage: tacctl backend disable <id> [-y]")
	e.want(e.run("", "disable", "-x"), 1)
	e.has("[ERROR] Unknown option '-x'. Usage: tacctl backend disable <id> [-y]")
}

// The gate covers the backends that stay, not the one going.
func TestBackendDisableGatesTheRest(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	// The one being disabled refuses its gate: that must not stop it.
	e.fake.Gate = backend.GateRefused
	e.want(e.run("", "disable", "fake", "-y"), 0)
	if e.enabledNow() != "tacacs" {
		t.Error("not disabled")
	}
	// A backend that stays and was edited by hand does stop it.
	e.fake.Gate = backend.GateOK
	e.want(e.run("", "enable", "fake"), 0)
	e.tac.Gate = backend.GateRefused
	before := e.state()
	e.want(e.run("", "disable", "fake", "-y"), 3)
	e.has("[ERROR] Backend 'fake' was not disabled. tacctl.yaml, the store and every rendered file are as they were.")
	if e.state() != before {
		t.Error("something changed")
	}
	e.noLeftovers()
}

func TestBackendDisableStopFails(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	e.fake.StopFails = true
	e.want(e.run("", "disable", "fake", "-y"), 1)
	e.has("[ERROR] Backend 'fake' is out of backends.enabled, but its service could not be stopped or disabled. Run: systemctl stop fake.service ; systemctl disable fake.service\n")
	if e.enabledNow() != "tacacs" {
		t.Error("backends.enabled not updated")
	}
}

func TestBackendDisableThenEnable(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	before, _ := os.ReadFile(e.fakeConf)
	e.want(e.run("", "disable", "fake", "-y"), 0)
	e.want(e.run("", "enable", "fake"), 0)
	if after, _ := os.ReadFile(e.fakeConf); !bytes.Equal(after, before) {
		t.Error("files differ")
	}
	if e.enabledNow() != "tacacs fake" || e.fake.Active() != "active" {
		t.Error("not serving again")
	}
}

// Mutations after a disable render only the backends that are enabled.
func TestBackendDisabledIsNotRendered(t *testing.T) {
	e := newSwEnv(t)
	e.fakeUp()
	e.want(e.run("", "disable", "fake", "-y"), 0)
	e.reset()
	_, err := e.set.StoreApply(context.Background(), backend.ApplyOptions{}, func() error {
		_, err := store.Mutate(e.p.StoreFile, e.env.MutateOptions(), func(s *store.Store) error { return s.UserDel("carol") })
		return err
	})
	if err != nil {
		t.Fatalf("apply: %v\n%s", err, e.out())
	}
	if len(e.fake.Calls()) != 0 {
		t.Errorf("fake called %q", e.fake.Calls())
	}
	tq, _ := os.ReadFile(e.p.Config)
	fk, _ := os.ReadFile(e.fakeConf)
	if strings.Contains(string(tq), "carol") || !strings.Contains(string(fk), "carol\n") {
		t.Error("the disabled backend's file followed the change, or tacquito's did not")
	}
}

// The CLI: the verbs are registered native, their argument
// errors are those of the command, and a backends.enabled naming no module
// is refused.
func TestBackendEnableDisableCLI(t *testing.T) {
	sb := newSandbox(t, true)
	sb.env = append(sb.env, sandboxPathEnv(sb.dir)...)
	sb.run("", []string{"backend", "enable", "ldap"})
	sb.expect(1, "", "[ERROR] Unknown backend 'ldap' (known: tacacs radius).")
	sb.run("", []string{"backend", "enable"})
	sb.expect(1, "", "[ERROR] Missing backend id (known: tacacs radius).")
	sb.run("", []string{"backend", "disable", "radius", "--bogus"})
	sb.expect(1, "", "[ERROR] Unknown option '--bogus'. Usage: tacctl backend disable <id> [-y]")
	sb.run("", []string{"backend", "enable", "tacacs", "-y"})
	sb.expect(0, "[INFO] Backend 'tacacs' is already enabled.", "")
	sb.run("", []string{"backend", "disable", "radius", "-y"})
	sb.expect(0, "[INFO] Backend 'radius' is not enabled. Nothing to do.", "")
	sb.run("", []string{"backend", "disable", "tacacs", "-y"})
	sb.expect(1, "", "[ERROR] Backend 'tacacs' is the only enabled backend.")
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, ldap]\n", 0o600)
	sb.run("", []string{"backend", "enable", "radius", "-y"})
	sb.expect(1, "", "backends.enabled names 'ldap', and this tacctl has no such backend (it has: tacacs radius).")
}
