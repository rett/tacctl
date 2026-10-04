package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/rendered"
)

// tests/integration/upgrade_restart.bats, the TACACS+ tests: which
// services 'tacctl upgrade' restarts. A restart drops every session of the
// daemon, so it follows only what tacquito reads: a new binary, a changed
// unit or drop-in, the store migration or a changed tacquito.yaml. An
// upgrade with nothing new restarts nothing.
//
// The phases run as cmd_upgrade runs them (preflight, build, config,
// files, finish), each upgrade on a fresh lifecycle state, as a new
// process would. systemctl keeps which units are active; git and go stand
// in for the tacquito checkout (HEAD and upstream are strings; a build
// writes "built at <HEAD>" as the binary). Each test starts after one
// upgrade (the first installs the units); the next one is under test.
//
// The RADIUS tests of that file, and the ones about the management repo's
// pull and re-exec, belong to the RADIUS module and the orchestrator.

type uenv struct {
	*ltenv
	sd     *fakeSystemd
	repo   *fakeTacquito
	deploy string
}

func newUpgradeEnv(t *testing.T) *uenv {
	t.Helper()
	e := newLifeTenv(t).withStoreLife("store.multiscope.yaml")
	u := &uenv{ltenv: e, sd: e.systemd(), repo: e.tacquitoRepo(commit1)}
	u.run.On([]string{"ss"}, execx.Result{Stdout: []byte(`LISTEN 0 128 *:49 *:* users:(("tacquito",pid=4242,fd=3))` + "\n")})
	writeFile(t, u.b.tacquitoBin(), "built at "+commit1+"\n")
	if err := os.Chmod(u.b.tacquitoBin(), 0o755); err != nil {
		t.Fatal(err)
	}
	u.sd.active["tacquito"] = true
	u.render(false)
	u.deploy = u.deployTree()
	// The first upgrade (it installs the units); the test runs the next one.
	if err := u.upgrade(u.deploy); err != nil {
		t.Fatalf("first upgrade: %v\n%s", err, u.out())
	}
	if !exists(u.dropIn("default")) || !exists(u.b.serviceFile()) {
		t.Fatal("units not installed")
	}
	u.reset()
	return u
}

// again is the upgrade under test, as a new process.
func (u *uenv) again() error {
	u.freshLife()
	return u.upgrade(u.deploy)
}

// olderRender is older_render: the file as the release before rendered
// it, recorded as what tacctl wrote.
func (u *uenv) olderRender(path string) {
	u.t.Helper()
	appendFile(u.t, path, "# rendered by the release before\n")
	if err := rendered.Record(u.p.Rendered, path); err != nil {
		u.t.Fatal(err)
	}
	u.reset()
}

func (u *uenv) wantServiceCalls(want ...string) {
	u.t.Helper()
	if got := u.serviceCalls(); !slices.Equal(got, want) {
		u.t.Fatalf("service calls %q, want %q\n%s", got, want, u.out())
	}
}

func (u *uenv) binary() string { return readFile(u.t, u.b.tacquitoBin()) }

// --- nothing new ------------------------------------------------------------

func TestUpgradeNothingNewRestartsNothing(t *testing.T) {
	u := newUpgradeEnv(t)
	if err := u.again(); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	u.wantServiceCalls()
	if u.countCalls(`^systemctl daemon-reload`) != 0 || u.countCalls(`^go `) != 0 {
		t.Fatal(u.run.Argvs())
	}
}

func TestUpgradeNothingNewSaysSo(t *testing.T) {
	u := newUpgradeEnv(t)
	if err := u.again(); err != nil {
		t.Fatal(err)
	}
	mustNotContain(t, u.out(), "Restarting")
	r := u.b.UpgradeReport()
	if r.Head != "Scripts Updated (source unchanged at 1111111)" || r.FilesUpdated != 0 || len(r.Notes) != 0 {
		t.Fatal(r)
	}
	mustContain(t, u.out(), "Tacquito source already up to date (1111111); patches applied.")
	mustContain(t, u.out(), "  Unchanged: tacquito.service")
	mustContain(t, u.out(), "  Unchanged: README.md")
	mustContain(t, u.out(), "  Unchanged: logrotate config")
}

// --- each trigger restarts tacquito, once -------------------------------------

func TestUpgradeNewBinaryRestartsTacquito(t *testing.T) {
	u := newUpgradeEnv(t)
	u.repo.setRemote(commit2)
	if err := u.again(); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	mustContain(t, u.out(), "Updated: 1111111 -> 2222222")
	mustContain(t, u.out(), "Backed up current binary to "+u.b.tacquitoBin()+".bak")
	mustContain(t, u.out(), "Changes:\n2222222 upstream change\n")
	if u.binary() != "built at "+commit2+"\n" {
		t.Fatal(u.binary())
	}
	u.wantServiceCalls("systemctl restart tacquito.service")
	if exists(u.b.tacquitoBin() + ".bak") {
		t.Fatal(".bak left after a restart that came up")
	}
	if r := u.b.UpgradeReport(); r.Head != "Upgrade Complete: 1111111 -> 2222222" {
		t.Fatal(r)
	}
	// Server and hash generator, each built once.
	if u.countCalls(`^go build -o `) != 2 {
		t.Fatal(u.run.Argvs())
	}
	if handoverLine(u.b) != UpgradeFromEnv+"=1111111" {
		t.Fatal(u.b.UpgradeHandover())
	}
}

// handoverLine is the one line of UpgradeHandover, "" for none.
func handoverLine(b *Backend) string { return strings.Join(b.UpgradeHandover(), "\n") }

// A rebuild driven by the patch overlay alone (upstream unchanged): one
// restart, and the headline says why.
func TestUpgradeOverlayRebuildRestartsTacquito(t *testing.T) {
	u := newUpgradeEnv(t)
	u.run.On([]string{"git", "-C", u.src(), "apply"}, execx.Result{Code: 1})
	writeFile(t, filepath.Join(u.p.PatchDir, "0009-new.patch"), "diff\n")
	// The new patch is not applied yet and applies.
	u.run.OnFunc([]string{"git", "-C", u.src(), "apply", "--check"}, func(execx.Cmd) (execx.Result, error) { return execx.Result{}, nil })
	if err := u.again(); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	mustContain(t, u.out(), "Applied tacquito patch: 0009-new.patch")
	u.wantServiceCalls("systemctl restart tacquito.service")
	if r := u.b.UpgradeReport(); r.Head != "Upgrade Complete: rebuilt at 1111111 (patch overlay refreshed)" {
		t.Fatal(r)
	}
}

// The build runs before tacctl pulls itself; a tacctl that changed
// re-executes the upgrade, whose own build finds the source current. The
// binary the first run built (it left the previous one as .bak) is not
// running yet: this run restarts on it.
func TestUpgradeBinaryBuiltBeforeTheReExecIsRestartedAndKept(t *testing.T) {
	u := newUpgradeEnv(t)
	bin := u.b.tacquitoBin()
	writeFile(t, bin+".bak", u.binary())
	writeFile(t, bin, "built at "+commit1+" by the run before\n")
	if err := u.again(); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	mustContain(t, u.out(), "The binary built from it is not running yet.")
	if r := u.b.UpgradeReport(); r.Head != "Upgrade Complete: now running the tacquito binary built at 1111111" {
		t.Fatal(r)
	}
	if u.countCalls(`^go `) != 0 {
		t.Fatal(u.run.Argvs())
	}
	u.wantServiceCalls("systemctl restart tacquito.service")
	if exists(bin + ".bak") {
		t.Fatal(".bak left")
	}
	mustContain(t, u.binary(), "by the run before")
	// Once restarted, the next upgrade has nothing to do.
	u.reset()
	if err := u.again(); err != nil {
		t.Fatal(err)
	}
	u.wantServiceCalls()
}

func TestUpgradeTheRunBeforeTheReExecHandsOverItsStart(t *testing.T) {
	u := newUpgradeEnv(t)
	writeFile(t, u.b.tacquitoBin()+".bak", u.binary())
	u.freshLife()
	u.b.SetUpgradeFrom("0abcdef")
	if err := u.upgrade(u.deploy); err != nil {
		t.Fatal(err)
	}
	if r := u.b.UpgradeReport(); r.Head != "Upgrade Complete: 0abcdef -> 1111111" {
		t.Fatal(r)
	}
	u.wantServiceCalls("systemctl restart tacquito.service")
}

// "a rebuild after the re-exec (a new patch) keeps the .bak of the binary
// the daemon still runs, to go back to".
func TestUpgradeRebuildAfterTheReExecKeepsTheRunningBak(t *testing.T) {
	u := newUpgradeEnv(t)
	bin := u.b.tacquitoBin()
	writeFile(t, bin+".bak", "running\n")
	u.repo.setRemote(commit2)
	u.sd.failStart["tacquito"] = true
	wantCode(t, u.again(), 1)
	mustNotContain(t, u.out(), "Backed up current binary")
	mustContain(t, u.out(), "Rolled back to the previous binary. Service is running.")
	if u.binary() != "running\n" {
		t.Fatal(u.binary())
	}
	u.wantServiceCalls("systemctl restart tacquito.service", "systemctl restart tacquito.service")
}

// "a restart that fails with an exit status still gets the rollback, and
// the upgrade says so".
func TestUpgradeFailedRestartStillRollsBack(t *testing.T) {
	u := newUpgradeEnv(t)
	u.repo.setRemote(commit2)
	u.sd.failRestart["tacquito"] = 1
	wantCode(t, u.again(), 1)
	mustContain(t, u.out(), "Tacquito failed to start after upgrade. Rolling back binary...")
	mustContain(t, u.out(), "Rolled back to the previous binary. Service is running.")
	if u.binary() != "built at "+commit1+"\n" {
		t.Fatal(u.binary())
	}
	u.wantServiceCalls("systemctl restart tacquito.service", "systemctl restart tacquito.service")
	if exists(u.b.tacquitoBin() + ".bak") {
		t.Fatal(".bak left after the rollback")
	}
}

func TestUpgradeFailedRollbackRestartEndsInItsMessage(t *testing.T) {
	u := newUpgradeEnv(t)
	u.repo.setRemote(commit2)
	u.sd.failRestart["tacquito"] = 2
	wantCode(t, u.again(), 1)
	mustContain(t, u.out(), "Rolling back binary...")
	mustContain(t, u.out(), "Rollback failed. Check: journalctl -u tacquito")
	if u.binary() != "built at "+commit1+"\n" {
		t.Fatal(u.binary())
	}
}

func TestUpgradeChangedUnitFileRestartsTacquito(t *testing.T) {
	u := newUpgradeEnv(t)
	appendFile(t, filepath.Join(u.deploy, Share, "tacquito.service"), "# changed in this release\n")
	if err := u.again(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "Updated: tacquito.service")
	u.wantServiceCalls("systemctl restart tacquito.service")
	if u.b.UpgradeReport().FilesUpdated != 1 {
		t.Fatal(u.b.UpgradeReport())
	}
}

func TestUpgradeChangedDropInRestartsTacquito(t *testing.T) {
	u := newUpgradeEnv(t)
	u.olderRender(u.dropIn("default"))
	if err := u.again(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "Rendered: the listener drop-in of tacquito.service")
	u.wantServiceCalls("systemctl restart tacquito.service")
}

func TestUpgradeChangedConfigRenderRestartsTacquito(t *testing.T) {
	u := newUpgradeEnv(t)
	u.olderRender(u.p.Config)
	if err := u.again(); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	mustNotContain(t, readFile(t, u.p.Config), "rendered by the release before")
	u.wantServiceCalls("systemctl restart tacquito.service")
}

// The store gate moved a legacy install into the store: one restart, and
// the summary says so.
func TestUpgradeStoreFlipRestartsTacquito(t *testing.T) {
	u := newUpgradeEnv(t)
	u.freshLife()
	u.b.life.flip = func(context.Context) lifecycle.FlipResult { return lifecycle.Flipped }
	if err := u.upgrade(u.deploy); err != nil {
		t.Fatal(err)
	}
	u.wantServiceCalls("systemctl restart tacquito.service")
	if r := u.b.UpgradeReport(); !slices.Equal(r.Notes, []string{"Store: migrated from tacquito.yaml ('tacctl store rollback' undoes it)"}) {
		t.Fatal(r)
	}
}

// A gate that stopped restarts nothing on its own account.
func TestUpgradeStoreFlipStoppedRestartsNothing(t *testing.T) {
	u := newUpgradeEnv(t)
	u.freshLife()
	u.b.life.flip = func(context.Context) lifecycle.FlipResult { return lifecycle.FlipStopped }
	if err := u.upgrade(u.deploy); err != nil {
		t.Fatal(err)
	}
	u.wantServiceCalls()
	if r := u.b.UpgradeReport(); !slices.Equal(r.Notes, []string{"Store: NOT migrated — legacy read-only mode (see 'Store migration stopped' above)"}) {
		t.Fatal(r)
	}
}

// After a flip, a daemon that does not come back gets the store rollback
// hint; with nothing to roll back the upgrade says it failed.
func TestUpgradeStoreFlipFailedRestartGivesTheHint(t *testing.T) {
	u := newUpgradeEnv(t)
	u.freshLife()
	u.b.life.flip = func(context.Context) lifecycle.FlipResult { return lifecycle.Flipped }
	u.sd.failStart["tacquito"] = true
	wantCode(t, u.upgrade(u.deploy), 1)
	mustContain(t, u.out(), "Tacquito failed to start. Check: journalctl -u tacquito")
	mustContain(t, u.out(), "This upgrade moved the configuration into the store. If the rendered "+u.p.Config+
		" is the cause, 'tacctl store rollback' restores the previous file.")
	u.wantServiceCalls("systemctl restart tacquito.service")
}

// Every trigger at once is still one restart.
func TestUpgradeEveryTriggerAtOnceIsOneRestart(t *testing.T) {
	u := newUpgradeEnv(t)
	u.repo.setRemote(commit2)
	appendFile(t, filepath.Join(u.deploy, Share, "tacquito.service"), "# changed\n")
	u.olderRender(u.p.Config)
	u.freshLife()
	u.b.life.flip = func(context.Context) lifecycle.FlipResult { return lifecycle.Flipped }
	if err := u.upgrade(u.deploy); err != nil {
		t.Fatal(err)
	}
	u.wantServiceCalls("systemctl restart tacquito.service")
	if strings.Count(u.out(), "Restarting tacquito service...") != 1 {
		t.Fatal(u.out())
	}
}

// --- what no daemon reads ------------------------------------------------------

func TestUpgradeNewReadmeOrLogrotateRestartsNothing(t *testing.T) {
	u := newUpgradeEnv(t)
	appendFile(t, filepath.Join(u.deploy, "README.md"), "\nnew line\n")
	appendFile(t, filepath.Join(u.deploy, Share, "tacquito.logrotate"), "# new\n")
	if err := u.again(); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "  Updated: README.md")
	mustContain(t, u.out(), "  Updated: logrotate config")
	if u.b.UpgradeReport().FilesUpdated != 2 {
		t.Fatal(u.b.UpgradeReport())
	}
	mustNotContain(t, u.out(), "Restarting")
	u.wantServiceCalls()
	if st, _ := os.Stat(filepath.Join(u.p.Etc, "README.md")); st.Mode().Perm() != 0o644 {
		t.Fatal(st.Mode())
	}
}

// --- across the self-update re-exec ----------------------------------------------

// "a tacquito build before a branch switch's re-exec is restarted on once,
// by the re-executed run": the first process builds and re-executes (its
// phases after build never run); the second gets UpgradeFromEnv from it.
func TestUpgradeBuildBeforeTheReExecIsRestartedOnceByTheNewProcess(t *testing.T) {
	u := newUpgradeEnv(t)
	u.repo.setRemote(commit2)
	ctx := context.Background()
	u.freshLife()
	for _, ph := range []string{"preflight", "build"} {
		if err := u.b.Upgrade(ctx, backend.Phase(ph), ""); err != nil {
			t.Fatal(err)
		}
	}
	handover := u.b.UpgradeHandover()
	if !slices.Equal(handover, []string{"TACCTL_UPGRADE_TACQUITO_FROM=1111111"}) {
		t.Fatal(handover)
	}
	// The re-executed process.
	u.freshLife()
	from, _ := strings.CutPrefix(handover[0], UpgradeFromEnv+"=")
	u.b.SetUpgradeFrom(from)
	if err := u.upgrade(u.deploy); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	mustContain(t, u.out(), "The binary built from it is not running yet.")
	if r := u.b.UpgradeReport(); r.Head != "Upgrade Complete: 1111111 -> 2222222" {
		t.Fatal(r)
	}
	if strings.Count(u.out(), "Restarting tacquito service") != 1 {
		t.Fatal(u.out())
	}
	// Built once (server and hash generator), by the first process.
	if u.countCalls(`^go build`) != 2 {
		t.Fatal(u.run.Argvs())
	}
	u.wantServiceCalls("systemctl restart tacquito.service")
	if exists(u.b.tacquitoBin() + ".bak") {
		t.Fatal(".bak left")
	}
	if u.binary() != "built at "+commit2+"\n" {
		t.Fatal(u.binary())
	}
	// It keeps handing the start over, should it re-execute again.
	if !slices.Equal(u.b.UpgradeHandover(), handover) {
		t.Fatal(u.b.UpgradeHandover())
	}
}

// Without a build there is nothing to hand over.
func TestUpgradeHandoverEmptyWithoutABuild(t *testing.T) {
	u := newUpgradeEnv(t)
	if err := u.again(); err != nil {
		t.Fatal(err)
	}
	if h := u.b.UpgradeHandover(); h != nil {
		t.Fatal(h)
	}
}
