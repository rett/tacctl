package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/execx"
)

// The phases of 'tacctl install' and 'tacctl uninstall', 'upgrade
// preflight' and the failure paths of 'upgrade build', against the
// scripted runner (no bats file drives them; 0.1.16's cmd_install and
// cmd_uninstall shell out to git, go and useradd).

func (e *ltenv) goVersion(v string) {
	e.run.On([]string{e.b.goBin(), "version"}, execx.Result{Stdout: []byte("go version go" + v + " linux/amd64\n")})
}

func (e *ltenv) dirOf(prefix ...string) string {
	for _, c := range e.run.Calls() {
		if slices.Equal(c.Argv()[:min(len(prefix), len(c.Argv()))], prefix) {
			return c.Dir
		}
	}
	return "<no call>"
}

// --- install build -------------------------------------------------------------

func TestInstallBuildClonesPatchesAndBuilds(t *testing.T) {
	e := newLifeTenv(t)
	e.goVersion(GoVersion)
	e.tacquitoRepo(commit1)
	if err := os.RemoveAll(e.src()); err != nil {
		t.Fatal(err)
	}
	if err := e.b.Install(context.Background(), backend.PhaseBuild, ""); err != nil {
		t.Fatalf("%v\n%s", err, e.out())
	}
	out := e.out()
	for _, s := range []string{
		"Go 1.26.2 already installed, skipping.",
		"Cloning tacquito...",
		"Building tacquito server...",
		"Building password hash generator...",
		"Binaries installed:",
		"  Server:  " + e.b.tacquitoBin(),
		"  Hashgen: " + e.b.hashgenBin(),
	} {
		mustContain(t, out, s)
	}
	if !e.called(`^git clone --quiet https://github.com/facebookincubator/tacquito.git ` + e.src() + `$`) {
		t.Fatal(e.run.Argvs())
	}
	if d := e.dirOf("go", "build", "-o", e.b.tacquitoBin()); d != e.src()+"/cmds/server" {
		t.Fatal(d)
	}
	if d := e.dirOf("go", "build", "-o", e.b.hashgenBin()); d != e.src()+"/cmds/server/config/authenticators/bcrypt/generator" {
		t.Fatal(d)
	}
	for _, f := range []string{e.b.tacquitoBin(), e.b.hashgenBin()} {
		if st, err := os.Stat(f); err != nil || st.Mode().Perm() != 0o755 {
			t.Fatal(f, err)
		}
	}
	if !e.called(`^git config --system --add safe.directory ` + e.src() + `$`) {
		t.Fatal(e.run.Argvs())
	}
}

func TestInstallBuildPullsAnExistingCheckout(t *testing.T) {
	e := newLifeTenv(t)
	e.goVersion(GoVersion)
	e.tacquitoRepo(commit1)
	e.run.On([]string{"git", "config", "--system", "--get-all", "safe.directory"}, execx.Result{Stdout: []byte("/opt/tacctl\n" + e.src() + "\n")})
	if err := e.b.Install(context.Background(), backend.PhaseBuild, ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.out(), "Tacquito source already exists at "+e.src()+", pulling latest...")
	if e.dirOf("git", "checkout", "--", ".") != e.src() || e.dirOf("git", "pull", "--quiet") != e.src() {
		t.Fatal(e.run.Argvs())
	}
	if e.called(`^git clone`) || e.called(`safe.directory --add|--add safe.directory`) {
		t.Fatal(e.run.Argvs())
	}
}

// Another Go than the one 0.1.16 installs is used as it is: installing Go
// is the bootstrap shim's.
func TestInstallBuildUsesTheGoThatIsThere(t *testing.T) {
	e := newLifeTenv(t)
	e.goVersion("1.27.1")
	e.tacquitoRepo(commit1)
	if err := e.b.Install(context.Background(), backend.PhaseBuild, ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.out(), "Go 1.27.1 already installed, skipping.")
	if e.called(`wget|tar `) {
		t.Fatal(e.run.Argvs())
	}
}

func TestInstallBuildWithoutGo(t *testing.T) {
	e := newLifeTenv(t)
	e.b.life.goBin = filepath.Join(e.dir, "no-go")
	wantCode(t, e.b.Install(context.Background(), backend.PhaseBuild, ""), 1)
	mustContain(t, e.stderr.String(), "Go not found at "+e.b.life.goBin+". Install Go first.")
	if len(e.run.Calls()) != 0 {
		t.Fatal(e.run.Argvs())
	}
}

func TestInstallBuildFailuresEndWithTheirStatus(t *testing.T) {
	e := newLifeTenv(t)
	e.goVersion(GoVersion)
	e.tacquitoRepo(commit1)
	e.run.On([]string{"git", "pull"}, execx.Result{Code: 1})
	wantCode(t, e.b.Install(context.Background(), backend.PhaseBuild, ""), 1)
	if e.called(`^go `) {
		t.Fatal(e.run.Argvs())
	}

	e = newLifeTenv(t)
	e.goVersion(GoVersion)
	e.tacquitoRepo(commit1)
	e.run.On([]string{"go", "build"}, execx.Result{Code: 2})
	wantCode(t, e.b.Install(context.Background(), backend.PhaseBuild, ""), 2)
	mustNotContain(t, e.out(), "Binaries installed")
	if e.countCalls(`^go build`) != 1 {
		t.Fatal(e.run.Argvs())
	}
}

// --- install files, account, start ---------------------------------------------

func TestInstallFilesLogrotate(t *testing.T) {
	e := newLifeTenv(t)
	tree := repoRoot(t)
	if err := e.b.Install(context.Background(), backend.PhaseFiles, tree); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(e.p.LogrotateDir, "tacquito")
	mustContain(t, e.out(), "Log rotation installed: "+dst)
	if !sameBytes(dst, filepath.Join(tree, Share, "tacquito.logrotate")) {
		t.Fatal("not copied")
	}
	// A tree without the file: nothing.
	e.reset()
	if err := e.b.Install(context.Background(), backend.PhaseFiles, e.dir); err != nil || e.out() != "" {
		t.Fatal(err, e.out())
	}
}

func TestInstallAccountCreatesTheUserAndDirectories(t *testing.T) {
	e := newLifeTenv(t)
	tree := repoRoot(t)
	for _, d := range []string{e.p.Etc, e.p.Log} {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}
	e.run.On([]string{"id", "tacquito"}, execx.Result{Code: 1})
	if err := e.b.Install(context.Background(), backend.PhaseAccount, tree); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.out(), "Creating tacquito service user...")
	if !e.called(`^useradd --system --no-create-home --shell /usr/sbin/nologin tacquito$`) {
		t.Fatal(e.run.Argvs())
	}
	for d, mode := range map[string]os.FileMode{e.p.Etc: 0o755, e.p.Log: 0o750, filepath.Join(e.p.Etc, "README.md"): 0o644} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != mode {
			t.Fatal(d, err)
		}
	}
	if !sameBytes(filepath.Join(e.p.Etc, "README.md"), filepath.Join(tree, "README.md")) {
		t.Fatal("README.md")
	}

	// The user exists already; useradd failing is the phase's failure.
	e.reset()
	e.run.On([]string{"id", "tacquito"}, execx.Result{})
	if err := e.b.Install(context.Background(), backend.PhaseAccount, tree); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.out(), "Service user 'tacquito' already exists.")
	if e.called(`^useradd`) {
		t.Fatal(e.run.Argvs())
	}
	e2 := newLifeTenv(t)
	e2.run.On([]string{"id"}, execx.Result{Code: 1})
	e2.run.On([]string{"useradd"}, execx.Result{Code: 9})
	wantCode(t, e2.b.Install(context.Background(), backend.PhaseAccount, tree), 9)
}

func TestInstallAccountReadmeThatCannotBeWrittenWarns(t *testing.T) {
	e := newLifeTenv(t)
	if err := os.MkdirAll(filepath.Join(e.p.Etc, "README.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.b.Install(context.Background(), backend.PhaseAccount, repoRoot(t)); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.out(), "Could not install "+filepath.Join(e.p.Etc, "README.md")+".")
}

func TestInstallStart(t *testing.T) {
	e := newLifeTenv(t).withStoreLife("store.multiscope.yaml")
	e.render(false)
	e.run.On([]string{"ss"}, execx.Result{Stdout: []byte("LISTEN 0 128 *:49 *:*\n")})
	sd := e.systemd()
	if err := e.b.Install(context.Background(), backend.PhaseStart, repoRoot(t)); err != nil {
		t.Fatalf("%v\n%s", err, e.out())
	}
	for _, s := range []string{"Installing systemd service...", "Starting tacquito...", "Tacquito is running!", "Listening on port 49/tcp"} {
		mustContain(t, e.out(), s)
	}
	var order []string
	for _, a := range e.run.Argvs() {
		if strings.HasPrefix(a, "systemctl ") && !strings.HasPrefix(a, "systemctl show") {
			order = append(order, a)
		}
	}
	if !slices.Equal(order, []string{"systemctl daemon-reload", "systemctl daemon-reload", "systemctl enable tacquito.service",
		"systemctl start tacquito.service", "systemctl is-active --quiet tacquito.service"}) {
		t.Fatal(order)
	}
	if !sd.enabled["tacquito"] || !exists(e.b.serviceFile()) || !exists(e.dropIn("default")) {
		t.Fatal("not installed")
	}
	if !slices.Equal(e.sleeps, []time.Duration{2 * time.Second}) {
		t.Fatal(e.sleeps)
	}
	e.noKeep()
}

func TestInstallStartDaemonThatDoesNotComeUp(t *testing.T) {
	e := newLifeTenv(t).withStoreLife("store.multiscope.yaml")
	e.render(false)
	e.run.On([]string{"systemctl", "is-active"}, execx.Result{Code: 3})
	wantCode(t, e.b.Install(context.Background(), backend.PhaseStart, repoRoot(t)), 1)
	mustContain(t, e.stderr.String(), "Tacquito failed to start. Check: journalctl -u tacquito")
}

func TestInstallStartUnitsThatCannotBeInstalled(t *testing.T) {
	e := newLifeTenv(t)
	wantCode(t, e.b.Install(context.Background(), backend.PhaseStart, e.dir), 1)
	mustContain(t, e.out(), "Unit update stopped: the unit files are not under "+e.dir+"/"+Share+".")
	mustContain(t, e.stderr.String(), "Could not install the systemd units (see above).")
	if e.called(`^systemctl (enable|start)`) {
		t.Fatal(e.run.Argvs())
	}
}

// --- upgrade preflight and build failures ---------------------------------------

func TestUpgradePreflight(t *testing.T) {
	e := newLifeTenv(t)
	ctx := context.Background()
	if err := e.b.Upgrade(ctx, backend.PhasePreflight, ""); err != nil {
		t.Fatal(err)
	}
	if !e.called(`^git config --system --add safe.directory ` + e.src() + `$`) {
		t.Fatal(e.run.Argvs())
	}

	e.b.life.goBin = filepath.Join(e.dir, "no-go")
	wantCode(t, e.b.Upgrade(ctx, backend.PhasePreflight, ""), 1)
	mustContain(t, e.stderr.String(), "Go not found at "+e.b.life.goBin+". Install Go first.")

	if err := os.RemoveAll(e.src()); err != nil {
		t.Fatal(err)
	}
	e.reset()
	wantCode(t, e.b.Upgrade(ctx, backend.PhasePreflight, ""), 1)
	mustContain(t, e.stderr.String(), "Tacquito source not found at "+e.src()+". Run 'tacctl install' first.")
	if len(e.run.Calls()) != 0 {
		t.Fatal(e.run.Argvs())
	}
}

func TestUpgradeBuildFailureRestoresThePreviousBinary(t *testing.T) {
	e := newLifeTenv(t)
	repo := e.tacquitoRepo(commit1)
	repo.setRemote(commit2)
	bin := e.b.tacquitoBin()
	writeFile(t, bin, "old\n")
	e.run.On([]string{"go", "build", "-o", bin}, execx.Result{Code: 1})
	wantCode(t, e.b.Upgrade(context.Background(), backend.PhaseBuild, ""), 1)
	mustContain(t, e.stderr.String(), "Build failed. Restoring previous binary.")
	if readFile(t, bin) != "old\n" || exists(bin+".bak") {
		t.Fatal("not restored")
	}
	if e.called(`^go build -o ` + e.b.hashgenBin()) {
		t.Fatal(e.run.Argvs())
	}
}

func TestUpgradeBuildHashgenFailureIsNotCritical(t *testing.T) {
	e := newLifeTenv(t)
	repo := e.tacquitoRepo(commit1)
	repo.setRemote(commit2)
	writeFile(t, e.b.tacquitoBin(), "old\n")
	writeFile(t, e.b.hashgenBin(), "old\n")
	if err := os.Chmod(e.b.hashgenBin(), 0o700); err != nil {
		t.Fatal(err)
	}
	e.run.On([]string{"go", "build", "-o", e.b.hashgenBin()}, execx.Result{Code: 1})
	if err := e.b.Upgrade(context.Background(), backend.PhaseBuild, ""); err != nil {
		t.Fatal(err)
	}
	mustContain(t, e.out(), "Hashgen build failed (non-critical).")
	if st, _ := os.Stat(e.b.hashgenBin()); st.Mode().Perm() != 0o755 {
		t.Fatal(st.Mode())
	}
	// With no hash generator at all, 0.1.16's phase ends with status 1.
	e = newLifeTenv(t)
	repo = e.tacquitoRepo(commit1)
	repo.setRemote(commit2)
	e.run.On([]string{"go", "build", "-o", e.b.hashgenBin()}, execx.Result{Code: 1})
	wantCode(t, e.b.Upgrade(context.Background(), backend.PhaseBuild, ""), 1)
	if e.stderr.String() != "" {
		t.Fatalf("%q", e.stderr.String())
	}
}

func TestUpgradeBuildWithoutUpstreamEndsWithGitsStatus(t *testing.T) {
	e := newLifeTenv(t)
	e.tacquitoRepo(commit1)
	e.run.On([]string{"git", "rev-parse", "@{u}"}, execx.Result{Code: 128, Stderr: []byte("fatal: no upstream configured\n")})
	wantCode(t, e.b.Upgrade(context.Background(), backend.PhaseBuild, ""), 128)
	if e.called(`^git (pull|checkout)|^go `) {
		t.Fatal(e.run.Argvs())
	}
}

// --- uninstall program, data, account --------------------------------------------

func TestUninstallProgram(t *testing.T) {
	u := newUnitsEnv(t)
	u.install()
	u.b.unitsKeepDiscard()
	bin := u.b.tacquitoBin()
	for _, f := range []string{bin, bin + ".bak", u.b.hashgenBin()} {
		writeFile(t, f, "x\n")
	}
	u.reset()
	if err := u.b.Uninstall(context.Background(), backend.PhaseProgram, false); err != nil {
		t.Fatal(err)
	}
	mustContain(t, u.out(), "Removing systemd unit...")
	for _, f := range []string{bin, bin + ".bak", u.b.hashgenBin(), u.unit, u.tmpl, u.p.OverrideDir} {
		if exists(f) {
			t.Fatal(f)
		}
	}
	if !u.called(`^systemctl daemon-reload$`) {
		t.Fatal(u.run.Argvs())
	}
}

func TestUninstallData(t *testing.T) {
	e := newLifeTenv(t)
	now := time.Date(2026, 10, 3, 12, 34, 56, 0, time.Local)
	e.env.Now = func() time.Time { return now }
	writeFile(t, filepath.Join(e.p.LogrotateDir, "tacquito"), "x\n")
	writeFile(t, filepath.Join(e.p.Etc, "tacquito.yaml"), "x\n")
	writeFile(t, filepath.Join(e.p.Log, "accounting.log"), "x\n")
	if err := e.b.Uninstall(context.Background(), backend.PhaseData, true); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(e.dir, "root") + "/tacquito-logs-20261003_123456.tar.gz"
	if !e.called(`^tar czf ` + archive + ` -C ` + filepath.Dir(e.p.Log) + ` log/$`) {
		t.Fatal(e.run.Argvs())
	}
	mustContain(t, e.out(), "Accounting logs saved to "+archive)
	mustContain(t, e.out(), "Removing log directory...")
	if !slices.Equal(e.b.UninstallSaved(), []string{"Accounting logs saved to: " + archive}) {
		t.Fatal(e.b.UninstallSaved())
	}
	for _, d := range []string{filepath.Join(e.p.LogrotateDir, "tacquito"), e.p.Etc, e.p.Log} {
		if exists(d) {
			t.Fatal(d)
		}
	}
	// Without --keep-logs nothing is archived.
	e = newLifeTenv(t)
	if err := e.b.Uninstall(context.Background(), backend.PhaseData, false); err != nil {
		t.Fatal(err)
	}
	if e.called(`^tar`) || len(e.b.UninstallSaved()) != 0 || exists(e.p.Log) {
		t.Fatal(e.run.Argvs())
	}
}

func TestUninstallAccount(t *testing.T) {
	e := newLifeTenv(t)
	if err := e.b.Uninstall(context.Background(), backend.PhaseAccount, false); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(e.run.Argvs(), []string{
		"git config --system --unset-all safe.directory ^" + e.src() + "$",
		"id tacquito",
		"userdel tacquito",
	}) {
		t.Fatal(e.run.Argvs())
	}
	mustContain(t, e.out(), "Removing tacquito service user...")
	e = newLifeTenv(t)
	e.run.On([]string{"id"}, execx.Result{Code: 1})
	_ = e.b.Uninstall(context.Background(), backend.PhaseAccount, false)
	if e.called(`^userdel`) {
		t.Fatal(e.run.Argvs())
	}
}

// A phase a command does not have is a no-op.
func TestLifecycleUnknownPhaseIsANoOp(t *testing.T) {
	e := newLifeTenv(t)
	ctx := context.Background()
	if e.b.Install(ctx, backend.PhaseFinish, "") != nil || e.b.Upgrade(ctx, backend.PhaseStop, "") != nil ||
		e.b.Uninstall(ctx, backend.PhaseBuild, false) != nil || e.b.Install(ctx, "bogus", "") != nil {
		t.Fatal("not a no-op")
	}
	if len(e.run.Calls()) != 0 || e.out() != "" {
		t.Fatal(e.run.Argvs(), e.out())
	}
}
