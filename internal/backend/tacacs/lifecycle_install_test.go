package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
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
		"Go 1.27.2 already installed, skipping.",
		"Cloning tacquito...",
		"Building tacquito server...",
		"Building password hash generator...",
		"Binaries installed:",
		"  Server:  " + e.b.tacquitoBin(),
		"  Hashgen: " + e.b.hashgenBin(),
	} {
		mustContain(t, out, s)
	}
	if !e.called(`^git clone --quiet https://github\.com/rett/tacquito\.git ` + e.src() + `$`) {
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
	if e.dirOf("git", "checkout", "--", ".") != e.src() || e.dirOf("git", "pull", "--ff-only", "--quiet") != e.src() {
		t.Fatal(e.run.Argvs())
	}
	if e.called(`^git clone`) || e.called(`safe.directory --add|--add safe.directory`) {
		t.Fatal(e.run.Argvs())
	}
}

// The pull of the tacquito checkout cannot stall (install and upgrade): it
// fast-forwards, and a checkout that cannot is reset to its upstream with a
// warning that names both commits, since it is only a build tree. When the
// reset fails too the phase ends with the pull's status.
func TestBuildPullFastForwardsOrResets(t *testing.T) {
	const warn = "Tacquito source at SRC could not fast-forward; reset it to its upstream branch (was 1111111, now 2222222)."
	for _, upgrade := range []bool{false, true} {
		name := "install"
		if upgrade {
			name = "upgrade"
		}
		build := func(e *ltenv) error {
			if upgrade {
				return e.b.Upgrade(context.Background(), backend.PhaseBuild, "")
			}
			return e.b.Install(context.Background(), backend.PhaseBuild, "")
		}
		setup := func(t *testing.T) (*ltenv, *fakeTacquito) {
			e := newLifeTenv(t)
			e.goVersion(GoVersion)
			repo := e.tacquitoRepo(commit1)
			repo.setRemote(commit2)
			if upgrade {
				writeFile(t, e.b.tacquitoBin(), "old\n")
				writeFile(t, e.b.hashgenBin(), "old\n")
			}
			return e, repo
		}
		t.Run(name+" fast-forwards", func(t *testing.T) {
			e, _ := setup(t)
			if err := build(e); err != nil {
				t.Fatalf("%v\n%s", err, e.out())
			}
			if e.dirOf("git", "pull", "--ff-only", "--quiet") != e.src() || e.called(`^git pull --quiet`) || e.called(`^git reset`) {
				t.Fatal(e.run.Argvs())
			}
			mustNotContain(t, e.out(), "could not fast-forward")
			if got := readFile(t, e.b.tacquitoBin()); got != "built at "+commit2+"\n" {
				t.Fatalf("binary %q", got)
			}
		})
		t.Run(name+" resets to the upstream when it cannot fast-forward", func(t *testing.T) {
			e, repo := setup(t)
			repo.setDiverged(true, false)
			if err := build(e); err != nil {
				t.Fatalf("%v\n%s", err, e.out())
			}
			mustContain(t, e.out(), strings.ReplaceAll(warn, "SRC", e.src()))
			if e.dirOf("git", "reset", "--hard", "@{u}") != e.src() {
				t.Fatal(e.run.Argvs())
			}
			// the reset follows the checkout of the patched files and the
			// failed pull, and the build is of the upstream's commit
			var pull, reset, build int = -1, -1, -1
			for i, a := range e.run.Argvs() {
				switch {
				case a == "git pull --ff-only --quiet":
					pull = i
				case a == "git reset --hard @{u}":
					reset = i
				case strings.HasPrefix(a, "go build") && build < 0:
					build = i
				}
			}
			if pull < 0 || reset < pull || build < reset {
				t.Fatal(e.run.Argvs())
			}
			if got := readFile(t, e.b.tacquitoBin()); got != "built at "+commit2+"\n" {
				t.Fatalf("binary %q", got)
			}
		})
		t.Run(name+" fails with the pull's status when the reset fails too", func(t *testing.T) {
			e, repo := setup(t)
			repo.setDiverged(true, true)
			wantCode(t, build(e), 128)
			mustNotContain(t, e.out(), "could not fast-forward")
			if e.called(`^go `) {
				t.Fatal(e.run.Argvs())
			}
			if upgrade {
				bin := e.b.tacquitoBin()
				if readFile(t, bin) != "old\n" || exists(bin+".bak") {
					t.Fatal("the previous binary is not back")
				}
			}
		})
	}
}

// A checkout cloned from upstream tacquito (before 0.2.24) is pointed at
// the fork before it is pulled, by install and by upgrade; an origin set by
// hand stays, and a set-url that fails is a warning.
func TestBuildRepointsAnUpstreamCheckoutAtTheFork(t *testing.T) {
	for _, tc := range []struct {
		name, origin, want string
		fails, upgrade     bool
		getFails, rerun    bool
		say                string
	}{
		{name: "install", origin: TacquitoUpstreamRepo, want: TacquitoRepo,
			say: "Tacquito source now pulls from " + TacquitoRepo + " (was " + TacquitoUpstreamRepo + ")."},
		{name: "upgrade", origin: TacquitoUpstreamRepo, want: TacquitoRepo, upgrade: true,
			say: "Tacquito source now pulls from " + TacquitoRepo},
		{name: "no .git", origin: "https://github.com/facebookincubator/tacquito/", want: TacquitoRepo,
			say: "(was https://github.com/facebookincubator/tacquito)."},
		{name: "by hand", origin: "https://git.example.com/tacquito.git", want: "https://git.example.com/tacquito.git"},
		{name: "fork", origin: TacquitoRepo, want: TacquitoRepo},
		{name: "fails", origin: TacquitoUpstreamRepo, want: TacquitoUpstreamRepo, fails: true,
			say: "Could not point " + "SRC" + " at " + TacquitoRepo + "; it still pulls from " + TacquitoUpstreamRepo + "."},
		{name: "upgrade fails", origin: TacquitoUpstreamRepo, want: TacquitoUpstreamRepo, fails: true, upgrade: true,
			say: "Could not point " + "SRC" + " at " + TacquitoRepo},
		{name: "no origin", origin: TacquitoUpstreamRepo, want: TacquitoUpstreamRepo, getFails: true, upgrade: true},
		// The run re-executed by the self-update (the new binary): the old
		// binary's run pulled upstream and built, left tacquito.bak, and
		// could not repoint; this run does, before it fetches.
		{name: "re-exec", origin: TacquitoUpstreamRepo, want: TacquitoRepo, upgrade: true, rerun: true,
			say: "Tacquito source now pulls from " + TacquitoRepo},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newLifeTenv(t)
			e.goVersion(GoVersion)
			repo := e.tacquitoRepo(commit1)
			repo.setOrigin(tc.origin)
			repo.setURLFails = tc.fails
			repo.getURLFails = tc.getFails
			var err error
			if tc.rerun {
				writeFile(t, e.b.tacquitoBin(), "built at "+commit1+"\n")
				writeFile(t, e.b.tacquitoBin()+".bak", "old\n")
				e.b.SetUpgradeFrom("0000000")
			}
			if tc.upgrade {
				if !tc.rerun {
					writeFile(t, e.b.tacquitoBin(), "old\n")
				}
				err = e.b.Upgrade(context.Background(), backend.PhaseBuild, "")
			} else {
				err = e.b.Install(context.Background(), backend.PhaseBuild, "")
			}
			if err != nil {
				t.Fatalf("%v\n%s", err, e.out())
			}
			if got := repo.originURL(); got != tc.want {
				t.Fatalf("origin %q, want %q", got, tc.want)
			}
			if tc.say != "" {
				mustContain(t, e.out(), strings.ReplaceAll(tc.say, "SRC", e.src()))
			}
			if tc.origin == tc.want && !tc.fails && e.called(`^git remote set-url`) {
				t.Fatal(e.run.Argvs())
			}
			// The origin is read and moved before anything is fetched or
			// pulled from it.
			getURL, setURL, pull := -1, -1, -1
			for i, a := range e.run.Argvs() {
				switch {
				case a == "git remote get-url origin" && getURL < 0:
					getURL = i
				case strings.HasPrefix(a, "git remote set-url origin ") && setURL < 0:
					setURL = i
				case (a == "git fetch --quiet" || a == "git pull --ff-only --quiet") && pull < 0:
					pull = i
				}
			}
			if pull < 0 || getURL < 0 || getURL > pull || (setURL >= 0 && setURL > pull) {
				t.Fatal(e.run.Argvs())
			}
			if tc.rerun {
				mustContain(t, e.out(), "The binary built from it is not running yet.")
				if e.called(`^go build`) {
					t.Fatal(e.run.Argvs())
				}
			}
		})
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
	e.run.On([]string{"git", "reset"}, execx.Result{Code: 1})
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
	for d, mode := range map[string]os.FileMode{e.p.Etc: 0o755, e.p.Log: 0o750} {
		if st, err := os.Stat(d); err != nil || st.Mode().Perm() != mode {
			t.Fatal(d, err)
		}
	}
	if exists(filepath.Join(e.p.Etc, "README.md")) {
		t.Fatal("README.md installed into the daemon's directory")
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
		"systemctl reset-failed tacquito.service tacquito@*.service", "systemctl start tacquito.service", "systemctl is-active --quiet tacquito.service"}) {
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
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	// tacctl runs with umask 077; the restored binary must stay executable
	// for the tacquito user.
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	e.run.On([]string{"go", "build", "-o", bin}, execx.Result{Code: 1})
	wantCode(t, e.b.Upgrade(context.Background(), backend.PhaseBuild, ""), 1)
	mustContain(t, e.stderr.String(), "Build failed. Restoring previous binary.")
	if readFile(t, bin) != "old\n" || exists(bin+".bak") {
		t.Fatal("not restored")
	}
	if st, err := os.Stat(bin); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("restored binary mode %v (%v), want 0755", st.Mode().Perm(), err)
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
