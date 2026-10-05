package lifecycle_test

// install, upgrade and uninstall as a whole (WP3.3d), with stand-in
// backends that record every phase, on a host whose every path is in the
// sandbox (TestOrchestrationIsSandboxed). Ported here: tests/unit/deps.bats
// (ensure_dependencies) and the install-flow tests of
// tests/e2e/install_seed.bats (the order of README.md and the seed,
// uninstall_remove_access, what cmd_uninstall removes).

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
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// stand is a stand-in backend for the orchestration: it prints and records
// each lifecycle phase ("<id> <lifecycle> <phase>"), notes whether the
// store existed at that moment, can fail one phase, and leaves a summary
// and a handover.
type stand struct {
	*faketest.Backend
	o       *ohost
	failAt  string // "<lifecycle> <phase>"
	summary backend.UpgradeSummary
	saved   []string
	from    *string // what SetUpgradeFrom got (nil: never called)
	hand    []string
	logDir  string
}

func (s *stand) phase(verb string, p backend.Phase, extra string) error {
	line := s.ID() + " " + verb + " " + string(p)
	if extra != "" {
		line += " " + extra
	}
	s.o.phases = append(s.o.phases, line)
	_, err := os.Stat(s.o.p.StoreFile)
	s.o.storeAt[line] = err == nil
	s.o.out.Info("PHASE " + line)
	if s.failAt == verb+" "+string(p) {
		s.o.out.Error("PHASE FAILED " + line)
		return &backend.Error{Code: 7, Reason: "stand-in"}
	}
	return nil
}

func (s *stand) Install(ctx context.Context, p backend.Phase, tree string) error {
	if err := s.phase("install", p, tree); err != nil {
		return err
	}
	return s.Backend.Install(ctx, p, tree)
}
func (s *stand) Upgrade(_ context.Context, p backend.Phase, tree string) error {
	return s.phase("upgrade", p, tree)
}
func (s *stand) Uninstall(_ context.Context, p backend.Phase, keep bool) error {
	extra := ""
	if keep {
		extra = "--keep-logs"
	}
	return s.phase("uninstall", p, extra)
}
func (s *stand) Describe() backend.Description {
	d := s.Backend.Describe()
	d.Impl, d.LogDir = s.ID()+"-daemon", s.logDir
	return d
}
func (s *stand) UpgradeSummary() backend.UpgradeSummary { return s.summary }
func (s *stand) UninstallSaved() []string               { return s.saved }
func (s *stand) SetUpgradeFrom(c string)                { s.from = &c }
func (s *stand) UpgradeHandover() []string              { return s.hand }

// ohost is a host: tacctl's fixed locations rerooted into the sandbox, a
// source tree with the shipped files, the deploy clone, two stand-ins
// (tacacs, radius).
type ohost struct {
	t        *testing.T
	w        string
	p        paths.Paths
	run      *fake.Runner
	out      ui.Output
	stdout   *bytes.Buffer
	stderr   *bytes.Buffer
	tac, rad *stand
	set      *backend.Set
	be       *backend.Env
	environ  []string
	commit   string
	stdin    string
	phases   []string
	storeAt  map[string]bool
	head     string // the deploy clone's HEAD (git rev-parse HEAD)
}

func newOhost(t *testing.T) *ohost {
	t.Helper()
	w := t.TempDir()
	o := &ohost{t: t, w: w, run: &fake.Runner{}, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
		storeAt: map[string]bool{}, commit: "c0ffee", head: "c0ffee"}
	o.out = ui.Output{Stdout: o.stdout, Stderr: o.stderr}
	j := func(p ...string) string { return filepath.Join(append([]string{w}, p...)...) }
	o.environ = []string{"PATH=/usr/bin:/bin",
		"TACCTL_ETC=" + j("etc"), "TACCTL_STATE_DIR=" + j("state"), "TACCTL_LOG=" + j("log"), "TACCTL_BIN=" + j("bin"),
		"TACCTL_CONFIG=" + j("etc", "tacquito.yaml"),
		"TACCTL_SUDOERS_FILE=" + j("sudoers.d", "tacctl"), "TACCTL_TIER_SUDOERS_FILE=" + j("sudoers.d", "tacctl-tiers"),
		"TACCTL_SYSTEMD_DIR=" + j("systemd"), "TACCTL_OVERRIDE_DIR=" + j("systemd", "tacquito.service.d"),
		"TACCTL_LOGROTATE_DIR=" + j("logrotate.d"), "TACQUITO_SRC=" + j("tacquito-src"),
		"TACCTL_LINUX_DIR=" + j("var-lib-tacctl", "linux"), "TACCTL_VAR_LIB=" + j("var-lib-tacctl"), "TACCTL_TREE=" + j("tree"),
		"TACCTL_SSHD_DROPIN=" + j("sshd_config.d", "tacctl-console.conf"), "TACCTL_SHELLS_FILE=" + j("shells"),
		"TACCTL_RADIUS_DIR=" + j("raddb"), "TACCTL_RADIUS_LOG=" + j("radius-log"),
		"TACCTL_RADIUS_BIN=" + j("radius-bin", "radiusd"), "TACCTL_RADIUS_DICT=" + j("radius-share", "dictionary"),
		"TMPDIR=" + j("tmp"),
	}
	o.p = paths.Resolve(paths.NewEnv(o.environ), "", func(string) bool { return false }).Reroot(w)
	for _, d := range []string{"etc", "log", "tmp", "tree/bin", "tree/config", "tree/man", "tree/config/backends/tacacs",
		filepath.Dir(o.p.Command), filepath.Dir(o.p.Completion), "root"} {
		if err := os.MkdirAll(filepath.Join(w, strings.TrimPrefix(d, w)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", j("tmp"))
	o.write(j("tree", "bin", "tacctl.sh"), "#!/bin/bash\n# the shim\n")
	o.write(j("tree", "man", "tacctl.1"), ".TH TACCTL 1\n")
	o.write(j("tree", "go.mod"), "module github.com/rett/tacctl\n")

	reg := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	o.tac = &stand{Backend: faketest.New(backend.TACACS, o.p.Config, j("tacstate")), o: o, logDir: o.p.Log}
	o.rad = &stand{Backend: faketest.New(backend.RADIUS, j("raddb", "tacctl-radius.conf"), j("radstate")), o: o,
		logDir: j("radius-log")}
	for _, s := range []*stand{o.tac, o.rad} {
		if err := reg.Add(s.ID(), func(env *backend.Env) backend.Backend { s.Env = env; return s }); err != nil {
			t.Fatal(err)
		}
	}
	snaps := snapshot.New(o.p, "0.2.0-test", nil, o.out)
	snaps.Chown = nil
	cfg := conf.Load(o.p.Overrides, reg.IDs())
	cfg.Owner = nil
	o.be = &backend.Env{Paths: o.p, Conf: cfg, Runner: o.run, Out: o.out, Now: func() time.Time {
		return time.Date(2026, 10, 3, 12, 34, 56, 0, time.Local)
	}, Snapshots: snaps}
	o.set = backend.NewSet(reg, o.be)
	o.script()
	return o
}

// script plays git (the deploy clone and its build recipe), dpkg-query
// (everything installed) and apt-get.
func (o *ohost) script() {
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "dpkg-query" }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte("install ok installed")}, nil
	})
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "git" }, func(c execx.Cmd) (execx.Result, error) {
		a := strings.Join(c.Args, " ")
		switch {
		case strings.HasPrefix(a, "clone "):
			dst := c.Args[len(c.Args)-1]
			o.write(filepath.Join(dst, "bin", "tacctl.sh"), "#!/bin/bash\n")
			o.write(filepath.Join(dst, "go.mod"), "module github.com/rett/tacctl\n")
			_ = os.MkdirAll(filepath.Join(dst, ".git"), 0o755)
		case a == "rev-parse HEAD", a == "rev-parse @{u}":
			return execx.Result{Stdout: []byte(o.head + "\n")}, nil
		case a == "rev-parse --short HEAD":
			return execx.Result{Stdout: []byte(o.head[:6] + "\n")}, nil
		}
		return execx.Result{}, nil
	})
	o.run.Func(func(c execx.Cmd) bool { return strings.HasSuffix(c.Name, "/bin/tacctl.sh") }, func(c execx.Cmd) (execx.Result, error) {
		o.write(c.Args[1], "new binary\n")
		_ = os.Chmod(c.Args[1], 0o755)
		return execx.Result{}, nil
	})
}

func (o *ohost) write(path, text string) {
	o.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		o.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		o.t.Fatal(err)
	}
}

func (o *ohost) host() *lifecycle.Host {
	o.be.Prompter = ui.NewPrompter(strings.NewReader(o.stdin), o.out)
	env := lifecycle.NewEnv(o.be, bytes.NewReader(bytes.Repeat([]byte{0xab}, 64)), false)
	env.Chown = func(string) {}
	return &lifecycle.Host{Env: env, Environ: paths.NewEnv(o.environ), Commit: o.commit, Completion: testCompletion}
}

// do runs one command; the exit status.
func (o *ohost) do(f func(context.Context, *lifecycle.Host, []string) error, args ...string) int {
	o.t.Helper()
	o.stdout.Reset()
	o.stderr.Reset()
	o.run.Reset()
	o.phases = nil
	err := f(context.Background(), o.host(), args)
	return backend.ExitCode(err)
}

func (o *ohost) text() string { return stripANSI(o.stdout.String()) }

// inOrder: each pattern found in s after the one before it.
func inOrder(t *testing.T, s string, patterns ...string) {
	t.Helper()
	at := 0
	for _, p := range patterns {
		i := strings.Index(s[at:], p)
		if i < 0 {
			t.Fatalf("%q missing after offset %d in:\n%s", p, at, s)
		}
		at += i + len(p)
	}
}

func (o *ohost) enableBoth() {
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs, radius]\n")
	o.be.Conf.Reload()
}

// Every path the orchestration can write is in the sandbox.
func TestOrchestrationIsSandboxed(t *testing.T) {
	o := newOhost(t)
	root := o.w + string(filepath.Separator)
	p := o.p
	for name, path := range map[string]string{
		"Etc": p.Etc, "StateDir": p.StateDir, "Log": p.Log, "Bin": p.Bin, "Config": p.Config, "Templates": p.Templates,
		"SudoersFile": p.SudoersFile, "TierSudoersFile": p.TierSudoersFile, "SystemdDir": p.SystemdDir,
		"OverrideDir": p.OverrideDir, "TacacsUnitDir": p.TacacsUnitDir, "LogrotateDir": p.LogrotateDir,
		"TacquitoSrc": p.TacquitoSrc, "LinuxDir": p.LinuxDir, "VarLib": p.VarLib, "KnownHosts": p.KnownHosts,
		"Tree": p.Tree, "PatchDir": p.PatchDir, "Deploy": p.Deploy, "Command": p.Command, "GoBin": p.GoBin, "Completion": p.Completion,
		"ManPage": p.ManPage, "ArchiveDir": p.ArchiveDir,
		"radius Dir": p.Radius("debian").Dir, "radius LogDir": p.Radius("rhel").LogDir,
		"radius DropIn": p.Radius("debian").DropIn, "radius Logrotate": p.Radius("rhel").Logrotate,
	} {
		if !strings.HasPrefix(filepath.Clean(path)+string(filepath.Separator), root) {
			t.Errorf("%s=%s is outside the sandbox", name, path)
		}
	}
}

// --- ensure_dependencies (tests/unit/deps.bats) ---------------------------------

// dpkg plays dpkg-query: the packages of have are installed.
func (o *ohost) dpkg(have ...string) {
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "dpkg-query" }, func(c execx.Cmd) (execx.Result, error) {
		if slices.Contains(have, c.Args[len(c.Args)-1]) {
			return execx.Result{Stdout: []byte("install ok installed")}, nil
		}
		return execx.Result{Code: 1}, nil
	})
}

func deps(o *ohost) int {
	return o.do(func(ctx context.Context, h *lifecycle.Host, _ []string) error { return h.EnsureDependencies(ctx) })
}

func TestDepsNothingMissingInstallsNothing(t *testing.T) {
	o := newOhost(t)
	o.dpkg(append(slices.Clone(lifecycle.DepsCore), lifecycle.DepsLinuxHosts...)...)
	if deps(o) != 0 || !strings.Contains(o.text(), "Required packages: all present.") || o.run.Called("apt-get") {
		t.Errorf("out %q calls %v", o.text(), o.run.Argvs())
	}
	// python3 and its modules left the required set (3.9 item 6).
	if slices.Contains(lifecycle.DepsCore, "python3") || !slices.Equal(lifecycle.DepsCore, []string{"git", "wget"}) {
		t.Errorf("DepsCore %v", lifecycle.DepsCore)
	}
}

func TestDepsInstallsOnlyWhatIsMissing(t *testing.T) {
	o := newOhost(t)
	have := append(slices.Clone(lifecycle.DepsCore), lifecycle.DepsLinuxHosts...)
	o.dpkg(slices.DeleteFunc(have, func(p string) bool { return p == "podman" || p == "uidmap" })...)
	if deps(o) != 0 {
		t.Fatalf("exit: %s", o.stderr)
	}
	calls := o.run.Calls()
	var apt []execx.Cmd
	for _, c := range calls {
		if c.Name == "apt-get" {
			apt = append(apt, c)
		}
	}
	if len(apt) != 1 || strings.Join(apt[0].Args, " ") != "install -y -qq podman uidmap" ||
		!slices.Contains(apt[0].Env, "DEBIAN_FRONTEND=noninteractive") || !slices.Contains(apt[0].Env, "PATH=/usr/bin:/bin") {
		t.Errorf("apt calls %+v", apt)
	}
	if !strings.Contains(o.text(), "Installing packages for Linux host support: podman uidmap") {
		t.Errorf("out %q", o.text())
	}
}

func TestDepsMissingCorePackageThatCannotBeInstalledIsFatal(t *testing.T) {
	o := newOhost(t)
	o.dpkg(append([]string{"git"}, lifecycle.DepsLinuxHosts...)...)
	o.run.On([]string{"apt-get", "install"}, execx.Result{Code: 100})
	if code := deps(o); code != 1 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(stripANSI(o.stderr.String()), "[ERROR] Could not install: wget. Install them and re-run.") ||
		!o.run.Called("apt-get", "update", "-qq") || o.run.Count("apt-get", "install") != 2 {
		t.Errorf("err %q calls %v", o.stderr, o.run.Argvs())
	}
}

func TestDepsMissingLinuxHostPackagesOnlyWarn(t *testing.T) {
	o := newOhost(t)
	o.dpkg(lifecycle.DepsCore...)
	o.run.On([]string{"apt-get", "install"}, execx.Result{Code: 100})
	if code := deps(o); code != 0 || !strings.Contains(o.text(), "everything else works") {
		t.Errorf("exit %d out %q", code, o.text())
	}
}

func TestDepsNotDebianWarnsWithTheList(t *testing.T) {
	o := newOhost(t)
	o.run.Missing("apt-get")
	if code := deps(o); code != 0 || !strings.Contains(o.text(), "[WARN] Not a Debian/Ubuntu system") ||
		!strings.Contains(o.text(), "[WARN]   git wget openssh-client") || o.run.Called("dpkg-query") {
		t.Errorf("exit %d out %q", code, o.text())
	}
}

// --- templates (the 0.1.16 manifest rule) ---------------------------------------

func templatesSync(o *ohost) (lifecycle.TemplateSync, int) {
	var res lifecycle.TemplateSync
	code := o.do(func(ctx context.Context, h *lifecycle.Host, _ []string) error {
		var err error
		res, err = h.TemplatesSync(ctx, o.p.Tree)
		return err
	})
	return res, code
}

// A first sync installs every shipped template (0600) and writes the
// manifest byte for byte as 0.1.16's templates_sync does: the golden was
// made from the 0.1.17 tag with
//
//	git archive 0.1.17 | tar -x -C "$T"
//	env -i PATH=/usr/bin:/bin TACCTL_SKIP_SUDO=1 TACCTL_ETC="$D/etc" TACCTL_STATE_DIR="$D/state" \
//	    bash -c 'set -euo pipefail; source "$1"; templates_sync "$2" >/dev/null' _ "$T/bin/tacctl.sh" "$T"
//	cp "$D/state/templates/.shipped.sha256" tests/fixtures/golden/templates.manifest
//
// A second sync writes nothing.
func TestTemplatesSyncFreshAndManifestGolden(t *testing.T) {
	o := newOhost(t)
	res, code := templatesSync(o)
	if code != 0 || res.Updated != 7 || len(res.Customised) != 0 {
		t.Fatalf("exit %d res %+v err %s", code, res, o.stderr)
	}
	inOrder(t, o.text(), "Installed: template: cisco-legacy.template", "Installed: template: cisco-radius.template",
		"Installed: template: cisco.template", "Installed: template: juniper-radius.template",
		"Installed: template: juniper.template", "Installed: template: wti-radius.template", "Installed: template: wti.template")
	manifest := filepath.Join(o.p.Templates, lifecycle.TemplateManifest)
	if got, want := readFile(t, manifest), fixture(t, "golden/templates.manifest"); got != want {
		t.Errorf("manifest differs from the 0.1.17 golden:\n%s\nwant\n%s", got, want)
	}
	for _, f := range []string{manifest, filepath.Join(o.p.Templates, "cisco.template")} {
		if st, _ := os.Stat(f); st.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, st.Mode())
		}
	}
	before, _ := os.Stat(manifest)
	time.Sleep(10 * time.Millisecond)
	res, _ = templatesSync(o)
	after, _ := os.Stat(manifest)
	if res.Updated != 0 || !before.ModTime().Equal(after.ModTime()) || strings.Count(o.text(), "Unchanged: template:") != 7 {
		t.Errorf("second sync: %+v %s", res, o.text())
	}
}

// A template the operator changed is kept, the shipped one goes beside it
// as .template.new (warned); one tacctl wrote earlier (its recorded hash)
// is updated; going back to the shipped text drops the .new.
func TestTemplatesSyncCustomisedAndRecorded(t *testing.T) {
	o := newOhost(t)
	templatesSync(o)
	cisco := filepath.Join(o.p.Templates, "cisco.template")
	o.write(cisco, "my own\n")
	res, code := templatesSync(o)
	if code != 0 || !slices.Equal(res.Customised, []string{"cisco.template"}) || res.Updated != 0 {
		t.Fatalf("res %+v", res)
	}
	if readFile(t, cisco) != "my own\n" || !strings.Contains(o.text(), "[WARN]   Customised template kept: "+cisco) ||
		!strings.Contains(o.text(), "[WARN]     Compare: diff "+cisco+" "+cisco+".new  (to take it: mv "+cisco+".new "+cisco+")") {
		t.Errorf("out %s", o.text())
	}
	shipped := readFile(t, cisco+".new")
	// An old shipped version (the manifest records what tacctl wrote).
	manifest := filepath.Join(o.p.Templates, lifecycle.TemplateManifest)
	m := readFile(t, manifest)
	o.write(cisco, "old shipped\n")
	old := sha256.Sum256([]byte("old shipped\n"))
	o.write(manifest, strings.Replace(m, fixtureSum(t, m, "cisco.template"), hex.EncodeToString(old[:]), 1))
	res, _ = templatesSync(o)
	if res.Updated != 1 || readFile(t, cisco) != shipped || !strings.Contains(o.text(), "Updated: template: cisco.template") {
		t.Errorf("res %+v out %s", res, o.text())
	}
	if _, err := os.Stat(cisco + ".new"); err == nil {
		t.Error(".new left beside a shipped template")
	}
	if readFile(t, manifest) != fixture(t, "golden/templates.manifest") {
		t.Errorf("manifest %s", readFile(t, manifest))
	}
}

// Without a record, the git history of the tree decides: a content some
// commit had is tacctl's; anything else (or no clone) is customised.
func TestTemplatesSyncHistoryFallback(t *testing.T) {
	o := newOhost(t)
	o.write(filepath.Join(o.p.Templates, "wti.template"), "old wti\n")
	o.write(filepath.Join(o.p.Templates, "juniper.template"), "custom juniper\n")
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "git" && slices.Contains(c.Args, "hash-object") },
		func(c execx.Cmd) (execx.Result, error) {
			data, _ := os.ReadFile(c.Args[len(c.Args)-1])
			return execx.Result{Stdout: []byte("blob-" + strings.Fields(string(data))[0] + "\n")}, nil
		})
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "git" && slices.Contains(c.Args, "log") },
		func(c execx.Cmd) (execx.Result, error) {
			if c.Args[len(c.Args)-1] == "config/templates/wti.template" {
				return execx.Result{Stdout: []byte(":100644 100644 aaaa blob-old M\tconfig/templates/wti.template\n")}, nil
			}
			return execx.Result{}, nil
		})
	res, _ := templatesSync(o)
	if !slices.Equal(res.Customised, []string{"juniper.template"}) || res.Updated != 6 {
		t.Errorf("res %+v\n%s", res, o.text())
	}
	if !o.run.Called("git", "-C", o.p.Tree, "rev-parse", "--git-dir") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	// Not a clone: anything that differs is customised.
	o = newOhost(t)
	o.write(filepath.Join(o.p.Templates, "wti.template"), "old wti\n")
	o.run.On([]string{"git", "-C", o.p.Tree, "rev-parse"}, execx.Result{Code: 128})
	if res, _ := templatesSync(o); !slices.Equal(res.Customised, []string{"wti.template"}) {
		t.Errorf("res %+v", res)
	}
}

func fixtureSum(t *testing.T, manifest, name string) string {
	t.Helper()
	for _, l := range strings.Split(manifest, "\n") {
		if f := strings.Fields(l); len(f) == 2 && f[1] == name {
			return f[0]
		}
	}
	t.Fatalf("%s not in the manifest", name)
	return ""
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// --- install ---------------------------------------------------------------------

func install(o *ohost, args ...string) int { return o.do(lifecycle.Install, args...) }

// The plan, then a closed stdin (or any answer but y/Y) cancels with exit
// 0 before anything runs; an unknown argument or --branch without a value
// is refused with the usage, exit 1, before anything runs; git and wget
// are required first.
func TestInstallCancelPrereqsAndBranchUsage(t *testing.T) {
	o := newOhost(t)
	for _, answer := range []string{"", "n\n", "yes\n", "Y1\n"} {
		o.stdin = answer
		if code := install(o, "--branch", "feature/x"); code != 0 {
			t.Fatalf("exit %d", code)
		}
		inOrder(t, o.text(), "  tacctl Installer", "Install tacctl ("+o.p.Deploy+", "+o.p.Command+") and its state directory ("+o.p.StateDir+")",
			"Go 1.26.2 (if not present)", "RADIUS (FreeRADIUS) is not installed; add it later with: tacctl backend enable radius", "[INFO] Cancelled.")
		if len(o.phases) != 0 || len(o.run.Calls()) != 0 {
			t.Errorf("ran %v %v", o.phases, o.run.Argvs())
		}
	}
	o.stdin = ""
	for bad, args := range map[string][]string{"--branch": {"--branch"}, "whatever": {"whatever", "--branch", "feature/x"},
		"extra": {"-y", "extra"}} {
		want := "[ERROR] Unknown argument: '" + bad + "'\n[ERROR] Usage: tacctl install [--branch <name>] [-y|--yes]\n"
		if code := install(o, args...); code != 1 || o.stdout.Len() != 0 || stripANSI(o.stderr.String()) != want ||
			len(o.phases) != 0 || len(o.run.Calls()) != 0 {
			t.Errorf("%q: exit %d %q %q", args, code, o.stdout, o.stderr)
		}
	}
	o.run.Missing("wget")
	if code := install(o, "-y"); code != 1 || stripANSI(o.stderr.String()) != "[ERROR] Required command 'wget' not found. Install it first.\n" ||
		o.stdout.Len() != 0 {
		t.Errorf("no wget: exit %d %q %q", code, o.stdout, o.stderr)
	}
}

// A fresh install, -y: 0.1.16's order (cmd_install), each backend's
// phases with the source tree, README.md's 'account' phase before the
// seed (install_seed.bats "cmd_install places README.md after the config
// directory exists"), the clone, the installed command built from it, the
// completion and the man page, the summary with the new secret.
func TestInstallFresh(t *testing.T) {
	o := newOhost(t)
	o.commit = "something-else" // a dev binary: the command is built from the clone
	if code := install(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	tree := o.p.Tree
	if want := []string{"tacacs install build " + tree, "tacacs install files " + tree, "tacacs install account " + tree,
		"tacacs install start " + tree}; !slices.Equal(o.phases, want) {
		t.Errorf("phases %v", o.phases)
	}
	if o.storeAt["tacacs install account "+tree] || !o.storeAt["tacacs install start "+tree] {
		t.Errorf("the seed is not between 'account' and 'start': %v", o.storeAt)
	}
	inOrder(t, o.text(), "PHASE tacacs install build", "[INFO] Management repo cloned to "+o.p.Deploy,
		"[INFO] Building "+o.p.Command+" from "+o.p.Deploy+"...", "Installed: template: cisco-legacy.template",
		"[INFO] Config templates installed: "+o.p.Templates+"/", "PHASE tacacs install files",
		"[INFO] Bash completion installed: "+o.p.Completion, "[INFO] Man page installed: "+o.p.ManPage,
		"[INFO] Management CLI installed:", "[INFO]   Deploy source: "+o.p.Deploy, "[INFO] Required packages: all present.",
		"PHASE tacacs install account", "Seeding the store at", "PHASE tacacs install start",
		"  Installation Complete", "  Shared Secret:  abababababababababababababababab",
		"SAVE THE SHARED SECRET (shown again by: tacctl scope secret lab show).", "9. Review config:          tacctl config show")
	if !o.run.Called("git", "clone", "--quiet", paths.ManageRepo, o.p.Deploy) ||
		!o.run.Called(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "--build", o.p.Command) {
		t.Errorf("calls %v", o.run.Argvs())
	}
	for f, mode := range map[string]os.FileMode{o.p.Completion: 0o644, o.p.ManPage: 0o644, filepath.Join(o.p.Deploy, "bin", "tacctl.sh"): 0o755} {
		if st, err := os.Stat(f); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", f, st, err)
		}
	}
	if readFile(t, o.p.Command) != "new binary\n" {
		t.Error("the installed command is not the built binary")
	}
	// No python anywhere.
	for _, c := range o.run.Argvs() {
		if strings.Contains(c, "python") {
			t.Errorf("ran %s", c)
		}
	}
}

// Over an existing clone: pulled (on --branch's branch), the installed
// command left alone when it is this binary at the clone's HEAD; an
// existing store is kept.
func TestInstallOverExistingCloneAndStore(t *testing.T) {
	o := newOhost(t)
	o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "#!/bin/bash\n")
	_ = os.MkdirAll(filepath.Join(o.p.Deploy, ".git"), 0o755)
	o.write(o.p.Command, "the shim built this\n")
	_ = os.Chmod(o.p.Command, 0o755)
	o.write(o.p.StoreFile, fixture(t, "store.minimal.yaml"))
	if code := install(o, "--branch", "develop", "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	inOrder(t, o.text(), "Management repo already cloned at "+o.p.Deploy+", pulling latest...",
		"Existing store found at", "  Existing store kept: users, groups, scopes and shared secrets are unchanged.",
		"  Show a scope's shared secret: tacctl scope secret <scope> show")
	if !o.run.Called("git", "checkout", "develop") || !o.run.Called("git", "pull", "--quiet") || o.run.Called("git", "clone") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	if readFile(t, o.p.Command) != "the shim built this\n" || strings.Contains(o.text(), "Shared Secret:") {
		t.Errorf("rebuilt, or a secret shown:\n%s", o.text())
	}
}

// Over an existing store, a backend's 'upgrade config' phase that fails is
// named with the way to finish (after its own messages), and the install
// carries on to the start phase and the summary, exit 0.
func TestInstallOverAStoreWarnsWhenABackendsConfigStepFails(t *testing.T) {
	o := newOhost(t)
	o.enableBoth()
	o.write(o.p.StoreFile, fixture(t, "store.minimal.yaml"))
	o.tac.failAt = "upgrade config"
	if code := install(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	inOrder(t, o.text(), "Existing store found at", "PHASE tacacs upgrade config",
		"[WARN] tacacs: configuration step failed (see above); run 'tacctl upgrade' after the install",
		"PHASE radius upgrade config", "PHASE tacacs install start", "  Installation Complete")
	if strings.Contains(o.text(), "radius: configuration step failed") {
		t.Errorf("a backend that did not fail is named:\n%s", o.text())
	}
}

// 'install --branch <bash release>': the clone is a tree of the bash era
// (lib/core.sh, no go.mod), which has nothing to build; the install stops
// before building, with the release's own installer to run, exit 1.
func TestInstallBranchOfABashReleaseStopsBeforeBuilding(t *testing.T) {
	o := newOhost(t)
	o.commit = "something-else"
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "git" && len(c.Args) > 0 && c.Args[0] == "clone" },
		func(c execx.Cmd) (execx.Result, error) {
			dst := c.Args[len(c.Args)-1]
			o.write(filepath.Join(dst, "bin", "tacctl.sh"), "#!/bin/bash\n")
			o.write(filepath.Join(dst, "lib", "core.sh"), "# bash era\n")
			_ = os.MkdirAll(filepath.Join(dst, ".git"), 0o755)
			return execx.Result{}, nil
		})
	if code := install(o, "--branch", "0.1.18", "-y"); code != 1 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	want := "[ERROR] '0.1.18' is a release of the bash era; install it with its own installer: sudo " +
		filepath.Join(o.p.Deploy, "bin", "tacctl.sh") + " install\n"
	if got := stripANSI(o.stderr.String()); got != want {
		t.Errorf("stderr %q, want %q", got, want)
	}
	if o.run.Called(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "--build") || strings.Contains(o.text(), "Building ") ||
		slices.Contains(o.phases, "tacacs install files "+o.p.Tree) {
		t.Errorf("went on: %v %v\n%s", o.phases, o.run.Argvs(), o.text())
	}
}

// A failing phase ends the install with its status, nothing after it.
func TestInstallPhaseFailureStops(t *testing.T) {
	o := newOhost(t)
	o.tac.failAt = "install build"
	if code := install(o, "-y"); code != 7 || o.run.Called("git", "clone") || len(o.phases) != 1 {
		t.Errorf("exit %d phases %v", code, o.phases)
	}
}

// --- upgrade -----------------------------------------------------------------------

func upgrade(o *ohost, args ...string) int { return o.do(lifecycle.Upgrade, args...) }

// cloned makes the deploy clone a Go tree at o.head, built into the
// installed command by this binary.
func (o *ohost) cloned() {
	o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "#!/bin/bash\n")
	o.write(filepath.Join(o.p.Deploy, "go.mod"), "module github.com/rett/tacctl\n")
	o.write(filepath.Join(o.p.Deploy, "man", "tacctl.1"), ".TH TACCTL 1\n")
	_ = os.MkdirAll(filepath.Join(o.p.Deploy, ".git"), 0o755)
	o.write(o.p.Command, "binary\n")
	_ = os.Chmod(o.p.Command, 0o755)
}

// The order of radius.bats "upgrade: the output reads in order" with both
// backends: banner, backends, preflight before it, build, the clone, the
// config phase, the system files with the count, finish, and the summary:
// the head a backend set, its count of files plus the completion, the
// console's symlink and templates, the backends' notes in order, then the
// templates note.
func TestUpgradeOrderAndSummary(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.enableBoth()
	o.tac.summary = backend.UpgradeSummary{Head: "Scripts Updated (source unchanged at abc1234)",
		Notes: []string{"Units: tacquito.service and its listener drop-in are current (settings in x)"}, FilesUpdated: 2}
	o.rad.summary = backend.UpgradeSummary{Notes: []string{"RADIUS: config re-rendered for this release, FreeRADIUS restarted"}}
	o.write(filepath.Join(o.p.Templates, "wti.template"), "mine\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	text := o.text()
	inOrder(t, text, "PHASE tacacs upgrade preflight", "PHASE radius upgrade preflight", "  tacctl Upgrade",
		"[INFO] Backends: tacacs (tacacs-daemon), radius (radius-daemon)", "PHASE tacacs upgrade build",
		"PHASE radius upgrade build", "[INFO] Pulling latest management scripts...", "[INFO] Management scripts already up to date.",
		"[INFO] Required packages: all present.", "PHASE tacacs upgrade config", "PHASE radius upgrade config",
		"[INFO] Updating system files...", "PHASE tacacs upgrade files "+o.p.Deploy, "PHASE radius upgrade files "+o.p.Deploy,
		"[INFO]   Updated: bash completion", "[INFO]   Updated: "+o.p.ConsoleCommand+" -> "+o.p.Command,
		"Customised template kept:", "[INFO] 10 file(s) updated.",
		"PHASE tacacs upgrade finish", "PHASE radius upgrade finish",
		rule+"\n  Scripts Updated (source unchanged at abc1234)\n  Managed scripts: 10 updated\n"+
			"  Units: tacquito.service and its listener drop-in are current (settings in x)\n"+
			"  RADIUS: config re-rendered for this release, FreeRADIUS restarted\n"+
			"  Templates: kept 1 customised (wti.template); this release's version of each is beside it as <name>.template.new (see above)\n"+
			rule+"\n\n")
	// The banner once, and only the preflight's own lines before it.
	if strings.Count(text, "tacctl Upgrade") != 1 ||
		strings.TrimSpace(text[:strings.Index(text, rule)]) != "[INFO] PHASE tacacs upgrade preflight\n[INFO] PHASE radius upgrade preflight" {
		t.Errorf("banner:\n%s", text)
	}
	if o.run.Called(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "--build") || len(o.run.Execs()) != 0 {
		t.Errorf("built or exec'd: %v", o.run.Argvs())
	}
	if st, _ := os.Stat(filepath.Join(o.p.Deploy, "bin", "tacctl.sh")); st.Mode().Perm() != 0o755 {
		t.Errorf("entrypoint mode %v", st.Mode())
	}
	if st, err := os.Lstat(o.p.Command); err != nil || !st.Mode().IsRegular() {
		t.Error("the installed command is no longer the binary")
	}
	// Again: the completion is current now, nothing to count but the
	// backend's own; the head defaults when no backend sets one.
	o.tac.summary = backend.UpgradeSummary{}
	o.rad.summary = backend.UpgradeSummary{}
	upgrade(o)
	inOrder(t, o.text(), "[INFO]   Unchanged: bash completion", "[INFO] 0 file(s) updated.", "  Upgrade Complete\n  Managed scripts: 0 updated\n  Templates: kept 1")
	// Nothing updated and the backend says it changed nothing: the head
	// says the installation was current; a backend note keeps its head.
	o.tac.summary = backend.UpgradeSummary{Head: "Scripts Updated (source unchanged at abc1234)",
		UpToDate: "Already Up to Date (source unchanged at abc1234)"}
	upgrade(o)
	inOrder(t, o.text(), "[INFO] 0 file(s) updated.", "  Already Up to Date (source unchanged at abc1234)\n  Managed scripts: 0 updated\n")
	o.rad.summary = backend.UpgradeSummary{Notes: []string{"RADIUS: config re-rendered for this release, FreeRADIUS restarted"}}
	upgrade(o)
	inOrder(t, o.text(), "[INFO] 0 file(s) updated.", "  Scripts Updated (source unchanged at abc1234)\n  Managed scripts: 0 updated\n")
}

// The completion is the binary's own output, written only when the
// installed one differs: a stale file is "Updated" and replaced, a current
// one "Unchanged", and a host with no completion directory gets it.
func TestUpgradeCompletionIsRewrittenOnlyWhenItDiffers(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.write(o.p.Completion, "complete -F _old tacctl\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !strings.Contains(o.text(), "[INFO]   Updated: bash completion") || readFile(t, o.p.Completion) != "complete -F _tacctl tacctl\n" {
		t.Errorf("not updated: %q\n%s", readFile(t, o.p.Completion), o.text())
	}
	if st, err := os.Stat(o.p.Completion); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v %v", st, err)
	}
	o.stdout.Reset()
	upgrade(o)
	if !strings.Contains(o.text(), "[INFO]   Unchanged: bash completion") {
		t.Errorf("rewritten again:\n%s", o.text())
	}
	_ = os.RemoveAll(filepath.Dir(o.p.Completion))
	o.stdout.Reset()
	upgrade(o)
	if !strings.Contains(o.text(), "[INFO]   Updated: bash completion") || readFile(t, o.p.Completion) != "complete -F _tacctl tacctl\n" {
		t.Errorf("a missing directory:\n%s", o.text())
	}
}

// The tiers sudoers drop-in an administrator installed is brought to this
// release's rules: rewritten (visudo -cf, then install) only when it
// differs, "Unchanged" when it does not, never created, and a rewrite that
// visudo refuses leaves the old file with a warning while the upgrade
// carries on.
func TestUpgradeRefreshesTheTiersSudoersOnlyWhenInstalledAndDifferent(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	installs := func() int { return o.run.Count("install") }
	o.run.Func(func(c execx.Cmd) bool { return c.Name == "install" }, func(c execx.Cmd) (execx.Result, error) {
		data, err := os.ReadFile(c.Args[len(c.Args)-2])
		if err != nil {
			return execx.Result{Code: 1}, nil
		}
		return execx.Result{}, os.WriteFile(c.Args[len(c.Args)-1], data, 0o440)
	})
	file := o.p.TierSudoersFile

	// Absent: never created, not mentioned.
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if exists(file) || strings.Contains(o.text(), "tiers sudoers") || o.run.Called("visudo") {
		t.Fatalf("absent file touched:\n%s", o.text())
	}

	// Stale: rewritten through visudo and install, counted.
	o.write(file, "# an older release's rules\n")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	inOrder(t, o.text(), "[INFO] Updating system files...", "[INFO]   Updated: tiers sudoers", "file(s) updated.", "Managed scripts:")
	if readFile(t, file) != tier.Sudoers() || installs() != 1 || o.run.Count("visudo") != 1 {
		t.Fatalf("not rewritten: %q %v", readFile(t, file), o.run.Argvs())
	}
	for _, c := range o.run.Calls() {
		if c.Name == "install" && !slices.Equal(c.Args[:6], []string{"-m", "0440", "-o", "root", "-g", "root"}) {
			t.Errorf("install %v", c.Args)
		}
	}

	// Current: left alone.
	if code := upgrade(o); code != 0 || !strings.Contains(o.text(), "[INFO]   Unchanged: tiers sudoers") ||
		installs() != 0 || o.run.Called("visudo") {
		t.Fatalf("exit %d, rewritten again:\n%s", code, o.text())
	}

	// visudo refuses: the old file stays, a warning, the upgrade finishes.
	o.write(file, "# an older release's rules\n")
	o.run.Fail([]string{"visudo"}, 1, "")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	inOrder(t, o.text(), "[WARN]   Not updated: tiers sudoers (visudo validation failed; "+file+" is unchanged)", "Managed scripts:")
	if readFile(t, file) != "# an older release's rules\n" || installs() != 0 {
		t.Errorf("replaced although visudo refused: %q", readFile(t, file))
	}
	if left, _ := filepath.Glob(filepath.Join(o.w, "tmp", "tmp.*")); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}
}

// No clone (radius.bats's order test): no git in it, nothing built or
// exec'd; the files come from the binary's own tree when the deploy
// directory is missing.
func TestUpgradeWithoutAClone(t *testing.T) {
	o := newOhost(t)
	_ = os.MkdirAll(o.p.Deploy, 0o755)
	o.write(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "")
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	for _, c := range o.run.Calls() {
		if c.Dir == o.p.Deploy || strings.HasSuffix(c.Name, "tacctl.sh") {
			t.Errorf("ran %v in the clone", c.Argv())
		}
	}
	if strings.Contains(o.text(), "Pulling latest") || len(o.run.Execs()) != 0 {
		t.Errorf("out %s", o.text())
	}
	_ = os.RemoveAll(o.p.Deploy)
	upgrade(o)
	inOrder(t, o.text(), "[INFO] Cloning management repo...", "PHASE tacacs upgrade files "+o.p.Deploy)
}

// The self-update hands the backends' handover to the new process, which
// gives it back to them before the build.
func TestUpgradeHandoverAcrossTheReexec(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.commit = "old"
	o.tac.hand = []string{lifecycle.UpgradeFromEnv + "=abc1234"}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	ex := o.run.Execs()
	if len(ex) != 1 || ex[0].Path != o.p.Command || !slices.Equal(ex[0].Argv, []string{o.p.Command, "upgrade"}) ||
		!slices.Contains(ex[0].Env, lifecycle.ReexecEnv+"=1") || !slices.Contains(ex[0].Env, lifecycle.UpgradeFromEnv+"=abc1234") {
		t.Fatalf("execs %+v", ex)
	}
	inOrder(t, o.text(), "Building "+o.p.Command, "[INFO] tacctl updated — restarting upgrade with new version...")
	if o.tac.from == nil || *o.tac.from != "" {
		t.Errorf("SetUpgradeFrom %v", o.tac.from)
	}
	// The new process: the guard, the handover in its environment.
	o.environ = append(o.environ, lifecycle.ReexecEnv+"=1", lifecycle.UpgradeFromEnv+"=abc1234")
	o.commit = o.head
	if code := upgrade(o); code != 0 || *o.tac.from != "abc1234" || len(o.run.Execs()) != 0 {
		t.Errorf("exit %d from %v execs %v", code, *o.tac.from, o.run.Execs())
	}
	if i := slices.Index(o.phases, "tacacs upgrade build"); i < 0 {
		t.Errorf("phases %v", o.phases)
	}
}

// A failing phase stops the upgrade with its status: preflight before
// anything is touched, finish before the summary.
func TestUpgradePhaseFailureStops(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.tac.failAt = "upgrade preflight"
	if code := upgrade(o); code != 7 || strings.Contains(o.text(), "tacctl Upgrade") || len(o.run.Calls()) != 0 {
		t.Errorf("exit %d out %s calls %v", code, o.text(), o.run.Argvs())
	}
	o.tac.failAt = "upgrade finish"
	if code := upgrade(o); code != 7 || strings.Contains(o.text(), "Managed scripts:") {
		t.Errorf("exit %d out %s", code, o.text())
	}
}

// --- uninstall ---------------------------------------------------------------------

func uninstall(o *ohost, args ...string) int { return o.do(lifecycle.Uninstall, args...) }

// installed puts every file uninstall removes in place.
func (o *ohost) installed() {
	o.cloned()
	for _, f := range []string{o.p.Completion, o.p.ManPage, o.p.SudoersFile, o.p.TierSudoersFile,
		filepath.Join(o.p.LinuxDir, "builds", "debian-13-x86_64", "pam_tacplus.so"), filepath.Join(o.p.BackupDir, "x", "store.yaml"),
		o.p.StoreFile} {
		o.write(f, "x\n")
	}
}

func TestUninstallCancel(t *testing.T) {
	o := newOhost(t)
	o.installed()
	if code := uninstall(o); code != 0 || len(o.phases) != 0 || !strings.HasSuffix(o.text(), "[INFO] Cancelled.\n") {
		t.Errorf("exit %d phases %v out %s", code, o.phases, o.text())
	}
	inOrder(t, o.text(), "  tacctl Uninstaller", "Backends: tacacs (tacacs-daemon)",
		"  - Bash completion ("+o.p.Completion+") and man page", "  - Management repo ("+o.p.Deploy+")",
		"(/usr/local/go) will NOT be removed.")
	if strings.Contains(o.text(), "RADIUS (FreeRADIUS)") {
		t.Error("RADIUS listed while not present")
	}
}

// -y: no question asked, nothing kept; the phases in order on every
// present backend (a disabled but installed RADIUS too), every tacctl file
// gone (install_seed.bats "cmd_uninstall removes the tier sudoers rules,
// bash completion and Linux host data").
func TestUninstallYes(t *testing.T) {
	o := newOhost(t)
	o.installed()
	o.rad.SetInstalled(true)
	o.write(o.p.KnownHosts, "# generated\n")
	if code := uninstall(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	want := []string{"tacacs uninstall stop", "radius uninstall stop", "tacacs uninstall program", "radius uninstall program",
		"tacacs uninstall data", "radius uninstall data", "tacacs uninstall account", "radius uninstall account"}
	if !slices.Equal(o.phases, want) {
		t.Errorf("phases %v", o.phases)
	}
	if strings.Contains(o.text(), "Preserve") || o.run.Called("tar") {
		t.Errorf("asked or archived:\n%s", o.text())
	}
	inOrder(t, o.text(), "RADIUS (FreeRADIUS): tacctl's instance", "[INFO] Removing binaries and symlinks...",
		"PHASE tacacs uninstall program", "[INFO] Removing sudoers rules and Linux host build data...",
		"[INFO] Removing logrotate config and bash completion...", "[INFO] Removing man page...",
		"[INFO] Removing configuration and state directories...", "PHASE tacacs uninstall data",
		"[INFO] Removing management repo...", "PHASE tacacs uninstall account", "  Uninstall Complete",
		"  Not removed:\n    - Go installation (/usr/local/go)\n    - tacquito source (/opt/tacquito-src)\n    - Go build cache (/root/.cache/go-build)\n")
	for _, f := range []string{o.p.Command, o.p.Completion, o.p.ManPage, o.p.SudoersFile, o.p.TierSudoersFile, o.p.LinuxDir,
		filepath.Dir(o.p.LinuxDir), o.p.StateDir, o.p.Deploy, o.p.KnownHosts, o.p.VarLib} {
		if _, err := os.Lstat(f); err == nil {
			t.Errorf("%s left", f)
		}
	}
	if !o.run.Called("git", "config", "--system", "--unset-all", "safe.directory", "^"+o.p.Deploy+"$") || !o.run.Called("mandb", "-q") {
		t.Errorf("calls %v", o.run.Argvs())
	}
}

// Kept on request: the backups archived under /root before the state
// directory goes, each backend's logs with --keep-logs, and what they
// saved listed.
func TestUninstallKeepsWhatItIsAskedTo(t *testing.T) {
	o := newOhost(t)
	o.installed()
	o.enableBoth()
	o.rad.saved = []string{"RADIUS logs saved to: /root/r.tar.gz"}
	o.stdin = "y\ny\nn\ny\n"
	if code := uninstall(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	archive := o.p.ArchiveDir + "/tacquito-backups-20261003_123456.tar.gz"
	if !o.run.Called("tar", "czf", archive, "-C", o.p.StateDir, "backups/") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	if !slices.Contains(o.phases, "tacacs uninstall data") || !slices.Contains(o.phases, "radius uninstall data --keep-logs") {
		t.Errorf("phases %v", o.phases)
	}
	inOrder(t, o.text(), "[INFO] Config backups saved to "+archive, "[INFO] Removing configuration and state directories...",
		"    - Config backups saved to: "+archive+"\n    - RADIUS logs saved to: /root/r.tar.gz\n")
}

// uninstall_remove_access (install_seed.bats): both sudoers drop-ins and
// the Linux host data go, with the data's parent when that leaves it
// empty; nothing to remove is fine, and a shared parent stays.
func TestUninstallRemovesAccess(t *testing.T) {
	o := newOhost(t)
	o.installed()
	other := filepath.Join(filepath.Dir(o.p.SudoersFile), "other")
	o.write(other, "keep\n")
	uninstall(o, "-y")
	if _, err := os.Stat(other); err != nil {
		t.Error("another sudoers file went too")
	}
	o = newOhost(t)
	o.cloned()
	_ = os.MkdirAll(o.p.LinuxDir, 0o755)
	o.write(filepath.Join(filepath.Dir(o.p.LinuxDir), "other"), "not ours\n")
	if code := uninstall(o, "--yes"); code != 0 {
		t.Fatalf("exit %d %s", code, o.stderr)
	}
	if _, err := os.Stat(o.p.LinuxDir); err == nil {
		t.Error("Linux host data left")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(o.p.LinuxDir), "other")); err != nil {
		t.Error("the shared parent went")
	}
}

func TestUninstallPhaseFailureStops(t *testing.T) {
	o := newOhost(t)
	o.installed()
	o.tac.failAt = "uninstall stop"
	if code := uninstall(o, "-y"); code != 7 {
		t.Errorf("exit %d", code)
	}
	if _, err := os.Stat(o.p.Command); err != nil || strings.Contains(o.text(), "Removing") {
		t.Errorf("went on:\n%s", o.text())
	}
}

const rule = "============================================"

// The bootstrap shim installs the Go that tacctl names (paths.GoVersion,
// which the banner of install prints), and go.mod asks for no newer one.
func TestShimGoVersionIsTacctls(t *testing.T) {
	shim := filepath.Join("..", "..", "bin", "tacctl.sh")
	if !strings.Contains(readFile(t, shim), "\nGO_VERSION=\""+paths.GoVersion+"\"\n") {
		t.Errorf("%s does not install Go %s", shim, paths.GoVersion)
	}
	for _, l := range strings.Split(readFile(t, filepath.Join("..", "..", "go.mod")), "\n") {
		if v, ok := strings.CutPrefix(l, "go "); ok && v > paths.GoVersion {
			t.Errorf("go.mod needs Go %s, newer than %s", v, paths.GoVersion)
		}
	}
}

// 'config branch <b>' switches the clone and says to run 'tacctl upgrade':
// nothing is pulled then (START is HEAD already), but the installed command
// was not built from HEAD, so the upgrade rebuilds and re-executes it; a
// branch that is a bash release is handed over to without a pull as well.
func TestUpgradeAfterConfigBranch(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.commit = "the-previous-branch"
	if code := upgrade(o); code != 0 || !o.run.Called(filepath.Join(o.p.Deploy, "bin", "tacctl.sh"), "--build", o.p.Command) ||
		len(o.run.Execs()) != 1 || o.run.Called("git", "pull", "--ff-only") {
		t.Errorf("exit %d calls %v execs %v", code, o.run.Argvs(), o.run.Execs())
	}
	inOrder(t, o.text(), "Management scripts already up to date.", "Building "+o.p.Command)

	o = newOhost(t)
	o.cloned()
	_ = os.Remove(filepath.Join(o.p.Deploy, "go.mod"))
	o.write(filepath.Join(o.p.Deploy, "lib", "core.sh"), "# 0.1.17\n")
	if code := upgrade(o); code != 0 || len(o.run.Execs()) != 1 || o.run.Execs()[0].Path != filepath.Join(o.p.Deploy, "bin", "tacctl.sh") {
		t.Errorf("exit %d execs %v", code, o.run.Execs())
	}
	if target, err := os.Readlink(o.p.Command); err != nil || target != filepath.Join(o.p.Deploy, "bin", "tacctl.sh") {
		t.Errorf("command %q %v", target, err)
	}
}

// testCompletion stands for the generated completion script.
func testCompletion() ([]byte, error) { return []byte("complete -F _tacctl tacctl\n"), nil }

// Install and upgrade bring an existing VarLib (made 0700 by an older
// build step) to 0711, so users' ssh reaches VarLib/ssh/known_hosts; a
// missing one is not created.
func TestInstallUpgradeRepairVarLib(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if _, err := os.Stat(o.p.VarLib); !os.IsNotExist(err) {
		t.Errorf("VarLib created: %v", err)
	}
	o = newOhost(t)
	o.cloned()
	if err := os.MkdirAll(o.p.VarLib, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(o.p.VarLib, 0o700); err != nil {
		t.Fatal(err)
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if st, err := os.Stat(o.p.VarLib); err != nil || st.Mode().Perm() != 0o711 {
		t.Errorf("VarLib mode %v %v", st.Mode().Perm(), err)
	}
}

// The login console's symlink: made by install, refreshed by upgrade when
// it points elsewhere.
func TestConsoleLinkInstallAndUpgrade(t *testing.T) {
	o := newOhost(t)
	o.commit = "something-else"
	if code := install(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if target, err := os.Readlink(o.p.ConsoleCommand); err != nil || target != o.p.Command {
		t.Fatalf("install: %q %v", target, err)
	}
	o = newOhost(t)
	o.cloned()
	o.write(o.p.Command, "binary\n")
	if err := os.Symlink("/elsewhere", o.p.ConsoleCommand); err != nil {
		t.Fatal(err)
	}
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if target, _ := os.Readlink(o.p.ConsoleCommand); target != o.p.Command || !strings.Contains(o.text(), "Updated: "+o.p.ConsoleCommand) {
		t.Errorf("upgrade: %q\n%s", target, o.text())
	}
	o.stdout.Reset()
	if code := upgrade(o); code != 0 || strings.Contains(o.text(), "Updated: "+o.p.ConsoleCommand) {
		t.Errorf("a current link was rewritten: %d\n%s", code, o.text())
	}
}

// An installed sshd drop-in that differs from this release's is rewritten
// through 'sshd -t' and sshd reloaded; a current one is left; none is
// never created; one sshd refuses stays as it was.
func TestUpgradeRefreshesConsoleDropIn(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.run.On([]string{"sshd", "-t"}, execx.Result{})
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if _, err := os.Stat(o.p.SSHDDropIn); err == nil || strings.Contains(o.text(), "sshd drop-in") || o.run.Called("sshd") {
		t.Errorf("a drop-in was created or checked:\n%s", o.text())
	}
	o.write(o.p.SSHDDropIn, "Match Group tac-console\n    AllowTcpForwarding no\n")
	o.stdout.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if readFile(t, o.p.SSHDDropIn) != console.DropIn(o.p.ConsoleCommand, false) || !strings.Contains(o.text(), "[INFO]   Updated: sshd drop-in") ||
		!o.run.Called("sshd", "-t") || !o.run.Called("systemctl", "reload", "ssh.service") {
		t.Errorf("not refreshed:\n%s\n%q", o.text(), o.run.Argvs())
	}
	o.stdout.Reset()
	upgrade(o)
	if !strings.Contains(o.text(), "[INFO]   Unchanged: sshd drop-in") {
		t.Errorf("second run:\n%s", o.text())
	}
	old := "Match Group tac-console\n"
	o.write(o.p.SSHDDropIn, old)
	o.run.Fail([]string{"sshd", "-t"}, 255, "Bad configuration option: DisableForwarding")
	o.stdout.Reset()
	o.stderr.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("a refused drop-in failed the upgrade: %d", code)
	}
	if readFile(t, o.p.SSHDDropIn) != old || !strings.Contains(o.text(), "Not updated: sshd drop-in (sshd -t refused the configuration") {
		t.Errorf("refused:\n%s", o.text())
	}
}

// Uninstall leaves no account with the console as its shell: each gets
// /bin/bash back (named), then sshd's drop-in, the /etc/shells line and the
// symlink go.
func TestUninstallRestoresConsoleShells(t *testing.T) {
	o := newOhost(t)
	o.installed()
	o.write(o.p.SSHDDropIn, console.DropIn(o.p.ConsoleCommand, false))
	o.write(o.p.ShellsFile, "/bin/sh\n/bin/bash\n"+o.p.ConsoleCommand+"\n")
	if err := os.Symlink(o.p.Command, o.p.ConsoleCommand); err != nil {
		t.Fatal(err)
	}
	o.run.On([]string{"getent", "passwd"}, execx.Result{Stdout: []byte("root:x:0:0:root:/root:/bin/bash\n" +
		"alice:x:80000:80000:alice (TACACS+):/home/alice:" + o.p.ConsoleCommand + "\n" +
		"bob:x:80001:80001:bob (TACACS+):/home/bob:/bin/bash\n" +
		"carol:x:80002:80002:carol (TACACS+):/home/carol:" + o.p.ConsoleCommand + "\n")})
	o.run.Fail([]string{"usermod", "-s", "/bin/bash", "carol"}, 8, "usermod: user carol is currently used by process 1")
	o.run.On([]string{"sshd", "-t"}, execx.Result{})
	if code := uninstall(o, "-y"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !o.run.Called("usermod", "-s", "/bin/bash", "alice") || o.run.Called("usermod", "-s", "/bin/bash", "bob") {
		t.Errorf("calls %q", o.run.Argvs())
	}
	inOrder(t, o.text(), "[INFO] Login shell /bin/bash restored for: alice", "Could not give these accounts /bin/bash back",
		"carol", "[INFO] Removed sshd drop-in "+o.p.SSHDDropIn, "[INFO] Removed "+o.p.ConsoleCommand+" from "+o.p.ShellsFile,
		"[INFO] Removing binaries and symlinks...")
	for _, f := range []string{o.p.SSHDDropIn, o.p.ConsoleCommand} {
		if _, err := os.Lstat(f); err == nil {
			t.Errorf("%s left", f)
		}
	}
	if readFile(t, o.p.ShellsFile) != "/bin/sh\n/bin/bash\n" {
		t.Errorf("shells %q", readFile(t, o.p.ShellsFile))
	}
}
