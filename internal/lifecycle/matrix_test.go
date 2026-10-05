package lifecycle_test

// The offline and partial-failure matrix of docs/plans/go-rewrite.md 5.2,
// as fake-runner tests of the Go upgrade's self-update and hand-over
// (WP3.3c writes them; WP3.3d implements lifecycle.Upgrade against them).
//
// Each test builds a host (matrixHost): a deploy clone (/opt/tacctl) whose
// git the fake runner plays, the installed command (/usr/local/bin/tacctl)
// as a file, a tacquito source checkout, and one stand-in backend 'tacacs'
// whose 'upgrade build' fetches tacquito through the runner (the first
// network call of an upgrade). It then runs 'tacctl upgrade [args]' through
// subject and checks where the upgrade stopped and what it left.
//
// # The contract (what lifecycle.Upgrade must do)
//
// The order is 0.1.16's cmd_upgrade (lib/lifecycle.sh at the tag):
//
//  1. every enabled backend's 'upgrade preflight', then 'upgrade build' (a
//     failing phase stops the upgrade, exit status non-zero);
//  2. the deploy clone: 'git checkout -- .'; START = 'git rev-parse HEAD'
//     (before any branch switch: 0.1.16 item (g)); with --branch <b>:
//     'git fetch --tags --force', then 'git checkout <b>' or
//     'git checkout -b <b> origin/<b>'; 'git fetch --tags --force' (failure:
//     "[ERROR] git fetch failed. Check network / credentials.", exit 1);
//     LOCAL = 'git rev-parse HEAD', REMOTE = 'git rev-parse @{u}'; when they
//     differ, 'git pull --ff-only'. git runs with '-C <deploy>' or with the
//     deploy clone as its working directory; the matrix plays both;
//  3. a pulled tree with no go.mod and a lib/core.sh is a bash release:
//     stdout "Target branch is a bash release of tacctl; handing over.",
//     <deploy>/bin/tacctl.sh made 0755, the installed command replaced by a
//     symlink to it, then Runner.Exec(<deploy>/bin/tacctl.sh, [_, "upgrade"])
//     (no --branch passed on, as 0.1.16's re-exec), and nothing else in this
//     process: no build, no further backend phase;
//  4. self-update: when 'git diff --quiet START HEAD -- cmd internal vendor
//     go.mod go.sum bin config patches' fails, or the running binary's
//     commit is not HEAD, and TACCTL_UPGRADE_REEXEC=1 is not set: run the
//     build recipe '<deploy>/bin/tacctl.sh --build <installed command>'
//     through the runner (it replaces the command atomically, or leaves it
//     as it was). Then Runner.Exec(<installed command>, [_, "upgrade"], env)
//     with TACCTL_UPGRADE_REEXEC=1 in env, and nothing else in this
//     process. A build that fails: '<installed command>.new' removed (a
//     cancelled build is killed, so the recipe's own trap may not have run),
//     the installed command untouched, stderr says "could not be built (see
//     above). The installed command is unchanged." and gives the recovery
//     line "sudo git -C <deploy> checkout <START>", exit status non-zero, no
//     exec and no further backend phase (Decision 20: print the recipe, stop).
//     A build interrupted (Ctrl-C: the context is cancelled) ends the same
//     way, quietly or not, with a non-zero status;
//  5. otherwise every enabled backend's 'upgrade config', 'upgrade files',
//     'upgrade finish' (a failing phase stops the upgrade, exit status
//     non-zero; the installed command stays; running 'tacctl upgrade' again
//     after the fault is gone completes it, with no pull, build or exec).
//
// What the matrix does not pin (WP3.3d's choice): the banner and info
// lines, the exact wording of a failing backend phase, the exit status
// beyond "non-zero", the order of the backend phases within a step, and
// anything the shim (bash) does: its own rows (toolchain install, step 3)
// are WP3.3d's bats tests.
//
// # The implementation
//
// realUpgrade (below) maps a matrixHost onto lifecycle.Upgrade's inputs:
// the runner (h.Run), the backend set (h.Set, whose Env carries the paths,
// tacctl.yaml and the output), the deploy clone (h.Deploy), the installed
// command (h.Binary), the running binary's commit (h.BinaryCommit), the
// environment (h.Env), the context. WP3.3c's reference stub, written
// against the contract above, was replaced by it in WP3.3d with one change
// to the host: the deploy clone has a '.git' directory, as 0.1.16 updates
// the clone only then.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/ui"
)

// upgradeSubject is the shape of lifecycle.Upgrade the matrix drives:
// 'tacctl upgrade args...' on host h. The error's exit status is
// matrixCode's.
type upgradeSubject interface {
	Upgrade(ctx context.Context, h *matrixHost, args []string) error
}

// subject is what the matrix runs: lifecycle.Upgrade (WP3.3d; WP3.3c's
// reference stub, written against the contract above, is gone).
var subject upgradeSubject = realUpgrade{}

// The commits of the deploy clone the matrix knows.
const (
	commitOld    = "1111111111111111111111111111111111111111" // the running Go release
	commitNew    = "2222222222222222222222222222222222222222" // the next Go release
	commitBash   = "3333333333333333333333333333333333333333" // 0.1.16, a bash release
	reexecGuard  = "TACCTL_UPGRADE_REEXEC=1"
	oldBinary    = "old tacctl binary\n"
	newBinary    = "new tacctl binary\n"
	fetchOffline = "fatal: unable to access 'https://github.com/rett/tacctl.git/': Could not resolve host: github.com\n"
)

// matrixHost is everything an upgrade touches, under one temp dir.
type matrixHost struct {
	t *testing.T
	// Deploy is the clone (/opt/tacctl); its files follow the commit
	// checked out (a Go release: go.mod and the shim; a bash release:
	// lib/core.sh and the bash entrypoint).
	Deploy string
	// Binary is the installed command (/usr/local/bin/tacctl).
	Binary string
	// BinaryCommit is the commit the running binary was built from.
	BinaryCommit string
	// TacquitoSrc is the tacquito source checkout.
	TacquitoSrc string
	// Env is the process environment of the upgrade.
	Env []string
	// Run plays every external program.
	Run *fake.Runner
	// Set holds the stand-in 'tacacs' backend, enabled.
	Set *backend.Set
	Out ui.Output

	stdout, stderr *bytes.Buffer
	tac            *matrixBackend
	root           string // the sandbox everything above is under
	cancel         context.CancelFunc

	mu      sync.Mutex
	head    string            // the deploy clone's HEAD
	branch  string            // its current branch
	local   map[string]string // local branches
	remote  map[string]string // origin's branches
	offline bool              // the deploy clone's remote is unreachable
	// build is what the build recipe does: "" builds, else a failure mode.
	build string
}

// The build recipe's failure modes.
const (
	buildNoGo      = "no-go"
	buildDiskFull  = "disk-full"
	buildInterrupt = "interrupt"
)

func newMatrixHost(t *testing.T) *matrixHost {
	t.Helper()
	w := t.TempDir()
	h := &matrixHost{
		t: t, Deploy: filepath.Join(w, "opt", "tacctl"), Binary: filepath.Join(w, "usr", "local", "bin", "tacctl"),
		BinaryCommit: commitOld, TacquitoSrc: filepath.Join(w, "opt", "tacquito-src"),
		Run: &fake.Runner{}, stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{},
		head: commitOld, branch: "develop",
		local:  map[string]string{"develop": commitOld},
		remote: map[string]string{"develop": commitOld, "master": commitBash, "feature/x": commitNew},
	}
	h.Out = ui.Output{Stdout: h.stdout, Stderr: h.stderr}
	// The deploy clone is a git clone (0.1.16 updates it only then: a
	// '.git' directory).
	for _, d := range []string{"state", "etc", filepath.Dir(h.Binary), h.TacquitoSrc, "tac", "tmp", filepath.Join(h.Deploy, ".git")} {
		if !filepath.IsAbs(d) {
			d = filepath.Join(w, d)
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TMPDIR", filepath.Join(w, "tmp"))
	if err := os.WriteFile(h.Binary, []byte(oldBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	h.checkout(commitOld)
	// Every path an upgrade can write, under the sandbox (matrixHostDefaults).
	j := func(p ...string) string { return filepath.Join(append([]string{w}, p...)...) }
	h.Env = []string{"PATH=/usr/bin:/bin",
		"TACCTL_ETC=" + j("etc"), "TACCTL_STATE_DIR=" + j("state"), "TACCTL_LOG=" + j("log"), "TACCTL_BIN=" + j("bin"),
		"TACCTL_CONFIG=" + j("etc", "tacquito.yaml"),
		"TACCTL_SUDOERS_FILE=" + j("sudoers.d", "tacctl"), "TACCTL_TIER_SUDOERS_FILE=" + j("sudoers.d", "tacctl-tiers"),
		"TACCTL_SYSTEMD_DIR=" + j("systemd"), "TACCTL_OVERRIDE_DIR=" + j("systemd", "tacquito.service.d"),
		"TACCTL_LOGROTATE_DIR=" + j("logrotate.d"), "TACQUITO_SRC=" + h.TacquitoSrc, "TACCTL_LINUX_DIR=" + j("linux"), "TACCTL_VAR_LIB=" + j("var-lib"),
		"TACCTL_TREE=" + h.Deploy,
		"TACCTL_SSHD_DROPIN=" + j("sshd_config.d", "tacctl-console.conf"), "TACCTL_SHELLS_FILE=" + j("shells"),
		"TACCTL_RADIUS_DIR=" + j("raddb"), "TACCTL_RADIUS_LOG=" + j("radius-log"),
		"TACCTL_RADIUS_BIN=" + j("radius-bin", "radiusd"), "TACCTL_RADIUS_DICT=" + j("radius-share", "dictionary"),
	}
	h.root = w
	p := paths.Resolve(paths.NewEnv(h.Env), "", func(string) bool { return false })
	reg := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	h.tac = &matrixBackend{Backend: faketest.New(backend.TACACS, p.Config, filepath.Join(w, "tac")), h: h}
	if err := reg.Add(backend.TACACS, func(env *backend.Env) backend.Backend {
		h.tac.Env = env
		return h.tac
	}); err != nil {
		t.Fatal(err)
	}
	cfg := conf.Load(p.Overrides, reg.IDs())
	cfg.Owner = nil
	h.Set = backend.NewSet(reg, &backend.Env{Paths: p, Conf: cfg, Runner: h.Run, Out: h.Out, Now: time.Now})
	h.script()
	if bad := matrixHostDefaults(h); len(bad) != 0 {
		t.Fatalf("the matrix host leaves host paths: %v", bad)
	}
	return h
}

// matrixHostDefaults names every path of the host (the deploy clone, the
// installed command, the paths of its environment, tacctl's fixed host
// locations as realUpgrade passes them, both RADIUS layouts)
// that is not under its sandbox: an implementation run by the matrix must
// not be able to reach the machine the tests run on.
func matrixHostDefaults(h *matrixHost) []string {
	root := filepath.Clean(h.root) + string(filepath.Separator)
	p := matrixPaths(h)
	check := map[string]string{
		"Deploy": h.Deploy, "Binary": h.Binary, "TacquitoSrc": h.TacquitoSrc,
		"paths.Deploy": p.Deploy, "Command": p.Command, "GoBin": p.GoBin, "Completion": p.Completion,
		"ManPage": p.ManPage, "ArchiveDir": p.ArchiveDir, "Templates": p.Templates, "BackupDir": p.BackupDir,
		"Etc": p.Etc, "StateDir": p.StateDir, "Log": p.Log, "Bin": p.Bin, "Config": p.Config,
		"SudoersFile": p.SudoersFile, "TierSudoersFile": p.TierSudoersFile, "OverrideDir": p.OverrideDir,
		"TacacsUnitDir": p.TacacsUnitDir, "SystemdDir": p.SystemdDir, "LogrotateDir": p.LogrotateDir,
		"paths.TacquitoSrc": p.TacquitoSrc, "LinuxDir": p.LinuxDir, "VarLib": p.VarLib, "KnownHosts": p.KnownHosts, "Tree": p.Tree, "PatchDir": p.PatchDir,
	}
	for _, fam := range []string{"debian", "rhel"} {
		l := p.Radius(fam)
		for name, path := range map[string]string{"Dir": l.Dir, "Bin": l.Bin, "LogDir": l.LogDir,
			"SystemDict": l.SystemDict, "DropIn": l.DropIn, "Logrotate": l.Logrotate} {
			check[fam+" "+name] = path
		}
	}
	var bad []string
	for name, path := range check {
		if !strings.HasPrefix(filepath.Clean(path)+string(filepath.Separator), root) {
			bad = append(bad, name+"="+path)
		}
	}
	return bad
}

// The guard sees a host default (newMatrixHost fails on one).
func TestMatrixHostIsSandboxed(t *testing.T) {
	h := newMatrixHost(t)
	if bad := matrixHostDefaults(h); len(bad) != 0 {
		t.Errorf("host defaults: %v", bad)
	}
	h.Env = []string{"PATH=/usr/bin:/bin"}
	if bad := matrixHostDefaults(h); len(bad) < 10 {
		t.Errorf("the guard missed host defaults: %v", bad)
	}
}

// checkout puts the files of a commit in the deploy clone.
func (h *matrixHost) checkout(commit string) {
	h.t.Helper()
	files := map[string]string{"go.mod": "module github.com/rett/tacctl\n", "bin/tacctl.sh": "#!/bin/bash\n# the 0.2.0 shim at " + commit + "\n"}
	gone := "lib/core.sh"
	if commit == commitBash {
		files = map[string]string{"lib/core.sh": "# 0.1.16\n", "bin/tacctl.sh": "#!/bin/bash\n# tacctl 0.1.16\n"}
		gone = "go.mod"
	}
	_ = os.Remove(filepath.Join(h.Deploy, gone))
	for name, text := range files {
		p := filepath.Join(h.Deploy, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			h.t.Fatal(err)
		}
		// A checkout leaves the entrypoint 0644 here, so that the hand-over
		// must make it executable.
		if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
			h.t.Fatal(err)
		}
		_ = os.Chmod(p, 0o644)
	}
}

// gitIn is the git sub-command run in dir ('git -C dir ...' or with dir as
// the working directory), or nil.
func gitIn(c execx.Cmd, dir string) []string {
	if c.Name != "git" {
		return nil
	}
	if len(c.Args) >= 2 && c.Args[0] == "-C" && filepath.Clean(c.Args[1]) == dir {
		return c.Args[2:]
	}
	if c.Dir != "" && filepath.Clean(c.Dir) == dir {
		return c.Args
	}
	return nil
}

// script makes the runner play the deploy clone's git, tacquito's fetch
// and the build recipe.
func (h *matrixHost) script() {
	h.Run.Func(func(c execx.Cmd) bool { return gitIn(c, h.Deploy) != nil }, func(c execx.Cmd) (execx.Result, error) {
		return h.git(gitIn(c, h.Deploy)), nil
	})
	h.Run.Func(func(c execx.Cmd) bool { return gitIn(c, h.TacquitoSrc) != nil }, func(c execx.Cmd) (execx.Result, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if sub := gitIn(c, h.TacquitoSrc); len(sub) > 0 && sub[0] == "fetch" && h.offline {
			return execx.Result{Code: 128, Stderr: []byte(strings.ReplaceAll(fetchOffline, "rett/tacctl", "facebookincubator/tacquito"))}, nil
		}
		return execx.Result{}, nil
	})
	recipe := filepath.Join(h.Deploy, "bin", "tacctl.sh")
	h.Run.Func(func(c execx.Cmd) bool { return c.Name == recipe && len(c.Args) > 0 && c.Args[0] == "--build" },
		func(c execx.Cmd) (execx.Result, error) { return h.buildRecipe(c) })
}

// git plays the deploy clone.
func (h *matrixHost) git(sub []string) execx.Result {
	h.mu.Lock()
	defer h.mu.Unlock()
	ok := func(s string) execx.Result { return execx.Result{Stdout: []byte(s)} }
	if len(sub) == 0 {
		return execx.Result{Code: 1}
	}
	switch sub[0] {
	case "rev-parse":
		switch {
		case slices.Contains(sub, "@{u}"):
			if r, found := h.remote[h.branch]; found {
				return ok(r + "\n")
			}
			return execx.Result{Code: 128, Stderr: []byte("fatal: no upstream configured\n")}
		case slices.Contains(sub, "--short"):
			return ok(h.head[:7] + "\n")
		case slices.Contains(sub, "--abbrev-ref"):
			return ok(h.branch + "\n")
		}
		return ok(h.head + "\n")
	case "symbolic-ref":
		return ok(h.branch + "\n")
	case "fetch":
		if h.offline {
			return execx.Result{Code: 128, Stderr: []byte(fetchOffline)}
		}
	case "checkout":
		if len(sub) >= 2 && sub[1] == "--" {
			return ok("")
		}
		name := sub[len(sub)-1]
		if len(sub) >= 4 && sub[1] == "-b" {
			name = sub[2]
			r, found := h.remote[name]
			if !found {
				return execx.Result{Code: 128}
			}
			h.local[name] = r
		}
		c, found := h.local[name]
		if !found {
			return execx.Result{Code: 1, Stderr: []byte("error: pathspec '" + name + "' did not match\n")}
		}
		h.branch, h.head = name, c
		h.checkout(c)
	case "pull":
		if h.offline {
			return execx.Result{Code: 1, Stderr: []byte(fetchOffline)}
		}
		if r, found := h.remote[h.branch]; found {
			h.head = r
			h.local[h.branch] = r
			h.checkout(r)
		}
	case "diff":
		// 'diff --quiet <from> HEAD -- <paths>': every commit pair of the
		// matrix differs in its Go code and in bin/.
		for i, a := range sub {
			if a == "HEAD" && i > 0 && sub[i-1] != h.head {
				return execx.Result{Code: 1}
			}
		}
	}
	return ok("")
}

// buildRecipe plays 'bin/tacctl.sh --build <out>': <out>.new then a rename
// on success; a failure leaves <out> as it was.
func (h *matrixHost) buildRecipe(c execx.Cmd) (execx.Result, error) {
	h.mu.Lock()
	mode := h.build
	h.mu.Unlock()
	if len(c.Args) < 2 {
		return execx.Result{Code: 1, Stderr: []byte("Usage: tacctl.sh --build <out> [--tags <tags>]\n")}, nil
	}
	out := c.Args[1]
	stderr := func(s string) {
		if c.Stderr != nil {
			_, _ = c.Stderr.Write([]byte(s))
		}
	}
	switch mode {
	case buildNoGo:
		stderr("\033[0;31m[ERROR]\033[0m Go toolchain not found at /usr/local/go/bin/go.\n")
		return execx.Result{Code: 1}, nil
	case buildDiskFull:
		// The half-written binary is left behind (the trap did not run).
		_ = os.WriteFile(out+".new", []byte("half"), 0o755)
		stderr("go: writing " + out + ".new: no space left on device\n")
		return execx.Result{Code: 1}, nil
	case buildInterrupt:
		_ = os.WriteFile(out+".new", []byte("half"), 0o755)
		h.cancel()
		return execx.Result{Code: 130}, context.Canceled
	}
	if err := os.WriteFile(out+".new", []byte(newBinary), 0o755); err != nil {
		return execx.Result{Code: 1}, nil
	}
	if err := os.Rename(out+".new", out); err != nil {
		return execx.Result{Code: 1}, nil
	}
	return execx.Result{}, nil
}

// upgrade runs 'tacctl upgrade args...' through the subject.
func (h *matrixHost) upgrade(args ...string) error {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.cancel = cancel
	h.stdout.Reset()
	h.stderr.Reset()
	h.Run.Reset()
	h.tac.reset()
	return subject.Upgrade(ctx, h, args)
}

// matrixCode is the exit status an error stands for.
func matrixCode(err error) int {
	if err == nil {
		return 0
	}
	var c interface{ ExitCode() int }
	if errors.As(err, &c) {
		return c.ExitCode()
	}
	return 1
}

func (h *matrixHost) read(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// binaryUntouched: the installed command is the old binary, a regular file,
// and no <binary>.new is left.
func (h *matrixHost) binaryUntouched() {
	h.t.Helper()
	st, err := os.Lstat(h.Binary)
	if err != nil || !st.Mode().IsRegular() || h.read(h.Binary) != oldBinary || st.Mode().Perm() != 0o755 {
		h.t.Errorf("the installed command changed (%v, %v)", st, err)
	}
	if _, err := os.Lstat(h.Binary + ".new"); err == nil {
		h.t.Error(h.Binary + ".new left behind")
	}
}

// deployCalls are the git sub-commands run in the deploy clone.
func (h *matrixHost) deployCalls() []string {
	var out []string
	for _, c := range h.Run.Calls() {
		if sub := gitIn(c, h.Deploy); sub != nil {
			out = append(out, strings.Join(sub, " "))
		}
	}
	return out
}

func (h *matrixHost) deployCalled(prefix string) bool {
	for _, c := range h.deployCalls() {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

func (h *matrixHost) built() bool {
	return h.Run.Called(filepath.Join(h.Deploy, "bin", "tacctl.sh"), "--build")
}

// phasesRun are the backend's upgrade phases this run, in order.
func (h *matrixHost) phasesRun() []string {
	h.tac.mu.Lock()
	defer h.tac.mu.Unlock()
	return slices.Clone(h.tac.phases)
}

func (h *matrixHost) noExec() {
	h.t.Helper()
	if e := h.Run.Execs(); len(e) != 0 {
		h.t.Errorf("exec'd %v", e)
	}
}

func (h *matrixHost) errHas(want string) {
	h.t.Helper()
	if !strings.Contains(stripANSI(h.stderr.String()), want) {
		h.t.Errorf("stderr lacks %q:\n%s", want, h.stderr)
	}
}

func stripANSI(s string) string {
	for _, c := range []string{ui.Red, ui.Green, ui.Yellow, ui.Bold, ui.NC, ui.Cyan} {
		s = strings.ReplaceAll(s, c, "")
	}
	return s
}

// matrixBackend is the stand-in TACACS+ backend: its 'upgrade build'
// fetches tacquito (the first network call of an upgrade), and a phase can
// be made to fail.
type matrixBackend struct {
	*faketest.Backend
	h      *matrixHost
	failAt backend.Phase

	mu     sync.Mutex
	phases []string
}

// Upgrade records the phase; build fetches tacquito through the runner.
func (b *matrixBackend) Upgrade(ctx context.Context, phase backend.Phase, _ string) error {
	b.mu.Lock()
	b.phases = append(b.phases, string(phase))
	b.mu.Unlock()
	out := b.Env.Out
	if phase == backend.PhaseBuild {
		res, err := b.h.Run.Run(ctx, execx.Cmd{Name: "git", Args: []string{"-C", b.h.TacquitoSrc, "fetch", "--quiet"}, Stderr: out.Stderr})
		if err != nil || res.Code != 0 {
			return &backend.Error{Code: 128, Reason: "git fetch"}
		}
	}
	if phase == b.failAt {
		out.Error("FreeRADIUS rejects the rendered configuration ('freeradius -C'):")
		return backend.ErrFailed
	}
	return nil
}

func (b *matrixBackend) reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.phases = nil
}

// --- the matrix -------------------------------------------------------------------

// Host offline, first network call: tacquito's fetch in 'upgrade build'.
// The tree and the binary are untouched; retry when online.
func TestMatrixOfflineAtTacquitoFetch(t *testing.T) {
	h := newMatrixHost(t)
	h.remote["develop"] = commitNew
	h.offline = true
	err := h.upgrade()
	if matrixCode(err) == 0 {
		t.Fatal("an offline upgrade succeeded")
	}
	for _, c := range []string{"checkout", "fetch", "pull"} {
		if h.deployCalled(c) {
			t.Errorf("the deploy clone was touched: %v", h.deployCalls())
		}
	}
	if h.head != commitOld || h.read(filepath.Join(h.Deploy, "go.mod")) == "" {
		t.Error("the tree moved")
	}
	h.binaryUntouched()
	if h.built() {
		t.Error("built")
	}
	h.noExec()
	if got := h.phasesRun(); slices.Contains(got, "config") {
		t.Errorf("phases %v", got)
	}
}

// Host offline at tacctl's own fetch (tacquito's source is reachable, its
// remote is not): 0.1.16's message, nothing pulled, built or exec'd.
func TestMatrixOfflineAtTacctlFetch(t *testing.T) {
	h := newMatrixHost(t)
	h.remote["develop"] = commitNew
	// tacquito's fetch works: make only the deploy clone offline once the
	// build phase is over.
	deployFetch := func(c execx.Cmd) bool { return slices.Contains(gitIn(c, h.Deploy), "fetch") }
	h.Run.When(deployFetch, execx.Result{Code: 128, Stderr: []byte(fetchOffline)}, nil)
	err := h.upgrade()
	if matrixCode(err) != 1 {
		t.Fatalf("exit %d (%v)", matrixCode(err), err)
	}
	h.errHas("[ERROR] git fetch failed. Check network / credentials.")
	if h.deployCalled("pull") || h.built() || h.head != commitOld {
		t.Errorf("calls %v", h.deployCalls())
	}
	h.binaryUntouched()
	h.noExec()
}

// The pull succeeds, the Go toolchain is missing (or too old) and cannot be
// had: the build recipe fails; Decision 20: the recipe is printed, exit 1,
// the installed command untouched, no exec, the upgrade stops.
func TestMatrixNoGoToolchain(t *testing.T) {
	h := newMatrixHost(t)
	h.remote["develop"] = commitNew
	h.build = buildNoGo
	err := h.upgrade()
	if matrixCode(err) == 0 {
		t.Fatal("a failed build succeeded")
	}
	h.errHas("Go toolchain not found at /usr/local/go/bin/go.") // the recipe's own complaint
	h.errHas("could not be built (see above). The installed command is unchanged.")
	h.errHas("sudo git -C " + h.Deploy + " checkout " + commitOld)
	if h.head != commitNew {
		t.Error("the pull did not happen")
	}
	h.binaryUntouched()
	h.noExec()
	if got := h.phasesRun(); slices.Contains(got, "config") || slices.Contains(got, "finish") {
		t.Errorf("the upgrade went on with the old code: %v", got)
	}
}

// The build fails for lack of space (or a vendor tree out of sync): as
// above, and a half-written <binary>.new is not left behind.
func TestMatrixBuildFailsDiskFull(t *testing.T) {
	h := newMatrixHost(t)
	h.remote["develop"] = commitNew
	h.build = buildDiskFull
	err := h.upgrade()
	if matrixCode(err) == 0 {
		t.Fatal("a failed build succeeded")
	}
	h.errHas("no space left on device")
	h.errHas("could not be built (see above). The installed command is unchanged.")
	h.binaryUntouched()
	h.noExec()
}

// Ctrl-C during the build: <binary>.new removed, the installed command
// untouched, no exec, a non-zero status; a re-run then completes.
func TestMatrixInterruptDuringBuild(t *testing.T) {
	h := newMatrixHost(t)
	h.remote["develop"] = commitNew
	h.build = buildInterrupt
	err := h.upgrade()
	if matrixCode(err) == 0 {
		t.Fatal("an interrupted build succeeded")
	}
	h.binaryUntouched()
	h.noExec()
	if got := h.phasesRun(); slices.Contains(got, "config") {
		t.Errorf("phases %v", got)
	}
	// Re-run: the tree is already at the new commit, the binary is not
	// built from it, so it is built now and exec'd.
	h.build = ""
	if err := h.upgrade(); err != nil {
		t.Fatalf("re-run: %v\n%s", err, h.stderr)
	}
	if h.read(h.Binary) != newBinary || len(h.Run.Execs()) != 1 {
		t.Errorf("binary %q, execs %v", h.read(h.Binary), h.Run.Execs())
	}
}

// The self-update: pulled Go code is built into the installed command,
// which is exec'd with 'upgrade' and the loop guard; nothing else runs in
// the old process.
func TestMatrixSelfUpdateReexecs(t *testing.T) {
	h := newMatrixHost(t)
	h.remote["develop"] = commitNew
	if err := h.upgrade(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	if h.read(h.Binary) != newBinary {
		t.Error("not built")
	}
	execs := h.Run.Execs()
	if len(execs) != 1 || execs[0].Path != h.Binary || !slices.Equal(execs[0].Argv[1:], []string{"upgrade"}) ||
		!slices.Contains(execs[0].Env, reexecGuard) {
		t.Fatalf("execs %+v", execs)
	}
	if !h.Run.Called(filepath.Join(h.Deploy, "bin", "tacctl.sh"), "--build", h.Binary) {
		t.Errorf("build call: %v", h.Run.Argvs())
	}
	if got := h.phasesRun(); slices.Contains(got, "config") || slices.Contains(got, "finish") {
		t.Errorf("the old process went on: %v", got)
	}
	// START is taken before the branch switch (0.1.16 item (g)): a switch
	// to a branch already at the remote, with nothing to pull, still
	// rebuilds and exec's.
	h = newMatrixHost(t)
	if err := h.upgrade("--branch", "feature/x"); err != nil {
		t.Fatalf("--branch: %v\n%s", err, h.stderr)
	}
	if h.head != commitNew || h.deployCalled("pull") || !h.built() || len(h.Run.Execs()) != 1 {
		t.Errorf("head %s, calls %v, execs %v", h.head, h.deployCalls(), h.Run.Execs())
	}
}

// Built, exec'd, and then the Go upgrade fails mid-way (a backend's
// 'upgrade config', e.g. 'freeradius -C' rejects the render): the upgrade
// stops with a non-zero status, the new binary stays installed; running
// 'tacctl upgrade' again once the cause is fixed completes it, with nothing
// to pull, build or exec.
func TestMatrixMidUpgradeFailure(t *testing.T) {
	h := newMatrixHost(t)
	// The state after the self-update: tree and binary at the new commit,
	// this process the exec'd one.
	h.remote["develop"] = commitNew
	h.local["develop"] = commitNew
	h.head = commitNew
	h.checkout(commitNew)
	if err := os.WriteFile(h.Binary, []byte(newBinary), 0o755); err != nil {
		t.Fatal(err)
	}
	h.BinaryCommit = commitNew
	h.Env = append(h.Env, reexecGuard)
	h.tac.failAt = backend.PhaseConfig
	err := h.upgrade()
	if matrixCode(err) == 0 {
		t.Fatal("a failed backend phase succeeded")
	}
	if got := h.phasesRun(); !slices.Contains(got, "build") || !slices.Contains(got, "config") ||
		slices.Contains(got, "files") || slices.Contains(got, "finish") {
		t.Errorf("phases %v", got)
	}
	if h.read(h.Binary) != newBinary || h.built() {
		t.Error("the binary changed")
	}
	h.noExec()
	// Again, the cause fixed (and without the guard: a new invocation).
	h.tac.failAt = ""
	h.Env = h.Env[:len(h.Env)-1]
	if err := h.upgrade(); err != nil {
		t.Fatalf("second run: %v\n%s", err, h.stderr)
	}
	if got := h.phasesRun(); !slices.Equal(got[len(got)-3:], []string{"config", "files", "finish"}) {
		t.Errorf("phases %v", got)
	}
	if h.deployCalled("pull") || h.built() {
		t.Errorf("pulled or built: %v", h.Run.Argvs())
	}
	h.noExec()
}

// The loop guard: an exec'd upgrade whose binary is still not at HEAD (the
// remote moved again) does not build and exec a second time; it finishes.
func TestMatrixReexecGuard(t *testing.T) {
	h := newMatrixHost(t)
	h.Env = append(h.Env, reexecGuard)
	h.BinaryCommit = "4444444444444444444444444444444444444444"
	if err := h.upgrade(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	if h.built() {
		t.Error("built again")
	}
	h.noExec()
	if got := h.phasesRun(); !slices.Contains(got, "finish") {
		t.Errorf("phases %v", got)
	}
}

// Nothing to do: a second upgrade pulls, builds and execs nothing (0.1.16
// item (c) at the self-update level).
func TestMatrixUpToDate(t *testing.T) {
	h := newMatrixHost(t)
	if err := h.upgrade(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	if h.deployCalled("pull") || h.built() {
		t.Errorf("calls %v", h.Run.Argvs())
	}
	h.noExec()
	h.binaryUntouched()
	if got := h.phasesRun(); !slices.Equal(got, []string{"preflight", "build", "config", "files", "finish"}) {
		t.Errorf("phases %v", got)
	}
}

// Rollback: 'upgrade --branch master' while master is 0.1.16 hands over to
// the bash tree: the symlink is back, the bash entrypoint executable and
// exec'd with 'upgrade', nothing is built.
func TestMatrixRollbackToBashRelease(t *testing.T) {
	h := newMatrixHost(t)
	if err := h.upgrade("--branch", "master"); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	entry := filepath.Join(h.Deploy, "bin", "tacctl.sh")
	if !strings.Contains(stripANSI(h.stdout.String()), "Target branch is a bash release of tacctl; handing over.") {
		t.Errorf("stdout:\n%s", h.stdout)
	}
	if target, err := os.Readlink(h.Binary); err != nil || target != entry {
		t.Errorf("the installed command is not the symlink: %q %v", target, err)
	}
	if st, err := os.Stat(entry); err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("entrypoint mode %v %v", st, err)
	}
	execs := h.Run.Execs()
	if len(execs) != 1 || execs[0].Path != entry || !slices.Equal(execs[0].Argv[1:], []string{"upgrade"}) {
		t.Fatalf("execs %+v", execs)
	}
	if h.built() {
		t.Error("built a bash release")
	}
	if got := h.phasesRun(); slices.Contains(got, "config") {
		t.Errorf("phases %v", got)
	}
	if h.read(filepath.Join(h.Deploy, "lib", "core.sh")) == "" || h.read(filepath.Join(h.Deploy, "go.mod")) != "" {
		t.Error("the tree is not the bash release")
	}
}

// dpkg plays dpkg-query on the matrix host: the packages of have are
// installed, every other one is not.
func (h *matrixHost) dpkg(have ...string) {
	h.Run.Func(func(c execx.Cmd) bool { return c.Name == "dpkg-query" }, func(c execx.Cmd) (execx.Result, error) {
		if slices.Contains(have, c.Args[len(c.Args)-1]) {
			return execx.Result{Stdout: []byte("install ok installed")}, nil
		}
		return execx.Result{Code: 1}, nil
	})
}

// Rollback onto a bash release whose packages are all there: no apt-get,
// the hand-over as before (3.9 item 32).
func TestMatrixRollbackBashDepsPresent(t *testing.T) {
	h := newMatrixHost(t)
	h.dpkg("python3", "python3-yaml", "python3-bcrypt")
	if err := h.upgrade("--branch", "master"); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	out := stripANSI(h.stdout.String())
	if !strings.Contains(out, "Packages the bash release needs: all present.") ||
		!strings.Contains(out, "Target branch is a bash release of tacctl; handing over.") {
		t.Errorf("stdout:\n%s", out)
	}
	if h.Run.Called("apt-get") {
		t.Error("apt-get ran although every package is installed")
	}
	if n := len(h.Run.Execs()); n != 1 {
		t.Errorf("execs: %d", n)
	}
}

// A server installed with 0.2.0 has no python: the packages are installed
// with apt-get first, then the host is handed over.
func TestMatrixRollbackInstallsBashDeps(t *testing.T) {
	h := newMatrixHost(t)
	h.dpkg("python3")
	if err := h.upgrade("--branch", "master"); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	if !strings.Contains(stripANSI(h.stdout.String()), "Installing packages the bash release needs: python3-yaml python3-bcrypt") {
		t.Errorf("stdout:\n%s", h.stdout)
	}
	if !h.Run.Called("apt-get", "install", "-y", "-qq", "python3-yaml", "python3-bcrypt") {
		t.Errorf("apt-get install not called: %v", h.Run.Argvs())
	}
	for _, r := range h.Run.Records() {
		if r.Cmd.Name == "apt-get" && !slices.Contains(r.Cmd.Env, "DEBIAN_FRONTEND=noninteractive") {
			t.Errorf("apt-get without DEBIAN_FRONTEND=noninteractive: %v", r.Cmd.Env)
		}
	}
	entry := filepath.Join(h.Deploy, "bin", "tacctl.sh")
	execs := h.Run.Execs()
	if len(execs) != 1 || execs[0].Path != entry {
		t.Fatalf("execs %+v", execs)
	}
	if target, err := os.Readlink(h.Binary); err != nil || target != entry {
		t.Errorf("the installed command is not the symlink: %q %v", target, err)
	}
}

// apt-get cannot install them: no hand-over. The installed command is the
// Go binary as before, the clone is back on its branch, and the message
// names the command that fixes it.
func TestMatrixRollbackRefusedWithoutBashDeps(t *testing.T) {
	h := newMatrixHost(t)
	h.dpkg()
	h.Run.On([]string{"apt-get", "install"}, execx.Result{Code: 100})
	err := h.upgrade("--branch", "master")
	if err == nil {
		t.Fatal("upgrade succeeded")
	}
	if n := len(h.Run.Execs()); n != 0 {
		t.Errorf("exec'd %d times", n)
	}
	if st, err := os.Lstat(h.Binary); err != nil || !st.Mode().IsRegular() || h.read(h.Binary) != oldBinary {
		t.Errorf("the installed command changed: %v %v", st, err)
	}
	if h.branch != "develop" || h.head != commitOld {
		t.Errorf("the clone is on %s at %s", h.branch, h.head)
	}
	if h.read(filepath.Join(h.Deploy, "go.mod")) == "" {
		t.Error("the tree is not the Go tree again")
	}
	errs := stripANSI(h.stderr.String())
	for _, want := range []string{
		"Could not install: python3 python3-yaml python3-bcrypt. The bash release cannot run without them; not handing over.",
		h.Deploy + " is back on 'develop'; " + h.Binary + " is unchanged.",
		"sudo apt-get install -y python3 python3-yaml python3-bcrypt && sudo tacctl upgrade --branch master",
	} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(stripANSI(h.stdout.String()), "handing over") {
		t.Error("announced a hand-over")
	}
}

// --- the implementation ------------------------------------------------------

// realUpgrade is lifecycle.Upgrade on the matrix host: its paths
// (matrixPaths), runner, backend set, environment and binary commit.
type realUpgrade struct{}

func (realUpgrade) Upgrade(ctx context.Context, h *matrixHost, args []string) error {
	be := h.Set.Env
	be.Paths = matrixPaths(h)
	host := &lifecycle.Host{Env: lifecycle.NewEnv(be, nil, false), Environ: paths.NewEnv(h.Env), Commit: h.BinaryCommit, Completion: testCompletion}
	return lifecycle.Upgrade(ctx, host, args)
}

// matrixPaths are the paths an upgrade on h works with: those of its
// environment, tacctl's fixed host locations moved into the sandbox, the
// deploy clone and the installed command h's.
func matrixPaths(h *matrixHost) paths.Paths {
	p := paths.Resolve(paths.NewEnv(h.Env), "", func(string) bool { return false }).Reroot(h.root)
	p.Deploy, p.Command = h.Deploy, h.Binary
	return p
}
