package lifecycle_test

// Assertions of deleted bats tests that the ports elsewhere in this
// package left out: tests/e2e/install_seed.bats (#2, #3),
// tests/integration/upgrade_store_flip.bats (#22),
// tests/integration/migrate_exec_service_name.bats (#7) and
// tests/integration/upgrade_restart.bats (#17, #19).

import (
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/model"
)

// install_seed.bats "install: the mode and the generated secret are handed
// to the caller, not printed": the secret never reaches the argv (or the
// environment) of a command the install runs (the daemon binary is there,
// so a load-smoke, if the seed ran one, would be recorded too).
func TestSeedTheGeneratedSecretIsOnNoCommandLine(t *testing.T) {
	e := newSeedEnv(t)
	e.fakeTacquito("serve")
	e.reset()
	r := e.mustFreshInstall()
	if r.Mode != lifecycle.SeedFresh || r.Secret != secret {
		t.Fatalf("%+v", r)
	}
	// (In Go a fresh install runs no command at all here: the secret
	// comes from env.Rand, not 'openssl rand', and the chown is a call.
	// The check stays, so that a command added later is held to it.)
	if e.run.ArgvContains(secret) {
		t.Errorf("the secret is on a command line: %v", e.run.Argvs())
	}
	for _, c := range e.run.Calls() {
		for _, v := range c.Env {
			if strings.Contains(v, secret) {
				t.Errorf("the secret is in the environment of %v", c.Argv())
			}
		}
	}
	// The secret did reach the files the commands read.
	if !strings.Contains(e.read(e.p.StoreFile), secret) || !strings.Contains(e.read(e.p.Config), secret) {
		t.Error("the secret is not in the store and the rendered config")
	}
}

// install_seed.bats "install: the store holds the built-in groups, ...":
// the built-in groups' priv-lvl values.
func TestSeedTheBuiltinGroupsPrivLvl(t *testing.T) {
	e := newSeedEnv(t)
	e.mustFreshInstall()
	_, m, err := model.LoadStore(e.p.StoreFile)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"readonly": 1, "operator": 7, "superuser": 15}
	if len(m.Groups) != len(want) {
		t.Errorf("groups %+v", m.Groups)
	}
	for _, g := range m.Groups {
		w, ok := want[g.Name]
		if !ok || g.PrivLvl == nil || *g.PrivLvl != w || !g.Builtin {
			t.Errorf("group %s: priv_lvl %v builtin %v, want %d", g.Name, g.PrivLvl, g.Builtin, w)
		}
	}
	// And so in the store file itself.
	text := e.read(e.p.StoreFile)
	for _, s := range []string{"  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}\n",
		"  operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}\n",
		"  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}\n"} {
		has(t, text, s)
	}
}

// upgrade_store_flip.bats "rollback: the next upgrade flips again and
// reuses the pre-store copy": after a rollback (StoreUnflip, what 'tacctl
// store rollback' does once confirmed), the next upgrade's gate flips
// again, and the one pre-store copy is still the only one.
func TestFlipAfterARollbackTheNextUpgradeFlipsAgainReusingThePreStoreCopy(t *testing.T) {
	e := newTenv(t)
	e.fakeTacquito("serve")
	e.write(e.p.Config, fixture(t, "legacy.fresh-install.yaml"), 0o640)
	e.upgradeSync()
	original := sha(t, e.p.Config)
	if r := e.flip(); r != lifecycle.Flipped {
		t.Fatalf("first flip %v\n%s", r, e.output())
	}
	pre := e.preStoreFiles()
	if len(pre) != 1 {
		t.Fatalf("pre-store copies %v", pre)
	}
	if err := lifecycle.StoreUnflip(e.env, pre[0]); err != nil {
		t.Fatal(err)
	}
	if sha(t, e.p.Config) != original || exists(e.p.StoreFile) || exists(e.p.Rendered) {
		t.Fatal("rollback state")
	}
	e.reset()
	e.upgradeSync()
	if r := e.flip(); r != lifecycle.Flipped {
		t.Fatalf("flip after the rollback %v\n%s", r, e.output())
	}
	if got := e.preStoreFiles(); !slices.Equal(got, pre) || sha(t, got[0]) != original {
		t.Errorf("pre-store copies %v, want %v", got, pre)
	}
	if !exists(e.p.StoreFile) || !exists(e.p.Rendered) || e.systemctlCalled() {
		t.Error("state after the second flip")
	}
}

// migrate_exec_service_name.bats "with a store the file is left alone;
// the import and render do the healing": after the forced render,
// exec_operator keeps values: [7].
func TestMigrateExecWithAStoreTheRenderKeepsTheOperatorPrivLvl(t *testing.T) {
	e := newTenv(t)
	e.loadFixture("tacquito.legacy-exec.yaml")
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil {
		t.Fatal(err)
	}
	if err := e.set.ConfigRender(ctx, true); err != nil {
		t.Fatal(err)
	}
	cfg := e.read(e.p.Config)
	i := strings.Index(cfg, "\nexec_operator:")
	if i < 0 {
		t.Fatalf("no exec_operator anchor:\n%s", cfg)
	}
	// grep -A4 '^exec_operator:'
	blk := strings.Join(strings.SplitN(cfg[i+1:], "\n", 6)[:5], "\n")
	has(t, blk, "values: [7]")
	has(t, blk, "name: shell")
}

// upgrade_restart.bats "upgrade --branch to a branch whose lib/ differs
// re-executes the new tacctl once; that run has nothing more to pull": the
// switch and the update are reported, the build and exec happen once, and
// the re-executed run (the loop guard set, the binary now HEAD's) is on
// the branch, up to date, and finishes.
func TestUpgradeBranchSwitchReportsAndReexecsOnce(t *testing.T) {
	h := newMatrixHost(t)
	if err := h.upgrade("--branch", "feature/x"); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	out := stripANSI(h.stdout.String())
	inOrder(t, out, "[INFO] Switched to branch 'feature/x'.\n", "[INFO] Management scripts updated: "+commitNew[:7]+"\n",
		"tacctl updated — restarting upgrade with new version...")
	if n := strings.Count(out, "restarting upgrade with new version"); n != 1 || len(h.Run.Execs()) != 1 {
		t.Errorf("restarting %d times, execs %v", n, h.Run.Execs())
	}
	// The new process.
	h.Env = append(h.Env, reexecGuard)
	h.BinaryCommit = commitNew
	if err := h.upgrade(); err != nil {
		t.Fatalf("re-executed run: %v\n%s", err, h.stderr)
	}
	out = stripANSI(h.stdout.String())
	has(t, out, "[INFO] Management scripts already up to date.\n")
	hasNot(t, out, "restarting upgrade")
	if h.branch != "feature/x" || h.deployCalled("pull") || h.built() {
		t.Errorf("branch %s calls %v", h.branch, h.deployCalls())
	}
	h.noExec()
	if got := h.phasesRun(); !slices.Contains(got, "finish") {
		t.Errorf("phases %v", got)
	}
}

// upgrade_restart.bats "a pull on the same branch that changes lib/
// re-executes once; one that changes only README.md does not": the second
// half, as the Go upgrade has it. 0.1.18 re-executed only when bin/ or
// lib/ changed between START and HEAD; the Go upgrade also rebuilds and
// re-executes whenever the running binary was not built from HEAD, so a
// pull that changes only README.md (no change under the self-update
// paths: 'git diff --quiet' succeeds) still rebuilds and re-executes once.
func TestUpgradeAReadmeOnlyPullStillRebuildsBecauseTheBinaryIsNotHEAD(t *testing.T) {
	h := newMatrixHost(t)
	const readmeOnly = "5555555555555555555555555555555555555555"
	h.remote["develop"] = readmeOnly
	// Only README.md differs between START and the pulled commit.
	h.Run.When(func(c execx.Cmd) bool { return slices.Contains(gitIn(c, h.Deploy), "diff") }, execx.Result{}, nil)
	if err := h.upgrade(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	out := stripANSI(h.stdout.String())
	has(t, out, "[INFO] Management scripts updated: "+readmeOnly[:7]+"\n")
	if !h.deployCalled("pull --ff-only") || !h.deployCalled("diff --quiet "+commitOld+" HEAD --") {
		t.Errorf("calls %v", h.deployCalls())
	}
	// Go: the binary (built from 1111111) is not HEAD (5555555): rebuilt, exec'd.
	if !h.built() || len(h.Run.Execs()) != 1 || strings.Count(out, "restarting upgrade with new version") != 1 {
		t.Errorf("built %v execs %v\n%s", h.built(), h.Run.Execs(), out)
	}
	// The same pull with a binary that is already HEAD's: no rebuild, no exec.
	h = newMatrixHost(t)
	h.remote["develop"] = readmeOnly
	h.BinaryCommit = readmeOnly
	h.Run.When(func(c execx.Cmd) bool { return slices.Contains(gitIn(c, h.Deploy), "diff") }, execx.Result{}, nil)
	if err := h.upgrade(); err != nil {
		t.Fatalf("upgrade: %v\n%s", err, h.stderr)
	}
	if h.built() {
		t.Error("built")
	}
	h.noExec()
	if got := h.phasesRun(); !slices.Contains(got, "finish") {
		t.Errorf("phases %v", got)
	}
}
