package tacacs

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/rett/tacctl/internal/backend"
)

// install_seed.bats "install_readme: a checkout without README.md is not
// an error": the account phase on a tree without README.md succeeds and
// places nothing.
func TestInstallAccountWithoutReadmeIsNotAnError(t *testing.T) {
	e := newLifeTenv(t)
	tree := filepath.Join(e.dir, "no-readme")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := e.b.Install(context.Background(), backend.PhaseAccount, tree); err != nil {
		t.Fatalf("%v\n%s", err, e.out())
	}
	if exists(filepath.Join(e.p.Etc, "README.md")) {
		t.Fatal("README.md placed from a tree without one")
	}
	mustNotContain(t, e.out(), "Could not install")
}

// units_convert.bats "not converted: the first settings change converts,
// keeping the other settings", end to end with the units install that
// follows: a later upgrade has nothing left to import.
func TestFirstSettingsChangeConvertsThenUnitsInstallHasNothingToImport(t *testing.T) {
	u := newUnitsEnv(t)
	u.oldInstall("TACQUITO_ADDRESS=10.1.0.1:49", "TACQUITO_LEVEL=30")
	if err := u.b.Metrics(context.Background(), "disable", ""); err != nil {
		t.Fatalf("%v\n%s", err, u.out())
	}
	mustContain(t, u.out(), "settings moved from "+u.oldDropin+" into "+u.overrides)
	if exists(u.oldDropin) {
		t.Fatal("the hand-managed drop-in is still there")
	}
	if envOf(t, u.dropin, "TACQUITO_ADDRESS") != "10.1.0.1:49" || envOf(t, u.dropin, "TACQUITO_LEVEL") != "30" ||
		envOf(t, u.dropin, "TACQUITO_METRICS_ADDRESS") != "127.0.0.1:0" {
		t.Fatal(readFile(t, u.dropin))
	}

	u.reset()
	u.freshLife()
	if !u.install() {
		t.Fatal(u.out())
	}
	mustNotContain(t, u.out(), "settings moved")
	for _, n := range u.b.life.unitsNotes {
		mustNotContain(t, n, "settings moved")
	}
	if got := envOf(t, u.dropin, "TACQUITO_LEVEL"); got != "30" {
		t.Fatalf("TACQUITO_LEVEL=%q after the units install", got)
	}
	u.b.unitsKeepDiscard()
}

// upgrade_restart.bats "a binary rolled back after a failed restart keeps
// its mode": tacctl runs under umask 077; the binary put back after a
// restart that fails must stay 0755 for the tacquito user.
func TestUpgradeFailedRestartRollbackKeepsTheBinaryMode(t *testing.T) {
	u := newUpgradeEnv(t)
	u.repo.setRemote(commit2)
	u.sd.failRestart["tacquito"] = 1
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	wantCode(t, u.again(), 1)
	mustContain(t, u.out(), "Rolled back to the previous binary. Service is running.")
	if u.binary() != "built at "+commit1+"\n" {
		t.Fatal(u.binary())
	}
	if st, err := os.Stat(u.b.tacquitoBin()); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("rolled-back binary mode %v (%v), want 0755", st.Mode().Perm(), err)
	}
}

// backend_cli.bats "tacacs service enable and disable act on every
// listener's unit": the whole-backend enable and disable both name every
// listener's unit.
func TestServiceWholeBackendEnableAndDisableReachEveryListener(t *testing.T) {
	e := newTenv(t)
	ctx := context.Background()
	e.writeOverrides("listeners:\n  tacacs:\n    mgmt: {network: tcp, address: \"127.0.0.1:4949\"}\n")
	if _, err := e.b.Service(ctx, backend.ServiceEnable, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.b.Service(ctx, backend.ServiceDisable, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.run.Argvs(); !slices.Equal(got, []string{"systemctl enable tacquito.service tacquito@mgmt.service",
		"systemctl disable tacquito.service tacquito@mgmt.service"}) {
		t.Fatal(got)
	}
}

// backend_cli.bats "backend disable: tacacs, when another backend stays,
// stops and disables tacquito and keeps tacquito.yaml", the module's half:
// the whole-backend stop and disable it is called with are
// 'systemctl stop tacquito' and 'systemctl disable tacquito.service', and
// neither touches tacquito.yaml.
func TestServiceWholeBackendStopAndDisable(t *testing.T) {
	e := newTenv(t).withStore("store.multiscope.yaml")
	e.render(false)
	before := state(e.p.Config)
	e.reset()
	ctx := context.Background()
	if _, err := e.b.Service(ctx, backend.ServiceStop, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.b.Service(ctx, backend.ServiceDisable, ""); err != nil {
		t.Fatal(err)
	}
	if got := e.run.Argvs(); !slices.Equal(got, []string{"systemctl stop tacquito", "systemctl disable tacquito.service"}) {
		t.Fatal(got)
	}
	if state(e.p.Config) != before {
		t.Fatal("tacquito.yaml changed")
	}
}
