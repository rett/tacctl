package lifecycle_test

// WP10.8a: fixes to the reviews of the upgrade and the rollback.

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/lifecycle"
)

// A4/B9 and C-missing (2): the rollback removes the tier-pin marker, so the
// round trip 0.2.3 -> rollback -> 0.2.2 (a group at priv-lvl 15 is created
// there, without the tier setting 0.2.2 has no use for) -> upgrade pins that
// group as it pins every one it finds; without the rollback the marker
// stands and the new group is held at the operator tier, never pinned.
func TestRollbackThenUpgradePinsAGroupMadeUnder022(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.store15()
	if code := upgrade(o); code != 0 {
		t.Fatalf("first upgrade: exit %d\n%s", code, o.stderr)
	}
	if !lifecycle.TierPinDone(o.p) {
		t.Fatal("the first upgrade left no marker")
	}
	// The group made under 0.2.2 (a priv-lvl 15 group needs no tier there).
	store := readFile(t, o.p.StoreFile)
	o.write(o.p.StoreFile, strings.Replace(store, "groups:\n", "groups:\n  late: {priv_lvl: 15, juniper_class: LATE-CLASS}\n", 1))
	if err := os.Chmod(o.p.StoreFile, 0o600); err != nil {
		t.Fatal(err)
	}

	// Without the rollback: the marker stands, nothing is pinned.
	if code := upgrade(o); code != 0 {
		t.Fatalf("upgrade over the marker: exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(readFile(t, o.p.Overrides), "late:") {
		t.Fatalf("the marker did not hold:\n%s", readFile(t, o.p.Overrides))
	}

	plan, err := lifecycle.PlanRollback(lifecycle.RollbackInput{Paths: o.p, Conf: o.be.Conf, HasStore: true})
	if err != nil {
		t.Fatal(err)
	}
	var step lifecycle.RollbackStep
	for _, s := range plan.Steps {
		if strings.Contains(s.Title, "tier-pin marker") {
			step = s
		}
	}
	if !step.Todo || step.Title != "remove the tier-pin marker so the next upgrade pins again" || !plan.Pending() {
		t.Fatalf("the dry run does not list the marker: %+v", step)
	}
	done, err := lifecycle.ApplyRollback(plan)
	if err != nil || !strings.Contains(strings.Join(done, "\n"), o.p.TierPinMarker+": removed") {
		t.Fatalf("apply: %q %v", done, err)
	}
	if lifecycle.TierPinDone(o.p) {
		t.Fatal("the marker is still there")
	}
	o.be.Conf.Reload()
	o.stdout.Reset()
	if code := upgrade(o); code != 0 {
		t.Fatalf("upgrade after the rollback: exit %d\n%s", code, o.stderr)
	}
	if y := readFile(t, o.p.Overrides); !strings.Contains(y, "late: superuser") {
		t.Errorf("the group made under 0.2.2 is not pinned:\n%s", y)
	}
	if !strings.Contains(o.text(), "Group 'late' (priv-lvl 15): tier recorded as superuser") || !lifecycle.TierPinDone(o.p) {
		t.Errorf("output:\n%s", o.text())
	}
}

// A3: 0.2.2's 'group preset roles' wrote tier.engineer: engineer, so the
// group is engineer-tier at the upgrade while its accounts on the tacctl
// server stay in tac-superuser until a host sync. The upgrade says so, red,
// with the sync; it names only accounts of the model that are no superuser.
func TestUpgradeSaysWhenServerAccountsStillHoldRoot(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	fixture := readFile(t, "../../tests/fixtures/store.multiscope.yaml")
	o.write(o.p.StoreFile, strings.Replace(fixture, "groups:\n", "groups:\n  engineer: {priv_lvl: 15, juniper_class: EN-CLASS}\n", 1))
	o.write(o.p.StoreFile, strings.Replace(readFile(t, o.p.StoreFile), "  carol:\n    group: readonly", "  carol:\n    group: engineer", 1))
	o.write(o.p.Overrides, "tier:\n  engineer: engineer\n")
	o.write(o.p.LinuxHosts, "authsrv|local||lab|127.0.0.1|\n")
	o.be.Conf.Reload()
	// carol (now an engineer) and alice (superuser) are in tac-superuser;
	// root and a local administrator that is no tacctl user are not named.
	o.run.On([]string{"getent", "group", "tac-superuser"}, execx.Result{Stdout: []byte("tac-superuser:x:990:alice,carol,root,localadmin\n")})
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	out := o.text()
	if !strings.Contains(out, "but still in tac-superuser (root on this server): carol.") || !strings.Contains(out, "End it with: tacctl host sync authsrv") {
		t.Errorf("no word of the stale root membership:\n%s", out)
	}
	if strings.Contains(out, "alice,") || strings.Contains(out, "localadmin") {
		t.Errorf("a superuser or a non-user is named:\n%s", out)
	}

	// Nobody stale, or no enrolled server: nothing is said.
	o.stdout.Reset()
	o.run.On([]string{"getent", "group", "tac-superuser"}, execx.Result{Stdout: []byte("tac-superuser:x:990:alice\n")})
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s", code, o.stderr)
	}
	if strings.Contains(o.text(), "host sync") {
		t.Errorf("nothing is stale:\n%s", o.text())
	}
}
