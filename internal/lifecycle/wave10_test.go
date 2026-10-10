package lifecycle_test

// WP10.8a: fixes to the reviews of the upgrade.

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

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
