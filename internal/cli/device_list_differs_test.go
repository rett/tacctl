package cli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device list --differs' keeps the devices whose last pull differs from
// what tacctl renders now, computed from the records as 'device config list
// --differs' does: the same devices, the CONFIG column and the JSON say
// differs, a device never pulled is not in it, and an engineer gets their
// own scopes' devices; a read-only user is refused.
func TestDeviceListDiffersIsConfigListDiffers(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"lab-k", "192.168.1.21", "juniper"},
		[3]string{"prod-j", "10.99.0.20", "juniper"}, [3]string{"lab-o", "192.168.1.22", "other"})
	b.sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	b.serve("juniper", b.expected("lab-j"))
	b.run("device", "config", "pull", "lab-j", "prod-j")
	list := func(args ...string) string { return b.run(append([]string{"device", "list"}, args...)...) }

	// Nothing has changed since the pulls: nothing differs.
	if out := list("--differs"); b.sb.code != 0 || !strings.Contains(out, "Registered devices (0), of 0\n") || !strings.Contains(out, "None match.") {
		t.Fatalf("before the change: %d\n%s", b.sb.code, out)
	}
	if out := list("--differs", "--json"); strings.TrimSpace(out) != "[]" {
		t.Fatalf("before the change, JSON: %s", out)
	}

	// A change of the store makes the pulled devices differ without a pull.
	b.sb.cfgRun("", []string{"config", "mgmt-acl", "add", "198.51.100.0/24"}, route, "SUDO_USER=alice")
	if b.sb.code != 0 {
		t.Fatalf("mgmt-acl add: %d %q", b.sb.code, b.sb.stderr())
	}
	out := list("--differs")
	if b.sb.code != 0 || !strings.Contains(out, "Registered devices (2), of 2\n") || !strings.Contains(out, "lab-j") || !strings.Contains(out, "prod-j") ||
		strings.Contains(out, "lab-k") || strings.Contains(out, "lab-o") {
		t.Fatalf("after the change: %d\n%s", b.sb.code, out)
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "lab-j") && !slices.Contains(strings.Fields(l), "differs") {
			t.Errorf("the CONFIG column of the row %q says nothing of it", l)
		}
	}
	// Without the option the list reads the record only, as before.
	for _, l := range strings.Split(list(), "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "lab-j") && !slices.Contains(strings.Fields(l), "ok") {
			t.Errorf("device list row %q", l)
		}
	}
	// The same devices as 'device config list --differs'.
	var cfg []struct{ Name string }
	if err := json.Unmarshal([]byte(b.run("device", "config", "list", "--differs", "--json")), &cfg); err != nil {
		t.Fatal(err)
	}
	var js []deviceJSON
	if err := json.Unmarshal([]byte(list("--differs", "--json")), &js); err != nil {
		t.Fatal(err)
	}
	var fromCfg, fromList []string
	for _, c := range cfg {
		fromCfg = append(fromCfg, c.Name)
	}
	for _, j := range js {
		fromList = append(fromList, j.Name)
		if j.Config != "differs" || !slices.Contains(j.DiffersIn, "mgmt-acl") {
			t.Errorf("%s: config %q, differs_in %v", j.Name, j.Config, j.DiffersIn)
		}
	}
	if !slices.Equal(fromCfg, fromList) || len(fromList) != 2 {
		t.Errorf("config list --differs %v, device list --differs %v", fromCfg, fromList)
	}
	// Without --differs the JSON has no differs_in.
	if strings.Contains(list("--json"), "differs_in") {
		t.Error("differs_in without --differs")
	}
	// It narrows with the other options like --stale does, "of" counts what differs.
	if out := list("--differs", "--scope", "prod"); !strings.Contains(out, "Registered devices (1), of 2\n") || strings.Contains(out, "lab-j") {
		t.Errorf("--differs --scope prod:\n%s", out)
	}

	// An engineer gets the same result for their own scopes.
	asBob := func(args ...string) string {
		return plain(b.sb.cfgRun("", args, func(r *fake.Runner) {
			route(r)
			r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
		}, "SUDO_USER=bob"))
	}
	if out := asBob("device", "list", "--differs"); b.sb.code != 0 || !strings.Contains(out, "Registered devices (1), of 1\n") || !strings.Contains(out, "lab-j") ||
		strings.Contains(out, "prod-j") {
		t.Errorf("engineer: %d\n%s", b.sb.code, out)
	}
	// An operator too; a read-only user is refused, as for --scan.
	b.sb.write("state/tacctl.yaml", "{}\n", 0o600)
	if out := b.sb.asUser("bob", "tac-operator", "device", "list", "--differs", "--json"); b.sb.code != 0 || !strings.Contains(out, "lab-j") ||
		!strings.Contains(out, `"differs_in"`) {
		t.Errorf("operator: %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	b.sb.asUser("carol", "tac-readonly", "device", "list", "--differs")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device list --differs' is not permitted for the readonly tier.") {
		t.Errorf("readonly: %d %q", b.sb.code, b.sb.stderr())
	}
}
