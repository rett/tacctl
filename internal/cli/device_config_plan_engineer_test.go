package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
)

// The engineer plans the devices of their own scopes and only those; a
// section their login's class cannot commit is left out with the class
// named; an operator does not plan at all.

// engineerBox is a pulled Junos device of scope lab and one of prod, both
// missing the standard's server and authentication order; bob (group
// operator) is an engineer of lab, and his group's class is EN-CLASS.
func engineerBox(t *testing.T) *pullBox {
	t.Helper()
	b := newPullBox(t)
	b.sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	store := b.sb.read("state/store.yaml")
	b.sb.write("state/store.yaml", strings.Replace(store, "juniper_class: OP-CLASS", "juniper_class: EN-CLASS", 1), 0o600)
	b.devices([3]string{"lab-j", "192.168.1.20", "juniper"}, [3]string{"prod-j", "10.99.0.20", "juniper"})
	var kept []string
	for _, l := range strings.Split(strings.TrimSpace(b.expected("lab-j")), "\n") {
		if strings.HasPrefix(l, "set system authentication-order") || strings.HasPrefix(l, "set system tacplus-server") {
			continue
		}
		kept = append(kept, l)
	}
	text := strings.Join(kept, "\n") + "\n"
	b.serve("juniper", text)
	b.servePlain(text)
	b.run("device", "config", "pull", "--all")
	if b.sb.code != 0 {
		t.Fatalf("pull: %d %s", b.sb.code, b.sb.stderr())
	}
	return b
}

func TestPlanEngineerSeesOnlyTheirScopesAndTheirClass(t *testing.T) {
	b := engineerBox(t)
	asBob := func(args ...string) string {
		return plain(b.sb.cfgRun("", append([]string{"device", "config", "plan"}, args...), func(r *fake.Runner) {
			route(r)
			idAs("bob", "tac-users tac-operator")(r)
		}, "SUDO_USER=bob"))
	}

	// the superuser's plan has the server and the order
	out := b.run("device", "config", "plan", "lab-j")
	if b.sb.code != 0 || !strings.Contains(out, "set system authentication-order tacplus") || !strings.Contains(out, "set system tacplus-server 10.0.0.42") {
		t.Fatalf("superuser: %d\n%s", b.sb.code, out)
	}

	// bob's: the order (a bit EN-CLASS has), not the server (it has not)
	out = asBob("lab-j")
	if b.sb.code != 0 {
		t.Fatalf("engineer: %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	un := unwrapPlan(out)
	for _, want := range []string{"set system authentication-order tacplus\n", "Not fixable by this login: EN-CLASS cannot change 'system tacplus-server' (ask a superuser)"} {
		if !strings.Contains(un, want) && !strings.Contains(out, want) {
			t.Errorf("no %q in\n%s", want, out)
		}
	}
	from, to := strings.Index(out, "PASTE FROM HERE"), strings.Index(out, "PASTE TO HERE")
	if from < 0 || to < from || strings.Contains(out[from:to], "tacplus-server") {
		t.Errorf("a server in the engineer's region:\n%s", out)
	}
	planGolden(t, "junos-engineer.out", out)
	// the scope's key read is logged, never printed where the device has it
	var logged bool
	for _, c := range b.sb.runner.Calls() {
		if c.Name == "logger" && strings.Contains(strings.Join(c.Args, " "), "secret-read kind=scope name=lab by=bob") {
			logged = true
		}
	}
	if !logged {
		t.Error("no secret-read line for the engineer's plan")
	}
	if al := b.auditLines("device config plan"); len(al) != 1 || !strings.Contains(al[0], "device config plan user=bob device=lab-j status=needs-change") {
		t.Errorf("audit %q", al)
	}

	// another scope's device is not found, and --all is all of bob's
	asBob("prod-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "Device 'prod-j' not found.") {
		t.Errorf("another scope: %d %q", b.sb.code, b.sb.stderr())
	}
	out = asBob("--all")
	if b.sb.code != 0 || strings.Contains(out, "prod-j") || !strings.Contains(out, "lab-j") {
		t.Errorf("--all: %d\n%s", b.sb.code, out)
	}
	// the superuser's --all has both
	if out := b.run("device", "config", "plan", "--all"); !strings.Contains(out, "prod-j") || !strings.Contains(out, "lab-j") {
		t.Errorf("superuser --all:\n%s", out)
	}
	// an operator may not plan: the tier's own refusal, logged
	b.sb.write("state/tacctl.yaml", "{}\n", 0o600)
	b.sb.asUser("bob", "tac-operator", "device", "config", "plan", "lab-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config plan' is not permitted for the operator tier.") {
		t.Errorf("operator: %d %q", b.sb.code, b.sb.stderr())
	}
	b.sb.asUser("carol", "tac-readonly", "device", "config", "plan", "lab-j")
	if b.sb.code != 1 || !strings.Contains(b.sb.stderr(), "'tacctl device config' is not permitted for the readonly tier.") {
		t.Errorf("readonly: %d %q", b.sb.code, b.sb.stderr())
	}
}
