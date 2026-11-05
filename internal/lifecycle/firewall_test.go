package lifecycle_test

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// The break-glass firewall (0.2.24) in install, upgrade and uninstall: the
// rules file and the boot unit are written, the table is loaded through the
// runner (nft is scripted; no test runs the real one), nftables.service is
// never named.

const heldOverrides = `breakglass_hold:
  sw1:
    address: 192.0.2.10
    since: '2026-10-12T13:11:00+00:00'
    by: alice
    reason: console recovery
`

func (o *ohost) neverTouchedNftablesService(t *testing.T) {
	t.Helper()
	for _, c := range o.run.Calls() {
		argv := strings.Join(c.Argv(), " ")
		if c.Name == "systemctl" && strings.Contains(argv, "nftables") {
			t.Errorf("nftables.service was touched: %s", argv)
		}
		if strings.Contains(argv, "flush") || strings.Contains(argv, "ruleset") {
			t.Errorf("the ruleset was touched: %s", argv)
		}
	}
}

// An upgrade from 0.2.23 with a hold standing renders and loads the table, so
// the standing hold gets the fix; the boot unit is written and enabled.
func TestUpgradeLoadsTheTableForStandingHolds(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.enableBoth()
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\n"+heldOverrides)
	if code := upgrade(o); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !strings.Contains(o.text(), "[INFO] Break-glass firewall: 192.0.2.10 refused on tcp/49 (reject); tacctl-breakglass-firewall.service loads the table at boot.") {
		t.Errorf("out:\n%s", o.text())
	}
	rules := readFile(t, o.p.FirewallRules)
	if !strings.Contains(rules, "elements = { 192.0.2.10 }") || !strings.Contains(rules, "reject with tcp reset") {
		t.Errorf("rules:\n%s", rules)
	}
	if !o.run.Called("nft", "-f", o.p.FirewallRules) || !o.run.Called("systemctl", "enable", "--quiet", "tacctl-breakglass-firewall.service") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	if unit := readFile(t, o.p.FirewallUnit); !strings.Contains(unit, "ExecStart=/fake/bin/nft -f "+o.p.FirewallRules) {
		t.Errorf("unit:\n%s", unit)
	}
	o.neverTouchedNftablesService(t)
	// again: nothing changes
	before := readFile(t, o.p.FirewallUnit)
	upgrade(o)
	if readFile(t, o.p.FirewallUnit) != before {
		t.Error("the unit changed")
	}
}

// Without holds the table is loaded with empty sets; nft missing with nothing
// held is no warning (the package step said it); nft missing with a hold, or
// failing, is a warning with the fix and does not fail the upgrade.
func TestUpgradeFirewallStepNeverFailsTheUpgrade(t *testing.T) {
	o := newOhost(t)
	o.cloned()
	o.enableBoth()
	if code := upgrade(o); code != 0 || !strings.Contains(o.text(), "Break-glass firewall: the table inet tacctl is loaded (reject on tcp/49, no address held)") {
		t.Fatalf("exit %d\n%s", code, o.text())
	}
	if strings.Contains(readFile(t, o.p.FirewallRules), "elements") {
		t.Error("empty sets have elements")
	}

	o = newOhost(t)
	o.cloned()
	o.enableBoth()
	o.run.Missing("nft")
	if code := upgrade(o); code != 0 || strings.Contains(o.text(), "Break-glass firewall") {
		t.Fatalf("no nft, no holds: exit %d\n%s", code, o.text())
	}

	o = newOhost(t)
	o.cloned()
	o.enableBoth()
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\n"+heldOverrides)
	o.run.Missing("nft")
	if code := upgrade(o); code != 0 || !strings.Contains(o.text(), "[WARN] Break-glass firewall: NOT APPLIED (nft is not installed). The server still completes the TCP handshake on tcp/49 for 192.0.2.10") ||
		!strings.Contains(o.text(), "Fix: sudo apt-get install nftables, then tacctl config breakglass-firewall reject.") {
		t.Fatalf("hold, no nft: exit %d\n%s", code, o.text())
	}

	o = newOhost(t)
	o.cloned()
	o.enableBoth()
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\n"+heldOverrides)
	o.run.On([]string{"nft", "-f"}, execx.Result{Code: 1, Stderr: []byte("Error: Operation not permitted\n")})
	if code := upgrade(o); code != 0 || !strings.Contains(o.text(), "NOT APPLIED (nft -f ") || !strings.Contains(o.text(), "Fix: remove the cause, then tacctl config breakglass-firewall reject.") {
		t.Fatalf("nft fails: exit %d\n%s", code, o.text())
	}
}

func TestInstallLoadsTheTable(t *testing.T) {
	o := newOhost(t)
	o.commit = "something-else"
	if code := install(o, "--yes"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !strings.Contains(o.text(), "Break-glass firewall: the table inet tacctl is loaded (reject on tcp/49, no address held)") ||
		!o.run.Called("nft", "-f", o.p.FirewallRules) || !o.run.Called("systemctl", "enable", "--quiet", "tacctl-breakglass-firewall.service") {
		t.Errorf("out:\n%s\ncalls %v", o.text(), o.run.Argvs())
	}
	o.neverTouchedNftablesService(t)
}

func TestUninstallRemovesTheFirewall(t *testing.T) {
	o := newOhost(t)
	o.installed()
	o.write(o.p.Overrides, "backends:\n  enabled: [tacacs]\n"+heldOverrides)
	o.write(o.p.FirewallRules, "table inet tacctl\n")
	o.write(o.p.FirewallUnit, "[Unit]\n")
	if code := uninstall(o, "--yes"); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, o.stdout, o.stderr)
	}
	if !strings.Contains(o.text(), "the nftables table inet tacctl, "+o.p.FirewallRules) || !strings.Contains(o.text(), "Break-glass firewall removed: the nftables table inet tacctl") {
		t.Errorf("out:\n%s", o.text())
	}
	if _, err := os.Stat(o.p.FirewallUnit); err == nil {
		t.Error("the unit is left")
	}
	if !o.run.Called("systemctl", "disable", "--quiet", "tacctl-breakglass-firewall.service") {
		t.Errorf("calls %v", o.run.Argvs())
	}
	o.neverTouchedNftablesService(t)
}
