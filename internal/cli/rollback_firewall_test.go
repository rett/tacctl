package cli

import (
	"os"
	"strings"
	"testing"
)

// The rollback and the break-glass firewall (0.2.24): every target removes
// the setting, the nftables table (through the runner: nft is scripted), the
// rules file and the boot unit, leaves the package, and says so. A hold that
// stands stays: 0.2.23 has the record.

func rollbackFirewallState(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollback0223State(t)
	hs.step("", "config", "breakglass-firewall", "drop")
	if _, err := os.Stat(hs.path("state", "breakglass-firewall.nft")); err != nil {
		t.Fatal(err)
	}
	return hs
}

func TestRollbackRemovesTheFirewall(t *testing.T) {
	hs := rollbackFirewallState(t)
	hs.write("state/tacctl.yaml", hs.overrides()+"breakglass_hold:\n  sw1:\n    address: 10.99.0.1\n    since: '2026-10-12T13:11:00+00:00'\n    by: alice\n    reason: console recovery\n", 0o600)
	r := hs.runner()
	hs.run(r, "rollback", "0.2.23")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{
		"remove breakglass.firewall",
		"the break-glass firewall: remove the nftables table, its rules file and its boot unit   [does]",
		"the nftables package stays; nftables.service is never touched",
		"The break-glass hold of sw1 (10.99.0.1) stands, and 0.2.23 takes it over as it is, without the firewall",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if r.Called("nft") || !strings.Contains(hs.overrides(), "firewall: drop") {
		t.Error("the dry run changed something")
	}

	r = hs.runner()
	hs.run(r, "rollback", "0.2.23", "--apply")
	hs.expect(0, "", "")
	out = hs.all()
	for _, want := range []string{
		"removed 1 key",
		"break-glass firewall: removed the nftables table inet tacctl, " + hs.path("state", "breakglass-firewall.nft"),
		"the nftables package stays",
		"The break-glass firewall is removed: the nftables table inet tacctl",
		"The hold of sw1 (10.99.0.1) stands, and 0.2.23 takes it as it is: its server completes the TCP handshake of the held address",
		"run no verb that changes the holds, their device or host names, the listeners or the setting ('tacctl breakglass hold|release', 'device address', 'device|host rename', 'device rename --replace', 'backup restore', 'server listen', 'config breakglass-firewall')",
		"each writes the table, its rules file and the boot unit again, and the setting 0.2.23 refuses",
		// the key was set: the apply took a snapshot, and the next steps say where the state is
		"The snapshot the rollback took first (the newest entry of 'tacctl backup list') holds the 0.2.25 state. Restore it with 0.2.25 only:",
		"0.2.23's restore refuses a tacctl.yaml with a key it does not know.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(hs.overrides(), "firewall") || !strings.Contains(hs.overrides(), "breakglass_hold") {
		t.Errorf("tacctl.yaml:\n%s", hs.overrides())
	}
	for _, f := range []string{hs.path("state", "breakglass-firewall.nft"), hs.path("systemd", "tacctl-breakglass-firewall.service")} {
		if _, err := os.Stat(f); err == nil {
			t.Errorf("%s is left", f)
		}
	}
	if !r.Called("nft", "-f") || !r.Called("systemctl", "disable", "--quiet", "tacctl-breakglass-firewall.service") {
		t.Errorf("calls %v", r.Argvs())
	}
	for _, c := range r.Calls() {
		a := strings.Join(c.Argv(), " ")
		if c.Name == "systemctl" && strings.Contains(a, "nftables") || strings.Contains(a, "flush") || strings.Contains(a, "ruleset") {
			t.Errorf("the host's ruleset or nftables.service was touched: %s", a)
		}
	}
	// again: nothing to do
	hs.run(hs.runner(), "rollback", "0.2.23", "--apply")
	hs.expect(0, "Nothing to convert", "")
	if strings.Contains(hs.all(), "break-glass firewall") {
		t.Errorf("a second rollback speaks of the firewall:\n%s", hs.all())
	}
}

// The older targets remove it too, and so does the one before them.
func TestRollbackFirewallIsRemovedForEveryTarget(t *testing.T) {
	for _, target := range []string{"0.2.22", "0.2.21"} {
		hs := rollbackFirewallState(t)
		hs.run(hs.runner(), "rollback", target, "--apply", "--yes")
		if hs.code != 0 || strings.Contains(hs.overrides(), "firewall") || !strings.Contains(hs.all(), "break-glass firewall: removed") {
			t.Errorf("%s: %d\n%s", target, hs.code, hs.all())
		}
	}
}

// A host that never had the table has nothing to say about it, with the key
// unset: the 0.2.23 dry run is what it was.
func TestRollbackWithoutAFirewallMentionsNone(t *testing.T) {
	hs := rollback0223State(t)
	hs.run(hs.runner(), "rollback", "0.2.23")
	if strings.Contains(hs.all(), "firewall") {
		t.Errorf("%s", hs.all())
	}
}
