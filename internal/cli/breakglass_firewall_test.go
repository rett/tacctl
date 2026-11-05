package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// The break-glass firewall (0.2.24) in-process: the setting command, and the
// table the holds load, with nft scripted on the fake runner (no test runs a
// real nft, systemctl or apt-get).

const heldLabSw = `tier:
  operator: engineer
breakglass_hold:
  lab-sw:
    address: 192.168.1.1
    since: '2026-10-12T13:11:00+00:00'
    by: root
    reason: console recovery
`

func (sb *sandbox) fwRules() string { return sb.read("state/breakglass-firewall.nft") }

// nftLoads is how many times the rules file was handed to nft.
func (sb *sandbox) nftLoads() int { return sb.runner.Count("nft", "-f") }

func TestBreakglassFirewallSettingShowsAndSets(t *testing.T) {
	sb := engineerSandbox(t)
	out := plain(sb.run("", []string{"config", "breakglass-firewall"}))
	for _, want := range []string{"Break-glass firewall: reject   (default)", "Held now: none", "Usage: tacctl config breakglass-firewall [reject|drop|off]"} {
		if !strings.Contains(out, want) {
			t.Errorf("show lacks %q:\n%s", want, out)
		}
	}
	if sb.nftLoads() != 0 {
		t.Error("showing the setting loaded a table")
	}

	// A bad value, and a second argument, change nothing.
	sb.run("", []string{"config", "breakglass-firewall", "block"})
	sb.expect(1, "", "Invalid value: 'block'. Use: reject, drop, off")
	sb.run("", []string{"config", "breakglass-firewall", "drop", "x"})
	sb.expect(1, "", "Unknown argument: 'x'")
	if strings.Contains(sb.overrides(), "breakglass:") || sb.nftLoads() != 0 {
		t.Fatalf("a refused value changed something:\n%s", sb.overrides())
	}

	// drop: written, loaded at once, said.
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "drop"}))
	if sb.code != 0 || !strings.Contains(out, "the table inet tacctl is loaded with drop on tcp/49 and no held address") {
		t.Fatalf("drop: %d %q %q", sb.code, out, sb.stderr())
	}
	if o := sb.overrides(); !strings.Contains(o, "breakglass:\n  firewall: drop\n") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if sb.nftLoads() != 1 || !strings.Contains(sb.fwRules(), "tcp dport { 49 } drop") {
		t.Errorf("loads %d, rules:\n%s", sb.nftLoads(), sb.fwRules())
	}
	if !hasAuditMatch(sb.runner, "", `config breakglass-firewall from=reject to=drop firewall=drop`) {
		t.Errorf("no detail line: %v", sb.runner.Argvs())
	}

	// off: written as a string (not a YAML boolean), the table removed.
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "off"}))
	if sb.code != 0 || !strings.Contains(out, "off: the table inet tacctl is removed") {
		t.Fatalf("off: %d %q %q", sb.code, out, sb.stderr())
	}
	if o := sb.overrides(); !strings.Contains(o, "firewall: 'off'") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if strings.Contains(sb.fwRules(), "chain") {
		t.Errorf("an off table defines a chain:\n%s", sb.fwRules())
	}
	if got := plain(sb.run("", []string{"config", "breakglass-firewall"})); !strings.Contains(got, "Break-glass firewall: off   (tacctl.yaml)") {
		t.Errorf("show:\n%s", got)
	}
	if got := plain(sb.run("", []string{"config", "validate"})); strings.Contains(got, "breakglass.firewall") {
		t.Errorf("a valid setting is reported:\n%s", got)
	}

	// reject: the default, so the key goes; the table is loaded again.
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "reject"}))
	if sb.code != 0 || strings.Contains(sb.overrides(), "firewall") || sb.nftLoads() != 1 {
		t.Fatalf("reject: %d %q loads %d\n%s", sb.code, out, sb.nftLoads(), sb.overrides())
	}
	// unchanged: the table is loaded again all the same.
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "reject"}))
	if !strings.Contains(out, "breakglass.firewall is reject already; the table was loaded again.") || sb.nftLoads() != 1 {
		t.Errorf("again: %q loads %d", out, sb.nftLoads())
	}
}

func TestBreakglassFirewallSettingWithAHold(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	out := plain(sb.run("", []string{"config", "breakglass-firewall", "reject"}))
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.1 refused on tcp/49 (reject)") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if r := sb.fwRules(); !strings.Contains(r, "elements = { 192.168.1.1 }") || !strings.Contains(r, "reject with tcp reset") {
		t.Errorf("rules:\n%s", r)
	}
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "off"}))
	if !strings.Contains(out, "the server completes the TCP handshake of a held address again") {
		t.Errorf("off: %q", out)
	}
}

func TestBreakglassFirewallSettingWhenNftIsMissing(t *testing.T) {
	sb := engineerSandbox(t)
	sb.script = func(r *fake.Runner) { r.Missing("nft") }
	// nothing held: nothing to refuse, so nothing fails
	out := plain(sb.run("", []string{"config", "breakglass-firewall", "drop"}))
	if sb.code != 0 || !strings.Contains(out, "nothing is held and nft is not installed") || !strings.Contains(out, "sudo apt-get install nftables") {
		t.Fatalf("no hold: %d %q %q", sb.code, out, sb.stderr())
	}
	// an address held: red, the fix, exit 1; the setting is written all the same
	sb.write("state/tacctl.yaml", heldLabSw+"breakglass:\n  firewall: drop\n", 0o600)
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "drop"}))
	if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft is not installed)") ||
		!strings.Contains(sb.stderr(), "sudo apt-get install nftables, then tacctl config breakglass-firewall drop") {
		t.Fatalf("held: %d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.overrides(), "firewall: drop") {
		t.Errorf("the setting was not kept:\n%s", sb.overrides())
	}
}

func TestBreakglassFirewallSettingWhenNftFails(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-f"}, execx.Result{Code: 1, Stderr: []byte("Error: Operation not permitted\n")})
	}
	out := plain(sb.run("", []string{"config", "breakglass-firewall", "drop"}))
	if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft -f ") || !strings.Contains(out, "Operation not permitted") ||
		!strings.Contains(sb.stderr(), "then tacctl config breakglass-firewall drop") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if !hasAuditMatch(sb.runner, "", `config breakglass-firewall from=reject to=drop firewall=failed`) {
		t.Errorf("no detail line: %v", sb.runner.Argvs())
	}
}

func TestBreakglassFirewallIsTheSuperusers(t *testing.T) {
	sb := engineerSandbox(t)
	sb.asEngineer("", "config", "breakglass-firewall", "off")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
		t.Errorf("%d %q", sb.code, sb.stderr())
	}
	if strings.Contains(sb.overrides(), "firewall") {
		t.Error("an engineer changed the setting")
	}
}

func TestBreakglassFirewallShowReadsTheLiveTable(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	sb.script = func(r *fake.Runner) {
		r.Fail([]string{"nft", "-j", "list", "table"}, 1, "Error: No such file or directory")
	}
	out := plain(sb.run("", []string{"config", "breakglass-firewall"}))
	if !strings.Contains(out, "Held now: 192.168.1.1; ports tcp/49") || !strings.Contains(out, "Table:    differs: the table inet tacctl is missing") ||
		!strings.Contains(out, "tacctl config breakglass-firewall reject") {
		t.Errorf("%q", out)
	}
	sb.script = func(r *fake.Runner) {
		r.Fail([]string{"nft", "-j", "list", "table"}, 1, "netlink: Error: cannot open: Operation not permitted")
	}
	out = plain(sb.run("", []string{"config", "breakglass-firewall"}))
	if sb.code != 0 || !strings.Contains(out, "Table:    not read (nft says: netlink: Error: cannot open: Operation not permitted)") {
		t.Errorf("%d %q", sb.code, out)
	}
}

func TestBreakglassFirewallRulesFileIsOwnedByTacctlOnly(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "breakglass-firewall", "drop"})
	if st, err := os.Stat(filepath.Join(sb.dir, "state", "breakglass-firewall.nft")); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", st, err)
	}
	for _, c := range sb.runner.Calls() {
		if c.Name == "nft" && (len(c.Args) < 2 || c.Args[0] != "-f") {
			t.Errorf("nft was run with %v", c.Args)
		}
		for _, a := range c.Argv() {
			if a == "flush" || a == "ruleset" || strings.Contains(a, "nftables") && c.Name == "systemctl" {
				t.Errorf("the host's ruleset or nftables.service was touched: %v", c.Argv())
			}
		}
	}
}
