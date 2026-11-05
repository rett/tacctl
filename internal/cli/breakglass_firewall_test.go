package cli

import (
	"encoding/json"
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

// argvIndex is the position of the first recorded call that starts with
// prefix (-1: none), after position from.
func argvIndex(r *fake.Runner, from int, prefix ...string) int {
	for i, c := range r.Calls() {
		if i < from {
			continue
		}
		argv := c.Argv()
		if len(argv) >= len(prefix) && strings.Join(argv[:len(prefix)], " ") == strings.Join(prefix, " ") {
			return i
		}
	}
	return -1
}

func TestBreakglassHoldLoadsTheTableBesideTheRestart(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	out := sb.hold(t, "lab-sw", "console recovery after a failed paste", "lab-sw")
	if sb.code != 0 {
		t.Fatalf("hold: %d %q %q", sb.code, out, sb.stderr())
	}
	// the line of the report, beside the Rendered line
	if !strings.Contains(out, "  Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.1; tacacs restarted.\n  Firewall: 192.168.1.1 refused on tcp/49 (reject)\n") {
		t.Errorf("the report:\n%s", out)
	}
	r := sb.fwRules()
	for _, want := range []string{"elements = { 192.168.1.1 }", "ip saddr @held4 tcp dport { 49 } reject with tcp reset"} {
		if !strings.Contains(r, want) {
			t.Errorf("rules lack %q:\n%s", want, r)
		}
	}
	// the restart first, the table after it
	restart := argvIndex(sb.runner, 0, "systemctl", "restart")
	load := argvIndex(sb.runner, 0, "nft", "-f")
	if restart < 0 || load < restart {
		t.Errorf("restart at %d, nft at %d: %v", restart, load, sb.runner.Argvs())
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw addr=192\.168\.1\.1 reason="console recovery after a failed paste" by=root firewall=reject result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	if sb.runner.Called("nft", "list") || sb.runner.Called("nft", "flush") {
		t.Error("nft read or flushed the ruleset")
	}

	// a rename moves the record; the table is loaded again, the same
	before := sb.nftLoads()
	sb.run("", []string{"device", "rename", "lab-sw", "lab-core"})
	sb.expect(0, "renamed to 'lab-core'", "")
	if sb.nftLoads() != 1 || !strings.Contains(sb.fwRules(), "192.168.1.1") {
		t.Errorf("rename: loads %d (was %d)\n%s", sb.nftLoads(), before, sb.fwRules())
	}

	// the release: the reverse, the sets empty
	out = plain(sb.run("", []string{"breakglass", "release", "lab-core"}))
	if sb.code != 0 || !strings.Contains(out, "  Firewall: 192.168.1.1 accepted again on tcp/49\n") {
		t.Fatalf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	if r := sb.fwRules(); strings.Contains(r, "elements") || strings.Contains(r, "192.168.1.1") {
		t.Errorf("rules after the release:\n%s", r)
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass release device=lab-core addr=192\.168\.1\.1 held=\S+ by=root firewall=reject result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
}

func TestBreakglassHoldWithDropAndOff(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "breakglass-firewall", "drop"})
	out := sb.hold(t, "lab-sw", "x", "lab-sw")
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.1 refused on tcp/49 (drop)") || !strings.Contains(sb.fwRules(), "tcp dport { 49 } drop") {
		t.Fatalf("drop: %d %q\n%s", sb.code, out, sb.fwRules())
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw .* firewall=drop result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	sb.run("", []string{"breakglass", "release", "lab-sw"})
	sb.run("", []string{"config", "breakglass-firewall", "off"})
	out = sb.hold(t, "lab-sw", "x", "lab-sw")
	if sb.code != 0 || !strings.Contains(out, "Firewall: off: the server still completes the TCP handshake on tcp/49 for 192.168.1.1") {
		t.Fatalf("off: %d %q", sb.code, out)
	}
	if strings.Contains(sb.fwRules(), "chain") {
		t.Errorf("an off table is defined:\n%s", sb.fwRules())
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw .* firewall=off result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	out = plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	if sb.code != 0 || !strings.Contains(out, "Firewall: off: no table, nothing to lift") {
		t.Errorf("release: %d %q", sb.code, out)
	}
}

func TestBreakglassHoldWhenNftIsMissingStillHolds(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	sb.script = func(r *fake.Runner) { r.Missing("nft") }
	out := sb.hold(t, "lab-sw", "console recovery", "lab-sw")
	if sb.code != 1 {
		t.Fatalf("exit %d, want 1: %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Break-glass HELD on lab-sw (192.168.1.1)",
		"Firewall: NOT APPLIED (nft is not installed)",
		"The server still completes the TCP handshake on tcp/49 for 192.168.1.1, so a device that falls back to its local accounts only when the server is unreachable",
		"WTI \"Fallback Local: On (Transport Failure)\", Junos \"authentication-order [ tacplus password ]\") will not.",
		"Fix: sudo apt-get install nftables, then tacctl config breakglass-firewall reject",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(sb.stderr(), "the firewall table was not loaded (nft is not installed): sudo apt-get install nftables, then tacctl config breakglass-firewall reject") {
		t.Errorf("stderr %q", sb.stderr())
	}
	// the hold stands: record, rendering, restart
	if o := sb.overrides(); !strings.Contains(o, "breakglass_hold:\n  lab-sw:\n    address: 192.168.1.1\n") {
		t.Errorf("no record:\n%s", o)
	}
	if strings.Contains(sb.renderedConfig(), `"192.168.0.0/16"`) || sb.restarts() != 1 {
		t.Errorf("restarts %d\n%s", sb.restarts(), sb.renderedConfig())
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw .* firewall=failed result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	// the red lines are red
	if raw := sb.out.String(); !strings.Contains(raw, "\x1b[0;31mFirewall: NOT APPLIED") {
		t.Errorf("not red: %q", raw)
	}

	// the release says the address may still be refused, and exits 1
	out = plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	if sb.code != 1 || !strings.Contains(out, "may still refuse the TCP connections of 192.168.1.1 on tcp/49") ||
		!strings.Contains(out, "Break-glass RELEASED") || !strings.Contains(out, "Fix: sudo apt-get install nftables") {
		t.Errorf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Error("the release did not stand")
	}
	// ... and the command that repairs it, once nft is there
	sb.script = nil
	sb.run("", []string{"config", "breakglass-firewall", "reject"})
	sb.expect(0, "", "")
}

func TestBreakglassHoldWhenNftFails(t *testing.T) {
	sb := engineerSandbox(t)
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-f"}, execx.Result{Code: 1, Stderr: []byte("Error: Could not process rule: No such file or directory\n")})
	}
	out := sb.hold(t, "lab-sw", "x", "lab-sw")
	if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft -f ") || !strings.Contains(out, "Could not process rule") ||
		!strings.Contains(out, "Fix: remove the cause above, then tacctl config breakglass-firewall reject") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Error("the hold did not stand")
	}
}

func TestBreakglassSeveralHoldsLoadOneTable(t *testing.T) {
	sb := engineerSandbox(t)
	sb.dev("", "add", "lab-rtr", "192.168.1.2", "--vendor", "cisco", "--no-host-key")
	sb.run("", []string{"config", "render"})
	holdTTY(t, sb, "lab-sw,lab-rtr\n")
	out := plain(sb.run("", []string{"breakglass", "hold", "lab-sw,lab-rtr", "--reason", "x"}))
	sb.tty = nil
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.1, 192.168.1.2 refused on tcp/49 (reject)") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if sb.nftLoads() != 1 || !strings.Contains(sb.fwRules(), "elements = { 192.168.1.1, 192.168.1.2 }") {
		t.Errorf("loads %d\n%s", sb.nftLoads(), sb.fwRules())
	}
	out = plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	if !strings.Contains(out, "Firewall: 192.168.1.1 accepted again on tcp/49; 1 other held address stays refused") {
		t.Errorf("release:\n%s", out)
	}
	out = plain(sb.run("", []string{"breakglass", "release", "lab-rtr"}))
	if !strings.Contains(out, "Firewall: 192.168.1.2 accepted again on tcp/49\n") {
		t.Errorf("last release:\n%s", out)
	}
}

func TestBreakglassMoveLoadsTheTableForTheNewAddress(t *testing.T) {
	sb := heldLab(t)
	out := plain(sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9", "--yes"}))
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.9 refused on tcp/49 (reject); 192.168.1.1 accepted again") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if r := sb.fwRules(); !strings.Contains(r, "192.168.1.9") || strings.Contains(r, "192.168.1.1 ") || strings.Contains(r, "192.168.1.1,") {
		t.Errorf("rules:\n%s", r)
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold-move device=lab-sw from=192\.168\.1\.1 to=192\.168\.1\.9 by=root firewall=reject result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	// with nft failing the move stands and says so
	sb.script = func(r *fake.Runner) { r.Missing("nft") }
	out = plain(sb.run("", []string{"device", "address", "lab-sw", "192.168.1.10", "--yes"}))
	if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft is not installed)") {
		t.Errorf("%d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.overrides(), "address: 192.168.1.10") {
		t.Errorf("the move did not stand:\n%s", sb.overrides())
	}
}

func TestBreakglassRestoreLoadsTheTable(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	sb.hold(t, "lab-sw", "x", "lab-sw")
	// the newest snapshot with no hold in it
	snaps, _ := filepath.Glob(sb.path("state", "backups", "2*"))
	id := ""
	for _, s := range snaps {
		if !strings.Contains(sb.read("state/backups/"+filepath.Base(s)+"/tacctl.yaml"), "breakglass_hold") {
			id = filepath.Base(s)
		}
	}
	if id == "" {
		t.Fatalf("no snapshot without the hold: %v", snaps)
	}
	out := plain(sb.run("y\n", []string{"backup", "restore", id}))
	if sb.code != 0 || sb.nftLoads() != 1 || strings.Contains(sb.fwRules(), "192.168.1.1") {
		t.Fatalf("restore: %d loads %d %q\n%s", sb.code, sb.nftLoads(), out, sb.fwRules())
	}
	// and back: a snapshot that has the hold loads it
	sb.hold(t, "lab-sw", "x", "lab-sw")
	sb.run("", []string{"backup", "list"})
	snaps, _ = filepath.Glob(sb.path("state", "backups", "2*"))
	withHold := ""
	for _, s := range snaps {
		if strings.Contains(sb.read("state/backups/"+filepath.Base(s)+"/tacctl.yaml"), "breakglass_hold") {
			withHold = filepath.Base(s)
		}
	}
	sb.run("", []string{"breakglass", "release", "lab-sw"})
	if withHold == "" {
		t.Skip("no snapshot with the hold")
	}
	out = plain(sb.run("y\n", []string{"backup", "restore", withHold}))
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.1 refused on tcp/49 (reject)") || !strings.Contains(sb.fwRules(), "192.168.1.1") {
		t.Errorf("restore with the hold: %d %q\n%s", sb.code, out, sb.fwRules())
	}
}

func TestServerListenLoadsTheTableWithTheNewPorts(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	out := plain(sb.run("", []string{"server", "listen", "tcp", ":4949"}))
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.1 refused on tcp/4949 (reject)") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.fwRules(), "tcp dport { 4949 } reject with tcp reset") {
		t.Errorf("rules:\n%s", sb.fwRules())
	}
	// a second listener adds its port
	out = plain(sb.run("", []string{"server", "listen", "--listener", "mgmt", "tcp", "192.0.2.10:49"}))
	if sb.code != 0 || !strings.Contains(sb.fwRules(), "tcp dport { 49, 4949 } reject with tcp reset") {
		t.Errorf("%d %q\n%s", sb.code, out, sb.fwRules())
	}
	// a failure to load is red and exits 1
	sb.script = func(r *fake.Runner) { r.Missing("nft") }
	out = plain(sb.run("", []string{"server", "listen", "--listener", "mgmt", "reset"}))
	if sb.code != 1 || !strings.Contains(out, "the table still matches the old ports") {
		t.Errorf("%d %q %q", sb.code, out, sb.stderr())
	}
	// nothing held and no table written: a listener change says nothing of it
	sb2 := engineerSandbox(t)
	out = plain(sb2.run("", []string{"server", "listen", "tcp", ":4949"}))
	if strings.Contains(out, "Firewall") || sb2.nftLoads() != 0 {
		t.Errorf("a listener change without holds touched the firewall: %q", out)
	}
}

// liveTable is what 'nft -j list table inet tacctl' says for 192.168.1.1
// refused with a reset on tcp/49.
const liveTable = `{"nftables": [{"metainfo": {"version": "1.0.9"}},
 {"table": {"family": "inet", "name": "tacctl", "handle": 1}},
 {"set": {"family": "inet", "name": "held4", "table": "tacctl", "type": "ipv4_addr", "handle": 2, "elem": ["192.168.1.1"]}},
 {"set": {"family": "inet", "name": "held6", "table": "tacctl", "type": "ipv6_addr", "handle": 3}},
 {"chain": {"family": "inet", "table": "tacctl", "name": "input", "handle": 1, "type": "filter", "hook": "input", "prio": -10, "policy": "accept"}},
 {"rule": {"family": "inet", "table": "tacctl", "chain": "input", "handle": 5, "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "@held4"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 49}},
   {"reject": {"type": "tcp reset"}}]}},
 {"rule": {"family": "inet", "table": "tacctl", "chain": "input", "handle": 6, "expr": [
   {"match": {"op": "==", "left": {"payload": {"protocol": "ip6", "field": "saddr"}}, "right": "@held6"}},
   {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 49}},
   {"reject": {"type": "tcp reset"}}]}}]}`

func TestBreakglassFirewallDriftInStatusValidateAndList(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	sb.run("", []string{"config", "render"})

	// in sync: green lines, nothing to fix
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-j", "list", "table", "inet", "tacctl"}, execx.Result{Stdout: []byte(liveTable)})
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"status"}, "Break-glass firewall: 192.168.1.1 refused on tcp/49 (reject)"},
		{[]string{"config", "validate"}, "Break-glass firewall: 192.168.1.1 refused on tcp/49 (reject)"},
		{[]string{"breakglass", "list"}, "Firewall: 192.168.1.1 refused on tcp/49 (reject)"},
	} {
		if got := plain(sb.run("", c.args)); !strings.Contains(got, c.want) {
			t.Errorf("%v lacks %q:\n%s", c.args, c.want, got)
		}
	}
	if sb.run("", []string{"config", "validate"}); sb.code != 0 {
		t.Errorf("validate exit %d with a table that is right", sb.code)
	}

	// the table is gone: red, the fix, and validate fails with a finding
	sb.script = func(r *fake.Runner) {
		r.Fail([]string{"nft", "-j", "list", "table"}, 1, "Error: No such file or directory")
	}
	status := plain(sb.run("", []string{"status"}))
	if !strings.Contains(status, "Break-glass firewall: the table inet tacctl differs from the holds and the setting: the table inet tacctl is missing, so the server still completes the TCP handshake of 192.168.1.1 on tcp/49 (tacctl config breakglass-firewall reject)") {
		t.Errorf("status:\n%s", status)
	}
	if raw := sb.run("", []string{"status"}); !strings.Contains(raw, "\x1b[0;31m    ") && !strings.Contains(raw, "\x1b[0;31mBreak-glass firewall") {
		t.Errorf("status line is not red: %q", raw)
	}
	out := plain(sb.run("", []string{"config", "validate"}))
	if sb.code != 1 || !strings.Contains(out, "Break-glass firewall: the table inet tacctl differs") || !strings.Contains(out, "(tacctl config breakglass-firewall reject)") {
		t.Errorf("validate: %d\n%s", sb.code, out)
	}
	js := sb.run("", []string{"config", "validate", "--json"})
	if f := validateJSONOf(t, js).find("breakglass_firewall"); f == nil || f.Level != levelError || f.Fix != "tacctl config breakglass-firewall reject" {
		t.Errorf("no finding: %s", js)
	}
	if got := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(got, "Firewall: the table inet tacctl differs") {
		t.Errorf("list:\n%s", got)
	}

	// an address that is held but missing from the set, a verdict that is wrong
	sb.write("state/tacctl.yaml", heldLabSw+"breakglass:\n  firewall: drop\n", 0o600)
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-j", "list", "table", "inet", "tacctl"}, execx.Result{Stdout: []byte(liveTable)})
	}
	out = plain(sb.run("", []string{"config", "validate"}))
	if sb.code != 1 || !strings.Contains(out, "the verdict for the set held4 is reject, not drop (breakglass.firewall is drop)") ||
		!strings.Contains(out, "tacctl config breakglass-firewall drop") {
		t.Errorf("verdict: %d\n%s", sb.code, out)
	}

	// not readable: said, not failed
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	sb.script = func(r *fake.Runner) {
		r.Fail([]string{"nft", "-j", "list", "table"}, 1, "netlink: Error: cannot open: Operation not permitted")
	}
	out = plain(sb.run("", []string{"config", "validate"}))
	if !strings.Contains(out, "Break-glass firewall: reject; the live table was not read (nft says: netlink: Error: cannot open: Operation not permitted)") ||
		strings.Contains(sb.stderr(), "firewall") {
		t.Errorf("unreadable: %d\n%s", sb.code, out)
	}
	if got := plain(sb.run("", []string{"status"})); !strings.Contains(got, "the live table was not read") {
		t.Errorf("status:\n%s", got)
	}
	// setting off with an address held: said, not a finding
	sb.write("state/tacctl.yaml", heldLabSw+"breakglass:\n  firewall: 'off'\n", 0o600)
	sb.script = func(r *fake.Runner) {
		r.Fail([]string{"nft", "-j", "list", "table"}, 1, "Error: No such file or directory")
	}
	out = plain(sb.run("", []string{"config", "validate"}))
	if !strings.Contains(out, "Break-glass firewall: off: the server still completes the TCP handshake of 192.168.1.1 on tcp/49") {
		t.Errorf("off:\n%s", out)
	}

	// nothing held and no table: nothing is shown
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	if got := plain(sb.run("", []string{"status"})); strings.Contains(got, "firewall") {
		t.Errorf("status without holds:\n%s", got)
	}
	// ... unless a table is left that nothing asks for
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-j", "list", "table", "inet", "tacctl"}, execx.Result{Stdout: []byte(liveTable)})
	}
	if got := plain(sb.run("", []string{"status"})); !strings.Contains(got, "192.168.1.1 is in the set held4 but not held") {
		t.Errorf("a stale table:\n%s", got)
	}
}

func TestBreakglassListJSONNamesTheSetting(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw+"breakglass:\n  firewall: drop\n", 0o600)
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"breakglass", "list", "--json"})), &js); err != nil || len(js) != 1 || js[0].Firewall != "drop" {
		t.Errorf("%v %+v", err, js)
	}
}

func TestBreakglassFirewallLinesAreForTheSuperuserOnly(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	for _, args := range [][]string{{"status"}, {"breakglass", "list"}, {"config", "validate"}} {
		if got := sb.asEngineer("", args...); strings.Contains(got, "firewall") || strings.Contains(sb.stderr(), "nft") {
			t.Errorf("%v shows the table to an engineer:\n%s", args, got)
		}
	}
	if sb.runner.Called("nft") {
		t.Error("an engineer's command ran nft")
	}
}
