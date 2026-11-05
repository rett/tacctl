package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// The break-glass firewall on a host without nft (0.2.24): the table is a
// failure only where it is to refuse something (an address held, the setting
// not off) or where a table tacctl loaded earlier may still be live. A host
// that has no nft and asks for nothing sees no red line and no exit 1.

const redMark = "\x1b[0;31m"

// noNft is the script of a host without nft.
func noNft(r *fake.Runner) { r.Missing("nft") }

// quiet fails the test when the last command was red, wrote an error, said
// the firewall was not applied or warned of it, or exited with anything but 0.
func (sb *sandbox) quiet(t *testing.T, what string) {
	t.Helper()
	all := plain(sb.out.String()) + sb.stderr()
	if sb.code != 0 || strings.Contains(sb.out.String(), redMark+"Firewall") || strings.Contains(all, "[ERROR]") || strings.Contains(all, "NOT APPLIED") || strings.Contains(all, "Break-glass firewall:") {
		t.Fatalf("%s: exit %d, stdout %q, stderr %q", what, sb.code, plain(sb.out.String()), sb.stderr())
	}
}

func TestBreakglassFirewallOffWithoutNftIsNoFailure(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	sb.script = noNft
	// the setting command, nothing held, twice
	for i := 1; i <= 2; i++ {
		out := plain(sb.run("", []string{"config", "breakglass-firewall", "off"}))
		sb.quiet(t, "off, nothing held")
		if !strings.Contains(out, "Firewall: off: no table is loaded.") || strings.Contains(out, "next hold needs it") || strings.Contains(out, "apt-get") {
			t.Errorf("off %d: %q", i, out)
		}
	}
	if sb.fileExists("state/breakglass-firewall.nft") {
		t.Error("a host that cannot load the table got a rules file")
	}
	// a hold and its release, the setting off
	out := sb.hold(t, "lab-sw", "console recovery", "lab-sw")
	sb.quiet(t, "hold with off")
	if !strings.Contains(out, "Firewall: off: the server still completes the TCP handshake on tcp/49 for 192.168.1.1") {
		t.Errorf("hold:\n%s", out)
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw .* firewall=off result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	// the setting again, with the hold standing
	out = plain(sb.run("", []string{"config", "breakglass-firewall", "off"}))
	sb.quiet(t, "off with a hold")
	if !strings.Contains(out, "Firewall: off: no table is loaded (nft is not installed); the server completes the TCP handshake of a held address") {
		t.Errorf("off with a hold: %q", out)
	}
	sb.run("", []string{"breakglass", "release", "lab-sw"})
	sb.quiet(t, "release with off")
	// a listener change with the hold standing and the setting off
	sb.write("state/tacctl.yaml", heldLabSw+"breakglass:\n  firewall: 'off'\n", 0o600)
	sb.run("", []string{"server", "listen", "tcp", ":4949"})
	sb.quiet(t, "server listen with off")
}

func TestBreakglassFirewallNothingHeldWithoutNftIsNoFailure(t *testing.T) {
	sb := engineerSandbox(t)
	sb.script = noNft
	for i := 1; i <= 2; i++ {
		out := plain(sb.run("", []string{"config", "breakglass-firewall", "drop"}))
		sb.quiet(t, "drop, nothing held")
		if !strings.Contains(out, "nothing is held and nft is not installed") {
			t.Errorf("drop %d: %q", i, out)
		}
	}
	// a listener change with nothing held
	sb.run("", []string{"server", "listen", "tcp", ":4949"})
	sb.quiet(t, "server listen, nothing held")

	// the release of the last hold: nothing was ever loaded, so nothing is
	// left to lift
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	out := plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	sb.quiet(t, "release of the last hold")
	if !strings.Contains(out, "Break-glass RELEASED on lab-sw") || strings.Contains(out, "Firewall:") {
		t.Errorf("release: %q", out)
	}
	// the word is the setting that was applied (the hand-written file has none: reject)
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass release device=lab-sw .* firewall=reject result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
}

// A table that was loaded (the boot unit says so) may outlive nftables: the
// setting command is red until nft is back, and says why.
func TestBreakglassFirewallAfterNftWasRemoved(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "breakglass-firewall", "drop"})
	sb.expect(0, "", "")
	if !sb.fileExists("systemd/tacctl-breakglass-firewall.service") {
		t.Skip("the sandbox puts the unit elsewhere")
	}
	sb.script = noNft
	out := plain(sb.run("", []string{"config", "breakglass-firewall", "drop"}))
	if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft is not installed, and a table loaded earlier may still be in the kernel)") ||
		!strings.Contains(sb.stderr(), "sudo apt-get install nftables, then tacctl config breakglass-firewall drop") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	// turned off with nft, the unit goes, and nothing is red without it
	sb.script = nil
	sb.run("", []string{"config", "breakglass-firewall", "off"})
	sb.expect(0, "", "")
	sb.script = noNft
	sb.run("", []string{"config", "breakglass-firewall", "off"})
	sb.quiet(t, "off after the unit was removed")
}

// With nft installed and failing, nothing held: the real reason, not "nft is
// not installed", and the command is red.
func TestBreakglassFirewallSettingWhenNftFailsWithNothingHeld(t *testing.T) {
	sb := engineerSandbox(t)
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-f"}, execx.Result{Code: 1, Stderr: []byte("Error: Operation not permitted\n")})
	}
	for _, v := range []string{"drop", "off"} {
		out := plain(sb.run("", []string{"config", "breakglass-firewall", v}))
		if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft -f ") || !strings.Contains(out, "Operation not permitted") ||
			strings.Contains(out, "nft is not installed") || strings.Contains(sb.stderr(), "apt-get") {
			t.Errorf("%s: %d %q %q", v, sb.code, out, sb.stderr())
		}
		if !strings.Contains(sb.stderr(), "then tacctl config breakglass-firewall "+v) {
			t.Errorf("%s: no fix: %q", v, sb.stderr())
		}
	}
}

// The boot unit that cannot be enabled is a warning, not a failure: the table
// is loaded.
func TestBreakglassFirewallBootUnitFailureIsAWarning(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", heldLabSw, 0o600)
	sb.script = func(r *fake.Runner) {
		r.On([]string{"systemctl", "enable"}, execx.Result{Code: 1})
	}
	out := plain(sb.run("", []string{"config", "breakglass-firewall", "reject"}))
	if sb.code != 0 || !strings.Contains(out, "Firewall: 192.168.1.1 refused on tcp/49 (reject)") ||
		!strings.Contains(out, "[WARN] Break-glass firewall: the boot unit tacctl-breakglass-firewall.service could not be installed") ||
		!strings.Contains(out, "lost at the next reboot") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
}

// A restore that empties the holds and cannot load the table: the risk is the
// addresses that were held before, not the (none) held now.
func TestBreakglassRestoreThatEmptiesTheHoldsAndFails(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	sb.hold(t, "lab-sw", "x", "lab-sw")
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
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-f"}, execx.Result{Code: 1, Stderr: []byte("Error: Operation not permitted\n")})
	}
	out := plain(sb.run("y\n", []string{"backup", "restore", id}))
	if sb.code != 1 || !strings.Contains(out, "Firewall: NOT APPLIED (nft -f ") ||
		!strings.Contains(out, "No address is held after the restore, but the table inet tacctl could not be updated: it may still refuse the TCP connections of the addresses that were held before on tcp/49.") {
		t.Fatalf("%d %q %q", sb.code, out, sb.stderr())
	}
	if strings.Contains(out, "for ,") || strings.Contains(out, "for  ") || strings.Contains(out, "completes the TCP handshake") {
		t.Errorf("hold wording with an empty list:\n%s", out)
	}
}

// A replacement of a held device whose table cannot be loaded: the record is
// gone, so the way out is the setting command, not 'breakglass release'.
func TestDeviceReplaceOfAHeldDeviceWhenTheTableIsNotLoaded(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	sb.hold(t, "lab-sw", "x", "lab-sw")
	sb.dev("", "clone", "lab-sw", "lab-sw2", "--staging", "192.0.2.77")
	sb.expect(0, "", "")
	sb.script = func(r *fake.Runner) {
		r.On([]string{"nft", "-f"}, execx.Result{Code: 1, Stderr: []byte("Error: Operation not permitted\n")})
	}
	sb.dev("", "rename", "lab-sw2", "lab-sw", "--replace", "--yes")
	all := sb.stderr() + plain(sb.out.String())
	if sb.code != 1 || !strings.Contains(all, "the record is removed and the files are rendered without the hold, but the firewall table was not loaded") ||
		!strings.Contains(all, "then tacctl config breakglass-firewall reject") {
		t.Fatalf("%d %q", sb.code, all)
	}
	if strings.Contains(all, "rendered files are as they were") || strings.Contains(all, "tacctl breakglass release lab-sw") {
		t.Errorf("stale advice:\n%s", all)
	}
}
