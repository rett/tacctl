package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device address' on a held device moves the hold (docs/plans/0.2.14-plan.md
// D175), on the engineer sandbox: lab-sw at 192.168.1.1 (scope lab,
// 192.168/16) is held, the address it moves to is 192.168.1.9.

// heldLab is a sandbox rendered once, with lab-sw held.
func heldLab(t *testing.T) *sandbox {
	t.Helper()
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	if out := sb.hold(t, "lab-sw", "console recovery after a failed paste", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold: %d %q %q", sb.code, out, sb.stderr())
	}
	return sb
}

// carvedPrefixes are the prefixes 192.168.0.0/16 is rendered as without addr.
func carvedPrefixes(addr string) []string {
	return cidr.Subtract([]string{"192.168.0.0/16"}, []string{addr})
}

// The rendered file carves addr out of 192.168.0.0/16 and answers the other
// address whole again (it is inside the prefixes of the carve of addr).
func checkCarvedAt(t *testing.T, cfg, addr, other string) {
	t.Helper()
	if !strings.Contains(cfg, "# break-glass held: "+addr+" (device lab-sw)") {
		t.Errorf("the rendered file does not name the hold at %s:\n%s", addr, cfg)
	}
	if strings.Contains(cfg, "# break-glass held: "+other+" ") {
		t.Errorf("the rendered file still names the hold at %s:\n%s", other, cfg)
	}
	want, gone := carvedPrefixes(addr), carvedPrefixes(other)
	for _, p := range want {
		if !strings.Contains(cfg, `"`+p+`"`) {
			t.Errorf("the rendered file lacks %s (192.168.0.0/16 without %s)", p, addr)
		}
	}
	for _, p := range gone {
		if !strings.Contains(strings.Join(want, " "), p) && strings.Contains(cfg, `"`+p+`"`) {
			t.Errorf("the rendered file still has %s (192.168.0.0/16 without %s)", p, other)
		}
	}
}

func TestBreakglassDeviceAddressMovesTheHold(t *testing.T) {
	sb := heldLab(t)
	cfg0 := sb.renderedConfig()
	checkCarvedAt(t, cfg0, "192.168.1.1", "192.168.1.9")
	rec := sb.overrides()

	out := plain(sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9", "-y"}))
	if sb.code != 0 {
		t.Fatalf("address: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Device 'lab-sw' address set to 192.168.1.9.",
		"Break-glass hold MOVED on lab-sw from 192.168.1.1 to 192.168.1.9 (held since ",
		"Reason:   console recovery after a failed paste",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.9; tacacs restarted.",
		"Old address: 192.168.1.1 is answered again (scope 'lab').",
		"Carved:   only 192.168.1.9, the address registered for lab-sw.",
		"Held now: lab-sw (", "When done: tacctl breakglass release lab-sw",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report lacks %q:\n%s", want, out)
		}
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts for the move, want 1", n)
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold-move device=lab-sw from=192\.168\.1\.1 to=192\.168\.1\.9 by=root`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	// The registry and the record are on the new address; the record keeps
	// its reason and its time.
	if d := sb.devices(); !strings.Contains(d, "192.168.1.9") || strings.Contains(d, "192.168.1.1\n") {
		t.Errorf("devices.yaml:\n%s", d)
	}
	if o := sb.overrides(); !strings.Contains(o, "  lab-sw:\n    address: 192.168.1.9\n") || strings.Contains(o, "192.168.1.1\n") ||
		strings.ReplaceAll(o, "192.168.1.9", "192.168.1.1") != rec {
		t.Errorf("tacctl.yaml:\n%s\nwas:\n%s", o, rec)
	}
	checkCarvedAt(t, sb.renderedConfig(), "192.168.1.9", "192.168.1.1")
	if list := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(list, "192.168.1.9") || strings.Contains(list, "orphan") {
		t.Errorf("list:\n%s", list)
	}
	if got := plain(sb.run("", []string{"device", "show", "lab-sw"})); !strings.Contains(got, "Break-glass:  HELD since ") ||
		!strings.Contains(got, "the server does not answer 192.168.1.9") {
		t.Errorf("device show:\n%s", got)
	}
	// The release gives the files back as they were before the hold's move.
	sb.run("", []string{"breakglass", "release", "lab-sw"})
	if sb.code != 0 || strings.Contains(sb.overrides(), "breakglass_hold") || strings.Contains(sb.renderedConfig(), "break-glass") {
		t.Errorf("release: %d %q\n%s", sb.code, sb.stderr(), sb.overrides())
	}
}

// Without -y the line asks; only a yes goes on.
func TestBreakglassDeviceAddressAsksBeforeMoving(t *testing.T) {
	sb := heldLab(t)
	devs, rec, cfg := sb.devices(), sb.overrides(), sb.renderedConfig()
	for _, answer := range []string{"n\n", "\n", ""} {
		out := plain(sb.run(answer, []string{"device", "address", "lab-sw", "192.168.1.9"}))
		if sb.code != 0 || !strings.Contains(out, "Aborted.") {
			t.Errorf("answer %q: %d %q %q", answer, sb.code, out, sb.stderr())
		}
		if sb.devices() != devs || sb.overrides() != rec || sb.renderedConfig() != cfg || sb.restarts() != 0 {
			t.Errorf("answer %q changed something", answer)
		}
	}
	if w := sb.stderr(); strings.Contains(w, "address set") {
		t.Errorf("stderr %q", w)
	}
	sb.run("y\n", []string{"device", "address", "lab-sw", "192.168.1.9"})
	if sb.code != 0 || !strings.Contains(sb.devices(), "192.168.1.9") || !strings.Contains(sb.overrides(), "address: 192.168.1.9\n") {
		t.Fatalf("yes: %d %q\n%s", sb.code, sb.stderr(), sb.overrides())
	}
	if sb.restarts() != 1 {
		t.Errorf("%d restarts, want 1", sb.restarts())
	}
}

// The new address passes what a new hold passes, and a refusal changes
// nothing.
func TestBreakglassDeviceAddressRefusesWhatAHoldRefuses(t *testing.T) {
	for _, c := range []struct {
		name, addr, want string
		prepare          func(sb *sandbox)
	}{
		{"loopback", "127.0.0.9", "127.0.0.9 is a loopback address", nil},
		{"listener", "192.168.1.9", "192.168.1.9 is where the tacacs listener extra binds", func(sb *sandbox) {
			sb.write("state/tacctl.yaml", sb.overrides()+"listeners:\n  tacacs:\n    extra:\n      network: tcp\n      address: 192.168.1.9:4949\n", 0o600)
		}},
		{"enrolled host", "192.0.2.10", "192.0.2.10 is the address of the enrolled host 'web1'", nil},
		{"held by another record", "10.99.0.1", "Address 10.99.0.1 is already held, on 'prod-sw'", func(sb *sandbox) {
			if out := sb.hold(t, "prod-sw", "x", "prod-sw"); sb.code != 0 {
				t.Fatalf("hold prod-sw: %q %q", out, sb.stderr())
			}
		}},
		{"not covered by a scope", "100.64.0.9", "No scope covers 100.64.0.9 (tacctl scope lookup 100.64.0.9)", nil},
		{"registered to another device", "192.168.1.2", "192.168.1.2 is already registered as 'lab-rtr'", func(sb *sandbox) {
			sb.dev("", "add", "lab-rtr", "192.168.1.2", "--no-host-key")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := heldLab(t)
			if c.prepare != nil {
				c.prepare(sb)
			}
			devs, rec, cfg := sb.devices(), sb.overrides(), sb.renderedConfig()
			out := plain(sb.run("y\n", []string{"device", "address", "lab-sw", c.addr, "-y"}))
			if sb.code != 1 || !strings.Contains(sb.stderr(), c.want) || !strings.Contains(sb.stderr(), "Nothing was changed.") {
				t.Errorf("exit %d, stderr %q, want %q and 'Nothing was changed.'\n%s", sb.code, sb.stderr(), c.want, out)
			}
			if sb.devices() != devs || sb.overrides() != rec || sb.renderedConfig() != cfg || sb.restarts() != 0 {
				t.Errorf("a refused move changed something (%d restarts)", sb.restarts())
			}
		})
	}
}

// A move is the superuser's, and --apply does not go with it; a change to
// the address it already has changes nothing.
func TestBreakglassDeviceAddressOtherRefusals(t *testing.T) {
	sb := heldLab(t)
	devs, rec, cfg := sb.devices(), sb.overrides(), sb.renderedConfig()

	sb.asEngineer("", "device", "address", "lab-sw", "192.168.1.3", "-y")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "break-glass is held on lab-sw: moving its address moves the hold, which is the superuser's. Nothing was changed.") {
		t.Errorf("engineer: %d %q", sb.code, sb.stderr())
	}
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9", "--apply", "-y"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "--apply does not go with a held device") {
		t.Errorf("--apply: %d %q", sb.code, sb.stderr())
	}
	sb.run("", []string{"device", "address", "lab-sw", "clear"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The address is required") {
		t.Errorf("clear: %d %q", sb.code, sb.stderr())
	}
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9.9", "-y"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Invalid address") {
		t.Errorf("invalid: %d %q", sb.code, sb.stderr())
	}
	if sb.devices() != devs || sb.overrides() != rec || sb.renderedConfig() != cfg {
		t.Error("a refusal changed something")
	}
	// Its own address: nothing moves, nothing restarts.
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.1"})
	if sb.code != 0 || sb.overrides() != rec || sb.restarts() != 0 {
		t.Errorf("same address: %d %q", sb.code, sb.stderr())
	}
	// An orphan record is not a hold on the device: the address moves
	// as for any device. (The device is registered at an address other
	// than the record's.)
	sb.dev("", "address", "prod-sw", "10.99.0.5")
	if sb.code != 0 {
		t.Errorf("an unheld device: %d %q", sb.code, sb.stderr())
	}
}

// A restart that fails leaves the registry and the record on the new
// address, says so and exits 1.
func TestBreakglassDeviceAddressSaysWhenTheRestartFailed(t *testing.T) {
	sb := heldLab(t)
	sb.script = func(r *fake.Runner) { r.On([]string{"systemctl", "restart"}, execx.Result{Code: 1}) }

	out := plain(sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9", "-y"}))
	if sb.code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", sb.code, out, sb.stderr())
	}
	want := "Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.9; " +
		"tacacs NOT restarted: the running server still answers 192.168.1.9 and does not answer 192.168.1.1 until it is restarted (run: sudo systemctl restart tacquito)."
	if !strings.Contains(out, want) || strings.Contains(out, "tacacs restarted") {
		t.Errorf("report:\n%s", out)
	}
	if strings.Contains(out, "is answered again") {
		t.Errorf("the report says the old address is answered although the restart failed:\n%s", out)
	}
	if !strings.Contains(sb.stderr(), "the move is not in force until the backend named under Rendered is restarted") {
		t.Errorf("stderr %q", sb.stderr())
	}
	if !strings.Contains(sb.devices(), "192.168.1.9") || !strings.Contains(sb.overrides(), "  lab-sw:\n    address: 192.168.1.9\n") {
		t.Errorf("the registry or the record was not kept:\n%s\n%s", sb.devices(), sb.overrides())
	}
	checkCarvedAt(t, sb.renderedConfig(), "192.168.1.9", "192.168.1.1")
}

// The registry is not part of StoreApply's rollback: a render that fails
// after it was written must not leave it on an address the record is not at.
func TestBreakglassDeviceAddressRenderFailureKeepsRegistryAndRecordTogether(t *testing.T) {
	sb := heldLab(t)
	devs, rec, cfg := sb.devices(), sb.overrides(), sb.renderedConfig()
	// The render cannot replace its file: the directory is not writable.
	dir := sb.path("etc")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if f, err := os.CreateTemp(dir, "probe"); err == nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		t.Skip("the directory stays writable (running as root?)")
	}
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9", "-y"})
	_ = os.Chmod(dir, 0o700)
	if sb.code != 1 || !strings.Contains(sb.stderr(), "could not be rendered") {
		t.Fatalf("exit %d, want 1 and a render failure: %q", sb.code, sb.stderr())
	}
	if sb.devices() != devs || sb.overrides() != rec || sb.renderedConfig() != cfg || sb.restarts() != 0 {
		t.Errorf("the failed move changed something:\n%s\n%s", sb.devices(), sb.overrides())
	}
}

// An import does not move a hold: it stays refused, and says where the
// move is.
func TestBreakglassImportStillRefusesToMoveAHeldDevice(t *testing.T) {
	sb := heldLab(t)
	exported := sb.dev("", "export")
	devs, rec := sb.devices(), sb.overrides()
	sb.run(strings.Replace(exported, "192.168.1.1", "192.168.1.9", 1), []string{"device", "import", "-y", "-"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "break-glass is held on lab-sw: an import neither removes it nor moves it to another address; move the hold with 'tacctl device address lab-sw <address>'") ||
		!strings.Contains(sb.stderr(), "Nothing was changed.") {
		t.Errorf("import: %d %q", sb.code, sb.stderr())
	}
	if sb.devices() != devs || sb.overrides() != rec {
		t.Error("a refused import changed something")
	}
}
