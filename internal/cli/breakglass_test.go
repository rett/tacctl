package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/testpty"
)

// The break-glass hold (docs/plans/0.2.5-plan.md D121-D126) in-process, on
// the engineer sandbox: prod-sw at 10.99.0.1 (scope prod, 10/8) and lab-sw
// at 192.168.1.1 (scope lab, 192.168/16, bob's own).

// holdTTY gives the sandbox a terminal and types line on it.
func holdTTY(t *testing.T, sb *sandbox, line string) {
	t.Helper()
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	sb.tty = slave
	if _, err := master.WriteString(line); err != nil {
		t.Fatal(err)
	}
}

func (sb *sandbox) restarts() int { return sb.runner.Count("systemctl", "restart") }

func (sb *sandbox) renderedConfig() string { return sb.read("etc/tacquito.yaml") }

// hold runs 'breakglass hold <device> --reason <reason>' typing the device
// name back (or typed instead of it).
func (sb *sandbox) hold(t *testing.T, device, reason, typed string) string {
	t.Helper()
	sb.tty = nil
	holdTTY(t, sb, typed+"\n")
	out := plain(sb.run("", []string{"breakglass", "hold", device, "--reason", reason}))
	sb.tty = nil
	return out
}

func TestBreakglassHoldRoundTrip(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	// Render once so the files exist; what a hold must give back is this.
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	if strings.Contains(original, "break-glass") {
		t.Fatal("a render without a hold names one")
	}

	// A reason is required, a terminal is required, the name must be typed.
	sb.run("", []string{"breakglass", "hold", "lab-sw"})
	sb.expect(1, "", "--reason is required")
	sb.run("", []string{"breakglass", "hold", "lab-sw", "--reason", "x"})
	sb.expect(1, "", "No terminal to confirm on")
	out := sb.hold(t, "lab-sw", "console recovery after a failed paste", "lab-swx")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The name typed back is not 'lab-sw'. Nothing was changed.") {
		t.Fatalf("a wrong name: %d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(out, "Hold break-glass on lab-sw (192.168.1.1, scope lab, cisco)?") ||
		!strings.Contains(out, "This is for one device in exceptional circumstances.") ||
		!strings.Contains(out, "lab-admin [admin]") || !strings.Contains(out, "Nothing releases it but 'tacctl breakglass release lab-sw'.") {
		t.Errorf("the prompt:\n%s", out)
	}
	if o := sb.overrides(); strings.Contains(o, "breakglass_hold") || sb.restarts() != 0 {
		t.Fatalf("a refused hold changed something (restarts %d):\n%s", sb.restarts(), o)
	}

	// The hold: one restart, the record, the carved file.
	out = sb.hold(t, "lab-sw", "console recovery after a failed paste", "lab-sw")
	if sb.code != 0 {
		t.Fatalf("hold: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Break-glass HELD on lab-sw (192.168.1.1) since ", " by root.",
		"Reason:   console recovery after a failed paste",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.1; tacacs restarted.",
		"ssh: log in as a local account;", "the CONSOLE list is local",
		"Held now: lab-sw (under 1 min, root)", "When done: tacctl breakglass release lab-sw",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hold report lacks %q:\n%s", want, out)
		}
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts for the hold, want 1", n)
	}
	if !sb.runner.CalledRegexp(`logger.* -p auth\.info breakglass hold device=lab-sw addr=192\.168\.1\.1 reason="console recovery after a failed paste" by=root`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	o := sb.overrides()
	if !strings.Contains(o, "breakglass_hold:\n  lab-sw:\n    address: 192.168.1.1\n") || !strings.Contains(o, "reason: console recovery after a failed paste\n") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	cfg := sb.renderedConfig()
	if strings.Contains(cfg, `"192.168.0.0/16"`) || !strings.Contains(cfg, "# break-glass held: 192.168.1.1 (device lab-sw)") {
		t.Errorf("the rendered file:\n%s", cfg)
	}
	if strings.Contains(cfg, "console recovery") {
		t.Error("the reason is in the rendered file")
	}
	if !strings.Contains(sb.store(), "192.168.0.0/16") {
		t.Error("the store was changed")
	}

	// Held twice is refused with the record; another device may be held.
	sb.hold(t, "lab-sw", "again", "lab-sw")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Break-glass is already held on 'lab-sw' (192.168.1.1)") {
		t.Errorf("held twice: %d %q", sb.code, sb.stderr())
	}

	// Every display says so.
	list := plain(sb.run("", []string{"breakglass", "list"}))
	for _, want := range []string{"Break-glass holds (1)", "lab-sw", "192.168.1.1", "lab", "console recovery after a failed paste"} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q:\n%s", want, list)
		}
	}
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"breakglass", "list", "--json"})), &js); err != nil || len(js) != 1 ||
		js[0].Device != "lab-sw" || js[0].Scope != "lab" || !js[0].Registered || !js[0].Covered || js[0].By != "root" {
		t.Errorf("list --json: %v %+v", err, js)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"device", "show", "lab-sw"}, "Break-glass:  HELD since "},
		{[]string{"device", "show", "lab-sw"}, "; the server does not answer 192.168.1.1"},
		{[]string{"device", "list"}, "BREAK-GLASS"},
		{[]string{"device", "list"}, "1 device(s) held for break-glass: tacctl breakglass list"},
		{[]string{"status"}, "Break-glass:        HELD on lab-sw (192.168.1.1) since "},
		{[]string{"scope", "show", "lab"}, "Break-glass held: lab-sw (192.168.1.1) since "},
		{[]string{"scope", "list"}, "(1 break-glass hold)"},
		{[]string{"scope", "routing"}, "break-glass held: 192.168.1.1 (lab-sw) is carved out of 192.168.0.0/16 (lab) and answered by nothing: tacctl breakglass list"},
		{[]string{"scope", "lookup", "192.168.1.1"}, "-> scope 'lab' (via prefix 192.168.0.0/16), NOT ANSWERED: break-glass held on lab-sw since "},
		{[]string{"scope", "lookup", "192.168.0.0/16"}, "Break-glass held inside this range: 192.168.1.1 (lab-sw)"},
		{[]string{"config", "validate"}, "Break-glass hold:    lab-sw (192.168.1.1) held since "},
	} {
		got := plain(sb.run("", c.args))
		if !strings.Contains(got, c.want) {
			t.Errorf("%v lacks %q:\n%s", c.args, c.want, got)
		}
	}
	// An address that is not held is looked up as before.
	if got := plain(sb.run("", []string{"scope", "lookup", "192.168.1.2"})); strings.Contains(got, "NOT ANSWERED") {
		t.Errorf("another address: %s", got)
	}
	var dj []deviceJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"device", "list", "--json"})), &dj); err != nil {
		t.Fatal(err)
	}
	for _, d := range dj {
		if (d.Name == "lab-sw") != (d.Breakglass != nil) || (d.Breakglass != nil && (!d.Breakglass.Held || d.Breakglass.Address != "192.168.1.1")) {
			t.Errorf("device list --json: %s %+v", d.Name, d.Breakglass)
		}
	}

	// The held device cannot be moved or removed; a rename follows.
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.9"})
	sb.expect(1, "", "break-glass is held on lab-sw: release it first (tacctl breakglass release lab-sw)")
	sb.run("", []string{"device", "remove", "lab-sw", "-y"})
	sb.expect(1, "", "break-glass is held on lab-sw: release it first")
	sb.run("", []string{"device", "remove", "--all", "-y"})
	sb.expect(1, "", "break-glass is held on lab-sw")
	if !strings.Contains(sb.devices(), "lab-sw") {
		t.Error("a refused remove removed it")
	}
	before := sb.restarts()
	sb.run("", []string{"device", "rename", "lab-sw", "lab-core"})
	sb.expect(0, "renamed to 'lab-core'", "")
	if o := sb.overrides(); !strings.Contains(o, "  lab-core:\n    address: 192.168.1.1\n") || strings.Contains(o, "  lab-sw:\n") {
		t.Errorf("the rename did not carry the record:\n%s", o)
	}
	if sb.restarts() != before {
		t.Error("a rename restarted a backend")
	}
	if cfg := sb.renderedConfig(); !strings.Contains(cfg, "(device lab-core)") {
		t.Errorf("the rendered comment does not follow the rename:\n%s", cfg)
	}

	// Release: one restart, the original bytes.
	sb.run("", []string{"breakglass", "release", "nosuch"})
	sb.expect(1, "", "Break-glass is not held on 'nosuch'. Held now: lab-core")
	out = plain(sb.run("", []string{"breakglass", "release", "lab-core"}))
	if sb.code != 0 {
		t.Fatalf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{"Break-glass RELEASED on lab-core (192.168.1.1): held ", "(console recovery after a failed paste).",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; tacacs restarted.",
		"Check:    tacctl device config pull lab-core --diff (aaa: ok), then a new ssh login as yourself.", "Still held: none"} {
		if !strings.Contains(out, want) {
			t.Errorf("release report lacks %q:\n%s", want, out)
		}
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts for the release, want 1", n)
	}
	if got := sb.renderedConfig(); got != original {
		t.Errorf("hold then release did not restore the rendering:\n%s", got)
	}
	if o := sb.overrides(); strings.Contains(o, "breakglass_hold") {
		t.Errorf("the record is left:\n%s", o)
	}
	if !sb.runner.CalledRegexp(`logger.* -p auth\.info breakglass release device=lab-core addr=192\.168\.1\.1 held=\S+ by=root`) {
		t.Errorf("no release audit line: %v", sb.runner.Argvs())
	}
	if out := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(out, "None held") {
		t.Errorf("list after the release: %s", out)
	}
	if out := plain(sb.run("", []string{"status"})); !strings.Contains(out, "Break-glass:        none held") {
		t.Errorf("status after the release: %s", out)
	}
}

// Every refusal of D122, in its order, changes nothing.
func TestBreakglassHoldRefusals(t *testing.T) {
	sb := engineerSandbox(t)
	sb.dev("", "add", "nowhere", "100.64.0.9", "--no-host-key")
	sb.dev("", "add", "loop", "127.0.0.1", "--no-host-key")
	sb.dev("", "add", "noaddr", "--no-host-key", "--hostname", "noaddr.example.net")
	sb.write("state/linux-hosts", "web1|root@192.168.1.10||lab|192.0.2.1|\n", 0o600)
	sb.dev("", "add", "same-as-host", "192.168.1.10", "--no-host-key", "--allow-generic")
	sb.run("", []string{"config", "render"})
	for _, c := range []struct{ device, want string }{
		{"nosuch", "Device 'nosuch' not found"},
		{"web1", "is an enrolled host, not a registered device"},
		{"nowhere", "'nowhere' is already unanswered: no scope covers 100.64.0.9 (tacctl scope lookup 100.64.0.9)"},
		{"loop", "127.0.0.1 is a loopback address"},
		{"same-as-host", "is the address of the enrolled host 'web1'"},
	} {
		holdTTY(t, sb, c.device+"\n")
		sb.run("", []string{"breakglass", "hold", c.device, "--reason", "x"})
		sb.tty = nil
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.want) {
			t.Errorf("%s: exit %d %q, want %q", c.device, sb.code, sb.stderr(), c.want)
		}
	}
	// A device with no address.
	if sb.devices(); strings.Contains(sb.devices(), "noaddr") {
		holdTTY(t, sb, "noaddr\n")
		sb.run("", []string{"breakglass", "hold", "noaddr", "--reason", "x"})
		sb.tty = nil
		if sb.code != 1 || !strings.Contains(sb.stderr(), "has no address") {
			t.Errorf("noaddr: %d %q", sb.code, sb.stderr())
		}
	}
	// A listener's address.
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nlisteners:\n  tacacs:\n    extra:\n      network: tcp\n      address: 192.168.1.1:4949\n", 0o600)
	holdTTY(t, sb, "lab-sw\n")
	sb.run("", []string{"breakglass", "hold", "lab-sw", "--reason", "x"})
	sb.tty = nil
	if sb.code != 1 || !strings.Contains(sb.stderr(), "192.168.1.1 is where the tacacs listener extra binds") {
		t.Errorf("listener: %d %q", sb.code, sb.stderr())
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Error("a refusal wrote a record")
	}
	// An over-long reason, and a reason that is not text.
	sb.run("", []string{"breakglass", "hold", "lab-sw", "--reason", strings.Repeat("x", 257)})
	sb.expect(1, "", "--reason is limited to 256 characters")
	sb.run("", []string{"breakglass", "hold", "lab-sw", "--reason", "  "})
	sb.expect(1, "", "--reason must not be empty")
}

// The engineer reads the holds of their own scopes; hold and release are
// the superuser's.
func TestBreakglassEngineerTier(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	for _, name := range []string{"lab-sw", "prod-sw"} {
		out := sb.hold(t, name, "why "+name, name)
		if sb.code != 0 {
			t.Fatalf("hold %s: %d %q %q", name, sb.code, out, sb.stderr())
		}
	}
	before := sb.overrides()
	// hold and release: the gate.
	for _, args := range [][]string{{"breakglass", "hold", "lab-sw", "--reason", "x"}, {"breakglass", "release", "lab-sw"}, {"breakglass"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if sb.overrides() != before {
		t.Error("an engineer's refusal changed tacctl.yaml")
	}
	// list: their own scope only, read-only.
	out := sb.asEngineer("", "breakglass", "list")
	if sb.code != 0 || !strings.Contains(out, "lab-sw") || strings.Contains(out, "prod-sw") {
		t.Errorf("engineer list: %d %q", sb.code, out)
	}
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.asEngineer("", "breakglass", "list", "--json")), &js); err != nil || len(js) != 1 || js[0].Device != "lab-sw" {
		t.Errorf("engineer list --json: %v %+v", err, js)
	}
	// Where the device is shown, the hold is.
	if got := sb.asEngineer("", "device", "show", "lab-sw"); !strings.Contains(got, "Break-glass:  HELD since ") {
		t.Errorf("device show: %q", got)
	}
	if got := sb.asEngineer("", "device", "list"); !strings.Contains(got, "BREAK-GLASS") || strings.Contains(got, "2 device(s) held") ||
		!strings.Contains(got, "1 device(s) held for break-glass") {
		t.Errorf("device list: %q", got)
	}
	if got := sb.asEngineer("", "status"); strings.Contains(got, "prod-sw") || !strings.Contains(got, "HELD on lab-sw") {
		t.Errorf("status: %q", got)
	}
	if got := sb.asEngineer("", "scope", "list"); !strings.Contains(got, "(1 break-glass hold)") {
		t.Errorf("scope list: %q", got)
	}
	// Another scope's hold is not shown to the engineer at all.
	if got := sb.asEngineer("", "scope", "show", "prod"); sb.code != 1 || strings.Contains(got, "prod-sw") {
		t.Errorf("scope show prod: %d %q", sb.code, got)
	}
	// The engineer's own device changes are refused while held.
	sb.asEngineer("", "device", "address", "lab-sw", "192.168.1.3")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "break-glass is held on lab-sw: release it first") {
		t.Errorf("engineer address: %d %q", sb.code, sb.stderr())
	}
	// A superuser's list shows both.
	if out := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(out, "lab-sw") || !strings.Contains(out, "prod-sw") || !strings.Contains(out, "Break-glass holds (2)") {
		t.Errorf("superuser list: %s", out)
	}
}

// A no-op release (the device was uncovered meanwhile) restarts nothing and
// says so; a hold is released from the record alone.
func TestBreakglassReleaseOfAnUncoveredDeviceChangesNothing(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	if out := sb.hold(t, "lab-sw", "x", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold: %q %q", out, sb.stderr())
	}
	// Take the prefix away: nothing covers the address any more.
	sb.run("", []string{"scope", "prefixes", "lab", "remove", "192.168.0.0/16"})
	if sb.code != 0 {
		t.Fatalf("remove prefix: %d %q", sb.code, sb.stderr())
	}
	list := plain(sb.run("", []string{"breakglass", "list"}))
	if !strings.Contains(list, "no scope covers it now") {
		t.Errorf("list: %s", list)
	}
	// ... and the device is gone from the registry by hand: still releasable.
	sb.write("state/devices.yaml", "version: 1\ndevices: {}\n", 0o600)
	before := sb.renderedConfig()
	out := plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	if sb.code != 0 || !strings.Contains(out, "no scope covers 192.168.1.1, so the rendering did not change; no backend file changed, nothing restarted.") {
		t.Errorf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	if sb.restarts() != 0 {
		t.Errorf("a no-op release restarted %d backends", sb.restarts())
	}
	if sb.renderedConfig() != before {
		t.Error("a no-op release changed the rendering")
	}
}

// 'device config pull' refuses a held device up front and a batch skips it;
// 'plan' of the last pull works and names the hold; 'tacctl ssh' warns.
func TestBreakglassPullSkipsAndPlanNamesTheHold(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	if out := sb.hold(t, "lab-sw", "x", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold: %q %q", out, sb.stderr())
	}
	want := "break-glass is held on lab-sw: the device does not authenticate your login until it is released (tacctl breakglass release lab-sw)"
	sb.asEngineer("", "device", "config", "pull", "lab-sw")
	if sb.code != 1 || !strings.Contains(sb.stderr(), want) {
		t.Errorf("named pull: %d %q", sb.code, sb.stderr())
	}
	out := sb.asEngineer("", "device", "config", "pull", "--all")
	if !strings.Contains(out, "skipped lab-sw: "+want) {
		t.Errorf("batch pull: %d %q %q", sb.code, out, sb.stderr())
	}
	// Plan from the last pull works (no pull yet: it says so, naming the
	// device, and the cover page marks the hold).
	out = sb.asEngineer("", "device", "config", "plan", "lab-sw")
	if strings.Contains(out, "does not authenticate") {
		t.Errorf("plan without --pull refused the hold: %q", out)
	}
	out = plain(sb.run("", []string{"device", "config", "plan", "--all"}))
	if !strings.Contains(out, "[break-glass held]") {
		t.Errorf("the cover page does not mark the device:\n%s", out)
	}
}
