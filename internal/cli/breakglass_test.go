package cli

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
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
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw addr=192\.168\.1\.1 reason="console recovery after a failed paste" by=root`) {
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

	// The held device cannot be removed, nor moved to an address a hold
	// would be refused at (its move is breakglass_move_test.go); a rename
	// follows.
	sb.run("", []string{"device", "address", "lab-sw", "127.0.0.9", "-y"})
	sb.expect(1, "", "127.0.0.9 is a loopback address")
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
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass release device=lab-core addr=192\.168\.1\.1 held=\S+ by=root`) {
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
	// Moving a held device moves the hold, which is not the engineer's.
	sb.asEngineer("", "device", "address", "lab-sw", "192.168.1.3")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "break-glass is held on lab-sw: moving its address moves the hold, which is the superuser's") {
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

// seenFrom writes the seen cache the logs would have made.
func (sb *sandbox) seenFrom(t *testing.T, ss ...backend.Sighting) {
	t.Helper()
	s := devreg.NewSeen()
	s.Apply("tacacs", ss)
	s.Updated = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if err := os.MkdirAll(sb.path("var-lib"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(sb.path("var-lib", "devices-seen.json")); err != nil {
		t.Fatal(err)
	}
}

// The hold carves the registered address and says so; when the logs hold no
// request from it, the report warns that a device that sends from another
// address is still answered and names where to learn that address.
func TestBreakglassHoldSaysOnlyTheRegisteredAddressIsCarved(t *testing.T) {
	const carved = "  Carved:   only 192.168.1.1, the address registered for lab-sw. " +
		"A device that sends its AAA from another address (a source interface, a NAT) is still answered.\n"
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	sight := func(addr, nas string) backend.Sighting {
		return backend.Sighting{Time: at, Address: addr, User: "alice", Outcome: backend.SightAccept, NASID: nas}
	}
	for _, c := range []struct {
		name string
		seen []backend.Sighting
		warn string // "" for none
	}{
		{"no log data", nil, ""},
		{"seen at the registered address", []backend.Sighting{sight("192.168.1.1", "")}, ""},
		{"seen from no address of its own", []backend.Sighting{sight("192.168.1.50", "other-sw")},
			"the server has seen lab-sw from no address at all (no request from 192.168.1.1, none that identifies as 'lab-sw'). " +
				"If it sends from another address it is still answered; learn the address it sends from with 'tacctl device config pull lab-sw' " +
				"(its source interface) or on the device with 'show tacacs' and its own log."},
		{"seen from another address", []backend.Sighting{sight("203.0.113.9", "lab-sw")},
			"the server's logs hold no request from 192.168.1.1, but 203.0.113.9 identifies as 'lab-sw': that is most likely where lab-sw sends from, " +
				"and it is still answered; learn the address it sends from with 'tacctl device config pull lab-sw'"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := engineerSandbox(t)
			sb.run("", []string{"config", "render"})
			if c.seen != nil {
				sb.seenFrom(t, c.seen...)
			}
			out := plain(sb.hold(t, "lab-sw", "x", "lab-sw"))
			if sb.code != 0 {
				t.Fatalf("hold: %d %q %q", sb.code, out, sb.stderr())
			}
			if !strings.Contains(out, carved) {
				t.Errorf("no carved line:\n%s", out)
			}
			i := strings.Index(out, "  Warning:  ")
			switch {
			case c.warn == "" && i >= 0:
				t.Errorf("a warning was given:\n%s", out)
			case c.warn != "" && (i < 0 || !strings.Contains(out[i:], c.warn)):
				t.Errorf("no warning %q:\n%s", c.warn, out)
			}
		})
	}
}

// A restart that failed is said so, with the command, and exits 1; the
// record and the rendered files stay.
func TestBreakglassHoldAndReleaseSayWhenTheRestartFailed(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	sb.script = func(r *fake.Runner) { r.On([]string{"systemctl", "restart"}, execx.Result{Code: 1}) }

	out := sb.hold(t, "lab-sw", "recovery", "lab-sw")
	if sb.code != 1 {
		t.Fatalf("hold: exit %d, want 1\n%s\n%s", sb.code, out, sb.stderr())
	}
	want := "Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.1; " +
		"tacacs NOT restarted: the running server still answers 192.168.1.1 until it is restarted (run: sudo systemctl restart tacquito)."
	if !strings.Contains(out, want) || strings.Contains(out, "tacacs restarted") {
		t.Errorf("hold report:\n%s", out)
	}
	if !strings.Contains(sb.stderr(), "The hold is recorded and the rendered files are kept, but it is not in force until the backend named under Rendered is restarted") {
		t.Errorf("stderr %q", sb.stderr())
	}
	if !strings.Contains(sb.overrides(), "address: 192.168.1.1") || !strings.Contains(sb.renderedConfig(), "# break-glass held: 192.168.1.1") {
		t.Errorf("the record or the files were not kept:\n%s", sb.overrides())
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw `) {
		t.Error("the hold was not logged")
	}

	out = plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	if sb.code != 1 {
		t.Fatalf("release: exit %d, want 1\n%s\n%s", sb.code, out, sb.stderr())
	}
	want = "Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; " +
		"tacacs NOT restarted: the running server still does not answer 192.168.1.1 until it is restarted (run: sudo systemctl restart tacquito)."
	if !strings.Contains(out, want) {
		t.Errorf("release report:\n%s", out)
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") || sb.renderedConfig() != original {
		t.Error("the release was not kept")
	}
}

// A second hold of a device is refused as already held and leaves the first
// record as it was, also when it is the one that was written meanwhile (the
// check is made under tacctl.yaml's lock).
func TestBreakglassHoldMadeMeanwhileIsNotOverwritten(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	sb.tty = nil
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	sb.tty = slave
	// Another superuser's hold lands while this one waits for the name; the
	// name is typed after it. Either the early check or the one under the
	// lock refuses the second hold, and neither may change the record.
	meanwhile := "breakglass_hold:\n  lab-sw:\n    address: 192.168.1.1\n    since: '2026-10-10T14:02:00+00:00'\n    by: alice\n    reason: first\n"
	go func() {
		time.Sleep(700 * time.Millisecond)
		_ = os.WriteFile(sb.path("state", "tacctl.yaml"), []byte("tier:\n  operator: engineer\n"+meanwhile), 0o600)
		_, _ = master.WriteString("lab-sw\n")
	}()
	sb.run("", []string{"breakglass", "hold", "lab-sw", "--reason", "second"})
	sb.tty = nil
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Break-glass is already held on 'lab-sw' (192.168.1.1)") ||
		!strings.Contains(sb.stderr(), "Nothing was changed.") {
		t.Fatalf("exit %d, stderr %q", sb.code, sb.stderr())
	}
	if o := sb.overrides(); !strings.Contains(o, "by: alice") || !strings.Contains(o, "reason: first") || strings.Contains(o, "second") {
		t.Errorf("the record was overwritten:\n%s", o)
	}
}

// A record written by hand under a key with a dot in it is read, listed and
// carved, named by 'config validate', and a release removes it from where it
// is stored and renders the carve away.
func TestBreakglassHandWrittenDottedKeyIsReleased(t *testing.T) {
	sb := engineerSandbox(t)
	sb.dev("", "add", "sw.lab", "192.168.1.5", "--vendor", "cisco", "--no-host-key")
	if sb.code != 0 {
		t.Fatalf("add: %d %q", sb.code, sb.stderr())
	}
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nbreakglass_hold:\n  sw.lab:\n    address: 192.168.1.5\n"+
		"    since: '2026-10-10T14:02:00+00:00'\n    by: alice\n    reason: written by hand\n", 0o600)
	sb.run("", []string{"config", "render"})
	if cfg := sb.renderedConfig(); !strings.Contains(cfg, "# break-glass held: 192.168.1.5 (device sw.lab)") {
		t.Fatalf("the dotted record was not carved:\n%s", cfg)
	}
	if out := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(out, "sw.lab") || !strings.Contains(out, "written by hand") {
		t.Errorf("list:\n%s", out)
	}
	out := plain(sb.run("", []string{"config", "validate"}))
	if !strings.Contains(out, "breakglass_hold.sw.lab (device sw.lab) is stored under the key 'sw.lab', which holds a dot") {
		t.Errorf("validate does not name the key:\n%s", out)
	}

	out = plain(sb.run("", []string{"breakglass", "release", "sw.lab"}))
	if sb.code != 0 || !strings.Contains(out, "Break-glass RELEASED on sw.lab (192.168.1.5)") {
		t.Fatalf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	if o := sb.overrides(); strings.Contains(o, "breakglass_hold") || strings.Contains(o, "sw.lab") {
		t.Errorf("the record is left:\n%s", o)
	}
	if got := sb.renderedConfig(); got != original {
		t.Errorf("the carve is left:\n%s", got)
	}
	if out := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(out, "None held") {
		t.Errorf("list after the release:\n%s", out)
	}
}

// An entry that is not a usable hold is named by 'config validate', carves
// nothing, and is removed by name.
func TestBreakglassUnusableEntriesAreNamedAndRemoved(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nbreakglass_hold:\n  bare:\n    reason: no address\n"+
		"  wide:\n    address: 192.168.0.0/16\n    reason: a prefix\n  word:\n    address: nope\n", 0o600)
	out := plain(sb.run("", []string{"config", "validate"}))
	for _, want := range []string{
		"breakglass_hold.bare (device bare) has no address, so it silences nothing",
		"breakglass_hold.wide (device wide) has the address '192.168.0.0/16', which is not one IPv4 or IPv6 address, so it silences nothing",
		"breakglass_hold.word (device word) has the address 'nope'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q:\n%s", want, out)
		}
	}
	if sb.code == 0 {
		t.Error("validate passed with a record that has no address")
	}
	// Nothing is carved: the rendering is as without them.
	sb.run("", []string{"config", "render"})
	if got := sb.renderedConfig(); got != original {
		t.Errorf("an unusable entry changed the rendering:\n%s", got)
	}
	if out := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(out, "None held") {
		t.Errorf("list:\n%s", out)
	}
	for _, name := range []string{"bare", "wide", "word"} {
		out := plain(sb.run("", []string{"breakglass", "release", name}))
		if sb.code != 0 || !strings.Contains(out, "Break-glass record REMOVED for "+name+": the entry ") {
			t.Errorf("release %s: %d %q %q", name, sb.code, out, sb.stderr())
		}
	}
	if o := sb.overrides(); strings.Contains(o, "breakglass_hold") {
		t.Errorf("entries are left:\n%s", o)
	}
}

// A hold applies to a device only while the device is registered at the
// record's address: a record of another address, or of a device that is not
// registered, is an orphan, shown and named as one, and releasable by name.
func TestBreakglassOrphanRecords(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	if out := sb.hold(t, "lab-sw", "recovery", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold: %q %q", out, sb.stderr())
	}
	// Removed by hand from devices.yaml and registered again, at another
	// address, under the same name.
	sb.write("state/devices.yaml", strings.Replace(sb.devices(), "192.168.1.1", "192.168.1.9", 1), 0o600)

	list := plain(sb.run("", []string{"breakglass", "list"}))
	for _, want := range []string{"lab-sw (orphan)", "192.168.1.1", "recovery",
		"lab-sw is an orphan record: lab-sw is registered at 192.168.1.9, not at 192.168.1.1, so it holds no registered device or enrolled host, and it still silences 192.168.1.1; 'tacctl breakglass release lab-sw' removes it."} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q:\n%s", want, list)
		}
	}
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"breakglass", "list", "--json"})), &js); err != nil || len(js) != 1 || !js[0].Orphan || !js[0].Registered {
		t.Errorf("list --json: %v %+v", err, js)
	}
	// It is no hold of the device: not shown as held, not refused, not carried.
	if got := plain(sb.run("", []string{"device", "show", "lab-sw"})); strings.Contains(got, "Break-glass") {
		t.Errorf("device show:\n%s", got)
	}
	if got := plain(sb.run("", []string{"device", "list"})); strings.Contains(got, "BREAK-GLASS") {
		t.Errorf("device list:\n%s", got)
	}
	if got := plain(sb.run("", []string{"status"})); !strings.Contains(got, "Break-glass:        ORPHAN record lab-sw (192.168.1.1) since ") ||
		!strings.Contains(got, "lab-sw is registered at 192.168.1.9, not at 192.168.1.1; the server does not answer 192.168.1.1") {
		t.Errorf("status:\n%s", got)
	}
	if got := plain(sb.run("", []string{"config", "validate"})); !strings.Contains(got, "lab-sw is an orphan record: lab-sw is registered at 192.168.1.9, not at 192.168.1.1; it still silences 192.168.1.1") {
		t.Errorf("validate:\n%s", got)
	}
	// The carve stays: the record's address is the one carved.
	if cfg := sb.renderedConfig(); !strings.Contains(cfg, "# break-glass held: 192.168.1.1 (device lab-sw)") {
		t.Errorf("the carve went:\n%s", cfg)
	}
	// A second hold under the name would write over the record: refused.
	sb.hold(t, "lab-sw", "again", "lab-sw")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A break-glass record named 'lab-sw' stands at 192.168.1.1") ||
		!strings.Contains(sb.stderr(), "not at the address the device is registered at (192.168.1.9)") {
		t.Errorf("hold over an orphan: %d %q", sb.code, sb.stderr())
	}
	// The device may be moved and renamed: the orphan stays under its name.
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.8"})
	if sb.code != 0 {
		t.Errorf("device address: %d %q", sb.code, sb.stderr())
	}
	sb.run("", []string{"device", "rename", "lab-sw", "lab-core"})
	if sb.code != 0 || !strings.Contains(sb.overrides(), "  lab-sw:\n    address: 192.168.1.1\n") || strings.Contains(sb.overrides(), "lab-core") {
		t.Errorf("rename carried an orphan: %d\n%s", sb.code, sb.overrides())
	}
	// Gone from the registry altogether.
	sb.write("state/devices.yaml", "version: 1\ndevices: {}\n", 0o600)
	list = plain(sb.run("", []string{"breakglass", "list"}))
	if !strings.Contains(list, "lab-sw (orphan)") || !strings.Contains(list, "no device or host of that name is registered") {
		t.Errorf("list of an unregistered device:\n%s", list)
	}
	out := plain(sb.run("", []string{"breakglass", "release", "lab-sw"}))
	if sb.code != 0 || !strings.Contains(out, "Break-glass RELEASED on lab-sw (192.168.1.1)") {
		t.Errorf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Error("the record is left")
	}
}

// holdList runs 'breakglass hold <args>' on a terminal and types typed.
func (sb *sandbox) holdList(t *testing.T, typed string, args ...string) string {
	t.Helper()
	sb.tty = nil
	holdTTY(t, sb, typed+"\n")
	out := plain(sb.run("", append([]string{"breakglass", "hold"}, args...)))
	sb.tty = nil
	return out
}

// listSandbox is the engineer sandbox with a Juniper device beside lab-sw in
// scope lab, and one local account recorded for the scope.
func listSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := engineerSandbox(t)
	sb.dev("", "add", "lab-rtr", "192.168.1.2", "--vendor", "juniper", "--no-host-key")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	return sb
}

// A list is held in one write, one render and one restart, each device with
// its own reason or the default; the audit line is one per device; the
// release of the list is one restart and the original bytes.
func TestBreakglassHoldListRoundTrip(t *testing.T) {
	sb := listSandbox(t)
	original := sb.renderedConfig()
	out := sb.holdList(t, "lab-sw,lab-rtr", "lab-sw=console recovery,lab-rtr", "--reason", "paste cut the session")
	if sb.code != 0 {
		t.Fatalf("hold: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Hold break-glass on 2 devices (lab-sw,lab-rtr)?",
		"  lab-sw (192.168.1.1, scope lab, cisco)\n    Reason: console recovery\n    Local accounts: lab-admin [admin]\n",
		"  lab-rtr (192.168.1.2, scope lab, juniper)\n    Reason: paste cut the session\n",
		"Nothing releases them but 'tacctl breakglass release lab-sw,lab-rtr'.",
		"Break-glass HELD on lab-sw (192.168.1.1) since ",
		"Break-glass HELD on lab-rtr (192.168.1.2) since ",
		"  Reason:   console recovery\n",
		"  Reason:   paste cut the session\n",
		"  Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.1, 192.168.1.2; tacacs restarted.\n",
		"Way in, cisco (lab-sw):", "Way in, juniper (lab-rtr):",
		"  When done: tacctl breakglass release lab-sw,lab-rtr\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hold report lacks %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "Rendered:"); n != 1 {
		t.Errorf("%d Rendered lines, want 1", n)
	}
	if strings.Contains(out, "Not held:") {
		t.Errorf("a Not held line:\n%s", out)
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts for the hold of two devices, want 1", n)
	}
	for _, line := range []string{
		`breakglass hold device=lab-sw addr=192\.168\.1\.1 reason="console recovery" by=root`,
		`breakglass hold device=lab-rtr addr=192\.168\.1\.2 reason="paste cut the session" by=root`,
	} {
		if !hasAuditMatch(sb.runner, "auth.info", line) {
			t.Errorf("no audit line %q: %v", line, sb.runner.Argvs())
		}
	}
	o := sb.overrides()
	for _, want := range []string{"  lab-sw:\n    address: 192.168.1.1\n", "reason: console recovery\n", "  lab-rtr:\n    address: 192.168.1.2\n", "reason: paste cut the session\n"} {
		if !strings.Contains(o, want) {
			t.Errorf("tacctl.yaml lacks %q:\n%s", want, o)
		}
	}
	if cfg := sb.renderedConfig(); !strings.Contains(cfg, "# break-glass held: 192.168.1.1 (device lab-sw)") ||
		!strings.Contains(cfg, "# break-glass held: 192.168.1.2 (device lab-rtr)") || strings.Contains(cfg, "paste cut") {
		t.Errorf("the rendered file:\n%s", cfg)
	}
	if list := plain(sb.run("", []string{"breakglass", "list"})); !strings.Contains(list, "Break-glass holds (2)") {
		t.Errorf("list:\n%s", list)
	}

	// The release of the list: one restart, the original bytes, one line each.
	out = plain(sb.run("", []string{"breakglass", "release", "lab-rtr,lab-sw"}))
	if sb.code != 0 {
		t.Fatalf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Break-glass RELEASED on lab-rtr (192.168.1.2): held ", "(paste cut the session).",
		"Break-glass RELEASED on lab-sw (192.168.1.1): held ", "(console recovery).",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; tacacs restarted.",
		"Check:    tacctl device config pull lab-rtr,lab-sw --diff (aaa: ok), then a new ssh login as yourself.",
		"Still held: none",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("release report lacks %q:\n%s", want, out)
		}
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts for the release of two devices, want 1", n)
	}
	if got := sb.renderedConfig(); got != original {
		t.Errorf("hold then release did not restore the rendering:\n%s", got)
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Errorf("a record is left:\n%s", sb.overrides())
	}
	for _, dev := range []string{"lab-rtr", "lab-sw"} {
		if !hasAuditMatch(sb.runner, "auth.info", `breakglass release device=`+dev+` addr=\S+ held=\S+ by=root`) {
			t.Errorf("no release audit line for %s: %v", dev, sb.runner.Argvs())
		}
	}
}

// Best effort: the device that is refused is named with why, the others are
// held together; the names typed back are the accepted ones; with nothing
// accepted nothing changes; the exit code is 1 when any was not held.
func TestBreakglassHoldListIsBestEffort(t *testing.T) {
	sb := listSandbox(t)
	sb.dev("", "add", "nowhere", "100.64.0.9", "--no-host-key")

	// The names are the accepted ones, as printed: a refused one is not typed.
	out := sb.holdList(t, "lab-sw,nosuch", "lab-sw,nosuch,nowhere", "--reason", "r")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The names typed back are not 'lab-sw'. Nothing was changed.") {
		t.Fatalf("wrong typed back: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Hold break-glass on 1 device (lab-sw)?",
		"  Not held: nosuch: not found (tacctl device list)\n",
		"  Not held: nowhere: it is already unanswered: no scope covers 100.64.0.9 (tacctl scope lookup 100.64.0.9)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("prompt lacks %q:\n%s", want, out)
		}
	}
	if sb.restarts() != 0 || strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Error("a refused confirmation changed something")
	}

	out = sb.holdList(t, "lab-sw", "lab-sw,nosuch,nowhere", "--reason", "r")
	if sb.code != 1 {
		t.Fatalf("hold: exit %d, want 1\n%s\n%s", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Break-glass HELD on lab-sw (192.168.1.1) since ",
		"  When done: tacctl breakglass release lab-sw\n",
		"  Not held: nosuch: not found (tacctl device list)\n",
		"  Not held: nowhere: it is already unanswered",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hold report lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(sb.stderr(), "2 of 3 devices were not held (see Not held).") {
		t.Errorf("stderr %q", sb.stderr())
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts, want 1", n)
	}
	if o := sb.overrides(); !strings.Contains(o, "  lab-sw:\n") || strings.Contains(o, "nosuch") || strings.Contains(o, "nowhere") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}

	// Held already is one more refusal; lab-rtr is held with it.
	out = sb.holdList(t, "lab-rtr", "lab-sw,lab-rtr", "--reason", "r2")
	if sb.code != 1 || !strings.Contains(out, "  Not held: lab-sw: already held (192.168.1.1) since ") ||
		!strings.Contains(out, "Break-glass HELD on lab-rtr (192.168.1.2)") {
		t.Errorf("held already: %d\n%s\n%s", sb.code, out, sb.stderr())
	}

	// Nothing accepted: refused, nothing changed, nothing asked.
	before := sb.overrides()
	sb.run("", []string{"breakglass", "hold", "nosuch,lab-sw", "--reason", "r"})
	sb.expect(1, "", "Not held: nosuch: not found (tacctl device list)")
	if !strings.Contains(sb.stderr(), "Not held: lab-sw: already held") || !strings.Contains(sb.stderr(), "Nothing was changed.") {
		t.Errorf("stderr %q", sb.stderr())
	}
	if sb.overrides() != before || sb.restarts() != 0 {
		t.Error("a refused list changed something")
	}
}

// A hold made while the names were typed is skipped and named; the others
// are held.
func TestBreakglassHoldListSkipsTheOneMadeMeanwhile(t *testing.T) {
	sb := listSandbox(t)
	master, slave, err := testpty.Open()
	if err != nil {
		t.Skip("no pty:", err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	sb.tty = slave
	meanwhile := "breakglass_hold:\n  lab-sw:\n    address: 192.168.1.1\n    since: '2026-10-10T14:02:00+00:00'\n    by: alice\n    reason: first\n"
	// The other hold lands after the command is waiting for the names (its
	// checks take milliseconds; the margin is for a loaded CI machine).
	go func() {
		time.Sleep(2 * time.Second)
		_ = os.WriteFile(sb.path("state", "tacctl.yaml"), []byte("tier:\n  operator: engineer\n"+meanwhile), 0o600)
		_, _ = master.WriteString("lab-sw,lab-rtr\n")
	}()
	out := plain(sb.run("", []string{"breakglass", "hold", "lab-sw,lab-rtr", "--reason", "second"}))
	sb.tty = nil
	if sb.code != 1 {
		t.Fatalf("exit %d, want 1\n%s\n%s", sb.code, out, sb.stderr())
	}
	if !strings.Contains(out, "Break-glass HELD on lab-rtr (192.168.1.2)") || strings.Contains(out, "HELD on lab-sw") ||
		!strings.Contains(out, "  Not held: lab-sw: break-glass is already held on 'lab-sw' (192.168.1.1) since ") ||
		!strings.Contains(out, "another hold was made while the name was typed") ||
		!strings.Contains(out, "  When done: tacctl breakglass release lab-rtr\n") {
		t.Errorf("report:\n%s", out)
	}
	if o := sb.overrides(); !strings.Contains(o, "by: alice") || !strings.Contains(o, "reason: first") ||
		!strings.Contains(o, "  lab-rtr:\n") || strings.Count(o, "reason: second") != 1 {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts, want 1", n)
	}
	if hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw `) {
		t.Error("the skipped device was logged as held")
	}
}

// The arguments of a list: each device needs a reason, its own or the
// default; a name is given once; nothing is asked or changed.
func TestBreakglassHoldListUsageErrors(t *testing.T) {
	sb := listSandbox(t)
	before := sb.overrides()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"lab-sw,lab-rtr=x"}, "A reason is required for 'lab-sw'"},
		{[]string{"lab-sw,lab-rtr"}, "A reason is required for 'lab-sw', 'lab-rtr'"},
		{[]string{"lab-sw=x,lab-rtr", "--reason", "  "}, "--reason must not be empty."},
		{[]string{"lab-sw=,lab-rtr", "--reason", "x"}, "The reason of 'lab-sw' must not be empty."},
		{[]string{"lab-sw,LAB-SW", "--reason", "x"}, "'LAB-SW' is named twice."},
		{[]string{"lab-sw,,lab-rtr", "--reason", "x"}, "A name is missing in 'lab-sw,,lab-rtr'."},
		{[]string{"=x", "--reason", "x"}, "A name is missing in '=x'."},
		// the same device by name and by address
		{[]string{"lab-sw,192.168.1.1", "--reason", "x"}, "'192.168.1.1' is the device 'lab-sw', which is in the list already."},
		// an unquoted --reason: its words are an argument too many
		{[]string{"lab-sw", "--reason", "console", "recovery"}, "Unknown argument: 'recovery'"},
	} {
		sb.run("", append([]string{"breakglass", "hold"}, c.args...))
		sb.expect(1, "", c.want)
		if !strings.Contains(sb.stderr(), "Usage: tacctl breakglass hold <name>[=<reason>][,<name>[=<reason>]...]") {
			t.Errorf("%v: no usage in %q", c.args, sb.stderr())
		}
	}
	// A reason of its own needs no --reason (and an empty --reason is no
	// error then); a single device with none keeps its message; one list is
	// one argument.
	sb.run("", []string{"breakglass", "hold", "lab-sw"})
	sb.expect(1, "", "--reason is required: a hold is for one device or host in exceptional circumstances")
	sb.run("", []string{"breakglass", "hold", "lab-sw=x,lab-rtr=y", "--reason", "  "})
	sb.expect(1, "", "No terminal to confirm on")
	sb.run("", []string{"breakglass", "hold", "lab-sw=x", "lab-rtr=y"})
	sb.expect(1, "", "Unknown argument: 'lab-rtr=y'")
	if sb.overrides() != before {
		t.Error("a usage error changed tacctl.yaml")
	}
	out := sb.holdList(t, "lab-sw,lab-rtr", "lab-sw=a,lab-rtr=b")
	if sb.code != 0 || !strings.Contains(out, "  Reason:   a\n") || !strings.Contains(out, "  Reason:   b\n") {
		t.Errorf("own reasons: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
	// A restart that failed is said once, with the list to release.
	sb.run("", []string{"breakglass", "release", "lab-sw,lab-rtr"})
	sb.script = func(r *fake.Runner) { r.On([]string{"systemctl", "restart"}, execx.Result{Code: 1}) }
	out = sb.holdList(t, "lab-sw,lab-rtr", "lab-sw,lab-rtr", "--reason", "x")
	if sb.code != 1 || strings.Count(out, "NOT restarted") != 1 ||
		!strings.Contains(sb.stderr(), "'tacctl breakglass release lab-sw,lab-rtr' removes the record.") {
		t.Errorf("restart failed: %d\n%s\n%s", sb.code, out, sb.stderr())
	}
}

// 'release' of a list: what is not held is named and the rest is released in
// one restart, exit 1; with none held nothing changes.
func TestBreakglassReleaseListWithOneNotHeld(t *testing.T) {
	sb := listSandbox(t)
	sb.holdList(t, "lab-sw,lab-rtr", "lab-sw,lab-rtr", "--reason", "x")
	if sb.code != 0 {
		t.Fatalf("hold: %d %q", sb.code, sb.stderr())
	}
	before := sb.overrides()
	sb.run("", []string{"breakglass", "release", "nosuch,nosuch2"})
	sb.expect(1, "", "Not released: nosuch: break-glass is not held on it")
	if !strings.Contains(sb.stderr(), "Held now: lab-rtr") || !strings.Contains(sb.stderr(), "Nothing was changed.") ||
		sb.overrides() != before || sb.restarts() != 0 {
		t.Errorf("none held: %q", sb.stderr())
	}

	out := plain(sb.run("", []string{"breakglass", "release", "lab-sw,nosuch"}))
	if sb.code != 1 {
		t.Fatalf("release: exit %d, want 1\n%s\n%s", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Break-glass RELEASED on lab-sw (192.168.1.1): held ",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; tacacs restarted.",
		"Still held: lab-rtr (",
		"  Not released: nosuch: break-glass is not held on it\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("release report lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(sb.stderr(), "1 of 2 devices was not held, so not released.") {
		t.Errorf("stderr %q", sb.stderr())
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts, want 1", n)
	}
	if o := sb.overrides(); strings.Contains(o, "  lab-sw:") || !strings.Contains(o, "  lab-rtr:") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
}

// One device is asked and reported exactly as before the list form: the
// prompt, the report, the refusals.
func TestBreakglassSingleDeviceOutputIsUnchanged(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"scope", "breakglass", "lab", "add", "lab-admin"})
	sb.run("", []string{"config", "render"})
	norm := func(s string) string {
		var keep []string
		for _, l := range strings.Split(s, "\n") {
			if !strings.HasPrefix(l, "[INFO] Config snapshot saved to ") {
				keep = append(keep, l)
			}
		}
		return regexp.MustCompile(`\d{4}-\d\d-\d\d \d\d:\d\d`).ReplaceAllString(strings.Join(keep, "\n"), "<T>")
	}
	out := norm(sb.hold(t, "lab-sw", "console recovery", "lab-sw"))
	wantHold := `
Hold break-glass on lab-sw (192.168.1.1, scope lab, cisco)?
  This is for one device in exceptional circumstances. The server stops answering 192.168.1.1: every login at
  that device falls to its local accounts (lab-admin [admin]); nobody without one can
  log in there until you release it.
  The backends that serve it restart now and again at release (the restart every scope change makes).
  Nothing releases it but 'tacctl breakglass release lab-sw'.
[INFO] Service restarted.

Break-glass HELD on lab-sw (192.168.1.1) since <T> by root.
  Reason:   console recovery
  Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.1; tacacs restarted.
  Carved:   only 192.168.1.1, the address registered for lab-sw. A device that sends its AAA from another address (a source interface, a NAT) is still answered.

  ssh: log in as a local account; the device waits for the server first (a few seconds), then takes the local
  password, and the account lands at the level of its 'username ... privilege' line.
  Console: log in as the local account (the CONSOLE list is local), then 'enable' with the local enable secret.
  Logins by your TACACS+ name fail on this device until you release it.
  Nothing it does is accounted here: a held device sends its accounting to a server that does not answer it;
  what the technician types is in the device's own log only.

  Held now: lab-sw (under 1 min, root)
  When done: tacctl breakglass release lab-sw

`
	if out != wantHold {
		t.Errorf("hold:\n%s\nwant:\n%s", out, wantHold)
	}
	// Refusals: nothing on stdout but the record of a second hold.
	out = norm(sb.hold(t, "lab-sw", "again", "lab-sw"))
	if out != "  Reason: console recovery\n" || norm(sb.stderr()) != "[ERROR] Break-glass is already held on 'lab-sw' (192.168.1.1) since <T> by root (under 1 min).\n"+
		"[ERROR] Release it first (tacctl breakglass release lab-sw), then hold again with the new reason. Nothing was changed.\n" || sb.code != 1 {
		t.Errorf("held twice: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.hold(t, "nosuch", "x", "nosuch")
	if sb.stderr() != "[ERROR] Device 'nosuch' not found. List them with: tacctl device list\n" || sb.code != 1 {
		t.Errorf("unknown: %d %q", sb.code, sb.stderr())
	}
	sb.run("", []string{"breakglass", "release", "nosuch"})
	if norm(sb.stderr()) != "[ERROR] Break-glass is not held on 'nosuch'. Held now: lab-sw (under 1 min, root) (tacctl breakglass list)\n[ERROR] Nothing was changed.\n" || sb.code != 1 {
		t.Errorf("release unknown: %d %q", sb.code, sb.stderr())
	}
	out = norm(plain(sb.run("", []string{"breakglass", "release", "lab-sw"})))
	wantRel := `[INFO] Service restarted.

Break-glass RELEASED on lab-sw (192.168.1.1): held under 1 min by root (console recovery).
  Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; tacacs restarted.
  Check:    tacctl device config pull lab-sw --diff (aaa: ok), then a new ssh login as yourself.
  Still held: none

`
	if out != wantRel || sb.code != 0 {
		t.Errorf("release: %d\n%s\nwant:\n%s", sb.code, out, wantRel)
	}
}
