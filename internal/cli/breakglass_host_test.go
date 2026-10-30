package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devreg"
)

// A break-glass hold on an enrolled Linux host (docs/plans/0.2.14-plan.md
// D176 and D179-D181), on the engineer sandbox: web1 (ssh target 192.168.1.10,
// scope lab, 192.168/16) and db1 (10.99.0.20, scope prod, 10/8) are enrolled;
// web2 is enrolled by name, and the address its last sync recorded is
// 192.168.1.12.

// hostLines are the enrolled hosts of hostLab.
const hostLines = "web1|root@192.168.1.10||lab|192.0.2.1|\n" +
	"db1|root@10.99.0.20||prod|192.0.2.1|\n" +
	"web2|root@web2.example.net||lab|192.0.2.1|\n"

// hostLab is a rendered sandbox with the hosts of hostLines and nothing held.
func hostLab(t *testing.T) *sandbox {
	t.Helper()
	sb := engineerSandbox(t)
	sb.write("state/linux-hosts", hostLines, 0o600)
	sb.recordHostAddress("web2", "192.168.1.12")
	sb.run("", []string{"config", "render"})
	return sb
}

// recordHostAddress writes the address a sync recorded for an enrolled host.
func (sb *sandbox) recordHostAddress(name, addr string) {
	sb.t.Helper()
	path := sb.path("state", "devices.yaml")
	f, err := devreg.Load(path)
	if err != nil {
		sb.t.Fatal(err)
	}
	f.SetHostAddress(name, addr, "2026-10-04 12:00")
	text, err := f.Text()
	if err != nil {
		sb.t.Fatal(err)
	}
	sb.write("state/devices.yaml", string(text), 0o600)
}

func (sb *sandbox) sshCalls() int { return sb.runner.Count("ssh") + sb.runner.Count("ssh-keyscan") }

// holdHost holds name on its terminal and checks that it went through.
func holdHost(t *testing.T, sb *sandbox, name, reason string) string {
	t.Helper()
	out := sb.hold(t, name, reason, name)
	if sb.code != 0 {
		t.Fatalf("hold %s: %d %q %q", name, sb.code, out, sb.stderr())
	}
	return out
}

// A held enrolled host is named a host in the comment block of both backend
// files and a held device a device (D237), and the files are what a fresh
// render writes: 'config validate' reads them as up to date.
func TestBreakglassHoldCommentNamesAHostAsAHost(t *testing.T) {
	sb := engineerSandbox(t)
	sandboxRADIUS(sb)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nbackends:\n  enabled:\n  - tacacs\n  - radius\n", 0o600)
	sb.write("state/linux-hosts", hostLines, 0o600)
	sb.recordHostAddress("web2", "192.168.1.12")
	sb.run("", []string{"config", "render"})
	if sb.code != 0 {
		t.Fatalf("render: %d %q", sb.code, sb.stderr())
	}
	holdHost(t, sb, "web1", "locked out of sudo")
	if out := sb.hold(t, "lab-sw", "console recovery", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold lab-sw: %d %q %q", sb.code, out, sb.stderr())
	}
	tac, rad := sb.renderedConfig(), sb.read("raddb/tacctl-radius.conf")
	for _, c := range []struct{ file, text string }{
		{"tacquito.yaml", tac}, {"clients.conf", rad},
	} {
		for _, want := range []string{"(host web1)", "(device lab-sw)"} {
			if !strings.Contains(c.text, want) {
				t.Errorf("%s lacks %q:\n%s", c.file, want, c.text)
			}
		}
		for _, bad := range []string{"(device web1)", "(host lab-sw)"} {
			if strings.Contains(c.text, bad) {
				t.Errorf("%s has %q", c.file, bad)
			}
		}
	}
	if out := plain(sb.run("", []string{"config", "validate"})); !strings.Contains(out, "up to date") ||
		strings.Contains(out, "out of date") {
		t.Errorf("validate after the holds (exit %d):\n%s", sb.code, out)
	}
}

func TestBreakglassHostHoldRoundTrip(t *testing.T) {
	sb := hostLab(t)
	original := sb.renderedConfig()

	// The prompt names the host and what it keeps.
	sb.tty = nil
	holdTTY(t, sb, "web1x\n")
	out := plain(sb.run("", []string{"breakglass", "hold", "web1", "--reason", "locked out of sudo"}))
	sb.tty = nil
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The name typed back is not 'web1'. Nothing was changed.") {
		t.Fatalf("a wrong name: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Hold break-glass on web1 (192.168.1.10, scope lab, linux)?",
		"This is for one host in exceptional circumstances.",
		"every TACACS+ or RADIUS", "the host's local administrator and its console work",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the prompt lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") || sb.restarts() != 0 {
		t.Fatal("a refused hold changed something")
	}

	out = holdHost(t, sb, "web1", "locked out of sudo")
	for _, want := range []string{
		"Break-glass HELD on web1 (192.168.1.10) since ", " by root.",
		"Reason:   locked out of sudo",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers as 16 prefixes without 192.168.1.10; tacacs restarted.",
		"Carved:   only 192.168.1.10, the address recorded for the host web1.",
		"ssh or console: log in as the host's local administrator",
		"'tacctl host sync', 'host show --check'", "and so is 'host unenroll'.",
		"a held host sends its accounting to a server that does not answer it",
		"Held now: web1 (under 1 min, root)", "When done: tacctl breakglass release web1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("hold report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Local accounts:") || strings.Contains(out, "ssh: log in as a local account") {
		t.Errorf("the report speaks of a device:\n%s", out)
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts for the hold, want 1", n)
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold host=web1 addr=192\.168\.1\.10 reason="locked out of sudo" by=root`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	if o := sb.overrides(); !strings.Contains(o, "breakglass_hold:\n  web1:\n    address: 192.168.1.10\n") || !strings.Contains(o, "reason: locked out of sudo\n") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	cfg := sb.renderedConfig()
	if strings.Contains(cfg, `"192.168.0.0/16"`) || !strings.Contains(cfg, "# break-glass held: 192.168.1.10 (host web1)") {
		t.Errorf("the rendered file:\n%s", cfg)
	}
	for _, p := range carvedPrefixes("192.168.1.10") {
		if !strings.Contains(cfg, `"`+p+`"`) {
			t.Errorf("the rendered file lacks %s", p)
		}
	}
	if !strings.Contains(sb.store(), "192.168.0.0/16") {
		t.Error("the store was changed")
	}
	// The host is not touched over ssh.
	if n := sb.sshCalls(); n != 0 {
		t.Errorf("%d ssh calls", n)
	}

	// Held twice is refused; the displays say so.
	sb.hold(t, "web1", "again", "web1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Break-glass is already held on 'web1' (192.168.1.10)") {
		t.Errorf("held twice: %d %q", sb.code, sb.stderr())
	}
	list := plain(sb.run("", []string{"breakglass", "list"}))
	for _, want := range []string{"Break-glass holds (1)", "NAME", "KIND", "web1", "host", "192.168.1.10", "lab", "locked out of sudo"} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q:\n%s", want, list)
		}
	}
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"breakglass", "list", "--json"})), &js); err != nil || len(js) != 1 ||
		js[0].Device != "web1" || js[0].Kind != "host" || js[0].Vendor != "linux" || js[0].Scope != "lab" || !js[0].Registered || js[0].Orphan || !js[0].Covered {
		t.Errorf("list --json: %v %+v", err, js)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"host", "list"}, "STATE"},
		{[]string{"host", "list"}, "BREAK-GLASS"},
		{[]string{"host", "list"}, "1 host(s) held for break-glass: tacctl breakglass list"},
		{[]string{"host", "show", "web1"}, "Break-glass\n  Held:         HELD since "},
		{[]string{"host", "show", "web1"}, "; the server does not answer 192.168.1.10"},
		{[]string{"host", "show", "web1"}, "Release:      tacctl breakglass release web1"},
		{[]string{"status"}, "Break-glass:        HELD on web1 (192.168.1.10) since "},
		{[]string{"scope", "show", "lab"}, "Break-glass held: web1 (192.168.1.10) since "},
		{[]string{"scope", "routing"}, "break-glass held: 192.168.1.10 (web1) is carved out of 192.168.0.0/16 (lab)"},
		{[]string{"config", "validate"}, "Break-glass hold:    web1 (192.168.1.10) held since "},
	} {
		if got := plain(sb.run("", c.args)); !strings.Contains(got, c.want) {
			t.Errorf("%v lacks %q:\n%s", c.args, c.want, got)
		}
	}
	// Only a held host is marked.
	hl := plain(sb.run("", []string{"host", "list"}))
	if strings.Count(hl, "BREAK-GLASS") != 1 {
		t.Errorf("host list marks %d rows:\n%s", strings.Count(hl, "BREAK-GLASS"), hl)
	}
	for _, l := range strings.Split(hl, "\n") {
		if strings.Contains(l, "BREAK-GLASS") && !strings.HasPrefix(strings.TrimSpace(l), "web1") {
			t.Errorf("host list marks the wrong row: %q", l)
		}
	}
	var hv map[string]any
	if err := json.Unmarshal([]byte(sb.run("", []string{"host", "show", "web1", "--json"})), &hv); err != nil {
		t.Fatal(err)
	}
	if b, ok := hv["breakglass"].(map[string]any); !ok || b["held"] != true || b["address"] != "192.168.1.10" || b["reason"] != "locked out of sudo" {
		t.Errorf("host show --json: %v", hv["breakglass"])
	}
	var hv2 map[string]any
	if err := json.Unmarshal([]byte(sb.run("", []string{"host", "show", "db1", "--json"})), &hv2); err != nil {
		t.Fatal(err)
	}
	if _, ok := hv2["breakglass"]; ok {
		t.Errorf("an unheld host has a breakglass field: %v", hv2["breakglass"])
	}
	if got := plain(sb.run("", []string{"host", "show", "db1"})); strings.Contains(got, "Break-glass") {
		t.Errorf("db1 is shown as held:\n%s", got)
	}
	// The devices' displays are the devices'.
	if got := plain(sb.run("", []string{"device", "list"})); strings.Contains(got, "BREAK-GLASS") {
		t.Errorf("device list marks a host:\n%s", got)
	}
	var dj []deviceJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"device", "list", "--json"})), &dj); err != nil {
		t.Fatal(err)
	}
	for _, d := range dj {
		if d.Breakglass != nil {
			t.Errorf("device list --json: %s has %+v", d.Name, d.Breakglass)
		}
	}
	// 'device address' is for devices.
	devs, rec := sb.devices(), sb.overrides()
	sb.run("", []string{"device", "address", "web1", "192.168.1.50", "--yes"})
	if sb.code != 1 || sb.devices() != devs || sb.overrides() != rec {
		t.Errorf("device address on a host: %d %q", sb.code, sb.stderr())
	}

	// Completion offers the held host and every host to hold.
	if got := sb.run("", []string{"_completion-names", "held"}); got != "web1\n" {
		t.Errorf("held names %q", got)
	}
	if got := sb.run("", []string{"_completion-names", "devices"}); !strings.Contains(got, "web1\n") || !strings.Contains(got, "db1\n") {
		t.Errorf("device names %q", got)
	}

	// Release: one restart, the original bytes.
	out = plain(sb.run("", []string{"breakglass", "release", "web1"}))
	if sb.code != 0 {
		t.Fatalf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{"Break-glass RELEASED on web1 (192.168.1.10): held ", "(locked out of sudo).",
		"Rendered: 192.168.0.0/16 of scope 'lab' answers whole again; tacacs restarted.",
		"Check:    a new login as yourself at the host (tacctl host show web1 --check).", "Still held: none"} {
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
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass release host=web1 addr=192\.168\.1\.10 held=\S+ by=root`) {
		t.Errorf("no release audit line: %v", sb.runner.Argvs())
	}
	if got := plain(sb.run("", []string{"host", "list"})); strings.Contains(got, "BREAK-GLASS") {
		t.Errorf("host list after the release:\n%s", got)
	}
}

// The address of a host is the one a sync recorded, else its ssh target's.
func TestBreakglassHostHoldsTheRecordedAddress(t *testing.T) {
	sb := hostLab(t)
	out := holdHost(t, sb, "web2", "x")
	if !strings.Contains(out, "Break-glass HELD on web2 (192.168.1.12)") || !strings.Contains(sb.overrides(), "  web2:\n    address: 192.168.1.12\n") {
		t.Errorf("recorded address:\n%s\n%s", out, sb.overrides())
	}
	// A host without a record is held at its ssh target's address; one
	// named by the address a sync recorded is held under its name.
	holdHost(t, sb, "web1", "y")
	if !strings.Contains(sb.overrides(), "  web1:\n    address: 192.168.1.10\n") {
		t.Errorf("ssh target address:\n%s", sb.overrides())
	}
	sb.run("", []string{"breakglass", "release", "web2"})
	if out := sb.hold(t, "192.168.1.12", "by address", "web2"); sb.code != 0 {
		t.Fatalf("hold by address: %d %q %q", sb.code, out, sb.stderr())
	}
	if !strings.Contains(sb.overrides(), "  web2:\n    address: 192.168.1.12\n") {
		t.Errorf("by address:\n%s", sb.overrides())
	}
}

// Every refusal changes nothing.
func TestBreakglassHostHoldRefusals(t *testing.T) {
	sb := hostLab(t)
	sb.dev("", "add", "dup1", "192.168.1.30", "--no-host-key", "--allow-generic")
	sb.dev("", "add", "twin", "192.168.1.40", "--no-host-key")
	sb.write("state/linux-hosts", hostLines+
		"dup1|root@192.168.1.31||lab|192.0.2.1|\n"+
		"nohost|root@nohost.example.net||lab|192.0.2.1|\n"+
		"here|local||lab|127.0.0.1|\n"+
		"loop|root@127.0.0.5||lab|192.0.2.1|\n"+
		"far|root@100.64.0.9||lab|192.0.2.1|\n", 0o600)
	sb.run("", []string{"config", "render"})
	devs, rec, cfg := sb.devices(), sb.overrides(), sb.renderedConfig()
	for _, c := range []struct{ name, want string }{
		{"dup1", "'dup1' is ambiguous: it is the device 'dup1' and the host 'dup1'. Nothing was changed."},
		{"nohost", "Host 'nohost' has no address: none is recorded and its ssh target is not an address. Record it: tacctl host sync nohost. Nothing was changed."},
		{"here", "'here' is this server (enrolled with --local)"},
		{"loop", "127.0.0.5 is a loopback address"},
		{"far", "'far' is already unanswered: no scope covers 100.64.0.9"},
		{"nosuch", "Device 'nosuch' not found"},
	} {
		holdTTY(t, sb, c.name+"\n")
		sb.run("", []string{"breakglass", "hold", c.name, "--reason", "x"})
		sb.tty = nil
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.want) {
			t.Errorf("%s: exit %d %q, want %q", c.name, sb.code, sb.stderr(), c.want)
		}
	}
	if sb.devices() != devs || sb.overrides() != rec || sb.renderedConfig() != cfg || sb.restarts() != 0 {
		t.Error("a refusal changed something")
	}
	// A list: each name is checked on its own.
	out := sb.holdList(t, "web1", "web1,dup1,here", "--reason", "x")
	if sb.code != 1 {
		t.Errorf("a list with refusals: %d %q", sb.code, sb.stderr())
	}
	for _, want := range []string{"Hold break-glass on 1 host (web1)?", "Not held: dup1: the name is ambiguous", "Not held: here: it is this server (enrolled with --local)"} {
		if !strings.Contains(out, want) {
			t.Errorf("the list lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(sb.stderr(), "2 of 3 devices and hosts were not held (see Not held).") {
		t.Errorf("stderr %q", sb.stderr())
	}
	sb.run("", []string{"breakglass", "release", "web1"})
	if sb.code != 0 {
		t.Fatal(sb.stderr())
	}
	if strings.Contains(sb.overrides(), "breakglass_hold") || sb.devices() != devs || sb.renderedConfig() != cfg {
		t.Error("a hold and its release changed something")
	}
	// A host at a device's address is not held (it would silence the
	// device): the converse of the next check.
	sb.recordHostAddress("web2", "192.168.1.40")
	holdTTY(t, sb, "web2\n")
	sb.run("", []string{"breakglass", "hold", "web2", "--reason", "x"})
	sb.tty = nil
	if sb.code != 1 || !strings.Contains(sb.stderr(), "192.168.1.40 is the address of the registered device 'twin': a hold there would silence the device 'twin' too. Nothing was changed.") {
		t.Errorf("a host at a device's address: %d %q", sb.code, sb.stderr())
	}
	out = sb.holdList(t, "web1", "web2,web1", "--reason", "x")
	if sb.code != 1 || !strings.Contains(out, "Not held: web2: 192.168.1.40 is the address of the registered device 'twin'") {
		t.Errorf("a list with a host at a device's address: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.run("", []string{"breakglass", "release", "web1"})
	sb.recordHostAddress("web2", "192.168.1.12")
	devs = sb.devices()
	// A device at a host's address is not held (it would silence the host).
	sb.write("state/devices.yaml", strings.Replace(sb.devices(), "192.168.1.40", "192.168.1.10", 1), 0o600)
	holdTTY(t, sb, "twin\n")
	sb.run("", []string{"breakglass", "hold", "twin", "--reason", "x"})
	sb.tty = nil
	if sb.code != 1 || !strings.Contains(sb.stderr(), "192.168.1.10 is the address of the enrolled host 'web1': a hold there would silence the host's logins too. Nothing was changed.") {
		t.Errorf("a device at a host's address: %d %q", sb.code, sb.stderr())
	}
	// Nor does a device move there (device address on a held device).
	sb.write("state/devices.yaml", devs, 0o600)
	if out := sb.hold(t, "lab-sw", "x", "lab-sw"); sb.code != 0 {
		t.Fatalf("hold lab-sw: %q %q", out, sb.stderr())
	}
	sb.run("", []string{"device", "address", "lab-sw", "192.168.1.10", "--yes"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "192.168.1.10 is the address of the enrolled host 'web1'") || !strings.Contains(sb.stderr(), "Nothing was changed.") {
		t.Errorf("device address onto a host: %d %q", sb.code, sb.stderr())
	}
}

// A mixed list holds hosts and devices, each with its own way in.
func TestBreakglassHostAndDeviceInOneList(t *testing.T) {
	sb := hostLab(t)
	out := sb.holdList(t, "web1,lab-sw", "web1=sudo,lab-sw=paste")
	if sb.code != 0 {
		t.Fatalf("hold: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{
		"Hold break-glass on 2 devices and hosts (web1,lab-sw)?", "Local access: the host's local administrator and its console",
		"Way in, linux (web1):", "Way in, cisco (lab-sw):",
		"Break-glass HELD on web1 (192.168.1.10)", "Break-glass HELD on lab-sw (192.168.1.1)",
		"Held now: ", "web1 (under 1 min, root)", "lab-sw (under 1 min, root)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the list lacks %q:\n%s", want, out)
		}
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts, want 1", n)
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass hold host=web1 `) || !hasAuditMatch(sb.runner, "auth.info", `breakglass hold device=lab-sw `) {
		t.Errorf("audit lines: %v", sb.runner.Argvs())
	}
	out = plain(sb.run("", []string{"breakglass", "release", "web1,lab-sw"}))
	if sb.code != 0 || !strings.Contains(out, "Break-glass RELEASED on web1") || !strings.Contains(out, "Break-glass RELEASED on lab-sw") ||
		!strings.Contains(out, "Check:    tacctl device config pull lab-sw --diff") || !strings.Contains(out, "Hosts: tacctl host show web1 --check.") {
		t.Errorf("release: %d %q %q", sb.code, out, sb.stderr())
	}
	if !hasAuditMatch(sb.runner, "auth.info", `breakglass release host=web1 `) || !hasAuditMatch(sb.runner, "auth.info", `breakglass release device=lab-sw `) {
		t.Errorf("release audit lines: %v", sb.runner.Argvs())
	}
}

// Nothing that logs in to a held host is attempted (D179), and the host can
// be neither forgotten nor changed meanwhile.
func TestBreakglassHeldHostRefusesWhatLogsIn(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web1", "locked out of sudo")
	state := func() string {
		return sb.read("state/linux-hosts") + sb.devices() + sb.overrides()
	}
	before := state()
	for _, c := range []struct {
		args []string
		cmd  string
	}{
		{[]string{"host", "sync", "web1"}, "tacctl host sync web1"},
		{[]string{"host", "show", "web1", "--check"}, "tacctl host show web1 --check"},
		{[]string{"host", "show", "web1", "--check", "--json"}, "tacctl host show web1 --check"},
		{[]string{"host", "enroll", "root@192.168.1.10", "--name", "web1", "--server", "192.0.2.1"}, "tacctl host enroll web1"},
		{[]string{"host", "target", "web1", "root@192.168.1.11"}, "tacctl host target web1"},
		{[]string{"host", "provisioner", "web1", "rotate", "svc", "--password"}, "tacctl host provisioner web1 rotate"},
		{[]string{"host", "provisioner", "web1", "rotate", "svc", "--key", "/nonexistent/key", "--dry-run"}, "tacctl host provisioner web1 rotate"},
	} {
		sb.run("", c.args)
		errs := sb.stderr()
		if sb.code != 1 || !strings.Contains(errs, "Break-glass is held on host 'web1' (192.168.1.10) since ") || !strings.Contains(errs, ": locked out of sudo.") ||
			!strings.Contains(errs, "'"+c.cmd+"' is refused for a held host: nothing was attempted over ssh and nothing was changed. Release it first: tacctl breakglass release web1") {
			t.Errorf("%v: exit %d %q", c.args, sb.code, errs)
		}
		if n := sb.sshCalls(); n != 0 {
			t.Errorf("%v: %d ssh calls: %v", c.args, n, sb.runner.Argvs())
		}
		if sb.out.String() != "" {
			t.Errorf("%v printed %q", c.args, sb.out.String())
		}
	}
	// 'host move' to another scope is an enroll, and is refused alike.
	sb.run("", []string{"host", "move", "web1", "prod"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "refused for a held host") || sb.sshCalls() != 0 {
		t.Errorf("host move: %d %q", sb.code, sb.stderr())
	}
	// Removal: with and without --force.
	for _, args := range [][]string{{"host", "unenroll", "web1"}, {"host", "unenroll", "web1", "--force"}} {
		sb.run("", args)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Break-glass is held on 'web1': release it first (tacctl breakglass release web1). Nothing was attempted over ssh and nothing was changed.") ||
			sb.sshCalls() != 0 {
			t.Errorf("%v: exit %d %q", args, sb.code, sb.stderr())
		}
	}
	// 'host sync --all' skips it and says why; with nothing else it is done.
	sb.write("state/linux-hosts", "web1|root@192.168.1.10||lab|192.0.2.1|\n", 0o600)
	out := plain(sb.run("", []string{"host", "sync", "--all"}))
	if sb.code != 0 || !strings.Contains(out, "web1: skipped by sync: break-glass is held on it since ") ||
		!strings.Contains(out, "(tacctl breakglass release web1)") || !strings.Contains(out, "No hosts to sync.") || sb.sshCalls() != 0 {
		t.Errorf("sync --all: %d %q %q (%d ssh calls)", sb.code, out, sb.stderr(), sb.sshCalls())
	}
	sb.write("state/linux-hosts", hostLines, 0o600)
	if state() != before {
		t.Error("a refusal changed something")
	}
	// What only reads is allowed: the target is shown.
	if got := plain(sb.run("", []string{"host", "target", "web1"})); sb.code != 0 || !strings.Contains(got, "root@192.168.1.10") {
		t.Errorf("host target show: %d %q", sb.code, got)
	}
	// The held host is released, and the sync is tried again.
	sb.run("", []string{"breakglass", "release", "web1"})
	sb.run("", []string{"host", "sync", "web1"})
	if strings.Contains(sb.stderr(), "refused for a held host") || sb.sshCalls() == 0 {
		t.Errorf("after the release: %d %q (%d ssh calls)", sb.code, sb.stderr(), sb.sshCalls())
	}
}

// A held host among the names typed to 'host sync' refuses the whole run
// before any host is reached (D215); the hosts that are not held are not
// synced either, and an unknown name is refused first.
func TestBreakglassSyncNamesRefusesAHeldHost(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web1", "x")
	before := sb.read("state/linux-hosts")
	for _, args := range [][]string{{"web2", "web1"}, {"web1", "web2"}, {"db1", "web2", "web1"}} {
		sb.run("", append([]string{"host", "sync"}, args...))
		errs := sb.stderr()
		cmd := "tacctl host sync " + strings.Join(args, " ")
		if sb.code != 1 || !strings.Contains(errs, "Break-glass is held on host 'web1' (192.168.1.10) since ") ||
			!strings.Contains(errs, "'"+cmd+"' is refused for a held host: nothing was attempted over ssh and nothing was changed. Release it first: tacctl breakglass release web1") {
			t.Errorf("%v: exit %d %q", args, sb.code, errs)
		}
		if n := sb.sshCalls(); n != 0 {
			t.Errorf("%v: %d ssh calls: %v", args, n, sb.runner.Argvs())
		}
		if sb.out.String() != "" {
			t.Errorf("%v printed %q", args, sb.out.String())
		}
	}
	sb.run("", []string{"host", "sync", "web1", "ghost"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "No enrolled host named 'ghost'. See 'tacctl host list'.") || sb.sshCalls() != 0 {
		t.Errorf("unknown among a held: %d %q (%d ssh calls)", sb.code, sb.stderr(), sb.sshCalls())
	}
	if sb.read("state/linux-hosts") != before {
		t.Error("a refusal changed the registry")
	}
}

// A host sync of the hosts that are not held goes on.
func TestBreakglassSyncAllSkipsOnlyTheHeldHost(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web1", "x")
	out := plain(sb.run("", []string{"host", "sync", "--all"}))
	if !strings.Contains(out, "web1: skipped by sync") {
		t.Errorf("web1 is not skipped: %q", out)
	}
	// db1 and web2 are tried (the fake runner has no host to reach).
	if sb.sshCalls() == 0 {
		t.Error("the other hosts were not tried")
	}
	for _, a := range sb.runner.Argvs() {
		if strings.HasPrefix(a, "ssh ") && strings.Contains(a, "192.168.1.10") {
			t.Errorf("web1 was reached: %s", a)
		}
	}
}

// The engineer sees the holds of the hosts of their own scopes and holds
// nothing.
func TestBreakglassHostEngineerTier(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web1", "lab host")
	holdHost(t, sb, "db1", "prod host")
	before := sb.overrides()
	for _, args := range [][]string{{"breakglass", "hold", "web1", "--reason", "x"}, {"breakglass", "release", "web1"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if sb.overrides() != before {
		t.Error("an engineer's refusal changed tacctl.yaml")
	}
	out := sb.asEngineer("", "breakglass", "list")
	if sb.code != 0 || !strings.Contains(out, "web1") || strings.Contains(out, "db1") {
		t.Errorf("engineer list: %d %q", sb.code, out)
	}
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.asEngineer("", "breakglass", "list", "--json")), &js); err != nil || len(js) != 1 || js[0].Device != "web1" || js[0].Kind != "host" {
		t.Errorf("engineer list --json: %v %+v", err, js)
	}
	if got := sb.asEngineer("", "host", "list"); !strings.Contains(got, "web1") || !strings.Contains(got, "BREAK-GLASS") || strings.Contains(got, "db1") ||
		!strings.Contains(got, "1 host(s) held for break-glass") {
		t.Errorf("host list: %q", got)
	}
	if got := sb.asEngineer("", "host", "show", "web1"); !strings.Contains(got, "HELD since ") {
		t.Errorf("host show: %q", got)
	}
	if got := sb.asEngineer("", "host", "show", "db1"); sb.code != 1 || strings.Contains(got, "HELD") {
		t.Errorf("host show of another scope: %d %q", sb.code, got)
	}
	if got := sb.asEngineer("", "status"); strings.Contains(got, "db1") || !strings.Contains(got, "HELD on web1") {
		t.Errorf("status: %q", got)
	}
	// An engineer does not run --check on any host, held or not.
	sb.asEngineer("", "host", "show", "web1", "--check")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "which is the superuser's") || sb.sshCalls() != 0 {
		t.Errorf("host show --check: %d %q", sb.code, sb.stderr())
	}
}

// A record holds a host only while a host of its name is enrolled at the
// record's address; otherwise it is an orphan, listed and releasable.
func TestBreakglassHostOrphanRecords(t *testing.T) {
	sb := hostLab(t)
	holdHost(t, sb, "web1", "recovery")

	// Re-enrolled by hand at another address.
	sb.write("state/linux-hosts", strings.Replace(hostLines, "192.168.1.10", "192.168.1.11", 1), 0o600)
	list := plain(sb.run("", []string{"breakglass", "list"}))
	for _, want := range []string{"web1 (orphan)", "192.168.1.10",
		"web1 is an orphan record: web1 is enrolled at 192.168.1.11, not at 192.168.1.10, so it holds no registered device or enrolled host, and it still silences 192.168.1.10; 'tacctl breakglass release web1' removes it."} {
		if !strings.Contains(list, want) {
			t.Errorf("list lacks %q:\n%s", want, list)
		}
	}
	var js []holdJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"breakglass", "list", "--json"})), &js); err != nil || len(js) != 1 || !js[0].Orphan || !js[0].Registered || js[0].Kind != "host" {
		t.Errorf("list --json: %v %+v", err, js)
	}
	// It is no hold of the host: shown nowhere on it, and nothing is refused.
	if got := plain(sb.run("", []string{"host", "list"})); strings.Contains(got, "BREAK-GLASS") {
		t.Errorf("host list:\n%s", got)
	}
	if got := plain(sb.run("", []string{"host", "show", "web1"})); strings.Contains(got, "Break-glass") {
		t.Errorf("host show:\n%s", got)
	}
	if got := plain(sb.run("", []string{"status"})); !strings.Contains(got, "Break-glass:        ORPHAN record web1 (192.168.1.10) since ") ||
		!strings.Contains(got, "web1 is enrolled at 192.168.1.11, not at 192.168.1.10; the server does not answer 192.168.1.10") {
		t.Errorf("status:\n%s", got)
	}
	sb.run("", []string{"host", "sync", "web1"})
	if strings.Contains(sb.stderr(), "refused for a held host") {
		t.Errorf("an orphan refused a sync: %q", sb.stderr())
	}
	// A new hold under the name would write over the record: refused.
	sb.hold(t, "web1", "again", "web1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "A break-glass record named 'web1' stands at 192.168.1.10") ||
		!strings.Contains(sb.stderr(), "not at the address the host is recorded at (192.168.1.11)") {
		t.Errorf("hold over an orphan: %d %q", sb.code, sb.stderr())
	}

	// Gone from the registry altogether.
	sb.write("state/linux-hosts", "db1|root@10.99.0.20||prod|192.0.2.1|\n", 0o600)
	list = plain(sb.run("", []string{"breakglass", "list"}))
	if !strings.Contains(list, "web1 (orphan)") || !strings.Contains(list, "no device or host of that name is registered") {
		t.Errorf("list of an unenrolled host:\n%s", list)
	}
	out := plain(sb.run("", []string{"breakglass", "release", "web1"}))
	if sb.code != 0 || !strings.Contains(out, "Break-glass RELEASED on web1 (192.168.1.10)") || strings.Contains(sb.overrides(), "breakglass_hold") {
		t.Errorf("release: %d %q %q", sb.code, out, sb.stderr())
	}
}

// A host is held by its name: an address that is only its ssh target's is
// not found, and is said to be the host's.
func TestBreakglassHostIsHeldByName(t *testing.T) {
	sb := hostLab(t)
	before := sb.overrides()
	for _, addr := range []string{"192.168.1.10", "10.99.0.20"} {
		name := map[string]string{"192.168.1.10": "web1", "10.99.0.20": "db1"}[addr]
		holdTTY(t, sb, addr+"\n")
		sb.run("", []string{"breakglass", "hold", addr, "--reason", "x"})
		sb.tty = nil
		want := "that address belongs to the enrolled host '" + name + "'; hold it by name (tacctl breakglass hold " + name + "). Nothing was changed."
		if sb.code != 1 || !strings.Contains(sb.stderr(), want) || strings.Contains(sb.stderr(), "not found") {
			t.Errorf("%s: %d %q", addr, sb.code, sb.stderr())
		}
	}
	// An address that is nobody's stays not found.
	sb.run("", []string{"breakglass", "hold", "192.168.7.7", "--reason", "x"})
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Device '192.168.7.7' not found") {
		t.Errorf("an unknown address: %d %q", sb.code, sb.stderr())
	}
	if sb.overrides() != before || sb.restarts() != 0 {
		t.Error("a refusal changed something")
	}
}

// A registry that cannot be read does not say a host is not held: what logs
// in to a host is refused, since the address of its hold is in it.
func TestBreakglassHostHoldUnreadableRegistry(t *testing.T) {
	sb := hostLab(t)
	// web2 is held at the address a sync recorded, which its ssh target
	// (a name) does not give.
	holdHost(t, sb, "web2", "x")
	sb.write("state/devices.yaml", "devices: [\n", 0o600)
	for _, c := range []struct {
		args []string
		host string
	}{
		{[]string{"host", "sync", "web2"}, "web2"},
		{[]string{"host", "sync", "--all"}, "web1"},
		{[]string{"host", "target", "web2", "root@192.168.1.11"}, "web2"},
		{[]string{"host", "unenroll", "web2"}, "web2"},
		{[]string{"host", "show", "web2", "--check"}, "web2"},
		{[]string{"host", "provisioner", "web2", "rotate", "svc", "--password"}, "web2"},
		{[]string{"host", "enroll", "root@web2.example.net", "--name", "web2", "--server", "192.0.2.1"}, "web2"},
	} {
		sb.run("", c.args)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The device registry cannot be read, so the break-glass hold on "+c.host+" cannot be checked; nothing was attempted.") ||
			sb.sshCalls() != 0 {
			t.Errorf("%v: exit %d %q (%d ssh calls)", c.args, sb.code, sb.stderr(), sb.sshCalls())
		}
	}
}
