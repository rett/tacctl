package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/snmp"
)

// scaleInv is an invocation on the sandbox's files, to read the scale in force
// the way a verb does.
func (sb *sandbox) scaleInv() *invocation {
	sb.t.Helper()
	runner := &fake.Runner{}
	runner.On([]string{"systemctl"}, execx.Result{})
	runner.On([]string{"logger"}, execx.Result{})
	a := app.New(nil, paths.NewEnv(sb.env), "/opt/x/dist/tacctl", 1000,
		app.Stdio{Stdin: strings.NewReader(""), Stdout: &sb.out, Stderr: &sb.err}, runner)
	a.Paths = a.Paths.Reroot(sb.dir)
	return &invocation{ctx: sb.t.Context(), app: a, hooks: sb.hooks}
}

// The timing scale (0.2.22): the order of resolution, the bounds of what it
// scales, the three verbs and what they write and show.

// The device's own value wins over its scope's, the scope's over the
// server's, and 1 is what is left; a level that is not set (0) or is no scale
// (a hand-edited file) is skipped.
func TestResolveTimeoutScale(t *testing.T) {
	for name, tc := range map[string]struct {
		own, scope, global int
		n                  int
		from               string
	}{
		"nothing is 1, built in":           {n: 1, from: scaleFromBuiltIn},
		"the server's":                     {global: 3, n: 3, from: scaleFromGlobal},
		"the scope's over the server's":    {scope: 4, global: 3, n: 4, from: scaleFromScope},
		"the device's over both":           {own: 5, scope: 4, global: 3, n: 5, from: scaleFromDevice},
		"the device's alone":               {own: 2, n: 2, from: scaleFromDevice},
		"a device that asks for 1":         {own: 1, scope: 4, global: 3, n: 1, from: scaleFromDevice},
		"the top of the range":             {own: 10, n: 10, from: scaleFromDevice},
		"above the range is skipped":       {own: 11, scope: 4, n: 4, from: scaleFromScope},
		"negative is skipped":              {own: -3, scope: 0, global: 2, n: 2, from: scaleFromGlobal},
		"nothing valid is 1":               {own: 99, scope: -1, global: 12, n: 1, from: scaleFromBuiltIn},
		"a scope that decided over global": {scope: 1, global: 7, n: 1, from: scaleFromScope},
	} {
		t.Run(name, func(t *testing.T) {
			got := resolveTimeoutScale(tc.own, tc.scope, tc.global)
			if got.N != tc.n || got.From != tc.from {
				t.Errorf("resolveTimeoutScale(%d, %d, %d) = %+v, want %d from %s", tc.own, tc.scope, tc.global, got, tc.n, tc.from)
			}
		})
	}
}

// The per-device time of a pull or an apply is scaled and kept inside its
// bounds (10 to 600 s): the clamp is documented, and scale 1 is the setting.
func TestScaledDeviceTimeoutIsClamped(t *testing.T) {
	for _, tc := range []struct {
		base  time.Duration
		scale int
		want  time.Duration
	}{
		{90 * time.Second, 1, 90 * time.Second},
		{90 * time.Second, 3, 270 * time.Second},
		{90 * time.Second, 6, 540 * time.Second},
		{90 * time.Second, 7, 600 * time.Second},
		{90 * time.Second, 10, 600 * time.Second},
		{600 * time.Second, 1, 600 * time.Second},
		{600 * time.Second, 2, 600 * time.Second},
		{10 * time.Second, 1, 10 * time.Second},
		{10 * time.Second, 10, 100 * time.Second},
		{5 * time.Second, 1, 10 * time.Second},
		{90 * time.Second, 0, 90 * time.Second},
		{90 * time.Second, -4, 90 * time.Second},
		{90 * time.Second, 50, 600 * time.Second},
	} {
		if got := scaledDeviceTimeout(tc.base, tc.scale); got != tc.want {
			t.Errorf("scaledDeviceTimeout(%v, %d) = %v, want %v", tc.base, tc.scale, got, tc.want)
		}
	}
}

// The SNMP timeout is scaled and never above its documented maximum.
func TestScaledSNMPTimeoutStopsAtItsMaximum(t *testing.T) {
	for _, tc := range []struct{ secs, scale, want int }{
		{2, 1, 2}, {2, 3, 6}, {2, 5, 10}, {2, 6, 10}, {2, 10, 10}, {10, 1, 10}, {10, 2, 10}, {1, 10, 10}, {4, 0, 4}, {4, -2, 4},
	} {
		if got := scaledSNMPTimeout(tc.secs, tc.scale); got != tc.want || got > snmp.MaxTimeout {
			t.Errorf("scaledSNMPTimeout(%d, %d) = %d, want %d", tc.secs, tc.scale, got, tc.want)
		}
	}
}

func TestTimeoutScaleVerbs(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"sat-j", "192.168.1.20", "juniper"}, [3]string{"sat-c", "192.168.1.30", "cisco"})
	sb := b.sb

	// Nothing is set: every timing is as it was, and a read writes nothing.
	out := plain(sb.dev("", "timeout-scale", "sat-j"))
	for _, w := range []string{"Timeout scale of device 'sat-j': 1", "built in: no scale is set", "Every timing is as it has always been."} {
		if sb.code != 0 || !strings.Contains(out, w) {
			t.Errorf("device read lacks %q: %d\n%s", w, sb.code, out)
		}
	}
	if strings.Contains(sb.overrides(), "timeout_scale") || strings.Contains(sb.devices(), "timeout_scale") {
		t.Error("a read wrote a file")
	}
	// device show, list --json and scope show say nothing of a scale of 1
	if show := plain(sb.dev("", "show", "sat-j")); strings.Contains(show, "Timeout scale") {
		t.Errorf("device show names a scale of 1:\n%s", show)
	}
	if strings.Contains(sb.dev("", "list", "--json"), "timeout_scale") || strings.Contains(sb.dev("", "show", "sat-j", "--json"), "timeout_scale") {
		t.Error("--json names a scale of 1")
	}
	if out := plain(sb.cfgRun("", []string{"scope", "show", "lab"}, nil)); strings.Contains(out, "Timeout scale") {
		t.Errorf("scope show names a scale of 1:\n%s", out)
	}

	// The server's scale.
	sb.cfgRun("", []string{"config", "devices", "timeout-scale", "2"}, nil)
	sb.said(0, "The timeout scale of the whole server set to 2.")
	if o := sb.overrides(); !strings.Contains(o, "timeout_scale: 2") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if out := plain(sb.cfgRun("", []string{"config", "devices", "show"}, nil)); !strings.Contains(out, "timeout-scale:   2   (set;") {
		t.Errorf("config devices show:\n%s", out)
	}
	if out := plain(sb.cfgRun("", []string{"config", "devices", "timeout-scale"}, nil)); !strings.Contains(out, "Timeout scale: 2") {
		t.Errorf("config devices timeout-scale:\n%s", out)
	}
	for _, bad := range []string{"0", "11", "-1", "fast", "2.5"} {
		sb.cfgRun("", []string{"config", "devices", "timeout-scale", bad}, nil)
		if sb.code == 0 {
			t.Errorf("config devices timeout-scale %s accepted", bad)
		}
	}
	// a device follows it
	out = plain(sb.dev("", "timeout-scale", "sat-j"))
	if !strings.Contains(out, "Timeout scale of device 'sat-j': 2  (the default of the whole server, device.timeout_scale)") {
		t.Errorf("device read:\n%s", out)
	}
	show := plain(sb.dev("", "show", "sat-j"))
	if !strings.Contains(show, "Timeout scale: 2  (the default of the whole server, device.timeout_scale)") {
		t.Errorf("device show:\n%s", show)
	}

	// The scope's scale wins over the server's, and the read says what it makes
	// of the timings, with the SNMP maximum and the pull bounds.
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "6"}, nil)
	sb.said(0, "Scope 'lab' timeout scale: 6.")
	if o := sb.overrides(); !strings.Contains(o, "timeout_scale_scope:") || !strings.Contains(o, "lab: 6") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	out = plain(sb.cfgRun("", []string{"scope", "timeout-scale", "lab"}, nil))
	for _, w := range []string{"Timeout scale of scope 'lab': 6  (the scope's own)",
		"ssh and NETCONF connect:    60 s", "ssh-keyscan 30 s, one type 18 s", "handshake 60 s",
		"SNMP timeout:               10 s  (2 s x 6, held to the most SNMP takes; at most 10 s)",
		"pull and apply, a device:   540 s  (90 s x 6; between 10 s and 600 s; --timeout of a run replaces it)",
		"not scaled:                 the confirmed-commit windows"} {
		if !strings.Contains(out, w) {
			t.Errorf("scope read lacks %q:\n%s", w, out)
		}
	}
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "6"}, nil)
	sb.said(0, "timeout scale is 6 already; nothing was changed")
	if out := plain(sb.cfgRun("", []string{"scope", "show", "lab"}, nil)); !strings.Contains(out, "Timeout scale:  6  (the scope's own)") {
		t.Errorf("scope show:\n%s", out)
	}

	// The device's own wins over both, with its JSON.
	sb.dev("", "timeout-scale", "sat-j", "3")
	sb.said(0, "Device 'sat-j' timeout scale: 3.")
	if d := sb.devices(); !strings.Contains(d, "timeout_scale: 3") {
		t.Errorf("devices.yaml:\n%s", d)
	}
	out = plain(sb.dev("", "timeout-scale", "sat-j"))
	for _, w := range []string{"Timeout scale of device 'sat-j': 3  (the device's own)", "SNMP timeout:               6 s  (2 s x 3; at most 10 s)",
		"pull and apply, a device:   270 s"} {
		if !strings.Contains(out, w) {
			t.Errorf("device read lacks %q:\n%s", w, out)
		}
	}
	var j struct {
		TimeoutScale *struct {
			Scale int    `json:"scale"`
			From  string `json:"from"`
		} `json:"timeout_scale"`
	}
	if err := json.Unmarshal([]byte(sb.dev("", "show", "sat-j", "--json")), &j); err != nil || j.TimeoutScale == nil || j.TimeoutScale.Scale != 3 || j.TimeoutScale.From != "device" {
		t.Errorf("device show --json: %v %+v", err, j.TimeoutScale)
	}
	// the other device follows its scope; the list says so as JSON
	var list []struct {
		Name         string `json:"name"`
		TimeoutScale *struct {
			Scale int    `json:"scale"`
			From  string `json:"from"`
		} `json:"timeout_scale"`
	}
	if err := json.Unmarshal([]byte(sb.dev("", "list", "--json")), &list); err != nil || len(list) != 2 {
		t.Fatalf("device list --json: %v %d", err, len(list))
	}
	for _, d := range list {
		want, from := 6, "scope"
		if d.Name == "sat-j" {
			want, from = 3, "device"
		}
		if d.TimeoutScale == nil || d.TimeoutScale.Scale != want || d.TimeoutScale.From != from {
			t.Errorf("list --json %s: %+v, want %d from %s", d.Name, d.TimeoutScale, want, from)
		}
	}
	sb.dev("", "timeout-scale", "sat-j", "3")
	sb.said(0, "timeout scale is 3 already; nothing was changed")

	// Refusals: a value that is no scale, an unknown device, an unknown scope.
	for _, bad := range []string{"0", "11", "x", "1.5", "03", "clearr"} {
		sb.dev("", "timeout-scale", "sat-j", bad)
		sb.said(1, "The timeout scale is a whole number from 1 to 10, or clear: '"+bad+"'")
		sb.cfgRun("", []string{"scope", "timeout-scale", "lab", bad}, nil)
		sb.said(1, "The timeout scale is a whole number from 1 to 10, or clear: '"+bad+"'")
	}
	sb.dev("", "timeout-scale", "sat-j", "-2")
	sb.said(1, "Unknown option: '-2'")
	sb.dev("", "timeout-scale", "nowhere", "2")
	sb.said(1, "not found")
	sb.cfgRun("", []string{"scope", "timeout-scale", "nowhere", "2"}, nil)
	sb.said(1, "does not exist")

	// clear: the next level decides again
	sb.dev("", "timeout-scale", "sat-j", "clear")
	sb.said(0, "follows its scope's timeout scale again")
	if strings.Contains(sb.devices(), "timeout_scale") {
		t.Errorf("the device's scale stayed:\n%s", sb.devices())
	}
	sb.dev("", "timeout-scale", "sat-j", "clear")
	sb.said(0, "has no timeout scale of its own already")
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "clear"}, nil)
	sb.said(0, "follows the server's timeout scale again (2)")
	if strings.Contains(sb.overrides(), "timeout_scale_scope") {
		t.Errorf("the scope's scale stayed:\n%s", sb.overrides())
	}
	sb.cfgRun("", []string{"scope", "timeout-scale", "lab", "clear"}, nil)
	sb.said(0, "has no timeout scale of its own already")

	// an enrolled Linux host has no scale of its own
	// (the registry here has none; a name that is no device is not found)
}

// A scope's scale follows its rename and goes with its removal, as its other
// keys do.
func TestTimeoutScaleFollowsTheScope(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"scope", "timeout-scale", "dmz", "5"}, nil)
	sb.said(0, "Scope 'dmz' timeout scale: 5.")
	sb.run("", []string{"scope", "rename", "dmz", "edge"})
	sb.said(0, "Scope renamed: dmz -> edge")
	if o := sb.overrides(); strings.Contains(o, "dmz") || !strings.Contains(o, "edge: 5") {
		t.Errorf("tacctl.yaml after the rename:\n%s", o)
	}
	sb.run("y\n", []string{"scope", "remove", "edge", "--force"})
	sb.said(0, "Scope 'edge' removed.")
	if strings.Contains(sb.overrides(), "timeout_scale") {
		t.Errorf("the key stayed after the removal:\n%s", sb.overrides())
	}
}

// 'config validate' checks the three places: a device's, a scope's and the
// server's.
func TestConfigValidateChecksTheTimeoutScale(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "device:\n  timeout_scale: 11\ntimeout_scale_scope:\n  lab: 0\n  gone: 3\n", 0o640)
	sb.cfgRun("", []string{"config", "validate"}, nil)
	all := sb.stderr() + sb.out.String()
	if sb.code == 0 || !strings.Contains(all, "device.timeout_scale") || !strings.Contains(all, "timeout_scale_scope.lab") {
		t.Errorf("validate: %d\n%s", sb.code, all)
	}
	// a scope that does not exist is an orphan key
	if !strings.Contains(all, "timeout_scale_scope.gone") {
		t.Errorf("validate does not name the orphan scope:\n%s", all)
	}
	sb2 := newSandbox(t, true)
	sb2.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n  sw1:\n    address: 192.0.2.5\n    vendor: cisco\n    timeout_scale: 12\n", 0o600)
	sb2.cfgRun("", []string{"config", "validate"}, nil)
	all = sb2.stderr() + sb2.out.String()
	if sb2.code == 0 || !strings.Contains(all, "Invalid timeout_scale 12") {
		t.Errorf("validate of a device: %d\n%s", sb2.code, all)
	}
}
