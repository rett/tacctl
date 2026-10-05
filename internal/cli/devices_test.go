package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// 'config cisco|juniper|wti' in-process: the argument parsing, scope and
// protocol resolution, the RADIUS refusals and the wiring. The output bytes
// are pinned by internal/devices against the goldens and by
// config_templates.bats, config_radius.bats and tests/diff/corpus/devices.txt
// against 0.1.16.

// route scripts the server-address lookup the goldens use.
func route(r *fake.Runner) {
	r.On([]string{"ip", "-4", "route", "get", "1.0.0.0"},
		execx.Result{Stdout: []byte("1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0\n")})
}

func TestDeviceVerbsAreNative(t *testing.T) {
	inv := &invocation{app: newHarness(t, nil).app}
	c := configCmd(inv)
	for _, v := range []string{"cisco", "juniper", "wti"} {
		sub := child(c, v)
		if sub == nil || sub.RunE == nil {
			t.Errorf("config %s is not native", v)
			continue
		}
		if !strings.HasPrefix(sub.Use, v+" [--scope <name>]") || sub.Short == "" {
			t.Errorf("config %s: Use %q Short %q", v, sub.Use, sub.Short)
		}
		spec := configSpecs[v]
		want := 4
		if v == "cisco" {
			want = 5
		}
		if len(spec.Flags) != want || spec.Flags[0].Kind != KindScopes || spec.Flags[1].Kind != "tacacs|radius" {
			t.Errorf("config %s: spec %+v", v, spec)
		}
	}
}

func TestDeviceConfigRenders(t *testing.T) {
	sb := newSandbox(t, true)
	out := sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route)
	sb.expect(0, "Cisco IOS / IOS-XE Configuration  (scope: lab)", "")
	golden, err := os.ReadFile("../../tests/fixtures/golden/cisco-lab.conf")
	if err != nil {
		t.Fatal(err)
	}
	if plain(out) != string(golden) {
		t.Errorf("config cisco --scope lab is not the golden:\n%s", out)
	}
	if !sb.runner.Called("ip", "-4", "route", "get", "1.0.0.0") {
		t.Error("the server address was not looked up")
	}
	// Without --scope: the default scope (the shipped default is lab).
	sb.cfgRun("", []string{"config", "juniper"}, route)
	sb.expect(0, "Juniper Junos Configuration  (scope: lab)", "")
	sb.run("", []string{"scope", "default", "prod"})
	sb.cfgRun("", []string{"config", "wti"}, route)
	sb.expect(0, "WTI Console Server Configuration  (scope: prod, firmware v8.x text interface)", "")
	// A default that names no scope, with several scopes: refused.
	if err := os.WriteFile(filepath.Join(sb.dir, "state", "tacctl.yaml"), []byte("scope:\n  default: gone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out = sb.cfgRun("", []string{"config", "juniper"}, route)
	if sb.code != 1 || out != "" || !strings.Contains(plain(sb.err.String()), "[ERROR] No default scope set and no --scope provided.\n[ERROR] Run 'tacctl scope default <name>' or pass --scope <name>.\n") {
		t.Errorf("no default: %d %q %q", sb.code, out, sb.err.String())
	}
}

func TestDeviceConfigArguments(t *testing.T) {
	sb := newSandbox(t, true)
	usage := "Usage: tacctl config juniper [--scope <name>] [--protocol tacacs|radius] [--staging <bench-ip> [--name <device>]]   (without --protocol: the scope's auth-method, else its only protocol, else tacacs)"
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"juniper", "--scope"}, "[ERROR] " + usage},
		{[]string{"juniper", "--protocol"}, "[ERROR] " + usage},
		{[]string{"juniper", "--legacy"}, "[ERROR] Unknown argument: '--legacy'\n\x1b[0;31m[ERROR]\x1b[0m " + usage},
		{[]string{"juniper", "--scope=lab"}, "[ERROR] Unknown argument: '--scope=lab'"},
		{[]string{"wti", "--protocol", "ldap", "--scope", "nosuch"}, "[ERROR] Unknown protocol 'ldap'. Known protocols: tacacs, radius"},
		{[]string{"cisco", "--scope", "nosuch"}, "[ERROR] Scope 'nosuch' does not exist. Available: prod-inner prod lab dmz"},
		{[]string{"cisco", "--legacy", "--protocol", "radius", "--scope", "nosuch"},
			"[ERROR] --legacy (IOS 12.x syntax) applies to TACACS+ only; the RADIUS configuration uses the structured 'radius server' block (IOS 15.2 / IOS-XE and later)."},
		{[]string{"cisco", "--scope", "lab", "--protocol", "radius"},
			"[ERROR] The RADIUS backend is not enabled, so nothing on this server answers RADIUS requests and this configuration would not work."},
	} {
		out := sb.cfgRun("", append([]string{"config"}, c.args...), route)
		if sb.code != 1 || out != "" || !strings.Contains(plain(sb.err.String()), plain(c.err)) {
			t.Errorf("%q: exit %d, stdout %q, stderr %q", c.args, sb.code, out, sb.err.String())
		}
	}
	// The scope's auth-method radius and --legacy: refused, with the way out.
	sb.run("", []string{"scope", "auth-method", "lab", "radius"})
	sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--legacy"}, route)
	sb.expect(1, "", "Scope 'lab' has auth-method radius (tacctl scope auth-method), and --legacy (IOS 12.x syntax) applies to TACACS+ only.")
	sb.expect(1, "", "tacctl config cisco --scope lab --legacy --protocol tacacs")
	sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--legacy", "--protocol", "tacacs"}, route)
	sb.expect(0, "tacacs-server host 10.0.0.42 single-connection timeout 5 key lab-secret-0123456789abcdef", "")
}

func TestDeviceConfigRadius(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "cisco,juniper"})
	if err := os.WriteFile(filepath.Join(sb.dir, "state", "tacctl.yaml"),
		[]byte("backends:\n  enabled: [tacacs, radius]\nlisteners:\n  radius:\n    auth: {network: udp, address: \"10.0.0.77:1645\", role: auth}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := sb.cfgRun("", []string{"config", "cisco", "--scope", "lab", "--protocol", "radius"}, route)
	sb.expect(0, "Cisco IOS / IOS-XE Configuration  (scope: lab, protocol: RADIUS)", "")
	for _, want := range []string{"  address ipv4 10.0.0.77 auth-port 1645 acct-port 1813\n", "  key lab-secret-0123456789abcdef\n",
		"allow UDP 1645 (authentication) and 1813 (accounting)", "  - Using template: built-in cisco-radius.template\n"} {
		if !strings.Contains(plain(out), want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	// WTI is not enabled for the scope: refused, nothing on stdout.
	out = sb.cfgRun("", []string{"config", "wti", "--scope", "lab", "--protocol", "radius"}, route)
	if sb.code != 1 || out != "" || !strings.Contains(sb.err.String(), "Scope 'lab' sends no WTI attribute over RADIUS (WTI-Super)") {
		t.Errorf("wti: %d %q %q", sb.code, out, sb.err.String())
	}
	// A backends.enabled naming an unknown backend.
	if err := os.WriteFile(filepath.Join(sb.dir, "state", "tacctl.yaml"), []byte("backends:\n  enabled: [tacacs, ldap]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sb.cfgRun("", []string{"config", "juniper", "--scope", "lab", "--protocol", "radius"}, route)
	if sb.code != 1 || !strings.Contains(sb.err.String(), "backends.enabled names 'ldap'") {
		t.Errorf("unknown backend: %d %q", sb.code, sb.err.String())
	}
}

// Preflight: without a store or a tacquito.yaml the verbs stop there.
func TestDeviceConfigPreflight(t *testing.T) {
	sb := newSandbox(t, false)
	sb.cfgRun("", []string{"config", "cisco", "--scope", "lab"}, route)
	if sb.code != 1 || sb.out.String() != "" || sb.runner.Called("ip") {
		t.Errorf("exit %d, stdout %q, ip called %v", sb.code, sb.out.String(), sb.runner.Called("ip"))
	}
}
