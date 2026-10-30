package cli

// The server's port follows 'tacctl server listen' in everything that
// renders or compares it: the device walkthroughs, what a pull is compared
// with, the plan and the host script. These run a TACACS+ listener on
// tcp :4949 and RADIUS ones on udp :11812 and :11813; with the default
// listeners the output is what it always was (the goldens of
// devices_test.go and the bats suite).

import (
	"strings"
	"testing"
)

// listenMoved moves the listeners of the sandbox: tcp :4949 for TACACS+,
// udp :11812 and :11813 for RADIUS (enabled beside it).
func listenMoved(t *testing.T, sb *sandbox) {
	t.Helper()
	sb.run("", []string{"server", "listen", "tcp", ":4949"})
	if sb.code != 0 {
		t.Fatalf("server listen tcp :4949: %d %q", sb.code, sb.stderr())
	}
}

func TestWalkthroughsFollowTheTACACSListener(t *testing.T) {
	sb := newSandbox(t, true)
	listenMoved(t, sb)
	for _, c := range []struct {
		args []string
		want []string
	}{
		{[]string{"config", "cisco", "--scope", "lab"}, []string{"tacacs server TACACS\n  address ipv4 10.0.0.42\n  port 4949\n  key "}},
		{[]string{"config", "juniper", "--scope", "lab"}, []string{"set system tacplus-server 10.0.0.42 port 4949\n"}},
		{[]string{"config", "wti", "--scope", "lab"}, []string{"7. Authentication Port        : 4949\n", "does NOT prove TCP/4949 works"}},
	} {
		out := plain(sb.cfgRun("", c.args, route))
		sb.expect(0, "", "")
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%v: no %q in\n%s", c.args, w, out)
			}
		}
	}
}

// Without a moved listener the walkthroughs write no port statement: the
// goldens of TestDeviceConfigRenders and bats' config_templates are that, byte
// for byte; this names the statements.
func TestWalkthroughsWriteNoPortForTheDefaultListener(t *testing.T) {
	sb := newSandbox(t, true)
	for _, c := range []struct {
		args []string
		port string
	}{
		{[]string{"config", "cisco", "--scope", "lab"}, "\n  port "},
		{[]string{"config", "cisco", "--scope", "lab", "--legacy"}, " port "},
		{[]string{"config", "juniper", "--scope", "lab"}, "tacplus-server 10.0.0.42 port "},
		{[]string{"config", "wti", "--scope", "lab"}, "Authentication Port        : 4949"},
	} {
		if out := plain(sb.cfgRun("", c.args, route)); strings.Contains(out, c.port) {
			t.Errorf("%v: %q in\n%s", c.args, c.port, out)
		}
	}
}

// A pull that carries the moved port is in step with the rendering, and one
// that carries the old port (49) is a difference: the diff names both sides
// and the plan types the right one, for each vendor.
func TestPullAndPlanFollowTheTACACSListener(t *testing.T) {
	t.Run("cisco", func(t *testing.T) {
		b := newPullBox(t)
		listenMoved(t, b.sb)
		b.ciscoDevice("")
		text := b.expected("lab-c")
		if !strings.Contains(text, "\n  address ipv4 10.0.0.42\n  port 4949\n  key ") {
			t.Fatalf("the expected text has no port:\n%s", text)
		}
		b.serve("cisco", text)
		if out := b.run("device", "config", "pull", "lab-c", "--diff"); !strings.Contains(out, "1 ok") || strings.Contains(out, "differ") {
			t.Errorf("the moved port is not in step:\n%s", out)
		}
		// the device still has the old port
		b.serve("cisco", strings.Replace(text, "  port 4949\n", "  port 49\n", 1))
		out := b.run("device", "config", "pull", "lab-c", "--diff")
		for _, want := range []string{"1 differ", "- tacacs server TACACS > port 4949", "+ tacacs server TACACS > port 49"} {
			if !strings.Contains(out, want) {
				t.Errorf("diff: no %q in\n%s", want, out)
			}
		}
		plan := b.run("device", "config", "plan", "lab-c")
		for _, want := range []string{"different: the server TACACS: port 4949 (the device has: the server TACACS: port 49)",
			"\ntacacs server TACACS\n port 4949\nend\n"} {
			if !strings.Contains(plan, want) && !strings.Contains(unwrapPlan(plan), want) {
				t.Errorf("plan: no %q in\n%s", want, plan)
			}
		}
		// a device that has no port line at all is told it
		b.serve("cisco", strings.Replace(text, "  port 4949\n", "", 1))
		b.run("device", "config", "pull", "lab-c")
		if plan = b.run("device", "config", "plan", "lab-c"); !strings.Contains(plan, "\ntacacs server TACACS\n port 4949\nend\n") {
			t.Errorf("missing port:\n%s", plan)
		}
	})
	t.Run("cisco ios12", func(t *testing.T) {
		b := newPullBox(t)
		listenMoved(t, b.sb)
		b.ciscoDevice("")
		b.run("device", "ios-syntax", "lab-c", "ios12")
		text := b.expected("lab-c")
		if !strings.Contains(text, "tacacs-server host 10.0.0.42 single-connection port 4949 timeout 5 key ") {
			t.Fatalf("the expected text has no port:\n%s", text)
		}
		b.serve("cisco", text)
		b.version(ciscoVersion12)
		if out := b.run("device", "config", "pull", "lab-c", "--diff"); !strings.Contains(out, "1 ok") || strings.Contains(out, "differ") {
			t.Errorf("the moved port is not in step:\n%s", out)
		}
		b.serve("cisco", strings.Replace(text, " single-connection port 4949 timeout", " single-connection timeout", 1))
		b.version(ciscoVersion12)
		out := b.run("device", "config", "pull", "lab-c", "--diff")
		if !strings.Contains(out, "1 differ") || !strings.Contains(out, "port 4949") {
			t.Errorf("diff:\n%s", out)
		}
	})
	t.Run("juniper", func(t *testing.T) {
		b := newPullBox(t)
		listenMoved(t, b.sb)
		b.devices([3]string{"lab-j", "192.168.1.20", "juniper"})
		text := b.expected("lab-j")
		if !strings.Contains(text, "set system tacplus-server 10.0.0.42 port 4949\n") {
			t.Fatalf("the expected text has no port:\n%s", text)
		}
		b.serve("juniper", text)
		if out := b.run("device", "config", "pull", "lab-j", "--diff"); !strings.Contains(out, "1 ok") || strings.Contains(out, "differ") {
			t.Errorf("the moved port is not in step:\n%s", out)
		}
		b.serve("juniper", strings.Replace(text, "tacplus-server 10.0.0.42 port 4949", "tacplus-server 10.0.0.42 port 49", 1))
		out := b.run("device", "config", "pull", "lab-j", "--diff")
		for _, want := range []string{"1 differ", "- set system tacplus-server 10.0.0.42 port 4949", "+ set system tacplus-server 10.0.0.42 port 49"} {
			if !strings.Contains(out, want) {
				t.Errorf("diff: no %q in\n%s", want, out)
			}
		}
		plan := b.run("device", "config", "plan", "lab-j")
		for _, want := range []string{"configure exclusive\n# aaa: tacctl's TACACS+ server\nset system tacplus-server 10.0.0.42 port 4949\n"} {
			if !strings.Contains(plan, want) {
				t.Errorf("plan: no %q in\n%s", want, plan)
			}
		}
	})
	t.Run("wti", func(t *testing.T) {
		b := newWTIBox(t, "administrator", 0)
		listenMoved(t, b.sb)
		b.devices([3]string{"pdu1", "192.168.1.40", "wti"})
		// the unit's page says 49: the plan types the listener's port
		out := b.run("device", "config", "pull", "pdu1", "--diff")
		for _, want := range []string{"- tacacs port 4949", "+ tacacs port 49"} {
			if !strings.Contains(out, want) {
				t.Errorf("diff: no %q in\n%s", want, out)
			}
		}
		plan := b.run("device", "config", "plan", "pdu1")
		if !strings.Contains(unwrapPlan(plan), "Authentication Port") || !strings.Contains(unwrapPlan(plan), "-> 4949") {
			t.Errorf("plan:\n%s", plan)
		}
		noSecrets(t, "output", out+plan+b.storeText(), wtiSentinels...)
	})
}

// The host script is written for the listener's port: the header's TAC_PORT
// (and TAC_ACCT_PORT for RADIUS) is what pam_tacplus's server=ADDR:PORT and
// pam_radius_auth's server file are built from; the command says it too.
func TestLinuxScriptFollowsTheListeners(t *testing.T) {
	sb := newSandbox(t, true)
	sandboxTarball(t, sb)
	listenMoved(t, sb)
	out := sb.path("tacplus.sh")
	said := plain(sb.cfgRun("", []string{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "-o", out}, nil))
	if data := sb.read("tacplus.sh"); sb.code != 0 || !strings.Contains(data, "\nTAC_PORT=4949\n") {
		t.Errorf("tacplus: %d %q\n%s", sb.code, sb.stderr(), head(data))
	}
	if !strings.Contains(said, "Server:  192.0.2.1 port 4949") {
		t.Errorf("the command does not say the port:\n%s", said)
	}

	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  tacacs:\n    default: {network: tcp, address: \":4949\"}\n"+
		"  radius:\n    auth: {network: udp, address: \":11812\", role: auth}\n    acct: {network: udp, address: \":11813\", role: acct}\n", 0o600)
	out = sb.path("radius.sh")
	sb.cfgRun("", []string{"config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "--method", "radius", "-o", out}, nil)
	if data := sb.read("radius.sh"); sb.code != 0 || !strings.Contains(data, "\nTAC_PORT=11812\n") || !strings.Contains(data, "\nTAC_ACCT_PORT=11813\n") {
		t.Errorf("radius: %d %q\n%s", sb.code, sb.stderr(), head(data))
	}
}

// A RADIUS walkthrough names the listeners' ports and, where it contrasts the
// protocols, the TACACS+ one.
func TestRadiusWalkthroughsFollowTheListeners(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "vendor-attrs", "lab", "enable", "cisco,juniper,wti"})
	sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\nlisteners:\n  tacacs:\n    default: {network: tcp, address: \":4949\"}\n"+
		"  radius:\n    auth: {network: udp, address: \":11812\", role: auth}\n    acct: {network: udp, address: \":11813\", role: acct}\n", 0o600)
	for _, c := range []struct {
		vendor string
		want   []string
	}{
		{"cisco", []string{"  address ipv4 10.0.0.42 auth-port 11812 acct-port 11813\n", "UDP, not TCP/4949: allow UDP 11812 (authentication) and 11813 (accounting)"}},
		{"juniper", []string{"set system radius-server 10.0.0.42 port 11812\n", "set system radius-server 10.0.0.42 accounting-port 11813\n", "UDP, not TCP/4949: allow UDP 11812"}},
		{"wti", []string{"Authentication Port           : 11812\n", "Accounting Port               : 11813\n", "UDP, not TCP/4949: the unit sends to 11812 (authentication) and 11813 (accounting)"}},
	} {
		out := plain(sb.cfgRun("", []string{"config", c.vendor, "--scope", "lab", "--protocol", "radius"}, route))
		sb.expect(0, "", "")
		for _, w := range c.want {
			if !strings.Contains(out, w) {
				t.Errorf("%s: no %q in\n%s", c.vendor, w, out)
			}
		}
		if strings.Contains(out, "TCP/49:") {
			t.Errorf("%s: the default TACACS+ port is named:\n%s", c.vendor, out)
		}
	}
}

// 'config validate' and 'status' are as they were with listeners that moved:
// the rendered files are the store's, and the socket probed is the listener's.
func TestValidateAndStatusWithMovedListeners(t *testing.T) {
	s := newSectionsSandbox(t, true)
	s.run("", "server", "listen", "tcp", ":4949")
	s.expect(0, "Listener changed to tcp :4949", "")
	s.tcp = "LISTEN 0 128 *:4949 *:* users:((\"tacquito\",pid=4242,fd=3))\n"
	out := s.run("", "config", "validate")
	s.expect(0, "", "")
	mustMatch(t, "validate", out, `Rendered config:.* up to date`)
	mustNotContain(t, "validate", s.all(), "DRIFT", "[ERROR]")
	out = s.run("", "status")
	s.expect(0, "", "")
	mustMatch(t, "status", out, `Listening:\s+\*:4949`)
	mustNotContain(t, "status", s.all(), "DRIFT", "not detected", "[ERROR]")
}
