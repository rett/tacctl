package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/tier"
)

// The engineer tier (docs/plans/0.2.2-plan.md D18), on the sandbox of
// native_test.go: bob's group 'operator' (priv-lvl 7, scope lab) is given
// the tier engineer in tacctl.yaml, so bob is an engineer whatever his
// priv-lvl says. An engineer changes the devices and hosts of his own
// scopes, and nothing of anyone else's.
func engineerSandbox(t *testing.T) *sandbox {
	t.Helper()
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	sb.dev("", "add", "prod-sw", "10.99.0.1", "--vendor", "cisco", "--no-host-key")
	sb.dev("", "add", "lab-sw", "192.168.1.1", "--vendor", "cisco", "--no-host-key")
	sb.write("state/linux-hosts", "web1|root@192.0.2.10||lab|192.0.2.1|\ndb1|root@192.0.2.11||prod|192.0.2.1|\n", 0o600)
	return sb
}

// asEngineer runs tacctl as bob, a member of tac-engineer.
func (sb *sandbox) asEngineer(stdin string, args ...string) string {
	sb.t.Helper()
	return plain(sb.cfgRun(stdin, args, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
	}, "SUDO_USER=bob"))
}

func TestEngineerTierFromGroupSetting(t *testing.T) {
	sb := engineerSandbox(t)
	if got := sb.asEngineer("", "_console-policy"); !strings.Contains(got, " tier=engineer ") ||
		!strings.Contains(got, " system_shell=no ") || !strings.Contains(got, " forward=no ") {
		t.Errorf("policy line %q", got)
	}
	// What stays the superuser's.
	for _, args := range [][]string{{"user", "add", "x"}, {"group", "edit", "operator", "tier", "superuser"}, {"scope", "secret", "lab", "show"},
		{"scope", "prefixes", "lab", "add", "10.1.0.0/16"}, {"backend", "enable", "radius"}, {"backup", "restore", "x"},
		{"upgrade"}, {"host", "unenroll", "web1"}, {"device", "stale-days", "9"}, {"console", "system-shell", "tiers", "engineer"},
		{"config", "linux", "engineer-sudo", "all"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
}

func TestEngineerDevicesOfOwnScopes(t *testing.T) {
	sb := engineerSandbox(t)
	if sb.asEngineer("", "device", "add", "lab-rtr", "192.168.1.2", "--no-host-key"); sb.code != 0 ||
		!strings.Contains(sb.devices(), "lab-rtr") {
		t.Fatalf("add in lab: %d %q", sb.code, sb.stderr())
	}
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"device", "add", "prod-rtr", "10.99.0.2", "--no-host-key"}, "Scope 'prod' is not one of yours: the engineer tier changes the devices and hosts of its own scopes only (yours: lab)."},
		{[]string{"device", "add", "stray", "100.64.0.1", "--no-host-key"}, "'stray' is at an address no scope answers"},
		{[]string{"device", "port", "prod-sw", "2222"}, "Device 'prod-sw' not found."},
		{[]string{"device", "remove", "prod-sw", "-y"}, "Device 'prod-sw' not found."},
		{[]string{"device", "rename", "10.99.0.1", "x9"}, "Device '10.99.0.1' not found."},
		{[]string{"device", "address", "lab-sw", "10.99.0.7"}, "Scope 'prod' is not one of yours"},
		{[]string{"device", "hostkey", "prod-sw", "show"}, "Device 'prod-sw' not found."},
		{[]string{"config", "cisco", "--scope", "prod"}, "Scope 'prod' is not one of yours"},
		{[]string{"config", "wti", "--scope", "dmz", "--staging", "192.168.1.9"}, "Scope 'dmz' is not one of yours"},
		{[]string{"scope", "devices", "prod", "set", "10.99.0.1", "cisco"}, "Scope 'prod' is not one of yours"},
	} {
		before := sb.devices()
		sb.asEngineer("", c.args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.err) || sb.devices() != before {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
	}
	// An import may not touch another scope's device, nor replace the
	// registry.
	sb.asEngineer("prod-new,10.99.0.9\n", "device", "import", "-")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'prod' is not one of yours") || strings.Contains(sb.devices(), "prod-new") {
		t.Errorf("import into prod: %d %q", sb.code, sb.stderr())
	}
	sb.asEngineer("lab-new,192.168.1.9\n", "device", "import", "--replace", "-y", "-")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Scope 'prod' is not one of yours") || !strings.Contains(sb.devices(), "prod-sw") {
		t.Errorf("import --replace: %d %q", sb.code, sb.stderr())
	}
	if sb.asEngineer("lab-new,192.168.1.9\n", "device", "import", "-"); sb.code != 0 || !strings.Contains(sb.devices(), "lab-new") {
		t.Errorf("import into lab: %d %q", sb.code, sb.stderr())
	}
	if sb.asEngineer("", "device", "rename", "lab-sw", "lab-core"); sb.code != 0 || !strings.Contains(sb.devices(), "lab-core") {
		t.Errorf("rename: %d %q", sb.code, sb.stderr())
	}
	// --all is the engineer's own devices.
	if sb.asEngineer("", "device", "remove", "--all", "-y"); sb.code != 0 {
		t.Errorf("remove --all: %d %q", sb.code, sb.stderr())
	}
	if d := sb.devices(); !strings.Contains(d, "prod-sw") || strings.Contains(d, "lab-core") || strings.Contains(d, "lab-rtr") {
		t.Errorf("after remove --all:\n%s", d)
	}
	// The vendor tags and the device configuration of his own scope.
	if out := sb.asEngineer("", "scope", "devices", "lab"); sb.code != 0 || !strings.Contains(out, "Tagged addresses of scope 'lab'") {
		t.Errorf("scope devices lab: %d %q %q", sb.code, out, sb.stderr())
	}
	if out := sb.asEngineer("", "config", "cisco", "--scope", "lab"); sb.code != 0 || !strings.Contains(out, "lab-secret-0123456789abcdef") {
		t.Errorf("config cisco lab: %d %q", sb.code, sb.stderr())
	}
}

func TestEngineerHostsOfOwnScopes(t *testing.T) {
	sb := engineerSandbox(t)
	for _, args := range [][]string{{"host", "sync", "db1"}, {"host", "target", "db1"}, {"host", "move", "db1", "lab"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "No enrolled host named 'db1'") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if out := sb.asEngineer("", "host", "target", "web1"); sb.code != 0 || !strings.Contains(out, "root@192.0.2.10") {
		t.Errorf("target web1: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.asEngineer("", "host", "enroll", "--local", "--scope", "lab")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Enrolling this server (--local) is not the engineer tier's") {
		t.Errorf("enroll --local: %d %q", sb.code, sb.stderr())
	}
}

// The group's tier decides the tier a host's account gets (bob is sent as
// an engineer), and engineer-sudo travels in the header.
func TestEngineerScriptUsers(t *testing.T) {
	hs := newHostSandbox(t)
	hs.write("state/tacctl.yaml", "tier:\n  operator: engineer\nlinux:\n  engineer_sudo: [/usr/bin/systemctl, /usr/bin/journalctl]\n", 0o600)
	hs.run(nil, "config", "linux", "script", "--scope", "lab", "--server", "192.0.2.1", "-o", hs.path("tmp", "s.sh"))
	data := hs.read("tmp/s.sh")
	if hs.code != 0 || !strings.Contains(data, "TAC_USERS=$'alice:superuser:80000\\nbob:engineer:80001\\ncarol:readonly:80002'") ||
		!strings.Contains(data, "\nTAC_ENGINEER_SUDO=/usr/bin/systemctl\\,/usr/bin/journalctl\nTAC_PROTOCOL=6\n") {
		t.Errorf("script: %d %q\n%s", hs.code, hs.stderr(), head(data))
	}
}

func TestConfigLinuxEngineerSudo(t *testing.T) {
	sb := newSandbox(t, true)
	visudo := func(code int) func(*fake.Runner) {
		return func(r *fake.Runner) { r.On([]string{"visudo", "-cf"}, execx.Result{Code: code}) }
	}
	out := plain(sb.cfgRun("", []string{"config", "linux", "engineer-sudo"}, nil))
	if sb.code != 0 || !strings.Contains(out, "Engineers' sudo on enrolled hosts: every command (%tac-engineer ALL=(ALL:ALL) ALL, their own password)") {
		t.Errorf("show: %d %q", sb.code, out)
	}
	sb.cfgRun("", []string{"config", "linux", "engineer-sudo", "/usr/bin/systemctl,/usr/bin/journalctl"}, visudo(0))
	if sb.code != 0 || !strings.Contains(sb.read("state/tacctl.yaml"), "engineer_sudo:\n  - /usr/bin/systemctl\n  - /usr/bin/journalctl\n") ||
		!sb.runner.CalledRegexp("^visudo -cf ") {
		t.Errorf("set: %d %q %q", sb.code, sb.stderr(), sb.read("state/tacctl.yaml"))
	}
	if !strings.Contains(plain(sb.out.String()+sb.err.String()), "(%tac-engineer ALL=(ALL:ALL) /usr/bin/systemctl, /usr/bin/journalctl)") {
		t.Errorf("set message: %q", sb.out.String())
	}
	out = plain(sb.cfgRun("", []string{"config", "linux", "engineer-sudo"}, nil))
	if !strings.Contains(out, "Engineers' sudo on enrolled hosts: /usr/bin/systemctl, /usr/bin/journalctl") {
		t.Errorf("show set: %q", out)
	}
	for _, bad := range []string{"systemctl", "/usr/bin/systemctl restart", "/usr/bin/*", "/usr/bin/a,,/usr/bin/b", "/usr/../bin/sh", "ALL"} {
		before := sb.read("state/tacctl.yaml")
		sb.cfgRun("", []string{"config", "linux", "engineer-sudo", bad}, visudo(0))
		if sb.code != 1 || !strings.Contains(sb.stderr(), "Usage: tacctl config linux engineer-sudo") || sb.read("state/tacctl.yaml") != before {
			t.Errorf("%q: %d %q", bad, sb.code, sb.stderr())
		}
	}
	before := sb.read("state/tacctl.yaml")
	sb.cfgRun("", []string{"config", "linux", "engineer-sudo", "/usr/bin/top"}, visudo(1))
	if sb.code != 1 || !strings.Contains(sb.stderr(), "visudo rejected the line '%tac-engineer ALL=(ALL:ALL) /usr/bin/top'. Nothing was changed.") ||
		sb.read("state/tacctl.yaml") != before {
		t.Errorf("visudo refusal: %d %q", sb.code, sb.stderr())
	}
	sb.cfgRun("", []string{"config", "linux", "engineer-sudo", "all"}, visudo(0))
	if text, _ := os.ReadFile(sb.path("state", "tacctl.yaml")); sb.code != 0 || strings.Contains(string(text), "engineer_sudo") {
		t.Errorf("all: %d %q", sb.code, text)
	}
	if hosts.EngineerSudoLine(nil) != "%tac-engineer ALL=(ALL:ALL) ALL" {
		t.Errorf("line %q", hosts.EngineerSudoLine(nil))
	}
}

// console check asks sudo what each member of tac-engineer may run: tacctl
// only passes; anything else is the red warning, exit 1.
func TestConsoleCheckEngineerSudo(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	tacctlOnly := "Matching Defaults entries for bob on authsrv:\n    env_reset\n\nRunas and Command-specific defaults for bob:\n" +
		"    Defaults!/usr/local/bin/tacctl env_keep+=\"SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY\"\n\n" +
		"User bob may run the following commands on authsrv:\n" +
		"    (root) NOPASSWD: /usr/local/bin/tacctl \"\", /usr/local/bin/tacctl passwd, /usr/local/bin/tacctl device add *\n"
	run := func(sudo map[string]string) string {
		return sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice"), func(r *fake.Runner) {
			r.On([]string{"getent", "group", tier.EngineerGroup}, execx.Result{Stdout: []byte("tac-engineer:x:80005:bob,dave\n")})
			for u, out := range sudo {
				r.On([]string{"sudo", "-n", "-l", "-U", u}, execx.Result{Stdout: []byte(out)})
			}
		}))
	}
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	out := run(map[string]string{"bob": tacctlOnly, "dave": "User dave is not allowed to run sudo on authsrv.\n"})
	if sb.code != 0 || !strings.Contains(out, "sudo for bob: tacctl only") || !strings.Contains(out, "sudo for dave: tacctl only") ||
		!strings.Contains(out, "No member of tac-engineer can run anything but tacctl through sudo here.") {
		t.Errorf("tacctl only: %d\n%s", sb.code, out)
	}
	out = run(map[string]string{"bob": tacctlOnly + "    (ALL : ALL) ALL\n", "dave": "sudo: unknown user dave\n"})
	if sb.code != 1 || !strings.Contains(out, "WARNING: an engineer can run more than tacctl as root on this server: bob (tac-engineer) can run ALL through sudo") ||
		!strings.Contains(out, "sudo could not be asked what dave may run") {
		t.Errorf("more than tacctl: %d\n%s", sb.code, out)
	}
	for in, want := range map[string]string{
		"User x may run the following commands on h:\n    (root) NOPASSWD: SETENV: /usr/bin/vi /etc/hosts, /usr/local/bin/tacctl status\n": "/usr/bin/vi /etc/hosts",
		"User x may run the following commands on h:\n    (root) sudoedit /etc/motd\n":                                                     "sudoedit /etc/motd",
		"User x may run the following commands on h:\n    (root) NOPASSWD: /usr/local/bin/tacctl log tail *\n":                             "",
	} {
		other, ok := sudoBeyondTacctl(in)
		if !ok || strings.Join(other, ",") != want {
			t.Errorf("%q: %q %v", in, other, ok)
		}
	}
	if _, ok := sudoBeyondTacctl("sudo: a terminal is required\n"); ok {
		t.Error("an unreadable answer passes")
	}
}
