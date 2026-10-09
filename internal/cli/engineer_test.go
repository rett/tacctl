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
		!strings.Contains(got, " system_shell=no ") || !strings.Contains(got, " forward=no ") || strings.Contains(got, " gate=") {
		t.Errorf("policy line %q", got)
	}
	// What stays the superuser's.
	for _, args := range [][]string{{"user", "add", "x"}, {"group", "edit", "operator", "tier", "superuser"}, {"scope", "add", "x"},
		{"scope", "prefixes", "lab", "add", "10.1.0.0/16"}, {"backend", "enable", "radius"}, {"backup", "restore", "x"},
		{"upgrade"}, {"device", "stale-days", "9"}, {"console", "system-shell", "tiers", "engineer"},
		{"config", "linux", "engineer-sudo", "all"}, {"config", "snmp", "show"}, {"store", "show"}, {"config", "dump"}} {
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
		{[]string{"device", "add", "prod-rtr", "10.99.0.2", "--no-host-key"}, "Scope 'prod' is not one of yours: the engineer tier changes the devices of its own scopes only (yours: lab)."},
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
	sb.asEngineer("lab-new,192.168.1.9\n", "device", "import", "-", "--replace", "-y")
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

// Linux host deployment is the superuser's: an engineer's gate refuses every
// host verb but list and show, and nothing is written.
func TestEngineerHostsAreReadOnly(t *testing.T) {
	sb := engineerSandbox(t)
	hosts := sb.read("state/linux-hosts")
	for _, args := range [][]string{{"host", "sync", "web1"}, {"host", "sync", "--all"}, {"host", "target", "web1"}, {"host", "move", "web1", "lab"},
		{"host", "enroll", "--local", "--scope", "lab"}, {"host", "enroll", "root@192.0.2.50", "--name", "h1", "--scope", "lab"},
		{"host", "unenroll", "web1", "--force"}, {"host", "default-method"}, {"host", "default-method", "radius"},
		{"host", "provisioner", "web1", "rotate", "deploy2", "--key", "/tmp/k", "--yes"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl host "+args[1]+"' is not permitted for the engineer tier.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if sb.read("state/linux-hosts") != hosts {
		t.Errorf("the hosts registry changed:\n%s", sb.read("state/linux-hosts"))
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
			r.On([]string{"getent", "passwd", "bob"}, execx.Result{Stdout: []byte("bob:x:80001:80000:bob (TACACS+):/home/bob:" + link + "\n")})
			r.On([]string{"getent", "passwd", "dave"}, execx.Result{Stdout: []byte("dave:x:80004:80000:dave (TACACS+):/home/dave:/usr/sbin/nologin\n")})
			for u, out := range sudo {
				r.On([]string{"sudo", "-n", "-l", "-U", u}, execx.Result{Stdout: []byte(out)})
			}
		}))
	}
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	out := run(map[string]string{"bob": tacctlOnly, "dave": "User dave is not allowed to run sudo on authsrv.\n"})
	// sudo is asked in the C locale with a line it does not wrap.
	for _, c := range sb.runner.Records() {
		if c.Cmd.Name == "sudo" {
			env := strings.Join(c.Cmd.Env, " ")
			if !strings.Contains(env, "LC_ALL=C") || !strings.Contains(env, "LANGUAGE=C") || !strings.Contains(env, "COLUMNS=4096") {
				t.Errorf("sudo -l environment lacks the locale or width: %q", c.Cmd.Env)
			}
		}
	}
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
	// A rule sudo wrapped onto continuation lines is one rule; what is on
	// them counts.
	wrapped := "User bob may run the following commands on h:\n" +
		"    (root) NOPASSWD: /usr/local/bin/tacctl \"\", /usr/local/bin/tacctl passwd,\n" +
		"        /usr/local/bin/tacctl status, /usr/local/bin/tacctl device add *,\n" +
		"        /usr/bin/vi /etc/hosts\n" +
		"    (root) NOPASSWD: /usr/local/bin/tacctl log tail\n"
	if other, ok := sudoBeyondTacctl(wrapped); !ok || strings.Join(other, ",") != "/usr/bin/vi /etc/hosts" {
		t.Errorf("wrapped: %q %v", other, ok)
	}
	if other, ok := sudoBeyondTacctl(strings.Replace(wrapped, "        /usr/bin/vi /etc/hosts\n", "        /usr/local/bin/tacctl log tail *\n", 1)); !ok || len(other) != 0 {
		t.Errorf("wrapped, tacctl only: %q %v", other, ok)
	}
}

// 'group show' prints the Junos patterns to every tier (D29 of
// docs/plans/0.2.3-plan.md) and the hint to 'group junos' only to the tier
// that may run it.
func TestGroupShowJunosPatterns(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\njunos:\n  operator:\n    deny_commands: ['^request', '^start shell']\n    deny_configuration: ['^snmp']\n", 0o600)
	want := "  Junos rules:       deny-commands 25/241 bytes, deny-configuration 7/236 bytes\n" +
		"                     deny-commands\n                       ^request\n                       ^start shell\n" +
		"                     deny-configuration\n                       ^snmp\n  Users:"
	out := sb.asEngineer("", "group", "show", "operator")
	if sb.code != 0 || !strings.Contains(out, want) || strings.Contains(out, "group junos") {
		t.Errorf("engineer: %d\n%s%s", sb.code, out, sb.stderr())
	}
	// The superuser (root here) gets the hint as well.
	out = plain(sb.cfgRun("", []string{"group", "show", "operator"}, nil))
	if sb.code != 0 || !strings.Contains(out, "                       ^snmp\n                     tacctl group junos operator list\n  Users:") ||
		!strings.Contains(out, "\n                       ^start shell\n") {
		t.Errorf("superuser: %d\n%s%s", sb.code, out, sb.stderr())
	}
	// A group with no sets says none.
	out = plain(sb.cfgRun("", []string{"group", "show", "readonly"}, nil))
	if !strings.Contains(out, "  Junos rules:       none                             tacctl group junos readonly list\n") || strings.Contains(out, "\n                       ^") {
		t.Errorf("none: %d\n%s", sb.code, out)
	}
}

// B2: 'console check' looks at the engineers' logins: a shell that is neither
// the console nor nologin, sshd letting an engineer forward, and an engineer
// who is still in tac-superuser (S2) are red and exit 1.
func TestConsoleCheckEngineerLogin(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	run := func(shell, supers, tcp string) string {
		return sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice"), func(r *fake.Runner) {
			r.On([]string{"getent", "group", tier.EngineerGroup}, execx.Result{Stdout: []byte("tac-engineer:x:80005:bob\n")})
			r.On([]string{"getent", "group", tier.SuperuserGroup}, execx.Result{Stdout: []byte("tac-superuser:x:80002:" + supers + "\n")})
			r.On([]string{"getent", "passwd", "bob"}, execx.Result{Stdout: []byte("bob:x:80001:80000:bob (TACACS+):/home/bob:" + shell + "\n")})
			r.On([]string{"sudo", "-n", "-l", "-U", "bob"}, execx.Result{Stdout: []byte("User bob is not allowed to run sudo on authsrv.\n")})
			if tcp != "" {
				r.On([]string{"sshd", "-T", "-C", "user=bob,host=localhost,addr=127.0.0.1"}, execx.Result{Stdout: []byte("allowtcpforwarding " + tcp + "\nallowagentforwarding no\ndisableforwarding no\n")})
			} else {
				r.On([]string{"sshd", "-T", "-C", "user=bob,host=localhost,addr=127.0.0.1"}, execx.Result{Stdout: []byte("allowtcpforwarding no\nallowagentforwarding no\ndisableforwarding yes\n")})
			}
		}))
	}
	out := run(link, "alice", "")
	if sb.code != 0 || !strings.Contains(out, "login shell of bob: "+link) || !strings.Contains(out, "sshd for bob: allowtcpforwarding no") ||
		!strings.Contains(out, "Engineers here have the console or no login, and no one below the superuser tier keeps tac-superuser.") {
		t.Errorf("console shell: %d\n%s", sb.code, out)
	}
	if out = run("/usr/sbin/nologin", "alice", ""); sb.code != 0 || !strings.Contains(out, "login shell of bob: /usr/sbin/nologin") {
		t.Errorf("nologin: %d\n%s", sb.code, out)
	}
	out = run("/bin/bash", "alice", "")
	if sb.code != 1 || !strings.Contains(out, "bob (tac-engineer) has the login shell /bin/bash, but an engineer has the console or no login: tacctl host sync authsrv") {
		t.Errorf("bash: %d\n%s", sb.code, out)
	}
	out = run(link, "alice", "yes")
	if sb.code != 1 || !strings.Contains(out, "allowtcpforwarding is 'yes'") {
		t.Errorf("forwarding: %d\n%s", sb.code, out)
	}
	out = run(link, "alice,bob", "")
	if sb.code != 1 || !strings.Contains(out, "bob is an engineer but is still in tac-superuser here (stale membership; run: tacctl host sync authsrv)") {
		t.Errorf("stale: %d\n%s", sb.code, out)
	}
}

// B1: a tacctl.yaml that cannot be read makes no managed caller more than an
// operator (the tiers in it are unknown), and what syncs accounts or sets a
// tier refuses, naming the problem.
func TestBrokenConfCapsTheTierAndRefusesSync(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n  - [broken\n", 0o600)
	// bob's group is priv-lvl 7; alice (priv-lvl 15) is a superuser by band.
	asAlice := func(args ...string) string {
		return plain(sb.cfgRun("", args, func(r *fake.Runner) {
			r.On([]string{"id", "-nG", "--", "alice"}, execx.Result{Stdout: []byte("alice tac-users tac-superuser\n")})
		}, "SUDO_USER=alice"))
	}
	asAlice("host", "sync", "web1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl host sync' is not permitted: "+sb.path("state", "tacctl.yaml")+" cannot be read (") ||
		!strings.Contains(sb.stderr(), "so no tacctl user is trusted above the operator tier until it is fixed (tacctl config validate).") {
		t.Errorf("host sync as a band-15 caller: %d %q", sb.code, sb.stderr())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.warning", "tier DENY user=alice tier=operator reason=conf-problem cmd=host sync") {
		t.Errorf("not logged: %q", sb.runner.Argvs())
	}
	// The shell lists what the gate lets the caller run: an engineer the cap
	// makes an operator is told apart from the console's view of it (D56).
	asBob := plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "bob"}, execx.Result{Stdout: []byte("bob tac-users tac-engineer\n")})
	}, "SUDO_USER=bob"))
	if !strings.Contains(asBob, " tier=engineer gate=operator ") {
		t.Errorf("capped engineer's policy line %q", asBob)
	}
	// The diagnosis stays open to them.
	asAlice("config", "validate")
	if strings.Contains(sb.stderr(), "not permitted") {
		t.Errorf("config validate: %d %q", sb.code, sb.stderr())
	}
	// A caller the gate does not manage (root, here) is unaffected by the
	// cap but the sync itself refuses with the problem.
	sb.cfgRun("", []string{"host", "sync", "web1"}, nil)
	if sb.code != 1 || !strings.Contains(sb.stderr(), "cannot be read (") || !strings.Contains(sb.stderr(), "); accounts and tiers are not synced until it is fixed.") {
		t.Errorf("host sync as root: %d %q", sb.code, sb.stderr())
	}
	sb.cfgRun("", []string{"host", "enroll", "--local", "--scope", "lab"}, nil)
	if sb.code != 1 || !strings.Contains(sb.stderr(), "accounts and tiers are not synced until it is fixed.") {
		t.Errorf("host enroll as root: %d %q", sb.code, sb.stderr())
	}
	sb.cfgRun("", []string{"group", "edit", "operator", "tier", "readonly"}, nil)
	if sb.code != 1 || !strings.Contains(sb.stderr(), "accounts and tiers are not synced until it is fixed.") {
		t.Errorf("group edit tier as root: %d %q", sb.code, sb.stderr())
	}
}

// B1: a tier setting that is not a managed tier is readonly, not the band.
func TestInvalidGroupTierIsReadonly(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "tier:\n  superuser: root\n", 0o600)
	asAlice := plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "alice"}, execx.Result{Stdout: []byte("alice tac-users tac-superuser\n")})
	}, "SUDO_USER=alice"))
	if !strings.Contains(asAlice, " tier=readonly ") {
		t.Errorf("policy line %q", asAlice)
	}
}

// S2: lowering a group's tier syncs this server's accounts at once (the
// members would keep the groups of the old tier, an engineer made from a
// superuser its tac-superuser); raising it, or no change of rank, does not.
func TestGroupTierLoweredSyncsTheServer(t *testing.T) {
	hs := newHostSandbox(t)
	hs.reroot = true
	hs.loopback()
	hs.write("shells", "/bin/sh\n/bin/bash\n", 0o644)
	hs.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	runner := func() *fake.Runner {
		r := hs.runner()
		r.On([]string{"bash"}, execx.Result{Stdout: []byte("[INFO] Accounts: 3 managed by tacctl here.\n")})
		return r
	}
	// readonly -> operator is a raise: nothing to sync.
	hs.run(runner(), "group", "edit", "readonly", "tier", "operator")
	if hs.code != 0 || strings.Contains(plain(hs.out.String()+hs.err.String()), "syncing this server's accounts") {
		t.Errorf("raise: %d\n%s", hs.code, plain(hs.out.String()+hs.err.String()))
	}
	// superuser -> engineer lowers it.
	r := runner()
	hs.run(r, "group", "edit", "superuser", "tier", "engineer")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "The tier of 'superuser' is lower now: syncing this server's accounts (authsrv).") || !r.Called("bash") ||
		strings.Contains(all, "keep their old groups") {
		t.Errorf("lowered: %d\n%s", hs.code, all)
	}
	// ... and back to auto (priv-lvl 15 = superuser) is a raise.
	r = runner()
	hs.run(r, "group", "edit", "superuser", "tier", "auto")
	if hs.code != 0 || r.Called("bash") {
		t.Errorf("auto: %d\n%s", hs.code, plain(hs.out.String()+hs.err.String()))
	}
	// A sync that fails says what is left.
	r = runner()
	r.On([]string{"bash"}, execx.Result{Code: 1})
	hs.run(r, "group", "edit", "superuser", "tier", "operator")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 1 || !strings.Contains(all, "Members of 'superuser' keep their old groups on this server until: tacctl host sync authsrv") {
		t.Errorf("failed sync: %d\n%s", hs.code, all)
	}
	// No enrolled server: the line, and the change stands.
	hs.write("state/linux-hosts", "", 0o600)
	hs.run(runner(), "group", "edit", "operator", "tier", "readonly")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Members of 'operator' keep their old groups on this server until: tacctl host sync <name of this server>") ||
		!strings.Contains(hs.read("state/tacctl.yaml"), "operator: readonly") {
		t.Errorf("not enrolled: %d\n%s", hs.code, all)
	}
}

// D45: an engineer reads the secret of a scope of their own with
// 'scope secret <scope> show' and 'scope show <scope>', is told another
// scope does not exist, may not set or generate any, and every reveal is
// logged without the value.
func TestEngineerReadsOwnScopeSecret(t *testing.T) {
	sb := engineerSandbox(t)
	storeBefore := sb.store()
	out := sb.asEngineer("", "scope", "secret", "lab", "show")
	if sb.code != 0 || !strings.Contains(out, "lab-secret-0123456789abcdef") {
		t.Fatalf("own scope: %d %q %q", sb.code, out, sb.stderr())
	}
	if !sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=scope name=lab by=bob") {
		t.Errorf("not logged: %q", sb.runner.Argvs())
	}
	for _, c := range sb.runner.Records() {
		if c.Cmd.Name == "logger" && strings.Contains(strings.Join(c.Cmd.Args, " "), "lab-secret-0123456789abcdef") {
			t.Errorf("the secret is in a log line: %q", c.Cmd.Args)
		}
	}
	// scope show: the posture, never the value; another scope is unknown.
	out = sb.asEngineer("", "scope", "show", "lab")
	if sb.code != 0 || !strings.Contains(out, "Scope: lab") || strings.Contains(out, "lab-secret-0123456789abcdef") {
		t.Errorf("scope show lab: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, args := range [][]string{{"scope", "secret", "prod", "show"}, {"scope", "show", "prod"}, {"scope", "secret", "nosuch", "show"},
		{"scope", "secret", "prod", "set", "abcdefgh12345678ABCDEFGH"}, {"scope", "secret", "prod", "generate"}} {
		out = sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "' does not exist.") {
			t.Errorf("%v: %d %q %q", args, sb.code, out, sb.stderr())
		}
		if strings.Contains(out, "prod-secret") || strings.Contains(sb.stderr(), "prod-secret") {
			t.Errorf("%v: another scope's secret: %q %q", args, out, sb.stderr())
		}
	}
	for _, args := range [][]string{{"scope", "secret", "lab", "set", "abcdefgh12345678ABCDEFGH"}, {"scope", "secret", "lab", "generate"}, {"scope", "secret", "lab"},
		{"scope", "secret", "lab", "help"}} {
		sb.asEngineer("", args...)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier reads a scope's secret: tacctl scope secret lab show. Changing it is the superuser's. Nothing was changed.") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if sb.store() != storeBefore {
		t.Error("the store changed")
	}
	// The walkthrough of a scope of their own prints it as well: logged.
	sb.asEngineer("", "config", "cisco", "--scope", "lab")
	if n := sb.runner.Count("logger", "-t", "tacctl", "-p", "auth.info", "secret-read kind=scope name=lab by=bob"); n != 1 {
		t.Errorf("walkthrough: %d secret-read lines", n)
	}
	// A superuser (root here) is not logged as a restricted reveal.
	sb.cfgRun("", []string{"scope", "secret", "prod", "show"}, nil)
	if sb.code != 0 || sb.runner.Called("logger", "-t", "tacctl", "-p", "auth.info", "secret-read") {
		t.Errorf("superuser: %d %q", sb.code, sb.runner.Argvs())
	}
}

// D47: the hosts and staging addresses of an engineer's own scopes can be
// listed and shown (a host is read, and --check, which logs in, is refused),
// and an import taken from standard input only.
func TestEngineerHostRowsOfOwnScopes(t *testing.T) {
	sb := engineerSandbox(t)
	out := sb.asEngineer("", "host", "list")
	if sb.code != 0 || !strings.Contains(out, "web1") || strings.Contains(out, "db1") {
		t.Errorf("host list: %d %q %q", sb.code, out, sb.stderr())
	}
	out = sb.asEngineer("", "host", "show", "web1")
	if sb.code != 0 || !strings.Contains(out, "web1") {
		t.Errorf("host show web1: %d %q %q", sb.code, out, sb.stderr())
	}
	sb.asEngineer("", "host", "show", "db1")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "No enrolled host named 'db1'") {
		t.Errorf("host show db1: %d %q", sb.code, sb.stderr())
	}
	// --check opens ssh as the invoker: refused, and no ssh runs.
	sb.asEngineer("", "host", "show", "web1", "--check")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "'host show --check' logs in to the host over ssh, which is the superuser's") || sb.runner.Called("ssh") {
		t.Errorf("host show --check: %d %q %q", sb.code, sb.stderr(), sb.runner.Argvs())
	}
	// staging: their own scopes' addresses, listed only.
	sb.write("state/staging", "192.168.1.77/32|lab|device|lab-new|2026-10-01 10:00\n10.99.0.77/32|prod|device|prod-new|2026-10-01 10:00\n", 0o600)
	out = sb.asEngineer("", "scope", "staging", "list")
	if sb.code != 0 || !strings.Contains(out, "192.168.1.77/32") || strings.Contains(out, "10.99.0.77") {
		t.Errorf("staging list: %d %q %q", sb.code, out, sb.stderr())
	}
	staging := sb.read("state/staging")
	sb.asEngineer("", "scope", "staging", "remove", "192.168.1.77/32")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier lists the staging addresses of its scopes") || sb.read("state/staging") != staging {
		t.Errorf("staging remove: %d %q", sb.code, sb.stderr())
	}
	// device import: standard input only.
	sb.asEngineer("lab-new,192.168.1.9\n", "device", "import", "--check", "-")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier imports from standard input only: tacctl device import - [--check|--replace] < file") {
		t.Errorf("import --check -: %d %q", sb.code, sb.stderr())
	}
	sb.write("tmp/in.csv", "lab-new,192.168.1.9\n", 0o600)
	sb.asEngineer("", "device", "import", sb.path("tmp", "in.csv"))
	if sb.code != 1 || !strings.Contains(sb.stderr(), "The engineer tier imports from standard input only") || strings.Contains(sb.devices(), "lab-new") {
		t.Errorf("import file: %d %q", sb.code, sb.stderr())
	}
	sb.asEngineer("lab-new,192.168.1.9\n", "device", "import", "-", "--check")
	if sb.code != 0 {
		t.Errorf("import - --check: %d %q", sb.code, sb.stderr())
	}
	// N3: --staging --name names a device of their own scopes.
	sb.asEngineer("", "config", "cisco", "--scope", "lab", "--staging", "192.168.1.88", "--name", "prod-sw")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-sw' not found.") || strings.Contains(sb.read("state/staging"), "192.168.1.88") {
		t.Errorf("staging --name of another scope: %d %q", sb.code, sb.stderr())
	}
}

// N2: engineer-sudo warns for the commands that hand out a root shell, and
// still sets them.
func TestEngineerSudoWarnsForRootShells(t *testing.T) {
	sb := newSandbox(t, true)
	sb.cfgRun("", []string{"config", "linux", "engineer-sudo", "/usr/bin/systemctl,/usr/bin/vim,/bin/bash,/usr/bin/python3.11,/usr/bin/find,/usr/bin/env,/usr/bin/journalctl"}, nil)
	err := plain(sb.out.String())
	if sb.code != 0 {
		t.Fatalf("exit %d: %s", sb.code, plain(sb.err.String()))
	}
	for _, c := range []string{"/usr/bin/vim", "/bin/bash", "/usr/bin/python3.11", "/usr/bin/find", "/usr/bin/env"} {
		if !strings.Contains(err, c+" gives root a shell; engineers on those hosts are then superusers in all but name.") {
			t.Errorf("no warning for %s:\n%s", c, err)
		}
	}
	for _, c := range []string{"/usr/bin/systemctl", "/usr/bin/journalctl"} {
		if strings.Contains(err, c+" gives root a shell") {
			t.Errorf("warning for %s:\n%s", c, err)
		}
	}
	if !strings.Contains(sb.read("state/tacctl.yaml"), "/usr/bin/vim") {
		t.Error("the setting was not written")
	}
}
