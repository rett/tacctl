package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/tier"
)

// WP10.2g: the fixes to the re-review of WP10.2f (docs/plans/0.2.3-plan.md
// §3a, B1, B2, S1, S2).

func idAs(user, groups string) func(*fake.Runner) {
	return func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " " + groups + "\n")})
	}
}

// B1: every shape of a tier setting that cannot be a tier makes a priv-lvl 15
// member readonly (never the band's superuser), and the syncs refuse,
// naming it, until it is fixed. alice is in the built-in superuser group.
func TestInvalidTierSettingsNeverLeaveTheBand(t *testing.T) {
	for _, c := range []struct{ name, yaml, problem string }{
		{"mapping", "tier:\n  superuser: {x: engineer}\n", "'tier.superuser' must be one of"},
		{"list", "tier:\n  superuser: [engineer]\n", "'tier.superuser' must be one of"},
		{"null", "tier:\n  superuser:\n", "'tier.superuser' must be one of"},
		{"empty", "tier:\n  superuser: ''\n", "'tier.superuser' must be one of"},
		{"number", "tier:\n  superuser: 15\n", "'tier.superuser' must be one of"},
		{"tier is a string", "tier: engineer\n", "'tier' must be a mapping"},
		{"tier is a list", "tier: [superuser]\n", "'tier' must be a mapping"},
		{"tier is empty", "tier:\n", "'tier' must be a mapping"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb := newSandbox(t, true)
			sb.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
			sb.write("state/tacctl.yaml", c.yaml, 0o600)
			policy := plain(sb.cfgRun("", []string{"_console-policy"}, idAs("alice", "tac-users tac-superuser"), "SUDO_USER=alice"))
			if !strings.Contains(policy, " tier=readonly ") {
				t.Errorf("alice (priv-lvl 15): %q", policy)
			}
			// The syncs refuse for the superuser that is root here...
			for _, args := range [][]string{{"host", "sync", "authsrv"}, {"host", "sync", "--all"}, {"host", "enroll", "--local", "--scope", "lab"}} {
				sb.cfgRun("", args, nil)
				if sb.code != 1 || !strings.Contains(sb.stderr(), "cannot be read ("+c.problem) ||
					!strings.Contains(sb.stderr(), "accounts and tiers are not synced until it is fixed.") {
					t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
				}
			}
			// ... and the gate: no managed caller is trusted above the
			// operator tier, with the problem named.
			sb.cfgRun("", []string{"host", "sync", "authsrv"}, idAs("alice", "tac-users tac-superuser"), "SUDO_USER=alice")
			if sb.code != 1 || !strings.Contains(sb.stderr(), "'tacctl host sync' is not permitted for the readonly tier.") {
				t.Errorf("host sync as alice: %d %q", sb.code, sb.stderr())
			}
			// The setting is repaired with the verb that writes it.
			sb.cfgRun("", []string{"group", "edit", "superuser", "tier", "superuser"}, nil)
			if sb.code != 0 {
				t.Fatalf("repair: %d %q", sb.code, sb.stderr())
			}
			policy = plain(sb.cfgRun("", []string{"_console-policy"}, idAs("alice", "tac-users tac-superuser"), "SUDO_USER=alice"))
			if !strings.Contains(policy, " tier=superuser ") {
				t.Errorf("after the repair: %q", policy)
			}
		})
	}
}

// B2: with tacctl.yaml unreadable the cap makes an engineer an operator, and
// 'console system-shell tiers' / 'forwarding tiers' naming operator would
// open a system shell and forwarding to it. The policy line keeps the
// engineer's lockdown, whichever way the engineer is known.
func TestCappedEngineerKeepsTheConsoleLockdown(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n", 0o600)
	sb.write("shells", "/bin/sh\n/bin/bash\n", 0o644)
	for _, args := range [][]string{{"console", "system-shell", "tiers", "superuser,operator"}, {"console", "forwarding", "tiers", "superuser,operator"}} {
		sb.cfgRun("", args, nil)
		if sb.code != 0 {
			t.Fatalf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	line := func(user, groups string) string {
		return plain(sb.cfgRun("", []string{"_console-policy"}, idAs(user, groups), "SUDO_USER="+user))
	}
	// A readable file: the engineer tier is closed to both.
	if got := line("bob", "tac-users tac-engineer"); !strings.Contains(got, "shell=console ") || !strings.Contains(got, " system_shell=no ") ||
		!strings.Contains(got, " forward=no ") || !strings.Contains(got, " tier=engineer ") {
		t.Errorf("readable: %q", got)
	}
	// Broken: still the engineer's lockdown, though the gate's tier is
	// operator ('tier=' says what the console's tier is).
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\n  - [broken\n", 0o600)
	if got := line("bob", "tac-users tac-engineer"); !strings.Contains(got, "shell=console ") || !strings.Contains(got, " system_shell=no ") ||
		!strings.Contains(got, " forward=no ") || !strings.Contains(got, " tier=engineer ") {
		t.Errorf("broken, member of tac-engineer: %q", got)
	}
	// A band-15 engineer: the setting cannot be read, only the group says so.
	if got := line("alice", "tac-users tac-engineer"); !strings.Contains(got, " system_shell=no ") || !strings.Contains(got, " forward=no ") ||
		!strings.Contains(got, " tier=engineer ") {
		t.Errorf("broken, band 15 in tac-engineer: %q", got)
	}
	// Not an engineer: the cap is what it was (operator), and the settings
	// that name operator still apply to it.
	if got := line("alice", "tac-users tac-superuser"); !strings.Contains(got, " tier=operator ") || strings.Contains(got, " forward=no ") {
		t.Errorf("broken, a superuser: %q", got)
	}
}

func hostLowerSandbox(t *testing.T) *hostSandbox {
	t.Helper()
	hs := newHostSandbox(t)
	hs.reroot = true
	hs.loopback()
	hs.write("shells", "/bin/sh\n/bin/bash\n", 0o644)
	hs.write("state/linux-hosts", "authsrv|local||lab|127.0.0.1|\n", 0o600)
	return hs
}

func (hs *hostSandbox) lowerRunner() *fake.Runner {
	r := hs.runner()
	r.On([]string{"bash"}, execx.Result{Stdout: []byte("[INFO] Accounts: 3 managed by tacctl here.\n")})
	return r
}

// S2: every verb that lowers a tier syncs this server's accounts at once, or
// says what is left: group edit tier (in engineer_test.go), group edit
// priv-lvl, user move and group preset roles --force. A raise, or a change
// that leaves every rank, does not.
func TestEveryLoweringVerbSyncsTheServer(t *testing.T) {
	synced := "syncing this server's accounts (authsrv)."
	for _, c := range []struct {
		name  string
		setup func(*hostSandbox)
		args  []string
		stdin string
		sync  bool
		left  string
	}{
		// bob is in operator (priv-lvl 7), carol in readonly (1).
		{name: "priv-lvl lowered", args: []string{"group", "edit", "operator", "priv-lvl", "3"}, sync: true, left: "Members of 'operator' keep their old groups"},
		{name: "priv-lvl in the band", args: []string{"group", "edit", "operator", "priv-lvl", "9"}},
		{name: "priv-lvl raised", args: []string{"group", "edit", "readonly", "priv-lvl", "7"}},
		{name: "moved down", args: []string{"user", "move", "bob", "readonly"}, sync: true, left: "'bob' keeps the groups of the old tier"},
		{name: "moved up", args: []string{"user", "move", "bob", "superuser"}},
		{name: "moved sideways", args: []string{"user", "move", "carol", "readonly"}},
		{
			name: "preset --force", args: []string{"group", "preset", "roles", "--force"}, stdin: "y\n", sync: true,
			// A group called engineer at priv-lvl 15 with no tier is a
			// superuser group by its band; the preset makes it the engineer
			// tier, and bob in it a lowered user.
			setup: func(hs *hostSandbox) {
				for _, a := range [][]string{{"group", "add", "engineer", "15", "ENG-CLASS"}, {"user", "move", "bob", "engineer"}} {
					if hs.run(nil, a...); hs.code != 0 {
						hs.t.Fatalf("%v: %d %q", a, hs.code, hs.err.String())
					}
				}
			},
			left: "Members of the role groups keep their old groups",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			hs := hostLowerSandbox(t)
			if c.setup != nil {
				c.setup(hs)
			}
			hs.stdin = c.stdin
			r := hs.lowerRunner()
			hs.run(r, c.args...)
			all := plain(hs.out.String() + hs.err.String())
			if hs.code != 0 || strings.Contains(all, synced) != c.sync || r.Called("bash") != c.sync {
				t.Errorf("%v: exit %d, synced %v, want %v\n%s", c.args, hs.code, r.Called("bash"), c.sync, all)
			}
			if c.sync && strings.Contains(all, "keep their old groups") {
				t.Errorf("%v: a successful sync still says who is left:\n%s", c.args, all)
			}
			if c.left == "" {
				return
			}
			// A sync that fails says what is left; the change stands.
			hs = hostLowerSandbox(t)
			if c.setup != nil {
				c.setup(hs)
			}
			hs.stdin = c.stdin
			r = hs.lowerRunner()
			r.On([]string{"bash"}, execx.Result{Code: 1})
			hs.run(r, c.args...)
			all = plain(hs.out.String() + hs.err.String())
			if hs.code != 1 || !strings.Contains(all, c.left+" on this server until: tacctl host sync authsrv") {
				t.Errorf("%v with a failing sync: exit %d\n%s", c.args, hs.code, all)
			}
		})
	}
}

// S2: 'console check' flags every tac-superuser member whose tier is not
// superuser, not only the engineers.
func TestConsoleCheckStaleSuperuserMembers(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	out := sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice"), func(r *fake.Runner) {
		r.On([]string{"getent", "group", tier.SuperuserGroup}, execx.Result{Stdout: []byte("tac-superuser:x:80002:alice,bob,carol,ghost\n")})
		r.On([]string{"getent", "passwd", "ghost"}, execx.Result{Stdout: []byte("ghost:x:80100:80000:ghost (TACACS+):/home/ghost:/bin/bash\n")})
	}))
	if sb.code != 1 ||
		!strings.Contains(out, "bob is operator, not a superuser, but is still in tac-superuser here (stale membership; run: tacctl host sync authsrv)") ||
		!strings.Contains(out, "carol is readonly, not a superuser, but is still in tac-superuser here (stale membership; run: tacctl host sync authsrv)") {
		t.Errorf("stale members: %d\n%s", sb.code, out)
	}
	// alice is a superuser: not named. ghost is no tacctl user (a removed
	// one): named.
	if strings.Contains(out, "alice is") || !strings.Contains(out, "ghost is no tacctl user (removed?) but is still in tac-superuser here (stale membership; run: tacctl host sync authsrv)") {
		t.Errorf("members:\n%s", out)
	}
}

// S5: the engineer tier's sshd lockdown is a drop-in of its own, written at
// every sync of this server whatever the console's state (here: no console
// link at all), checked on its own by 'console check', and not part of the
// console's drop-in.
func TestEngineerSSHDDropInWithoutTheConsole(t *testing.T) {
	hs := hostLowerSandbox(t)
	engineer := hs.path("sshd_config.d", "00-tacctl-engineer.conf")
	consoleDropIn := hs.path("sshd_config.d", "tacctl-console.conf")
	r := hs.lowerRunner()
	r.On([]string{"sshd", "-t"}, execx.Result{})
	hs.run(r, "host", "sync", "authsrv")
	all := plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "Installed: sshd drop-in "+engineer+" (engineer tier)") {
		t.Fatalf("sync: %d\n%s", hs.code, all)
	}
	if data, _ := os.ReadFile(engineer); string(data) != console.EngineerDropIn(false) {
		t.Errorf("drop-in %q", data)
	}
	if _, err := os.Stat(consoleDropIn); err == nil {
		t.Error("the console's drop-in was written without the console")
	}
	if !r.Called("sshd", "-t") || !r.Called("systemctl", "reload", "ssh.service") {
		t.Errorf("sshd not checked and reloaded: %q", r.Argvs())
	}
	for _, want := range []string{"Match Group tac-engineer", "DisableForwarding yes", "AllowTcpForwarding no", "PermitTunnel no", "GatewayPorts no"} {
		if !strings.Contains(console.EngineerDropIn(false), want) {
			t.Errorf("the engineer drop-in lacks %q", want)
		}
	}
	// The console's own text no longer holds an engineer block.
	if strings.Contains(console.DropIn("/usr/local/bin/tacctl-console", false, false, []tier.Tier{tier.Superuser}), tier.EngineerGroup) {
		t.Error("the console's drop-in still mentions the engineer group")
	}
	// Again: unchanged, not reloaded, not reported.
	r = hs.lowerRunner()
	r.On([]string{"sshd", "-t"}, execx.Result{})
	hs.run(r, "host", "sync", "authsrv")
	if all = plain(hs.out.String() + hs.err.String()); hs.code != 0 || strings.Contains(all, "engineer tier)") || r.Called("systemctl", "reload") {
		t.Errorf("second sync: %d\n%s", hs.code, all)
	}
	// sshd refusing it is a warning; the accounts are synced anyway and the
	// file is put back.
	if err := os.Remove(engineer); err != nil {
		t.Fatal(err)
	}
	r = hs.lowerRunner()
	r.On([]string{"sshd", "-t"}, execx.Result{Code: 255, Stderr: []byte("bad config\n")})
	hs.run(r, "host", "sync", "authsrv")
	all = plain(hs.out.String() + hs.err.String())
	if hs.code != 0 || !strings.Contains(all, "sshd refused the engineer tier's drop-in; "+engineer+" was put back as it was:") ||
		!strings.Contains(all, "until sshd's drop-in for the engineer tier is in place an engineer can still forward ports") || !r.Called("bash") {
		t.Errorf("refused: %d\n%s", hs.code, all)
	}
	if _, err := os.Stat(engineer); err == nil {
		t.Error("the refused drop-in stayed")
	}
}

// S5: 'console check' verifies the engineer drop-in on its own.
func TestConsoleCheckEngineerDropIn(t *testing.T) {
	sb, link := consoleInstallSandbox(t)
	engineer := sb.path("sshd_config.d", "00-tacctl-engineer.conf")
	out := sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link, "alice")))
	if sb.code != 0 || !strings.Contains(out, "Installed: sshd drop-in "+engineer+" (engineer tier)") {
		t.Fatalf("install: %d\n%s", sb.code, out)
	}
	check := func() string {
		return sb.rootRun([]string{"console", "check"}, both(sshdOK(link), passwdWith(link, "alice")))
	}
	if out = check(); sb.code != 0 || !strings.Contains(out, "sshd drop-in "+engineer+": present, current") {
		t.Errorf("current: %d\n%s", sb.code, out)
	}
	sb.write("sshd_config.d/00-tacctl-engineer.conf", "Match Group tac-engineer\n    AllowTcpForwarding yes\n", 0o644)
	if out = check(); sb.code != 1 || !strings.Contains(out, "sshd drop-in "+engineer+": present, differs from this release's") {
		t.Errorf("differs: %d\n%s", sb.code, out)
	}
	if err := os.Remove(engineer); err != nil {
		t.Fatal(err)
	}
	if out = check(); sb.code != 1 || !strings.Contains(out, "sshd's drop-in for the engineer tier "+engineer+" is missing") {
		t.Errorf("missing: %d\n%s", sb.code, out)
	}
	// 'console remove' leaves it: engineers without the console still need it.
	sb.rootRun([]string{"console", "install"}, both(sshdOK(link), passwdWith(link)))
	sb.rootRun([]string{"console", "remove"}, both(sshdOK(link), passwdWith(link)))
	if _, err := os.Stat(engineer); err != nil {
		t.Errorf("console remove took the engineer drop-in: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(engineer), "tacctl-console.conf")); err == nil {
		t.Error("console remove left the console's drop-in")
	}
}

// N3: a device registry that cannot be read does not let an engineer name a
// device of another scope in 'config <vendor> --staging --name'.
func TestEngineerStagingNameFailsClosed(t *testing.T) {
	sb := engineerSandbox(t)
	sb.asEngineer("", "config", "cisco", "--scope", "lab", "--staging", "192.168.1.50", "--name", "prod-sw")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "Device 'prod-sw' not found.") {
		t.Fatalf("readable: %d %q", sb.code, sb.stderr())
	}
	sb.write("state/devices.yaml", "devices: [broken\n", 0o600)
	sb.asEngineer("", "config", "cisco", "--scope", "lab", "--staging", "192.168.1.50", "--name", "prod-sw")
	if sb.code == 0 {
		t.Errorf("unreadable registry: %d %q", sb.code, sb.stderr())
	}
}
