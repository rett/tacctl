package cli

// WP10.8a, A2: a setting of a group that is gone is not taken over by a new
// group of the same name.

import (
	"slices"
	"strings"
	"testing"
)

// A leftover tier.<group> (the group went with a store import, a restore or
// a hand edit) is not taken over by a NEW group of that name: group add
// clears the tier, WTI level and Junos rules of the name unless the flag is
// given.
func TestGroupAddClearsALeftoverTierSetting(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/tacctl.yaml", "tier:\n  helpdesk: superuser\n  keep: engineer\nwti_level:\n  helpdesk: administrator\n"+
		"junos:\n  helpdesk:\n    deny_commands: ['^request system.*$']\n", 0o600)
	out := sb.asUser("alice", "tac-superuser", "group", "add", "helpdesk", "5", "HELP-CLASS")
	if sb.code != 0 || !strings.Contains(plain(out), "tacctl.yaml still held tier, wti-level, junos settings of an earlier group 'helpdesk'") {
		t.Fatalf("group add: %d %q %q", sb.code, out, sb.stderr())
	}
	y := sb.read("state/tacctl.yaml")
	if strings.Contains(y, "helpdesk") || !strings.Contains(y, "keep: engineer") {
		t.Errorf("tacctl.yaml after the add:\n%s", y)
	}
	sb.asUser("alice", "tac-superuser", "user", "move", "carol", "helpdesk")
	if sb.code != 0 {
		t.Fatalf("user move: %d %q", sb.code, sb.stderr())
	}
	if got := sb.asUser("carol", "", "_console-policy"); !strings.Contains(got, " tier=readonly ") {
		t.Errorf("carol took over the leftover tier: %q", got)
	}

	// With --tier the flag sets it again; the leftover WTI level still goes.
	sb.write("state/tacctl.yaml", "tier:\n  ops: superuser\nwti_level:\n  ops: administrator\n", 0o600)
	sb.asUser("alice", "tac-superuser", "group", "add", "ops", "5", "OPS-CLASS", "--tier", "operator")
	y = sb.read("state/tacctl.yaml")
	if sb.code != 0 || !strings.Contains(y, "ops: operator") || strings.Contains(y, "administrator") || strings.Contains(y, "superuser") {
		t.Errorf("group add --tier over a leftover: %d\n%s", sb.code, y)
	}
	// A group with no leftover says nothing about it.
	sb.asUser("alice", "tac-superuser", "group", "add", "plain", "5", "PLAIN-CLASS")
	if strings.Contains(plain(sb.out.String()), "earlier group") {
		t.Errorf("group add without a leftover: %q", sb.out.String())
	}
}

// config validate warns (no error) of settings for groups that do not
// exist, and the steps that replace the store but keep tacctl.yaml say the
// same.
func TestStaleGroupSettingsAreWarnedOf(t *testing.T) {
	sb := renderedSandbox(t)
	sb.write("state/tacctl.yaml", "tier:\n  ghost: superuser\n  operator: engineer\nwti_level:\n  ghost: user\n", 0o600)
	sb.run("", []string{"config", "validate"})
	out := plain(sb.out.String() + sb.err.String())
	if !strings.Contains(out, "Group settings:") || !strings.Contains(out, "tier, wti-level settings for group 'ghost', which does not exist") {
		t.Errorf("config validate:\n%s", out)
	}
	if strings.Contains(out, "'operator', which does not exist") {
		t.Errorf("a group that exists is reported:\n%s", out)
	}
	if sb.code != 0 {
		t.Errorf("a stale setting is a warning, not an error: exit %d %q", sb.code, sb.stderr())
	}

	// store import --replace: the imported store has no 'ghost'.
	hs := hostLowerSandbox(t)
	hs.write("state/tacctl.yaml", "tier:\n  ghost: superuser\n", 0o600)
	hs.stdin = "y\n"
	hs.run(hs.lowerRunner(), "store", "import", "--replace")
	if all := plain(hs.out.String() + hs.err.String()); hs.code != 0 || !strings.Contains(all, "settings for group 'ghost', which does not exist") {
		t.Errorf("store import --replace: %d\n%s", hs.code, all)
	}

	// backup restore --legacy.
	lg := renderedSandbox(t)
	lg.write("state/tacctl.yaml", "tier:\n  ghost: superuser\n", 0o600)
	lg.write("state/backups/legacy/tacquito.yaml.pre-store.20250101_000000", fixture(t, "golden/tacquito.minimal.rendered.yaml"), 0o600)
	lg.run("y\n", []string{"backup", "restore", "--legacy", "pre-store.20250101_000000"})
	if all := plain(lg.out.String() + lg.err.String()); lg.code != 0 || !strings.Contains(all, "settings for group 'ghost', which does not exist") {
		t.Errorf("backup restore --legacy: %d\n%s", lg.code, all)
	}
}

// C-missing (5): the reset family restarts each backend its change reaches
// exactly once with --yes, and none on a dry run: 'group reset' changes what
// both backends render, 'group commands reset' what only TACACS+ renders,
// 'group privilege reset' nothing a daemon reads.
func TestResetFamilyRestartsEachBackendOnce(t *testing.T) {
	for _, c := range []struct {
		args           []string
		tacacs, radius int
	}{
		{[]string{"group", "reset", "operator", "--yes"}, 1, 1},
		{[]string{"group", "commands", "reset", "operator", "--yes"}, 1, 0},
		{[]string{"group", "privilege", "reset", "operator", "--yes"}, 0, 0},
	} {
		sb := newSandbox(t, true)
		// RADIUS is enabled only where it is expected to restart (rendering
		// its files is the slow part of the sandbox); for the others it is
		// the reset that must leave a daemon alone.
		if c.radius > 0 {
			sandboxRADIUS(sb)
			sb.write("state/tacctl.yaml", "backends:\n  enabled: [tacacs, radius]\n", 0o600)
		}
		sb.modify("operator")
		restarts := func(unit string) int { return sb.runner.Count("systemctl", "restart", unit) }

		// Dry run, with and without --yes: nothing is restarted, nothing run.
		for _, dry := range [][]string{append(slices.Clone(c.args[:len(c.args)-1]), "--dry-run"), append(slices.Clone(c.args), "--dry-run")} {
			sb.plainRun("", dry...)
			if sb.code != 0 || sb.runner.Called("systemctl") {
				t.Errorf("%v: exit %d, systemctl called: %q", dry, sb.code, sb.runner.Argvs())
			}
		}

		out := sb.plainRun("", c.args...)
		if sb.code != 0 {
			t.Fatalf("%v: exit %d\n%s%s", c.args, sb.code, out, sb.err.String())
		}
		if n := restarts("tacquito"); n != c.tacacs {
			t.Errorf("%v: tacquito restarted %d times, want %d: %q", c.args, n, c.tacacs, sb.runner.Argvs())
		}
		if n := restarts("freeradius.service"); n != c.radius {
			t.Errorf("%v: freeradius restarted %d times, want %d: %q", c.args, n, c.radius, sb.runner.Argvs())
		}
		// Nothing to change the second time: no restart at all.
		sb.plainRun("", c.args...)
		if sb.code != 0 || sb.runner.Called("systemctl", "restart") {
			t.Errorf("%v again: exit %d, restarted: %q", c.args, sb.code, sb.runner.Argvs())
		}
	}
}
