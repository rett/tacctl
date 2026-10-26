package cli

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The emergency lockdown (0.2.19) in-process, on the engineer sandbox: alice
// (superuser) is in prod and lab, bob (an engineer by the tier setting) in
// lab, carol (readonly) in lab and dmz.

// lockdown runs 'emergency lockdown <args>' typing typed on a terminal.
func (sb *sandbox) lockdown(t *testing.T, typed string, args ...string) string {
	t.Helper()
	sb.tty = nil
	if typed != "" {
		holdTTY(t, sb, typed+"\n")
	}
	out := plain(sb.run("", append([]string{"emergency", "lockdown"}, args...)))
	sb.tty = nil
	return out
}

func TestEmergencyLockdownRoundTrip(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	if !strings.Contains(original, "bob") {
		t.Fatal("bob is not rendered")
	}

	// the dry run says who loses access and changes nothing
	out := sb.lockdown(t, "", "lab", "enable", "--dry-run")
	for _, want := range []string{"Lock the logins of operator, readonly on scope 'lab'?", "Lose access (2): bob, carol",
		"Keep access, superusers (1): alice", "Dry run: nothing was changed."} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run lacks %q:\n%s", want, out)
		}
	}
	if o := sb.overrides(); strings.Contains(o, "emergency") || sb.restarts() != 0 {
		t.Fatalf("a dry run changed something:\n%s", o)
	}

	// a terminal is required and the scope typed back
	sb.run("", []string{"emergency", "lockdown", "lab", "enable"})
	sb.expect(1, "", "No terminal to confirm on")
	sb.lockdown(t, "labx", "lab", "enable")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "What was typed is not 'lab'. Nothing was changed.") {
		t.Fatalf("a wrong name: %d %q", sb.code, sb.stderr())
	}
	if strings.Contains(sb.overrides(), "emergency") {
		t.Fatal("a refused lockdown wrote the record")
	}

	// the lockdown: one restart, the record, the users gone from the scope
	out = sb.lockdown(t, "lab", "lab", "enable", "--reason", "credential leak")
	if sb.code != 0 {
		t.Fatalf("enable: %d %q %q", sb.code, out, sb.stderr())
	}
	for _, want := range []string{"EMERGENCY LOCKDOWN on scope 'lab' since ", " by root", "logins of groups operator, readonly are refused; superusers keep access. Reason: credential leak",
		"Rendered: tacacs rendered and restarted", "Lift it with: tacctl emergency lockdown lab disable"} {
		if !strings.Contains(out, want) {
			t.Errorf("enable report lacks %q:\n%s", want, out)
		}
	}
	if n := sb.restarts(); n != 1 {
		t.Errorf("%d restarts, want 1", n)
	}
	o := sb.overrides()
	for _, want := range []string{"emergency:\n  lockdown:\n    lab:\n", "groups:\n      - operator\n      - readonly\n", "reason: credential leak\n", "by: root\n"} {
		if !strings.Contains(o, want) {
			t.Errorf("tacctl.yaml lacks %q:\n%s", want, o)
		}
	}
	if !hasAuditMatch(sb.runner, "auth.notice", `emergency lockdown enable scope=lab groups=operator,readonly exempt=alice reason="credential leak" by=root locked=2 result=ok`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	cfg := sb.renderedConfig()
	if cfg == original {
		t.Fatal("the rendered file did not change")
	}
	if strings.Contains(cfg, "credential leak") {
		t.Error("the reason is in the rendered file")
	}
	if !strings.Contains(sb.store(), "bob") {
		t.Error("the store was changed")
	}

	// locked again: nothing to do
	sb.lockdown(t, "", "lab", "enable", "operator")
	if sb.code != 0 {
		t.Errorf("again: %d %q", sb.code, sb.stderr())
	}

	// status, plain and JSON
	st := plain(sb.run("", []string{"emergency", "lockdown", "status"}))
	for _, want := range []string{"EMERGENCY LOCKDOWN on scope 'lab'", "Locked out (2): bob, carol", "Superusers who keep access: alice", "Lift it with: tacctl emergency lockdown lab disable"} {
		if !strings.Contains(st, want) {
			t.Errorf("status lacks %q:\n%s", want, st)
		}
	}
	var js []lockdownJSON
	if err := json.Unmarshal([]byte(sb.run("", []string{"emergency", "lockdown", "status", "--json"})), &js); err != nil || len(js) != 1 ||
		js[0].Scope != "lab" || strings.Join(js[0].LockedUsers, ",") != "bob,carol" || strings.Join(js[0].Exempt, ",") != "alice" {
		t.Errorf("status --json: %v %+v", err, js)
	}
	if got := plain(sb.run("", []string{"emergency", "lockdown", "prod"})); !strings.Contains(got, "No emergency lockdown stands on scope 'prod'.") {
		t.Errorf("a bare scope: %q", got)
	}

	// the message on the commands of the scope, not on the others
	sb.run("", []string{"scope", "show", "lab"})
	if !strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN on scope 'lab'") {
		t.Errorf("scope show lab: no notice in %q", sb.stderr())
	}
	sb.run("", []string{"scope", "show", "prod"})
	if strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN") {
		t.Errorf("scope show prod: a notice for another scope: %q", sb.stderr())
	}
	sb.run("", []string{"device", "show", "lab-sw"})
	if !strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN on scope 'lab'") {
		t.Errorf("device show lab-sw: no notice in %q", sb.stderr())
	}
	sb.run("", []string{"scope", "list"})
	if !strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN on scope 'lab'") {
		t.Errorf("scope list: no notice in %q", sb.stderr())
	}

	// narrowing, then lifting: the rendered file comes back as it was
	sb.lockdown(t, "", "lab", "disable", "readonly")
	if sb.code != 0 || !strings.Contains(sb.overrides(), "- operator\n") || strings.Contains(sb.overrides(), "- readonly\n") {
		t.Errorf("narrow: %d %q\n%s", sb.code, sb.stderr(), sb.overrides())
	}
	out = sb.lockdown(t, "", "lab", "disable")
	if sb.code != 0 || !strings.Contains(out, "Emergency lockdown LIFTED on scope 'lab'") {
		t.Fatalf("disable: %d %q %q", sb.code, out, sb.stderr())
	}
	if strings.Contains(sb.overrides(), "emergency") {
		t.Errorf("the record stands:\n%s", sb.overrides())
	}
	if got := sb.renderedConfig(); got != original {
		t.Errorf("the rendered file is not what it was:\n%s", got)
	}
	if !hasAuditMatch(sb.runner, "auth.notice", `emergency lockdown disable scope=lab groups=operator held=`) {
		t.Errorf("no audit line: %v", sb.runner.Argvs())
	}
	sb.run("", []string{"scope", "show", "lab"})
	if strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN") {
		t.Errorf("a notice after the lift: %q", sb.stderr())
	}
}

func TestEmergencyLockdownRefusals(t *testing.T) {
	sb := engineerSandbox(t)
	for _, c := range []struct {
		args []string
		err  string
	}{
		{[]string{"lab", "enable", "superuser"}, "Group 'superuser' is a superuser group, and superusers are never locked."},
		{[]string{"lab", "enable", "--tier", "superuser"}, "Superusers are never locked"},
		{[]string{"lab", "enable", "nogroup"}, "There is no group 'nogroup'."},
		{[]string{"nolab", "enable"}, "There is no scope 'nolab'."},
		{[]string{"lab", "enable", "operator", "--tier", "readonly"}, "Give the groups or --tier, not both."},
		{[]string{"lab", "freeze"}, "Unknown action: 'freeze'"},
	} {
		sb.run("", append([]string{"emergency", "lockdown"}, c.args...))
		if sb.code != 1 || !strings.Contains(sb.stderr(), c.err) {
			t.Errorf("%v: %d %q", c.args, sb.code, sb.stderr())
		}
	}
	if strings.Contains(sb.overrides(), "emergency") {
		t.Error("a refusal wrote the record")
	}
	// the verb is the superuser's
	sb.asEngineer("", "emergency", "lockdown", "lab", "enable", "--dry-run")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "is not permitted for the engineer tier") {
		t.Errorf("as an engineer: %d %q", sb.code, sb.stderr())
	}
}

func TestEmergencyLockdownEngineerSeesTheNoticeOfOwnScopes(t *testing.T) {
	sb := engineerSandbox(t)
	sb.lockdown(t, "prod", "prod", "enable", "--tier", "engineer")
	if sb.code != 0 {
		t.Fatalf("enable: %d %q", sb.code, sb.stderr())
	}
	sb.asEngineer("", "device", "show", "lab-sw")
	if strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN") {
		t.Errorf("the lockdown of prod is shown for lab: %q", sb.stderr())
	}
	sb.lockdown(t, "lab", "lab", "enable")
	sb.asEngineer("", "device", "show", "lab-sw")
	if !strings.Contains(sb.stderr(), "EMERGENCY LOCKDOWN on scope 'lab'") || strings.Contains(sb.stderr(), "scope 'prod'") {
		t.Errorf("the engineer's notice: %q", sb.stderr())
	}
}

func TestEmergencyLockdownFollowsNamesAndIsReported(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"group", "add", "temps", "5", "TEMP-CLASS"})
	if sb.code != 0 {
		t.Skipf("group add: %d %q", sb.code, sb.stderr())
	}
	sb.lockdown(t, "lab", "lab", "enable", "temps,operator", "--reason", "drill")
	if sb.code != 0 {
		t.Fatalf("enable: %d %q", sb.code, sb.stderr())
	}
	if got := plain(sb.run("", []string{"status"})); !strings.Contains(got, "Emergency lockdown: scope lab since ") {
		t.Errorf("status:\n%s", got)
	}
	got := plain(sb.run("", []string{"config", "validate"}))
	if !strings.Contains(got, "scope lab is locked down since ") || !strings.Contains(got, "tacctl emergency lockdown lab disable") {
		t.Errorf("config validate:\n%s", got)
	}
	// a group that is removed leaves the lockdown
	sb.run("y\n", []string{"group", "remove", "temps"})
	if sb.code != 0 || strings.Contains(sb.overrides(), "- temps") || !strings.Contains(sb.overrides(), "- operator") {
		t.Errorf("group remove: %d %q\n%s", sb.code, sb.stderr(), sb.overrides())
	}
	// a scope that is renamed takes the record with it
	sb.run("y\n", []string{"scope", "rename", "dmz", "dmz2"})
	sb.run("y\n", []string{"scope", "rename", "lab", "lab2"})
	if sb.code != 0 || !strings.Contains(sb.overrides(), "    lab2:\n") || strings.Contains(sb.overrides(), "    lab:\n") {
		t.Errorf("scope rename: %d %q\n%s", sb.code, sb.stderr(), sb.overrides())
	}
}

// A restore is a render like any other: a lockdown goes with a snapshot that
// lacks it, and the report names the lockdowns before and after.
func TestEmergencyLockdownGoesWithARestoredSnapshotThatLacksIt(t *testing.T) {
	sb := engineerSandbox(t)
	sb.run("", []string{"config", "render"})
	original := sb.renderedConfig()
	if out := sb.lockdown(t, "lab", "lab", "enable"); sb.code != 0 {
		t.Fatalf("enable: %q %q", out, sb.stderr())
	}
	snaps, _ := filepath.Glob(sb.path("state", "backups", "2*"))
	slices.Sort(snaps)
	var id string
	for i := len(snaps) - 1; i >= 0; i-- {
		if !strings.Contains(sb.read("state/backups/"+filepath.Base(snaps[i])+"/tacctl.yaml"), "emergency") {
			id = filepath.Base(snaps[i])
			break
		}
	}
	if id == "" {
		t.Fatalf("no snapshot without the lockdown: %v", snaps)
	}
	out := plain(sb.run("y\n", []string{"backup", "restore", id}))
	if sb.code != 0 {
		t.Fatalf("restore: %d %q %q", sb.code, out, sb.stderr())
	}
	if want := "Emergency lockdowns change: locked now: lab (operator, readonly); locked after the restore: none"; !strings.Contains(out, want) {
		t.Errorf("the restore does not name the lockdowns:\n%s", out)
	}
	if got := sb.renderedConfig(); got != original {
		t.Errorf("the restored rendering is not the original:\n%s", got)
	}
}

func TestEmergencyLockdownRefusesAGroupMadeASuperuser(t *testing.T) {
	sb := engineerSandbox(t)
	sb.lockdown(t, "lab", "lab", "enable")
	if sb.code != 0 {
		t.Fatalf("enable: %d %q", sb.code, sb.stderr())
	}
	for _, args := range [][]string{{"group", "edit", "operator", "tier", "superuser"}, {"group", "edit", "readonly", "priv-lvl", "15"}} {
		sb.run("y\n", args)
		if sb.code != 1 || !strings.Contains(sb.stderr(), "is locked by an emergency lockdown on scope(s) lab, and a superuser group is never locked") {
			t.Errorf("%v: %d %q", args, sb.code, sb.stderr())
		}
	}
	if strings.Contains(sb.read("state/tacctl.yaml"), "tier:\n  operator: superuser") {
		t.Error("the tier was written")
	}
	// lifted, the same edit goes through
	sb.lockdown(t, "", "lab", "disable")
	sb.run("y\n", []string{"group", "edit", "operator", "tier", "superuser"})
	if sb.code != 0 {
		t.Errorf("after the lift: %d %q", sb.code, sb.stderr())
	}
}

func TestEmergencyLockdownDisableNamesAGroupTheRecordHoldsAlone(t *testing.T) {
	sb := engineerSandbox(t)
	sb.write("state/tacctl.yaml", "tier:\n  operator: engineer\nemergency:\n  lockdown:\n    lab:\n      groups:\n        - ghost\n        - readonly\n      since: '2026-10-25T12:00:00Z'\n      by: alice\n", 0o600)
	sb.lockdown(t, "", "lab", "disable", "ghost")
	if sb.code != 0 || strings.Contains(sb.overrides(), "ghost") || !strings.Contains(sb.overrides(), "readonly") {
		t.Errorf("disable ghost: %d %q\n%s", sb.code, sb.stderr(), sb.overrides())
	}
	sb.lockdown(t, "", "lab", "disable", "nogroup")
	if sb.code != 1 || !strings.Contains(sb.stderr(), "There is no group 'nogroup'.") {
		t.Errorf("disable nogroup: %d %q", sb.code, sb.stderr())
	}
}

// Which command lines of the verb change nothing (the audit class reads
// them without a start line).
func TestLockdownReadForm(t *testing.T) {
	for _, c := range []struct {
		args []string
		read bool
	}{
		{nil, true},
		{[]string{"status"}, true},
		{[]string{"status", "lab", "--json"}, true},
		{[]string{"lab"}, true},
		{[]string{"lab", "enable", "--dry-run"}, true},
		{[]string{"--all-scopes", "enable", "--dry-run"}, true},
		{[]string{"--help"}, true},
		{[]string{"lab", "enable"}, false},
		{[]string{"lab", "disable"}, false},
		{[]string{"lab", "enable", "ops", "--reason", "x"}, false},
		{[]string{"--all-scopes", "enable"}, false},
		{[]string{"--all-scopes", "disable", "ops"}, false},
	} {
		if got := lockdownReadForm(c.args); got != c.read {
			t.Errorf("%v: read = %v", c.args, got)
		}
	}
}
