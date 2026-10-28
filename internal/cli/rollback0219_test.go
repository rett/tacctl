package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"time"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.19' on the host sandbox. The plan's own cases are
// internal/lifecycle's.

// rollback0220State is the state of rollbackState with what 0.2.20 writes
// and 0.2.19 refuses: a strict management filter mode, the console's colour
// and a list_max that never asks, a system-shell setting and a password-cache
// choice of one user, and a user who must change the password; and what
// 0.2.19 reads as it is: a lockdown that stands, the Junos root account as a
// break-glass entry, and the record of a pull of a Junos device.
func rollback0220State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollbackState(t)
	hs.step("", "scope", "mgmt-acl", "lab", "add", "10.0.0.0/8")
	hs.step("", "scope", "mgmt-acl", "lab", "mode", "strict")
	hs.step("", "console", "color", "on")
	hs.step("", "console", "list-max", "-1")
	hs.step("", "console", "system-shell", "user", "bob", "enable")
	hs.write("state/console.yaml", strings.Replace(hs.read("state/console.yaml"), "settings:\n", "settings:\n  password_cache_users: {erin: true}\n", 1), 0o600)
	flagPasswordChange(t, hs, "erin")
	hs.step("", "scope", "breakglass", "prod", "add", "bg-prod")
	hs.step("", "scope", "breakglass", "prod", "add", "root")
	// The record of a pull of the Junos device sw2 (scope prod) by this
	// release: its breakglass section holds root's password (the leaf's name
	// only) and the root-login leaf, as every Junos pull of 0.2.20 keeps them.
	st := devconf.Store{Records: hs.path("var-lib", "devices-config.json"), Dir: hs.path("var-lib", "device-config")}
	recs, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	recs.Put("sw2", devconf.Record{Address: "10.99.0.2", Vendor: "juniper", Transport: "ssh", Pulled: time.Now().Add(-time.Hour), Result: devconf.ResultOK, SecretsVisible: true})
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	if err := st.SaveSections("sw2", "juniper", map[string]devices.Section{"breakglass": {Name: "breakglass", Lines: []string{
		`set system root-authentication encrypted-password "$6$examplesalt$EXAMPLEHASH"`, "set system services ssh root-login allow"}}}); err != nil {
		t.Fatal(err)
	}
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    lab:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	return hs
}

// The dry run writes nothing; --apply puts back 0.2.19's per-tier drop-in
// after visudo, takes no snapshot when no file of tacctl's own is converted
// and ends with the upgrade of the tag; a second --apply has nothing to
// convert.
func TestRollback0219PutsBackTheTiersDropIn(t *testing.T) {
	hs := rollback0216State(t, "true")
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.19"}, {"rollback", "v0.2.19", "--hosts"}} {
		r := hs.runner()
		hs.run(r, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps || r.Called("visudo") || r.Called("ssh") {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
	}
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.19 (dry run)",
		"2. put back the per-tier sudoers drop-in 0.2.19 writes   [does]",
		"the engineer's rule of 'scope mgmt-acl * mode'",
		"0.2.20 changed nothing on the enrolled hosts",
		"To convert the state: tacctl rollback 0.2.19 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}

	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.19", "--apply")
	hs.expect(0, "Applying.", "")
	out = hs.all()
	for _, want := range []string{"sudoers.d/tacctl-tiers: rewritten with the text 0.2.19 writes", "Next steps", "tacctl upgrade --branch 0.2.19",
		"do not run 'tacctl scope mgmt-acl <scope> mode strict', 'tacctl user add'"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if !r.CalledRegexp(`^visudo -cf `) {
		t.Errorf("no visudo check: %q", r.Argvs())
	}
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers0219() {
		t.Errorf("the tiers drop-in is not 0.2.19's:\n%s", got)
	}
	if hs.snapshots() != snaps {
		t.Errorf("a snapshot was taken")
	}
	if !strings.Contains(hs.overrides(), "strict: true") {
		t.Error("audit.strict, a key 0.2.19 has, was removed")
	}
	hs.run(nil, "rollback", "0.2.19", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.19 can read.", "")
}

// 0.2.20's keys are removed after a snapshot, with the warnings and --yes; a
// lockdown that stands does not refuse 0.2.19 and stays.
func TestRollback0219RemovesThe0220Keys(t *testing.T) {
	hs := rollback0220State(t)
	hs.run(nil, "rollback", "0.2.19")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"remove scope_mgmt_acl.mode.lab", "remove settings.color: on", "set settings.list_max to 1000",
		"remove settings.system_shell_users: bob enable", "remove settings.password_cache_users: erin (on)", "remove password_change_required of erin",
		"Scopes with a strict management filter lose the mode", "Users who must change their password get their device access back",
		"Scopes that record the Junos root account for break-glass", "tacctl scope breakglass prod remove root",
		"take the Junos root statements out of the stored pulls", "take 2 statements out of the breakglass section of sw2.yaml",
		"To convert the state: tacctl rollback 0.2.19 --apply --yes"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "locked down") {
		t.Errorf("the lockdown refuses 0.2.19:\n%s", out)
	}
	hs.run(nil, "rollback", "0.2.19", "--apply")
	hs.expect(1, "", "The warnings above need your decision")
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.19", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	if hs.snapshots() == snaps {
		t.Error("no snapshot was taken first")
	}
	ov := hs.overrides()
	if strings.Contains(ov, "mode:") || !strings.Contains(ov, "lockdown:") || !strings.Contains(ov, "10.0.0.0/8") {
		t.Errorf("tacctl.yaml after:\n%s", ov)
	}
	if c := hs.read("state/console.yaml"); strings.Contains(c, "color") || strings.Contains(c, "system_shell_users") || strings.Contains(c, "password_cache_users") || !strings.Contains(c, "list_max: 1000") {
		t.Errorf("console.yaml after:\n%s", c)
	}
	if strings.Contains(hs.read("state/store.yaml"), "password_change_required") {
		t.Error("the store keeps the flag")
	}
	if got := hs.read("var-lib/device-config/sw2.yaml"); strings.Contains(got, "root") || !strings.Contains(got, "breakglass: \"\"") {
		t.Errorf("the stored pull of sw2 after:\n%s", got)
	}
}

// The check against the real release: where the 0.2.19 tag is here and go is
// there, build that release (testknobs) and run its readers against the
// state, before and after the rollback. Before, its config validate refuses
// the mode key and the password change flag, and its console show the console
// settings of 0.2.20; after, both read the state, the lockdown that stands
// included, its store commands write it, and once 0.2.19 has rendered, the
// state is valid.
func TestRollbackRealOldBinary0219(t *testing.T) {
	bin := oldBinaryOf(t, "0.2.19", old0219Flag)
	hs := rollback0220State(t)
	stubs := t.TempDir()
	for _, name := range []string{"systemctl", "logger", "chown"} {
		if err := os.WriteFile(filepath.Join(stubs, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	run := func(args ...string) (string, int) {
		res, err := execx.Real{}.Run(context.Background(), execx.Cmd{Name: bin, Args: args,
			Env: append(append([]string(nil), hs.env...), "PATH="+stubs+":/usr/bin:/bin", "HOME="+t.TempDir(), "LANG=C.UTF-8")})
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return plain(string(res.Stdout) + string(res.Stderr)), res.Code
	}
	out, code := run("config", "validate")
	if code != 1 || !strings.Contains(out, "scope_mgmt_acl.mode.lab: unknown config key") || !strings.Contains(out, "user 'erin': unknown field 'password_change_required'") {
		t.Errorf("0.2.19 config validate before: %d\n%s", code, out)
	}
	if out, code := run("console", "show"); code != 1 || !strings.Contains(out, "settings: unknown key") {
		t.Errorf("0.2.19 console show before: %d\n%s", code, out)
	}
	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.19", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	// The rendered files are this release's (they keep erin off the devices,
	// the warning says so) until 0.2.19 renders them.
	out, _ = run("config", "validate")
	for _, want := range []string{"Store:                valid", "tacctl.yaml:          valid", "scope lab is locked down"} {
		if !strings.Contains(out, want) || strings.Contains(out, "unknown") {
			t.Errorf("0.2.19 config validate after: no %q\n%s", want, out)
		}
	}
	if out, code := run("config", "render"); code != 0 {
		t.Errorf("0.2.19 config render after: %d\n%s", code, out)
	}
	if out, code := run("config", "validate"); code != 0 || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.19 config validate after its render: %d\n%s", code, out)
	}
	if out, code := run("console", "show"); code != 0 || strings.Contains(out, "unknown") || strings.Contains(out, "must be") {
		t.Errorf("0.2.19 console show after: %d\n%s", code, out)
	}
	if out, code := run("user", "disable", "erin"); code != 0 {
		t.Errorf("0.2.19 user disable (a store write) after: %d\n%s", code, out)
	}
	if out, code := run("emergency", "lockdown", "status", "lab"); code != 0 || !strings.Contains(out, "operator") {
		t.Errorf("0.2.19 emergency lockdown status after: %d\n%s", code, out)
	}
	// The root entry stays and 0.2.19 renders it as a local user, as the
	// warning says.
	if out, code := run("config", "juniper", "--scope", "prod"); code != 0 || !strings.Contains(out, "# set system login user root class ") || strings.Contains(out, "root-authentication") || strings.Contains(out, "root-login") {
		t.Errorf("0.2.19 config juniper after: %d\n%s", code, out)
	}
	if out, code := run("config", "cisco", "--scope", "prod"); code != 0 || !strings.Contains(out, "! username root privilege 15 ") {
		t.Errorf("0.2.19 config cisco after: %d\n%s", code, out)
	}
	// 0.2.19's comparison expects root as a login user on the Junos device of
	// the scope, which Junos never has; with the entry removed (0.2.19 can) it
	// does not. The root statements of this release's pull are out of the
	// stored section.
	if out, _ := run("device", "config", "diff", "sw2"); !strings.Contains(out, "- set system login user root class ") || strings.Contains(out, "root-authentication") || strings.Contains(out, "root-login") {
		t.Errorf("0.2.19 device config diff after:\n%s", out)
	}
	if out, code := run("scope", "breakglass", "prod", "remove", "root"); code != 0 {
		t.Errorf("0.2.19 scope breakglass remove root after: %d\n%s", code, out)
	}
	if out, _ := run("device", "config", "diff", "sw2"); strings.Contains(out, "login user root") {
		t.Errorf("0.2.19 device config diff without the entry:\n%s", out)
	}
	// Why they are taken out: left in, 0.2.19 reads them as extra statements
	// of the section, which differs.
	if err := (devconf.Store{Records: hs.path("var-lib", "devices-config.json"), Dir: hs.path("var-lib", "device-config")}).SaveSections("sw2", "juniper",
		map[string]devices.Section{"breakglass": {Name: "breakglass", Lines: []string{"set system root-authentication encrypted-password \"$6$examplesalt$EXAMPLEHASH\"", "set system services ssh root-login allow"}}}); err != nil {
		t.Fatal(err)
	}
	if out, _ := run("device", "config", "diff", "sw2"); !strings.Contains(out, "breakglass  differs") || !strings.Contains(out, "+ set system root-authentication encrypted-password") ||
		!strings.Contains(out, "+ set system services ssh root-login allow") {
		t.Errorf("0.2.19 device config diff of a stored pull of this release:\n%s", out)
	}
}

// old0219Flag names a 0.2.19 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary0219 -args -old-bin-0219=<path>.
var old0219Flag = flag.String("old-bin-0219", "", "a tacctl 0.2.19 binary built with -tags testknobs (TestRollbackRealOldBinary0219)")
