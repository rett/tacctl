package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// 'tacctl rollback 0.2.21', the release before 0.2.22, on the host sandbox
// with this server enrolled. The plan's own cases are internal/lifecycle's.

// The dry run of 0.2.21 removes the server name and nothing else: the
// managed scope is 0.2.21's own, so no user is touched, and the server
// address stays. --apply needs no --yes (no warning), takes a snapshot, and a
// second run has nothing to do.
func TestRollback0221RemovesTheServerNameOnly(t *testing.T) {
	hs := rollback0221State(t)
	hs.step("", "server", "name", "core-1")
	before := tree(t, hs.dir)
	hs.run(hs.runner(), "rollback", "0.2.21", "--hosts")
	hs.expect(0, "This was a dry run: nothing was changed.", "")
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.21 (dry run)", "remove server.name", "the server name is 0.2.22's",
		"nothing to do for 0.2.21: this release changed nothing on the enrolled hosts", "To convert the state: tacctl rollback 0.2.21 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	for _, not := range []string{"remove server.addresses", "add scope", "Warnings", "--yes"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run says %q:\n%s", not, out)
		}
	}
	if got := changedFiles(before, tree(t, hs.dir)); len(got) != 0 {
		t.Errorf("the dry run changed %q", got)
	}
	storeBefore := hs.store()
	snaps := hs.snapshots()
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Applying.", "")
	if !strings.Contains(hs.all(), "removed 1 key") || !strings.Contains(hs.all(), "tacctl upgrade --branch 0.2.21") ||
		!strings.Contains(hs.all(), "do not run 'tacctl server name <label>'") {
		t.Errorf("--apply:\n%s", hs.all())
	}
	if hs.snapshots() == snaps {
		t.Error("no snapshot was taken first")
	}
	if o := hs.overrides(); strings.Contains(o, "name:") || !strings.Contains(o, "addresses") {
		t.Errorf("tacctl.yaml:\n%s", o)
	}
	if hs.store() != storeBefore {
		t.Error("the store changed: no scope is added to a user for 0.2.21")
	}
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.21 can read.", "")
}

// Without a server name there is nothing to do, and the plan says so.
func TestRollback0221WithNoServerName(t *testing.T) {
	hs := rollback0221State(t)
	hs.run(hs.runner(), "rollback", "0.2.21")
	hs.expect(0, "nothing to remove (no server name or timeout scale is set)", "")
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.21 can read.", "")
}

// 0.2.21 reads a user name with a period (0.2.20 and 0.2.21 allowed one), so
// it does not stop its rollback; 0.2.19 refuses the name, as before.
func TestRollback0221IsNotStoppedByADottedName(t *testing.T) {
	hs := rollback0221State(t)
	hs.write("state/store.yaml", strings.Replace(hs.store(), "\n  erin:", "\n  erin.smith:", 1), 0o600)
	hs.run(hs.runner(), "rollback", "0.2.21")
	hs.expect(0, "Roll back to 0.2.21 (dry run)", "")
	hs.run(hs.runner(), "rollback", "0.2.19")
	hs.expect(1, "", "erin.smith")
}

// 0.2.21 has the emergency lockdown record, so a lockdown that stands does not
// stop its rollback, in the dry run and with --apply, and the record stays;
// 0.2.18 has none and refuses, with the way out. (A reorder of the 0.2.21
// branch of PlanRollback behind the lockdown refusal fails here.)
func TestRollback0221IsNotStoppedByALockdown(t *testing.T) {
	hs := rollback0221State(t)
	hs.step("", "server", "name", "core-1")
	hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"emergency:\n  lockdown:\n    lab:\n      groups:\n      - operator\n      since: '2026-10-25T12:00:00+00:00'\n      by: alice\n      reason: drill\n", 0o640)
	hs.run(hs.runner(), "rollback", "0.2.21")
	hs.expect(0, "Roll back to 0.2.21 (dry run)", "")
	if strings.Contains(hs.all(), "locked down") {
		t.Errorf("the dry run names the lockdown as a reason:\n%s", hs.all())
	}
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Applying.", "")
	if o := hs.overrides(); !strings.Contains(o, "lockdown:") || !strings.Contains(o, "reason: drill") || strings.Contains(o, "name: core-1") {
		t.Errorf("tacctl.yaml after --apply:\n%s", o)
	}
	hs.run(hs.runner(), "rollback", "0.2.18")
	hs.expect(1, "", "Scope lab is locked down")
}

// The check against the real release: built from the 0.2.21 tag, its config
// validate refuses the server name before the rollback and reads the state
// after, with its server address, the users' login to the server and a user
// whose name has a period.
func TestRollbackRealOldBinary0221(t *testing.T) {
	bin := oldBinaryOf(t, "0.2.21", old0221Flag)
	hs := rollback0221State(t)
	hs.write("state/store.yaml", strings.Replace(hs.store(), "\n  erin:", "\n  erin.smith:", 1), 0o600)
	hs.step("", "server", "name", "core-1")
	// the timing scale of 0.2.22, in the three places 0.2.21 refuses it
	hs.step("", "config", "devices", "timeout-scale", "3")
	hs.step("", "scope", "timeout-scale", "lab", "2")
	hs.step("", "device", "timeout-scale", "sw1", "4")
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
	if out, code := run("config", "validate"); code != 1 || !strings.Contains(out, "server.name: unknown config key") ||
		!strings.Contains(out, "device.timeout_scale: unknown config key") || !strings.Contains(out, "timeout_scale_scope.lab: unknown config key") {
		t.Errorf("0.2.21 config validate before: %d\n%s", code, out)
	}
	if out, code := run("device", "list"); code == 0 || !strings.Contains(out, "unknown key 'timeout_scale'") {
		t.Errorf("0.2.21 device list before: %d\n%s", code, out)
	}
	hs.run(hs.runner(), "rollback", "0.2.21", "--apply")
	hs.expect(0, "Applying.", "")
	if out, code := run("config", "render"); code != 0 {
		t.Errorf("0.2.21 config render after: %d\n%s", code, out)
	}
	if out, code := run("config", "validate"); code != 0 || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.21 config validate after: %d\n%s", code, out)
	}
	if out, code := run("device", "show", "sw1"); code != 0 || !strings.Contains(out, "10.99.0.1") {
		t.Errorf("0.2.21 device show after: %d\n%s", code, out)
	}
	if out, code := run("device", "list"); code != 0 || !strings.Contains(out, "sw2") {
		t.Errorf("0.2.21 device list after: %d\n%s", code, out)
	}
	if out, code := run("user", "show", "erin.smith"); code != 0 || !strings.Contains(out, "erin.smith") {
		t.Errorf("0.2.21 user show of the dotted name after: %d\n%s", code, out)
	}
	if out, code := run("server", "addresses"); code != 0 || !strings.Contains(out, "192.0.2.10") {
		t.Errorf("0.2.21 server addresses after: %d\n%s", code, out)
	}
	if out, code := run("host", "list"); code != 0 || !strings.Contains(out, "authsrv") {
		t.Errorf("0.2.21 host list after: %d\n%s", code, out)
	}
}

// old0221Flag names a 0.2.21 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary0221 -args -old-bin-0221=<path>.
var old0221Flag = flag.String("old-bin-0221", "", "a tacctl 0.2.21 binary built with -tags testknobs (TestRollbackRealOldBinary0221)")
