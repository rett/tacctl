package cli

import (
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.9' (docs/plans/0.2.10-plan.md) on the host sandbox: a
// 0.2.10 state (the transport setting, the NETCONF service setting of a
// scope and of a device, a record whose apply names its transport), dry
// run, --apply, and the refusal while an apply is pending. The plan's own
// cases are internal/lifecycle's.

const rb029Records = `{"version": 1, "devices": {
 "sw2": {"address": "10.99.0.2", "vendor": "juniper", "hostname": "sw2.example.net", "login": "local:admin", "user_pulled": true,
   "applied": {"at": "2026-10-15T10:00:00Z", "by": "alice", "result": "applied", "id": "tacctl-20261015T100000Z-ab12", "kind": "apply", "shape": "0123abcd", "via": "netconf"}}}}
`

func rollback029State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollbackState(t)
	hs.step("", "config", "devices", "apply-confirm-timeout", "15")
	hs.step("", "config", "devices", "apply-pause", "30")
	hs.step("", "config", "devices", "apply-transport", "netconf")
	hs.step("", "scope", "netconf", "lab", "enable", "--connection-limit", "3", "--rate-limit", "10")
	hs.step("", "device", "netconf", "sw2", "enable", "--connection-limit", "5")
	hs.write("var-lib/devices-config.json", rb029Records, 0o600)
	hs.write("var-lib/device-apply/shapes.json", "{}\n", 0o600)
	hs.write("var-lib/device-apply/locks/sw2.lock", "", 0o600)
	return hs
}

func TestRollback029DryRunListsEveryStepAndWritesNothing(t *testing.T) {
	hs := rollback029State(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.9"}, {"rollback", "v0.2.9"}, {"rollback", "0.2.9", "--hosts"}, {"rollback", "0.2.9", "--yes"}} {
		r := hs.runner()
		hs.run(r, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
		if hs.snapshots() != snaps || len(r.Execs()) != 0 || r.Called("visudo") || r.Called("install") || r.Called("ssh") {
			t.Errorf("%v: a snapshot, an ssh or a sudoers install: %q", args, r.Argvs())
		}
	}
	hs.run(nil, "rollback", "0.2.9")
	out := hs.all()
	state := hs.path("state")
	for _, want := range []string{
		"Roll back to 0.2.9 (dry run)",
		"1. " + state + "/tacctl.yaml: remove the keys 0.2.9 does not know   [does]",
		"remove device.apply.transport", "remove netconf_scope.lab.state",
		"2. " + state + "/devices.yaml: remove the per-device NETCONF service setting   [does]",
		"remove the netconf map of sw2 (enable, connection-limit 5)",
		"3. leave what 0.2.10 wrote in " + hs.path("var-lib") + " (listed, not deleted)   [leaves]",
		"leaves " + hs.path("var-lib", "devices-config.json"),
		"1 record has the 'via' field of its 'applied' part", "0.2.9 ignores the fields it does not know",
		"4. leave every other file untouched   [leaves]",
		"Warnings (--apply refuses without --yes while any applies)",
		"Settings 0.2.9 cannot use are dropped", "device.apply.transport=netconf",
		"To convert the state: tacctl rollback 0.2.9 --apply --yes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	// Not 0.2.3's steps, and no sudoers step.
	for _, not := range []string{"console.yaml: write it", "per-device SNMP", "device.config.max_concurrency", "put back the sudoers drop-ins"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run names %q:\n%s", not, out)
		}
	}
}

func TestRollback029ApplyNeedsYes(t *testing.T) {
	hs := rollback029State(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	hs.run(nil, "rollback", "0.2.9", "--apply")
	hs.expect(1, "Warnings (--apply refuses without --yes", "The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed.")
	if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps {
		t.Errorf("a refused apply changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

func TestRollback029ApplyRoundTrip(t *testing.T) {
	hs := rollback029State(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	ovBefore := hs.overrides()
	for _, want := range []string{"transport: netconf", "netconf_scope:", "connection_limit: 3"} {
		if !strings.Contains(ovBefore, want) {
			t.Fatalf("the state lacks %q:\n%s", want, ovBefore)
		}
	}
	devBefore := before[hs.path("state", "devices.yaml")]
	if !strings.Contains(devBefore, "netconf:") {
		t.Fatalf("devices.yaml lacks the device's setting:\n%s", devBefore)
	}

	r := hs.runner()
	hs.run(r, "rollback", "0.2.9", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	for _, want := range []string{"Config snapshot saved to", "state/tacctl.yaml: removed 4 keys",
		"state/devices.yaml: removed the NETCONF service setting of 1 device",
		"Next steps", "tacctl upgrade --branch 0.2.9", "holds the 0.2.10 state. Restore it with 0.2.10 only"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "rollback target=0.2.9 keys=4 by=root") {
		t.Errorf("the audit line: %q", r.Argvs())
	}
	if r.Called("systemctl") || r.Called("ssh") || r.Called("install") || r.Called("visudo") || len(r.Execs()) != 0 {
		t.Errorf("a service was restarted, a drop-in installed or a device contacted: %q", r.Argvs())
	}
	if hs.snapshots() != snaps+1 {
		t.Fatalf("snapshots %d -> %d", snaps, hs.snapshots())
	}
	// The snapshot is the state before, devices.yaml included.
	snap := newestSnapshot(t, hs)
	if b, err := os.ReadFile(snap + "/tacctl.yaml"); err != nil || string(b) != ovBefore {
		t.Errorf("the snapshot's tacctl.yaml is not the state before (%v):\n%s", err, b)
	}
	if b, err := os.ReadFile(snap + "/devices.yaml"); err != nil || string(b) != devBefore {
		t.Errorf("the snapshot's devices.yaml is not the state before (%v):\n%s", err, b)
	}

	ov := hs.overrides()
	if strings.Contains(ov, "transport: netconf") || strings.Contains(ov, "netconf_scope") ||
		!strings.Contains(ov, "confirm_timeout: 15") || !strings.Contains(ov, "pause: 30") || !strings.Contains(ov, "max_concurrency: 16") {
		t.Errorf("tacctl.yaml:\n%s", ov)
	}
	after := tree(t, hs.dir)
	if dv := after[hs.path("state", "devices.yaml")]; strings.Contains(dv, "netconf") || !strings.Contains(dv, "sw2") || !strings.Contains(dv, "Rack 4, DC1") {
		t.Errorf("devices.yaml:\n%s", dv)
	}
	// What 0.2.9 reads as it is stays, byte for byte; 0.2.10 changed no
	// sudoers text, so the drop-ins are untouched too.
	for _, kept := range []string{hs.path("var-lib", "devices-config.json"), hs.path("var-lib", "device-apply", "shapes.json"),
		hs.path("var-lib", "device-apply", "locks", "sw2.lock"), hs.path("state", "console.yaml"),
		hs.path("state", "store.yaml"), hs.path("state", "snmp", "devices", "sw2.yaml"),
		hs.path("sudoers.d", "tacctl-tiers"), hs.path("sudoers.d", "tacctl")} {
		if a, ok := after[kept]; !ok || a != before[kept] {
			t.Errorf("%s was not left alone", kept)
		}
	}
	if after[hs.path("sudoers.d", "tacctl-tiers")] != tier.Sudoers() {
		t.Error("the per-tier drop-in is not this release's (0.2.9's) text")
	}
	// A second run changes nothing.
	r = hs.runner()
	hs.run(r, "rollback", "0.2.9", "--apply", "--yes")
	hs.expect(0, "Nothing to convert: every file is one 0.2.9 can read.", "")
	if hs.snapshots() != snaps+1 {
		t.Errorf("the second apply took a snapshot: %d", hs.snapshots())
	}
	if now := tree(t, hs.dir); !reflectEqual(after, now) {
		t.Errorf("the second apply changed %q", changedFiles(after, now))
	}
	// The dry run of the converted state has nothing left to do.
	hs.run(nil, "rollback", "0.2.9")
	if o := hs.all(); strings.Contains(o, "[does]") || strings.Contains(o, "Warnings") {
		t.Errorf("a converted state:\n%s", o)
	}
}

// A confirmed commit that is pending, or whose outcome is unknown, refuses
// the rollback to either target; dry run and --apply alike; nothing changes.
func TestRollbackRefusesWhileAnApplyIsPending(t *testing.T) {
	hs := rollback029State(t)
	hs.write("var-lib/devices-config.json", `{"version": 1, "devices": {
 "sw2": {"address": "10.99.0.2", "vendor": "juniper",
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "via": "netconf"}},
 "sw1": {"address": "10.99.0.1", "vendor": "juniper", "applied": {"at": "2026-10-13T09:00:00Z", "by": "alice", "result": "unknown", "id": "tacctl-20261013T090000Z-ef56"}}}}
`, 0o600)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, ver := range []string{"0.2.9", "0.2.3"} {
		for _, extra := range [][]string{nil, {"--apply", "--yes"}} {
			hs.run(nil, append([]string{"rollback", ver}, extra...)...)
			hs.expect(1, "", "An apply of 'tacctl device config apply' is not settled on 2 devices")
			e := hs.err.String()
			for _, want := range []string{"sw1: unknown", "sw2: pending until 2026-10-13", "tacctl device config apply sw1 --check",
				"tacctl device config forget sw1", "Nothing was changed."} {
				if !strings.Contains(e, want) {
					t.Errorf("%s %v: no %q in %q", ver, extra, want, e)
				}
			}
			if strings.Contains(hs.out.String(), "Roll back to") {
				t.Errorf("%s: a plan was printed", ver)
			}
		}
	}
	if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps {
		t.Errorf("a refused rollback changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

// 0.2.8 and the releases before it are refused the one-release-at-a-time
// way, with the exact commands.
func TestRollback029RefusesFurtherBack(t *testing.T) {
	hs := rollback029State(t)
	before := tree(t, hs.dir)
	hs.run(nil, "rollback", "0.2.8")
	hs.expect(1, "", "tacctl rollback 0.2.9 --apply")
	e := hs.err.String()
	for _, want := range []string{"0.2.8 is further back", "tacctl upgrade --branch 0.2.9", "Nothing was changed."} {
		if !strings.Contains(e, want) {
			t.Errorf("no %q in %q", want, e)
		}
	}
	if !reflectEqual(before, tree(t, hs.dir)) {
		t.Errorf("a refusal changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

// 0.2.3 is still a target from this release: its dry run lists the apply
// state it leaves and the 0.2.10 settings it removes, and --apply converts.
func TestRollback023FromThisRelease(t *testing.T) {
	hs := rollback029State(t)
	hs.run(nil, "rollback", "0.2.3")
	hs.expect(0, "Roll back to 0.2.3 (dry run)", "")
	out := hs.all()
	for _, want := range []string{"remove device.apply.confirm_timeout", "remove device.apply.pause", "remove device.apply.transport",
		"remove netconf_scope.lab.state", "remove the netconf map of sw2 (enable, connection-limit 5)",
		"leaves " + hs.path("var-lib", "device-apply") + " (the shape store and the device locks of 'device config apply')"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.3", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	if p := old023Problems(t, hs); len(p) != 0 {
		t.Errorf("a 0.2.3 reader refuses the converted state: %q", p)
	}
}

// The strongest check: where the 0.2.9 tag is in this repository and go is
// there, build that release (testknobs) from a 'git archive' and run its
// config validate and device list against the state, before and after the
// rollback. Before, each refuses the 0.2.10 form with the message that
// motivated the step; after, each accepts it, and the apply records written
// with the 'via' field are read.
func TestRollbackRealOldBinary029(t *testing.T) {
	bin := oldBinaryOf(t, "0.2.9", old029Flag)
	hs := rollback029State(t)
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

	// Before: the 0.2.10 state is refused, file by file.
	out, code := run("config", "validate")
	if code != 1 || !strings.Contains(out, "device.apply.transport: unknown config key") || !strings.Contains(out, "netconf_scope") {
		t.Errorf("0.2.9 config validate before: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 1 || !strings.Contains(out, "device 'sw2': unknown key 'netconf'") {
		t.Errorf("0.2.9 device list before: %d\n%s", code, out)
	}

	r := hs.runner()
	hs.run(r, "rollback", "0.2.9", "--apply", "--yes")
	hs.expect(0, "Applying.", "")

	// After: it reads everything, the records included.
	out, code = run("config", "validate")
	if code != 0 || strings.Contains(out, "unknown config key") || !strings.Contains(out, "Configuration is valid.") {
		t.Errorf("0.2.9 config validate after: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 0 || !strings.Contains(out, "sw2") {
		t.Errorf("0.2.9 device list after: %d\n%s", code, out)
	}
	if out, code = run("device", "show", "sw2"); code != 0 || strings.Contains(out, "unknown") {
		t.Errorf("0.2.9 device show after: %d\n%s", code, out)
	}
	if out, code = run("device", "config", "list"); code != 0 || strings.Contains(out, "cannot be read") {
		t.Errorf("0.2.9 device config list after (the records with a via field): %d\n%s", code, out)
	}
	// 0.2.9 writes its own forms again, and reads what it wrote.
	if out, code = run("device", "location", "sw3", "Rack 9"); code != 0 {
		t.Errorf("0.2.9 device location: %d\n%s", code, out)
	}
	if out, code = run("device", "list"); code != 0 {
		t.Errorf("0.2.9 device list after its own write: %d\n%s", code, out)
	}
}

// old029Flag names a 0.2.9 binary built with -tags testknobs, to skip the
// build: go test ./internal/cli -run RealOldBinary029 -args -old-bin-029=<path>.
var old029Flag = flag.String("old-bin-029", "", "a tacctl 0.2.9 binary built with -tags testknobs (TestRollbackRealOldBinary029)")
