package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.8' (D143 of docs/plans/0.2.9-rollout-plan.md) on the
// host sandbox: a 0.2.9 state (the two device.apply settings, this
// release's drop-ins, a record with an applied part and the apply state
// directory), dry run, --apply, and the refusal while an apply is pending.
// The plan's own cases are internal/lifecycle's.

const rb028Records = `{"version": 1, "devices": {
 "sw2": {"address": "10.99.0.2", "vendor": "juniper", "hostname": "sw2.example.net", "login": "local:admin", "user_pulled": true,
   "applied": {"at": "2026-10-13T10:00:00Z", "by": "alice", "result": "applied", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply", "shape": "0123abcd"}}}}
`

func rollback029State(t *testing.T) *hostSandbox {
	t.Helper()
	hs := rollbackState(t)
	hs.step("", "config", "devices", "apply-confirm-timeout", "15")
	hs.step("", "config", "devices", "apply-pause", "30")
	hs.write("var-lib/devices-config.json", rb028Records, 0o600)
	hs.write("var-lib/device-apply/shapes.json", "{}\n", 0o600)
	hs.write("var-lib/device-apply/locks/sw2.lock", "", 0o600)
	return hs
}

func TestRollback028DryRunListsEveryStepAndWritesNothing(t *testing.T) {
	hs := rollback029State(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.8"}, {"rollback", "v0.2.8"}, {"rollback", "0.2.8", "--hosts"}, {"rollback", "0.2.8", "--yes"}} {
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
	hs.run(nil, "rollback", "0.2.8")
	out := hs.all()
	state := hs.path("state")
	for _, want := range []string{
		"Roll back to 0.2.8 (dry run)",
		"1. " + state + "/tacctl.yaml: remove the keys 0.2.8 does not know   [does]",
		"remove device.apply.confirm_timeout", "remove device.apply.pause",
		"2. put back the sudoers drop-ins 0.2.8 writes   [does]",
		"rewrite " + hs.path("sudoers.d", "tacctl-tiers"), "rewrite " + hs.path("sudoers.d", "tacctl"),
		"3. leave what 0.2.9 wrote in " + hs.path("var-lib") + " (listed, not deleted)   [leaves]",
		"leaves " + hs.path("var-lib", "devices-config.json"),
		"1 record has an 'applied' part", "'login', 'user_pulled' or 'hostname'", "0.2.8 ignores the fields it does not know",
		"leaves " + hs.path("var-lib", "device-apply") + " (the state of 'device config apply': shapes.json; 1 device lock in locks/)",
		"4. leave every other file untouched   [leaves]",
		"Warnings (--apply refuses without --yes while any applies)",
		"Settings 0.2.8 cannot use are dropped", "device.apply.confirm_timeout=15, device.apply.pause=30",
		"To convert the state: tacctl rollback 0.2.8 --apply --yes",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	// Not 0.2.3's steps.
	for _, not := range []string{"console.yaml: write it", "per-device SNMP", "device.config.max_concurrency"} {
		if strings.Contains(out, not) {
			t.Errorf("the dry run names %q:\n%s", not, out)
		}
	}
}

func TestRollback028ApplyNeedsYes(t *testing.T) {
	hs := rollback029State(t)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	hs.run(nil, "rollback", "0.2.8", "--apply")
	hs.expect(1, "Warnings (--apply refuses without --yes", "The warnings above need your decision: read them, then run the command again with --yes. Nothing was changed.")
	if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps {
		t.Errorf("a refused apply changed %q", changedFiles(before, tree(t, hs.dir)))
	}
}

func TestRollback028ApplyRoundTrip(t *testing.T) {
	hs := rollback029State(t)
	hs.write("sudoers.d/tacctl-tiers", tier.Sudoers(), 0o640)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	ovBefore := hs.overrides()
	if !strings.Contains(ovBefore, "confirm_timeout: 15") || !strings.Contains(ovBefore, "pause: 30") {
		t.Fatalf("the state lacks the settings:\n%s", ovBefore)
	}

	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.8", "--apply", "--yes")
	hs.expect(0, "Applying.", "")
	out := hs.all()
	for _, want := range []string{"Config snapshot saved to", "state/tacctl.yaml: removed 2 keys",
		"sudoers.d/tacctl-tiers: rewritten with the text 0.2.8 writes", "sudoers.d/tacctl: rewritten with the text 0.2.8 writes",
		"Next steps", "tacctl upgrade --branch 0.2.8", "holds the 0.2.9 state. Restore it with 0.2.9 only"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "rollback target=0.2.8 keys=2 by=root") {
		t.Errorf("the audit line: %q", r.Argvs())
	}
	if r.Called("systemctl") || r.Called("ssh") || len(r.Execs()) != 0 {
		t.Errorf("a service was restarted or a device contacted: %q", r.Argvs())
	}
	if hs.snapshots() != snaps+1 {
		t.Fatalf("snapshots %d -> %d", snaps, hs.snapshots())
	}
	// The snapshot is the state before.
	snap := newestSnapshot(t, hs)
	if b, err := os.ReadFile(snap + "/tacctl.yaml"); err != nil || string(b) != ovBefore {
		t.Errorf("the snapshot's tacctl.yaml is not the state before (%v):\n%s", err, b)
	}

	ov := hs.overrides()
	if strings.Contains(ov, "confirm_timeout: 15") || strings.Contains(ov, "pause: 30") || strings.Contains(ov, "apply:") ||
		!strings.Contains(ov, "max_concurrency: 16") || !strings.Contains(ov, "engineer: engineer") {
		t.Errorf("tacctl.yaml:\n%s", ov)
	}
	after := tree(t, hs.dir)
	if after[hs.path("sudoers.d", "tacctl-tiers")] != tier.Sudoers028() || after[hs.path("sudoers.d", "tacctl")] != tier.GroupSudoers028("ops") {
		t.Error("a sudoers drop-in is not 0.2.8's text")
	}
	// What 0.2.8 ignores is left: byte for byte.
	for _, kept := range []string{hs.path("var-lib", "devices-config.json"), hs.path("var-lib", "device-apply", "shapes.json"),
		hs.path("var-lib", "device-apply", "locks", "sw2.lock"), hs.path("state", "console.yaml"), hs.path("state", "devices.yaml"),
		hs.path("state", "store.yaml"), hs.path("state", "snmp", "devices", "sw2.yaml")} {
		if a, ok := after[kept]; !ok || a != before[kept] {
			t.Errorf("%s was not left alone", kept)
		}
	}
	// A second run changes nothing.
	r = hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.8", "--apply", "--yes")
	hs.expect(0, "Nothing to convert: every file is one 0.2.8 can read.", "")
	if hs.snapshots() != snaps+1 || r.Called("install") {
		t.Errorf("the second apply took a snapshot or installed: %d %q", hs.snapshots(), r.Argvs())
	}
	if now := tree(t, hs.dir); !reflectEqual(after, now) {
		t.Errorf("the second apply changed %q", changedFiles(after, now))
	}
	// The dry run of the converted state has nothing left to do.
	hs.run(nil, "rollback", "0.2.8")
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
   "applied": {"at": "2026-10-13T10:00:00Z", "until": "2026-10-13T12:10:00Z", "by": "alice", "result": "pending", "id": "tacctl-20261013T100000Z-ab12", "kind": "apply"}},
 "sw1": {"address": "10.99.0.1", "vendor": "juniper", "applied": {"at": "2026-10-13T09:00:00Z", "by": "alice", "result": "unknown", "id": "tacctl-20261013T090000Z-ef56"}}}}
`, 0o600)
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, ver := range []string{"0.2.8", "0.2.3"} {
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

// 0.2.3 is still a target from this release: its dry run lists the apply
// state it leaves, and --apply converts as it did.
func TestRollback023FromThisRelease(t *testing.T) {
	hs := rollback029State(t)
	hs.run(nil, "rollback", "0.2.3")
	hs.expect(0, "Roll back to 0.2.3 (dry run)", "")
	out := hs.all()
	for _, want := range []string{"remove device.apply.confirm_timeout", "remove device.apply.pause",
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
