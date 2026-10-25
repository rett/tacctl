package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.17' (docs/plans/0.2.18-plan.md D273) on the host
// sandbox: the dry run writes nothing; --apply puts back 0.2.17's per-tier
// drop-in (the rules of the old verb names), after visudo, takes
// no snapshot (no file of tacctl's own is converted) and ends with the
// upgrade of the tag; a second --apply has nothing to convert.
func TestRollback0217PutsBackTheTiersDropIn(t *testing.T) {
	hs := rollback0216State(t, "true")
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.17"}, {"rollback", "v0.2.17", "--hosts"}} {
		r := hs.runner()
		hs.run(r, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps || r.Called("visudo") || r.Called("ssh") {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
	}
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.17 (dry run)",
		"2. put back the per-tier sudoers drop-in 0.2.17 writes   [does]",
		"the rules of 'device ios-syntax', 'device notice list' and 'device client-config' become 0.2.17's 'device config-syntax', 'device notices' and 'device ssh-config'",
		"3. leave every other file untouched   [leaves]",
		"To convert the state: tacctl rollback 0.2.17 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "audit.strict") || strings.Contains(out, "--yes") {
		t.Errorf("the dry run names audit.strict or --yes:\n%s", out)
	}

	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.17", "--apply")
	hs.expect(0, "Applying.", "")
	out = hs.all()
	for _, want := range []string{"sudoers.d/tacctl-tiers: rewritten with the text 0.2.17 writes", "Next steps", "tacctl upgrade --branch 0.2.17"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if !r.CalledRegexp(`^visudo -cf `) {
		t.Errorf("no visudo check: %q", r.Argvs())
	}
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers0217() {
		t.Errorf("the tiers drop-in is not 0.2.17's:\n%s", got)
	}
	if hs.snapshots() != snaps || !strings.Contains(hs.overrides(), "strict: true") {
		t.Errorf("a snapshot was taken or tacctl.yaml changed:\n%s", hs.overrides())
	}
	for _, p := range changedFiles(before, tree(t, hs.dir)) {
		if p != hs.path("sudoers.d", "tacctl-tiers") && !strings.Contains(p, ".lock") {
			t.Errorf("the rollback changed %s", strings.TrimPrefix(p, hs.dir))
		}
	}
	hs.run(nil, "rollback", "0.2.17", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.17 can read.", "")
}

// A registry with a configuration syntax setting: the rollback to 0.2.17
// takes a snapshot and writes the setting under config_syntax; this release
// still reads it, and its next change stores ios_syntax again.
func TestRollback0217WritesTheSyntaxKeyBack(t *testing.T) {
	hs := rollbackState(t)
	hs.step("", "device", "ios-syntax", "sw1", "modern")
	if dv := hs.read("state/devices.yaml"); !strings.Contains(dv, "    ios_syntax: modern") {
		t.Fatalf("devices.yaml:\n%s", dv)
	}
	snaps := hs.snapshots()
	hs.run(nil, "rollback", "0.2.17")
	if out := hs.all(); !strings.Contains(out, "1. "+hs.path("state")+"/devices.yaml: write the configuration syntax setting under the key 0.2.17 reads (config_syntax)   [does]") ||
		!strings.Contains(out, "write ios_syntax of sw1 (modern) as config_syntax") {
		t.Errorf("the dry run:\n%s", out)
	}
	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.17", "--apply")
	hs.expect(0, "Applying.", "")
	if out := hs.all(); !strings.Contains(out, "devices.yaml: wrote the configuration syntax of 1 device under config_syntax") ||
		!strings.Contains(out, "do not run a command that changes the device registry") {
		t.Errorf("--apply:\n%s", out)
	}
	if hs.snapshots() != snaps+1 {
		t.Errorf("snapshots %d -> %d", snaps, hs.snapshots())
	}
	dv := hs.read("state/devices.yaml")
	if strings.Contains(dv, "ios_syntax") || !strings.Contains(dv, "    config_syntax: modern") {
		t.Errorf("devices.yaml after:\n%s", dv)
	}
	if out := plain(hs.run(nil, "device", "ios-syntax", "sw1")); strings.TrimSpace(out) != "modern" {
		t.Errorf("read back: %q %q", out, hs.all())
	}
	hs.step("", "device", "ios-syntax", "sw1", "ios12")
	if dv := hs.read("state/devices.yaml"); strings.Contains(dv, "config_syntax") || !strings.Contains(dv, "    ios_syntax: ios12") {
		t.Errorf("devices.yaml after a change:\n%s", dv)
	}
}

// A registry that holds both keys with different values: ios_syntax is
// used, and the device commands say so once.
func TestRegistryWithBothSyntaxKeysSaysSo(t *testing.T) {
	sb := newSandbox(t, true)
	sb.write("state/devices.yaml", "version: 1\ndevices:\n  sw1: {address: 10.99.0.1, vendor: cisco, ios_syntax: ios12, config_syntax: modern}\n", 0o600)
	out := sb.dev("", "ios-syntax", "sw1")
	if sb.code != 0 || !strings.HasSuffix(out, "\nios12\n") ||
		strings.Count(out+sb.stderr(), "device 'sw1' has ios_syntax ios12 and config_syntax modern; ios_syntax is used") != 1 {
		t.Errorf("%d %q %q", sb.code, out, sb.stderr())
	}
}
