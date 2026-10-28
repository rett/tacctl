package cli

import (
	"strings"
	"testing"
)

// 'tacctl rollback <release before 0.2.20>' with a scope whose management
// filter mode is strict: the dry run lists the key and warns of the scopes,
// --apply needs --yes (the warning is a decision), removes the key after a
// snapshot, and leaves the permit list alone.
func TestRollbackWithAStrictMgmtACLModeWarnsAndRemovesTheKey(t *testing.T) {
	for _, target := range []string{"0.2.19", "0.2.18", "0.2.16"} {
		hs := rollbackState(t)
		hs.write("state/tacctl.yaml", hs.read("state/tacctl.yaml")+"scope_mgmt_acl:\n  permits:\n    lab:\n    - 10.0.0.0/8\n  mode:\n    lab: strict\n", 0o640)
		before := tree(t, hs.dir)
		hs.run(nil, "rollback", target)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		out := hs.all()
		for _, want := range []string{"remove scope_mgmt_acl.mode.lab", "Scopes with a strict management filter lose the mode",
			target + " has no management filter mode (0.2.20): scope lab is strict", "To stay deny by default, keep this release"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: the dry run lacks %q:\n%s", target, want, out)
			}
		}
		if !reflectEqual(before, tree(t, hs.dir)) {
			t.Errorf("%s: the dry run changed %q", target, changedFiles(before, tree(t, hs.dir)))
		}
		hs.run(nil, "rollback", target, "--apply")
		hs.expect(1, "", "The warnings above need your decision")
		if !strings.Contains(hs.overrides(), "strict") {
			t.Fatalf("%s: a refused apply changed tacctl.yaml", target)
		}
		snaps := hs.snapshots()
		hs.run(nil, "rollback", target, "--apply", "--yes")
		hs.expect(0, "Applying.", "")
		if ov := hs.overrides(); strings.Contains(ov, "mode:") || strings.Contains(ov, "strict") || !strings.Contains(ov, "10.0.0.0/8") {
			t.Errorf("%s: tacctl.yaml after:\n%s", target, ov)
		}
		if hs.snapshots() == snaps {
			t.Errorf("%s: no snapshot was taken first", target)
		}
		// nothing of tacctl.yaml is left to remove
		hs.run(nil, "rollback", target)
		hs.expect(0, "", "")
		if out := hs.all(); strings.Contains(out, "remove scope_mgmt_acl.mode") || strings.Contains(out, "Scopes with a strict management filter") {
			t.Errorf("%s: a second dry run still lists the key:\n%s", target, out)
		}
	}
}
