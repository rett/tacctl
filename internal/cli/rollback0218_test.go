package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

// 'tacctl rollback 0.2.18' on the host sandbox: the dry run writes nothing;
// --apply puts back 0.2.18's per-tier drop-in after visudo, takes no snapshot
// (no file of tacctl's own is converted) and ends with the upgrade of the tag;
// a second --apply has nothing to convert.
func TestRollback0218PutsBackTheTiersDropIn(t *testing.T) {
	hs := rollback0216State(t, "true")
	before := tree(t, hs.dir)
	snaps := hs.snapshots()
	for _, args := range [][]string{{"rollback", "0.2.18"}, {"rollback", "v0.2.18", "--hosts"}} {
		r := hs.runner()
		hs.run(r, args...)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		if !reflectEqual(before, tree(t, hs.dir)) || hs.snapshots() != snaps || r.Called("visudo") || r.Called("ssh") {
			t.Errorf("%v changed %q", args, changedFiles(before, tree(t, hs.dir)))
		}
	}
	out := hs.all()
	for _, want := range []string{"Roll back to 0.2.18 (dry run)",
		"2. put back the per-tier sudoers drop-in 0.2.18 writes   [does]",
		"the engineer's rules of 'device config apply', 'device enroll'",
		"To convert the state: tacctl rollback 0.2.18 --apply"} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run lacks %q:\n%s", want, out)
		}
	}

	r := hs.runner()
	sudoersInstall(r)
	hs.run(r, "rollback", "0.2.18", "--apply")
	hs.expect(0, "Applying.", "")
	out = hs.all()
	for _, want := range []string{"sudoers.d/tacctl-tiers: rewritten with the text 0.2.18 writes", "Next steps", "tacctl upgrade --branch 0.2.18",
		"do not run 'tacctl emergency lockdown'"} {
		if !strings.Contains(out, want) {
			t.Errorf("--apply output lacks %q:\n%s", want, out)
		}
	}
	if !r.CalledRegexp(`^visudo -cf `) {
		t.Errorf("no visudo check: %q", r.Argvs())
	}
	if got := hs.read("sudoers.d/tacctl-tiers"); got != tier.Sudoers0218() {
		t.Errorf("the tiers drop-in is not 0.2.18's:\n%s", got)
	}
	if hs.snapshots() != snaps {
		t.Errorf("a snapshot was taken")
	}
	hs.run(nil, "rollback", "0.2.18", "--apply")
	hs.expect(0, "Nothing to convert: every file is one 0.2.18 can read.", "")
}
