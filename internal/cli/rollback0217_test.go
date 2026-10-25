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
		"1. put back the per-tier sudoers drop-in 0.2.17 writes   [does]",
		"the rules of 'device ios-syntax', 'device notice list' and 'device client-config' become 0.2.17's 'device config-syntax', 'device notices' and 'device ssh-config'",
		"2. leave every other file untouched   [leaves]",
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
