package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/store"
)

// flagPasswordChange sets users.<name>.password_change_required in the
// sandbox's store as the verbs of 0.2.20 do.
func flagPasswordChange(t *testing.T, hs *hostSandbox, names ...string) {
	t.Helper()
	for _, n := range names {
		if _, err := store.Mutate(hs.path("state", "store.yaml"), store.MutateOptions{}, func(s *store.Store) error {
			return s.UserSet(n, "password_change_required=true")
		}); err != nil {
			t.Fatal(err)
		}
	}
}

// 'tacctl rollback <older release>' with users who must change their
// password: the dry run warns who gets their device access back and writes
// nothing, --apply needs --yes, then removes the key from the store after a
// snapshot (an older release refuses it) and keeps the users.
func TestRollbackWithARequiredPasswordChangeWarnsAndRemovesTheKey(t *testing.T) {
	for _, target := range []string{"0.2.18", "0.2.9"} {
		hs := rollbackState(t)
		// erin is the engineer of rollbackState, alice a superuser
		flagPasswordChange(t, hs, "bob", "erin", "alice")
		before := tree(t, hs.dir)
		hs.run(nil, "rollback", target)
		hs.expect(0, "This was a dry run: nothing was changed.", "")
		out := hs.all()
		for _, want := range []string{"remove password_change_required of erin", "Users who must change their password get their device access back",
			target + " has no required password change (0.2.20): bob, erin are flagged", "To convert the state: tacctl rollback " + target + " --apply --yes"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: the dry run lacks %q:\n%s", target, want, out)
			}
		}
		if strings.Contains(out, "alice, ") || strings.Contains(out, ", alice") {
			t.Errorf("%s: the warning names the superuser:\n%s", target, out)
		}
		if !reflectEqual(before, tree(t, hs.dir)) {
			t.Errorf("%s: the dry run changed %q", target, changedFiles(before, tree(t, hs.dir)))
		}
		hs.run(nil, "rollback", target, "--apply")
		hs.expect(1, "", "The warnings above need your decision")
		if !strings.Contains(hs.read("state/store.yaml"), "password_change_required: true") {
			t.Fatalf("%s: a refused apply changed the store", target)
		}
		snaps := hs.snapshots()
		hs.run(nil, "rollback", target, "--apply", "--yes")
		hs.expect(0, "Applying.", "")
		if !strings.Contains(hs.all(), "store.yaml: removed the required password change of 3 users") {
			t.Errorf("%s: the apply does not say what it removed:\n%s", target, hs.all())
		}
		got := hs.read("state/store.yaml")
		if strings.Contains(got, "password_change_required") || !strings.Contains(got, "bob:") || !strings.Contains(got, "erin:") || !strings.Contains(got, "alice:") {
			t.Errorf("%s: the store after:\n%s", target, got)
		}
		if hs.snapshots() == snaps {
			t.Errorf("%s: no snapshot was taken first", target)
		}
		hs.run(nil, "rollback", target)
		hs.expect(0, "", "")
		if out := hs.all(); strings.Contains(out, "password_change_required") || strings.Contains(out, "device access back") {
			t.Errorf("%s: a second dry run still lists the key:\n%s", target, out)
		}
	}
}
