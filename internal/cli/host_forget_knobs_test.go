//go:build testknobs

package cli

import "testing"

// A snapshot that cannot be taken is a refusal: nothing is changed.
func TestHostForgetThatCannotSnapshotChangesNothing(t *testing.T) {
	sb := renameLab(t)
	before := sb.renameState()
	sb.run("", []string{"host", "forget", "web1", "--yes"}, "TACCTL_FAULT=snapshot")
	sb.expect(1, "", "Could not snapshot the current state. Nothing was changed.")
	if sb.renameState() != before {
		t.Error("a refusal changed something")
	}
}
