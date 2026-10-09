package cli

// WP10.8a: the code, template and test fixes of the three final reviews.

import (
	"strings"
	"testing"
)

// A1: the completion helper is open to every tier, so it names only what
// the caller can list with a verb of its own tier: no break-glass account
// of another scope (nor of its own: the verb is the superuser's), no backup
// ids for the readonly tier ('backup list' is an operator row).
func TestCompletionNamesTellALowerTierOnlyWhatItsVerbsList(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"scope", "breakglass", "prod", "add", "prodadmin"})
	sb.expect(0, "recorded", "")
	sb.run("", []string{"scope", "breakglass", "lab", "add", "labadmin"})
	sb.expect(0, "recorded", "")
	sb.mkSnapshot("20260101_000000_000", "x\n", "")

	// The superuser is told them.
	if got := sb.run("", []string{"_completion-names", "breakglass-users", "prod"}); got != "prodadmin\n" {
		t.Errorf("superuser: %q", got)
	}
	if got := sb.run("", []string{"_completion-names", "backups"}); got != "20260101_000000_000\n" {
		t.Errorf("superuser backups: %q", got)
	}
	// carol (readonly, lab and dmz) and bob (operator, lab) are told no
	// break-glass name, of another scope or of their own.
	for _, who := range [][2]string{{"carol", ""}, {"bob", ""}} {
		for _, scope := range []string{"prod", "lab"} {
			if got := sb.asUser(who[0], who[1], "_completion-names", "breakglass-users", scope); got != "" || sb.code != 0 {
				t.Errorf("%s breakglass-users %s: %d %q", who[0], scope, sb.code, got)
			}
		}
	}
	// Backup ids: the readonly tier has no verb that lists them.
	if got := sb.asUser("carol", "", "_completion-names", "backups"); got != "" {
		t.Errorf("readonly backups: %q", got)
	}
	if got := sb.asUser("bob", "", "_completion-names", "backups"); !strings.Contains(got, "20260101_000000_000") {
		t.Errorf("operator backups: %q", got)
	}
}
