package cli

// A snapshot of 0.2.25 or earlier (and the one 'tacctl upgrade' takes before
// it renames them) can hold a user whose name has a period, which 0.2.20 and
// 0.2.21 allowed. 'backup restore' and 'backup recover' read such a snapshot
// (store.ValidateFileLegacyDots; the live store is judged strictly): the
// restore puts its files back and says so, the store then reads and every
// write to it is refused until 'tacctl upgrade' renames the users. No renderer
// writes a name with a period (tacquito's parser refuses it in an anchor), so
// the restore of such a snapshot renders nothing and the services keep the
// configuration they have.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/store"
)

// snapshotDottedUsers are the users of the snapshot store at path whose name
// has a period, in the order of the file; none when it cannot be read.
func snapshotDottedUsers(path string) []string {
	raw, err := store.LoadRaw(path)
	if err != nil {
		return nil
	}
	return store.DottedUsers(raw)
}

// dottedUsersText is "alice.smith, bob.smith" with at most five names.
func dottedUsersText(users []string) string {
	const most = 5
	if len(users) <= most {
		return strings.Join(users, ", ")
	}
	return strings.Join(users[:most], ", ") + " and " + strconv.Itoa(len(users)-most) + " more"
}

// restoreDotsNote says what a restore of a snapshot with such users does.
func restoreDotsNote(id string, users []string) string {
	n := len(users)
	return "Snapshot " + id + " holds " + strconv.Itoa(n) + " " + plural(n, "user", "users") + " whose name has a period (" + dottedUsersText(users) +
		"), which a release before 0.2.22 allowed. It is restored, but nothing is rendered: a name with a period cannot be rendered, so the services keep the configuration they have. " +
		"Run 'tacctl upgrade' to rename " + plural(n, "the user", "the users") + " (each period becomes '_') and render; until then the store can be read and every change to it is refused."
}

// dotsSkipReason is why 'backup recover' skips a user of the snapshot whose
// name has a period: no user has one now, and a recovery sets data on users
// that exist, it makes none.
const dotsSkipReason = "the name has a period, so it is not recovered"

// recoverDotsNote says what 'backup recover' does about such users.
func recoverDotsNote(id string, users []string) string {
	n := len(users)
	return "  Snapshot " + id + " holds " + strconv.Itoa(n) + " " + plural(n, "user", "users") + " whose name has a period (" + dottedUsersText(users) +
		"), which a release before 0.2.22 allowed. " + plural(n, "That user is", "Those users are") + " skipped: 'tacctl upgrade' renames " + plural(n, "it", "them") +
		" in the store (each period becomes '_'), and a recovery sets data on users that exist; it adds none."
}
