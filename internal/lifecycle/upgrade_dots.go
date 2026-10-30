package lifecycle

// A user name is letters, digits, '_' and '-' again (0.2.22): every user has
// an account on the tacctl server, and a name with a period cannot be a Linux
// account name. A store written by 0.2.20 or 0.2.21 can still hold one. It is
// read (so that 'user rename' runs), and the upgrade refuses while one stands,
// naming each with the command that renames it.

import (
	"errors"
	"fmt"

	"github.com/rett/tacctl/internal/backend"
)

// dottedUsersGate is the upgrade's check of the store for a user name with a
// period. It prints the refusal and returns backend.ErrFailed while one
// stands. A store that cannot be read is said so and does not stop the
// upgrade: the store gate the backends run later reports the file, and an
// upgrade is what may put it right.
//
// An upgrade started by a release before 0.2.22 has no such check: it moves
// the state, pulls and rebuilds, replaces the installed command and
// re-executes it (ReexecEnv=1), and this gate is the new command's. The
// refusal then says what was done and what was not.
func (h *Host) dottedUsersGate() error {
	inStore, err := DottedUsers(h.Paths, isRegular(h.Paths.StoreFile))
	var unreadable *UnreadableStoreError
	if errors.As(err, &unreadable) {
		h.Out.Warn(unreadable.Path + " cannot be read, so a user name with a period was not looked for (" + unreadable.Cause +
			"); the upgrade goes on, and the store gate reports the file")
		return nil
	} else if err != nil {
		return err
	}
	if len(inStore) == 0 {
		return nil
	}
	for _, l := range UpgradeDottedUsersRefusal(inStore, h.Environ.Get(ReexecEnv) == "1") {
		h.Out.Error(l)
	}
	return backend.ErrFailed
}

// UpgradeDottedUsersRefusal is the refusal of an upgrade while a store user
// name with a period stands: each name with the command that fixes it. When
// the upgrade was re-executed after an update of the installed command
// (reexec), the refusal says that command and the tacquito build were
// updated and the store, configuration and services were not; otherwise
// nothing was changed.
func UpgradeDottedUsersRefusal(inStore []string, reexec bool) []string {
	n := len(inStore)
	lines := []string{"The store has " + fmt.Sprint(n) + " " + pluralWord(n, "user", "users") +
		" whose name has a period, which user names no longer hold:"}
	for _, u := range inStore {
		lines = append(lines, "  "+u+"   (tacctl user rename "+u+" <new-name>)")
	}
	lines = append(lines, "A user name is letters, digits, '_' and '-': a period cannot be part of a Linux account name, and every user has an account on this server.")
	if reexec {
		return append(lines, "tacctl and the tacquito build were updated; the store, the configuration and the services were not.",
			"Rename the users, then run 'tacctl upgrade' again to finish.")
	}
	return append(lines, "Rename the users first, then run the upgrade again. Nothing was changed.")
}
