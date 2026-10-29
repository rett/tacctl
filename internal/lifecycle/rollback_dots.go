package lifecycle

// A user name could hold periods in 0.2.20 and 0.2.21 (a new one cannot from
// 0.2.22: names.ValidateUsername), and a restored snapshot of either can bring
// one back. Every release a rollback goes to (0.2.3, 0.2.9, 0.2.16, 0.2.17,
// 0.2.18 and 0.2.19, whose user-name pattern is verified against each tag)
// reads letters, digits, '_' and '-' only, so a store that keeps a dotted
// name fails there with "user '<name>': invalid name" on every store command.
// The rollback is refused while one stands, for every target but 0.2.21 and 0.2.20
// (which read such a name), in the dry run and --apply alike, and nothing is
// changed. A console.yaml override under a dotted name (the ignored 'users'
// mapping of 0.2.19 and before) is not a reason to refuse: the plan takes that
// entry out of the file (console.DottedUsersKey).

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// DottedUsers are the users of the store (when the install has one) with a
// period in their name, sorted. A store that cannot be read is an error: a
// name that cannot be seen must not be hidden.
func DottedUsers(pa paths.Paths, hasStore bool) (inStore []string, err error) {
	if !hasStore {
		return nil, nil
	}
	raw, err := store.LoadRaw(pa.StoreFile)
	if err != nil {
		return nil, &UnreadableStoreError{Path: pa.StoreFile, Cause: strings.TrimSuffix(err.Error(), ".")}
	}
	if root, ok := raw.(*yamlpy.Map); ok {
		if users, ok := root.Get("users"); ok {
			if m, ok := users.(*yamlpy.Map); ok {
				inStore = dotted(m.Keys())
			}
		}
	}
	return inStore, nil
}

// UnreadableStoreError is DottedUsers' error for a store that cannot be
// read: the rollback stops on it, the upgrade says it and goes on.
type UnreadableStoreError struct{ Path, Cause string }

func (e *UnreadableStoreError) Error() string {
	return fmt.Sprintf("%s cannot be read, so a user name with a period cannot be ruled out (%s); fix it first (tacctl config validate)",
		e.Path, e.Cause)
}

func dotted(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.Contains(n, ".") {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return out
}

// DottedUsersRefusal is the refusal of a rollback while a store user name
// with a period stands: each name with the command that fixes it, and why
// the older release cannot take it over.
func DottedUsersRefusal(inStore []string) *RollbackRefusal {
	n := len(inStore)
	lines := []string{"The store has " + fmt.Sprint(n) + " " + pluralWord(n, "user", "users") +
		" whose name has a period, which every release a rollback goes to refuses (\"user '<name>': invalid name\" on every store command):"}
	for _, u := range inStore {
		lines = append(lines, "  "+u+"   (tacctl user rename "+u+" <new-name>)")
	}
	lines = append(lines, "Rename the users first, then run the rollback again. Nothing was changed.")
	return &RollbackRefusal{Lines: lines}
}
