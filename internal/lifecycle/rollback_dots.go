package lifecycle

// A user name may hold periods from 0.2.20 (names.ValidateUsername). Every
// release a rollback goes to (0.2.3, 0.2.9, 0.2.16, 0.2.17 and 0.2.18, whose
// user-name pattern is verified against each tag) reads letters, digits, '_'
// and '-' only, so a store, or a console.yaml, that keeps a dotted name
// fails there with "user '<name>': invalid name" on every store command.
// The rollback is refused while one stands, for every target, in the dry
// run and --apply alike, and nothing is changed.

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// DottedUsers are the users with a period in their name: those of the store
// (when the install has one) and the keys under users in console.yaml, each
// list sorted. A file that cannot be read is an error: a name that cannot be
// seen must not be hidden.
func DottedUsers(pa paths.Paths, hasStore bool) (inStore, inConsole []string, err error) {
	if hasStore {
		raw, err := store.LoadRaw(pa.StoreFile)
		if err != nil {
			return nil, nil, fmt.Errorf("%s cannot be read, so a user name with a period cannot be ruled out (%s); fix it first (tacctl config validate)",
				pa.StoreFile, strings.TrimSuffix(err.Error(), "."))
		}
		if root, ok := raw.(*yamlpy.Map); ok {
			if users, ok := root.Get("users"); ok {
				if m, ok := users.(*yamlpy.Map); ok {
					inStore = dotted(m.Keys())
				}
			}
		}
	}
	if _, serr := os.Stat(pa.ConsoleFile); serr == nil {
		f, err := console.Load(pa.ConsoleFile)
		if err != nil {
			return nil, nil, fmt.Errorf("%s cannot be read, so a user name with a period cannot be ruled out (%s); fix it first",
				pa.ConsoleFile, strings.TrimSuffix(strings.Join(strings.Fields(err.Error()), " "), "."))
		}
		inConsole = dotted(f.UserNames())
	}
	return inStore, inConsole, nil
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

// DottedUsersRefusal is the refusal of a rollback while a user name with a
// period stands: each name with the command that fixes it, and why the
// older release cannot take it over.
func DottedUsersRefusal(pa paths.Paths, inStore, inConsole []string) *RollbackRefusal {
	var lines []string
	if n := len(inStore); n > 0 {
		lines = append(lines, "The store has "+fmt.Sprint(n)+" "+pluralWord(n, "user", "users")+
			" whose name has a period, which every release a rollback goes to refuses (\"user '<name>': invalid name\" on every store command):")
		for _, u := range inStore {
			lines = append(lines, "  "+u+"   (tacctl user rename "+u+" <new-name>)")
		}
	}
	if n := len(inConsole); n > 0 {
		lines = append(lines, pa.ConsoleFile+" has "+fmt.Sprint(n)+" "+pluralWord(n, "override", "overrides")+
			" under users for a name with a period, which the older release refuses:")
		for _, u := range inConsole {
			lines = append(lines, "  "+u+"   (tacctl console user "+u+" clear)")
		}
	}
	last := "Rename the users first, then run the rollback again. Nothing was changed."
	if len(inConsole) > 0 {
		last = "Rename the users first (a rename does not move a console override: clear it, and set it again under the new name if it is wanted), then run the rollback again. Nothing was changed."
	}
	lines = append(lines, last)
	return &RollbackRefusal{Lines: lines}
}
