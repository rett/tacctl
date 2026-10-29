package store

import (
	"github.com/rett/tacctl/internal/yamlpy"
)

// PasswordChangeKey is the user key of a required password change
// (0.2.20). Every release before 0.2.20 refuses the key ("user '<name>':
// unknown field 'password_change_required'"), so a rollback removes it
// (RollbackPasswordChange).
const PasswordChangeKey = "password_change_required"

// PasswordChangeKeys are the users of the store at path that carry
// PasswordChangeKey with any value (true, false, or one the store does not
// accept), by name: an older release refuses the key itself, so a rollback
// removes it wherever it is. The file is read as it is, not validated: a
// rollback must see the key in a store that no longer validates too. A file
// that cannot be read is an error.
func PasswordChangeKeys(path string) ([]string, error) {
	raw, err := LoadRaw(path)
	if err != nil {
		return nil, err
	}
	root, ok := raw.(*yamlpy.Map)
	if !ok {
		return nil, nil
	}
	users, ok := root.Get("users")
	if !ok {
		return nil, nil
	}
	um, ok := users.(*yamlpy.Map)
	if !ok {
		return nil, nil
	}
	var out []string
	for _, name := range sortedKeys(um) {
		if u, ok := mapOf(get(um, name)); ok && u.Has(PasswordChangeKey) {
			out = append(out, name)
		}
	}
	return out, nil
}

// RollbackPasswordChange removes PasswordChangeKey from every user of the
// store at path, in one validated write under the store's lock (before runs
// first, as a snapshot; an error from it stops the write). It reports the
// users that had the key and whether the file was written; a store without
// the key is not touched. The removal is the whole change: nothing else of
// the store is rewritten but what any write canonicalises.
func RollbackPasswordChange(path string, before func() error) (removed []string, changed bool, err error) {
	if before != nil {
		if err := before(); err != nil {
			return nil, false, err
		}
	}
	changed, err = mutate(path, false, nil, func(s *Store) error {
		users := s.section("users")
		for _, name := range sortedKeys(users) {
			if u, ok := mapOf(get(users, name)); ok && u.Delete(PasswordChangeKey) {
				removed = append(removed, name)
			}
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return removed, changed, nil
}

// RollbackAddScope adds scope to the scopes of each of names in the store at
// path that does not have it yet, in one validated write under the store's
// lock: the rollback of the scope of this server's own login (0.2.21), which
// every user is a member of without having it, to a release that needs it in
// each user's own scopes. It reports the users it was added to; a store where
// each has it already is not touched.
func RollbackAddScope(path, scope string, names []string) (added []string, err error) {
	_, err = mutate(path, false, nil, func(s *Store) error {
		users := s.section("users")
		for _, name := range names {
			u, ok := mapOf(get(users, name))
			if !ok {
				continue
			}
			var list []string
			if l, ok := get(u, "scopes").([]any); ok {
				for _, v := range l {
					if t, ok := v.(string); ok {
						list = append(list, t)
					}
				}
			}
			if inList(list, scope) {
				continue
			}
			if err := s.UserSet(name, "scopes="+joinCSV(append(list, scope))); err != nil {
				return err
			}
			added = append(added, name)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return added, nil
}

func joinCSV(list []string) string {
	out := ""
	for i, s := range list {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
