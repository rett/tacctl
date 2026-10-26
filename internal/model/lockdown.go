package model

// The model with the members of a locked group taken out of a scope
// (the emergency lockdown, conf/lockdown.go). Both renderers and the read-back
// of the rendered file use this copy; the store is never changed.

import "slices"

// WithoutMembers returns the model with every user of a locked group taken
// out of the scope that locks the group: locked maps a scope to the groups it
// locks. A user that is in no locked scope, or whose group is not locked, is
// the same user; the others are copies whose Scopes lack the locked scopes
// (the user stays, so a user with no scope left is rendered with none and the
// server refuses the login). The receiver is not changed; with nothing locked
// it is returned as it is.
func (m *Model) WithoutMembers(locked map[string][]string) *Model {
	if len(locked) == 0 {
		return m
	}
	out := *m
	out.Users = make([]*User, 0, len(m.Users))
	out.users = make(map[string]*User, len(m.Users))
	for _, u := range m.Users {
		nu := u
		var keep []string
		cut := false
		for _, s := range u.Scopes {
			if slices.Contains(locked[s], u.Group) {
				cut = true
				continue
			}
			keep = append(keep, s)
		}
		if cut {
			c := *u
			c.Scopes = keep
			nu = &c
		}
		out.Users = append(out.Users, nu)
		out.users[nu.Name] = nu
	}
	return &out
}

// LockedOut lists the users that WithoutMembers takes out of the scope: the
// members of the scope whose group is in groups, by name.
func (m *Model) LockedOut(scope string, groups []string) []*User {
	var out []*User
	for _, u := range m.Users {
		if slices.Contains(groups, u.Group) && slices.Contains(u.Scopes, scope) {
			out = append(out, u)
		}
	}
	return out
}
