package model

import (
	"slices"

	"github.com/rett/tacctl/internal/store"
)

// WithUserScopes returns the model with the scope list of each user for
// which f answers (scopes, true) replaced by scopes: the renderers' way of
// keeping one user out of some scopes without touching the store (as
// WithoutMembers does for a locked group). A user f leaves alone is the same
// user; a changed one is a copy (the user stays, so one with no scope left
// is rendered with none and the server refuses the login). The receiver is
// not changed; f is asked about the users of the receiver.
func (m *Model) WithUserScopes(f func(u *User) ([]string, bool)) *Model {
	out := *m
	out.Users = make([]*User, 0, len(m.Users))
	out.users = make(map[string]*User, len(m.Users))
	changed := false
	for _, u := range m.Users {
		nu := u
		if scopes, ok := f(u); ok && !slices.Equal(scopes, u.Scopes) {
			c := *u
			c.Scopes = scopes
			nu = &c
			changed = true
		}
		out.Users = append(out.Users, nu)
		out.users[nu.Name] = nu
	}
	if !changed {
		return m
	}
	return &out
}

// ScopeOf is the scope that answers address for protocol: of the scopes the
// protocol serves ("": any scope), the one with the most specific prefix that
// contains it, in the order the daemons try them (routingPairs). "" when
// none does or the address is not valid.
func (m *Model) ScopeOf(address, protocol string) string {
	q, valid := store.ParseNet(address)
	if !valid {
		return ""
	}
	for _, p := range m.routingPairs() {
		if protocol != "" {
			if s := m.scopes[p.scope]; s == nil || !s.ServedBy(protocol) {
				continue
			}
		}
		pnet, valid := store.ParseNet(p.cidr)
		if valid && pnet.Version() == q.Version() && pnet.Contains(q) {
			return p.scope
		}
	}
	return ""
}

// WithoutScope returns the model as the listings show it when the scope name
// is not to be shown: without the scope, and with it taken out of every
// user's scopes. The receiver is not changed; a model without the scope is
// returned as it is.
func (m *Model) WithoutScope(name string) *Model {
	if name == "" || m.scopes[name] == nil {
		return m
	}
	out := m.WithUserScopes(func(u *User) ([]string, bool) {
		if !slices.Contains(u.Scopes, name) {
			return nil, false
		}
		return slices.DeleteFunc(slices.Clone(u.Scopes), func(s string) bool { return s == name }), true
	})
	if out == m {
		c := *m
		out = &c
	}
	out.Scopes = slices.DeleteFunc(slices.Clone(m.Scopes), func(s *Scope) bool { return s.Name == name })
	out.scopes = make(map[string]*Scope, len(out.Scopes))
	for _, s := range out.Scopes {
		out.scopes[s.Name] = s
	}
	return out
}
