package pwchange

// The scope of this server's own logins (0.2.21). 'host enroll --local'
// registers the server in a scope tacctl manages, ManagedScope: its prefixes
// are the addresses the server's own logins come from (Server.Prefixes), it
// has a secret of its own, and no operator lists, edits or shares it. Every
// user is a member of it for the server's login only, without having it in
// the store: the Linux accounts of the server, the TACACS+ and RADIUS answers
// for the server's addresses, and with them the console. Device logins keep
// the user's own scopes. A server registered in another scope (an install
// from before 0.2.21 the next 'host enroll --local' or 'host sync' of the
// server has not taken over yet) is as it was: its users need that scope.
//
// The name is a scope name every earlier release accepts, so a rollback
// leaves the scope as it is and puts it in the users' own scopes instead
// (internal/lifecycle).

import (
	"slices"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// ManagedScope is the name of the scope of this server's own logins.
const ManagedScope = "tacctl"

// Managed reports whether the server is registered in a scope of the managed
// name. Whether that scope is the managed one is ManagedIn.
func (s Server) Managed() bool { return s.Scope == ManagedScope }

// ManagedIn reports whether the server is registered in the managed scope and
// the scope called so in m is one tacctl manages for it: whether its users
// are members of it without having it. A scope of that name that answers an
// address other than the server's login addresses is an operator's (made on
// a release before this one, or on one after a rollback), however the
// registry names it: no user is ever made a member of it, and nothing in it
// is repaired. No state is kept for that: the prefixes tell.
func (s Server) ManagedIn(m *model.Model) bool {
	if !s.Managed() {
		return false
	}
	sc := m.Scope(ManagedScope)
	return sc != nil && OnlyLoginAddresses(sc, s)
}

// OnlyLoginAddresses reports whether every prefix of sc is a login address
// (Prefixes) of one of the servers: a scope that answers the server alone.
func OnlyLoginAddresses(sc *model.Scope, servers ...Server) bool {
	var own []string
	for _, s := range servers {
		own = append(own, s.Prefixes()...)
	}
	for _, p := range sc.Prefixes {
		if n, ok := store.ParseNet(p); !ok || !slices.Contains(own, n.String()) {
			return false
		}
	}
	return true
}

// LooksManaged reports whether sc has the shape of the managed scope of some
// server: one or two single-address prefixes, 127.0.0.1 among them. It is how
// a copy of the scope in a file that comes from elsewhere (store import of a
// rendered tacquito.yaml) is told from an operator's scope of that name, when
// the server it belongs to is not known.
func LooksManaged(sc *model.Scope) bool {
	if sc == nil || len(sc.Prefixes) == 0 || len(sc.Prefixes) > 2 {
		return false
	}
	loop := false
	for _, p := range sc.Prefixes {
		n, ok := store.ParseNet(p)
		if !ok || !n.IsHost() {
			return false
		}
		loop = loop || n.String() == ServerAddress+"/32"
	}
	return loop
}

// Clash reports whether m has a scope called ManagedScope that is no scope
// of the managed kind for any of the servers: an operator's scope that has
// the reserved name.
func Clash(m *model.Model, servers ...Server) bool {
	sc := m.Scope(ManagedScope)
	return sc != nil && !OnlyLoginAddresses(sc, servers...)
}

// Prefixes are the prefixes of the managed scope: each of the server's login
// addresses (LoginAddresses) as a host prefix, in that order.
func (s Server) Prefixes() []string {
	var out []string
	for _, a := range s.LoginAddresses() {
		if n, ok := store.ParseNet(a); ok {
			out = append(out, n.String())
		}
	}
	return out
}

// Implicit reports whether u is a member of the managed scope without having
// it: every user but the accounting sink, a user whose name is no Linux
// account name (a period: no account on the server) and a user whose tier is
// none (a group without a priv-lvl, no login). A disabled user is one, so the
// server expires the account rather than removing it, as for a disabled user
// of any scope.
func Implicit(c *conf.Config, m *model.Model, u *model.User) bool {
	return u != nil && !u.AccountingSink && hosts.LinuxName(u.Name) && Tier(c, m, u) != tier.None
}

// WithServerScope is the model with every implicit member (Implicit) in the
// managed scope, when the server is registered in it and the scope exists
// and is the managed one (ManagedIn); the model as it is otherwise. It is
// what the renderers and the server's own accounts are made from; the store
// is not changed, and the listings show the users' own scopes.
func WithServerScope(c *conf.Config, m *model.Model, s Server) *model.Model {
	if !s.ManagedIn(m) {
		return m
	}
	return m.WithUserScopes(func(u *model.User) ([]string, bool) {
		if slices.Contains(u.Scopes, ManagedScope) || !Implicit(c, m, u) {
			return nil, false
		}
		return append(slices.Clone(u.Scopes), ManagedScope), true
	})
}

// WithServerScopeView is WithServerScope for a merged tacctl.yaml view, as
// the renderers hold it.
func WithServerScopeView(view *yamlpy.Map, m *model.Model, s Server) *model.Model {
	return WithServerScope(conf.View(view), m, s)
}
