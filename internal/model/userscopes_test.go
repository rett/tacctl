package model

import (
	"slices"
	"testing"
)

func TestWithUserScopes(t *testing.T) {
	a := &User{Name: "alice", Group: "superuser", Scopes: []string{"prod", "lab"}}
	b := &User{Name: "bob", Group: "operator", Scopes: []string{"lab", "srv"}}
	m := &Model{Users: []*User{a, b}, users: map[string]*User{"alice": a, "bob": b}}
	if got := m.WithUserScopes(func(*User) ([]string, bool) { return nil, false }); got != m {
		t.Error("nothing changes: the model is copied")
	}
	// an answer equal to the scopes is no change either
	if got := m.WithUserScopes(func(u *User) ([]string, bool) { return slices.Clone(u.Scopes), true }); got != m {
		t.Error("the same scopes: the model is copied")
	}
	got := m.WithUserScopes(func(u *User) ([]string, bool) {
		if u.Name == "bob" {
			return []string{"srv"}, true
		}
		return nil, false
	})
	if got == m || got.User("alice") != a || !slices.Equal(got.User("bob").Scopes, []string{"srv"}) {
		t.Errorf("bob %v", got.User("bob").Scopes)
	}
	if !slices.Equal(b.Scopes, []string{"lab", "srv"}) {
		t.Error("the receiver was changed")
	}
	if got.Users[1] != got.User("bob") {
		t.Error("the list and the index disagree")
	}
}

func TestScopeOfAnAddressForAProtocol(t *testing.T) {
	m := &Model{scopes: map[string]*Scope{}}
	for _, s := range []*Scope{
		{Name: "all", Prefixes: []string{"127.0.0.0/8"}},
		{Name: "srv", Prefixes: []string{"127.0.0.1/32"}, Protocols: []string{"radius"}},
		{Name: "lan", Prefixes: []string{"192.0.2.0/24"}},
		{Name: "v6", Prefixes: []string{"::1/128"}},
	} {
		m.Scopes = append(m.Scopes, s)
		m.scopes[s.Name] = s
	}
	for _, c := range []struct{ addr, protocol, want string }{
		{"127.0.0.1", "", "srv"},
		{"127.0.0.1", "radius", "srv"},
		{"127.0.0.1", "tacacs", "all"},
		{"192.0.2.9", "tacacs", "lan"},
		{"198.51.100.1", "", ""},
		{"::1", "tacacs", "v6"},
		{"not an address", "", ""},
	} {
		if got := m.ScopeOf(c.addr, c.protocol); got != c.want {
			t.Errorf("ScopeOf(%s, %q) = %q, want %q", c.addr, c.protocol, got, c.want)
		}
	}
}
