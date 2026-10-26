package model

import (
	"slices"
	"testing"
)

func TestWithoutMembers(t *testing.T) {
	a := &User{Name: "alice", Group: "superuser", Scopes: []string{"prod", "lab"}}
	b := &User{Name: "bob", Group: "operator", Scopes: []string{"lab"}}
	c := &User{Name: "carol", Group: "readonly", Scopes: []string{"lab", "dmz"}}
	m := &Model{Users: []*User{a, b, c}, users: map[string]*User{"alice": a, "bob": b, "carol": c}}
	if got := m.WithoutMembers(nil); got != m {
		t.Error("nothing locked: the model is copied")
	}
	got := m.WithoutMembers(map[string][]string{"lab": {"operator", "readonly"}})
	if !slices.Equal(got.User("alice").Scopes, []string{"prod", "lab"}) || len(got.User("bob").Scopes) != 0 || !slices.Equal(got.User("carol").Scopes, []string{"dmz"}) {
		t.Errorf("scopes: alice %v bob %v carol %v", got.User("alice").Scopes, got.User("bob").Scopes, got.User("carol").Scopes)
	}
	if !slices.Equal(b.Scopes, []string{"lab"}) || !slices.Equal(c.Scopes, []string{"lab", "dmz"}) {
		t.Error("the receiver was changed")
	}
	if got.User("alice") != a {
		t.Error("an unaffected user is copied")
	}
	var names []string
	for _, u := range m.LockedOut("lab", []string{"operator", "readonly"}) {
		names = append(names, u.Name)
	}
	if !slices.Equal(names, []string{"bob", "carol"}) {
		t.Errorf("locked out: %v", names)
	}
}
