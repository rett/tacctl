package model

import (
	"slices"
	"testing"
)

// A member that the host's held function names has no login on that host:
// LinuxUsersHeld leaves it out and LinuxInactiveHeld lists it, as for a
// disabled user, so the host expires the account; a nil function holds
// nobody (LinuxUsers, LinuxInactive).
func TestLinuxViewsHoldMembers(t *testing.T) {
	a := &User{Name: "alice", Group: "superuser", Scopes: []string{"lab"}, Hash: "h"}
	b := &User{Name: "bob", Group: "operator", Scopes: []string{"lab"}, Hash: "h", PasswordChangeRequired: true}
	c := &User{Name: "carol", Group: "operator", Scopes: []string{"lab"}, Hash: "h", Disabled: true}
	m := &Model{Users: []*User{a, b, c}, users: map[string]*User{"alice": a, "bob": b, "carol": c},
		groups: map[string]*Group{"superuser": {privText: "15"}, "operator": {privText: "7"}}}
	if got := m.LinuxUsers("lab"); !slices.Equal(got, []string{"alice|15", "bob|7"}) {
		t.Errorf("users: %v", got)
	}
	if got := m.LinuxInactive("lab"); !slices.Equal(got, []string{"carol"}) {
		t.Errorf("inactive: %v", got)
	}
	held := func(u *User) bool { return u.PasswordChangeRequired }
	if got := m.LinuxUsersHeld("lab", held); !slices.Equal(got, []string{"alice|15"}) {
		t.Errorf("held users: %v", got)
	}
	if got := m.LinuxInactiveHeld("lab", held); !slices.Equal(got, []string{"bob", "carol"}) {
		t.Errorf("held inactive: %v", got)
	}
	if got := m.LinuxUsersHeld("lab", nil); !slices.Equal(got, m.LinuxUsers("lab")) {
		t.Errorf("nil held: %v", got)
	}
}
