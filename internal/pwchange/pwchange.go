// Package pwchange decides who is held to a required password change
// (0.2.20, the store flag users.<name>.password_change_required).
//
// The flag is the administrator's request; whether it binds a user is
// decided here, at run time and everywhere the same way (the renderers, the
// login console, the command line, the verbs that list it): a superuser is
// never held to it, whatever the store says, and the user's tier is read
// from the group as it is now, so a user moved into a superuser group is
// exempt from then on and one moved out is held again. The tier is the one
// tier.ForGroup makes of the group's setting in tacctl.yaml and its priv-lvl;
// a member of a group that needs a tier setting and has lost it (priv-lvl 15
// or more, not the built-in superuser group) is held at the operator tier by
// the gate, and is held here too.
//
// The package is pure: the model and the tacctl.yaml view are arguments. It
// is imported by the renderers, so it must not import policy (which imports
// the RADIUS renderer).
package pwchange

import (
	"strconv"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// superuserBand is the priv-lvl from which a group needs a tier setting
// (policy.SuperuserBand).
const superuserBand = 15

// Tier is the tier of the user's group as the flag sees it: the tier the
// gate gives the user, except that a group that lost its tier setting
// (ambiguous) is the operator tier, as the gate holds its members; the
// user's own state (disabled, the accounting sink) is not looked at. A user
// without a group, or a group without a priv-lvl, is tier.None.
func Tier(c *conf.Config, m *model.Model, u *model.User) tier.Tier {
	return GroupTier(c, m, u.Group)
}

// GroupTier is Tier for a group by name: what a user of the group is, for
// the verbs that decide before the user exists.
func GroupTier(c *conf.Config, m *model.Model, group string) tier.Tier {
	g := m.Group(group)
	if g == nil || g.PrivLvl == nil {
		return tier.None
	}
	setting := conf.GroupTierSetting(c, group)
	t := tier.ForGroup(setting, strconv.Itoa(*g.PrivLvl))
	// as policy.NeedsTier: the built-in superuser group is the superuser tier
	// by definition, any other group at priv-lvl 15 or more needs a setting
	if setting == "" && *g.PrivLvl >= superuserBand && group != "superuser" && tier.Rank(t) > tier.Rank(tier.Operator) {
		return tier.Operator
	}
	return t
}

// Superuser reports whether the user is a superuser by the tier of the
// group: the users the flag never binds.
func Superuser(c *conf.Config, m *model.Model, u *model.User) bool {
	return Tier(c, m, u) == tier.Superuser
}

// Subject reports whether the user is held to a password change now: the
// flag is set, the user is no accounting sink, and no superuser.
func Subject(c *conf.Config, m *model.Model, u *model.User) bool {
	return u != nil && u.PasswordChangeRequired && !u.AccountingSink && !Superuser(c, m, u)
}

// ServerAddress is the address this server's own logins (the console's
// pam_tacplus or pam_radius) come from: the one 'host enroll --local' needs
// a scope to cover.
const ServerAddress = "127.0.0.1"

// Carve is the model a renderer of protocol ("tacacs" or "radius") writes: a
// user held to a password change keeps, of the scopes of theirs, only the one
// that answers this server's own logins (model.ScopeOf of ServerAddress for
// the protocol), so a login from a device finds no scope the user is in and
// fails as for an unknown user, while the login at tacctl, which comes from
// the server, still works and the password can be changed there. Every other
// user, a superuser and an unflagged one included, is the same user. The
// decision is made here and now from the group's tier, never from the store
// alone (Subject), so the same model renders the same bytes. The store is
// not changed.
func Carve(m *model.Model, view *yamlpy.Map, protocol string) *model.Model {
	c := conf.View(view)
	server := m.ScopeOf(ServerAddress, protocol)
	return m.WithUserScopes(func(u *model.User) ([]string, bool) {
		if !Subject(c, m, u) {
			return nil, false
		}
		keep := []string{}
		for _, s := range u.Scopes {
			if s == server {
				keep = append(keep, s)
			}
		}
		return keep, true
	})
}

// Pending are the users held to a password change now, by name.
func Pending(c *conf.Config, m *model.Model) []*model.User {
	var out []*model.User
	for _, n := range m.UserNames() {
		if u := m.User(n); Subject(c, m, u) {
			out = append(out, u)
		}
	}
	return out
}
