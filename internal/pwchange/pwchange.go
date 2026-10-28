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
	g := m.Group(u.Group)
	if g == nil || g.PrivLvl == nil {
		return tier.None
	}
	setting := conf.GroupTierSetting(c, u.Group)
	t := tier.ForGroup(setting, strconv.Itoa(*g.PrivLvl))
	// as policy.NeedsTier: the built-in superuser group is the superuser tier
	// by definition, any other group at priv-lvl 15 or more needs a setting
	if setting == "" && *g.PrivLvl >= superuserBand && u.Group != "superuser" && tier.Rank(t) > tier.Rank(tier.Operator) {
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
