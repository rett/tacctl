package policy

import (
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
)

// The invariant of the tier setting (0.2.3, WP10.2h): every group other than
// the built-in superuser whose priv-lvl is 15 or more has an explicit
// tier.<group>. The priv-lvl band alone cannot say whether such a group is a
// superuser group or an engineer group whose setting was lost (a restored
// backup, a hand-edited tacctl.yaml), so a group at 15 with no setting is
// ambiguous and its members are trusted no further than the operator tier
// until a superuser sets one. The built-in readonly and operator groups
// count: their tier can be set (group edit operator tier engineer), and
// raised to 15 with the setting lost they are as ambiguous as any other.

// SuperuserBand is the priv-lvl from which the band makes a superuser.
const SuperuserBand = 15

// NeedsTier reports whether a group at priv-lvl privlvl (nil: none) must
// carry an explicit tier setting: it is not the built-in superuser group
// (superuser at 15 is the superuser tier by definition) and sits in the
// superuser band.
func NeedsTier(group string, privlvl *int) bool {
	return privlvl != nil && *privlvl >= SuperuserBand && group != "superuser"
}

// UnsetTierGroups are the groups of m that need a tier setting and have
// none, sorted: the ambiguous groups.
func UnsetTierGroups(c *conf.Config, m *model.Model) []string {
	var out []string
	for _, name := range m.GroupNames() {
		if g := m.Group(name); g != nil && NeedsTier(name, g.PrivLvl) && GroupTier(c, name) == "" {
			out = append(out, name)
		}
	}
	return out
}

// PinUnset writes tier.<group>: superuser, the tier 0.2.2 gave it by its
// band, for every ambiguous group of m (UnsetTierGroups); see PinGroups.
func PinUnset(c *conf.Config, m *model.Model, snapshot func() error) ([]string, error) {
	return PinGroups(c, UnsetTierGroups(c, m), snapshot)
}

// PinGroups writes tier.<group>: superuser for each of groups, calling
// snapshot first when there is one to write (an error from it writes
// nothing). The groups written are returned, also when a later write fails.
func PinGroups(c *conf.Config, groups []string, snapshot func() error) ([]string, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	if snapshot != nil {
		if err := snapshot(); err != nil {
			return nil, err
		}
	}
	var done []string
	for _, g := range groups {
		if err := WriteGroupTier(c, g, "superuser"); err != nil {
			return done, err
		}
		done = append(done, g)
	}
	return done, nil
}
