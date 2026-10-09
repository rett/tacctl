package policy

// The canonical state of a group (docs/plans/0.2.3-plan.md D51): what
// 'tacctl group reset' puts a group back to. For the built-in groups it is
// what a fresh install gives them, read from the single sources (the
// shipped defaults.yaml for the Cisco rules and privileges,
// store.BuiltinGroups for the priv-lvl and the Junos class) with no
// override of the tier, the WTI level or the Junos sets; with the role
// preset it is the role's values (RolePreset) instead. The engineer, which
// is not built in until 0.3.0 (D49), has only the preset's values. Any other
// group has no canonical state.

import "github.com/rett/tacctl/internal/store"

// Canonical is the canonical state of one group.
type Canonical struct {
	Group   string
	Builtin bool // a group every store holds (store.BuiltinGroups)
	PrivLvl int
	Class   string // the Junos class ("" for a group the preset gives none)
	Tier    string // the tier setting; "" is no setting (the priv-lvl band decides)
	WTI     string // the WTI level setting; "" is none (the band decides)
	// Junos are the deny sets by attribute; an attribute that is absent or
	// empty is a set that is cleared.
	Junos map[string][]string
	// Rules are the Cisco rule lines the group reads after the reset: the
	// shipped defaults (RulesOverride false: no commands.<group> of its own)
	// or the preset's rules (an override).
	Rules         []string
	RulesOverride bool
	// Privileges are the priv-exec mappings the group reads after the reset:
	// the shipped list (no override of its own).
	Privileges []string
}

// CanonicalGroup is the canonical state of group, with the role preset's
// values (preset) or the shipped ones; false for a group that is neither
// built in nor a role of the preset. The engineer's is the preset's whatever
// preset says.
func CanonicalGroup(group string, preset bool) (Canonical, bool) {
	var role *Role
	for _, r := range RolePreset() {
		if r.Group == group {
			role = &r
			break
		}
	}
	var c Canonical
	switch b, builtin := builtinGroup(group); {
	case builtin:
		c = Canonical{Group: group, Builtin: true, PrivLvl: b.PrivLvl, Class: b.JuniperClass,
			Rules: DefaultLines(group), Privileges: DefaultPrivileges(group)}
		if !preset || role == nil {
			return c, true
		}
	case role != nil:
		c = Canonical{Group: group, Privileges: DefaultPrivileges(group)}
	default:
		return Canonical{}, false
	}
	c.PrivLvl = role.PrivLvl
	if role.Class != "" {
		c.Class = role.Class
	}
	c.WTI, c.Tier, c.Junos = role.WTI, role.Tier, role.Junos
	c.Tier = tierSetting(group, c.PrivLvl, c.Tier)
	if role.Commands != nil {
		c.Rules, c.RulesOverride = role.Commands, true
	}
	return c, true
}

// tierSetting is the tier setting a group at privlvl carries: the one given,
// else (the invariant of the tier setting, NeedsTier) superuser for a group
// in the superuser band, which has to have one.
func tierSetting(group string, privlvl int, tier string) string {
	if tier == "" && NeedsTier(group, &privlvl) {
		return "superuser"
	}
	return tier
}

// JunosItems are the patterns of attr in the canonical state (none: the set
// is cleared).
func (c Canonical) JunosItems(attr string) []string { return c.Junos[attr] }

func builtinGroup(name string) (store.BuiltinGroup, bool) {
	for _, b := range store.BuiltinGroups {
		if b.Name == name {
			return b, true
		}
	}
	return store.BuiltinGroup{}, false
}
