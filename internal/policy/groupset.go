package policy

// The per-group device settings of 0.2.2 (docs/plans/0.2.2-plan.md §4.1,
// D18, D27): the Junos deny sets (junos.<group>.<attr>), the WTI access
// level (wti_level.<group>) and the tacctl tier (tier.<group>), all in
// tacctl.yaml. Each is optional: unset, the priv-lvl band decides (WTI
// and tier) or nothing is sent (Junos). Every group, built-in or custom,
// is edited the same way; nothing here knows a role by name.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/render/radius"
)

func junosPath(group, attr string) string { return "junos." + group + "." + attr }
func wtiPath(group string) string         { return "wti_level." + group }
func tierPath(group string) string        { return "tier." + group }

// --- Junos deny sets ---------------------------------------------------------

// JunosSet is the group's patterns for attr (deny_commands or
// deny_configuration), in the order they are sent; nothing when unset.
func JunosSet(c *conf.Config, group, attr string) []string {
	return c.GetList(junosPath(group, attr))
}

// WriteJunosSet stores the group's patterns for attr; no pattern at all
// removes the key (and junos.<group> once both attributes are gone). The
// schema checks the patterns and the length of the value they make.
func WriteJunosSet(c *conf.Config, group, attr string, items []string) error {
	if len(items) == 0 {
		return c.Unset(junosPath(group, attr))
	}
	return c.SetList(junosPath(group, attr), items)
}

// JunosProblem is the refusal of a set whose value would not fit (§4.2),
// one line per element; nil when it fits.
func JunosProblem(group, attr string, items []string) []string {
	n, limit := len(conf.JunosValue(items)), conf.JunosLimit(attr)
	if n <= limit {
		return nil
	}
	arg := conf.JunosArg(attr)
	return []string{
		fmt.Sprintf("Group '%s': %s would be %d bytes; the limit is %d", group, arg, n, limit),
		fmt.Sprintf("(TACACS+ carries '%s=<value>' in one argument of at most 255 bytes,", arg),
		"and Junos refuses the login when it is longer).",
		fmt.Sprintf("Shorten a pattern or remove one: tacctl group junos %s %s list", group, arg),
	}
}

// JunosAttrOf is the tacctl.yaml name of an attribute given either way
// (deny-commands or deny_commands); false for anything else.
func JunosAttrOf(word string) (string, bool) {
	attr := strings.ReplaceAll(word, "-", "_")
	return attr, slices.Contains(conf.JunosAttrs, attr)
}

// --- WTI access level --------------------------------------------------------

// wtiFloors are the lowest priv-lvl of each WTI band, the priv-lvl a
// group's wti service sends for a level set on it (D4).
var wtiFloors = map[string]int{"viewonly": 0, "user": 5, "superuser": 10, "administrator": 15}

// WTILevel is the group's WTI level: the one set on it (override true),
// else the band of its priv-lvl.
func WTILevel(c *conf.Config, group string, privlvl int) (level string, override bool) {
	if v, ok := c.Get(wtiPath(group), ""); ok && v != "" {
		return v, true
	}
	return WTILevelOf(privlvl), false
}

// WriteWTILevel sets the group's WTI level; "" (or "auto") removes it, so
// the priv-lvl band decides again.
func WriteWTILevel(c *conf.Config, group, level string) error {
	if level == "" || level == "auto" {
		return c.Unset(wtiPath(group))
	}
	return c.Set(wtiPath(group), level)
}

// WTIPrivLvl is the priv-lvl a level is sent as: the floor of its band.
func WTIPrivLvl(level string) int { return wtiFloors[level] }

// WTILevelOf is the level of a priv-lvl's band, from the same table the
// RADIUS renderer uses (radius.WTISuper), so the two cannot drift.
func WTILevelOf(privlvl int) string {
	_, label := radius.WTISuper(privlvl)
	return strings.ToLower(label)
}

// --- tacctl tier -------------------------------------------------------------

// GroupTier is the tier set on the group (readonly, operator, engineer or
// superuser), or "" when none is set and its priv-lvl band decides.
func GroupTier(c *conf.Config, group string) string {
	v, _ := c.Get(tierPath(group), "")
	return v
}

// WriteGroupTier sets the group's tier; "" (or "auto") removes it.
func WriteGroupTier(c *conf.Config, group, tier string) error {
	if tier == "" || tier == "auto" {
		return c.Unset(tierPath(group))
	}
	return c.Set(tierPath(group), tier)
}

// ForgetGroup removes every per-group device setting of group (group
// remove); RenameGroup moves them to the new name (group rename).
func ForgetGroup(c *conf.Config, group string) error {
	for _, p := range []string{"junos." + group, wtiPath(group), tierPath(group)} {
		if err := c.Unset(p); err != nil {
			return err
		}
	}
	return nil
}

// RenameGroup moves the per-group device settings from old to new.
func RenameGroup(c *conf.Config, old, new string) error {
	for _, attr := range conf.JunosAttrs {
		if items := JunosSet(c, old, attr); len(items) > 0 {
			if err := WriteJunosSet(c, new, attr, items); err != nil {
				return err
			}
		}
	}
	if v, ok := c.Get(wtiPath(old), ""); ok && v != "" {
		if err := WriteWTILevel(c, new, v); err != nil {
			return err
		}
	}
	if t := GroupTier(c, old); t != "" {
		if err := WriteGroupTier(c, new, t); err != nil {
			return err
		}
	}
	return ForgetGroup(c, old)
}
