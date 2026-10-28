package conf

import (
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// GroupTierSetting is the tier set on the group in tacctl.yaml (readonly,
// operator, engineer or superuser), or "" when none is set and its priv-lvl
// band decides. A setting that is there but cannot be one (tier.<group> a
// mapping, a list, null, empty or a number, or a tier that is not a mapping
// at all) is tier.InvalidSetting, which tier.ForGroup makes readonly: a
// hand-edit must never leave a group at priv-lvl 15 a superuser.
//
// policy.GroupTier is this function; it lives here so that the renderers,
// which policy imports, can read the setting too.
func GroupTierSetting(c *Config, group string) string {
	top, ok := c.Value("tier")
	if !ok {
		return ""
	}
	m, isMap := top.(*yamlpy.Map)
	if !isMap {
		return tier.InvalidSetting
	}
	v, ok := m.Get(group)
	if !ok {
		return ""
	}
	if s, isStr := v.(string); isStr && s != "" {
		return s
	}
	return tier.InvalidSetting
}
