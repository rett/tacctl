package policy

// The shipped command rules of operator and readonly up to 0.2.2. A
// commands block that equals them is not an override anybody made: it is
// what an earlier tacctl wrote (into tacquito.yaml of an install without a
// store, or as an override that HealDeadMatches just rewrote), so the
// migrations drop it and the current shipped rules apply
// (docs/plans/0.2.3-baseline-design.md).

import (
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

var previousDefaults = map[string][][2]string{
	"operator": {{"show", "permit"}, {"ping", "permit"}, {"traceroute", "permit"}, {"terminal", "permit"}, {"*", "deny"}},
	"readonly": {{"show", "permit"}, {"ping", "permit"}, {"traceroute", "permit"}, {"*", "deny"}},
}

// IsPreviousDefault reports whether rules (a commands.<group> list value)
// are the shipped rules of the group before 0.2.3.
func IsPreviousDefault(group string, rules any) bool {
	want, ok := previousDefaults[group]
	if !ok {
		return false
	}
	var list []any
	for _, r := range want {
		list = append(list, yamlpy.NewMap("name", r[0], "action", r[1]))
	}
	return py.Equal(rules, list)
}
