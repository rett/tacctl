package policy

import (
	"slices"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/yamlpy"
)

// GroupKeyFamilies are the tacctl.yaml mappings keyed by group name whose
// keys StaleGroups does not report (it has tier, wti_level and junos): the
// Cisco rules and the command rules of a group.
var GroupKeyFamilies = []string{"privileges", "commands"}

// OrphanKeys lists "<family>.<name>" for every key of the given mappings of
// tacctl.yaml (each a dotted path to a mapping keyed by a group or scope
// name) whose name exists says is not there, sorted by family and name. A
// family that is absent or is not a mapping adds nothing. The names are the
// ones a later group or scope of that name would take over; the built-in
// groups are never orphans.
func OrphanKeys(c *conf.Config, families []string, exists func(name string) bool) []string {
	var out []string
	for _, fam := range families {
		top, ok := c.Value(fam)
		if !ok {
			continue
		}
		m, isMap := top.(*yamlpy.Map)
		if !isMap {
			continue
		}
		var names []string
		for _, n := range m.Keys() {
			if !exists(n) && !slices.Contains(Builtins, n) {
				names = append(names, n)
			}
		}
		slices.Sort(names)
		for _, n := range names {
			out = append(out, fam+"."+n)
		}
	}
	return out
}
