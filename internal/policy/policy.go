// Package policy is lib/policy.sh and the rule helpers of lib/groups.sh at
// the 0.1.16 tag: the per-group command-authorization rules
// (commands.<group> in tacctl.yaml), the per-group Cisco priv-exec mappings
// (privileges.<group>), the default sets of the built-in groups, and the
// healing of command rules whose match regex can never fire.
//
// The rules travel the way 0.1.16 moves them between its functions: as
// 'name|action|match1,match2' lines (Lines), edited as lines and written
// back by parsing them (Write). The round trip is part of the behaviour: a
// match regex holding a comma is split at it on the next write of the
// group, as it was in 0.1.16.
package policy

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Catchall is the name of a group's trailing rule, whose action is the
// group's default.
const Catchall = "*"

// Builtins are the built-in groups, in the order the seed commands take
// them.
var Builtins = []string{"readonly", "operator", "superuser"}

// commandsPath and privilegesPath are the tacctl.yaml keys of a group.
func commandsPath(group string) string   { return "commands." + group }
func privilegesPath(group string) string { return "privileges." + group }

// Lines is read_group_commands: one 'name|action|match,match' line per
// rule of the group (tacctl.yaml over the shipped defaults); nothing for a
// group without rules. A rule that is no mapping is skipped; a missing
// action reads as permit.
func Lines(c *conf.Config, group string) []string {
	v, _ := c.Value(commandsPath(group))
	rules, ok := py.List(v)
	if !ok {
		return nil
	}
	var out []string
	for _, r := range rules {
		m, ok := r.(*yamlpy.Map)
		if !ok {
			continue
		}
		name, action := "", any("permit")
		if v, ok := m.Get("name"); ok {
			name = py.Str(v)
		}
		if v, ok := m.Get("action"); ok {
			action = v
		}
		var matches []string
		if v, ok := m.Get("match"); ok {
			if l, ok := py.List(v); ok {
				for _, x := range l {
					matches = append(matches, py.Str(x))
				}
			}
		}
		out = append(out, name+"|"+py.Str(action)+"|"+strings.Join(matches, ","))
	}
	return out
}

// Field is awk -F'|' '{print $<n>}' of a rule line (1-based; "" past the
// end).
func Field(line string, n int) string {
	f := strings.Split(line, "|")
	if n-1 < len(f) {
		return f[n-1]
	}
	return ""
}

// DefaultAction is read_group_default_action: the action of the trailing
// catch-all; permit for a group without rules, deny when the last rule is
// not a catch-all (tacquito fails a command no rule matches).
func DefaultAction(c *conf.Config, group string) string {
	lines := Lines(c, group)
	if len(lines) == 0 {
		return "permit"
	}
	last := lines[len(lines)-1]
	if Field(last, 1) == Catchall {
		return Field(last, 2)
	}
	return "deny"
}

// blank is a line awk 'NF' drops.
func blank(s string) bool { return strings.TrimSpace(s) == "" }

// Write is write_group_commands: the rule lines (blank ones ignored)
// become commands.<group>; no rule at all removes the key, so the shipped
// defaults (if any) apply again. Each line is 'name|action|matches': a
// missing action is permit, matches split at commas, empty ones dropped.
func Write(c *conf.Config, group string, lines []string) error {
	var rules []any
	for _, l := range lines {
		for _, line := range strings.Split(l, "\n") {
			if py.Strip(line) == "" {
				continue
			}
			parts := strings.SplitN(line, "|", 3)
			rule := yamlpy.NewMap("name", parts[0], "action", "permit")
			if len(parts) > 1 {
				rule.Set("action", parts[1])
			}
			if len(parts) > 2 {
				var matches []any
				for _, m := range strings.Split(parts[2], ",") {
					if m != "" {
						matches = append(matches, m)
					}
				}
				if len(matches) > 0 {
					rule.Set("match", matches)
				}
			}
			rules = append(rules, rule)
		}
	}
	if len(rules) == 0 {
		return c.Unset(commandsPath(group))
	}
	return c.SetValue(commandsPath(group), rules)
}

// withoutName is awk -F'|' -v n=<name> '$1 != n'.
func withoutName(lines []string, name string) []string {
	var out []string
	for _, l := range lines {
		if Field(l, 1) != name {
			out = append(out, l)
		}
	}
	return out
}

// nonBlank is awk 'NF'.
func nonBlank(lines []string) []string {
	var out []string
	for _, l := range lines {
		if !blank(l) {
			out = append(out, l)
		}
	}
	return out
}

// UpdateCatchall is update_group_catchall: the group's catch-all replaced
// by one with action, at the end.
func UpdateCatchall(c *conf.Config, group, action string) error {
	lines := withoutName(Lines(c, group), Catchall)
	return Write(c, group, nonBlank(append(lines, Catchall+"|"+action+"|")))
}

// InsertRule is insert_command_rule: a rule added before the catch-all
// (whose action stays the group's default action).
func InsertRule(c *conf.Config, group, name, action, matches string) error {
	catchall := Catchall + "|" + DefaultAction(c, group) + "|"
	lines := withoutName(Lines(c, group), Catchall)
	return Write(c, group, nonBlank(append(lines, name+"|"+action+"|"+matches, catchall)))
}

// RemoveRule is remove_command_rule: every rule named name dropped (the
// rest, catch-all included, written back).
func RemoveRule(c *conf.Config, group, name string) error {
	return Write(c, group, withoutName(Lines(c, group), name))
}

// Where is where InsertRuleAt puts a rule: at position 1 (First), before
// the first rule named Before, or (neither, or Before the catch-all)
// before the catch-all, as InsertRule does.
type Where struct {
	First  bool
	Before string
}

// NoRuleError is InsertRuleAt's answer to a Before that names no rule of
// the group.
type NoRuleError struct{ Group, Name string }

func (e *NoRuleError) Error() string {
	return "No rule named '" + e.Name + "' in group '" + e.Group + "'."
}

// InsertRuleAt is InsertRule with a position (where): the rule goes there,
// and the catch-all stays last (with the group's default action). Nothing
// is written when where.Before names no rule.
func InsertRuleAt(c *conf.Config, group, name, action, matches string, where Where) error {
	catchall := Catchall + "|" + DefaultAction(c, group) + "|"
	lines := nonBlank(withoutName(Lines(c, group), Catchall))
	at := len(lines)
	switch {
	case where.First:
		at = 0
	case where.Before != "" && where.Before != Catchall:
		at = -1
		for i, l := range lines {
			if Field(l, 1) == where.Before {
				at = i
				break
			}
		}
		if at < 0 {
			return &NoRuleError{Group: group, Name: where.Before}
		}
	}
	out := append(append(append([]string{}, lines[:at]...), name+"|"+action+"|"+matches), lines[at:]...)
	return Write(c, group, append(out, catchall))
}

// Numbered is a rule line with its 1-based position in the group (as
// 'group commands list' numbers it).
type Numbered struct {
	Pos  int
	Line string
}

// RulesWhere is the selector of RemoveRuleWhere: the rules named name
// whose match list equals matches (nil for any), in its stored order, and
// whose action is action ("" for any).
func RulesWhere(c *conf.Config, group, name string, matches []string, action string) []Numbered {
	var out []Numbered
	for i, l := range Lines(c, group) {
		if Field(l, 1) == name &&
			(matches == nil || ruleMatches(l) == strings.Join(matches, ",")) &&
			(action == "" || Field(l, 2) == action) {
			out = append(out, Numbered{Pos: i + 1, Line: l})
		}
	}
	return out
}

// AmbiguousError is RemoveRuleWhere's refusal of a selector that leaves
// several rules without all.
type AmbiguousError struct {
	Group, Name string
	Count       int
}

func (e *AmbiguousError) Error() string {
	return "Group '" + e.Group + "' has " + strconv.Itoa(e.Count) + " rules named '" + e.Name +
		"'; select one with --match/--action (see 'tacctl group commands list " + e.Group + "'), or pass --all."
}

// RemoveRuleWhere drops the rules RulesWhere selects and returns them (with
// their positions before the removal). One is removed; several are an
// AmbiguousError unless all, which removes them all (what RemoveRule does
// with no selector). None removes nothing; nothing is written then or on
// an error.
func RemoveRuleWhere(c *conf.Config, group, name string, matches []string, action string, all bool) ([]Numbered, error) {
	gone := RulesWhere(c, group, name, matches, action)
	if len(gone) == 0 {
		return nil, nil
	}
	if len(gone) > 1 && !all {
		return nil, &AmbiguousError{Group: group, Name: name, Count: len(gone)}
	}
	lines := Lines(c, group)
	keep := make([]string, 0, len(lines))
	for i, l := range lines {
		if !slices.ContainsFunc(gone, func(n Numbered) bool { return n.Pos == i+1 }) {
			keep = append(keep, l)
		}
	}
	return gone, Write(c, group, keep)
}

// ruleMatches is the match field of a rule line: everything after the
// second '|'.
func ruleMatches(line string) string {
	f := strings.SplitN(line, "|", 3)
	if len(f) < 3 {
		return ""
	}
	return f[2]
}

// GroupLevels is what SeedSiblings reads of the groups: the
// 'name|priv_lvl|juniper_class' lines of model_group_info.
type GroupLevels []string

// SeedSiblings is seed_command_rules_safely: before group gains command
// rules, every other group at its Cisco priv-lvl without rules of its own
// gets a permit-* catch-all, so that 'aaa authorization commands <level>'
// on a device does not deny its users everything. It returns the level
// and the groups it seeded (none when group has no level).
func SeedSiblings(c *conf.Config, groups GroupLevels, group string) (privlvl string, seeded []string, err error) {
	for _, l := range groups {
		if Field(l, 1) == group {
			privlvl = Field(l, 2)
		}
	}
	if privlvl == "" {
		return "", nil, nil
	}
	for _, l := range groups {
		other := Field(l, 1)
		if other == "" || other == group || Field(l, 2) != privlvl {
			continue
		}
		if len(Lines(c, other)) > 0 {
			continue
		}
		if err := Write(c, other, []string{Catchall + "|permit|"}); err != nil {
			return privlvl, seeded, err
		}
		seeded = append(seeded, other)
	}
	return privlvl, seeded, nil
}

// DefaultRules is default_rules_for_group: the legacy seed set of a
// built-in group (its default action and the commands it permits); ok is
// false for any other group.
func DefaultRules(group string) (action string, permits []string, ok bool) {
	switch group {
	case "readonly":
		return "deny", strings.Fields("show ping traceroute terminal exit end quit logout who where enable"), true
	case "operator":
		return "deny", strings.Fields("show ping traceroute terminal exit end quit logout who where enable clear test monitor"), true
	case "superuser":
		return "permit", nil, true
	}
	return "", nil, false
}

// ApplyDefaultRules is apply_default_rules: the group's rules replaced by
// its seed set. It does nothing and returns false for a group with none.
func ApplyDefaultRules(c *conf.Config, group string) (bool, error) {
	action, permits, ok := DefaultRules(group)
	if !ok {
		return false, nil
	}
	var lines []string
	for _, p := range permits {
		lines = append(lines, p+"|permit|")
	}
	return true, Write(c, group, append(lines, Catchall+"|"+action+"|"))
}

// --- privileges -------------------------------------------------------------

// Privileges is read_group_privileges: the group's priv-exec commands
// (tacctl.yaml over the shipped defaults).
func Privileges(c *conf.Config, group string) []string {
	return c.GetList(privilegesPath(group))
}

// DefaultPrivileges is default_privileges_for_group: the shipped list of
// the group (empty for a group that has none).
func DefaultPrivileges(group string) []string {
	p, _ := conf.Defaults().Get("privileges")
	m, ok := p.(*yamlpy.Map)
	if !ok {
		return nil
	}
	v, _ := m.Get(group)
	l, _ := py.List(v)
	out := make([]string, 0, len(l))
	for _, x := range l {
		out = append(out, py.Str(x))
	}
	return out
}

// WritePrivileges is write_group_privileges: the commands (blank ones
// dropped) become privileges.<group>; none at all is the default again.
func WritePrivileges(c *conf.Config, group string, cmds []string) error {
	return c.SetList(privilegesPath(group), conf.ListItems(strings.Join(cmds, "\n")+"\n"))
}

// --- healing ----------------------------------------------------------------

// Healed is one group conf_migrate_dead_command_matches changed: its
// override was dropped (the healed rules equal the shipped default) or
// rewritten.
type Healed struct {
	Group   string
	Dropped bool
}

// Message is the line 0.1.16 announced the change with (an info line).
func (h Healed) Message() string {
	if h.Dropped {
		return "Dropped commands." + h.Group + " override: its match regexes could never fire; shipped defaults now apply"
	}
	return "Rewrote commands." + h.Group + " override: removed match regexes that could never fire"
}

// HealDeadMatches is conf_migrate_dead_command_matches: every
// commands.<group> override in tacctl.yaml loses the match regexes that
// repeat their rule's command word (names.CommandMatchIsDead); an override
// that then equals the shipped default is dropped. Groups are taken by
// name; a group whose override is not a list is left alone. Nothing is
// written when nothing is dead, or when tacctl.yaml cannot be read.
func HealDeadMatches(c *conf.Config) ([]Healed, error) {
	if c.Problem() != "" {
		return nil, nil
	}
	cmds, _ := c.Overrides().Get("commands")
	groups, ok := cmds.(*yamlpy.Map)
	if !ok {
		return nil, nil
	}
	defaults := map[string]any{}
	if d, ok := conf.Defaults().Get("commands"); ok {
		if dm, ok := d.(*yamlpy.Map); ok {
			for k, v := range dm.All() {
				defaults[k] = v
			}
		}
	}
	keys := groups.Keys()
	sort.Strings(keys)
	var out []Healed
	for _, group := range keys {
		v, _ := groups.Get(group)
		rules, ok := py.List(v)
		if !ok {
			continue
		}
		changed := false
		var healed []any
		for _, r := range rules {
			m, isMap := r.(*yamlpy.Map)
			if !isMap {
				healed = append(healed, r)
				continue
			}
			mv, _ := m.Get("match")
			matches, isList := py.List(mv)
			if !isList || len(matches) == 0 {
				healed = append(healed, r)
				continue
			}
			nameV, _ := m.Get("name")
			name, nameIsStr := nameV.(string)
			var kept []any
			for _, x := range matches {
				rx, rxIsStr := x.(string)
				if nameIsStr && rxIsStr && names.CommandMatchIsDead(name, rx) {
					continue
				}
				kept = append(kept, x)
			}
			if len(kept) == len(matches) {
				healed = append(healed, r)
				continue
			}
			changed = true
			nm := yamlpy.NewMap()
			for k, val := range m.All() {
				nm.Set(k, val)
			}
			if len(kept) > 0 {
				nm.Set("match", kept)
			} else {
				nm.Delete("match")
			}
			healed = append(healed, nm)
		}
		if !changed {
			continue
		}
		if def, ok := defaults[group]; ok && py.Equal(listOf(healed), def) {
			if err := c.Unset(commandsPath(group)); err != nil {
				return out, err
			}
			out = append(out, Healed{Group: group, Dropped: true})
			continue
		}
		if err := c.SetValue(commandsPath(group), listOf(healed)); err != nil {
			return out, err
		}
		out = append(out, Healed{Group: group})
	}
	return out, nil
}

// listOf is healed as a list value ([] for none).
func listOf(l []any) []any {
	if l == nil {
		return []any{}
	}
	return l
}
