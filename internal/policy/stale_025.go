package policy

// The operator no longer holds anything that can interrupt service, even
// briefly (0.2.5; docs/plans/0.2.5-operator-audit.md). Settings an earlier
// release stored keep what they hold until the operator of tacctl resets
// them: an upgrade drops only a list that is exactly what 0.2.3 shipped
// (DropPreviousDefaults), and tells the rest (StaleOperatorPolicy).

import (
	"slices"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// retiredPrivileges are the privilege entries 0.2.5 took out of the
// operator's list; 'exec all: ping' and 'exec all: traceroute' were the
// lowering of the whole subtree.
var retiredPrivileges = []string{"exec all: ping", "exec all: traceroute", "exec all: monitor capture",
	"clear counters", "clear line", "clear ip arp", "clear arp-cache", "clear mac address-table dynamic"}

// The deny-commands the role preset of 0.2.3 set for the viewer and the
// operator on Junos; 0.2.5 sets other values (viewer: ping rapid|interval;
// operator: the whole 'clear' family, 'monitor traffic' whole).
const (
	viewerDenyCommands023   = `^(ssh|telnet|file|request|restart|start|load|op|test|monitor|configure|edit|clear|show system rollback)( .*)?$`
	operatorDenyCommands023 = `^(file|request|restart|start|load|op|test|configure|edit|clear (bgp|ospf|ospf3|isis|ldp|rsvp|mpls|pim|igmp|msdp|bfd|vrrp|lacp|system|security|network-access|log|dhcp)|monitor traffic .*write-file|show system rollback)( .*)?$`
)

// The 'show' denies 0.2.3's 'group preset roles' stored in front of the
// rules that release shipped. An install that ran the preset holds exactly
// these (the preset's values are overrides), and the fix that keeps its
// 'show' deny is the preset's reset, not the shipped rules' (which have
// none beyond 'running-config view full').
const (
	viewerShowDeny023   = `running-config view full|tech-support|startup-config|derived-config|key chain|snmp (community|user)|crypto|archive log`
	operatorShowDeny023 = `running-config view full|startup-config|derived-config|key chain|snmp (community|user)|crypto (isakmp key|key)|archive log`
)

// preset023Lines is the commands.<group> value 0.2.3's role preset wrote
// for readonly or operator, as rule lines.
func preset023Lines(group string) []string {
	deny := viewerShowDeny023
	if group == "operator" {
		deny = operatorShowDeny023
	}
	lines := []string{"show|deny|" + pfx(deny)}
	if gens := previousDefaults[group]; len(gens) > 1 {
		for _, r := range gens[1] {
			lines = append(lines, r.name+"|"+r.action+"|"+strings.Join(r.match, ","))
		}
	}
	return lines
}

// Stale is one stored setting that still carries what 0.2.5 removed.
type Stale struct {
	Setting string   // 'privileges.operator', 'commands.readonly', 'junos operator deny-commands'
	Group   string   // the group it belongs to
	Entries []string // what it carries that was removed (none for a Junos set)
	// Preset: the value is what 0.2.3's role preset stored (its 'show' deny
	// and the shipped rules of that release, or its Junos deny set), so the
	// fix is the role preset's reset of the section, which keeps the denies.
	Preset bool
}

// String is the setting with its removed entries.
func (s Stale) String() string {
	if len(s.Entries) == 0 {
		return s.Setting
	}
	return s.Setting + " (" + strings.Join(s.Entries, ", ") + ")"
}

// section is the 'group reset --only' word of a setting the role preset
// resets ("" for a privilege list).
func (s Stale) section() string {
	switch {
	case strings.HasPrefix(s.Setting, "commands."):
		return "commands"
	case strings.HasPrefix(s.Setting, "junos "):
		return "junos"
	}
	return ""
}

// presetFix reports whether the fix of s is the role preset's reset.
func (s Stale) presetFix() bool { return s.section() == "junos" || s.Preset }

// Fix is the command that replaces the setting: the shipped value for a
// list somebody stored, the role preset's for what the 0.2.3 preset stored
// (a reset that keeps its denies).
func (s Stale) Fix() string {
	switch {
	case s.presetFix():
		return "tacctl group reset " + s.Group + " --preset --only " + s.section()
	case strings.HasPrefix(s.Setting, "privileges."):
		return "tacctl group privilege reset " + s.Group
	}
	return "tacctl group commands reset " + s.Group
}

// Restores says what Fix puts back, for a sentence.
func (s Stale) Restores() string {
	if s.presetFix() {
		return "the role preset's value"
	}
	return "the shipped value"
}

// Fixes are the commands that clear every setting of stale, one per
// distinct fix, in the order of the settings; the preset's reset of the
// commands and of the Junos sets of one group is a single command
// ('--only commands,junos').
func Fixes(stale []Stale) []string {
	type pending struct {
		at       int
		sections []string
	}
	var out []string
	preset := map[string]*pending{}
	var groups []string
	for _, s := range stale {
		if !s.presetFix() {
			if f := s.Fix(); !slices.Contains(out, f) {
				out = append(out, f)
			}
			continue
		}
		p := preset[s.Group]
		if p == nil {
			p = &pending{at: len(out)}
			preset[s.Group] = p
			groups = append(groups, s.Group)
			out = append(out, "")
		}
		if sec := s.section(); !slices.Contains(p.sections, sec) {
			p.sections = append(p.sections, sec)
		}
	}
	for _, g := range groups {
		p := preset[g]
		sort.Strings(p.sections) // commands before junos, as --only lists them
		out[p.at] = "tacctl group reset " + g + " --preset --only " + strings.Join(p.sections, ",")
	}
	return out
}

// StaleOperatorPolicy names the stored settings of c that still carry what
// 0.2.5 removed from the operator and the viewer, with the removed
// entries: 'privileges.operator' (the lowered commands), 'commands.<group>'
// (a rule that permits monitor or clear, or ping or traceroute with any
// arguments) and the 0.2.3 preset's Junos deny-commands of the two roles.
// A commands list that is exactly what 0.2.3's role preset stored is marked
// Preset, so its fix is the preset's reset. Nothing for a group that holds
// other values or the shipped ones.
func StaleOperatorPolicy(c *conf.Config) []Stale {
	var out []Stale
	if c.HasOverride(privilegesPath("operator")) {
		var found []string
		for _, e := range Privileges(c, "operator") {
			for _, r := range retiredPrivileges {
				if strings.TrimSpace(e) == r {
					found = append(found, r)
				}
			}
		}
		if len(found) > 0 {
			out = append(out, Stale{Setting: "privileges.operator", Group: "operator", Entries: found})
		}
	}
	for _, group := range []string{"operator", "readonly"} {
		if !HasOverride(c, group) {
			continue
		}
		seen := map[string]bool{}
		var found []string
		lines := Lines(c, group)
		for _, l := range lines {
			parts := strings.SplitN(l, "|", 3)
			if len(parts) < 3 || parts[1] != "permit" {
				continue
			}
			name, match := parts[0], parts[2]
			if (name == "monitor" || name == "clear") && group == "operator" && !seen[name] ||
				(name == "ping" || name == "traceroute") && match == "" && !seen[name] {
				seen[name] = true
				found = append(found, name)
			}
		}
		if len(found) > 0 {
			sort.Strings(found)
			out = append(out, Stale{Setting: "commands." + group, Group: group, Entries: found,
				Preset: SameLines(lines, preset023Lines(group))})
		}
	}
	for _, j := range []struct{ group, value string }{{"readonly", viewerDenyCommands023}, {"operator", operatorDenyCommands023}} {
		if v := JunosSet(c, j.group, conf.JunosDenyCommands); len(v) == 1 && v[0] == j.value {
			out = append(out, Stale{Setting: "junos " + j.group + " deny-commands", Group: j.group, Preset: true})
		}
	}
	return out
}

// DropPreviousDefaults removes the overrides of c that are exactly what an
// earlier release shipped (previousDefaults, previousPrivileges): a list
// 'group privilege add' seeded from the shipped one, or a block an older
// tacctl wrote, is not a choice, so the current shipped value applies.
// It returns the settings it dropped, 'commands.operator' and so on. Nothing
// is written when nothing matches, or when tacctl.yaml cannot be read.
func DropPreviousDefaults(c *conf.Config) ([]string, error) {
	if c.Problem() != "" {
		return nil, nil
	}
	var out []string
	for _, k := range []struct {
		section string
		is      func(group string, v any) bool
		groups  []string
	}{
		{"commands", IsPreviousDefault, []string{"operator", "readonly"}},
		{"privileges", IsPreviousPrivileges, []string{"operator"}},
	} {
		sec, _ := c.Overrides().Get(k.section)
		m, ok := sec.(*yamlpy.Map)
		if !ok {
			continue
		}
		for _, group := range k.groups {
			v, ok := m.Get(group)
			if !ok {
				continue
			}
			if _, isList := py.List(v); !isList || !k.is(group, v) {
				continue
			}
			if err := c.Unset(k.section + "." + group); err != nil {
				return out, err
			}
			out = append(out, k.section+"."+group)
		}
	}
	return out, nil
}
