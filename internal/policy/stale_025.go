package policy

// The operator no longer holds anything that can interrupt service, even
// briefly (0.2.5; docs/plans/0.2.5-operator-audit.md). Settings an earlier
// release stored keep what they hold until the operator of tacctl resets
// them: an upgrade drops only a list that is exactly what 0.2.3 shipped
// (DropPreviousDefaults), and tells the rest (StaleOperatorPolicy).

import (
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

// Stale is one stored setting that still carries what 0.2.5 removed.
type Stale struct {
	Setting string   // 'privileges.operator', 'commands.readonly', 'junos operator deny-commands'
	Group   string   // the group it belongs to
	Entries []string // what it carries that was removed (none for a Junos set)
}

// String is the setting with its removed entries.
func (s Stale) String() string {
	if len(s.Entries) == 0 {
		return s.Setting
	}
	return s.Setting + " (" + strings.Join(s.Entries, ", ") + ")"
}

// Fix is the command that puts the shipped value back.
func (s Stale) Fix() string {
	switch {
	case strings.HasPrefix(s.Setting, "privileges."):
		return "tacctl group privilege reset " + s.Group
	case strings.HasPrefix(s.Setting, "commands."):
		return "tacctl group commands reset " + s.Group
	}
	return "tacctl group reset " + s.Group + " --preset"
}

// StaleOperatorPolicy names the stored settings of c that still carry what
// 0.2.5 removed from the operator and the viewer, with the removed
// entries: 'privileges.operator' (the lowered commands), 'commands.<group>'
// (a rule that permits monitor or clear, or ping or traceroute with any
// arguments) and the 0.2.3 preset's Junos deny-commands of the two roles.
// Nothing for a group that holds other values or the shipped ones.
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
			out = append(out, Stale{"privileges.operator", "operator", found})
		}
	}
	for _, group := range []string{"operator", "readonly"} {
		if !HasOverride(c, group) {
			continue
		}
		seen := map[string]bool{}
		var found []string
		for _, l := range Lines(c, group) {
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
			out = append(out, Stale{"commands." + group, group, found})
		}
	}
	for _, j := range []struct{ group, value string }{{"readonly", viewerDenyCommands023}, {"operator", operatorDenyCommands023}} {
		if v := JunosSet(c, j.group, conf.JunosDenyCommands); len(v) == 1 && v[0] == j.value {
			out = append(out, Stale{"junos " + j.group + " deny-commands", j.group, nil})
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
