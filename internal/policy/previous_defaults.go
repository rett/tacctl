package policy

// What earlier releases shipped for operator and readonly: the command
// rules up to 0.2.2, the rules and the privilege list of 0.2.3. A commands
// block that equals one of them is not an override anybody made: it is what
// an earlier tacctl wrote (into tacquito.yaml of an install without a
// store, as an override 'group commands add' seeded from the shipped list,
// or as an override that HealDeadMatches just rewrote), so the migrations
// drop it and the current shipped rules apply
// (docs/plans/0.2.3-baseline-design.md; 0.2.5 operator audit, section 6f).
// Only an exact match is dropped: a list that differs in one rule is a
// choice, which the upgrade tells the operator about (StaleOperatorPolicy)
// and does not touch.

import (
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// prevRule is one shipped command rule: name, action and, when it has
// them, the match regexes.
type prevRule struct {
	name, action string
	match        []string
}

const (
	prevShowFull = `^(running-config view full)( .*)?$`
	prevClear023 = `^(counters|line|(ip )?arp \S+|arp-cache \S+|mac address-table dynamic \S+)( .*)?$`
)

// previousDefaults is, by group, every earlier generation of its shipped
// rules, oldest first.
var previousDefaults = map[string][][]prevRule{
	"operator": {
		// up to 0.2.2
		{{"show", "permit", nil}, {"ping", "permit", nil}, {"traceroute", "permit", nil}, {"terminal", "permit", nil}, {"*", "deny", nil}},
		// 0.2.3 (and 0.2.4)
		{{"show", "deny", []string{prevShowFull}}, {"show", "permit", nil}, {"dir", "permit", nil}, {"ping", "permit", nil},
			{"traceroute", "permit", nil}, {"terminal", "permit", nil}, {"ssh", "permit", nil}, {"telnet", "permit", nil},
			{"monitor", "permit", []string{`^(capture)( .*)?$`}}, {"clear", "permit", []string{prevClear023}},
			{"undebug", "permit", nil}, {"exit", "permit", nil}, {"logout", "permit", nil}, {"*", "deny", nil}},
	},
	"readonly": {
		// up to 0.2.2
		{{"show", "permit", nil}, {"ping", "permit", nil}, {"traceroute", "permit", nil}, {"*", "deny", nil}},
		// 0.2.3 (and 0.2.4)
		{{"show", "deny", []string{prevShowFull}}, {"show", "permit", nil}, {"dir", "permit", nil}, {"ping", "permit", nil},
			{"traceroute", "permit", nil}, {"terminal", "permit", []string{`^(length|width)( .*)?$`}},
			{"exit", "permit", nil}, {"logout", "permit", nil}, {"*", "deny", nil}},
	},
}

// previousPrivileges is, by group, the shipped privilege lists of the
// releases that lowered more than the current one.
var previousPrivileges = map[string][][]string{
	"operator": {
		// 0.2.3 (and 0.2.4)
		{"exec all: ping", "exec all: traceroute", "exec all: monitor capture", "clear counters", "clear line",
			"clear ip arp", "clear arp-cache", "clear mac address-table dynamic", "undebug all"},
	},
}

// IsPreviousDefault reports whether rules (a commands.<group> list value)
// are the shipped rules of the group in an earlier release.
func IsPreviousDefault(group string, rules any) bool {
	for _, gen := range previousDefaults[group] {
		var list []any
		for _, r := range gen {
			m := yamlpy.NewMap("name", r.name, "action", r.action)
			if len(r.match) > 0 {
				var ms []any
				for _, x := range r.match {
					ms = append(ms, x)
				}
				m.Set("match", ms)
			}
			list = append(list, m)
		}
		if py.Equal(rules, list) {
			return true
		}
	}
	return false
}

// IsPreviousPrivileges reports whether list (a privileges.<group> list
// value) is the shipped privilege list of the group in an earlier release.
func IsPreviousPrivileges(group string, list any) bool {
	for _, gen := range previousPrivileges[group] {
		var want []any
		for _, x := range gen {
			want = append(want, x)
		}
		if py.Equal(list, want) {
			return true
		}
	}
	return false
}
