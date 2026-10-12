package devconf

// The device's own statements (0.2.7): an extra statement of the 'snmp'
// section that the planner leaves on the device by rule is unmanaged, not a
// difference. A section that lacks nothing and differs only by such
// statements reads ok, with their number (SectionResult.Unmanaged).
//
// The shapes mirror the Kept column of the planner's ownership rows
// (plan/owned.go, named by Row; a test there keeps the two in step) and the
// statements of no row at all ('snmp name', trap groups, trap options,
// 'snmp-server host'). Only the 'snmp' section has them: an extra of the
// other sections (another server, a login class, a filter, a user nobody
// recorded) is a finding about who can log in, and stays a difference.

import (
	"slices"
	"strings"
)

// keptShape is one shape of statement the planner keeps by rule.
type keptShape struct {
	// Row is the ownership row whose Kept column the shape is ("" for a
	// statement of no row).
	Row string
	// Pattern is the statement's first words, space separated; '$' is the
	// name of an object.
	Pattern string
	// keep reports whether a statement of the pattern is the device's own:
	// name is the word at '$' and prefix the pattern's words with it filled
	// in.
	keep func(name string, prefix []string, exp *renderedWords) bool
}

// The tests of the shapes.
var (
	// another community: its label is '<other:N>' (the bare mark of an
	// older record cannot be told apart, so it is not)
	otherCommunity = func(name string, _ []string, _ *renderedWords) bool { return IsOtherLabel(name) }
	// an object of a name the rendering does not set
	notRendered = func(_ string, prefix []string, exp *renderedWords) bool { return !exp.has(prefix) }
	// a statement the rendering has nothing of
	always = func(string, []string, *renderedWords) bool { return true }
)

// keptShapes are the shapes per family; the first whose pattern a statement
// starts with decides.
var keptShapes = map[string][]keptShape{
	FamilyJunos: {
		{Row: "junos.snmp.community", Pattern: "snmp community $", keep: otherCommunity},
		{Row: "junos.snmp.client-list", Pattern: "snmp client-list $", keep: notRendered},
		{Row: "junos.snmp.v3-user", Pattern: "snmp v3 usm local-engine user $", keep: notRendered},
		{Row: "junos.snmp.v3-group", Pattern: "snmp v3 vacm security-to-group security-model usm security-name $", keep: notRendered},
		{Row: "junos.snmp.v3-access", Pattern: "snmp v3 vacm access group $", keep: notRendered},
		{Row: "junos.snmp.view", Pattern: "snmp view $", keep: notRendered},
		{Row: "junos.snmp.location", Pattern: "snmp location", keep: notRendered},
		{Row: "junos.snmp.contact", Pattern: "snmp contact", keep: notRendered},
		{Row: "junos.snmp.description", Pattern: "snmp description", keep: notRendered},
		// no row: trap groups, trap options, the name, the engine id, the
		// rest of v3 and anything else under 'snmp'
		{Pattern: "snmp", keep: always},
	},
	FamilyIOS: {
		{Row: "ios.snmp.community", Pattern: "snmp-server community $", keep: otherCommunity},
		{Row: "ios.snmp.location", Pattern: "snmp-server location", keep: notRendered},
		{Row: "ios.snmp.contact", Pattern: "snmp-server contact", keep: notRendered},
		{Row: "ios.snmp.acl", Pattern: "ip access-list standard $", keep: notRendered},
		{Pattern: "snmp-server view $", keep: notRendered},
		{Pattern: "snmp-server group $", keep: notRendered},
		{Pattern: "snmp-server user $", keep: notRendered},
		// no row: 'snmp-server host', 'enable traps' and the rest
		{Pattern: "snmp-server", keep: always},
	},
}

// KeptShape is one of the shapes as data, for the test that keeps them in
// step with the ownership rows.
type KeptShape struct {
	Row, Pattern string
}

// KeptShapes returns the shapes of a family.
func KeptShapes(family string) []KeptShape {
	var out []KeptShape
	for _, s := range keptShapes[family] {
		out = append(out, KeptShape{Row: s.Row, Pattern: s.Pattern})
	}
	return out
}

// renderedWords are the words of the rendered statements.
type renderedWords [][]string

// has reports whether a rendered statement starts with the words.
func (r *renderedWords) has(prefix []string) bool {
	return slices.ContainsFunc(*r, func(w []string) bool { return len(w) >= len(prefix) && slices.Equal(w[:len(prefix)], prefix) })
}

// stmtWords are a statement's words: the Junos path, or the IOS context and
// line split.
func stmtWords(fam string, x stmt) []string {
	if fam == FamilyJunos {
		return x.path
	}
	return strings.Fields(strings.Join(x.path, " "))
}

// unmanaged reports an extra statement of a section that is the device's
// own by rule. A deactivated statement is a finding of its own.
func unmanaged(fam, section string, x stmt, exp []stmt) bool {
	if section != SectionSNMP || strings.HasPrefix(x.stem, "deactivate ") {
		return false
	}
	words := stmtWords(fam, x)
	var rw renderedWords
	for _, e := range exp {
		rw = append(rw, stmtWords(fam, e))
	}
	for _, s := range keptShapes[fam] {
		pat := strings.Fields(s.Pattern)
		if len(words) < len(pat) {
			continue
		}
		name, ok := "", true
		for i, p := range pat {
			switch {
			case p == "$":
				name = words[i]
			case p != words[i]:
				ok = false
			}
		}
		if ok {
			return s.keep(name, words[:len(pat)], &rw)
		}
	}
	return false
}
