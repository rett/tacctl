package plan

// What the report says of the objects a scope's configuration block put in
// the rendering (0.2.7): a community or trap group of the SNMP block is
// named by its block, never by its string. The planner's behaviour for them
// is in junos.go (the rows with Block set); this is only words.

import (
	"strings"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// blockObjects are the labels (devconf.CommunityLabels) of the communities
// and trap groups the rendering took from a block, and the trap options
// leaves it sets. A nil *blockObjects is "no block".
type blockObjects struct {
	scope            string
	community, group map[string]bool
	options          map[string]bool
}

// blockObjectsOf reads the block statements of the rendering's snmp
// section; nil when it has none.
func blockObjectsOf(expected []devices.Section, scope string) *blockObjects {
	var sec devices.Section
	for _, s := range expected {
		if s.Name == devconf.SectionSNMP {
			sec = s
		}
	}
	any := false
	for _, b := range sec.Block {
		any = any || b
	}
	if !any {
		return nil
	}
	byLabel, _ := devconf.CommunityLabels(devconf.FamilyJunos, sec.Lines)
	labelOf := map[string]string{}
	for l, name := range byLabel {
		labelOf[name] = l
	}
	b := &blockObjects{scope: scope, community: map[string]bool{}, group: map[string]bool{}, options: map[string]bool{}}
	for i, line := range sec.Lines {
		if i >= len(sec.Block) || !sec.Block[i] {
			continue
		}
		t := splitTokens(strings.TrimSpace(line))
		if len(t) < 4 || t[0] != "set" || t[1] != "snmp" {
			continue
		}
		switch t[2] {
		case "community":
			b.community[labelOf[t[3]]] = true
		case "trap-group":
			b.group[labelOf[t[3]]] = true
		case "trap-options":
			b.options[t[3]] = true
		}
	}
	return b
}

// where names the block for the words of an item.
func (b *blockObjects) where() string {
	if b.scope == "" {
		return "the SNMP block of this scope"
	}
	return "the SNMP block of scope '" + b.scope + "'"
}

// kindOf is "community", "trap-group" or "trap-options" for a statement
// (without its 'set') that is a block's object, "" for any other.
func (b *blockObjects) kindOf(t []string) string {
	if b == nil || len(t) < 3 || t[0] != "snmp" {
		return ""
	}
	switch {
	case t[1] == "community" && b.community[t[2]]:
		return "community"
	case t[1] == "trap-group" && b.group[t[2]]:
		return "trap-group"
	case t[1] == "trap-options" && b.options[t[2]]:
		return "trap-options"
	}
	return ""
}

// words is a block statement of the comparison in the words of a technician:
// "" when it is not a block's.
func (b *blockObjects) words(stem string) string {
	t := splitTokens(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate "))
	rest := func(from int) string {
		if from >= len(t) {
			return ""
		}
		return strings.Join(t[from:], " ")
	}
	var w string
	switch b.kindOf(t) {
	case "community":
		w = "a community of " + b.where() + ": " + rest(3)
	case "trap-group":
		w = "a trap group of " + b.where() + ": " + rest(3)
	case "trap-options":
		w = "a trap option of " + b.where() + ": " + rest(2)
	default:
		return ""
	}
	if strings.HasPrefix(stem, "deactivate ") {
		w = "deactivated: " + w
	}
	return strings.TrimSuffix(w, ": ")
}

// object names the object a block statement is part of, for grouping (the
// key and label of objectOf): "" for another statement.
func (b *blockObjects) object(stem string) (key, label string) {
	t := splitTokens(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate "))
	switch b.kindOf(t) {
	case "community":
		return "block community", "a community of " + b.where()
	case "trap-group":
		return "block trap-group", "a trap group of " + b.where()
	}
	return "", ""
}
