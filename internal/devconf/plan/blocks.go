package plan

// What the report says of the objects a scope's configuration block put in
// the rendering (0.2.7): a community, trap group, access list or trap host of
// the SNMP block is named by its block, never by its string. The planner's
// behaviour for them is in junos.go and ios.go (the rows with Block set);
// this is only words.

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
	// ios is set for an IOS rendering: acl holds the names of the access
	// lists the block defines, host its trap hosts (SNMPHostID: address, vrf,
	// kind, udp-port and community label) and traps its 'enable traps' lines (the compared text).
	ios   bool
	acl   map[string]bool
	host  map[string]bool
	traps map[string]bool
	// trapSource is set when the block states the trap source.
	trapSource bool
}

// blockObjectsOf reads the block statements of the rendering's snmp
// section; nil when it has none.
func blockObjectsOf(fam string, expected []devices.Section, scope string) *blockObjects {
	if fam == devconf.FamilyIOS {
		return blockObjectsOfIOS(expected, scope)
	}
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

// blockObjectsOfIOS is blockObjectsOf for an IOS rendering: the lines of
// the snmp section the block put there (an access list's header and its
// entries, a community, a trap host, an 'enable traps' line).
func blockObjectsOfIOS(expected []devices.Section, scope string) *blockObjects {
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
	byLabel, _ := devconf.CommunityLabels(devconf.FamilyIOS, sec.Lines)
	labelOf := map[string]string{}
	for l, name := range byLabel {
		labelOf[name] = l
	}
	b := &blockObjects{scope: scope, ios: true, community: map[string]bool{}, acl: map[string]bool{},
		host: map[string]bool{}, traps: map[string]bool{}}
	for i, line := range sec.Lines {
		if i >= len(sec.Block) || !sec.Block[i] {
			continue
		}
		f := strings.Fields(line)
		switch {
		case len(f) >= 4 && f[0] == "ip" && f[1] == "access-list" && f[2] == "standard":
			b.acl[f[3]] = true
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community":
			b.community[labelOf[f[2]]] = true
		case devconf.SNMPHostCommunity(f) > 0:
			i := devconf.SNMPHostCommunity(f)
			b.host[devconf.SNMPHostID(f, i, labelOf[f[i]])] = true
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "enable" && f[2] == "traps":
			b.traps[strings.Join(f, " ")] = true
		case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "trap-source":
			b.trapSource = true
		}
	}
	return b
}

// iosKind is "community", "acl", "host" or "traps" for a compared IOS
// statement (its path joined with ' > ') that is a block's object, "" for
// any other; name is the list's name for an entry.
func (b *blockObjects) iosKind(stem string) (kind, name string) {
	if b == nil || !b.ios {
		return "", ""
	}
	path := strings.Split(stem, pathSep)
	f := strings.Fields(path[len(path)-1])
	if len(path) == 2 {
		if h := strings.Fields(path[0]); len(h) >= 4 && h[0] == "ip" && h[1] == "access-list" && h[2] == "standard" && b.acl[h[3]] {
			return "acl", h[3]
		}
		return "", ""
	}
	switch {
	case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "community" && b.community[f[2]]:
		return "community", ""
	case devconf.SNMPHostCommunity(f) > 0 && b.host[devconf.SNMPHostID(f, devconf.SNMPHostCommunity(f), f[devconf.SNMPHostCommunity(f)])]:
		return "host", ""
	case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "enable" && f[2] == "traps" && b.traps[strings.Join(f, " ")]:
		return "traps", ""
	case len(f) >= 3 && f[0] == "snmp-server" && f[1] == "trap-source" && b.trapSource:
		return "trap-source", ""
	}
	return "", ""
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
	if b.ios {
		return b.iosWords(stem)
	}
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

// iosWords is words for an IOS statement.
func (b *blockObjects) iosWords(stem string) string {
	kind, name := b.iosKind(stem)
	path := strings.Split(stem, pathSep)
	leaf := path[len(path)-1]
	f := strings.Fields(leaf)
	rest := func(from int) string {
		if from >= len(f) {
			return ""
		}
		return strings.Join(f[from:], " ")
	}
	var w string
	switch kind {
	case "community":
		w = "a community of " + b.where() + ": " + rest(3)
	case "acl":
		w = "access list " + name + " of " + b.where() + ": " + leaf
	case "host":
		w = "a trap host of " + b.where() + ": " + rest(2)
	case "traps":
		w = "an 'enable traps' line of " + b.where() + ": " + rest(3)
	case "trap-source":
		w = "the trap source of " + b.where() + ": " + rest(2)
	default:
		return ""
	}
	return strings.TrimSuffix(w, ": ")
}

// object names the object a block statement is part of, for grouping (the
// key and label of objectOf): "" for another statement.
func (b *blockObjects) object(stem string) (key, label string) {
	if b.ios {
		if kind, name := b.iosKind(stem); kind == "acl" {
			return "block access list " + name, "access list " + name + " of " + b.where()
		}
		return "", ""
	}
	t := splitTokens(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate "))
	switch b.kindOf(t) {
	case "community":
		return "block community", "a community of " + b.where()
	case "trap-group":
		return "block trap-group", "a trap group of " + b.where()
	}
	return "", ""
}
