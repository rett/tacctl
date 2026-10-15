package plan

// The Junos planner (plan §4, D79, D80, D97).

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devices"
)

// jrow is an ownership row with its pattern split and what the rendering of
// the section says about it.
type jrow struct {
	OwnedRow
	pat []string
	// names are the object names the rendering sets at the pattern's '$'.
	names map[string]bool
	// keys are, for a single-valued row, the statement keys the rendering
	// sets (the pattern's tokens with the name filled in).
	keys map[string]bool
	// kinds are the leaf keywords the rendering sets under each name (the
	// token after the pattern).
	kinds map[string]map[string]bool
	// has is whether the rendering has any statement under the pattern.
	has   bool
	fired bool
}

// junosRows builds the section's rows from the table and the rendering's raw
// lines.
func junosRows(section string, exp devices.Section) []*jrow {
	var rows []*jrow
	for _, r := range junosOwned {
		if r.Section != section {
			continue
		}
		rows = append(rows, &jrow{OwnedRow: r, pat: strings.Fields(r.Pattern),
			names: map[string]bool{}, keys: map[string]bool{}, kinds: map[string]map[string]bool{}})
	}
	for i, line := range exp.Lines {
		t := splitTokens(strings.TrimSpace(line))
		if len(t) < 2 || t[0] != "set" {
			continue
		}
		t = t[1:]
		// A statement of a configuration block is for the rows of blocks, one
		// of the structured settings for the others.
		fromBlock := i < len(exp.Block) && exp.Block[i]
		for _, r := range rows {
			if r.Block != fromBlock {
				continue
			}
			name, at, ok := matchPrefix(r.pat, t)
			if !ok {
				continue
			}
			r.has = true
			if at >= 0 {
				r.names[name] = true
			}
			if r.Mode == ModeSingle {
				r.keys[strings.Join(t[:len(r.pat)], " ")] = true
			}
			if len(t) > len(r.pat) {
				if r.kinds[name] == nil {
					r.kinds[name] = map[string]bool{}
				}
				r.kinds[name][t[len(r.pat)]] = true
			}
		}
	}
	return rows
}

// rowOf finds the row a statement path belongs to.
func rowOf(rows []*jrow, path []string) (*jrow, string) {
	for _, r := range rows {
		if name, _, ok := matchPrefix(r.pat, path); ok {
			return r, name
		}
	}
	return nil, ""
}

// The rows of a configuration block (owned.go: Block).
const (
	rowCommunity      = "junos.snmp.community"
	rowBlockCommunity = "junos.snmp.block-community"
	rowTrapGroup      = "junos.snmp.trap-group"
)

// rowFor is rowOf with the origin of a community: a statement under a
// community the rendering took from a block is the block row's, one under
// the structured settings' community the community row's. byLabel maps a
// community label to its string (devconf.CommunityLabels).
func rowFor(rows []*jrow, path []string, byLabel map[string]string) (*jrow, string) {
	r, name := rowOf(rows, path)
	if r != nil && r.ID == rowCommunity {
		if b := findRowByID(rows, rowBlockCommunity); b != nil && b.names[byLabel[name]] {
			return b, name
		}
	}
	return r, name
}

// namedBy is the string a community or trap group row's object is known by
// in the rendering: the label's string when the row has an object of that
// name, "" for the device's own.
func namedBy(row *jrow, label string, byLabel map[string]string) string {
	switch row.ID {
	case rowCommunity, rowBlockCommunity, rowTrapGroup:
		if s := byLabel[label]; s != "" && row.names[s] {
			return s
		}
	}
	return ""
}

// singleLeaf reports whether the leaf of a community or trap group takes one
// value (a set replaces the device's value in place), as against a list
// (clients, categories, targets) whose extra entries are removed one by one.
func singleLeaf(row *jrow, leaf string) bool {
	switch row.ID {
	case rowCommunity, rowBlockCommunity:
		return leaf == "authorization" || leaf == "client-list-name"
	case rowTrapGroup:
		return leaf == "version"
	}
	return false
}

// rawIndex maps a compared stem to the rendered lines that produced it, in
// order (a rendered line can stand for several statements).
type rawIndex map[string][]string

func junosRaw(vendor string, exp devices.Section) rawIndex {
	idx := rawIndex{}
	for i, line := range exp.Lines {
		mark := i < len(exp.Secret) && exp.Secret[i]
		stems, err := devconf.ElideIn(vendor, []string{line}, []bool{mark}, exp.Lines)
		if err != nil {
			continue
		}
		for _, s := range stems {
			idx[s] = append(idx[s], strings.TrimSpace(line))
		}
	}
	return idx
}

func (r rawIndex) pop(stem string) string {
	q := r[stem]
	if len(q) == 0 {
		return ""
	}
	r[stem] = q[1:]
	return q[0]
}

// jl is one line of a comparison, parsed.
type jl struct {
	op     byte
	stem   string
	secret bool
	path   []string
	deact  bool
}

func parseJunosLines(r devconf.SectionResult) []jl {
	var out []jl
	for _, l := range r.Lines {
		if l.Op == devconf.OpOrder || l.Op == devconf.OpInfo {
			continue
		}
		stem := stemOf(l)
		x := jl{op: l.Op, stem: stem, secret: l.Secret}
		rest := stem
		switch {
		case strings.HasPrefix(stem, "set "):
			rest = strings.TrimPrefix(stem, "set ")
		case strings.HasPrefix(stem, "deactivate "):
			rest, x.deact = strings.TrimPrefix(stem, "deactivate "), true
		}
		x.path = splitTokens(rest)
		out = append(out, x)
	}
	return out
}

const orderPrefix = "system authentication-order"

func (p *planner) junosSection(name string, r devconf.SectionResult) secOut {
	var o secOut
	exp := p.expected(name)
	if exp.Absent {
		return p.junosAbsent(name, r)
	}
	rows := junosRows(name, exp)
	raws := junosRaw(devconf.FamilyJunos, exp)
	ls := parseJunosLines(r)
	cls := p.opt.Class
	// A community's name is the secret: the comparison shows it as its label,
	// '<secret:N>' for the rendering's N-th string (communityOf has its
	// name; a block's follow the structured settings') and '<other:N>' for
	// one of the device's own.
	communityOf, _ := devconf.CommunityLabels(devconf.FamilyJunos, exp.Lines)

	// The class: what it cannot see is withheld (plan D97 as the lab check L1
	// corrected it: those hierarchies are not visible to the class).
	// DECISION: a section the class sees only in part (aaa for EN-CLASS: the
	// authentication order, not the server or the accounting) is planned for
	// the part it sees and its reason is a skip entry too; a section it sees
	// none of that has a change is left out whole with the reason.
	hiddenRules := map[string]ClassRule{}
	var live []jl
	for _, x := range ls {
		if ok, rule := cls.canSee(x.path); !ok {
			hiddenRules[rule.Prefix] = rule
			if x.op == devconf.OpMissing || x.op == devconf.OpExtra {
				o.withheld = append(o.withheld, displayStem(x))
			}
			continue
		}
		live = append(live, x)
	}
	if len(o.withheld) > 0 {
		prefixes := make([]string, 0, len(hiddenRules))
		for pfx := range hiddenRules {
			prefixes = append(prefixes, pfx)
		}
		slices.Sort(prefixes)
		var bits []string
		for _, pfx := range prefixes {
			bits = append(bits, "'"+pfx+"' ("+strings.Join(hiddenRules[pfx].Bits, ", ")+")")
		}
		why := "not visible to class " + cls.Name + ": " + strings.Join(bits, ", ")
		if !hasChange(live, p.opt.Secrets) {
			o.refused, o.refusedKind = why, KindClassSkip
			return o
		}
		o.partial = why
		o.skipped = append(o.skipped, Skip{name, KindClassSkip, why})
	}

	// The authentication order is rewritten whole when anything in its group
	// differs (D97: delete directly followed by the rendered set, never a bare
	// delete; the delete is left out when the device has no order at all).
	// [S: lab check L4: delete then set in one paste leaves the compare empty
	// for the same value]
	orderTouched := false
	orderSeen, _ := cls.canSee(strings.Fields(orderPrefix))
	for _, l := range r.Lines {
		if l.Op == devconf.OpOrder && strings.HasPrefix(l.Text, orderPrefix) && orderSeen {
			orderTouched = true
		}
	}
	for _, x := range live {
		if strings.HasPrefix(strings.Join(x.path, " "), orderPrefix) && (x.op == devconf.OpMissing || x.op == devconf.OpExtra) {
			orderTouched = true
		}
	}
	if findRowByID(rows, "junos.aaa.order") == nil {
		orderTouched = false
	}

	var sets, deletes, orderLines []Line
	var setKeyOf []string
	supersededBy := map[string][]string{}
	// addDelete adds a delete line once and says, on the line, which
	// statements of the comparison it answers.
	addDelete := func(l Line, stem string) {
		for i := range deletes {
			if deletes[i].Text == l.Text {
				deletes[i].For = append(deletes[i].For, stem)
				return
			}
		}
		l.For = []string{stem}
		deletes = append(deletes, l)
	}
	inheritedRefs := []string{}
	refuseInherited := func(stem string) {
		inheritedRefs = append(inheritedRefs, stem)
	}
	// entryRestrict is, per client entry of a block's community that the plan
	// sets, whether the set carries the restrict flag.
	entryRestrict := map[string]bool{}
	var kept []Kept
	var deacts []jl
	keepStem := func(stem, note string) {
		kept = append(kept, Kept{Section: name, Text: stem, Note: note})
	}
	fire := func(r *jrow) {
		if r != nil {
			r.fired = true
		}
	}

	// foldedBare maps an NTP server's path to the stem of its bare statement,
	// which the line of one of its options answers
	foldedBare := map[string]string{}
	// the set lines (and the by-value re-pushes), in rendered order
	setKeys := map[string]bool{}
	rawFor := map[int]string{}
	for i, x := range ls {
		if x.secret && (x.op == devconf.OpMissing || x.op == devconf.OpSame || x.op == devconf.OpNotVisible) ||
			x.op == devconf.OpMissing && isMessagePath(x.path) {
			rawFor[i] = raws.pop(x.stem)
		}
	}
	for i, x := range ls {
		if !slices.ContainsFunc(live, func(y jl) bool { return y.stem == x.stem && y.op == x.op }) {
			continue
		}
		inOrder := strings.HasPrefix(strings.Join(x.path, " "), orderPrefix)
		switch x.op {
		case devconf.OpMissing:
			if inOrder && orderTouched {
				continue
			}
			row, _ := rowFor(rows, x.path, communityOf)
			fire(row)
			if isBareNTPServer(x.path) && missingOptionOf(live, x.path) {
				// the server is created by the statement of its option: its
				// own line is not typed, and the option's line answers it
				foldedBare[strings.Join(x.path, " ")] = x.stem
				continue
			}
			skey := ""
			if row != nil && row.Mode == ModeSingle {
				skey = strings.Join(x.path[:len(row.pat)], " ")
				setKeys[skey] = true
			}
			if row != nil && len(x.path) > len(row.pat) && singleLeaf(row, x.path[len(row.pat)]) {
				// a single-valued leaf of a community or trap group
				// (authorization, client-list-name, version): its set
				// replaces the device's value in place
				skey = strings.Join(x.path[:len(row.pat)+1], " ")
				setKeys[skey] = true
			}
			if row != nil && row.ID == rowBlockCommunity && len(x.path) > 4 && x.path[3] == "clients" {
				// a client entry of a block's community: the set of an entry
				// the device has with another flag changes the flag in place,
				// and the device's entry is not removed beside it
				skey = strings.Join(x.path[:5], " ")
				setKeys[skey] = true
				entryRestrict[skey] = len(x.path) > 5
			}
			if row != nil && row.Mode == ModeRenderedLeaves && len(x.path) > len(row.pat) {
				// a leaf under tacctl's server is single-valued: its set
				// replaces the device's value, which is then not deleted
				skey = strings.Join(x.path[:len(row.pat)+1], " ")
				setKeys[skey] = true
			}
			sl := p.junosSetLine(x, rawFor[i])
			sl.For = []string{x.stem}
			if isMessagePath(x.path) && len(sl.Text) > blocks.MessageNoteChars {
				o.warnings = append(o.warnings, p.longMessageWarning(len(sl.Text)))
			}
			sets = append(sets, sl)
			setKeyOf = append(setKeyOf, skey)
		case devconf.OpSame, devconf.OpNotVisible:
			if !x.secret {
				continue
			}
			if p.opt.Secrets && (!inOrder || !orderTouched) {
				row, _ := rowFor(rows, x.path, communityOf)
				fire(row)
				sets = append(sets, p.junosSetLine(x, rawFor[i]))
				setKeyOf = append(setKeyOf, "")
				continue
			}
			if x.op == devconf.OpSame {
				o.presentSecrets++
			} else {
				o.hiddenSecrets++
			}
		}
	}

	// The authentication order: delete, then the rendered lines.
	if orderTouched {
		row := findRowByID(rows, "junos.aaa.order")
		fire(row)
		devHas := false
		for _, s := range p.cur.Sections[name].Lines {
			if strings.HasPrefix(strings.TrimPrefix(s, "set "), orderPrefix) {
				devHas = true
				if !p.inPlain(name, s) {
					refuseInherited(s)
				}
			}
		}
		if devHas {
			orderLines = append(orderLines, Line{Op: OpDelete, Text: "delete " + orderPrefix})
		}
		for _, raw := range exp.Lines {
			t := strings.TrimSpace(raw)
			if strings.HasPrefix(t, "set "+orderPrefix) && !slices.ContainsFunc(orderLines, func(l Line) bool { return l.Text == t }) {
				orderLines = append(orderLines, Line{Op: OpSet, Text: t})
			}
		}
		var forOrder []string
		for _, l := range r.Lines {
			if strings.HasPrefix(strings.TrimPrefix(l.Text, "set "), orderPrefix) && l.Op != devconf.OpSame {
				forOrder = append(forOrder, stemOf(l))
			}
		}
		for i := range orderLines {
			orderLines[i].For = forOrder
		}
	}

	// Extras.
	for _, x := range live {
		if x.op != devconf.OpExtra {
			continue
		}
		if x.deact {
			deacts = append(deacts, x)
			continue
		}
		if strings.HasPrefix(strings.Join(x.path, " "), orderPrefix) {
			if orderTouched {
				continue
			}
			keepStem(x.stem, "")
			continue
		}
		row, objName := rowFor(rows, x.path, communityOf)
		if row == nil {
			keepStem(x.stem, "")
			continue
		}
		// the string of a community or trap group the rendering names, ""
		// for the device's own
		community := namedBy(row, objName, communityOf)
		known := row.names[objName] || community != ""
		switch row.Mode {
		case ModeWhole:
			if objName == secretMark && (row.ID == rowCommunity || row.ID == rowTrapGroup && row.has) {
				// DECISION: a record of an older tacctl has every community's
				// name as one mark, so whose community a leaf is cannot be
				// told: nothing is emitted for it, it is listed as unattributed
				// and left alone until a pull labels it. A trap group is the
				// same once a block names one.
				o.unattributed = append(o.unattributed, x.stem)
				keepStem(x.stem, communityNotVisible)
				continue
			}
			if !known {
				keepStem(x.stem, "")
				continue
			}
			if community != "" {
				// A leaf of an object tacctl renders (its community, or a
				// community or trap group of a block): one of a kind that takes
				// one value is replaced in place by its set, any other (a
				// stray 'clients' leaf) is deleted under the object's own name,
				// as the standard asks. Of the structured settings' community
				// only the kinds it renders are owned; a block's object is
				// owned whole.
				key := strings.Join(x.path[:min(4, len(x.path))], " ")
				if setKeys[key] {
					if !p.inPlain(name, x.stem) {
						refuseInherited(x.stem)
					}
					supersededBy[key] = append(supersededBy[key], x.stem)
					continue
				}
				if row.ID == rowCommunity && len(x.path) > 3 && row.kinds[community][x.path[3]] {
					keepStem(x.stem, "")
					continue
				}
				flagOnly := false
				if row.ID == rowBlockCommunity && len(x.path) > 4 && x.path[3] == "clients" {
					k5 := strings.Join(x.path[:5], " ")
					if setKeys[k5] {
						// the block has this client entry with another flag
						if entryRestrict[k5] && len(x.path) == 5 {
							// the set adds the flag to the device's entry
							if !p.inPlain(name, x.stem) {
								refuseInherited(x.stem)
							}
							supersededBy[k5] = append(supersededBy[k5], x.stem)
							continue
						}
						// the device's entry has the flag, the block's has
						// not: only the flag goes, the entry stays as a permit
						flagOnly = len(x.path) > 5 && !entryRestrict[k5]
					}
				}
				if !p.inPlain(name, x.stem) {
					refuseInherited(x.stem)
					continue
				}
				fire(row)
				addDelete(p.objectDelete(x.path[1], community, objName, x.path[3:], flagOnly), x.stem)
				continue
			}
			if !p.inPlain(name, x.stem) {
				refuseInherited(x.stem)
				continue
			}
			fire(row)
			if row.ID == "junos.mgmt-acl.filter" && len(x.path) >= 7 && x.path[5] == "term" {
				termKnown := p.renderedTerm(exp, objName, x.path[6])
				if !termKnown {
					text := "delete " + joinTokens(x.path[:7])
					addDelete(Line{Op: OpDelete, Text: text}, x.stem)
					continue
				}
			}
			text := junosDeleteText(x.path)
			{
				l := Line{Op: OpDelete, Text: text}
				if x.secret {
					l.Secret, l.Elided = true, text
				}
				addDelete(l, x.stem)
			}
		case ModeLeaves:
			if !row.has || row.Depth != 0 && len(x.path) != row.Depth {
				// 'system accounting destination <protocol>' is tacctl's;
				// 'destination <protocol> server <addr> ...' is another
				// server's, left as it is
				keepStem(x.stem, "")
				continue
			}
			if !p.inPlain(name, x.stem) {
				refuseInherited(x.stem)
				continue
			}
			fire(row)
			text := junosDeleteText(x.path)
			addDelete(Line{Op: OpDelete, Text: text}, x.stem)
		case ModeRenderedLeaves:
			kind := ""
			if len(x.path) > len(row.pat) {
				kind = x.path[len(row.pat)]
			}
			if !known || !row.kinds[objName][kind] {
				keepStem(x.stem, "")
				continue
			}
			if !p.inPlain(name, x.stem) {
				refuseInherited(x.stem)
				continue
			}
			if x.secret || kind != "" && setKeys[strings.Join(x.path[:len(row.pat)+1], " ")] {
				// single-valued: the rendered set replaces the value in place
				if kind != "" {
					k := strings.Join(x.path[:len(row.pat)+1], " ")
					supersededBy[k] = append(supersededBy[k], x.stem)
				}
				continue
			}
			fire(row)
			text := junosDeleteText(x.path)
			addDelete(Line{Op: OpDelete, Text: text}, x.stem)
		case ModeSingle:
			key := strings.Join(x.path[:min(len(row.pat), len(x.path))], " ")
			if row.ID == "junos.roles.user-class" {
				// the name sits inside the pattern: key is the user's class
				// leaf; owned only for a rendered template user
				if !known {
					keepStem(x.stem, "")
					continue
				}
			}
			if setKeys[key] {
				if !p.inPlain(name, x.stem) {
					refuseInherited(x.stem)
				}
				supersededBy[key] = append(supersededBy[key], x.stem)
				continue // replaced in place by its set
			}
			keepStem(x.stem, "")
		case ModeList, ModeAdditive:
			keepStem(x.stem, "")
		}
	}

	// Deactivated statements. DECISION: one that a delete of the plan takes
	// away is not listed; one that is tacctl's own (a rendered statement or
	// an object it renders: its server, its term) is a finding with the
	// 'activate' line shown and never emitted; any other is left as it is.
	for _, x := range deacts {
		covered := false
		for _, dl := range deletes {
			dt := splitTokens(dl.Text)
			if len(dt) > 1 && len(x.path) >= len(dt)-1 && slices.Equal(x.path[:len(dt)-1], dt[1:]) {
				covered = true
			}
		}
		if covered {
			continue
		}
		if p.renderedPrefix(exp, x.path) {
			act := "activate " + joinTokens(x.path)
			o.warnings = append(o.warnings, "'"+strings.TrimPrefix(x.stem, "deactivate ")+"' is deactivated on the device, so tacctl's statement is not live: type '"+act+"' yourself, it is never part of the block")
			keepStem(x.stem, "deactivated; to make it live type: "+act)
			continue
		}
		keepStem(x.stem, "deactivated: left as it is")
	}

	// The terms of the rendered filter, in the rendered order.
	var inserts []Line
	if name == "mgmt-acl" {
		inserts = p.junosTermOrder(exp, rows, deletes)
		if len(inserts) > 0 {
			fire(findRowByID(rows, "junos.mgmt-acl.filter"))
		}
	}

	// The lo0 checks of D97.
	if name == "mgmt-acl" && (len(sets)+len(deletes)+len(inserts)+len(orderLines) > 0) {
		if msg, warn := p.lo0Check(exp, rows); msg != "" {
			if warn {
				o.warnings = append(o.warnings, msg)
			} else {
				o.refused = msg
				return o
			}
		}
	}

	// DECISION: a statement that would have to change and comes from a group
	// refuses the whole section (a half-applied interdependent section is
	// worse than none), named with the statements; the rest of the block
	// stands (D97).
	if len(inheritedRefs) > 0 {
		o.inherited = inheritedRefs
		o.refused = "inherited from a group: change the group by hand (" + strings.Join(dedupe(inheritedRefs), "; ") + ")"
		o.kept = kept
		return o
	}

	for i := range sets {
		if k := setKeyOf[i]; k != "" {
			sets[i].For = append(sets[i].For, supersededBy[k]...)
		}
		if t := splitTokens(sets[i].Text); len(t) >= 6 && t[1] == "system" && t[2] == "ntp" && t[3] == "server" {
			k := strings.Join(t[1:5], " ")
			if stem, ok := foldedBare[k]; ok {
				sets[i].For = append(sets[i].For, stem)
				delete(foldedBare, k)
			}
		}
	}
	for i := range inserts {
		for _, l := range r.Lines {
			if l.Op == devconf.OpOrder && strings.HasPrefix(l.Text, "firewall family inet filter") {
				inserts[i].For = append(inserts[i].For, l.Text)
			}
		}
	}
	o.lines = append(o.lines, orderLines...)
	o.lines = append(o.lines, sets...)
	o.lines = append(o.lines, deletes...)
	o.lines = append(o.lines, inserts...)
	o.kept = kept
	for _, row := range rows {
		if row.fired {
			if w := strings.ReplaceAll(row.Why, "<scope>", p.blockScope()); !slices.Contains(o.why, w) {
				o.why = append(o.why, w)
			}
		}
	}
	return o
}

// blockScope names the scope whose block a row's reason speaks of.
func (p *planner) blockScope() string {
	if p.opt.Scope != "" {
		return "'" + p.opt.Scope + "'"
	}
	return "this scope"
}

// isBareNTPServer reports the path of a bare 'system ntp server <host>'
// statement.
func isBareNTPServer(path []string) bool {
	return len(path) == 4 && path[0] == "system" && path[1] == "ntp" && path[2] == "server"
}

// missingOptionOf reports whether a statement of the comparison, missing on
// the device, is an option of the server the path names.
func missingOptionOf(ls []jl, server []string) bool {
	return slices.ContainsFunc(ls, func(x jl) bool {
		return x.op == devconf.OpMissing && len(x.path) > 4 && slices.Equal(x.path[:4], server)
	})
}

// isMessagePath reports the path of the login message statement ('system
// login message <mark>').
func isMessagePath(path []string) bool {
	return len(path) == 4 && path[0] == "system" && path[1] == "login" && path[2] == "message"
}

// longMessageWarning is the warning of a login message statement that a
// person pasting it as one line into an interactive terminal would have cut
// (a terminal in canonical mode truncates a line at 1,023 characters). The
// statement itself is emitted whole; nothing of the message is in the words.
func (p *planner) longMessageWarning(n int) string {
	name := p.opt.Device
	if name == "" {
		name = "<name>"
	}
	return "the login message statement is " + strconv.Itoa(n) + " characters on one line, and a line over 1,023 characters pasted into an interactive terminal is truncated: " +
		"use `tacctl device config plan " + name + " --plain` (the statements for 'load set', through a file) for it"
}

// displayStem is a statement as shown (a secret's value is never in it).
func displayStem(x jl) string {
	if x.secret {
		return shownSecret(x.stem)
	}
	return x.stem
}

// junosFlags are the trailing words of a list entry that are flags of the
// entry, not nodes of their own: 'delete ... 0.0.0.0/0 restrict' would remove
// the flag and leave the entry as a permit.
var junosFlags = map[string]bool{"restrict": true, "except": true}

// junosDeleteText is the delete line of a statement: the entry's key, with a
// trailing flag (restrict, except) left off so the whole entry goes.
func junosDeleteText(path []string) string {
	for len(path) > 1 && junosFlags[path[len(path)-1]] {
		path = path[:len(path)-1]
	}
	return "delete " + joinTokens(path)
}

// renderedPrefix reports whether the path is a prefix of a statement the
// rendering holds (or equal to one).
func (p *planner) renderedPrefix(exp devices.Section, path []string) bool {
	for _, raw := range exp.Lines {
		t := splitTokens(raw)
		if len(t) > len(path) && t[0] == "set" && slices.Equal(t[1:len(path)+1], path) {
			return true
		}
	}
	return false
}

// communityNotVisible is why a leaf under a community of an older record is
// left alone.
const communityNotVisible = "the community's name is not visible"

// objectDelete is the delete of a leaf under a community or trap group the
// rendering names (kind is community or trap-group): its text holds the
// object's name, a secret; the line shows its label. A trailing flag of a
// client entry ('restrict') goes with the entry, unless flagOnly says the
// device's entry is to stay and lose the flag.
func (p *planner) objectDelete(kind, name, label string, rest []string, flagOnly bool) Line {
	for len(rest) > 1 && junosFlags[rest[len(rest)-1]] && !flagOnly {
		rest = rest[:len(rest)-1]
	}
	shown := "delete " + joinTokens(append([]string{"snmp", kind, label}, rest...))
	text := "delete " + joinTokens(append([]string{"snmp", kind, name}, rest...))
	if p.opt.NoSecrets {
		return Line{Op: OpDelete, Text: placeholderOf(shown), Secret: true, Elided: shown}
	}
	return Line{Op: OpDelete, Text: text, Secret: true, HasValue: true, Elided: shown}
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func hasChange(ls []jl, secrets bool) bool {
	for _, x := range ls {
		switch x.op {
		case devconf.OpMissing, devconf.OpExtra:
			return true
		case devconf.OpSame, devconf.OpNotVisible:
			if secrets && x.secret {
				return true
			}
		}
	}
	return false
}

func findRowByID(rows []*jrow, id string) *jrow {
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	return nil
}

// junosSetLine is the set line of a statement the plan emits: the stem for
// an ordinary one, the rendered line for a secret (its value), a placeholder
// under --no-secrets.
func (p *planner) junosSetLine(x jl, raw string) Line {
	if !x.secret && isMessagePath(x.path) && raw != "" {
		// the login message: the stem holds its mark, the line the rendered
		// statement, which is what the block says
		return Line{Op: OpSet, Text: raw}
	}
	if !x.secret {
		return Line{Op: OpSet, Text: x.stem}
	}
	shown := shownSecret(x.stem)
	if p.opt.NoSecrets || raw == "" {
		return Line{Op: OpSet, Text: placeholderOf(x.stem), Secret: true, Elided: shown}
	}
	return Line{Op: OpSet, Text: raw, Secret: true, HasValue: true, Elided: shown}
}

// renderedTerm reports whether the rendering has a term of the filter.
func (p *planner) renderedTerm(exp devices.Section, filter, term string) bool {
	for _, raw := range exp.Lines {
		t := splitTokens(raw)
		if len(t) >= 8 && t[0] == "set" && t[1] == "firewall" && t[4] == "filter" && t[5] == filter && t[6] == "term" && t[7] == term {
			return true
		}
	}
	return false
}

// termOrder lists a filter's terms in the order their statements first
// appear.
func termOrder(stmts []string, filter string, set bool) []string {
	var out []string
	for _, s := range stmts {
		t := splitTokens(s)
		if set {
			// a deactivated term is a statement of the hierarchy to the
			// comparison, and holds its place among the terms
			if len(t) == 0 || t[0] != "set" && t[0] != "deactivate" {
				continue
			}
			t = t[1:]
		}
		if len(t) >= 7 && t[0] == "firewall" && t[1] == "family" && t[3] == "filter" && t[4] == filter && t[5] == "term" {
			if !slices.Contains(out, t[6]) {
				out = append(out, t[6])
			}
		}
	}
	return out
}

// junosTermOrder returns the insert lines that put the rendered filter's
// terms in the rendered order after the sets and deletes of the plan: a new
// term lands last, an extra term is deleted, the rest is moved one insert per
// term that is not where it belongs. [S: lab check L4: 'insert ... after term
// A' and 'before term A' as pasted lines.] DECISION: the first term uses
// 'before term <current first>', every other 'after term <previous rendered>'.
func (p *planner) junosTermOrder(exp devices.Section, rows []*jrow, deletes []Line) []Line {
	row := findRowByID(rows, "junos.mgmt-acl.filter")
	if row == nil {
		return nil
	}
	var out []Line
	filters := make([]string, 0, len(row.names))
	for f := range row.names {
		filters = append(filters, f)
	}
	slices.Sort(filters)
	for _, filter := range filters {
		want := termOrder(exp.Lines, filter, true)
		dev := termOrder(p.cur.Sections["mgmt-acl"].Lines, filter, true)
		var cur []string
		for _, t := range dev {
			if slices.Contains(want, t) {
				cur = append(cur, t)
			}
		}
		for _, t := range want {
			if !slices.Contains(cur, t) {
				cur = append(cur, t)
			}
		}
		out = append(out, termInserts("firewall family inet filter "+quoteTok(filter)+" term ", want, cur)...)
	}
	return out
}

// termInserts returns the insert lines that take the terms from the order
// cur to the order want (the same terms): a term that is not where it
// belongs is moved with one insert, the first one 'before term <current
// first>', every other 'after term <previous wanted>'.
func termInserts(prefix string, want, cur []string) []Line {
	var out []Line
	cur = slices.Clone(cur)
	for i, t := range want {
		if i < len(cur) && cur[i] == t {
			continue
		}
		j := slices.Index(cur, t)
		if j < 0 {
			continue
		}
		cur = slices.Delete(cur, j, j+1)
		if i == 0 {
			out = append(out, Line{Op: OpInsert, Text: "insert " + prefix + quoteTok(t) + " before term " + quoteTok(cur[0])})
			cur = slices.Insert(cur, 0, t)
		} else {
			out = append(out, Line{Op: OpInsert, Text: "insert " + prefix + quoteTok(t) + " after term " + quoteTok(want[i-1])})
			at := slices.Index(cur, want[i-1])
			cur = slices.Insert(cur, at+1, t)
		}
	}
	return out
}

// lo0Check applies D97's filter checks. It returns a message and whether it
// is a warning (true) or a refusal (false).
func (p *planner) lo0Check(exp devices.Section, rows []*jrow) (string, bool) {
	row := findRowByID(rows, "junos.mgmt-acl.filter")
	if row == nil {
		return "", false
	}
	applied := false
	for _, s := range p.cur.Sections["mgmt-acl"].Lines {
		t := splitTokens(strings.TrimPrefix(s, "set "))
		if len(t) >= 7 && t[0] == "interfaces" && t[1] == "lo0" {
			if i := slices.Index(t, "filter"); i >= 0 {
				for _, n := range t[i+1:] {
					if row.names[n] {
						applied = true
					}
				}
			}
		}
	}
	if !applied {
		return "", false
	}
	if p.opt.From == "" {
		return "the management filter is applied on lo0 and --from was not given: check that the address you are logged in from is inside a permit-mgmt source before you paste (--from <address> makes tacctl check)", true
	}
	from, err := netip.ParseAddr(p.opt.From)
	if err != nil {
		return "--from " + p.opt.From + " is not an address", false
	}
	if from.Is6() && !from.Is4In6() {
		// the rendered filter is family inet: nothing to check an IPv6
		// address against, and it is not a reason to refuse
		return "--from " + p.opt.From + " is an IPv6 address and the management filter is family inet: not checked; make sure you reach the device from an address the filter permits", true
	}
	for _, raw := range exp.Lines {
		t := splitTokens(raw)
		if len(t) < 10 || t[0] != "set" || t[1] != "firewall" || t[4] != "filter" || t[6] != "term" || t[7] != "permit-mgmt" {
			continue
		}
		i := slices.Index(t, "source-address")
		if i < 0 {
			continue
		}
		for _, c := range t[i+1:] {
			if c == "[" || c == "]" {
				continue
			}
			if pf, err := netip.ParsePrefix(c); err == nil && pf.Contains(from) {
				return "", false
			}
			if a, err := netip.ParseAddr(c); err == nil && a == from {
				return "", false
			}
			if c != "[" && !strings.Contains(c, "/") && !strings.Contains(c, ".") && !strings.Contains(c, ":") {
				break
			}
		}
	}
	return fmt.Sprintf("the management filter is applied on lo0 and %s is not inside a permit-mgmt source of the rendered filter: pasting it could cut you off", p.opt.From), false
}
