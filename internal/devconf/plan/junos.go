package plan

// The Junos planner (plan §4, D79, D80, D97).

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

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
	for _, line := range exp.Lines {
		t := splitTokens(strings.TrimSpace(line))
		if len(t) < 2 || t[0] != "set" {
			continue
		}
		t = t[1:]
		for _, r := range rows {
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
	rows := junosRows(name, exp)
	raws := junosRaw(devconf.FamilyJunos, exp)
	ls := parseJunosLines(r)
	cls := p.opt.Class

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

	// the set lines (and the by-value re-pushes), in rendered order
	setKeys := map[string]bool{}
	rawFor := map[int]string{}
	for i, x := range ls {
		if x.secret && (x.op == devconf.OpMissing || x.op == devconf.OpSame || x.op == devconf.OpNotVisible) {
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
			row, _ := rowOf(rows, x.path)
			fire(row)
			skey := ""
			if row != nil && row.Mode == ModeSingle {
				skey = strings.Join(x.path[:len(row.pat)], " ")
				setKeys[skey] = true
			}
			if row != nil && row.ID == "junos.snmp.community" && len(x.path) > len(row.pat) {
				// a leaf of the community tacctl renders is single-valued
				// (authorization, client-list-name): its set replaces the
				// device's value in place
				skey = strings.Join(x.path[:len(row.pat)+1], " ")
				setKeys[skey] = true
			}
			if row != nil && row.Mode == ModeRenderedLeaves && len(x.path) > len(row.pat) {
				// a leaf under tacctl's server is single-valued: its set
				// replaces the device's value, which is then not deleted
				skey = strings.Join(x.path[:len(row.pat)+1], " ")
				setKeys[skey] = true
			}
			sl := p.junosSetLine(x, rawFor[i])
			sl.For = []string{x.stem}
			sets = append(sets, sl)
			setKeyOf = append(setKeyOf, skey)
		case devconf.OpSame, devconf.OpNotVisible:
			if !x.secret {
				continue
			}
			if p.opt.Secrets && (!inOrder || !orderTouched) {
				row, _ := rowOf(rows, x.path)
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

	// Extras. A community's name is the secret: the comparison shows it as
	// its label, '<secret:N>' for the rendering's N-th community (communityOf
	// has its name) and '<other:N>' for one of the device's own.
	communityOf, _ := devconf.CommunityLabels(devconf.FamilyJunos, exp.Lines)
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
		row, objName := rowOf(rows, x.path)
		if row == nil {
			keepStem(x.stem, "")
			continue
		}
		community := ""
		if row.ID == "junos.snmp.community" {
			community = communityOf[objName]
		}
		known := row.names[objName] || community != ""
		switch row.Mode {
		case ModeWhole:
			if row.ID == "junos.snmp.community" && objName == secretMark {
				// DECISION: a record of an older tacctl has every community's
				// name as one mark, so whose community a leaf is cannot be
				// told: nothing is emitted for it, it is listed as unattributed
				// and left alone until a pull labels it.
				o.unattributed = append(o.unattributed, x.stem)
				keepStem(x.stem, communityNotVisible)
				continue
			}
			if !known {
				keepStem(x.stem, "")
				continue
			}
			if community != "" {
				// A leaf of tacctl's own community: one of a kind tacctl
				// renders is replaced in place by its set, any other (a
				// stray 'clients' leaf) is deleted under the community's
				// own name, as the standard asks.
				key := strings.Join(x.path[:min(4, len(x.path))], " ")
				if setKeys[key] {
					if !p.inPlain(name, x.stem) {
						refuseInherited(x.stem)
					}
					supersededBy[key] = append(supersededBy[key], x.stem)
					continue
				}
				if len(x.path) > 3 && row.kinds[community][x.path[3]] {
					keepStem(x.stem, "")
					continue
				}
				if !p.inPlain(name, x.stem) {
					refuseInherited(x.stem)
					continue
				}
				fire(row)
				addDelete(p.communityDelete(community, objName, x.path[3:]), x.stem)
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
		case ModeList:
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
			o.why = append(o.why, row.Why)
		}
	}
	return o
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

// communityDelete is the delete of a leaf under a rendered community: its
// text holds the community's name, a secret; the line shows its label.
func (p *planner) communityDelete(community, label string, rest []string) Line {
	for len(rest) > 1 && junosFlags[rest[len(rest)-1]] {
		rest = rest[:len(rest)-1]
	}
	shown := "delete " + joinTokens(append([]string{"snmp", "community", label}, rest...))
	text := "delete " + joinTokens(append([]string{"snmp", "community", community}, rest...))
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
