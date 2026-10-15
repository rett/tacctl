package plan

// The Junos back-out (plan D108, D109; review H2): the set and delete lines
// that put the planned sections back to what the pull showed, computed
// from the statements the device had and the lines of the plan. It is its
// own region (Backout), never part of the output of the plan: a whole-output
// copy must not paste the undo.

import (
	"slices"
	"strings"
)

// junosBackout returns the back-out of the delta's lines, in the order to
// type them: the plan's lines undone last to first, then the term order.
func (p *planner) junosBackout(d Delta) []Line {
	var texts []string
	secret := map[string]bool{}
	for _, name := range d.order() {
		sec := p.cur.Sections[name]
		for i, l := range sec.Lines {
			for _, st := range ParseJunos(l).stmts {
				texts = append(texts, st.text())
				if i < len(sec.Secret) && sec.Secret[i] {
					secret[st.text()] = true
				}
			}
		}
	}
	before := ParseJunos(strings.Join(texts, "\n"))
	after := &JunosConfig{stmts: slices.Clone(before.stmts)}
	if err := after.Apply(d.Lines); err != nil {
		// a line the editor cannot apply: the back-out is not offered
		return nil
	}

	var out []Line
	seen := map[string]bool{}
	push := func(l Line) {
		k := string(l.Op) + " " + l.Text
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, l)
	}
	note := func(s string) { push(Line{Op: OpComment, Text: s}) }

	// restore types again every statement of the device that has the path as
	// its prefix.
	restore := func(path []string) bool {
		found := false
		for _, st := range before.stmts {
			if !pathHasPrefix(st.path, path) {
				continue
			}
			found = true
			text := "set " + joinTokens(st.path)
			switch {
			case st.head == "deactivate":
				note("it was deactivated, type yourself: deactivate " + joinTokens(st.path))
			case slices.ContainsFunc(st.path, isMark) || secret[st.text()]:
				note(againNote(st.path))
			default:
				push(Line{Op: OpSet, Text: text})
			}
		}
		return found
	}
	exists := func(path []string) bool {
		for _, st := range before.stmts {
			if pathHasPrefix(st.path, path) {
				return true
			}
		}
		return false
	}

	orderDone := false
	for i := len(d.Lines) - 1; i >= 0; i-- {
		l := d.Lines[i]
		t := splitTokens(l.Text)
		if len(t) < 2 || t[0] == "insert" {
			continue
		}
		path := t[1:]
		// lab is the same path with a community's or trap group's name as
		// the device's record shows it, its label: what the statements of the
		// pull are matched with (the text holds the name, which two of the
		// rendering's communities do not share).
		lab := path
		if l.Secret && l.Elided != "" {
			if et := splitTokens(l.Elided); len(et) == len(t) {
				lab = et[1:]
			}
		}
		if len(path) >= 5 && path[0] == "system" && path[1] == "ntp" && path[2] == "authentication-key" {
			// a key is known to the pull by its number alone (its type is not
			// compared and its value is not stored)
			lab = []string{path[0], path[1], path[2], path[3], "value"}
		}
		if strings.HasPrefix(strings.Join(path, " "), orderPrefix) {
			if orderDone {
				continue
			}
			orderDone = true
			if exists(strings.Fields(orderPrefix)) {
				push(Line{Op: OpDelete, Text: "delete " + orderPrefix})
				restore(strings.Fields(orderPrefix))
			} else {
				push(Line{Op: OpDelete, Text: "delete " + orderPrefix})
			}
			continue
		}
		switch t[0] {
		case "set":
			p.backoutSet(l, path, lab, before, secret, exists, push, note)
		case "delete":
			if !restore(lab) && l.Secret {
				// a leaf under a community whose name tacctl does not
				// hold: the device's own name is needed
				note("type again, with the community's own name: set " + strings.TrimPrefix(l.Elided, "delete "))
			}
		}
	}

	// the order of the terms: what the restored statements left, put back
	// the way the device had them
	sim := &JunosConfig{stmts: slices.Clone(after.stmts)}
	var applyable []Line
	for _, l := range out {
		if l.Op != OpComment {
			applyable = append(applyable, l)
		}
	}
	if err := sim.Apply(applyable); err != nil {
		return nil
	}
	for _, f := range termFilters(d.Lines) {
		want := termOrder(before.Statements(), f, true)
		cur := termOrder(sim.Statements(), f, true)
		if slices.Equal(want, cur) || len(want) != len(cur) {
			continue
		}
		for _, in := range termInserts("firewall family inet filter "+quoteTok(f)+" term ", want, cur) {
			push(in)
		}
	}
	return out
}

// backoutSet undoes one 'set' line of the plan.
func (p *planner) backoutSet(l Line, path, lab []string, before *JunosConfig, secret map[string]bool,
	exists func([]string) bool, push func(Line), note func(string)) {
	// a single-valued leaf: the device's value goes back
	if n := singleKeyLen(lab); n > 0 {
		for _, st := range before.stmts {
			if st.head == "set" && (len(st.path) == n+1 || len(st.path) == n && secret[st.text()]) && pathHasPrefix(st.path, lab[:n]) {
				if secret[st.text()] || slices.ContainsFunc(st.path, isMark) {
					note(againNote(st.path))
					return
				}
				if isMessagePath(st.path) {
					// the pull holds a digest of the login message, never
					// its text: it cannot be typed back from here
					note("the device had a login message that tacctl keeps no text of (" + st.path[3] +
						"): put it back with the rollback of the commit before this plan's, or type it yourself")
					return
				}
				push(Line{Op: OpSet, Text: "set " + joinTokens(st.path)})
				return
			}
		}
		// new: the object goes with it, or the leaf
		p.backoutDelete(l, path[:n], lab[:n], exists, push)
		return
	}
	if exists(lab) {
		if l.Secret {
			// the plan wrote over a value it does not hold; shown elided
			note(againNote(lab))
		}
		return
	}
	p.backoutDelete(l, path, lab, exists, push)
}

// backoutDelete removes what the plan added: the shallowest object the device
// did not have at all, else the statement's own path.
func (p *planner) backoutDelete(l Line, path, lab []string, exists func([]string) bool, push func(Line)) {
	n := len(path)
	for _, depth := range junosObjectDepths(lab) {
		if depth < len(lab) && !exists(lab[:depth]) {
			n = depth
			break
		}
	}
	// a list entry's flag ('restrict', 'except') is a node of its own:
	// deleting only the flag leaves the entry as a permit, which is right
	// when the device had the entry, and the whole entry goes otherwise
	if base := n; base > 1 && junosFlags[path[base-1]] {
		for base > 1 && junosFlags[path[base-1]] {
			base--
		}
		if !exists(lab[:base]) {
			n = base
		}
	}
	text := "delete " + joinTokens(path[:n])
	u := Line{Op: OpDelete, Text: text}
	if l.Secret && l.Elided != "" {
		// the community's name is the secret: so it is in this line too
		if slices.ContainsFunc(lab[:n], isMark) {
			u.Secret, u.HasValue = true, l.HasValue
			u.Elided = "delete " + joinTokens(lab[:n])
			if !l.HasValue {
				u.Text = placeholderOf(u.Elided)
			}
		}
	}
	push(u)
}

// againNote is the comment for a statement tacctl cannot type back: a
// secret's original value, or a community's own name. The path is elided.
func againNote(path []string) string {
	text := "set " + joinTokens(path)
	if slices.ContainsFunc(path, isMark) {
		return "type again, with the community's own name: " + text
	}
	return "type again with its original secret: " + text + " <secret>"
}

// pathHasPrefix reports whether a statement's path starts with the prefix. A
// community's name on the device is elided to its label and the prefix of a
// plan line holds the same label ('<secret:N>' for the rendering's N-th
// string, so two of the rendering's communities are never taken for each
// other, and a block's community is not the structured one), or the bare
// mark of an older record, which stands for any name of a community or trap
// group.
func pathHasPrefix(path, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i, w := range prefix {
		if path[i] == w {
			continue
		}
		named := i == 2 && len(path) > 2 && path[0] == "snmp" && (path[1] == "community" || path[1] == "trap-group")
		if named && (path[i] == secretMark || w == secretMark) {
			continue
		}
		return false
	}
	return true
}

// termFilters lists the filters (of family inet) the lines name a term of.
func termFilters(lines []Line) []string {
	var out []string
	for _, l := range lines {
		t := splitTokens(l.Text)
		if len(t) >= 8 && t[1] == "firewall" && t[2] == "family" && t[3] == "inet" && t[4] == "filter" && t[6] == "term" {
			if !slices.Contains(out, t[5]) {
				out = append(out, t[5])
			}
		}
	}
	return out
}
