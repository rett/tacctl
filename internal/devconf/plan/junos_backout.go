package plan

// The Junos back-out (plan D108, D109; review H2): the set and delete lines
// that put the planned sections back to what the pull showed, computed
// from the statements the device had and the lines of the plan. It is its
// own region (Backout), never part of the output of the plan: a whole-output
// copy must not paste the undo.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// junosBackout returns the back-out of the delta's lines, in the order to
// type them: the plan's lines undone last to first, then the term order.
func (p *planner) junosBackout(d Delta) []Line {
	var texts []string
	secret := map[string]bool{}
	for _, name := range PlanOrder(devconf.FamilyJunos) {
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
			case slices.Contains(st.path, secretMark) || secret[st.text()]:
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
			p.backoutSet(l, path, before, secret, exists, push, note)
		case "delete":
			if !restore(path) && l.Secret {
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
func (p *planner) backoutSet(l Line, path []string, before *JunosConfig, secret map[string]bool,
	exists func([]string) bool, push func(Line), note func(string)) {
	// a single-valued leaf: the device's value goes back
	if n := singleKeyLen(path); n > 0 {
		for _, st := range before.stmts {
			if st.head == "set" && (len(st.path) == n+1 || len(st.path) == n && secret[st.text()]) && pathHasPrefix(st.path, path[:n]) {
				if secret[st.text()] || slices.Contains(st.path, secretMark) {
					note(againNote(st.path))
					return
				}
				push(Line{Op: OpSet, Text: "set " + joinTokens(st.path)})
				return
			}
		}
		// new: the object goes with it, or the leaf
		p.backoutDelete(l, path[:n], exists, push)
		return
	}
	if exists(path) {
		if l.Secret {
			// the plan wrote over a value it does not hold; shown elided
			ep := path
			if l.Elided != "" {
				ep = splitTokens(strings.TrimPrefix(l.Elided, "set "))
			}
			note(againNote(ep))
		}
		return
	}
	p.backoutDelete(l, path, exists, push)
}

// backoutDelete removes what the plan added: the shallowest object the device
// did not have at all, else the statement's own path.
func (p *planner) backoutDelete(l Line, path []string, exists func([]string) bool, push func(Line)) {
	del := path
	for _, depth := range junosObjectDepths(path) {
		if depth < len(path) && !exists(path[:depth]) {
			del = path[:depth]
			break
		}
	}
	// a list entry's flag ('restrict', 'except') is a node of its own:
	// deleting only the flag leaves the entry as a permit, which is right
	// when the device had the entry, and the whole entry goes otherwise
	if base := del; len(base) > 1 && junosFlags[base[len(base)-1]] {
		for len(base) > 1 && junosFlags[base[len(base)-1]] {
			base = base[:len(base)-1]
		}
		if !exists(base) {
			del = base
		}
	}
	text := "delete " + joinTokens(del)
	u := Line{Op: OpDelete, Text: text}
	if l.Secret && l.Elided != "" {
		// the community's name is the secret: so it is in this line too
		if et := splitTokens(strings.TrimPrefix(l.Elided, "set ")); len(et) >= len(del) &&
			slices.Contains(et[:len(del)], secretMark) {
			u.Secret, u.HasValue = true, l.HasValue
			u.Elided = "delete " + joinTokens(et[:len(del)])
			if !l.HasValue {
				u.Text = strings.ReplaceAll(u.Elided, secretMark, "<SECRET>")
			}
		}
	}
	push(u)
}

// againNote is the comment for a statement tacctl cannot type back: a
// secret's original value, or a community's own name. The path is elided.
func againNote(path []string) string {
	text := "set " + joinTokens(path)
	if slices.Contains(path, secretMark) {
		return "type again, with the community's own name: " + text
	}
	return "type again with its original secret: " + text + " <secret>"
}

// pathHasPrefix reports whether a statement's path starts with the prefix; a
// community's name on the device is elided to the secret mark, which stands
// for any name.
func pathHasPrefix(path, prefix []string) bool {
	if len(path) < len(prefix) {
		return false
	}
	for i, w := range prefix {
		if path[i] != w && path[i] != secretMark {
			return false
		}
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
