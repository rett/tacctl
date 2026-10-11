package plan

// The irregularity report (plan D110): per device, above the region, in the
// words of a junior technician, one item per finding of the comparison with
// its severity and what the paste does about it; and the cover page of
// several devices.

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/devconf"
)

// buildItems turns the comparison into the report's items, linked to the
// lines of the plan by the statements each line answers (Line.For).
func (p *planner) buildItems(d *Delta, byName map[string]devconf.SectionResult) {
	answers := map[string][]int{}
	for i, l := range d.Lines {
		for _, s := range l.For {
			k := l.Section + "|" + s
			if !slices.Contains(answers[k], i) {
				answers[k] = append(answers[k], i)
			}
		}
	}
	extraOf := map[string]Extra{}
	for _, e := range d.Extras {
		extraOf[e.Section+"|"+e.Text] = e
	}
	for _, name := range PlanOrder(d.Vendor) {
		sp := d.Of(name)
		if sp.State == StateNotSelected || sp.State == StateNA {
			continue
		}
		r := byName[name]
		// the '+' statements a line fixes together with a '-' are one
		// finding ("different"), listed once
		plus := map[string]bool{}
		for _, l := range r.Lines {
			if l.Op == devconf.OpExtra {
				plus[stemOf(l)] = true
			}
		}
		merged := map[string]bool{}
		for _, l := range r.Lines {
			if l.Op != devconf.OpMissing {
				continue
			}
			for _, i := range answers[name+"|"+stemOf(l)] {
				for _, s := range d.Lines[i].For {
					if s != stemOf(l) && plus[s] {
						merged[s] = true
					}
				}
			}
		}
		var seenLineSets []string
		for _, l := range r.Lines {
			stem := stemOf(l)
			var kind string
			switch l.Op {
			case devconf.OpMissing:
				kind = KindMissing
			case devconf.OpExtra:
				kind = KindExtra
				if merged[stem] {
					continue
				}
			case devconf.OpOrder:
				kind = KindOrder
				stem = l.Text
			case devconf.OpNotVisible:
				kind = KindSecret
			default:
				continue
			}
			it := Item{Kind: kind, Section: name, Statement: stem}
			if l.Secret {
				it.Statement = shownSecret(stem)
			}
			it.Lines = slices.Clone(answers[name+"|"+stem])
			it.Fixed = len(it.Lines) > 0
			it.Words = plainWords(d.Vendor, stem)
			if kind == KindMissing {
				// a line that fixes it by replacing another one: different
				var device []string
				for _, i := range it.Lines {
					for _, s := range d.Lines[i].For {
						if s != stem && plus[s] && !slices.Contains(device, s) {
							device = append(device, s)
						}
					}
				}
				if len(device) > 0 {
					it.Kind = KindDifferent
					var ws []string
					for _, s := range device {
						ws = append(ws, plainWords(d.Vendor, s))
					}
					it.Words += " (the device has: " + strings.Join(ws, "; ") + ")"
				}
			}
			if kind == KindOrder {
				key := fmt.Sprint(it.Lines)
				if it.Fixed && slices.Contains(seenLineSets, key) {
					continue
				}
				seenLineSets = append(seenLineSets, key)
			}
			it.Severity = severityOf(d.Vendor, name, stem, kind)
			it.Action = p.actionFor(d, &it, extraOf, stem)
			d.Items = append(d.Items, it)
		}
	}
	d.Items = groupItems(d.Vendor, d.Items)
	if p.noLocal {
		d.Items = append(d.Items, Item{Kind: KindNoLocal, Section: "aaa", Severity: SevAccess,
			Words:     "the device has no local user at privilege 15",
			Statement: "username <name> privilege 15 secret ...",
			Action:    "Not fixed by this paste: create the local user by hand before you paste."})
	}
	for i := range d.Items {
		d.Items[i].N = i + 1
	}
}

// objectOf names the object a statement is part of, for grouping: a filter,
// a client list, a server block, an access list, a privilege level. Empty
// when the statement is its own.
func objectOf(vendor, stem string) (key, label string) {
	if vendor == devconf.FamilyJunos {
		t := splitTokens(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate "))
		switch {
		case len(t) >= 6 && t[0] == "firewall" && t[3] == "filter":
			return "filter " + t[4], "the management filter " + t[4]
		case len(t) >= 4 && t[0] == "snmp" && t[1] == "client-list":
			return "client-list " + t[2], "SNMP client list " + t[2]
		case len(t) >= 4 && t[0] == "snmp" && t[1] == "community":
			return "community", "an SNMP community"
		case len(t) >= 6 && t[0] == "system" && t[1] == "login" && t[2] == "class":
			return "class " + t[3], "login class " + t[3]
		case len(t) >= 4 && t[0] == "system" && (t[1] == "tacplus-server" || t[1] == "radius-server"):
			return t[1] + " " + t[2], "the " + map[string]string{"tacplus-server": "TACACS+", "radius-server": "RADIUS"}[t[1]] + " server " + t[2]
		}
		return "", ""
	}
	path := strings.Split(stem, pathSep)
	if len(path) >= 2 {
		return path[0], plainIOS(path[0])
	}
	f := strings.Fields(path[0])
	switch {
	case len(f) >= 5 && f[0] == "privilege" && f[1] == "exec":
		if i := slices.Index(f, "level"); i >= 0 && i+1 < len(f) {
			return "privilege " + f[i+1], "the commands of privilege level " + f[i+1]
		}
	case len(f) >= 3 && f[0] == "aaa" && f[1] == "accounting":
		return "aaa accounting", "accounting"
	case len(f) >= 3 && f[0] == "aaa" && f[1] == "authorization" && (f[2] == "commands" || f[2] == "config-commands"):
		return "aaa command authorization", "command authorization"
	}
	return "", ""
}

// groupItems folds two or more findings of one object, of one kind and
// one outcome, into one item: a tech reads "the management filter is
// missing (22 statements)", not twenty-two lines.
func groupItems(vendor string, items []Item) []Item {
	type gkey struct{ section, kind, obj, outcome string }
	outcome := func(it Item) string {
		if it.Fixed {
			return "fixed"
		}
		return it.Action
	}
	counts := map[gkey]int{}
	keyOf := func(it Item) (gkey, string) {
		obj, label := objectOf(vendor, it.Statement)
		if obj == "" {
			return gkey{}, ""
		}
		return gkey{it.Section, it.Kind, obj, outcome(it)}, label
	}
	for _, it := range items {
		if k, _ := keyOf(it); k.obj != "" {
			counts[k]++
		}
	}
	var out []Item
	at := map[gkey]int{}
	for _, it := range items {
		k, label := keyOf(it)
		if k.obj == "" || counts[k] < 2 {
			out = append(out, it)
			continue
		}
		if i, ok := at[k]; ok {
			g := &out[i]
			g.Lines = append(g.Lines, it.Lines...)
			g.n++
			continue
		}
		g := it
		g.Words = label
		g.Statement = "e.g. " + it.Statement
		g.n = 1
		at[k] = len(out)
		out = append(out, g)
	}
	for i := range out {
		if out[i].n > 1 {
			out[i].Words = out[i].Words + ": " + plural(out[i].n, "statement", "statements")
		}
		slices.Sort(out[i].Lines)
		out[i].Lines = slices.Compact(out[i].Lines)
	}
	return out
}

// actionFor says what the paste does about an item.
func (p *planner) actionFor(d *Delta, it *Item, extraOf map[string]Extra, stem string) string {
	sp := d.Of(it.Section)
	switch {
	case it.Fixed:
		return "Fixed by region " // the line numbers are the emitter's: see itemAction
	case sp.State == StateSkipped && sp.Kind == KindClassSkip:
		return "Not fixable by this login: " + d.Class + " cannot change " + classHierarchy(stem, sp.Why) + " (ask a superuser)."
	case sp.State == StateSkipped && sp.Kind == KindNotWritable:
		return "Not fixed: this login cannot change the section."
	case sp.State == StateSkipped && sp.Kind == KindNotPlannable:
		return "Not fixed: " + sp.Why + "."
	case sp.State == StateSkipped:
		return "Not fixed: " + firstSentence(sp.Why) + "."
	}
	for _, w := range d.Withheld {
		if w == cmdAuthWithheldPrefix+stem {
			return cmdAuthHeldText + "."
		}
	}
	for _, w := range d.Withheld {
		if strings.HasSuffix(w, stem) || strings.HasPrefix(w, stem) {
			switch {
			case strings.HasPrefix(w, "the access-class binding"):
				return "Left to you: the walkthrough's access-class line is never part of this output."
			case strings.HasPrefix(w, "the login method of lines"):
				return "Not typed: the record shows no such lines."
			default:
				return "Not fixable by this login: " + d.Class + " cannot change " + classHierarchy(stem, "") + " (ask a superuser)."
			}
		}
	}
	switch it.Kind {
	case KindSecret:
		return "Not visible to this login; left alone (--secrets pushes the value)."
	case KindExtra:
		if e, ok := extraOf[it.Section+"|"+stem]; ok && len(e.Remove) > 0 && e.Guard == "" {
			return "Left alone. To remove it later" + removeText(e.Remove)
		} else if ok && e.Guard != "" {
			return "Left alone (" + e.Guard + ")."
		}
		return "Left alone."
	case KindMissing:
		if strings.Contains(stem, "login") && strings.HasPrefix(stem, "line ") {
			return "Follows from 'aaa new-model': lines with no login method use the default list."
		}
	}
	return "Left alone."
}

func firstSentence(s string) string {
	if i := strings.Index(s, ": change the group"); i >= 0 {
		return s[:i] + ": change the group by hand"
	}
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i]
	}
	return s
}

// classHierarchy names the hierarchy a class cannot see, for the line that
// says so.
func classHierarchy(stem, why string) string {
	t := splitTokens(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate "))
	if r, ok := classRuleFor(t); ok {
		return "'" + r.Prefix + "'"
	}
	if why != "" {
		return why
	}
	return "this part of the configuration"
}

// severityOf classifies a finding (D110).
func severityOf(vendor, section, stem, kind string) string {
	t := strings.Fields(strings.NewReplacer(pathSep, " ").Replace(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate ")))
	has := func(i int, w string) bool { return len(t) > i && t[i] == w }
	switch section {
	case "snmp":
		if has(0, "snmp") && (has(1, "location") || has(1, "contact") || has(1, "description")) ||
			has(0, "snmp-server") && (has(1, "location") || has(1, "contact")) {
			return SevCosmetic
		}
		return SevMonitoring
	case "aaa":
		if has(0, "system") && has(1, "accounting") || has(0, "aaa") && has(1, "accounting") {
			return SevCosmetic
		}
		return SevAccess
	case "roles":
		if vendor == devconf.FamilyIOS {
			return SevCosmetic
		}
		return SevAccess
	case "mgmt-acl":
		return SevAccess
	}
	return SevCosmetic
}

// plainWords is a statement in the words of a technician.
func plainWords(vendor, stem string) string {
	if vendor == devconf.FamilyIOS {
		return plainIOS(stem)
	}
	return plainJunos(stem)
}

func plainJunos(stem string) string {
	deact := strings.HasPrefix(stem, "deactivate ")
	t := splitTokens(strings.TrimPrefix(strings.TrimPrefix(stem, "set "), "deactivate "))
	rest := func(from int) string {
		if from >= len(t) {
			return ""
		}
		return strings.Join(t[from:], " ")
	}
	var w string
	switch {
	case deact:
		w = "deactivated: " + strings.Join(t, " ")
	case len(t) >= 3 && t[0] == "system" && t[1] == "authentication-order":
		w = "the login order tries " + t[2]
	case len(t) >= 5 && t[0] == "system" && (t[1] == "tacplus-server" || t[1] == "radius-server"):
		proto := "TACACS+"
		if t[1] == "radius-server" {
			proto = "RADIUS"
		}
		if t[3] == "secret" {
			w = "the " + proto + " server " + t[2] + " has its secret"
		} else {
			w = "the " + proto + " server " + t[2] + ": " + rest(3)
		}
	case len(t) >= 3 && t[0] == "system" && t[1] == "tacplus-server":
		w = "a TACACS+ server " + t[2]
	case len(t) >= 3 && t[0] == "system" && t[1] == "radius-server":
		w = "a RADIUS server " + t[2]
	case len(t) >= 4 && t[0] == "system" && t[1] == "accounting" && t[2] == "events":
		w = "accounting sends the event " + t[3]
	case len(t) >= 4 && t[0] == "system" && t[1] == "accounting" && t[2] == "destination":
		w = "accounting goes to " + rest(3)
	case len(t) >= 6 && t[0] == "system" && t[1] == "login" && t[2] == "class" && t[4] == "permissions":
		w = "login class " + t[3] + " allows " + rest(5)
	case len(t) >= 5 && t[0] == "system" && t[1] == "login" && t[2] == "class":
		w = "login class " + t[3] + ": " + rest(4)
	case len(t) >= 6 && t[0] == "system" && t[1] == "login" && t[2] == "user" && t[4] == "class":
		w = "template user " + t[3] + " is in class " + t[5]
	case len(t) >= 5 && t[0] == "snmp" && t[1] == "client-list":
		w = "SNMP client list " + t[2] + " allows " + rest(3)
	case len(t) >= 3 && t[0] == "snmp" && t[1] == "community":
		w = "an SNMP community: " + rest(3)
	case len(t) >= 3 && t[0] == "snmp" && (t[1] == "location" || t[1] == "contact" || t[1] == "description"):
		w = "the SNMP " + t[1] + " is " + rest(2)
	case len(t) >= 3 && t[0] == "snmp" && t[1] == "v3":
		w = "SNMPv3: " + rest(2)
	case len(t) >= 7 && t[0] == "firewall" && t[3] == "filter" && t[5] == "term":
		w = "management filter " + t[4] + ", term " + t[6] + ": " + rest(7)
	case len(t) >= 2 && t[0] == "snmp":
		w = "SNMP: " + rest(1)
	default:
		w = strings.Join(t, " ")
	}
	return strings.TrimSuffix(w, ": ")
}

func plainIOS(stem string) string {
	path := strings.Split(stem, pathSep)
	leaf := path[len(path)-1]
	f := strings.Fields(leaf)
	var w string
	switch {
	case leaf == "aaa new-model":
		w = "AAA is not turned on"
	case len(path) == 2 && strings.HasPrefix(path[0], "tacacs server "), len(path) == 2 && strings.HasPrefix(path[0], "radius server "):
		w = "the server " + strings.Fields(path[0])[2] + ": " + leaf
	case len(f) >= 3 && f[0] == "tacacs-server" && f[1] == "host":
		w = "the TACACS+ server " + f[2]
	case len(f) >= 3 && f[0] == "radius-server" && f[1] == "host":
		w = "the RADIUS server " + f[2]
	case len(path) == 2 && strings.HasPrefix(path[0], "aaa group server "):
		w = "the server group " + strings.Fields(path[0])[len(strings.Fields(path[0]))-1] + ": " + leaf
	case len(f) >= 4 && f[0] == "aaa" && f[1] == "authentication" && f[2] == "enable":
		w = "the 'enable' list (it asks the server first, so nobody needs a shared enable password)"
	case len(f) >= 4 && f[0] == "aaa" && f[1] == "authentication" && f[3] == iosConsoleList:
		w = "the console's own login list " + iosConsoleList + " (local only, so a local user always gets in there)"
	case len(f) >= 4 && f[0] == "aaa" && f[1] == "authentication" && f[2] == "login":
		w = "the " + f[3] + " login method list"
	case len(f) >= 4 && f[0] == "aaa" && f[1] == "authentication":
		w = "the " + f[3] + " " + f[2] + " method list"
	case len(f) >= 3 && f[0] == "aaa" && f[1] == "session-id":
		w = "the accounting session id is " + f[2]
	case len(f) >= 3 && f[0] == "ip" && (f[1] == "tacacs" || f[1] == "radius") && f[2] == "source-interface":
		w = "the " + map[string]string{"tacacs": "TACACS+", "radius": "RADIUS"}[f[1]] + " source interface is " + strings.Join(f[3:], " ")
	case len(f) >= 4 && f[0] == "aaa" && f[1] == "authorization" && f[2] == "exec":
		w = "the " + f[3] + " exec authorization list (without it every new login lands at privilege 1)"
	case len(f) >= 5 && f[0] == "aaa" && f[1] == "authorization" && f[2] == "commands":
		w = "command authorization at level " + f[3]
	case len(f) >= 3 && f[0] == "aaa" && f[1] == "authorization" && f[2] == "config-commands":
		w = "authorization of configuration commands"
	case len(f) >= 3 && f[0] == "aaa" && f[1] == "accounting":
		w = "accounting of " + strings.Join(f[2:min(4, len(f))], " ")
	case len(f) >= 5 && f[0] == "privilege" && f[1] == "exec":
		if i := slices.Index(f, "level"); i >= 0 && i+2 < len(f) {
			w = "level " + f[i+1] + " may run " + strings.Join(f[i+2:], " ")
		}
	case len(f) >= 2 && f[0] == "snmp-server" && f[1] == "community":
		w = "an SNMP community"
	case len(f) >= 2 && f[0] == "snmp-server" && (f[1] == "location" || f[1] == "contact"):
		w = "the SNMP " + f[1] + " is " + strings.Join(f[2:], " ")
	case len(path) == 2 && strings.HasPrefix(path[0], "ip access-list "):
		w = "access list " + strings.Fields(path[0])[len(strings.Fields(path[0]))-1] + ": " + leaf
	case len(path) == 2 && strings.HasPrefix(path[0], "line ") && strings.HasPrefix(leaf, "access-class "):
		w = "the access-class binding of " + path[0]
	case len(path) == 2 && strings.HasPrefix(path[0], "line "):
		w = "the login method of " + path[0] + ": " + leaf
	}
	if w == "" {
		w = strings.Join(path, " ")
	}
	return w
}

// --- extras ---------------------------------------------------------------------------

// buildExtras records every statement left alone with the exact line that
// would remove it, and the guard that says why not when there is none
// (D111). The cleanup region is built from these later; nothing here is ever
// part of the region.
func (p *planner) buildExtras(d *Delta) {
	for _, k := range d.Kept {
		e := Extra{Section: k.Section, Text: k.Text}
		switch {
		case strings.HasPrefix(k.Text, "deactivate "):
			e.Guard = "deactivated; activate or delete it by hand"
		case d.Vendor == devconf.FamilyJunos:
			t := splitTokens(strings.TrimPrefix(k.Text, "set "))
			switch {
			case strings.Contains(k.Text, secretMark):
				e.Guard = "its name is the secret and is not known to tacctl"
			case len(t) >= 2 && t[0] == "snmp" && slices.Contains([]string{"name", "engine-id", "trap-options", "location", "contact", "description"}, t[1]),
				len(t) >= 2 && t[0] == "snmp" && strings.HasPrefix(t[1], "trap"):
				e.Guard = "the device's own identity: never removed"
			case len(t) >= 3 && t[0] == "system" && t[1] == "login" && t[2] == "user":
				e.Guard = "a login: never removed"
			case len(t) >= 4 && t[0] == "system" && t[1] == "login" && t[2] == "class" && p.classInUse(t[3]):
				e.Guard = "a login uses this class: not removed"
			default:
				e.Remove = []Line{{Op: OpDelete, Section: k.Section, Text: p.junosRemoval(k.Section, t)}}
			}
		default:
			path := strings.Split(k.Text, pathSep)
			leaf := path[len(path)-1]
			switch {
			case strings.Contains(k.Text, secretMark):
				e.Guard = "its name is the secret and is not known to tacctl"
			case strings.HasPrefix(leaf, "username "), strings.HasPrefix(leaf, "enable "), strings.HasPrefix(path[0], "line "):
				e.Guard = "a login or a line: never removed"
			case k.Note != "" && (strings.Contains(k.Note, "image") || strings.Contains(k.Note, "default level")):
				e.Guard = "the image's own line"
			default:
				e.Remove = p.iosRemoval(k.Section, path)
			}
		}
		d.Extras = append(d.Extras, e)
	}
}

// junosObjectDepths are the depths at which a statement's path names an
// object of its own, shallowest first: a server, a client list, a
// community, a login class, a filter and a term of one.
func junosObjectDepths(t []string) []int {
	switch {
	case len(t) >= 3 && t[0] == "system" && (t[1] == "tacplus-server" || t[1] == "radius-server"):
		return []int{3}
	case len(t) >= 3 && t[0] == "snmp" && (t[1] == "client-list" || t[1] == "community"):
		return []int{3}
	case len(t) >= 4 && t[0] == "system" && t[1] == "login" && (t[2] == "class" || t[2] == "user"):
		return []int{4}
	case len(t) >= 7 && t[0] == "firewall" && t[1] == "family" && t[3] == "filter" && t[5] == "term":
		return []int{5, 7}
	}
	return nil
}

// classInUse reports whether a login user of the pulled device is in the
// class.
func (p *planner) classInUse(class string) bool {
	for _, s := range p.cur.Sections["roles"].Lines {
		t := splitTokens(strings.TrimPrefix(s, "set "))
		if len(t) >= 6 && t[0] == "system" && t[1] == "login" && t[2] == "user" && t[4] == "class" && t[5] == class {
			return true
		}
	}
	return false
}

// junosRemoval is the one delete line that removes an extra statement
// (D111): the whole object (a server, a client list, a term) when the
// rendering does not hold the object, the statement's own leaf when it
// does (the object is tacctl's and stays).
func (p *planner) junosRemoval(section string, t []string) string {
	exp := p.expected(section)
	for _, depth := range junosObjectDepths(t) {
		if depth < len(t) && !p.renderedPrefix(exp, t[:depth]) {
			return "delete " + joinTokens(t[:depth])
		}
	}
	return junosDeleteText(t)
}

// iosRemoval is the lines that remove an extra statement (D111): the 'no'
// of the whole block or group when tacctl renders none like it, the
// server's own line for the legacy host forms, and otherwise the leaf as a
// 'no' line under its submode header.
func (p *planner) iosRemoval(section string, path []string) []Line {
	leaf := path[len(path)-1]
	ctx := slices.Clone(path[:len(path)-1])
	f := strings.Fields(leaf)
	no := func(ctx []string, text string) []Line {
		return []Line{{Op: OpNo, Section: section, Context: ctx, Text: text}}
	}
	if len(ctx) == 0 {
		if len(f) >= 3 && (f[0] == "tacacs-server" || f[0] == "radius-server") && f[1] == "host" {
			return no(nil, hostEntry(f))
		}
		return no(nil, leaf)
	}
	header := ctx[0]
	if len(ctx) == 1 {
		for _, pfx := range []string{"tacacs server ", "radius server ", "aaa group server "} {
			if strings.HasPrefix(header, pfx) && !p.ios.renderedHeader(header) {
				return no(nil, header)
			}
		}
		if header == "aaa server radius dynamic-author" && len(f) >= 2 && f[0] == "client" {
			return no(ctx, "client "+f[1])
		}
	}
	return no(ctx, leaf)
}

// renderedHeader reports whether the rendering has a block under the
// header.
func (st *iosState) renderedHeader(header string) bool {
	for _, es := range st.entries {
		for _, e := range es {
			if len(e.ctx) > 0 && e.ctx[0] == header {
				return true
			}
		}
	}
	return false
}

// removeLines are the lines of a removal as typed, a submode header
// before the lines under it.
func removeLines(lines []Line) []string {
	var out []string
	var ctx []string
	for _, l := range lines {
		if !slices.Equal(ctx, l.Context) {
			out = append(out, l.Context...)
			ctx = l.Context
		}
		text := l.Shown()
		if l.Op == OpNo {
			text = "no " + text
		}
		out = append(out, text)
	}
	return out
}

// removeText finishes the sentence 'To remove it later': one line, or the
// lines in order.
func removeText(lines []Line) string {
	ls := removeLines(lines)
	if len(ls) == 1 {
		return ": " + ls[0]
	}
	return ", type these lines in order: " + strings.Join(ls, " / ")
}

// --- the report ---------------------------------------------------------------------

func sensitivityLine(d Delta, h Header) string {
	if !d.HoldsSecret() {
		return ""
	}
	scope := d.Scope
	if scope == "" {
		scope = h.Scope
	}
	return "THIS OUTPUT HOLDS THE " + strings.Join(d.SecretKinds, " AND THE ") + " OF SCOPE " + scope + ": do not keep it in a file or a scrollback."
}

func boxLine(d Delta, h Header) string {
	bc := bannerChar(d.Vendor)
	vendor := h.Vendor
	proto := h.Protocol
	if proto == "" {
		proto = "TACACS+"
	}
	if d.Vendor == devconf.FamilyIOS {
		syntax := "syntax not known"
		switch d.Syntax {
		case SyntaxIOS12:
			syntax = "IOS 12.x syntax"
		case SyntaxModern:
			syntax = "IOS-XE and IOS 15 syntax"
		}
		proto = syntax + ", " + proto
	}
	addr := ""
	if h.Address != "" {
		addr = "  " + h.Address
	}
	return fmt.Sprintf("%s %s%s  scope %s  %s (%s) %s", bc, h.Device, addr, h.Scope, vendor, proto, bc)
}

// iosLabNote is the sentence every Cisco output's report carries (D100).
const iosLabNote = "Lab-tested on IOS 12.4(15) (a 7200 emulator); other IOS trains and IOS-XE are written from the references."

// Report is the box, the irregularity report and the one check line, all
// outside the region (D108, D110, D112).
func Report(d Delta, h Header, w Wrapper) string {
	var b strings.Builder
	c := commentLeader(d.Vendor)
	add := func(s string) {
		for _, l := range wrapText(s, 100) {
			b.WriteString(c + " " + l + "\n")
		}
	}
	blank := func() { b.WriteString(c + "\n") }

	b.WriteString(boxLine(d, h) + "\n")
	sec := ""
	if h.SecretsVisible {
		sec = "; the login could see secrets"
	}
	based := fmt.Sprintf("Based on the pull of %s by %s over %s (%s%s) and the standard of %s (tacctl %s).",
		fmtTime(h.Pulled), h.PulledBy, h.Transport, ageText(h.Now, h.Pulled), sec, fmtTime(h.Now), h.Version)
	if d.Vendor == devconf.FamilyIOS {
		based += " " + iosLabNote
	}
	add(based)
	if s := sensitivityLine(d, h); s != "" {
		add(s)
	}
	if hold := d.BreakglassHeld; hold != nil {
		add("BREAK-GLASS HELD on this device since " + hold.Since + " by " + hold.By + ": the server does not answer it, so the check below (\"a NEW ssh session as yourself\") cannot pass until it is released: tacctl breakglass release " + h.Device)
	}
	blank()

	fixed := 0
	for _, it := range d.Items {
		if it.Fixed || it.removedByCleanup() {
			fixed++
		}
	}
	switch {
	case len(d.Items) == 0 && d.Refusal() != "":
		add("CANNOT BE PLANNED: " + d.Refusal() + ". Nothing to paste.")
	case len(d.Items) == 0:
		add("CONSISTENT: nothing to paste.")
	default:
		add(fmt.Sprintf("What is irregular on %s (%s; the paste fixes %d, leaves %d):", h.Device,
			plural(len(d.Items), "item", "items"), fixed, len(d.Items)-fixed))
		for _, it := range d.Items {
			head := fmt.Sprintf("%2d. %-8s %-10s ", it.N, it.Section, it.Severity)
			text := it.Kind + ": " + it.Words
			if it.Statement != "" && !strings.EqualFold(it.Statement, it.Words) {
				text += " (" + it.Statement + ")"
			}
			text += ". " + it.Action
			text = strings.ReplaceAll(text, "). .", ").")
			for i, l := range wrapText(text, 100-len(head)) {
				if i == 0 {
					b.WriteString(c + " " + head + l + "\n")
				} else {
					b.WriteString(c + " " + strings.Repeat(" ", len(head)) + l + "\n")
				}
			}
		}
		if d.Empty() {
			// the cleanup region is the paste of the device (statusOf says
			// needs-change): a refused section is left as it is, not the reason
			// there is nothing to paste
			if !d.Cleanup.Empty() {
				if sk, ok := d.refusedSection(); ok {
					add("No fix to paste: the cleanup region below is the only paste. The section " + sk.Section +
						" is not planned and stays as it is (refused: " + firstSentence(sk.Why) + "); what else remains is left alone.")
				} else {
					add("No fix to paste: the cleanup region below is the only paste (what else remains is left alone).")
				}
			} else if r := d.Refusal(); r != "" {
				add("CANNOT BE PLANNED: " + r + ". Nothing is pasted for this device.")
			} else {
				add("Nothing to paste: everything above is left alone or cannot be fixed by this login.")
			}
		}
	}

	var consistent, notrendered, notselected, notvisible []string
	itemIn := map[string]bool{}
	for _, it := range d.Items {
		itemIn[it.Section] = true
	}
	for _, s := range d.Sections {
		switch s.State {
		case StateNoChange, StatePlanned:
			if !itemIn[s.Name] {
				consistent = append(consistent, s.Name)
			}
		case StateNA:
			notrendered = append(notrendered, s.Name)
		case StateNotSelected:
			notselected = append(notselected, s.Name)
		case StateNotVisible:
			notvisible = append(notvisible, s.Name)
		}
	}
	line := ""
	if len(consistent) > 0 {
		line = "Consistent: " + strings.Join(consistent, ", ") + ". "
	}
	if d.Vendor == devconf.FamilyIOS {
		line += "Not planned: netconf, breakglass."
	} else {
		line += "Not planned: netconf, breakglass (walkthrough Steps 6 and 7)."
	}
	add(line)
	if len(notrendered) > 0 {
		add("The standard has nothing for: " + strings.Join(notrendered, ", ") + ".")
	}
	if len(notselected) > 0 {
		add("Not selected (--section): " + strings.Join(notselected, ", ") + ".")
	}
	if len(notvisible) > 0 {
		add("Not visible to the pull's login, so not planned: " + strings.Join(notvisible, ", ") + ".")
	}
	var secret []string
	if d.Counts.SecretsPresent > 0 {
		secret = append(secret, fmt.Sprintf("%d present on the device, not changed", d.Counts.SecretsPresent))
	}
	if d.Counts.SecretsNotVisible > 0 {
		secret = append(secret, fmt.Sprintf("%d not visible to the pull's login, not changed", d.Counts.SecretsNotVisible))
	}
	if len(secret) > 0 {
		add("Secrets: " + strings.Join(secret, "; ") + " (--secrets pushes them).")
	}
	if d.Counts.Placeholders > 0 {
		add("Secrets are shown as <SECRET> on lines marked '" + commentLeader(d.Vendor) + " " + secretLinePrefix + "': read the value with 'tacctl scope secret show " + h.Scope +
			"' (the server secret) or 'tacctl scope snmp " + h.Scope + " show --reveal' (the SNMP community), put it in, remove the mark.")
	}
	if len(d.Unattributed) > 0 {
		add("Note: a delete under an SNMP community acts on the community tacctl renders only (the device's community names are not compared); 'statement not found' is then expected for a leaf of another community.")
	}
	if !d.InheritanceChecked && d.Vendor == devconf.FamilyJunos {
		add("The pull has no plain view of the configuration: statements that come from a group could not be told apart and were not checked (pull the device again to read it).")
	}
	if d.Converge {
		c := d.Cleanup
		switch {
		case c.Deferred != "":
			add("Cleanup (--converge): " + c.Deferred + ".")
		case c.Whole != "":
			add("Cleanup (--converge) is not offered: " + c.Whole + ".")
		case !c.Empty():
			pending := ""
			if d.Vendor == devconf.FamilyJunos {
				pending = ", and " + junosPendingCheck
			}
			add(fmt.Sprintf("Cleanup (--converge): the region below is the whole output: it removes %s: %s the standard does not have. Paste it only after you have checked that the pull of %s is current (tacctl device config pull %s --diff reads ok for aaa, and a NEW ssh session as yourself works)%s.",
				plural(len(c.Lines), "line", "lines"), cleanupKinds(c), h.Device, h.Device, pending))
			if len(c.Left) > 0 {
				add(extrasStay(len(c.Left)))
			}
		default:
			add("Cleanup (--converge): nothing to remove.")
			if len(c.Left) > 0 {
				add(extrasStay(len(c.Left)))
			}
		}
	}
	for _, n := range d.Notes {
		add("Note: " + n + ".")
	}
	for _, w := range d.Warnings {
		add("WARNING: " + w + ".")
	}
	if h.StaleDays > 0 && h.Now.Sub(h.Pulled) > timeDays(h.StaleDays) {
		add(fmt.Sprintf("WARNING: the pull is %s old and stale-days is %d: pull again before you paste.",
			strings.TrimSuffix(ageText(h.Now, h.Pulled), " ago"), h.StaleDays))
	}
	if d.Vendor == devconf.FamilyJunos && !h.SecretsVisible {
		add("WARNING: the pull's login could not see secrets: a secret the device holds could not be compared and is left alone.")
	}
	// the cleanup is the whole output of a device with no first region: the
	// same warnings and the same check line stand in front of it
	if !d.Empty() || !d.Cleanup.Empty() {
		if d.Vendor == devconf.FamilyIOS {
			add("The change is live when the paste ends. NOTHING rolls it back by itself. Keep a second terminal logged in at privilege 15 until the end.")
		} else {
			add("The switch undoes this by itself in " + fmt.Sprint(confirmMinutes(w)) + " minutes unless you type the one word after the check (see below).")
		}
		add("Paste over ssh, not the console; on a console paste at most twenty lines at a time and watch the echo for '" + errorWord(d.Vendor) + "'. Pasting the region twice is harmless.")
		blank()
		b.WriteString(c + " Type this first, on " + h.Device + ", and check the name:   " + checkLine(d.Vendor) + "\n")
		add(promptCheck(d.Vendor))
		blank()
	}
	return b.String()
}

func timeDays(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func errorWord(vendor string) string {
	if vendor == devconf.FamilyIOS {
		return "% Invalid"
	}
	return "error:"
}

// promptCheck is what the prompt must look like before the paste.
func promptCheck(vendor string) string {
	if vendor == devconf.FamilyIOS {
		return "The prompt must end in # (privileged mode), not in (config)#, before you paste: a prompt ending in > means type enable first, a prompt with (config) in it means a configuration session is open: type end first."
	}
	return "The prompt must end in > (operational mode) before you paste: a prompt ending in # means a configuration session is open: stop."
}

func checkLine(vendor string) string {
	if vendor == devconf.FamilyIOS {
		return "show version | include uptime"
	}
	return "show version | match Hostname"
}

// --- status and the cover page ----------------------------------------------------

// The states of a device on the cover page.
const (
	// StatusConsistent: the comparison found nothing at all.
	StatusConsistent = "consistent"
	// StatusNeedsChange: the paste has something to type.
	StatusNeedsChange = "needs-change"
	// StatusLeftAlone: the device has irregularities and nothing can be
	// pasted for them (extras, secrets not visible, sections this login
	// cannot change): it is not consistent, and the paste does not help.
	StatusLeftAlone = "left-alone"
	// StatusCannotPlan: no plan could be made.
	StatusCannotPlan = "cannot-plan"
)

// statusOf is the device's state. 'consistent' only with no finding of any
// kind: a device with an unfixed ACCESS problem is never called consistent.
// A plan with nothing to paste and a section it refused (a statement a group
// owns, the lock-out guards of the aaa unit, a record that needs a pull) is
// one that cannot be planned: the person is told there is nothing to paste
// because it is refused, not because nothing is wrong.
func statusOf(d Delta) string {
	switch {
	case !d.Empty(), !d.Cleanup.Empty():
		// the cleanup region (--converge) is the paste of a device that has
		// no other
		return StatusNeedsChange
	case d.Refusal() != "":
		return StatusCannotPlan
	case len(d.Items) > 0:
		return StatusLeftAlone
	}
	return StatusConsistent
}

// Refusal is the first refusal of a plan that has nothing to paste ("" when
// it has lines, or none of its sections was refused): 'refused: <section>:
// <why>'. A section the login's class cannot commit is no refusal (it is
// left to a superuser, and the report says so).
func (d Delta) Refusal() string {
	if sk, ok := d.refusedSection(); ok {
		return "refused: " + sk.Section + ": " + firstSentence(sk.Why)
	}
	return ""
}

// refusedSection is the first section a plan with nothing to paste refused.
func (d Delta) refusedSection() (Skip, bool) {
	if !d.Empty() {
		return Skip{}, false
	}
	for _, s := range d.Skipped {
		if s.Kind == KindRefused || s.Kind == KindNotPlannable {
			return s, true
		}
	}
	return Skip{}, false
}

// LeftCounts are the findings the paste leaves, by severity.
type LeftCounts struct {
	Access     int `json:"access"`
	Monitoring int `json:"monitoring"`
	Cosmetic   int `json:"cosmetic"`
}

// Total is the number of findings left.
func (c LeftCounts) Total() int { return c.Access + c.Monitoring + c.Cosmetic }

// leftOf counts the findings no line of the paste fixes.
func leftOf(d Delta) LeftCounts {
	var c LeftCounts
	for _, it := range d.Items {
		if it.Fixed || it.removedByCleanup() {
			continue
		}
		switch it.Severity {
		case SevAccess:
			c.Access++
		case SevMonitoring:
			c.Monitoring++
		default:
			c.Cosmetic++
		}
	}
	return c
}

func (c LeftCounts) String() string {
	var parts []string
	if c.Access > 0 {
		parts = append(parts, fmt.Sprintf("%d ACCESS", c.Access))
	}
	if c.Monitoring > 0 {
		parts = append(parts, fmt.Sprintf("%d MONITORING", c.Monitoring))
	}
	if c.Cosmetic > 0 {
		parts = append(parts, fmt.Sprintf("%d COSMETIC", c.Cosmetic))
	}
	return strings.Join(parts, ", ")
}

// DeviceStatus is one line of the cover page: a stable shape the CLI
// renders for several devices (D110).
type DeviceStatus struct {
	Device  string `json:"device"`
	Scope   string `json:"scope"`
	Vendor  string `json:"vendor"`
	Address string `json:"address,omitempty"`
	// State is one of the Status constants.
	State string `json:"state"`
	// Fixes is the number of irregularities the paste fixes, Left the
	// number it leaves (Remaining says how many of each severity), Extras
	// the statements left alone.
	Fixes     int        `json:"fixes"`
	Left      int        `json:"left"`
	Remaining LeftCounts `json:"remaining"`
	Extras    int        `json:"extras"`
	// Reason is why a device cannot be planned (not pulled, a stale pull,
	// refused, a failed read).
	Reason string `json:"reason,omitempty"`
	// BreakglassHeld marks a device the server was told not to answer.
	BreakglassHeld bool `json:"breakglass_held,omitempty"`
}

// StatusFor is the cover line of a planned device.
func StatusFor(d Delta, h Header) DeviceStatus {
	s := DeviceStatus{Device: h.Device, Scope: h.Scope, Vendor: h.Vendor, Address: h.Address, State: statusOf(d), Extras: len(d.Extras),
		BreakglassHeld: d.BreakglassHeld != nil}
	for _, it := range d.Items {
		if it.Fixed || it.removedByCleanup() {
			s.Fixes++
		} else {
			s.Left++
		}
	}
	s.Remaining = leftOf(d)
	if s.State == StatusCannotPlan {
		s.Reason = d.Refusal()
	}
	return s
}

// CannotPlan is the cover line of a device that could not be planned.
func CannotPlan(h Header, reason string) DeviceStatus {
	return DeviceStatus{Device: h.Device, Scope: h.Scope, Vendor: h.Vendor, Address: h.Address, State: StatusCannotPlan, Reason: reason}
}

// Cover is the cover page of several devices: one line each and the
// totals.
func Cover(ds []DeviceStatus) string {
	var b strings.Builder
	var ok, need, left, cannot int
	width := 0
	for _, s := range ds {
		width = max(width, len(s.Device))
	}
	fmt.Fprintf(&b, "# tacctl device config plan: %s\n", plural(len(ds), "device", "devices"))
	for _, s := range ds {
		var what string
		switch s.State {
		case StatusConsistent:
			ok++
			what = "consistent"
		case StatusNeedsChange:
			need++
			what = fmt.Sprintf("needs change: %s fixed by the paste", plural(s.Fixes, "irregularity", "irregularities"))
			if s.Left > 0 {
				what += fmt.Sprintf(", %d left (%s)", s.Left, s.Remaining)
			}
			if s.Extras > 0 {
				what += fmt.Sprintf(", %s", plural(s.Extras, "extra", "extras"))
			}
		case StatusLeftAlone:
			left++
			what = fmt.Sprintf("NOT consistent, nothing to paste: %s left (%s)", plural(s.Left, "irregularity", "irregularities"), s.Remaining)
			if s.Extras > 0 {
				what += fmt.Sprintf(", %s", plural(s.Extras, "extra", "extras"))
			}
		default:
			cannot++
			what = "cannot be planned: " + s.Reason
		}
		if s.BreakglassHeld {
			what += " [break-glass held]"
		}
		fmt.Fprintf(&b, "#   %-*s  %s\n", width, s.Device, what)
	}
	fmt.Fprintf(&b, "# %d consistent, %d need a change, %d not consistent with nothing to paste, %d cannot be planned\n", ok, need, left, cannot)
	return b.String()
}
