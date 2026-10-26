package plan

// Where a block's statement was written (0.2.19): a statement that comes from
// a configuration block carries the block it was written in, so a region says
// "# from scope block lab juniper system" or "# from device block sw1 system"
// above it, the words of the verb that edits the block, and a person pasting it knows it is a block's and whose.

import (
	"strings"

	"github.com/rett/tacctl/internal/devices"
)

// originsOfSections maps the trimmed text of each block line of the expected
// sections to its origin.
func originsOfSections(expected []devices.Section) map[string]string {
	var out map[string]string
	for _, sec := range expected {
		for i, o := range sec.Origin {
			if o == "" || i >= len(sec.Lines) {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[strings.TrimSpace(sec.Lines[i])] = o
		}
		// a service the block requires to be absent: the delete (Junos) or no
		// (IOS) that takes it away comes from the block that states it
		for i, o := range sec.ForbidOrigin {
			if o == "" || i >= len(sec.Forbid) {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out["delete "+sec.Forbid[i]] = o
			out["no "+sec.Forbid[i]] = o
		}
	}
	return out
}

// originsBySection is originsOfSections per section: the origin of a planned
// line is looked up among the block lines of its own section only, so that a
// statement tacctl renders from its structured settings (a login class, a
// community of the scope) is never taken for a block's.
func originsBySection(expected []devices.Section) map[string]map[string]string {
	var out map[string]map[string]string
	for _, sec := range expected {
		one := originsOfSections([]devices.Section{sec})
		if len(one) == 0 {
			continue
		}
		if out == nil {
			out = map[string]map[string]string{}
		}
		out[sec.Name] = one
	}
	return out
}

// originOf is the block a planned line comes from, "" when none is known. A
// line is looked up by its text; one the plan split from a longer statement
// ('set system ntp server H version 4' from the block's 'set system ntp server
// H prefer version 4 key 1') by the longest run of leading words it shares
// with a statement of a block, of at least three.
func (d Delta) originOf(l Line) string {
	m := d.origins[l.Section]
	switch l.Op {
	case OpDelete:
		return m[strings.TrimSpace(l.Text)]
	case OpNo:
		return m["no "+strings.TrimSpace(l.Text)]
	}
	// a line split from a longer statement shares its object with it: on
	// Junos the 'set', the path to the object and its name (five words for an
	// NTP server), on IOS the words to the name
	min := 3
	if strings.HasPrefix(strings.TrimSpace(l.Text), "set ") {
		min = 5
	}
	return lookupOriginMin(m, l.Text, min)
}

// lookupOrigin is the origin of a statement text in a map of the expected
// block lines: the line itself, else the one it shares the longest run of at
// least three leading words with.
func lookupOrigin(origins map[string]string, text string) string {
	return lookupOriginMin(origins, text, 3)
}

// lookupOriginMin is lookupOrigin with the fewest leading words a shared run
// must have.
func lookupOriginMin(origins map[string]string, text string, min int) string {
	if len(origins) == 0 {
		return ""
	}
	t := strings.TrimSpace(text)
	if o, ok := origins[t]; ok {
		return o
	}
	tw := strings.Fields(t)
	best, bestN, tie := "", min-1, false
	for k, o := range origins {
		kw := strings.Fields(k)
		n := 0
		for n < len(tw) && n < len(kw) && tw[n] == kw[n] {
			n++
		}
		switch {
		case n > bestN:
			best, bestN, tie = o, n, false
		case n == bestN && o != best:
			tie = true
		}
	}
	if tie {
		return "" // two blocks state statements this near: no guess
	}
	return best
}

// layerWords is the layer an origin names ("scope block lab juniper snmp"):
// "scope 'lab'" or "device 'sw1'"; "" for no origin.
func layerWords(origin string) string {
	f := strings.Fields(origin)
	if len(f) < 3 {
		return ""
	}
	return f[0] + " '" + f[2] + "'"
}

// blocksWords words the layers a section's block is made of, for the reason a
// section gives ("the statements of the system block of <words>"): "scope
// 'lab'" for the scope's block alone, "scope 'lab' with the block of device
// 'sw1' over it" where both state something, "device 'sw1'" for the device's
// own alone. The layers are read from the origins of the expected lines; with
// none known the scope's is named, as it always was.
func blocksWords(expected []devices.Section, scope, section string) string {
	scopeWord := "this scope"
	if scope != "" {
		scopeWord = "scope '" + scope + "'"
	}
	var hasScope, device string
	for _, sec := range expected {
		if sec.Name != section {
			continue
		}
		for _, o := range sec.Origin {
			f := strings.Fields(o)
			switch {
			case len(f) >= 3 && f[0] == "scope":
				hasScope = o
			case len(f) >= 3 && f[0] == "device":
				device = f[2]
			}
		}
	}
	switch {
	case device != "" && hasScope != "":
		return scopeWord + " with the block of device '" + device + "' over it"
	case device != "":
		return "device '" + device + "'"
	}
	return scopeWord
}

// blocksWords is blocksWords for a section of this planner's expected sections.
func (p *planner) blocksWords(section string) string {
	return blocksWords(p.exp, p.opt.Scope, section)
}

// whyOf is a row's reason with the scope's words replaced by the layers the
// section's block is made of.
func (p *planner) whyOf(row OwnedRow) string {
	w := strings.ReplaceAll(row.Why, "scope <scope>", p.blocksWords(row.Section))
	return strings.ReplaceAll(w, "<scope>", p.blockScope())
}
