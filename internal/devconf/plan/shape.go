package plan

// The shape of a delta (0.2.9 plan D135): a typed function of the delta's
// lines that says "this is the same change" for two devices. A batch trusts
// a confirmed apply for a shape, so the function is pure, holds no secret
// and does not depend on the order the planner or the device printed things.

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/devconf"
)

// ShapeAlgo is the generation of the masking and hashing rules below. A
// store files each shape with it and its masked lines, so a later rule
// re-files every stored shape from its lines (ShapeHash) instead of carrying
// two hashers.
const ShapeAlgo = 1

// shapeSecretStatement stands for a secret line that did not say where its
// value is; such lines are never merged in a shape.
const shapeSecretStatement = "<secret statement>"

// shapeHashChars is the length of the hash a person sees.
const shapeHashChars = 12

// ShapeMasked stands for a per-device value in a shape's lines.
const ShapeMasked = "<v>"

// MaskRule names the values of a statement that belong to one device and not
// to the change (a location, a contact, a banner): in a shape the whole value
// is ShapeMasked, so two devices that need the same change have one shape.
type MaskRule struct {
	// Family is devconf.FamilyJunos or devconf.FamilyIOS.
	Family string
	// Prefix is the statement path before the value, space separated, the
	// verb ('set', 'delete', ...) left out; '?' is any one word (a name).
	Prefix string
	// Why says what the value is.
	Why string
}

// shapeMasks is the masking table as data (D135): each rule names where a
// per-device value stands. A label such as '<secret:2>' or '<other:1>' is not
// a value: it is kept, and so is a secret's mark, which Line.Shown has put in
// place of the value already.
var shapeMasks = []MaskRule{
	{devconf.FamilyJunos, "snmp location", "the device's location"},
	{devconf.FamilyJunos, "snmp contact", "the device's contact"},
	{devconf.FamilyJunos, "snmp description", "the device's description"},
	{devconf.FamilyJunos, "system host-name", "the device's name"},
	{devconf.FamilyJunos, "system login message", "the login message (device names and places)"},
	{devconf.FamilyJunos, "system tacplus-server ? source-address", "the device's own management address"},
	{devconf.FamilyJunos, "system radius-server ? source-address", "the device's own management address"},
	{devconf.FamilyIOS, "snmp-server location", "the device's location"},
	{devconf.FamilyIOS, "snmp-server contact", "the device's contact"},
	{devconf.FamilyIOS, "hostname", "the device's name"},
	{devconf.FamilyIOS, "banner login", "the login banner"},
	{devconf.FamilyIOS, "banner motd", "the message of the day"},
}

// ShapeMasks returns the masking table.
func ShapeMasks() []MaskRule { return slices.Clone(shapeMasks) }

// junosVerbs are the first words of a Junos statement that are not its path.
var junosVerbs = []string{"set", "delete", "insert", "deactivate", "activate"}

// maskShapeLine is a line's text with the value of a masking rule replaced.
// A text no rule matches (or that has nothing after the prefix) is returned
// unchanged.
func maskShapeLine(family, text string) string {
	toks := splitTokens(text)
	verb := ""
	if family == devconf.FamilyJunos && len(toks) > 0 && slices.Contains(junosVerbs, toks[0]) {
		verb, toks = toks[0], toks[1:]
	}
	for _, r := range shapeMasks {
		if r.Family != family {
			continue
		}
		pre := strings.Fields(r.Prefix)
		if len(toks) <= len(pre) {
			continue
		}
		ok := true
		for i, p := range pre {
			if p != "?" && p != toks[i] {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		out := append(slices.Clone(toks[:len(pre)]), ShapeMasked)
		s := joinTokens(out)
		if verb != "" {
			s = verb + " " + s
		}
		return s
	}
	return text
}

// Shape is a delta's identity: the hash a person sees (12 hex characters of
// the SHA-256 of the text) and the masked, canonical lines it is the hash
// of. Two devices that need the same change have the same shape.
//
// The lines are the delta's, each in the form a person may see (a secret's
// value elided, Line.Shown), each per-device value masked by the table of
// ShapeMasks, grouped under a '[section]' line in PlanOrder; within a section
// they are sorted and a repeated line is dropped for Junos (a release prints
// a hierarchy in another order than the plan wrote it, and the delta's own
// order is the paste order, which is not identity), and kept in the planner's
// order for IOS, where an access list's order is the change.
//
// A delta with no statement, and a WTI unit's plan (a checklist, not
// statements), have no shape: the hash is empty and so are the lines.
func Shape(d Delta) (hash string, lines []string) {
	if len(d.Lines) == 0 || d.WTI != nil || d.Vendor == devconf.FamilyWTI {
		return "", nil
	}
	by := map[string][]string{}
	var seen []string
	for _, l := range d.Lines {
		if l.Op == OpComment {
			continue
		}
		if _, ok := by[l.Section]; !ok {
			seen = append(seen, l.Section)
		}
		by[l.Section] = append(by[l.Section], shapeLine(d.Vendor, l))
	}
	var order []string
	for _, s := range PlanOrder(d.Vendor) {
		if _, ok := by[s]; ok {
			order = append(order, s)
		}
	}
	// a section that is not in the order (none is planned) goes last, by name
	var rest []string
	for _, s := range seen {
		if !slices.Contains(order, s) {
			rest = append(rest, s)
		}
	}
	sort.Strings(rest)
	order = append(order, rest...)
	for _, s := range order {
		ls := by[s]
		if d.Vendor != devconf.FamilyIOS {
			sort.Strings(ls)
			// a secret statement that has no elided form is one mark for
			// every value: they are counted, not merged, so one change of a
			// secret and two have different shapes
			ls = slices.CompactFunc(ls, func(a, b string) bool {
				return a == b && !strings.HasSuffix(a, shapeSecretStatement)
			})
		}
		lines = append(lines, "["+s+"]")
		lines = append(lines, ls...)
	}
	return ShapeHash(lines), lines
}

// shapeLine is one line of a shape: the shown text, masked, with an IOS
// line's submode headers in front.
func shapeLine(family string, l Line) string {
	text := l.Shown()
	if l.Secret && l.Elided == "" && l.HasValue {
		// a secret line that did not say where its value is: nothing of it
		// may reach a shape
		text = shapeSecretStatement
	} else {
		text = maskShapeLine(family, text)
	}
	switch l.Op {
	case OpNo:
		text = "no " + text
	}
	if len(l.Context) > 0 {
		text = strings.Join(l.Context, " > ") + " > " + text
	}
	return text
}

// ShapeHash is the hash of masked lines as Shape returns them: the 12-hex
// form of the SHA-256 of the lines, one per line. A store re-files its
// shapes through it when ShapeAlgo changes.
func ShapeHash(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n") + "\n"))
	return hex.EncodeToString(sum[:])[:shapeHashChars]
}
