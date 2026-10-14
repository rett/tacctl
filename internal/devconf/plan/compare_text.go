package plan

// The text of a Junos `show | compare` (and of `show system rollback compare
// 1 0`), parsed into statements and normalised so two of them can be
// compared for equality and each can be held against the delta that was
// meant to produce it (0.2.9 plan D135, the landed check).
//
// What is dropped or folded, as the helper script did:
//
//   - the `{master:0}` line a switch prints before a prompt, `...` lines,
//     `##` annotations and the trailing `## SECRET-DATA` of a statement;
//   - the `uid N;` leaf Junos adds under a login user it created (a landed
//     compare has it, the check's has not);
//   - the brace layout: every `+`, `-` or `!` leaf becomes one statement
//     with its whole path, a bracket list is one statement per item, and the
//     statements are sorted, so the order a release prints hierarchies in is
//     not identity;
//   - a secret's value: '<secret>' stands in its place; and the name of an
//     SNMP community or trap group (which is the secret): '<secret:N>'
//     stands in its place, N numbering the distinct names by their first
//     appearance in the delta (ParseCompareFor), so the normalised text
//     holds none and may be stored and shown, and two names are two marks.
//     A statement also carries, unseen, an identity of its names, so Equal
//     and Unexplained tell them apart however they are numbered;
//   - an added or removed '/* ... */' annotation is a statement of its own
//     (CompareAnnotationMark), never skipped: no delta line explains it.
//
// [A: the exact shape of a landed compare is WP14.0's L3 capture; every rule
// above is the Junos reference's and the helper's, and an unrecognised line
// is an error, never skipped.]

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
)

// CompareStmt is one statement of a compare: an Op ('+' added, '-' removed,
// '!' changed or reordered) and the statement's whole path, a secret masked.
type CompareStmt struct {
	Op   byte
	Path []string
}

// Text is the statement as one line: the Op, a space, the words.
func (s CompareStmt) Text() string { return string(s.Op) + " " + strings.Join(s.Path, " ") }

// CompareText is a normalised compare: statements sorted by path then op,
// none repeated.
type CompareText struct {
	Stmts []CompareStmt
	// ids is, aligned with Stmts, each statement's path with a community's or
	// trap group's name (and an annotation's text) as a digest of it: what
	// Equal and Unexplained compare, so two names are never alike whatever
	// number the display gave them. Empty for a CompareText not made by
	// ParseCompare: the paths are compared.
	ids [][]string
}

// ident is the identity path of statement i.
func (c CompareText) ident(i int) []string {
	if i < len(c.ids) && len(c.ids[i]) == len(c.Stmts[i].Path) {
		return c.ids[i]
	}
	return c.Stmts[i].Path
}

// CompareAnnotationMark stands for the text of an annotation ('/* ... */')
// that a compare shows added or removed.
const CompareAnnotationMark = "/* annotation */"

// identOf is the unseen identity of a raw word: a digest, with a prefix no
// printed word has.
func identOf(kind, raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "\x00" + kind + ":" + hex.EncodeToString(sum[:8])
}

// CompareSecretMark stands for a secret's value in a normalised compare.
const CompareSecretMark = "<secret>"

// secretRule says where a secret stands in a Junos statement: Pattern is the
// path from its start, '?' any one word, '*' the word that is the secret
// (the rest of the statement, if any, follows it).
type secretRule struct {
	Pattern string
	Why     string
}

// compareSecrets are the statements whose value or name the device stores
// encrypted or hashed, so a compare prints the encrypted form and a
// community's name in clear. The test of this table holds it against every
// statement the rendering flags as a secret (devices.Section.Secret).
var compareSecrets = []secretRule{
	{"system tacplus-server ? secret *", "a TACACS+ server's secret"},
	{"system radius-server ? secret *", "a RADIUS server's secret"},
	{"snmp community *", "an SNMP community: its name is the secret"},
	{"snmp trap-group *", "an SNMP trap group: its name is the community its traps use"},
	{"snmp v3 usm local-engine user ? ? authentication-password *", "an SNMPv3 user's authentication password"},
	{"snmp v3 usm local-engine user ? ? privacy-password *", "an SNMPv3 user's privacy password"},
	{"system ntp authentication-key ? value *", "an NTP key's value"},
	{"system ntp authentication-key ? type ? value *", "an NTP key's value"},
	{"system login user ? authentication ? *", "a local user's hash or public key"},
	{"system login user ? class ? authentication ? *", "a local user's hash"},
}

// secretWords are words whose next word is a secret wherever they stand (a
// statement of a hierarchy the table above does not name).
var secretWords = []string{"secret", "encrypted-password", "plain-text-password", "authentication-password", "privacy-password"}

// isNameRule reports whether a rule's secret is a name (a community's or a
// trap group's): it is shown numbered, not as the constant mark.
func isNameRule(r secretRule) bool {
	return strings.HasPrefix(r.Pattern, "snmp community ") || strings.HasPrefix(r.Pattern, "snmp trap-group ")
}

// ruleAt returns the index of the secret word of a rule that the statement
// matches (-1: it does not).
func ruleAt(r secretRule, toks []string) int {
	pat := strings.Fields(r.Pattern)
	if len(toks) < len(pat) {
		return -1
	}
	at := -1
	for i, p := range pat {
		switch p {
		case "?":
		case "*":
			at = i
		default:
			if toks[i] != p {
				return -1
			}
		}
	}
	return at
}

// maskSecretTokens returns the words of a statement with a secret's value
// (or name) replaced by CompareSecretMark. The statement's own words are
// not changed.
func maskSecretTokens(toks []string) []string {
	shown, _ := maskTokens(toks, nil)
	return shown
}

// maskTokens is maskSecretTokens with the name of a community or trap group
// given by label (nil: the constant mark), and the identity path: the words
// with each name as a digest of it, each secret value as the mark.
func maskTokens(toks []string, label func(raw string) string) (shown, ident []string) {
	shown, ident = slices.Clone(toks), slices.Clone(toks)
	for _, r := range compareSecrets {
		at := ruleAt(r, toks)
		if at < 0 {
			continue
		}
		if isNameRule(r) {
			shown[at], ident[at] = CompareSecretMark, identOf("name", toks[at])
			if label != nil {
				shown[at] = label(toks[at])
			}
			continue
		}
		shown[at], ident[at] = CompareSecretMark, CompareSecretMark
	}
	for i := 0; i+1 < len(toks); i++ {
		if slices.Contains(secretWords, toks[i]) {
			shown[i+1], ident[i+1] = CompareSecretMark, CompareSecretMark
		}
	}
	return shown, ident
}

// nameOf returns the name of a community or trap group of a statement, if it
// has one.
func nameOf(toks []string) (string, bool) {
	for _, r := range compareSecrets {
		if !isNameRule(r) {
			continue
		}
		if at := ruleAt(r, toks); at >= 0 {
			return toks[at], true
		}
	}
	return "", false
}

// secretLabels numbers the names of a delta by first appearance: the same
// numbering a plan's elided lines carry ('<secret:1>'). Names the compare
// holds that the delta does not are numbered after them, in the order of the
// names (so two compares of one device agree whatever order the release
// printed them in).
type secretLabels struct {
	n map[string]int
}

func newSecretLabels(d Delta) *secretLabels {
	l := &secretLabels{n: map[string]int{}}
	for _, ds := range deltaStatementsOf(d, nil) {
		if name, ok := nameOf(ds.raw); ok {
			l.add(name)
		}
	}
	return l
}

func (l *secretLabels) add(name string) {
	if _, ok := l.n[name]; !ok {
		l.n[name] = len(l.n) + 1
	}
}

func (l *secretLabels) label(name string) string {
	return fmt.Sprintf("<secret:%d>", l.n[name])
}

// uidLeaf reports the 'system login user <x> uid <n>' statement Junos adds
// to a landed compare.
func uidLeaf(p []string) bool {
	if len(p) != 6 || p[0] != "system" || p[1] != "login" || p[2] != "user" || p[4] != "uid" {
		return false
	}
	for _, c := range p[5] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return p[5] != ""
}

// stripStatement cuts a leaf line at its ';' outside double quotes: what
// follows must be nothing or a '##' annotation.
func stripStatement(body string) (stmt string, ok bool) {
	in, esc := false, false
	for i := 0; i < len(body); i++ {
		c := body[i]
		switch {
		case esc:
			esc = false
		case in && c == '\\':
			esc = true
		case c == '"':
			in = !in
		case c == ';' && !in:
			rest := strings.TrimSpace(body[i+1:])
			return strings.TrimSpace(body[:i]), rest == "" || strings.HasPrefix(rest, "##")
		}
	}
	return "", false
}

// frame is an open block of the brace text.
type frame struct {
	words   []string
	op      byte
	emitted bool
}

// ParseCompare reads the text of a `show | compare` or `show system rollback
// compare` and returns it normalised, the names of communities and trap
// groups numbered in the order of the names. A line it does not know is an
// error (fail closed): a caller never treats an unparsed text as an empty
// compare. An empty text is an empty compare.
func ParseCompare(text string) (CompareText, error) {
	return ParseCompareFor(text, Delta{})
}

// rawStmt is a statement as parsed, before its names are numbered.
type rawStmt struct {
	op    byte
	words []string
	// ann is the text of an annotation (words is the path it stands in).
	ann    string
	isNote bool
}

// ParseCompareFor is ParseCompare with the names numbered by their first
// appearance in the delta's text: a compare's '<secret:N>' is then the
// number the plan's elided lines have for the same name. Use it for the
// compare of a delta's own rollout; the identity of the names does not
// depend on the numbers.
func ParseCompareFor(text string, d Delta) (CompareText, error) {
	var raws []rawStmt
	var base []string
	var stack []frame
	emit := func(op byte, words []string) {
		for _, w := range expandBrackets(words) {
			if uidLeaf(w) {
				continue
			}
			raws = append(raws, rawStmt{op: op, words: w})
		}
	}
	// the op a line stands under: its own, else the block's
	inherit := func(op byte) byte {
		if op == 0 && len(stack) > 0 {
			return stack[len(stack)-1].op
		}
		return op
	}
	inNote := false
	path := func(extra ...string) []string {
		p := slices.Clone(base)
		for _, f := range stack {
			p = append(p, f.words...)
		}
		return append(p, extra...)
	}
	for n, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if inNote {
			// the rest of a '/* ... */' annotation of several lines
			if strings.Contains(line, "*/") {
				inNote = false
			}
			continue
		}
		switch {
		case trimmed == "":
			continue
		case strings.HasPrefix(trimmed, "{") && strings.HasSuffix(trimmed, "}") && !strings.Contains(trimmed, " "):
			// {master:0}, {primary:node0}: a prompt's prefix
			continue
		case strings.HasPrefix(line, "[edit"):
			if !strings.HasSuffix(line, "]") {
				return CompareText{}, fmt.Errorf("compare line %d: an unclosed [edit] header", n+1)
			}
			if len(stack) > 0 {
				return CompareText{}, fmt.Errorf("compare line %d: a header inside an open block", n+1)
			}
			base = splitTokens(strings.TrimSuffix(strings.TrimPrefix(line, "[edit"), "]"))
			continue
		}
		var op byte
		body := line
		switch line[0] {
		case '+', '-', '!':
			op, body = line[0], line[1:]
		case ' ', '\t':
		default:
			return CompareText{}, fmt.Errorf("compare line %d: not a compare line: %q", n+1, trimmed)
		}
		body = strings.TrimSpace(body)
		switch {
		case body == "" || body == "..." || strings.HasPrefix(body, "##"):
			continue
		case strings.HasPrefix(body, "/*"):
			// an annotation: a change of it is a change of the
			// configuration, and it is named, not skipped
			if eff := inherit(op); eff != 0 {
				raws = append(raws, rawStmt{op: eff, words: path(), ann: body, isNote: true})
				if len(stack) > 0 {
					stack[len(stack)-1].emitted = true
				}
			}
			if !strings.Contains(body, "*/") {
				inNote = true
			}
			continue
		case body == "}":
			if len(stack) == 0 {
				return CompareText{}, fmt.Errorf("compare line %d: a closing brace with no block", n+1)
			}
			f := stack[len(stack)-1]
			if f.op != 0 && !f.emitted {
				// an added or removed block with nothing in it is a statement
				emit(f.op, path())
			}
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && f.emitted {
				stack[len(stack)-1].emitted = true
			}
		case strings.HasSuffix(body, "{"):
			words := splitTokens(strings.TrimSpace(strings.TrimSuffix(body, "{")))
			if len(words) == 0 {
				return CompareText{}, fmt.Errorf("compare line %d: a block with no name", n+1)
			}
			stack = append(stack, frame{words: words, op: inherit(op)})
		default:
			s, ok := stripStatement(body)
			if !ok || s == "" {
				return CompareText{}, fmt.Errorf("compare line %d: not a statement: %q", n+1, trimmed)
			}
			// a leaf with no op of its own inside an added or removed block
			// is the block's
			if eff := inherit(op); eff != 0 {
				emit(eff, path(splitTokens(s)...))
				if len(stack) > 0 {
					stack[len(stack)-1].emitted = true
				}
			}
		}
	}
	if len(stack) > 0 {
		return CompareText{}, fmt.Errorf("compare: %d block(s) not closed", len(stack))
	}
	// the names: the delta's first, in its order; then the compare's own, in
	// the order of the names
	labels := newSecretLabels(d)
	var extra []string
	for _, r := range raws {
		if name, ok := nameOf(r.words); ok {
			if _, in := labels.n[name]; !in && !slices.Contains(extra, name) {
				extra = append(extra, name)
			}
		}
	}
	sort.Strings(extra)
	for _, name := range extra {
		labels.add(name)
	}
	type item struct {
		stmt  CompareStmt
		ident []string
	}
	items := make([]item, 0, len(raws))
	for _, r := range raws {
		shown, ident := maskTokens(r.words, labels.label)
		if r.isNote {
			shown = append(shown, CompareAnnotationMark)
			ident = append(ident, identOf("note", r.ann))
		}
		items = append(items, item{CompareStmt{Op: r.op, Path: shown}, ident})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := strings.Join(items[i].stmt.Path, " "), strings.Join(items[j].stmt.Path, " ")
		if a != b {
			return a < b
		}
		if items[i].stmt.Op != items[j].stmt.Op {
			return items[i].stmt.Op < items[j].stmt.Op
		}
		return slices.Compare(items[i].ident, items[j].ident) < 0
	})
	items = slices.CompactFunc(items, func(a, b item) bool {
		return a.stmt.Op == b.stmt.Op && slices.Equal(a.stmt.Path, b.stmt.Path) && slices.Equal(a.ident, b.ident)
	})
	c := CompareText{}
	for _, it := range items {
		c.Stmts = append(c.Stmts, it.stmt)
		c.ids = append(c.ids, it.ident)
	}
	return c, nil
}

// NormaliseCompare is ParseCompare's text: the statements one per line, with
// no secret in them.
func NormaliseCompare(text string) (string, error) {
	c, err := ParseCompare(text)
	if err != nil {
		return "", err
	}
	return c.String(), nil
}

// Empty reports whether the compare changes nothing.
func (c CompareText) Empty() bool { return len(c.Stmts) == 0 }

// String is the normalised text: '<op> <statement>' per line, sorted.
func (c CompareText) String() string {
	var b strings.Builder
	for _, s := range c.Stmts {
		b.WriteString(s.Text())
		b.WriteByte('\n')
	}
	return b.String()
}

// Equal reports whether two compares hold the same statements: the landed
// check (what landed is the change the check showed).
func (c CompareText) Equal(o CompareText) bool {
	if len(c.Stmts) != len(o.Stmts) {
		return false
	}
	for i, a := range c.Stmts {
		b := o.Stmts[i]
		if a.Op != b.Op || !slices.Equal(a.Path, b.Path) || !slices.Equal(c.ident(i), o.ident(i)) {
			return false
		}
	}
	return true
}

// related reports whether one path is the other or a prefix of it.
func related(a, b []string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	return slices.Equal(a, b[:len(a)])
}

// deltaStatement is a Junos line of a delta as the compare would show it:
// the verb and the path (a secret masked, a list expanded, an insert's
// 'before|after term <t>' left off); ident is the path with each name as the
// digest a compare's statements carry, raw the words as typed.
type deltaStatement struct {
	verb  string
	path  []string
	ident []string
	raw   []string
}

func deltaStatements(d Delta) []deltaStatement { return deltaStatementsOf(d, nil) }

func deltaStatementsOf(d Delta, label func(string) string) []deltaStatement {
	var out []deltaStatement
	for _, l := range d.Lines {
		toks := splitTokens(l.Text)
		if len(toks) < 2 {
			continue
		}
		verb, path := toks[0], toks[1:]
		switch verb {
		case "set", "delete":
		case "insert":
			if len(path) > 3 {
				path = path[:len(path)-3]
			}
		default:
			continue
		}
		for _, p := range expandBrackets(path) {
			shown, ident := maskTokens(p, label)
			out = append(out, deltaStatement{verb: verb, path: shown, ident: ident, raw: p})
		}
	}
	return out
}

// replacedInPlace says whether a statement is a single-valued leaf: its set
// with another value replaces the one it removes. A leaf is single-valued
// when its row of the ownership table is ModeSingle (the row's pattern, then
// the value) or is one of the leaves the planner sets under a whole or
// rendered-leaves object, below. A multi-valued element (an NTP server, a
// source-address of a term, a client) is never replaced by a set of another:
// its removal is explained by a matching delete.
func replacedInPlace(path []string) bool {
	for _, r := range junosOwned {
		pat := strings.Fields(r.Pattern)
		if _, _, ok := matchPrefix(pat, path); !ok {
			continue
		}
		if r.Mode == ModeSingle && len(path) == len(pat)+1 {
			return true
		}
		if len(path) == len(pat)+2 && slices.Contains(singleLeaves[r.ID], path[len(pat)]) {
			return true
		}
	}
	return false
}

// singleLeaves are the single-valued leaves of the objects a plan sets
// beside their other statements (the tables' ModeWhole and
// ModeRenderedLeaves rows), by row.
var singleLeaves = map[string][]string{
	"junos.aaa.tacplus":          {"secret"},
	"junos.aaa.radius":           {"secret", "port", "accounting-port"},
	"junos.roles.class":          {"idle-timeout"},
	"junos.snmp.community":       {"authorization", "client-list-name"},
	"junos.snmp.block-community": {"authorization", "client-list-name"},
	"junos.snmp.trap-group":      {"version"},
}

// Unexplained returns the statements of the compare that no line of the
// delta accounts for, as '<op> <statement>' lines (nothing when the compare
// is what the delta was meant to produce, or less: a statement the device
// already had shows nothing). It is the tripwire of a check: a compare that
// holds a change outside the delta (a stranger's staged work, a statement
// the device normalised into something else) is not the reviewed change.
//
//   - an added statement is explained by a set line of the same path, or by
//     a set or insert line of an object it lies under;
//   - a removed statement by a delete line of it or of an object it lies
//     under, or, for a single-valued leaf only (the ownership table says
//     which), by a set line of the same leaf with another value (it is
//     replaced in place); a removed element of a list (an NTP server, a
//     source-address) is explained by a delete and by nothing else;
//   - an annotation added or removed by no line: a delta has none;
//   - a changed or reordered ('!') statement by a line of the same
//     hierarchy, either way.
//
// [A: L3] the rules are the Junos reference's; WP14.0 settles them against a
// capture.
func (c CompareText) Unexplained(d Delta) []string {
	ds := deltaStatements(d)
	var out []string
	for i, s := range c.Stmts {
		id := c.ident(i)
		ok := false
		if n := len(s.Path); n > 0 && s.Path[n-1] == CompareAnnotationMark {
			// nothing a delta types explains an annotation
			out = append(out, s.Text())
			continue
		}
		for _, x := range ds {
			switch s.Op {
			case '+':
				ok = (x.verb == "set" || x.verb == "insert") && under(id, x.ident)
			case '-':
				ok = x.verb == "delete" && under(id, x.ident) ||
					x.verb == "set" && len(x.ident) == len(id) && len(x.ident) > 1 &&
						slices.Equal(x.ident[:len(x.ident)-1], id[:len(id)-1]) && replacedInPlace(s.Path)
			default:
				ok = related(x.ident, id)
			}
			if ok {
				break
			}
		}
		if !ok {
			out = append(out, s.Text())
		}
	}
	return out
}

// under reports whether path is the object or the statement itself.
func under(path, object []string) bool {
	return len(object) <= len(path) && slices.Equal(object, path[:len(object)])
}
