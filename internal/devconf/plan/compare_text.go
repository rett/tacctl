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
//   - a secret's value, and the name of an SNMP community or trap group
//     (which is the secret): '<secret>' stands in its place, so the
//     normalised text holds none and may be stored and shown.
//
// [A: the exact shape of a landed compare is WP14.0's L3 capture; every rule
// above is the Junos reference's and the helper's, and an unrecognised line
// is an error, never skipped.]

import (
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

// maskSecretTokens returns the words of a statement with a secret's value
// (or name) replaced by CompareSecretMark. The statement's own words are
// not changed.
func maskSecretTokens(toks []string) []string {
	out := slices.Clone(toks)
	for _, r := range compareSecrets {
		pat := strings.Fields(r.Pattern)
		if len(toks) < len(pat) {
			continue
		}
		ok, at := true, -1
		for i, p := range pat {
			switch p {
			case "?":
			case "*":
				at = i
			default:
				if toks[i] != p {
					ok = false
				}
			}
			if !ok {
				break
			}
		}
		if ok && at >= 0 {
			out[at] = CompareSecretMark
		}
	}
	for i := 0; i+1 < len(toks); i++ {
		if slices.Contains(secretWords, toks[i]) {
			out[i+1] = CompareSecretMark
		}
	}
	return out
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
// compare` and returns it normalised. A line it does not know is an error
// (fail closed): a caller never treats an unparsed text as an empty compare.
// An empty text is an empty compare.
func ParseCompare(text string) (CompareText, error) {
	var out []CompareStmt
	var base []string
	var stack []frame
	emit := func(op byte, words []string) {
		for _, w := range expandBrackets(words) {
			p := maskSecretTokens(w)
			if uidLeaf(p) {
				continue
			}
			out = append(out, CompareStmt{Op: op, Path: p})
		}
	}
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
		case body == "" || body == "..." || strings.HasPrefix(body, "##") || strings.HasPrefix(body, "/*"):
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
			stack = append(stack, frame{words: words, op: op})
		default:
			s, ok := stripStatement(body)
			if !ok || s == "" {
				return CompareText{}, fmt.Errorf("compare line %d: not a statement: %q", n+1, trimmed)
			}
			if op != 0 {
				emit(op, path(splitTokens(s)...))
				if len(stack) > 0 {
					stack[len(stack)-1].emitted = true
				}
			}
		}
	}
	if len(stack) > 0 {
		return CompareText{}, fmt.Errorf("compare: %d block(s) not closed", len(stack))
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := strings.Join(out[i].Path, " "), strings.Join(out[j].Path, " ")
		if a != b {
			return a < b
		}
		return out[i].Op < out[j].Op
	})
	out = slices.CompactFunc(out, func(a, b CompareStmt) bool {
		return a.Op == b.Op && slices.Equal(a.Path, b.Path)
	})
	return CompareText{Stmts: out}, nil
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
	return slices.EqualFunc(c.Stmts, o.Stmts, func(a, b CompareStmt) bool {
		return a.Op == b.Op && slices.Equal(a.Path, b.Path)
	})
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
// 'before|after term <t>' left off).
type deltaStatement struct {
	verb string
	path []string
}

func deltaStatements(d Delta) []deltaStatement {
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
			out = append(out, deltaStatement{verb, maskSecretTokens(p)})
		}
	}
	return out
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
//     under, or by a set line of the same leaf with another value (a
//     single-valued leaf is replaced in place);
//   - a changed or reordered ('!') statement by a line of the same
//     hierarchy, either way.
//
// [A: L3] the rules are the Junos reference's; WP14.0 settles them against a
// capture.
func (c CompareText) Unexplained(d Delta) []string {
	ds := deltaStatements(d)
	var out []string
	for _, s := range c.Stmts {
		ok := false
		for _, x := range ds {
			switch s.Op {
			case '+':
				ok = (x.verb == "set" || x.verb == "insert") && under(s.Path, x.path)
			case '-':
				ok = x.verb == "delete" && under(s.Path, x.path) ||
					x.verb == "set" && len(x.path) == len(s.Path) && len(x.path) > 1 &&
						slices.Equal(x.path[:len(x.path)-1], s.Path[:len(s.Path)-1])
			default:
				ok = related(x.path, s.Path)
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
