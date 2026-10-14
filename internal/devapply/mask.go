package devapply

import (
	"slices"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// secretMark stands for a secret's value in anything the package returns,
// logs or stores.
const secretMark = "<secret>"

// masker elides the secret values of a delta's lines from a text: the whole
// statement by its shown form, and each word of a statement's value
// wherever it stands (a device may echo a value in an error). It is
// defence in depth: the lines are logged by Line.Shown and the device's
// answers are cut to the error table's lines, and still nothing leaves the
// package without passing through it.
type masker struct {
	whole  []string // Text, Shown pairs (longest Text first)
	tokens []string // the value words, longest first
}

// newMasker learns the secrets of the lines: a secret line's Text against
// its Shown form.
func newMasker(lines []plan.Line) *masker {
	m := &masker{}
	for _, l := range lines {
		m.add(l)
	}
	return m
}

func (m *masker) add(l plan.Line) {
	if !l.Secret && !l.HasValue {
		return
	}
	shown := l.Shown()
	if shown == l.Text || (l.Secret && l.Elided == "") {
		// a secret line that does not say where its value is: every word of
		// it that is not a hierarchy word is taken for a value
		shown = ""
	}
	if l.Text != "" {
		m.whole = append(m.whole, l.Text, nonEmpty(shown, secretMark))
	}
	known := map[string]bool{}
	for _, w := range strings.Fields(shown) {
		known[strings.Trim(w, `"`)] = true
	}
	for _, w := range strings.Fields(l.Text) {
		bare := strings.Trim(w, `"`)
		if known[bare] || bare == "" || plainWord(bare) {
			continue
		}
		for _, t := range []string{w, bare} {
			if t != "" && !slices.Contains(m.tokens, t) {
				m.tokens = append(m.tokens, t)
			}
		}
	}
	sort.SliceStable(m.tokens, func(i, j int) bool { return len(m.tokens[i]) > len(m.tokens[j]) })
}

// plainWord is a word that is never a secret's value (a verb, a hierarchy
// word the shown form dropped with the value): kept so the masker does not
// erase every 'set' of a text.
func plainWord(w string) bool {
	switch w {
	case "set", "delete", "insert", "system", "snmp", "community", "secret", "tacplus-server", "radius-server",
		"authorization", "read-only", "read-write", "clients", "trap-group", "authentication-password", "privacy-password":
		return true
	}
	return false
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// minSubstring is the shortest value word masked wherever it stands; a
// shorter one (a community 'ro') is masked only as a whole field, or it would
// erase every word that holds its letters.
const minSubstring = 4

// text is s with every secret value elided: the whole statements, then each
// value word (as a substring, or as a whole field when it is short).
func (m *masker) text(s string) string {
	if m == nil {
		return s
	}
	for i := 0; i+1 < len(m.whole); i += 2 {
		s = strings.ReplaceAll(s, m.whole[i], m.whole[i+1])
	}
	for _, t := range m.tokens {
		if len(t) >= minSubstring {
			s = strings.ReplaceAll(s, t, secretMark)
		} else {
			s = replaceField(s, t)
		}
	}
	return s
}

// replaceField replaces each occurrence of t in s that stands as a field of
// its own: at the start or the end, or next to a byte that cannot be part of
// a value word (a space, a quote, punctuation).
func replaceField(s, t string) string {
	if t == "" {
		return s
	}
	var b strings.Builder
	from := 0 // s[:from] is written
	for at := 0; at < len(s); {
		k := strings.Index(s[at:], t)
		if k < 0 {
			break
		}
		i, end := at+k, at+k+len(t)
		if (i == 0 || fieldEdge(s[i-1])) && (end == len(s) || fieldEdge(s[end])) {
			b.WriteString(s[from:i])
			b.WriteString(secretMark)
			from, at = end, end
			continue
		}
		at = i + 1
	}
	b.WriteString(s[from:])
	return b.String()
}

// fieldEdge reports whether a byte ends a value word.
func fieldEdge(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c >= 0x80:
		return false
	}
	switch c {
	case '-', '_', '.', '/', '$', '@', '+', '=', '%', '#', '!', '*', '&', '^', '~':
		return false
	}
	return true
}

// lines masks each line.
func (m *masker) lines(ls []string) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = m.text(l)
	}
	return out
}

// holds reports whether s holds a secret value.
func (m *masker) holds(s string) bool { return m.text(s) != s }
