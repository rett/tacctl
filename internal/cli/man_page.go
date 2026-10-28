package cli

// The entries of the manual page, for 'tacctl man <word>...': the section
// headings (.SH, .SS) and the tags of the entries (the line after .TP and
// .TQ), read from the roff source with the reader of man_roff.go, and the
// search that puts the pager on one of them.
//
// The mechanism is a search in the pager, not an anchor of the page: roff
// has no anchors, and the page is plain text on a terminal. The pattern is
// made from the text of the entry found in the page, never from the words
// the person typed (the words only choose the entry), and only letters,
// digits and a few marks reach it as they are; any other character is
// written as '.', which matches it in every regular-expression flavour a
// pager may use, so the pattern needs no quoting anywhere.

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

// manTopic is one place of the page that a word can name.
type manTopic struct {
	// text is the heading or the tag as the page prints it (font escapes
	// and macros taken out).
	text    string
	heading bool
	// indent is the column the page prints the tag at (7 under a heading,
	// 14 inside one level of .RS ...); 0 when unknown.
	indent int
	// lead is the first word of the text that follows a tag narrower than
	// the tag column, on the same line.
	lead string
	// names are the lower-case words that name a heading: its text, and
	// each command of its parenthesised "(tacctl user)" group.
	names []string
	// tags are the lower-case forms of a tag, one per alternative of a
	// "{ a | b }" group.
	tags []string
}

// manCommandLike is the start of a tag that a word can name: a command, a
// family or a topic, not an option or a placeholder.
var manCommandLike = regexp.MustCompile(`^[a-z_]`)

var manGroup = regexp.MustCompile(`\(([^()]*tacctl[^()]*)\)`)

// manTopics reads the headings and tags of the page source, in page order.
func manTopics(src []byte) []manTopic {
	var out []manTopic
	wantTag := false
	depth := 0 // levels of .RS ... .RE
	lines := strings.Split(string(src), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, `.\"`) {
			continue
		}
		name, _, _ := strings.Cut(l, " ")
		switch {
		case l == ".TP", l == ".TQ":
			wantTag = true
			continue
		case name == ".RS":
			depth++
			continue
		case name == ".RE":
			depth = max(depth-1, 0)
			continue
		case name == ".SH", name == ".SS":
			wantTag, depth = false, 0
			if text, ok := manLineText(l); ok && text != "" {
				out = append(out, manHeadingTopic(text))
			}
			continue
		}
		if !wantTag {
			continue
		}
		wantTag = false
		if text, ok := manLineText(l); ok && manCommandLike.MatchString(text) {
			e := manTopic{text: text, indent: manTagColumn * (depth + 1)}
			if utf8.RuneCountInString(text) < manTagColumn {
				e.lead = manLead(lines[i+1:])
			}
			for _, v := range expandAlternatives(text) {
				e.tags = append(e.tags, strings.ToLower(v))
			}
			out = append(out, e)
		}
	}
	return out
}

// manLead is the first word of the first line of text in lines: what follows
// a short tag on its line.
func manLead(lines []string) string {
	for _, l := range lines {
		if strings.HasPrefix(l, `.\"`) {
			continue
		}
		text, ok := manLineText(l)
		if f := strings.Fields(text); ok && len(f) > 0 {
			return f[0]
		}
		return ""
	}
	return ""
}

// manHeadingTopic is the topic of a heading: it is named by its text and by the
// commands of its group ("User management (tacctl user)" is also "user";
// "(tacctl scope vendor-attrs, tacctl scope devices)" is both).
func manHeadingTopic(text string) manTopic {
	e := manTopic{text: text, heading: true, names: []string{strings.ToLower(text)}}
	for _, g := range manGroup.FindAllStringSubmatch(text, -1) {
		for _, c := range strings.Split(g[1], ",") {
			c = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(c), "tacctl "))
			if c != "" {
				e.names = append(e.names, strings.ToLower(c))
			}
		}
	}
	return e
}

// manLookup finds the entry that the words name, or false. In this order, the
// first of the page in each step wins: a heading with the words as its text,
// a heading whose group names the command (`man user` is "User management"),
// a tag that is the words or starts with them (`man device config plan` is
// the entry "device config plan <name> ...", `man version` the entry of the
// command and not the setting of the same name further on).
func manLookup(entries []manTopic, words []string) (manTopic, bool) {
	w := strings.ToLower(strings.Join(strings.Fields(strings.Join(words, " ")), " "))
	if w == "" {
		return manTopic{}, false
	}
	steps := []func(manTopic) bool{
		func(e manTopic) bool { return e.heading && e.names[0] == w },
		func(e manTopic) bool {
			if !e.heading {
				return false
			}
			for _, n := range e.names[1:] {
				if n == w {
					return true
				}
			}
			return false
		},
		func(e manTopic) bool {
			for _, t := range e.tags {
				if t == w || strings.HasPrefix(t, w+" ") {
					return true
				}
			}
			return false
		},
	}
	for _, step := range steps {
		for _, e := range entries {
			if step(e) {
				return e, true
			}
		}
	}
	return manTopic{}, false
}

// manPatternMax is how much of a tag the search holds: enough to tell the
// entries apart, short enough to stay on the line where the tag is printed.
const manPatternMax = 60

// manTagColumn is the width of the tag column of the page (.TP): a tag at
// least this wide has its text on the next line.
const manTagColumn = 7

// manLiteral are the characters of a pattern that stand for themselves in
// every regular-expression flavour (basic and extended POSIX, PCRE).
const manLiteral = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:,=/@%-"

// searchPattern is the search that puts a pager on the entry: the start of
// the line, the indentation the page gives it, then its text (a blank is any
// run of blanks, for text the page justified; a dot is a dot; a character
// that is not plainly literal is any character). A heading is the whole line
// when it fits, and so is a tag as wide as the tag column or wider; a longer
// tag is cut at manPatternMax characters, since the line goes on with its
// options. A tag is searched for at the column the page prints it at, and one
// narrower than the tag column (the text follows it on its line) with the
// first word of that text after it.
func (e manTopic) searchPattern() string {
	text, cut := e.text, false
	if utf8.RuneCountInString(text) > manPatternMax {
		cut = true
		r := []rune(text)[:manPatternMax]
		text = string(r)
		if i := strings.LastIndex(text, " "); i > 0 {
			text = text[:i]
		}
	}
	var b strings.Builder
	short := !e.heading && !cut && e.indent > 0 && utf8.RuneCountInString(text) < manTagColumn
	if !e.heading && e.indent > 0 {
		// Only the column of the tags is searched: a sentence, or a list the
		// page wrapped, that begins with the same words is further in.
		b.WriteString("^" + strings.Repeat(" ", e.indent))
	} else {
		b.WriteString("^ *")
	}
	manLiteralPattern(&b, text)
	switch {
	case short && e.lead != "":
		b.WriteString("  *")
		manLiteralPattern(&b, e.lead)
	case !cut && !short:
		// The line holds the heading or tag and nothing else.
		b.WriteString(" *$")
	}
	return b.String()
}

// manLiteralPattern writes text as a pattern: a blank is a run of blanks, a
// dot is a dot, any other character that is not plainly literal is any
// character.
func manLiteralPattern(b *strings.Builder, text string) {
	space := false
	for _, r := range text {
		switch {
		case r == ' ':
			if !space {
				b.WriteString("  *")
			}
			space = true
			continue
		case r == '.':
			b.WriteString(`\.`)
		case r < utf8.RuneSelf && strings.ContainsRune(manLiteral, r):
			b.WriteRune(r)
		default:
			b.WriteByte('.')
		}
		space = false
	}
}
