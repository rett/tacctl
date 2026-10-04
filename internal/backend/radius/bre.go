package radius

import (
	"regexp"
	"strings"
)

// grepError is a complaint of grep about a pattern, worded as grep words it.
type grepError string

func (e grepError) Error() string { return string(e) }

// compileBRE is the pattern of 'grep -i -e <term>': a POSIX basic regular
// expression with GNU's extensions (\| \+ \? and \< \> \w \s \b), matched
// without regard to case. It is translated to RE2; a construct RE2 does not
// have (a back-reference) is an error, as is a pattern grep itself would
// refuse.
func compileBRE(bre string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)")
	atStart := true // start of the pattern, or after \( or \|
	n := len(bre)
	for i := 0; i < n; {
		c := bre[i]
		next := func(s string) bool { return strings.HasPrefix(bre[i+1:], s) }
		switch c {
		case '\\':
			if i+1 >= n {
				return nil, grepError("Trailing backslash")
			}
			d := bre[i+1]
			i += 2
			switch d {
			case '(':
				b.WriteByte('(')
				atStart = true
				continue
			case '|':
				b.WriteByte('|')
				atStart = true
				continue
			case ')':
				b.WriteByte(')')
			case '{':
				end := strings.Index(bre[i:], `\}`)
				if end < 0 {
					return nil, grepError("Unmatched \\{")
				}
				inner := bre[i : i+end]
				if !regexp.MustCompile(`^[0-9]*(,[0-9]*)?$`).MatchString(inner) || inner == "" || inner == "," {
					return nil, grepError("Invalid content of \\{\\}")
				}
				b.WriteString("{" + inner + "}")
				i += end + 2
			case '+', '?':
				b.WriteByte(d)
			case '<', '>':
				b.WriteString(`\b`)
			case 'w', 'W', 's', 'S', 'b', 'B':
				b.WriteByte('\\')
				b.WriteByte(d)
			case '`':
				b.WriteString(`\A`)
			case '\'':
				b.WriteString(`\z`)
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				return nil, grepError("back-references are not supported")
			default:
				writeLiteral(&b, d)
			}
		case '[':
			end, class, err := bracket(bre, i)
			if err != nil {
				return nil, err
			}
			b.WriteString(class)
			i = end
		case '*':
			if atStart {
				b.WriteString(`\*`)
			} else {
				b.WriteByte('*')
			}
			i++
		case '.':
			b.WriteByte('.')
			i++
		case '^':
			if atStart {
				b.WriteByte('^')
				i++
				continue // a '*' after the anchor is still literal
			}
			b.WriteString(`\^`)
			i++
		case '$':
			if i+1 == n || next(`\)`) || next(`\|`) {
				b.WriteByte('$')
			} else {
				b.WriteString(`\$`)
			}
			i++
		default:
			writeLiteral(&b, c)
			i++
		}
		atStart = false
	}
	return regexp.Compile(b.String())
}

// writeLiteral writes the character c as itself.
func writeLiteral(b *strings.Builder, c byte) {
	if c >= 0x80 {
		b.WriteByte(c)
		return
	}
	b.WriteString(regexp.QuoteMeta(string(c)))
}

// bracket translates the bracket expression that starts at bre[i] ('['); end
// is the index after its closing ']'.
func bracket(bre string, i int) (end int, class string, err error) {
	var b strings.Builder
	b.WriteByte('[')
	j := i + 1
	if j < len(bre) && bre[j] == '^' {
		b.WriteByte('^')
		j++
	}
	first := true
	for j < len(bre) {
		c := bre[j]
		switch {
		case c == ']' && !first:
			b.WriteByte(']')
			return j + 1, b.String(), nil
		case c == '[' && j+1 < len(bre) && (bre[j+1] == ':' || bre[j+1] == '.' || bre[j+1] == '='):
			kind := bre[j+1]
			close := strings.Index(bre[j+2:], string(kind)+"]")
			if close < 0 {
				return 0, "", grepError("Unmatched [, [^, [:, [., or [=")
			}
			if kind != ':' {
				return 0, "", grepError("collating symbols and equivalence classes are not supported")
			}
			b.WriteString(bre[j : j+2+close+2])
			j += 2 + close + 2
		case c == '\\' || c == '[' || c == ']' || (c == '^' && !first):
			b.WriteByte('\\')
			b.WriteByte(c)
			j++
		default:
			b.WriteByte(c)
			j++
		}
		first = false
	}
	return 0, "", grepError("Unmatched [, [^, [:, [., or [=")
}
