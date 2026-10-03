package shellquote

import "strings"

// UnmatchedQuoteError is xargs's refusal of an input with an unbalanced
// quote; Error is the text GNU xargs prints after "xargs: ".
type UnmatchedQuoteError struct{ Quote byte }

func (e *UnmatchedQuoteError) Error() string {
	kind := "single"
	if e.Quote == '"' {
		kind = "double"
	}
	return "unmatched " + kind + " quote; by default quotes are special to xargs unless you use the -0 option"
}

// XargsEcho is 'echo "$s" | xargs', the idiom the bash code trims list
// entries with: the blank-separated words of s, with xargs's quote and
// backslash processing, joined by single spaces. An unbalanced quote is an
// *UnmatchedQuoteError (xargs then prints its complaint and outputs
// nothing). Not reproduced: a word starting '-n' or '-e' that xargs's echo
// would take as an option.
func XargsEcho(s string) (string, error) {
	var words []string
	var cur strings.Builder
	inWord := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n': // xargs's blanks
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		case '\'', '"':
			j := strings.IndexByte(s[i+1:], c)
			if j < 0 {
				return "", &UnmatchedQuoteError{Quote: c}
			}
			cur.WriteString(s[i+1 : i+1+j])
			inWord = true
			i += j + 1
		case '\\':
			if i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
			}
			inWord = true
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, cur.String())
	}
	return strings.Join(words, " "), nil
}
