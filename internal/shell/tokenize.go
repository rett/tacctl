package shell

import (
	"errors"
	"strings"
)

// The tokenizer of a shell line. It knows three things and nothing else:
// words are separated by blanks (space and tab), single quotes keep
// everything up to the next single quote, and a backslash keeps the next
// character (inside double quotes only before '"' or '\'). There is no
// expansion, globbing, pipe, redirection, command separator, history
// expansion or command substitution: '$', '`', ';', '|', '&', '<', '>',
// '!', '*', '~', '#', a newline and every non-ASCII space are ordinary
// characters of a word. A line is therefore always one tacctl command, and
// a metacharacter reaches tacctl as part of an argument, where it is an
// unknown command or an invalid name.

// The tokenizer's errors: a line that ends inside quotes or after a
// backslash.
var (
	ErrUnterminatedQuote = errors.New("unterminated quote")
	ErrTrailingBackslash = errors.New("line ends with a backslash")
)

// Tokenize splits line into words.
func Tokenize(line string) ([]string, error) {
	words, st := scan(line)
	switch {
	case st.quote != 0:
		return nil, ErrUnterminatedQuote
	case st.escape:
		return nil, ErrTrailingBackslash
	}
	return words, nil
}

// scanState is where scan stopped: inside a word (and where it started,
// in bytes), inside quotes, after a backslash.
type scanState struct {
	inWord    bool
	wordStart int
	quote     byte // '\'' or '"' when inside quotes
	escape    bool
	partial   string // the word being built at the end of the line
}

// isBlank reports whether c separates words.
func isBlank(c byte) bool { return c == ' ' || c == '\t' }

// scan is the tokenizer's loop; it also returns where it stopped, which
// completion needs for the word under the cursor.
func scan(line string) ([]string, scanState) {
	var words []string
	var cur strings.Builder
	var st scanState
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case st.escape:
			cur.WriteByte(c)
			st.escape = false
		case st.quote == '\'':
			if c == '\'' {
				st.quote = 0
			} else {
				cur.WriteByte(c)
			}
		case st.quote == '"':
			switch {
			case c == '"':
				st.quote = 0
			case c == '\\' && i+1 < len(line) && (line[i+1] == '"' || line[i+1] == '\\'):
				i++
				cur.WriteByte(line[i])
			case c == '\\' && i+1 == len(line):
				// A backslash at the end inside double quotes is still
				// inside the quotes: the quote is unterminated.
				cur.WriteByte(c)
			default:
				cur.WriteByte(c)
			}
		case isBlank(c):
			if st.inWord {
				words = append(words, cur.String())
				cur.Reset()
				st.inWord = false
			}
		default:
			if !st.inWord {
				st.inWord, st.wordStart = true, i
			}
			switch c {
			case '\\':
				st.escape = true
			case '\'', '"':
				st.quote = c
			default:
				cur.WriteByte(c)
			}
		}
	}
	if st.inWord && st.quote == 0 && !st.escape {
		words = append(words, cur.String())
	}
	st.partial = cur.String()
	return words, st
}

// Quote writes w so that Tokenize reads it back as one word: as it is
// when it holds no blank, quote or backslash, else in single quotes (a
// single quote inside closes them, is escaped with a backslash and opens
// them again).
func Quote(w string) string {
	if w != "" && !strings.ContainsAny(w, " \t'\"\\") {
		return w
	}
	return "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
}
