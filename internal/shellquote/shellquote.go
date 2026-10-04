// Package shellquote reproduces bash's 'printf %q': the quoting that writes
// a value into a shell script so the shell reads it back unchanged
// (lib/linux_hosts.sh builds the host installer's TAC_* header with it).
//
// Q matches bash 5.2 byte for byte for every ASCII string and for any string
// when bash runs in the C locale. In a UTF-8 locale bash writes printable
// non-ASCII characters unquoted, where Q always spells every byte >= 0x80
// as an octal escape inside $'...'; the shell reads both back as the same
// bytes, so the installer behaves the same, only the text of the script
// differs.
package shellquote

import (
	"fmt"
	"strings"
)

// backslashed are the printable ASCII characters %q escapes with a backslash
// wherever they appear. '#' (at the start) and '~' (at the start or after ':'
// or '=') are escaped by position, see Q.
const backslashed = " !\"$&'()*,;<>?[\\]^`{|}"

// Q is the value as 'printf %q' prints it: "”" for the empty string,
// $'...' (ANSI-C quoting) when any byte is a control character, DEL or
// non-ASCII, otherwise the value with a backslash before each shell-special
// character.
func Q(s string) string {
	if s == "" {
		return "''"
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] >= 0x7f {
			return ansiC(s)
		}
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case strings.IndexByte(backslashed, c) >= 0,
			c == '#' && i == 0,
			c == '~' && (i == 0 || s[i-1] == ':' || s[i-1] == '='):
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

func ansiC(s string) string {
	var b strings.Builder
	b.WriteString("$'")
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\a':
			b.WriteString(`\a`)
		case '\b':
			b.WriteString(`\b`)
		case '\t':
			b.WriteString(`\t`)
		case '\n':
			b.WriteString(`\n`)
		case '\v':
			b.WriteString(`\v`)
		case '\f':
			b.WriteString(`\f`)
		case '\r':
			b.WriteString(`\r`)
		case 0x1b:
			b.WriteString(`\E`)
		case '\\':
			b.WriteString(`\\`)
		case '\'':
			b.WriteString(`\'`)
		default:
			if c < 0x20 || c >= 0x7f {
				fmt.Fprintf(&b, `\%03o`, c)
			} else {
				b.WriteByte(c)
			}
		}
	}
	b.WriteByte('\'')
	return b.String()
}
