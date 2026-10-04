package ui

import (
	"strings"
	"unicode/utf8"
)

// Echo is what bash's 'echo -e "<s>"' prints: s with its backslash escapes
// replaced (EchoE), then the newline echo adds, which a \c leaves out.
func Echo(s string) string {
	out, stop := EchoE(s)
	if stop {
		return out
	}
	return out + "\n"
}

// EchoE is what bash's 'echo -e' prints for s, without the newline it
// adds: the backslash escapes \a \b \e \E \f \n \r \t \v \\, \0nnn (up to
// three octal digits), \xHH (one or two hex digits), \uHHHH and \UHHHHHHHH
// (as UTF-8) are replaced, anything else is kept as written. \c ends the
// output: nothing after it is printed, not even echo's newline (stop).
// lib/core.sh's info/warn/error and many report lines of 0.1.16 print
// through 'echo -e', so a value holding "\t" reaches the terminal as a tab;
// Go lines built from such values pass through EchoE (or Echo) to print the
// same bytes.
func EchoE(s string) (out string, stop bool) {
	if !strings.Contains(s, `\`) {
		return s, false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := s[i]; e {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'e', 'E':
			b.WriteByte('\033')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case 'c':
			return b.String(), true
		case '0':
			v, n := 0, 0
			for n < 3 && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '7' {
				i++
				v = v*8 + int(s[i]-'0')
				n++
			}
			b.WriteByte(byte(v & 0xff))
		case 'x':
			v, n := 0, 0
			for n < 2 && i+1 < len(s) && isHex(s[i+1]) {
				i++
				v = v*16 + hexVal(s[i])
				n++
			}
			if n == 0 {
				b.WriteString(`\x`)
			} else {
				b.WriteByte(byte(v))
			}
		case 'u', 'U':
			limit := 4
			if e == 'U' {
				limit = 8
			}
			v, n := 0, 0
			for n < limit && i+1 < len(s) && isHex(s[i+1]) {
				i++
				v = v*16 + hexVal(s[i])
				n++
			}
			switch {
			case n == 0:
				b.WriteByte('\\')
				b.WriteByte(e)
			case v < 0x80:
				b.WriteByte(byte(v))
			default:
				var buf [utf8.UTFMax]byte
				b.Write(buf[:utf8.EncodeRune(buf[:], rune(v))])
			}
		default:
			b.WriteByte('\\')
			b.WriteByte(e)
		}
	}
	return b.String(), false
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	}
	return int(c-'A') + 10
}
