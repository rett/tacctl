package cli

import (
	"regexp"
	"strings"
)

// Reading the manual page's roff source (man/tacctl.1) as a reader sees it:
// `tacctl man` finds the entry of a command in it, and the Man tests
// (man_test.go, man_gate_test.go, man_gen_test.go) check the page with the
// same reader, so what the command finds is what the tests hold to the code.

var (
	manFontEsc = regexp.MustCompile(`\\f[BIRP1-4]|\\\(..|\\[&|^]`)
	manSpaces  = regexp.MustCompile(`\s+`)
)

// manArgs splits the arguments of a roff macro line: words, or "quoted
// words" with "" for a quote inside.
func manArgs(s string) []string {
	var out []string
	for s = strings.TrimSpace(s); s != ""; s = strings.TrimSpace(s) {
		if s[0] == '"' {
			i := 1
			var b strings.Builder
			for i < len(s) {
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						b.WriteByte('"')
						i += 2
						continue
					}
					break
				}
				b.WriteByte(s[i])
				i++
			}
			out = append(out, b.String())
			if i < len(s) {
				i++
			}
			s = s[i:]
			continue
		}
		i := strings.IndexAny(s, " \t")
		if i < 0 {
			i = len(s)
		}
		out = append(out, s[:i])
		s = s[i:]
	}
	return out
}

// manClean is a source line's text as a reader sees it: font macros and
// escapes removed, white space squeezed.
func manClean(s string) string {
	s = strings.ReplaceAll(s, `\-`, "-")
	s = strings.ReplaceAll(s, `\e`, `\`)
	return strings.TrimSpace(manSpaces.ReplaceAllString(manFontEsc.ReplaceAllString(s, ""), " "))
}

// manLineText is the text a source line prints, cleaned; ok is false for a
// comment and for a macro that prints nothing of its own (.TP, .PP, .RS ...).
func manLineText(l string) (text string, ok bool) {
	switch {
	case strings.HasPrefix(l, `.\"`), l == ".TP":
		return "", false
	case strings.HasPrefix(l, "."):
		name, rest, _ := strings.Cut(l[1:], " ")
		args := manArgs(rest)
		switch name {
		case "B", "I", "SM", "SS", "SH":
			return manClean(strings.Join(args, " ")), true
		case "BI", "BR", "IR", "IB", "RB", "RI":
			return manClean(strings.Join(args, "")), true
		}
		return "", false
	}
	return manClean(l), true
}

var manAlternatives = regexp.MustCompile(`\{ ([a-z :-]+(?: \| [a-z :-]+)+) \}`)

// expandAlternatives turns "config allow { list | add } [cidr]" into one
// string per alternative ("config allow list [cidr]", ...); a string
// without a braced group is returned as it is.
func expandAlternatives(s string) []string {
	m := manAlternatives.FindStringSubmatchIndex(s)
	if m == nil {
		return []string{s}
	}
	var out []string
	for _, alt := range strings.Split(s[m[2]:m[3]], " | ") {
		out = append(out, expandAlternatives(s[:m[0]]+strings.TrimSpace(alt)+s[m[1]:])...)
	}
	return out
}
