package shell

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/ui"
)

// The helpers that keep the widths right when a label or a description
// carries colour: a sequence 'ESC [ <digits and ;> m' takes no column, is
// never cut in two, and a style a cut leaves open is closed at the end of
// the piece and opened again at the start of the next.

var reSGR = regexp.MustCompile("\x1b\\[[0-9;]*m")

// stripSGR is s without its colour sequences.
func stripSGR(s string) string {
	if !strings.Contains(s, "\x1b[") {
		return s
	}
	return reSGR.ReplaceAllString(s, "")
}

// visLen is the number of columns s takes: its runes without the colour
// sequences.
func visLen(s string) int { return utf8.RuneCountInString(stripSGR(s)) }

// sgrAt reports the length of the colour sequence that starts at s[i] (0:
// none does).
func sgrAt(s string, i int) int {
	if s[i] != 0x1b || i+1 >= len(s) || s[i+1] != '[' {
		return 0
	}
	j := i + 2
	for j < len(s) && (s[j] == ';' || (s[j] >= '0' && s[j] <= '9')) {
		j++
	}
	if j < len(s) && s[j] == 'm' {
		return j + 1 - i
	}
	return 0
}

// track is the styles in effect after seq: a reset clears them.
func track(open, seq string) string {
	if seq == ui.NC || seq == "\x1b[m" {
		return ""
	}
	return open + seq
}

// cutVisible is the first n columns of s with every sequence in them (and
// those that follow the last rune, so a reset is kept), and a reset when a
// style is still open.
func cutVisible(s string, n int) string {
	var b strings.Builder
	open, cols := "", 0
	for i := 0; i < len(s); {
		if k := sgrAt(s, i); k > 0 {
			b.WriteString(s[i : i+k])
			open = track(open, s[i:i+k])
			i += k
			continue
		}
		if cols == n {
			break
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		b.WriteRune(r)
		cols++
		i += size
	}
	if open != "" {
		b.WriteString(ui.NC)
	}
	return b.String()
}

// carryStyle makes each line stand alone: a style open at the end of a line
// is closed there and opened again at the start of the next.
func carryStyle(lines []string) []string {
	if !slicesContainEsc(lines) {
		return lines
	}
	out := make([]string, len(lines))
	open := ""
	for i, l := range lines {
		line := open + l
		for j := 0; j < len(l); {
			if k := sgrAt(l, j); k > 0 {
				open = track(open, l[j:j+k])
				j += k
				continue
			}
			j++
		}
		if open != "" {
			line += ui.NC
		}
		out[i] = line
	}
	return out
}

func slicesContainEsc(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "\x1b[") {
			return true
		}
	}
	return false
}
