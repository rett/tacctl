package yamlpy

import (
	"strings"
	"unicode/utf8"
)

// scalarAnalysis is emitter.py's ScalarAnalysis.
type scalarAnalysis struct {
	scalar            string
	empty             bool
	multiline         bool
	allowFlowPlain    bool
	allowBlockPlain   bool
	allowSingleQuoted bool
	allowDoubleQuoted bool
	allowBlock        bool
}

// The character classes analyze_scalar tests with Python's 'in'.
const (
	pyBreaks          = "\n\u0085\u2028\u2029"
	pyWhitespaceOrEnd = "\x00 \t\r\n\u0085\u2028\u2029"
)

func runeIn(r rune, set string) bool { return strings.ContainsRune(set, r) }

// analyzeScalar is Emitter.analyze_scalar (PyYAML 6.0.1 emitter.py), line
// for line, with allow_unicode=False (safe_dump's default). It works on
// runes, as Python works on characters.
func analyzeScalar(scalar string) scalarAnalysis {
	// Empty scalar is a special case.
	if scalar == "" {
		return scalarAnalysis{scalar: scalar, empty: true, multiline: false,
			allowFlowPlain: false, allowBlockPlain: true,
			allowSingleQuoted: true, allowDoubleQuoted: true,
			allowBlock: false}
	}
	text := []rune(scalar)
	n := len(text)

	// Indicators and special characters.
	blockIndicators := false
	flowIndicators := false
	lineBreaks := false
	specialCharacters := false

	// Important whitespace combinations.
	leadingSpace := false
	leadingBreak := false
	trailingSpace := false
	trailingBreak := false
	breakSpace := false
	spaceBreak := false

	// Check document indicators.
	if strings.HasPrefix(scalar, "---") || strings.HasPrefix(scalar, "...") {
		blockIndicators = true
		flowIndicators = true
	}

	// First character or preceded by a whitespace.
	precededByWhitespace := true

	// Last character or followed by a whitespace.
	followedByWhitespace := n == 1 || runeIn(text[1], pyWhitespaceOrEnd)

	// The previous character is a space.
	previousSpace := false

	// The previous character is a break.
	previousBreak := false

	index := 0
	for index < n {
		ch := text[index]

		// Check for indicators.
		if index == 0 {
			// Leading indicators are special characters.
			if runeIn(ch, "#,[]{}&*!|>'\"%@`") {
				flowIndicators = true
				blockIndicators = true
			}
			if runeIn(ch, "?:") {
				flowIndicators = true
				if followedByWhitespace {
					blockIndicators = true
				}
			}
			if ch == '-' && followedByWhitespace {
				flowIndicators = true
				blockIndicators = true
			}
		} else {
			// Some indicators cannot appear within a scalar as well.
			if runeIn(ch, ",?[]{}") {
				flowIndicators = true
			}
			if ch == ':' {
				flowIndicators = true
				if followedByWhitespace {
					blockIndicators = true
				}
			}
			if ch == '#' && precededByWhitespace {
				flowIndicators = true
				blockIndicators = true
			}
		}

		// Check for line breaks, special, and unicode characters.
		if runeIn(ch, pyBreaks) {
			lineBreaks = true
		}
		// not (ch == '\n' or '\x20' <= ch <= '\x7E'):
		if ch != '\n' && (ch < '\x20' || ch > '\x7E') {
			// emitter.py tells printable unicode from the rest here, but
			// with allow_unicode=False both make the scalar special.
			specialCharacters = true
		}

		// Detect important whitespace combinations.
		switch {
		case ch == ' ':
			if index == 0 {
				leadingSpace = true
			}
			if index == n-1 {
				trailingSpace = true
			}
			if previousBreak {
				breakSpace = true
			}
			previousSpace = true
			previousBreak = false
		case runeIn(ch, pyBreaks):
			if index == 0 {
				leadingBreak = true
			}
			if index == n-1 {
				trailingBreak = true
			}
			if previousSpace {
				spaceBreak = true
			}
			previousSpace = false
			previousBreak = true
		default:
			previousSpace = false
			previousBreak = false
		}

		// Prepare for the next character.
		index++
		precededByWhitespace = runeIn(ch, pyWhitespaceOrEnd)
		followedByWhitespace = index+1 >= n || runeIn(text[index+1], pyWhitespaceOrEnd)
	}

	// Let's decide what styles are allowed.
	allowFlowPlain := true
	allowBlockPlain := true
	allowSingleQuoted := true
	allowDoubleQuoted := true
	allowBlock := true

	// Leading and trailing whitespaces are bad for plain scalars.
	if leadingSpace || leadingBreak || trailingSpace || trailingBreak {
		allowFlowPlain = false
		allowBlockPlain = false
	}

	// We do not permit trailing spaces for block scalars.
	if trailingSpace {
		allowBlock = false
	}

	// Spaces at the beginning of a new line are only acceptable for block
	// scalars.
	if breakSpace {
		allowFlowPlain = false
		allowBlockPlain = false
		allowSingleQuoted = false
	}

	// Spaces followed by breaks, as well as special character are only
	// allowed for double quoted scalars.
	if spaceBreak || specialCharacters {
		allowFlowPlain = false
		allowBlockPlain = false
		allowSingleQuoted = false
		allowBlock = false
	}

	// Although the plain scalar writer supports breaks, we never emit
	// multiline plain scalars.
	if lineBreaks {
		allowFlowPlain = false
		allowBlockPlain = false
	}

	// Flow indicators are forbidden for flow plain scalars.
	if flowIndicators {
		allowFlowPlain = false
	}

	// Block indicators are forbidden for block plain scalars.
	if blockIndicators {
		allowBlockPlain = false
	}

	return scalarAnalysis{scalar: scalar,
		empty: false, multiline: lineBreaks,
		allowFlowPlain:    allowFlowPlain,
		allowBlockPlain:   allowBlockPlain,
		allowSingleQuoted: allowSingleQuoted,
		allowDoubleQuoted: allowDoubleQuoted,
		allowBlock:        allowBlock}
}

// checkDomain reports whether s is inside the domain the emitter is
// verified on (docs/plans/go-rewrite.md 3.3): valid UTF-8 made of tab,
// printable ASCII and any rune from U+0080 up (written with PyYAML's
// escapes, as allow_unicode=False does), plus newlines that are neither
// first nor last. Everything else is refused rather than guessed at.
func checkDomain(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	i := 0
	for _, c := range s {
		if c == '\t' || (c >= 0x20 && c <= 0x7E) || c >= 0x80 {
			i++
			continue
		}
		if c == '\n' && i != 0 && i != n-1 {
			i++
			continue
		}
		return false
	}
	return true
}
