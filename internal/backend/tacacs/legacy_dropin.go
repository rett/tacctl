package tacacs

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/rendered"
)

// LegacyDropInKeys are the settings a hand-managed tacctl-overrides.conf
// may hold (LEGACY_DROPIN_KEYS).
var LegacyDropInKeys = []string{"TACQUITO_NETWORK", "TACQUITO_ADDRESS", "TACQUITO_LEVEL", "TACQUITO_METRICS_ADDRESS"}

// LegacyDropInValues is legacy_dropin_values (the 'legacy-dropin' command
// of the 0.1.16 render program): the settings of a hand-managed
// tacctl-overrides.conf, the drop-in of installs from before the listener
// model, as {TACQUITO_*: value}. Its Environment= lines are read as systemd
// reads them (shell-like words, quoted or not, several assignments to a
// line; the last assignment of a key wins). Any line that is not one of
// these settings (blank lines, comments and the [Service] header aside) is
// refused, by line: converting would drop it, or change which of two
// drop-ins wins. The refusal is a *rendered.Error; a file that cannot be
// read is the OS error (rendered.Report words both).
func LegacyDropInValues(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if !utf8.Valid(data) {
		return nil, &rendered.Error{Msg: path + ": not valid UTF-8"}
	}
	values := map[string]string{}
	var foreign []string
	for n, raw := range pySplitLines(string(data)) {
		line := py.Strip(raw)
		if line == "" || line[0] == '#' || line[0] == ';' || line == "[Service]" {
			continue
		}
		ours := false
		if rest, ok := strings.CutPrefix(line, "Environment="); ok {
			items, err := ShlexSplit(rest)
			if err != nil {
				items = nil
			}
			ours = len(items) > 0
			for _, item := range items {
				k, _, sep := strings.Cut(item, "=")
				if !sep || !slices.Contains(LegacyDropInKeys, k) {
					ours = false
				}
			}
			if ours {
				for _, item := range items {
					k, v, _ := strings.Cut(item, "=")
					values[k] = v
				}
			}
		}
		if !ours {
			foreign = append(foreign, "  line "+strconv.Itoa(n+1)+": "+line)
		}
	}
	if len(foreign) > 0 {
		return nil, &rendered.Error{Msg: path + " holds lines tacctl did not write and cannot carry over:\n" +
			strings.Join(foreign, "\n") +
			"\nMove them to a drop-in of your own in that directory (another .conf file) and run this again."}
	}
	return values, nil
}

// pySplitLines is Python's str.splitlines(): lines end at \n, \r, \r\n,
// \v, \f, \x1c, \x1d, \x1e, \x85, U+2028 and U+2029; the ends are dropped
// and no empty last line follows a final line end.
func pySplitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch r {
		case '\n', '\r', '\v', '\f', 0x1c, 0x1d, 0x1e, 0x85, 0x2028, 0x2029:
			out = append(out, s[start:i])
			i += size
			if r == '\r' && i < len(s) && s[i] == '\n' {
				i++
			}
			start = i
			continue
		}
		i += size
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// The errors of ShlexSplit (Python's ValueError texts, lower-cased).
var (
	ErrNoClosingQuotation = errors.New("shlex: no closing quotation")
	ErrNoEscapedCharacter = errors.New("shlex: no escaped character")
)

// ShlexSplit is Python's shlex.split(s) (POSIX mode, no comments): words
// separated by blanks (space, tab, CR, LF); single quotes keep everything
// literally; double quotes keep everything but a backslash before '"' or
// '\'; outside quotes a backslash keeps the next character literally;
// quoted parts join the word they touch, and an empty quoted word is a
// word ("").
func ShlexSplit(s string) ([]string, error) {
	const blanks = " \t\r\n"
	var words []string
	var word strings.Builder
	inWord := false // a word has begun (possibly empty, from quotes)
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		c := rs[i]
		switch {
		case strings.ContainsRune(blanks, c):
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		case c == '\\':
			if i+1 >= len(rs) {
				return nil, ErrNoEscapedCharacter
			}
			i++
			word.WriteRune(rs[i])
			inWord = true
		case c == '\'' || c == '"':
			inWord = true
			closed := false
			for i++; i < len(rs); i++ {
				d := rs[i]
				if d == c {
					closed = true
					break
				}
				if c == '"' && d == '\\' {
					if i+1 >= len(rs) {
						return nil, ErrNoEscapedCharacter
					}
					if next := rs[i+1]; next == '"' || next == '\\' {
						word.WriteRune(next)
						i++
						continue
					}
				}
				word.WriteRune(d)
			}
			if !closed {
				return nil, ErrNoClosingQuotation
			}
		default:
			word.WriteRune(c)
			inWord = true
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, nil
}
