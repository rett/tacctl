package policy

// Lint of a group's command rules (docs/plans/0.2.3-plan.md section 3b):
// the mistakes the tacquito probe of 2026-10-08 showed, found before a
// rule is rendered. tacquito tests a rule's 'match' regexes against the
// command's arguments (never the command word); it adds '^' and '$' when
// they are missing (tacctl now wraps every regex as ^(?:...)$ itself); a
// rule that does not match is skipped and the next one is tried; a rule
// without a match decides at once.

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding is one thing wrong or doubtful about a rule.
type Finding struct {
	Pos  int    // the rule's 1-based position in the group
	Line string // the rule line ('name|action|match,match')
	Msg  string
	// Error findings make the rule unusable (an empty or invalid regex);
	// the others are warnings.
	Error bool
}

// openEnd matches a regex whose last piece accepts any further arguments.
var openEnd = regexp.MustCompile(`(\.\*|\.\+|\( \.\*\)\?|\(\.\*\)\??)\)*$`)

// MatchProblems is what is wrong with one match regex of a rule: an empty
// or invalid one (Go's RE2, which is what tacquito uses) is an error; a prefix form that cannot match trailing arguments is a
// warning (the second result). A regex that begins with the command word
// is refused elsewhere (names.CommandMatchIsDead).
func MatchProblems(rx string) (errMsg, warnMsg string) {
	if rx == "" {
		return "the match is empty (tacquito skips an empty regex)", ""
	}
	if _, err := regexp.Compile(rx); err != nil {
		return "invalid regex: " + strings.TrimPrefix(err.Error(), "error parsing regexp: "), ""
	}
	if strings.HasSuffix(rx, "$") && !strings.HasSuffix(rx, `\$`) {
		return "", ""
	}
	if openEnd.MatchString(rx) {
		return "", ""
	}
	body := strings.TrimPrefix(rx, "^")
	group := body
	if strings.Contains(body, "|") && !wholeGroup(body) {
		group = "(" + body + ")"
	}
	return "", fmt.Sprintf("'%s' matches only the exact arguments '%s' (the whole arguments string is tested); "+
		"write '^%s( .*)?$' to allow trailing arguments, or end it with '$' if the exact match is meant", rx, body, group)
}

// wholeGroup reports whether s is one parenthesised group, "(...)".
func wholeGroup(s string) bool {
	if !strings.HasPrefix(s, "(") || !strings.HasSuffix(s, ")") {
		return false
	}
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 && i != len(s)-1 {
				return false
			}
		}
	}
	return depth == 0
}

// LintRules is the findings over a group's rule lines, in order: invalid
// matches, prefix forms without trailing arguments, and rules that can
// never be reached because an earlier rule of the same name has no match
// (or an earlier '*' decides everything).
func LintRules(lines []string) []Finding {
	var out []Finding
	matchless := map[string]int{} // name -> position of its first rule without a match
	catchall := 0
	for i, line := range lines {
		if blank(line) {
			continue
		}
		name := Field(line, 1)
		pos := i + 1
		var matches []string
		if m := ruleMatches(line); m != "" {
			matches = strings.Split(m, ",")
		}
		for _, rx := range matches {
			if e, w := MatchProblems(rx); e != "" {
				out = append(out, Finding{Pos: pos, Line: line, Msg: e, Error: true})
			} else if w != "" {
				out = append(out, Finding{Pos: pos, Line: line, Msg: w})
			}
		}
		switch {
		case catchall > 0:
			out = append(out, Finding{Pos: pos, Line: line,
				Msg: fmt.Sprintf("never reached: rule #%d '*' decides every command before it", catchall)})
		case name != Catchall && matchless[name] > 0:
			out = append(out, Finding{Pos: pos, Line: line,
				Msg: fmt.Sprintf("never reached: rule #%d '%s' has no match and decides every '%s' command first", matchless[name], name, name)})
		}
		if name == Catchall && catchall == 0 {
			catchall = pos
		}
		if len(matches) == 0 && name != Catchall && matchless[name] == 0 {
			matchless[name] = pos
		}
	}
	return out
}
