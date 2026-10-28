package devapply

// The answers of a device with more than one member (a virtual chassis, two
// routing engines, a chassis cluster): a command that runs on every member
// prints one block per member, the member's label and its text on the next
// line, 'fpc0: ' and then 'configuration check succeeds'. The readers of a
// commit's answer take these blocks; an answer without a label reads as it
// always did.

import (
	"fmt"
	"regexp"
	"strings"
)

// reMemberLabel is the line that opens a member's answer: the kind of
// member and its number or role ('fpc0:', 're1:', 'node0:', 'member2:',
// 'lc3:', 'fpcmaster:').
var reMemberLabel = regexp.MustCompile(`^((?:fpc|re|node|member|lc|lcc|scc|sfc)(?:[0-9]+|master|backup)):$`)

// memberText is what one member printed, in order.
type memberText struct {
	label string
	texts []string
}

// splitMembers separates an answer into the lines no label opens and the
// members' lines, in the order the members first appear. A member's answer
// is the line after its label; a label with no line (the end of the answer,
// or another label) is a fault, named in why.
func splitMembers(body []string) (plain []string, members []*memberText, why string) {
	nb := nonBlank(body)
	byLabel := map[string]*memberText{}
	for i := 0; i < len(nb); i++ {
		l := strings.TrimSpace(nb[i])
		m := reMemberLabel.FindStringSubmatch(l)
		if m == nil {
			plain = append(plain, l)
			continue
		}
		if i+1 >= len(nb) || reMemberLabel.MatchString(strings.TrimSpace(nb[i+1])) {
			return plain, members, fmt.Sprintf("member %s has no answer", m[1])
		}
		i++
		mt := byLabel[m[1]]
		if mt == nil {
			mt = &memberText{label: m[1]}
			byLabel[m[1]] = mt
			members = append(members, mt)
		}
		mt.texts = append(mt.texts, cut(strings.TrimSpace(nb[i])))
	}
	return plain, members, ""
}

// checkAnswer reads the answer of 'commit check': 'configuration check
// succeeds' alone, or one block of it for every member and nothing else. why
// names the member and the text that is no success (empty when the answer
// has no member or is whole).
func checkAnswer(body []string) (ok bool, why string) {
	plain, members, why := splitMembers(body)
	switch {
	case why != "":
		return false, why
	case len(members) == 0:
		return exactly(body, textCheckOK), ""
	}
	for _, m := range members {
		for i, t := range m.texts {
			if t != textCheckOK {
				return false, fmt.Sprintf("member %s answered %q", m.label, t)
			}
			if i > 0 {
				return false, fmt.Sprintf("member %s answered %q twice", m.label, t)
			}
		}
	}
	if len(plain) > 0 {
		return false, fmt.Sprintf("a line %q outside the members' answers", cut(plain[0]))
	}
	return true, ""
}

// readCommitted reports whether a commit's answer is want, after the
// check's 'configuration check succeeds' that a commit prints first [C] (or
// without it). A device with members prints it for each of them (by
// analogy with the check's blocks and the commit of two routing engines;
// no capture of a commit's answer from one): every member's text is the
// check's success, optionally, then the commit's note, optionally, and last
// 'commit complete'; the note may also stand alone between the members'
// blocks, where the single device prints it. why names the member and the
// text that cannot be read.
func readCommitted(body []string, want ...string) (ok bool, why string) {
	plain, members, why := splitMembers(body)
	switch {
	case why != "":
		return false, why
	case len(members) == 0:
		return exactly(body, append([]string{textCheckOK}, want...)...) || exactly(body, want...), ""
	}
	var notes []string
	for _, w := range want {
		if w != textCommitComplete {
			notes = append(notes, w)
		}
	}
	// the stand-alone lines are the note, or none when the members print it
	inMembers := false
	var unfinished []string
	for _, m := range members {
		// every member's lines in order: check?, note?, complete
		stage := 0
		for _, t := range m.texts {
			rank := -1
			switch {
			case t == textCheckOK:
				rank = 1
			case len(notes) > 0 && t == notes[0]:
				rank, inMembers = 2, true
			case t == textCommitComplete:
				rank = 3
			}
			if rank < 0 {
				return false, fmt.Sprintf("member %s answered %q", m.label, t)
			}
			if rank <= stage {
				return false, fmt.Sprintf("member %s answered %q again or out of order", m.label, t)
			}
			stage = rank
		}
		if stage != 3 {
			unfinished = append(unfinished, m.label)
		}
	}
	if len(plain) > 0 && !(len(notes) > 0 && !inMembers && exactly(plain, notes...)) {
		return false, fmt.Sprintf("a line %q outside the members' answers", cut(plain[0]))
	}
	if len(unfinished) > 0 {
		return false, fmt.Sprintf("member %s did not answer %q", unfinished[0], textCommitComplete)
	}
	if len(notes) > 0 && !inMembers && len(plain) == 0 {
		return false, fmt.Sprintf("no member and no line says %q", cut(notes[0]))
	}
	return true, ""
}
