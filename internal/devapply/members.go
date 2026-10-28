package devapply

// The answers of a device with more than one member (a virtual chassis, two
// routing engines, a chassis cluster): a command that runs on every member
// prints one block per member, the member's label and its text on the next
// line, 'fpc0: ' and then 'configuration check succeeds'. The readers of a
// commit's answer take these blocks; an answer without a label reads as it
// always did. A device of exactly one member (a virtual chassis of one
// prints 'fpc0:' in 'show version') answers like a single device, without a
// label, and takes a block labelled with that member too (plainOK).

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// reMemberLabel is the line that opens a member's answer: the kind of
// member and its number, the forms the captures show ('fpc0:' of a virtual
// chassis, 're1:' of two routing engines, 'node0:' of a cluster). Group 1 is
// the label, group 2 its kind.
var reMemberLabel = regexp.MustCompile(`^((fpc|re|node)[0-9]+):$`)

// memberText is what one member printed, in order.
type memberText struct {
	label string
	texts []string
}

// splitMembers separates an answer into the lines no label opens and the
// members' lines, in the order the members first appear. A member's answer
// is the line after its label; a label with no line (the end of the answer,
// or another label) is a fault, named in why, and so are labels of two kinds
// in one answer.
func splitMembers(body []string) (plain []string, members []*memberText, why string) {
	nb := nonBlank(body)
	byLabel := map[string]*memberText{}
	kind := ""
	for i := 0; i < len(nb); i++ {
		l := strings.TrimSpace(nb[i])
		m := reMemberLabel.FindStringSubmatch(l)
		if m == nil {
			plain = append(plain, l)
			continue
		}
		if kind != "" && m[2] != kind {
			return plain, members, fmt.Sprintf("labels of two kinds, %s and %s", members[0].label, m[1])
		}
		kind = m[2]
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

// memberLabels reads the labels of a 'show version' answer: the lines that
// open a member's block, in order, none for a single device. Two kinds, or a
// label twice, is an error.
func memberLabels(ls []string) ([]string, error) {
	var labels []string
	kind := ""
	for _, l := range ls {
		m := reMemberLabel.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		if kind != "" && m[2] != kind {
			return nil, fmt.Errorf("show version: labels of two kinds, %s and %s: %w", labels[0], m[1], ErrUnrecognised)
		}
		if slices.Contains(labels, m[1]) {
			return nil, fmt.Errorf("show version: member %s twice: %w", m[1], ErrUnrecognised)
		}
		kind = m[2]
		labels = append(labels, m[1])
	}
	return labels, nil
}

// setFault compares the labels an answer names with the members the
// pre-flight's 'show version' listed: the missing and the unexpected ones
// are named. It is empty when they are the same set, and when the pre-flight
// listed none (a single device, which prints no label; an answer that names
// members there is judged by its blocks alone).
func setFault(set, got []string) string {
	if len(set) == 0 {
		return ""
	}
	var missing, unexpected []string
	for _, l := range set {
		if !slices.Contains(got, l) {
			missing = append(missing, l)
		}
	}
	for _, l := range got {
		if !slices.Contains(set, l) {
			unexpected = append(unexpected, l)
		}
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "no answer from "+strings.Join(missing, ", "))
	}
	if len(unexpected) > 0 {
		parts = append(parts, "an answer from "+strings.Join(unexpected, ", ")+", which 'show version' did not list")
	}
	if len(parts) == 0 {
		return ""
	}
	return "the members that answered are not the chassis' (" + strings.Join(set, ", ") + "): " + strings.Join(parts, "; ")
}

// setKind is the kind of the members the pre-flight listed ('fpc', 're',
// 'node'), "" for none. Two routing engines answer a plain commit, without
// 'commit synchronize', with the single device's lines, so a set of kind re
// takes either that or its blocks; a virtual chassis (fpc) and a cluster
// (node) of two or more members answer with blocks (plainOK).
func setKind(set []string) string {
	if len(set) == 0 {
		return ""
	}
	if m := reMemberLabel.FindStringSubmatch(set[0] + ":"); m != nil {
		return m[2]
	}
	return ""
}

// plainOK reports whether an answer without a member label is read for the
// set the pre-flight listed: the plain lines of a single device. It is for
// no members, for exactly one member of any kind (a virtual chassis of one
// member prints the header 'fpc0:' in 'show version' and answers a commit
// like a single device; a block labelled with that member is read too, and
// a label of another member is not), and for two routing engines. A chassis
// or a cluster of two or more members must name every member.
func plainOK(set []string) bool {
	return len(set) < 2 || setKind(set) == "re"
}

// labelsOf are the labels of the members of an answer.
func labelsOf(members []*memberText) []string {
	var ls []string
	for _, m := range members {
		ls = append(ls, m.label)
	}
	return ls
}

// checkAnswer reads the answer of 'commit check': 'configuration check
// succeeds' alone, or one block of it for every member and nothing else. set
// is the members 'show version' listed (none for a single device): the
// answer then names exactly those, each once; for one member and for two
// routing engines the plain answer is read too (plainOK). why names the member and the
// text that is no success, or the missing and unexpected members (empty
// when the answer has no member or is whole).
func checkAnswer(body []string, set []string) (ok bool, why string) {
	plain, members, why := splitMembers(body)
	switch {
	case why != "":
		return false, why
	case len(members) == 0 && !plainOK(set):
		return false, setFault(set, nil)
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
	if why := setFault(set, labelsOf(members)); why != "" {
		return false, why
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
// text that cannot be read. set is the members 'show version' listed (none
// for a single device): the answer names exactly those, and every one of
// them ends in 'commit complete', so the commit's members are the check's;
// for one member, and for two routing engines, the plain answer is read too
// (plainOK).
func readCommitted(body []string, set []string, want ...string) (ok bool, why string) {
	plain, members, why := splitMembers(body)
	switch {
	case why != "":
		return false, why
	case len(members) == 0 && !plainOK(set):
		return false, setFault(set, nil)
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
	if len(plain) > 0 && (len(notes) == 0 || inMembers || !exactly(plain, notes...)) {
		return false, fmt.Sprintf("a line %q outside the members' answers", cut(plain[0]))
	}
	if why := setFault(set, labelsOf(members)); why != "" {
		return false, why
	}
	if len(unfinished) > 0 {
		return false, fmt.Sprintf("member %s did not answer %q", unfinished[0], textCommitComplete)
	}
	if len(notes) > 0 && !inMembers && len(plain) == 0 {
		return false, fmt.Sprintf("no member and no line says %q", cut(notes[0]))
	}
	return true, ""
}
