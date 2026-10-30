package devapply

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// The replies of a virtual chassis of three, as the device prints them [C]:
// 'show version' lists fpc0 (the master), fpc1 and fpc2, and the master
// answers without a label, so the labelled blocks leave it out. A label owns
// the lines up to the next label: the master's first lines come before the
// first label, and its 'commit complete' is the last line of the last group.
// The label lines end in a space.
const (
	chassisSet3 = "the members that answered are not the chassis' (fpc0, fpc1, fpc2): "

	// 'commit check'
	chassisCheck = "configuration check succeeds\nfpc1: \nconfiguration check succeeds\nfpc2: \nconfiguration check succeeds\n"

	// 'commit confirmed 15 comment "..."'; the note is the window's line
	chassisConfirmed = "configuration check succeeds\n" +
		"commit confirmed will be automatically rolled back in 15 minutes unless confirmed\n" +
		"fpc1: \ncommit complete\n" +
		"commit confirmed will be automatically rolled back in 15 minutes unless confirmed\n" +
		"fpc2: \ncommit complete\n" +
		"commit confirmed will be automatically rolled back in 15 minutes unless confirmed\n" +
		"commit complete\n"

	// the confirming 'commit' (and the commit that undoes a confirmed one)
	chassisConfirm = "configuration check succeeds\nfpc1: \ncommit complete\nfpc2: \ncommit complete\ncommit complete\n"

	// what the CLI prints after an answer
	chassisReminder = "\n# commit confirmed will be rolled back in 15 minutes\n{master:0}[edit]\n"
)

var chassisSet = []string{"fpc0", "fpc1", "fpc2"}

var chassisNote = plan.ApplyConfirmedNote(15)

// answerOf is what the session hands to the readers: the lines before the
// location line, as configAnswer cuts them.
func answerOf(t *testing.T, raw string) []string {
	t.Helper()
	body, ok := configAnswer(raw)
	if !ok {
		t.Fatalf("no location line in %q", raw)
	}
	return body
}

// The observed reply of 'commit check', as the session delivers it: CRLF
// line ends, a blank line and the prompt line '{master:0}[edit]' after it.
// The body is cut before the blank line and the prompt, so neither reaches
// checkAnswer.
func TestCheckAnswerUnlabelledMasterAsDelivered(t *testing.T) {
	for name, raw := range map[string]string{
		"lf":             chassisCheck + "\n{master:0}[edit]\n",
		"crlf":           strings.ReplaceAll(chassisCheck+"\n{master:0}[edit]\n", "\n", "\r\n"),
		"no trailing sp": strings.ReplaceAll(chassisCheck, ": \n", ":\n") + "\n{master:0}[edit]\n",
		"blank lines":    "\nconfiguration check succeeds\n\nfpc1: \n\nconfiguration check succeeds\nfpc2: \nconfiguration check succeeds\n\n{master:0}[edit]\n",
		"spaces around":  "  configuration check succeeds  \n  fpc1:  \n  configuration check succeeds \nfpc2: \nconfiguration check succeeds\n{master:0}[edit]\n",
		"reminder":       chassisCheck + chassisReminder,
	} {
		body := answerOf(t, raw)
		for _, l := range body {
			if strings.Contains(l, "master:0") || strings.HasPrefix(strings.TrimSpace(l), "#") {
				t.Errorf("%s: the prompt area reached the body: %q", name, body)
			}
		}
		if ok, why := checkAnswer(body, chassisSet); !ok {
			t.Errorf("%s: %s", name, why)
		}
	}
	// a body that still holds the prompt line is refused, not read
	if ok, why := checkAnswer(split(chassisCheck+"{master:0}[edit]\n"), chassisSet); ok || !strings.Contains(why, `"{master:0}[edit]"`) {
		t.Errorf("a prompt line in the body: %v %q", ok, why)
	}
}

// 'commit check' on the chassis: the master's line is the head, each other
// member has a group of its own.
func TestCheckAnswerUnlabelledMemberFailing(t *testing.T) {
	const bad = "warning: member is out of sync\n"
	const good = "configuration check succeeds\n"
	for name, c := range map[string]struct{ in, why string }{
		"master head":    {bad + "fpc1: \n" + good + "fpc2: \n" + good, `member fpc0 (unlabelled) answered "warning: member is out of sync", not "configuration check succeeds"`},
		"fpc1":           {good + "fpc1: \n" + bad + "fpc2: \n" + good, `member fpc1 answered "warning: member is out of sync", not "configuration check succeeds"`},
		"fpc2":           {good + "fpc1: \n" + good + "fpc2: \n" + bad, `member fpc2 answered "warning: member is out of sync", not "configuration check succeeds"`},
		"head twice":     {good + good + "fpc1: \n" + good + "fpc2: \n" + good, `member fpc0 (unlabelled) answered "configuration check succeeds" besides its own lines`},
		"group twice":    {good + "fpc1: \n" + good + good + "fpc2: \n" + good, `member fpc1 answered "configuration check succeeds" besides its own lines`},
		"stray in group": {good + "fpc1: \n" + good + "stray\nfpc2: \n" + good, `member fpc1 answered "stray" besides its own lines`},
		"stray at end":   {chassisCheck + "stray\n", `member fpc2 answered "stray" besides its own lines`},
		"commit text":    {"commit complete\nfpc1: \n" + good + "fpc2: \n" + good, `member fpc0 (unlabelled) answered "commit complete", not "configuration check succeeds"`},
		"empty member":   {good + "fpc1: \nfpc2: \n" + good, `member fpc1 has no answer`},
		"label twice":    {good + "fpc1: \n" + good + "fpc2: \n" + good + "fpc1: \n" + good, `member fpc1 has two blocks: its label appears twice`},
		"head missing":   {"fpc1: \n" + good + "fpc2: \n" + good, chassisSet3 + "no answer from fpc0"},
		"other kind":     {good + "fpc1: \n" + good + "re2: \n" + good, `labels of two kinds, fpc1 and re2`},
		"unexpected":     {chassisCheck + "fpc9: \n" + good, chassisSet3 + "an answer from fpc9, which 'show version' did not list"},
	} {
		ok, why := checkAnswer(split(c.in), chassisSet)
		if ok || why != c.why {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
}

// Members that lack a block: only one can be the one that answers without a
// label.
func TestCheckAnswerUnlabelledTwoMembersMissing(t *testing.T) {
	const good = "configuration check succeeds\n"
	const two = `a line "configuration check succeeds" outside the members' answers: members fpc0, fpc2 all lack a block, so it cannot be the answer of one`
	if ok, why := checkAnswer(split(good+"fpc1: \n"+good), chassisSet); ok || why != two {
		t.Errorf("two missing: %v %q", ok, why)
	}
	if ok, why := checkAnswer(split(good), chassisSet); ok || why != chassisSet3+"no answer from fpc0, fpc1, fpc2" {
		t.Errorf("plain only: %v %q", ok, why)
	}
	// every member has a block: a plain line is a stray line, as before
	if ok, why := checkAnswer(split(good+"fpc0: \n"+good+"fpc1: \n"+good+"fpc2: \n"+good), chassisSet); ok || why != `a line "configuration check succeeds" outside the members' answers` {
		t.Errorf("all labelled and plain: %v %q", ok, why)
	}
	// a set of two: a plain block and one label
	pair := []string{"fpc0", "fpc1"}
	if ok, why := checkAnswer(split(good+"fpc1: \n"+good), pair); !ok {
		t.Errorf("set of two, plain and fpc1: %s", why)
	}
	if ok, why := checkAnswer(split(good+"fpc2: \n"+good), pair); ok || !strings.Contains(why, "members fpc0, fpc1 all lack a block") {
		t.Errorf("set of two, plain and an unlisted label: %v %q", ok, why)
	}
	if ok, why := checkAnswer(split(good), pair); ok || why != "the members that answered are not the chassis' (fpc0, fpc1): no answer from fpc0, fpc1" {
		t.Errorf("set of two, plain only: %v %q", ok, why)
	}
}

// The other shapes read as they did: all-labelled, a single member, two
// routing engines, a cluster, and no set. Nothing else reads a plain block
// as a member's.
func TestCheckAnswerUnlabelledLeavesTheOtherShapes(t *testing.T) {
	const good = "configuration check succeeds\n"
	for name, c := range map[string]struct {
		in  string
		set []string
		ok  bool
	}{
		"all labelled":          {vcCheck, []string{"fpc0", "fpc1", "fpc2", "fpc3"}, true},
		"all labelled, three":   {"fpc0: \n" + good + "fpc1: \n" + good + "fpc2: \n" + good, chassisSet, true},
		"single, plain":         {good, nil, true},
		"one member, plain":     {good, []string{"fpc0"}, true},
		"one member, labelled":  {"fpc0: \n" + good, []string{"fpc0"}, true},
		"one member and a line": {good + "fpc0: \n" + good, []string{"fpc0"}, false},
		"engines, plain":        {good, []string{"re0", "re1"}, true},
		"engines, blocks":       {"re0: \n" + good + "re1: \n" + good, []string{"re0", "re1"}, true},
		"engines, plain and re": {good + "re1: \n" + good, []string{"re0", "re1"}, false},
		"cluster, blocks":       {"node0: \n" + good + "node1: \n" + good, []string{"node0", "node1"}, true},
		"cluster, plain and 1":  {good + "node1: \n" + good, []string{"node0", "node1"}, false},
		"cluster, plain":        {good, []string{"node0", "node1"}, false},
		"chassis, plain":        {good, chassisSet, false},
		"no set, a block":       {"fpc0: \n" + good, nil, true},
		"no set, plain+block":   {good + "fpc1: \n" + good, nil, false},
	} {
		if ok, why := checkAnswer(split(c.in), c.set); ok != c.ok {
			t.Errorf("%s: ok %v, want %v (%q)", name, ok, c.ok, why)
		}
	}
}

// The three replies of the chassis, with and without the CLI's reminder and
// the prompt, are read for the commit of each kind (the confirming commit's
// reply is also that of the commit that undoes a confirmed one).
func TestReadCommittedUnlabelledMaster(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want []string
	}{
		"commit confirmed": {chassisConfirmed, []string{chassisNote, textCommitComplete}},
		"confirm":          {chassisConfirm, []string{textCommitComplete}},
	} {
		for suffix, tail := range map[string]string{"with the prompt": chassisReminder, "without the reminder": "\n{master:0}[edit]\n", "crlf": ""} {
			raw := c.in + tail
			if suffix == "crlf" {
				raw = strings.ReplaceAll(c.in+chassisReminder, "\n", "\r\n")
			}
			body := answerOf(t, raw)
			for _, l := range body {
				if strings.Contains(l, "master:0") || strings.HasPrefix(strings.TrimSpace(l), "#") {
					t.Errorf("%s, %s: the prompt area reached the body: %q", name, suffix, body)
				}
			}
			if ok, why := readCommitted(body, chassisSet, c.want...); !ok {
				t.Errorf("%s, %s: %s", name, suffix, why)
			}
		}
	}
	// the reply without the master's check, as a commit of nothing new may
	// print (the check is optional)
	if ok, why := readCommitted(split("fpc1: \ncommit complete\nfpc2: \ncommit complete\ncommit complete\n"), chassisSet, textCommitComplete); !ok {
		t.Errorf("no check: %s", why)
	}
	// a body that still holds the reminder or the prompt is refused
	if ok, why := readCommitted(split(chassisConfirm+"# commit confirmed will be rolled back in 15 minutes\n"), chassisSet, textCommitComplete); ok || !strings.Contains(why, "member fpc2") {
		t.Errorf("a reminder in the body: %v %q", ok, why)
	}
}

// The strict rules of the unlabelled member's commit: its head, each
// member's group, its last line and the sets.
func TestReadCommittedUnlabelledMasterRefused(t *testing.T) {
	n := chassisNote + "\n"
	type c struct {
		in   string
		note bool
		why  string
	}
	for name, c := range map[string]c{
		// the master's head
		"head check fails":                           {"warning: x\n" + n + "fpc1: \ncommit complete\n" + n + "fpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc0 (unlabelled) answered "warning: x", not "commit confirmed will be`},
		"head lacks the note":                        {"configuration check succeeds\nfpc1: \ncommit complete\n" + n + "fpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc0 (unlabelled) did not answer "commit confirmed will be`},
		"head has a stray line":                      {"configuration check succeeds\nstray\n" + n + "fpc1: \ncommit complete\n" + n + "fpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc0 (unlabelled) answered "stray", not`},
		"head note out of order":                     {n + "configuration check succeeds\nfpc1: \ncommit complete\n" + n + "fpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc0 (unlabelled) answered`},
		"head note, none wanted":                     {"configuration check succeeds\n" + n + "fpc1: \ncommit complete\nfpc2: \ncommit complete\ncommit complete\n", false, `member fpc0 (unlabelled) answered "commit confirmed will be`},
		"head complete, check missing then complete": {"commit complete\nfpc1: \ncommit complete\nfpc2: \ncommit complete\ncommit complete\n", false, `member fpc0 (unlabelled) answered "commit complete" besides its own lines`},
		// a member's group
		"fpc1 fails":                {"configuration check succeeds\n" + n + "fpc1: \nwarning: y\n" + n + "fpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc1 answered "warning: y", not "commit complete"`},
		"fpc2 fails":                {"configuration check succeeds\n" + n + "fpc1: \ncommit complete\n" + n + "fpc2: \nwarning: z\n" + n + "commit complete\n", true, `member fpc2 answered "warning: z", not "commit complete"`},
		"fpc1 lacks the note":       {"configuration check succeeds\n" + n + "fpc1: \ncommit complete\nfpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc1 did not answer "commit confirmed will be`},
		"fpc1 note first":           {"configuration check succeeds\n" + n + "fpc1: \n" + n + "commit complete\nfpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc1 answered "commit confirmed will be`},
		"fpc1 extra line":           {"configuration check succeeds\n" + n + "fpc1: \ncommit complete\n" + n + "stray\nfpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc1 answered "stray" besides its own lines`},
		"fpc1 check after complete": {"configuration check succeeds\nfpc1: \ncommit complete\nconfiguration check succeeds\nfpc2: \ncommit complete\ncommit complete\n", false, `member fpc1 answered "configuration check succeeds" besides its own lines`},
		"fpc1 check twice":          {"configuration check succeeds\nfpc1: \nconfiguration check succeeds\nconfiguration check succeeds\ncommit complete\nfpc2: \ncommit complete\ncommit complete\n", false, `member fpc1 answered "configuration check succeeds", not "commit complete"`},
		"fpc1 extra complete":       {"configuration check succeeds\nfpc1: \ncommit complete\ncommit complete\nfpc2: \ncommit complete\ncommit complete\n", false, `member fpc1 answered "commit complete" besides its own lines`},
		"note in other window":      {"configuration check succeeds\n" + plan.ApplyConfirmedNote(9) + "\nfpc1: \ncommit complete\n" + n + "fpc2: \ncommit complete\n" + n + "commit complete\n", true, `member fpc0 (unlabelled) answered "commit confirmed will be automatically rolled back in 9 minutes`},
		// the master's last line
		"no last complete":     {"configuration check succeeds\n" + n + "fpc1: \ncommit complete\n" + n + "fpc2: \ncommit complete\n" + n, true, `member fpc0 (unlabelled) did not answer "commit complete" after`},
		"no last, plain":       {"configuration check succeeds\nfpc1: \ncommit complete\nfpc2: \ncommit complete\n", false, `member fpc0 (unlabelled) did not answer "commit complete" after`},
		"last is not complete": {"configuration check succeeds\nfpc1: \ncommit complete\nfpc2: \ncommit complete\nwarning: w\n", false, `member fpc0 (unlabelled) answered "warning: w" after the members' blocks, not "commit complete"`},
		"two last":             {"configuration check succeeds\nfpc1: \ncommit complete\nfpc2: \ncommit complete\ncommit complete\ncommit complete\n", false, `member fpc2 answered "commit complete" besides its own lines`},
		// the sets
		"a label twice":       {"configuration check succeeds\nfpc1: \ncommit complete\nfpc2: \ncommit complete\nfpc1: \ncommit complete\n", false, `member fpc1 has two blocks`},
		"two members missing": {"configuration check succeeds\nfpc1: \ncommit complete\ncommit complete\n", false, `a line "configuration check succeeds" outside the members' answers: members fpc0, fpc2 all lack a block`},
		"an unexpected block": {"configuration check succeeds\nfpc1: \ncommit complete\nfpc2: \ncommit complete\nfpc9: \ncommit complete\ncommit complete\n", false, chassisSet3 + "an answer from fpc9"},
	} {
		want := []string{textCommitComplete}
		if c.note {
			want = []string{chassisNote, textCommitComplete}
		}
		ok, why := readCommitted(split(c.in), chassisSet, want...)
		if ok || !strings.HasPrefix(why, c.why) {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	// a confirmed commit's reply read as a plain commit's, and the reverse
	if ok, _ := readCommitted(split(chassisConfirmed), chassisSet, textCommitComplete); ok {
		t.Error("the note was read where none is wanted")
	}
	if ok, _ := readCommitted(split(chassisConfirm), chassisSet, chassisNote, textCommitComplete); ok {
		t.Error("a reply without the note was read as a confirmed commit's")
	}
}

// The commit's readers for the other shapes read as before: the all-labelled
// chassis, the stand-alone note between the blocks, a single member, two
// routing engines and a cluster.
func TestReadCommittedUnlabelledLeavesTheOtherShapes(t *testing.T) {
	note := plan.ApplyConfirmedNote(5)
	label := func(l, t string) string { return l + ": \n" + t + "\n" }
	all := func(set []string, t string) string {
		var b strings.Builder
		for _, l := range set {
			b.WriteString(label(l, t))
		}
		return b.String()
	}
	for name, c := range map[string]struct {
		in   string
		set  []string
		want []string
		ok   bool
	}{
		"all labelled":        {all(chassisSet, "configuration check succeeds") + all(chassisSet, "commit complete"), chassisSet, []string{textCommitComplete}, true},
		"stand-alone note":    {all(chassisSet, "configuration check succeeds") + note + "\n" + all(chassisSet, "commit complete"), chassisSet, []string{note, textCommitComplete}, true},
		"single, plain":       {"configuration check succeeds\ncommit complete\n", nil, []string{textCommitComplete}, true},
		"one member, plain":   {"configuration check succeeds\ncommit complete\n", []string{"fpc0"}, []string{textCommitComplete}, true},
		"engines, plain":      {"configuration check succeeds\ncommit complete\n", []string{"re0", "re1"}, []string{textCommitComplete}, true},
		"engines, blocks":     {all([]string{"re0", "re1"}, "commit complete"), []string{"re0", "re1"}, []string{textCommitComplete}, true},
		"engines, plain+re":   {"commit complete\n" + label("re1", "commit complete"), []string{"re0", "re1"}, []string{textCommitComplete}, false},
		"cluster, plain+1":    {"commit complete\n" + label("node1", "commit complete"), []string{"node0", "node1"}, []string{textCommitComplete}, false},
		"cluster, blocks":     {all([]string{"node0", "node1"}, "commit complete"), []string{"node0", "node1"}, []string{textCommitComplete}, true},
		"chassis, plain":      {"commit complete\n", chassisSet, []string{textCommitComplete}, false},
		"one member + line":   {"commit complete\n" + label("fpc0", "commit complete"), []string{"fpc0"}, []string{textCommitComplete}, false},
		"chassis of 4, plain": {"configuration check succeeds\ncommit complete\n", []string{"fpc0", "fpc1", "fpc2", "fpc3"}, []string{textCommitComplete}, false},
	} {
		if ok, why := readCommitted(split(c.in), c.set, c.want...); ok != c.ok {
			t.Errorf("%s: ok %v, want %v (%q)", name, ok, c.ok, why)
		}
	}
}

// A labelled member may print the check before its 'commit complete', as the
// owner's head and the old path do; the note stays required of every member
// of a confirmed commit.
func TestReadCommittedUnlabelledMemberGroupWithCheck(t *testing.T) {
	const chk = "configuration check succeeds\n"
	n := chassisNote + "\n"
	if ok, why := readCommitted(split(chk+"fpc1: \n"+chk+"commit complete\nfpc2: \ncommit complete\ncommit complete\n"), chassisSet, textCommitComplete); !ok {
		t.Errorf("fpc1 starts with the check: %s", why)
	}
	// the last group, with the check and the owner's last line
	if ok, why := readCommitted(split(chk+"fpc1: \ncommit complete\nfpc2: \n"+chk+"commit complete\ncommit complete\n"), chassisSet, textCommitComplete); !ok {
		t.Errorf("fpc2 starts with the check: %s", why)
	}
	// without the owner's last line the check does not make one
	if ok, why := readCommitted(split(chk+"fpc1: \ncommit complete\nfpc2: \n"+chk+"commit complete\n"), chassisSet, textCommitComplete); ok || !strings.Contains(why, `member fpc0 (unlabelled) did not answer "commit complete" after`) {
		t.Errorf("fpc2 with the check, no last line: %v %q", ok, why)
	}
	// confirmed: check, complete, note in each group
	if ok, why := readCommitted(split(chk+n+"fpc1: \n"+chk+"commit complete\n"+n+"fpc2: \n"+chk+"commit complete\n"+n+"commit complete\n"), chassisSet, chassisNote, textCommitComplete); !ok {
		t.Errorf("confirmed, checks in the groups: %s", why)
	}
	// the note stays required, with or without the check
	for name, in := range map[string]string{
		"no note, no check": chk + n + "fpc1: \ncommit complete\nfpc2: \ncommit complete\n" + n + "commit complete\n",
		"no note, check":    chk + n + "fpc1: \n" + chk + "commit complete\nfpc2: \ncommit complete\n" + n + "commit complete\n",
	} {
		if ok, why := readCommitted(split(in), chassisSet, chassisNote, textCommitComplete); ok || !strings.Contains(why, `member fpc1 did not answer "commit confirmed will be`) {
			t.Errorf("%s: %v %q", name, ok, why)
		}
	}
}

// The master need not be fpc0 and the chassis need not have three members:
// the owner is the one member of the set that has no block.
func TestReadCommittedUnlabelledOtherChassis(t *testing.T) {
	const chk = "configuration check succeeds\n"
	n := chassisNote + "\n"
	pair := []string{"fpc0", "fpc1"}
	four := []string{"fpc0", "fpc1", "fpc2", "fpc3"}
	if ok, why := checkAnswer(split(chk+"fpc1: \n"+chk), pair); !ok {
		t.Errorf("two members, check: %s", why)
	}
	if ok, why := readCommitted(split(chk+"fpc1: \ncommit complete\ncommit complete\n"), pair, textCommitComplete); !ok {
		t.Errorf("two members, commit: %s", why)
	}
	if ok, why := readCommitted(split(chk+n+"fpc1: \ncommit complete\n"+n+"commit complete\n"), pair, chassisNote, textCommitComplete); !ok {
		t.Errorf("two members, confirmed: %s", why)
	}
	if ok, why := readCommitted(split(chk+"fpc1: \ncommit complete\n"), pair, textCommitComplete); ok || !strings.Contains(why, "member fpc0 (unlabelled) did not answer") {
		t.Errorf("two members, no last line: %v %q", ok, why)
	}
	// the master is fpc1: fpc0 and fpc2 are headed
	if ok, why := checkAnswer(split(chk+"fpc0: \n"+chk+"fpc2: \n"+chk), chassisSet); !ok {
		t.Errorf("master fpc1, check: %s", why)
	}
	if ok, why := readCommitted(split(chk+n+"fpc0: \ncommit complete\n"+n+"fpc2: \ncommit complete\n"+n+"commit complete\n"), chassisSet, chassisNote, textCommitComplete); !ok {
		t.Errorf("master fpc1, confirmed: %s", why)
	}
	if ok, why := readCommitted(split(chk+"fpc0: \nwarning: x\nfpc2: \ncommit complete\ncommit complete\n"), chassisSet, textCommitComplete); ok || !strings.Contains(why, "member fpc0 answered") {
		t.Errorf("master fpc1, fpc0 fails: %v %q", ok, why)
	}
	// the master is the last of four
	if ok, why := checkAnswer(split(chk+"fpc0: \n"+chk+"fpc1: \n"+chk+"fpc2: \n"+chk), four); !ok {
		t.Errorf("four members, master fpc3: %s", why)
	}
}
