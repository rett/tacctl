package devapply

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// The first capture of a virtual chassis of two members (two switches of one model, FPC 0
// the master, FPC 1 the backup) whose master prints its own label: the
// answers of a confirmed commit and of the confirming commit, as the device
// printed them (the banner, the location line and the prompt that follow
// are not part of the reply). The master's lines come in two blocks, its
// check and the note first and its 'commit complete' last, after the
// backup's block; a label's block holds several lines; a label repeats.
const (
	labelledNote2     = "commit confirmed will be automatically rolled back in 2 minutes unless confirmed"
	labelledConfirmed = "fpc0:\nconfiguration check succeeds\n" + labelledNote2 + "\n" +
		"fpc1:\ncommit complete\n" + labelledNote2 + "\n" +
		"fpc0:\ncommit complete\n\n"
	labelledConfirming = "fpc0:\nconfiguration check succeeds\n" +
		"fpc1:\ncommit complete\n" +
		"fpc0:\ncommit complete\n\n"
	labelledCheck = "fpc0:\nconfiguration check succeeds\nfpc1:\nconfiguration check succeeds\n"
)

var labelledSet = []string{"fpc0", "fpc1"}

// The capture is read: the confirmed commit (the note once for each member,
// 'commit complete' once for each, the master's across two blocks), the
// confirming commit (no note) and the check; the lines of a member may come
// in either order ('commit complete' and the note), and blank lines do not
// matter. The note is the one the transport sends.
func TestCommittedAnswerLabelledMaster(t *testing.T) {
	t.Parallel()
	if got := plan.ApplyConfirmedNote(2); got != labelledNote2 {
		t.Fatalf("the note is %q", got)
	}
	n := labelledNote2
	confirmed := []string{n, textCommitComplete}
	confirming := []string{textCommitComplete}
	for name, c := range map[string]struct {
		in   string
		want []string
	}{
		"confirmed commit":      {labelledConfirmed, confirmed},
		"confirming commit":     {labelledConfirming, confirming},
		"blank lines":           {strings.ReplaceAll(labelledConfirmed, "\n", "\n\n"), confirmed},
		"trailing spaces":       {strings.ReplaceAll(labelledConfirmed, ":\n", ": \n"), confirmed},
		"master note last":      {"fpc0:\nconfiguration check succeeds\ncommit complete\n" + n + "\nfpc1:\ncommit complete\n" + n + "\n", confirmed},
		"master in one block":   {"fpc0:\nconfiguration check succeeds\n" + n + "\ncommit complete\nfpc1:\ncommit complete\n" + n + "\n", confirmed},
		"backup note first":     {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\n" + n + "\ncommit complete\nfpc0:\ncommit complete\n", confirmed},
		"backup first":          {"fpc1:\ncommit complete\n" + n + "\nfpc0:\nconfiguration check succeeds\n" + n + "\nfpc0:\ncommit complete\n", confirmed},
		"backup with a check":   {"fpc1:\nconfiguration check succeeds\ncommit complete\n" + n + "\nfpc0:\ncommit complete\n" + n + "\n", confirmed},
		"no check at all":       {"fpc0:\n" + n + "\nfpc1:\ncommit complete\n" + n + "\nfpc0:\ncommit complete\n", confirmed},
		"confirming, no check":  {"fpc0:\ncommit complete\nfpc1:\ncommit complete\n", confirming},
		"confirming, in blocks": {"fpc0:\nconfiguration check succeeds\nfpc0:\ncommit complete\nfpc1:\ncommit complete\n", confirming},
	} {
		if ok, why := readCommitted(split(c.in), labelledSet, c.want...); !ok {
			t.Errorf("%s: %s", name, why)
		}
	}
	if ok, why := checkAnswer(split(labelledCheck), labelledSet); !ok {
		t.Errorf("the check: %s", why)
	}
	if ok, why := checkAnswer(split("fpc1:\nconfiguration check succeeds\nfpc0:\nconfiguration check succeeds\n"), labelledSet); !ok {
		t.Errorf("the check, backup first: %s", why)
	}
}

// What the capture's layout still refuses, with the member and the line
// named: a missing note, a member the set does not list, a line before the
// first label, a member without 'commit complete', a line twice, a line
// that is none of the member's, a member that is not in the answer, a label
// with no line, and the labels of two kinds.
func TestCommittedAnswerLabelledMasterRefusals(t *testing.T) {
	t.Parallel()
	n := labelledNote2
	confirmed := []string{n, textCommitComplete}
	confirming := []string{textCommitComplete}
	const sets = "the members that answered are not the chassis' (fpc0, fpc1): "
	for name, c := range map[string]struct {
		in   string
		want []string
		why  string
	}{
		"note missing in the backup": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\ncommit complete\nfpc0:\ncommit complete\n", confirmed,
			`member fpc1 did not answer "` + n + `"`},
		"note missing in the master": {"fpc0:\nconfiguration check succeeds\nfpc1:\ncommit complete\n" + n + "\nfpc0:\ncommit complete\n", confirmed,
			`member fpc0 did not answer "` + n + `"`},
		"no note at all": {labelledConfirming, confirmed, `member fpc0 did not answer "` + n + `"`},
		"a note for the confirming commit": {labelledConfirmed, confirming,
			`member fpc0 answered "` + n + `" besides its own lines`},
		"another window": {strings.ReplaceAll(labelledConfirmed, "2 minutes", "5 minutes"), confirmed,
			`member fpc0 answered "commit confirmed will be automatically rolled back in 5 minutes unless confirmed" besides its own lines`},
		"a third label": {labelledConfirmed + "fpc2:\ncommit complete\n" + n + "\n", confirmed,
			sets + "an answer from fpc2, which 'show version' did not list"},
		"a stray line before the first label": {"warning: x\n" + labelledConfirmed, confirmed,
			`a line "warning: x" outside the members' answers`},
		"the note before the first label": {n + "\n" + labelledConfirmed, confirmed,
			`a line "` + n + `" outside the members' answers`},
		"the master never completes": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\ncommit complete\n" + n + "\n", confirmed,
			`member fpc0 did not answer "commit complete"`},
		"the backup never completes": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\n" + n + "\nfpc0:\ncommit complete\n", confirmed,
			`member fpc1 did not answer "commit complete"`},
		"complete twice": {labelledConfirmed + "fpc1:\ncommit complete\n", confirmed,
			`member fpc1 answered "commit complete" twice`},
		"complete twice in a block": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\ncommit complete\ncommit complete\n" + n + "\nfpc0:\ncommit complete\n", confirmed,
			`member fpc1 answered "commit complete" twice`},
		"note twice": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\ncommit complete\n" + n + "\n" + n + "\nfpc0:\ncommit complete\n", confirmed,
			`member fpc1 answered "` + n + `" twice`},
		"note twice in the master": {labelledConfirmed + "fpc0:\n" + n + "\n", confirmed,
			`member fpc0 answered "` + n + `" twice`},
		"an extra line": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc1:\ncommit complete\nwarning: the member is behind\n" + n + "\nfpc0:\ncommit complete\n", confirmed,
			`member fpc1 answered "warning: the member is behind" besides its own lines`},
		"an extra line at the end": {labelledConfirmed + "warning: x\n", confirmed,
			`member fpc0 answered "warning: x" besides its own lines`},
		"an error": {"fpc0:\nconfiguration check succeeds\nfpc1:\nerror: commit failed\n", confirming,
			`member fpc1 answered "error: commit failed" besides its own lines`},
		"check after complete": {"fpc0:\ncommit complete\nconfiguration check succeeds\nfpc1:\ncommit complete\n", confirming,
			`member fpc0 answered "configuration check succeeds" again or out of order`},
		"check twice": {"fpc0:\nconfiguration check succeeds\nfpc1:\nconfiguration check succeeds\nfpc0:\nconfiguration check succeeds\ncommit complete\nfpc1:\ncommit complete\n", confirming,
			`member fpc0 answered "configuration check succeeds" again or out of order`},
		"the backup is absent": {"fpc0:\nconfiguration check succeeds\nfpc0:\ncommit complete\n", confirming,
			sets + "no answer from fpc1"},
		"the master is absent": {"fpc1:\ncommit complete\n", confirming,
			sets + "no answer from fpc0"},
		// the note that no label opens is the lines of the member no label names
		"the backup is absent, confirmed": {"fpc0:\nconfiguration check succeeds\n" + n + "\nfpc0:\ncommit complete\n", confirmed,
			`member fpc1 (unlabelled) did not answer "` + n + `"`},
		"a label with no line": {"fpc0:\nconfiguration check succeeds\nfpc1:\nfpc0:\ncommit complete\n", confirming,
			"member fpc1 has no answer"},
		"the last label with no line": {labelledConfirming + "fpc1:\n", confirming,
			"member fpc1 has no answer"},
		"labels of two kinds": {labelledConfirming + "re1:\ncommit complete\n", confirming,
			"labels of two kinds, fpc0 and re1"},
		// the layout readLines reads for larger sets (the note once, between
		// the blocks; a guess, no capture) is not the chassis of two's: every
		// member prints the note
		"a note that stands alone": {"fpc0:\nconfiguration check succeeds\nfpc1:\nconfiguration check succeeds\n" + n + "\nfpc0:\ncommit complete\nfpc1:\ncommit complete\n", confirmed,
			`member fpc0 did not answer "` + n + `"`},
		"another set": {labelledConfirming, confirming, ""},
	} {
		set := labelledSet
		if name == "another set" {
			set = []string{"fpc0", "fpc1", "fpc2"}
		}
		ok, why := readCommitted(split(c.in), set, c.want...)
		if name == "another set" {
			// no capture of a larger chassis: it is refused, the repeated
			// label and the size named
			if ok || !strings.Contains(why, "a label appears twice: a chassis of 3 members whose members all print a label is read in blocks for two members only") {
				t.Errorf("%s: ok %v, why %q", name, ok, why)
			}
			continue
		}
		if ok || why != c.why {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	// without the members 'show version' listed the blocks are not read
	if ok, _ := readCommitted(split(labelledConfirmed), nil, labelledNote2, textCommitComplete); ok {
		t.Error("the blocks were read for a device with no listed members")
	}
	for _, set := range [][]string{{"re0", "re1"}, {"node0", "node1"}, {"fpc0"}} {
		if ok, _ := readCommitted(split(labelledConfirmed), set, labelledNote2, textCommitComplete); ok {
			t.Errorf("the blocks were read for %v", set)
		}
	}
	// the check keeps its rules
	for name, in := range map[string]string{
		"twice":   labelledCheck + "fpc0:\nconfiguration check succeeds\n",
		"stray":   "warning: x\n" + labelledCheck,
		"a third": labelledCheck + "fpc2:\nconfiguration check succeeds\n",
		"error":   "fpc0:\nconfiguration check succeeds\nfpc1:\nerror: x\n",
	} {
		if ok, why := checkAnswer(split(in), labelledSet); ok || why == "" {
			t.Errorf("check, %s: ok %v, why %q", name, ok, why)
		}
	}
}

// The error of a refused answer shows the whole answer up to 40 lines, each
// cut at 120 bytes, so that a layout nobody has seen shows itself in full.
func TestAnswerErrorShowsTheWholeAnswer(t *testing.T) {
	t.Parallel()
	ls := split(labelledConfirmed)
	e := answerErrorWhy("commit confirmed 2 comment capture", ls, nil, `a line "x" outside the members' answers`)
	if got := len(e.Lines); got != 1+len(nonBlank(ls)) {
		t.Errorf("%d lines: %q", got, e.Lines)
	}
	if !strings.Contains(e.Error(), "fpc0:; configuration check succeeds; "+labelledNote2+"; fpc1:; commit complete; "+labelledNote2+"; fpc0:; commit complete") {
		t.Errorf("%v", e)
	}
	if strings.Contains(e.Error(), "...") || !errors.Is(e, ErrUnrecognised) {
		t.Errorf("%v", e)
	}
	var many []string
	for i := 0; i < 60; i++ {
		many = append(many, "line "+strings.Repeat("x", i))
	}
	many[3] = strings.Repeat("y", 300)
	e = answerError("show", many, nil)
	if len(e.Lines) != 41 || e.Lines[40] != "..." || e.Lines[39] != many[39] {
		t.Errorf("%d lines, last %q", len(e.Lines), e.Lines[len(e.Lines)-1])
	}
	if got := e.Lines[3]; len(got) != 123 || !strings.HasSuffix(got, "y...") {
		t.Errorf("a long line is %d bytes: %q", len(got), got)
	}
	if len(e.Lines[39]) > 120 {
		t.Errorf("line 39 is %d bytes", len(e.Lines[39]))
	}
}

// In a chassis of three or more members that all print a label, the answer is
// read one line per label as before: a label that appears twice is read when
// its lines, joined, are in order. Only an answer that is refused says when a
// label appeared twice (the documentation says so, and that no capture of a
// larger chassis exists).
func TestCommittedAnswerOfThreeReadsARepeatedLabel(t *testing.T) {
	t.Parallel()
	set := []string{"fpc0", "fpc1", "fpc2"}
	const repeated = "fpc0:\nconfiguration check succeeds\nfpc1:\ncommit complete\nfpc2:\ncommit complete\nfpc0:\ncommit complete\n"
	if ok, why := readCommitted(split(repeated), set); !ok || why != "" {
		t.Errorf("a label that repeats with its lines in order: ok %v, why %q", ok, why)
	}
	// the same repetition in an answer that is refused for another reason
	// gets the hint; a refused answer without a repeated label gets none
	_, why := readCommitted(split(repeated+"fpc2:\ncommit complete\n"), set)
	if !strings.Contains(why, "again or out of order") || !strings.Contains(why, "a label appears twice") {
		t.Errorf("why %q", why)
	}
	_, why = readCommitted(split("fpc0:\ncommit complete\nfpc1:\ncommit complete\n"), set)
	if why == "" || strings.Contains(why, "a label appears twice") {
		t.Errorf("why %q", why)
	}
}

// Device text in an error is cleaned of every character that can move or
// hide what a terminal shows: C0 and C1 controls (U+009B starts an escape
// sequence), the bidirectional overrides and the line separators.
func TestAnswerErrorCleansDeviceText(t *testing.T) {
	t.Parallel()
	const bad = "error\u009b[31m ‮evil next \x1b\x7f‍end"
	const want = "error?[31m ?evil?next????end" // 2029, ESC, DEL, ZWJ
	for name, e := range map[string]*AnswerError{
		"answerError":     answerError("commit", []string{bad}, nil),
		"answerErrorWide": answerErrorWide("commit", []string{bad}, nil),
		"answerErrorWhy":  answerErrorWhy("commit", nil, nil, bad),
	} {
		if len(e.Lines) != 1 || e.Lines[0] != want {
			t.Errorf("%s: lines %q, want %q", name, e.Lines, want)
		}
		if got := e.Error(); strings.ContainsAny(got, "\u009b‮  \x1b\x7f‍") {
			t.Errorf("%s: %q", name, got)
		}
	}
	if got := cut(bad); got != want {
		t.Errorf("cut = %q", got)
	}
}
