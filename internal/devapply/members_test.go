package devapply

import (
	"errors"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf/plan"
)

// The answers of a four-member virtual chassis (two EX4600 and two EX4300 on
// Junos 21.4R3-S2.4, one shared host name), as the device prints them. The
// label line ends in a space.
const vcCheck = "fpc0: \nconfiguration check succeeds\nfpc1: \nconfiguration check succeeds\n" +
	"fpc2: \nconfiguration check succeeds\nfpc3: \nconfiguration check succeeds\n"

const vcRule = "--------------------------------------------------------------------------\n"

const vcX86Suites = `JUNOS Base OS boot [21.4R3-S2.4]
JUNOS Base OS Software Suite [21.4R3-S2.4]
JUNOS Online Documentation [21.4R3-S2.4]
JUNOS Crypto Software Suite [21.4R3-S2.4]
JUNOS Crypto Software Suite [21.4R3-S2.4]
JUNOS Kernel Software Suite [21.4R3-S2.4]
JUNOS Phone-Home Software Suite [21.4R3-S2.4]
JUNOS Packet Forwarding Engine Support (qfx-ex-x86-32) [21.4R3-S2.4]
JUNOS jsd [i386-21.4R3-S2.4-jet-1]
JUNOS Routing Software Suite [21.4R3-S2.4]
JUNOS SDN Software Suite [21.4R3-S2.4]
JUNOS Enterprise Software Suite [21.4R3-S2.4]
JUNOS Web Management Platform Package [21.4R3-S2.4]
JUNOS Openconfig [21.4R3-S2.4]
JUNOS py-base-i386 [21.4R3-S2.4]
JUNOS py-extensions-i386 [21.4R3-S2.4]
`

const vcPowerpcSuites = `JUNOS EX  Software Suite [21.4R3-S2.4]
JUNOS FIPS mode utilities [21.4R3-S2.4]
JUNOS Crypto Software Suite [21.4R3-S2.4]
JUNOS Online Documentation [21.4R3-S2.4]
JUNOS Phone-Home Software Suite [21.4R3-S2.4]
JUNOS jsd [powerpc-21.4R3-S2.4-jet-1]
JUNOS SDN Software Suite [21.4R3-S2.4]
JUNOS EX 4300 Software Suite [21.4R3-S2.4]
JUNOS Web Management Platform Package [21.4R3-S2.4]
JUNOS py-base-powerpc [21.4R3-S2.4]
JUNOS py-extensions-powerpc [21.4R3-S2.4]
REST API Software Suite [21.4R3-S2.4]
`

const vcVersion = "fpc0:\n" + vcRule +
	"Hostname: jsw1.example.net\nModel: ex4600-40f\nJunos: 21.4R3-S2.4\n" + vcX86Suites +
	"JUNOS Host Software [18.1R3-S6.1]\n\n" +
	"fpc1:\n" + vcRule +
	"Hostname: jsw1.example.net\nModel: ex4600-40f\nJunos: 21.4R3-S2.4\n" + vcX86Suites +
	"JUNOS Host Software [21.4R3-S1.5]\n\n" +
	"fpc2:\n" + vcRule +
	"Hostname: jsw1.example.net\nModel: ex4300-48t\nJunos: 21.4R3-S2.4\n" + vcPowerpcSuites + "\n" +
	"fpc3:\n" + vcRule +
	"Hostname: jsw1.example.net\nModel: ex4300-48t\nJunos: 21.4R3-S2.4\n" + vcPowerpcSuites

// The 0.2.19 rules read the chassis: one hostname and one release for every
// member, the model of the first.
func TestParseVersionVirtualChassisCapture(t *testing.T) {
	id, err := parseVersion(vcVersion)
	if err != nil || id.Hostname != "jsw1.example.net" || id.Model != "ex4600-40f" || id.Release != "21.4R3-S2.4" {
		t.Errorf("%+v %v", id, err)
	}
}

func split(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

// 'commit check' prints a block for each member; the single chassis' answer
// reads as before.
func TestCheckAnswerMembers(t *testing.T) {
	for name, in := range map[string]string{
		"single":        "configuration check succeeds\n",
		"chassis":       vcCheck,
		"two engines":   "re0: \nconfiguration check succeeds\nre1: \nconfiguration check succeeds\n",
		"cluster":       "node0:\nconfiguration check succeeds\nnode1:\nconfiguration check succeeds\n",
		"one member":    "fpc0: \nconfiguration check succeeds\n",
		"blank between": "fpc0: \n\nconfiguration check succeeds\n\nfpc1: \nconfiguration check succeeds\n",
		"roles":         "member0:\nconfiguration check succeeds\nlcmaster:\nconfiguration check succeeds\n",
	} {
		if ok, why := checkAnswer(split(in)); !ok {
			t.Errorf("%s: %s", name, why)
		}
	}
	for name, c := range map[string]struct{ in, why string }{
		"empty":         {"", ""},
		"error":         {"fpc0: \nconfiguration check succeeds\nfpc1: \nerror: statement not found\n", `member fpc1 answered "error: statement not found"`},
		"warning":       {"fpc0: \nconfiguration check succeeds\nfpc1: \nwarning: foo is not set\nconfiguration check succeeds\n", `member fpc1 answered "warning: foo is not set"`},
		"no answer":     {"fpc0: \nconfiguration check succeeds\nfpc1: \nfpc2: \nconfiguration check succeeds\n", "member fpc1 has no answer"},
		"last no text":  {"fpc0: \nconfiguration check succeeds\nfpc1: \n", "member fpc1 has no answer"},
		"twice":         {"fpc0: \nconfiguration check succeeds\nfpc0: \nconfiguration check succeeds\n", `member fpc0 answered "configuration check succeeds" twice`},
		"loose line":    {"fpc0: \nconfiguration check succeeds\nconfiguration check succeeds\n", `a line "configuration check succeeds" outside the members' answers`},
		"loose first":   {"configuration check succeeds\nfpc0: \nconfiguration check succeeds\n", `a line "configuration check succeeds" outside the members' answers`},
		"complete":      {"fpc0: \ncommit complete\n", `member fpc0 answered "commit complete"`},
		"single loose":  {"configuration check succeeds\nconfiguration check succeeds\n", ""},
		"single other":  {"error: x\n", ""},
		"not a label":   {"fpc0 \nconfiguration check succeeds\n", ""},
		"upper label":   {"FPC0:\nconfiguration check succeeds\n", ""},
		"unknown label": {"vc0:\nconfiguration check succeeds\n", ""},
	} {
		ok, why := checkAnswer(split(c.in))
		if ok || why != c.why {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	// the refusal names the member and its text and keeps the error table
	e := answerErrorWhy("commit check", split("fpc0: \nconfiguration check succeeds\nfpc1: \nerror: x\n"), nil, `member fpc1 answered "error: x"`)
	if !errors.Is(e, ErrRefused) || !strings.HasPrefix(e.Error(), `commit check: member fpc1 answered "error: x"; `) {
		t.Errorf("%v", e)
	}
}

// A commit on a device with members: by analogy with the check's blocks and
// the commit of two routing engines (no capture): a block for each member,
// 'commit complete' last, the check's success and the confirmed note
// optional.
func TestCommittedAnswerMembers(t *testing.T) {
	note := plan.ApplyConfirmedNote(10)
	chk := func(l string) string { return l + ": \nconfiguration check succeeds\n" }
	done := func(l string) string { return l + ": \ncommit complete\n" }
	note1 := note + "\n"
	for name, c := range map[string]struct {
		in   string
		want []string
	}{
		"single":               {"configuration check succeeds\ncommit complete\n", []string{textCommitComplete}},
		"single no check":      {"commit complete\n", []string{textCommitComplete}},
		"single confirmed":     {"configuration check succeeds\n" + note1 + "commit complete\n", []string{note, textCommitComplete}},
		"chassis":              {chk("fpc0") + chk("fpc1") + done("fpc0") + done("fpc1"), []string{textCommitComplete}},
		"complete only":        {done("fpc0") + done("fpc1"), []string{textCommitComplete}},
		"two engines":          {chk("re0") + done("re1") + done("re0"), []string{textCommitComplete}},
		"confirmed between":    {chk("fpc0") + chk("fpc1") + note1 + done("fpc0") + done("fpc1"), []string{note, textCommitComplete}},
		"confirmed first":      {note1 + done("fpc0") + done("fpc1"), []string{note, textCommitComplete}},
		"confirmed in members": {chk("fpc0") + "fpc0: \n" + note1 + done("fpc0"), []string{note, textCommitComplete}},
		"in one block":         {"fpc0: \ncommit complete\nfpc1: \ncommit complete\n", []string{textCommitComplete}},
	} {
		if ok, why := readCommitted(split(c.in), c.want...); !ok {
			t.Errorf("%s: %s", name, why)
		}
	}
	for name, c := range map[string]struct {
		in   string
		want []string
		why  string
	}{
		"error in a member": {chk("fpc0") + "fpc1: \nerror: commit failed\n", []string{textCommitComplete}, `member fpc1 answered "error: commit failed"`},
		"member never done": {chk("fpc0") + chk("fpc1") + done("fpc0"), []string{textCommitComplete}, `member fpc1 did not answer "commit complete"`},
		"check twice":       {chk("fpc0") + chk("fpc0") + done("fpc0"), []string{textCommitComplete}, `member fpc0 answered "configuration check succeeds" again or out of order`},
		"done twice":        {done("fpc0") + done("fpc0"), []string{textCommitComplete}, `member fpc0 answered "commit complete" again or out of order`},
		"check after done":  {done("fpc0") + chk("fpc0"), []string{textCommitComplete}, `member fpc0 answered "configuration check succeeds" again or out of order`},
		"no answer":         {chk("fpc0") + "fpc1: \n", []string{textCommitComplete}, "member fpc1 has no answer"},
		"loose complete":    {chk("fpc0") + "commit complete\n", []string{textCommitComplete}, `a line "commit complete" outside the members' answers`},
		"loose line":        {chk("fpc0") + done("fpc0") + "warning: x\n", []string{textCommitComplete}, `a line "warning: x" outside the members' answers`},
		"note missing":      {chk("fpc0") + done("fpc0"), []string{note, textCommitComplete}, `no member and no line says "` + note + `"`},
		"other note":        {chk("fpc0") + plan.ApplyConfirmedNote(5) + "\n" + done("fpc0"), []string{note, textCommitComplete}, `a line "` + plan.ApplyConfirmedNote(5) + `" outside the members' answers`},
		"note not wanted":   {chk("fpc0") + note1 + done("fpc0"), []string{textCommitComplete}, `a line "` + note + `" outside the members' answers`},
		"note twice":        {chk("fpc0") + "fpc0: \n" + note1 + note1 + done("fpc0"), []string{note, textCommitComplete}, `a line "` + note + `" outside the members' answers`},
	} {
		ok, why := readCommitted(split(c.in), c.want...)
		if ok || why != c.why {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	// the single device keeps its old refusals
	for _, in := range []string{"", "commit complete\ncommit complete\n", "error: x\n", "configuration check succeeds\n"} {
		if ok, why := readCommitted(split(in), textCommitComplete); ok || why != "" {
			t.Errorf("%q: %v %q", in, ok, why)
		}
	}
}

// The NETCONF reply names the members as <routing-engine> elements (the
// shape the fake models; no capture of a virtual chassis' reply): each must
// hold the success element, once.
func TestNetconfReplyMembers(t *testing.T) {
	re := func(name, el string) string {
		return "<routing-engine><name>" + name + "</name>" + el + "</routing-engine>"
	}
	wrap := func(s string) string { return "<commit-results>" + s + "</commit-results>" }
	j := &JunosNetconf{m: nil}
	for name, c := range map[string]struct {
		in      string
		success []string
		ok      bool
		want    string
	}{
		"none":    {wrap(""), []string{"commit-check-success"}, true, ""},
		"one":     {wrap(re("re0", "<commit-check-success/>")), []string{"commit-check-success"}, true, ""},
		"four":    {wrap(re("fpc0", "<commit-check-success/>") + re("fpc1", "<commit-check-success/>") + re("fpc2", "<commit-check-success/>") + re("fpc3", "<commit-check-success/>")), []string{"commit-check-success"}, true, ""},
		"commit":  {wrap(re("fpc0", "<commit-success/>") + re("fpc1", "<commit-success/>")), []string{"commit-success", "ok"}, true, ""},
		"ok":      {wrap(re("fpc0", "<ok/>")), []string{"commit-success", "ok"}, true, ""},
		"silent":  {wrap(re("fpc0", "<commit-check-success/>") + re("fpc1", "")), []string{"commit-check-success"}, false, "member fpc1 did not answer <commit-check-success/>"},
		"other":   {wrap(re("fpc0", "<commit-check-success/>") + re("fpc1", "<commit-success/>")), []string{"commit-check-success"}, false, "member fpc1 did not answer <commit-check-success/>"},
		"twice":   {wrap(re("fpc0", "<commit-check-success/>") + re("fpc0", "<commit-check-success/>")), []string{"commit-check-success"}, false, "member fpc0 answered twice"},
		"no name": {wrap("<routing-engine><commit-check-success/></routing-engine>"), []string{"commit-check-success"}, false, "a member without a name"},
		"outside": {wrap(re("fpc0", "<commit-check-success/>") + "<commit-check-success/>"), []string{"commit-check-success"}, true, ""},
	} {
		r, err := parseReply(c.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		err = j.memberRefusal("commit check", r, c.success...)
		switch {
		case c.ok && err != nil:
			t.Errorf("%s: %v", name, err)
		case !c.ok && (err == nil || !errors.Is(err, ErrUnrecognised) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
