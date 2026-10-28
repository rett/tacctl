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
	} {
		if ok, why := checkAnswer(split(in), nil); !ok {
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
		"sfc":           {"sfc0:\nconfiguration check succeeds\n", ""},
		"lcc":           {"lcc3:\nconfiguration check succeeds\n", ""},
		"member":        {"member0:\nconfiguration check succeeds\n", ""},
		"role":          {"fpcmaster:\nconfiguration check succeeds\n", ""},
		"mixed kinds":   {"re0: \nconfiguration check succeeds\nfpc7: \nconfiguration check succeeds\nnode1: \nconfiguration check succeeds\n", "labels of two kinds, re0 and fpc7"},
	} {
		ok, why := checkAnswer(split(c.in), nil)
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
		if ok, why := readCommitted(split(c.in), nil, c.want...); !ok {
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
		ok, why := readCommitted(split(c.in), nil, c.want...)
		if ok || why != c.why {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	// the single device keeps its old refusals
	for _, in := range []string{"", "commit complete\ncommit complete\n", "error: x\n", "configuration check succeeds\n"} {
		if ok, why := readCommitted(split(in), nil, textCommitComplete); ok || why != "" {
			t.Errorf("%q: %v %q", in, ok, why)
		}
	}
}

// The members 'show version' listed are the ones every answer names: the
// check, then each commit's, whose members are the check's. An answer that
// names fewer, more or none fails closed with the missing and the unexpected
// members named.
func TestAnswersNameTheChassisMembers(t *testing.T) {
	set := []string{"fpc0", "fpc1", "fpc2", "fpc3"}
	if ok, why := checkAnswer(split(vcCheck), set); !ok {
		t.Errorf("the capture: %s", why)
	}
	const sets = "the members that answered are not the chassis' (fpc0, fpc1, fpc2, fpc3): "
	for name, c := range map[string]struct{ in, why string }{
		"one member":       {"fpc0: \nconfiguration check succeeds\n", sets + "no answer from fpc1, fpc2, fpc3"},
		"no member":        {"configuration check succeeds\n", sets + "no answer from fpc0, fpc1, fpc2, fpc3"},
		"an extra":         {vcCheck + "fpc4: \nconfiguration check succeeds\n", sets + "an answer from fpc4, which 'show version' did not list"},
		"missing, extra":   {"fpc0: \nconfiguration check succeeds\nfpc1: \nconfiguration check succeeds\nfpc2: \nconfiguration check succeeds\nre3: \nconfiguration check succeeds\n", "labels of two kinds, fpc0 and re3"},
		"one and an extra": {"fpc0: \nconfiguration check succeeds\nfpc1: \nconfiguration check succeeds\nfpc2: \nconfiguration check succeeds\nfpc9: \nconfiguration check succeeds\n", sets + "no answer from fpc3; an answer from fpc9, which 'show version' did not list"},
	} {
		ok, why := checkAnswer(split(c.in), set)
		if ok || why != c.why {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	chk := func(l string) string { return l + ": \nconfiguration check succeeds\n" }
	done := func(l string) string { return l + ": \ncommit complete\n" }
	all := func(f func(string) string) string {
		var b strings.Builder
		for _, l := range set {
			b.WriteString(f(l))
		}
		return b.String()
	}
	note := plan.ApplyConfirmedNote(5)
	good := all(chk) + note + "\n" + all(done)
	if ok, why := readCommitted(split(good), set, note, textCommitComplete); !ok {
		t.Errorf("a whole answer: %s", why)
	}
	for name, c := range map[string]struct{ in, why string }{
		"commit names one": {all(chk) + note + "\n" + done("fpc0"), `member fpc1 did not answer "commit complete"`},
		"names only one":   {note + "\n" + done("fpc0"), sets + "no answer from fpc1, fpc2, fpc3"},
		"check only":       {all(chk) + note + "\n", `member fpc0 did not answer "commit complete"`},
		"unlabelled":       {"configuration check succeeds\n" + note + "\ncommit complete\n", sets + "no answer from fpc0, fpc1, fpc2, fpc3"},
		"an extra member":  {good + done("fpc5"), sets + "an answer from fpc5, which 'show version' did not list"},
		"one has no done":  {all(chk) + note + "\n" + done("fpc0") + done("fpc1") + done("fpc2"), `member fpc3 did not answer "commit complete"`},
	} {
		ok, why := readCommitted(split(c.in), set, note, textCommitComplete)
		if ok || !strings.HasPrefix(why, c.why) {
			t.Errorf("%s: ok %v, why %q, want %q", name, ok, why, c.why)
		}
	}
	// the single device: no member listed, no member judged by a set
	if ok, why := readCommitted(split("configuration check succeeds\ncommit complete\n"), nil, textCommitComplete); !ok {
		t.Errorf("single: %s", why)
	}
}

// The labels of 'show version' are the members, in order; two kinds, or a
// label twice, is refused.
func TestParseVersionMemberLabels(t *testing.T) {
	id, err := parseVersion(vcVersion)
	if err != nil || strings.Join(id.Members, ",") != "fpc0,fpc1,fpc2,fpc3" {
		t.Errorf("%+v %v", id.Members, err)
	}
	id, err = parseVersion("Hostname: sw1.example.net\nModel: ex4300-48t\nJunos: 21.4R3-S2.4\n")
	if err != nil || len(id.Members) != 0 {
		t.Errorf("single: %+v %v", id.Members, err)
	}
	for name, in := range map[string]string{
		"two kinds": "re0:\nHostname: a\nJunos: 1\nfpc1:\nHostname: a\nJunos: 1\n",
		"twice":     "fpc0:\nHostname: a\nJunos: 1\nfpc0:\nHostname: a\nJunos: 1\n",
	} {
		if _, err := parseVersion(in); !errors.Is(err, ErrUnrecognised) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The NETCONF reply names the members as <routing-engine> elements (a shape
// inferred from the fake; no capture of a device with members). Each member,
// the same name over its elements, answers the check's success alone, or the
// commit's success after the check's or alone: never an error, never another
// member's success.
func TestNetconfReplyMembers(t *testing.T) {
	const ck, cs = "<commit-check-success/>", "<commit-success/>"
	re := func(name, el string) string {
		return "<routing-engine><name>" + name + "</name>" + el + "</routing-engine>"
	}
	wrap := func(s string) string { return "<commit-results>" + s + "</commit-results>" }
	four := func(el string) string {
		return re("fpc0", el) + re("fpc1", el) + re("fpc2", el) + re("fpc3", el)
	}
	chassis := []string{"fpc0", "fpc1", "fpc2", "fpc3"}
	for name, c := range map[string]struct {
		in     string
		commit bool
		set    []string
		want   string // "" is a whole reply
	}{
		"no members":        {wrap(""), false, chassis, ""},
		"one engine":        {wrap(re("re0", ck)), false, nil, ""},
		"four checks":       {wrap(four(ck)), false, chassis, ""},
		"commit alone":      {wrap(four(cs)), true, chassis, ""},
		"check then commit": {wrap(four(ck) + four(cs)), true, chassis, ""},
		"ok":                {wrap(four("<ok/>")), true, chassis, ""},
		"interleaved":       {wrap(re("fpc0", ck) + re("fpc1", cs) + re("fpc0", cs) + re("fpc2", ck+cs) + re("fpc3", cs)), true, chassis, ""},
		"single commit":     {wrap(re("re0", cs)), true, nil, ""},
		"silent":            {wrap(re("fpc0", ck) + re("fpc1", "")), false, nil, "member fpc1 did not answer <commit-check-success/>"},
		"silent commit":     {wrap(four(ck) + re("fpc0", cs)), true, nil, "member fpc1 answered <commit-check-success/>, not"},
		"commit for check":  {wrap(re("fpc0", cs)), false, nil, "member fpc0 answered <commit-success/>, not <commit-check-success/>"},
		"another's success": {wrap(re("fpc0", ck+cs) + re("fpc1", "")), true, nil, "member fpc1 did not answer <commit-success/>"},
		"check twice":       {wrap(re("fpc0", ck) + re("fpc0", ck)), false, nil, "member fpc0 answered <commit-check-success/><commit-check-success/>, not"},
		"commit twice":      {wrap(re("fpc0", cs+cs)), true, nil, "member fpc0 answered <commit-success/><commit-success/>, not"},
		"commit then check": {wrap(re("fpc0", cs+ck)), true, nil, "member fpc0 answered <commit-success/><commit-check-success/>, not"},
		"no name":           {wrap("<routing-engine>" + ck + "</routing-engine>"), false, nil, "a member without a name"},
		"missing":           {wrap(re("fpc0", ck) + re("fpc1", ck)), false, chassis, "the members that answered are not the chassis' (fpc0, fpc1, fpc2, fpc3): no answer from fpc2, fpc3"},
		"extra":             {wrap(four(ck) + re("fpc4", ck)), false, chassis, "an answer from fpc4, which 'show version' did not list"},
		"commit missing":    {wrap(four(ck) + re("fpc0", cs)), true, chassis, "member fpc1 answered"},
		"other name":        {wrap(re("re0", ck)), false, chassis, "no answer from fpc0, fpc1, fpc2, fpc3; an answer from re0"},
	} {
		r, err := parseReply(c.in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		j := &JunosNetconf{members: c.set}
		err = j.memberRefusal("commit check", r, c.commit)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case c.want != "" && (err == nil || !errors.Is(err, ErrUnrecognised) || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}

// An <rpc-error> inside a member's element names the member in the error.
func TestNetconfMemberErrorNamesTheMember(t *testing.T) {
	const reply = "<commit-results><routing-engine><name>fpc0</name><commit-check-success/></routing-engine>" +
		"<routing-engine><name>fpc2</name><rpc-error><error-severity>error</error-severity><error-message>statement not found</error-message></rpc-error></routing-engine></commit-results>"
	r, err := parseReply(reply)
	if err != nil || len(r.Errs) != 1 || r.Errs[0].Member != "fpc2" {
		t.Fatalf("%+v %v", r.Errs, err)
	}
	j := &JunosNetconf{}
	e := j.firstError("commit check", r)
	if !errors.Is(e, ErrRefused) || e.Error() != "commit check: member fpc2: error: statement not found" {
		t.Errorf("%v", e)
	}
	// an error outside any member is as it was
	r, _ = parseReply("<rpc-error><error-severity>error</error-severity><error-message>x</error-message></rpc-error>")
	if e := j.firstError("commit check", r); e.Error() != "commit check: error: x" {
		t.Errorf("%v", e)
	}
}
