package devapply

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/devconf/plan"
)

func TestFailedAllowNotReady(t *testing.T) {
	d := newDevice(t, nil)
	o := check(t, d, &planner{desired: desiredLines()}, func(in *Input) { in.Allow.Expected = nil })
	wantExit(t, o, ExitFailed, ResultFailed)
	if !strings.Contains(o.Reason, "the allow-list is not ready (nothing was sent)") || indexOf(o.Log, plan.ApplyConfigure) >= 0 {
		t.Errorf("%q %q", o.Reason, o.Log)
	}
	o = check(t, d, &planner{desired: desiredLines()}, func(in *Input) { in.Allow.Login = "" })
	wantExit(t, o, ExitFailed, ResultFailed)
}

func TestFailedOwnClass(t *testing.T) {
	// the held login is super-user: a leaf of that class that the rendering
	// does not set is refused
	d := newDevice(t, nil)
	o := check(t, d, &planner{}, func(in *Input) {
		in.Plan = func(context.Context, string, netIP) (plan.Delta, error) {
			return deltaOf(plan.Line{Section: "roles", Op: plan.OpSet, Text: "set system login class super-user idle-timeout 5"}), nil
		}
	})
	wantExit(t, o, ExitFailed, ResultFailed)
	if !strings.Contains(o.Reason, "statement outside the planner's domain") {
		t.Errorf("%q", o.Reason)
	}
}

func TestLockBusy(t *testing.T) {
	d := newDevice(t, nil)
	lk, err := LockDevice(d.state, "example-sw1")
	if err != nil {
		t.Fatal(err)
	}
	o := check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitFailed, ResultFailed)
	if !strings.Contains(o.Reason, "another apply is running on the device: example-sw1") || len(o.Log) != 0 {
		t.Errorf("%q %q", o.Reason, o.Log)
	}
	lk.Unlock()
	lk.Unlock()
	if _, err := LockDevice(d.state, "../x"); err == nil {
		t.Error("a path as a device name")
	}
	o = check(t, d, &planner{desired: desiredLines()}, nil)
	wantExit(t, o, ExitChecked, ResultChecked)
}

func TestCancelMarginNothingTyped(t *testing.T) {
	// the verification fails with less than the cancel margin left: a
	// 'rollback 1' then could load the change itself, so nothing is typed
	d := newDevice(t, nil)
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Hold = func(context.Context, time.Time) (bool, error) {
			d.clk.Advance(9*time.Minute + 40*time.Second)
			return false, nil
		}
	})
	wantExit(t, o, ExitPending, ResultPending)
	if indexOf(o.Log, plan.ApplyRollback1) >= 0 || !strings.Contains(o.Reason, "too little of the window was left to cancel") {
		t.Errorf("%q %q", o.Reason, o.Log)
	}
}

// confirmT answers the confirm with a text the transport does not know,
// without typing it.
type confirmT struct{ *JunosCLI }

func (confirmT) Confirm(context.Context, string, string) error {
	return &AnswerError{Cmd: "commit", Lines: []string{"error: something"}, base: ErrRefused}
}

func TestConfirmAnswerUnknown(t *testing.T) {
	d := newDevice(t, nil)
	o := apply(t, d, &planner{desired: desiredLines()}, func(in *Input) {
		in.Transport = confirmT{in.Transport.(*JunosCLI)}
	})
	// the state is read: still pending; the confirm is never retried from
	// another session and nothing else is committed
	wantExit(t, o, ExitPending, ResultPending)
	if !strings.Contains(o.Reason, "the confirm's answer") || o.Until.IsZero() {
		t.Errorf("%q", o.Reason)
	}
	if _, p := d.srv.PendingUntil(); !p {
		t.Error("not pending")
	}
}

func TestSettle(t *testing.T) {
	id := "tacctl-20261013T140000Z-3f2a"
	at := func(s string) CommitEntry {
		return CommitEntry{TimeText: "2026-10-13 " + s + " UTC", User: "alice", Via: "cli"}
	}
	pre := at("13:00:00")
	ourC := at("14:00:00")
	ourC.Comment, ourC.RollbackIn = "tacctl apply "+id+" by alice", 10
	conf := at("14:01:00")
	conf.Comment = "tacctl apply confirm " + id + " by alice"
	canc := at("14:01:00")
	canc.Comment = "tacctl apply cancel " + id
	exp := CommitEntry{TimeText: "2026-10-13 14:10:00 UTC", User: "root", Via: "other"}
	other := CommitEntry{TimeText: "2026-10-13 14:02:00 UTC", User: "bob", Via: "cli"}
	until := testStart.Add(10 * time.Minute)
	during, after := testStart.Add(time.Minute), until.Add(settleSlack)
	// the pending marker is the banner (pending), never the label (lab L2)
	cases := []struct {
		h       History
		pending bool
		pre     CommitEntry
		now     time.Time
		want    Exit
		facts   factsNeed
		over    bool
	}{
		{History{pre}, false, pre, during, ExitNothingCommitted, factsNo, false},
		{History{other, pre}, false, pre, during, ExitUnknown, factsNo, false},
		{History{ourC, pre}, true, pre, during, ExitPending, factsNo, false},
		{History{conf, ourC, pre}, false, pre, during, ExitApplied, factsNo, false},
		{History{canc, ourC, pre}, false, pre, during, ExitRolledBack, factsNo, false},
		// 'by root via other' is the device's own rollback or a commit of the
		// system that confirmed it: settled from the configuration
		{History{exp, ourC, pre}, false, pre, after, ExitUnknown, factsRequired, false},
		// a commit after ours that is not one tacctl recognises: never taken
		// for a confirm from the history alone (the caller reads the facts)
		{History{other, ourC, pre}, false, pre, during, ExitUnknown, factsRequired, false},
		// a confirm after the device's own rollback: the entry above ours
		// tells
		{History{conf, exp, ourC, pre}, false, pre, after, ExitUnknown, factsRequired, false},
		{History{pre}, false, CommitEntry{}, during, ExitUnknown, factsNo, false},
		// ours at entry 0 with its label and no banner, before the window's
		// end: a 'commit check' may have confirmed it, or the device printed
		// no banner and rolls it back at the end: pending
		{History{ourC, pre}, false, pre, during, ExitPending, factsNo, false},
		{History{ourC, pre}, false, pre, until, ExitPending, factsNo, false},
		// after the window's end: confirmed without an entry, settled from
		// the configuration when it can be
		{History{ourC, pre}, false, pre, after, ExitAppliedByOther, factsPreferred, false},
		// the window's end not known: unknown
		{History{ourC, pre}, false, pre, time.Time{}, ExitUnknown, factsNo, false},
		// the banner over another entry: someone's later pending commit
		{History{other, ourC, pre}, true, pre, during, ExitUnknown, factsNo, false},
		// the banner and no commit of ours
		{History{other, pre}, true, pre, during, ExitUnknown, factsNo, false},
		// the banner over a stranger's entry, the entry above ours names its
		// fate: reported, with the stranger's pending commit
		{History{other, canc, ourC, pre}, true, pre, during, ExitRolledBack, factsNo, true},
		{History{other, conf, ourC, pre}, true, pre, during, ExitApplied, factsNo, true},
		{History{other, exp, ourC, pre}, true, pre, after, ExitUnknown, factsRequired, true},
	}
	for i, c := range cases {
		u := until
		if c.now.IsZero() {
			c.now, u = during, time.Time{}
		}
		s := settle(CommitState{History: c.h, Pending: c.pending, Minutes: 3}, id, c.pre, c.now, u)
		if s.e != c.want || s.facts != c.facts || s.over != c.over {
			t.Errorf("%d: %s facts %d over %v, want %s %d %v (%s)", i, s.e, s.facts, s.over, c.want, c.facts, c.over, s.how)
		}
		if s.over && (!strings.Contains(s.how, "a later confirmed commit (by bob via cli at 2026-10-13 14:02:00 UTC) is pending") || !s.until.Equal(c.now.Add(4*time.Minute))) {
			t.Errorf("%d: %q %v", i, s.how, s.until)
		}
	}
}

func TestParsersFailClosed(t *testing.T) {
	if _, err := parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli commit something new\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("an unknown tail on entry 0: %v", err)
	}
	if _, err := parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli\nwhatever\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("a stray line: %v", err)
	}
	if _, err := parseHistory(""); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("empty: %v", err)
	}
	if _, err := parseHistory("error: permission denied\n"); !errors.Is(err, ErrRefused) {
		t.Errorf("a refusal: %v", err)
	}
	h, err := parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli commit confirmed, rollback in 10mins\n    tacctl apply x by alice\n1   2026-10-12 01:00:00 UTC by root via other\n")
	if err != nil || len(h) != 2 || h[0].RollbackIn != 10 || h[0].Comment != "tacctl apply x by alice" || h[0].Until() != "2026-10-13 14:10:00 UTC" {
		t.Errorf("%+v %v", h, err)
	}
	if _, err := parseVersion("Model: ex\nJunos: 25.4R1\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("no hostname: %v", err)
	}
	if _, err := parseVersion("Hostname: a\nJunos: 1\nHostname: b\nJunos: 1\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("two hostnames: %v", err)
	}
	if _, err := parseVersion("Hostname: a\nJunos: 1\nHostname: a\nJunos: 2\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("two releases: %v", err)
	}
	if id, err := parseVersion("fpc0:\n--------\nHostname: a\nModel: ex4600-40f\nJunos: 25.4R1\n\nfpc1:\n--------\nHostname: a\nModel: ex4300-48t\nJunos: 25.4R1\n"); err != nil || id.Model != "ex4600-40f" || id.Hostname != "a" || id.Release != "25.4R1" {
		t.Errorf("a mixed virtual chassis: %+v %v", id, err)
	}
	if id, err := parseVersion("fpc0:\n--------\nHostname: a\nModel: ex4200-48t\nJUNOS Base OS boot [12.3R12-S15.1]\nJUNOS Base OS Software Suite [12.3R12-S15.1]\n"); err != nil || id.Release != "12.3R12-S15.1" {
		t.Errorf("an older Junos: %+v %v", id, err)
	}
	if id, err := parseVersion("Hostname: a\nModel: srx300\nJUNOS Software Release [12.1X46-D40.2]\n"); err != nil || id.Release != "12.1X46-D40.2" {
		t.Errorf("a software release line: %+v %v", id, err)
	}
	if _, err := parseVersion("Hostname: a\nModel: x\n"); err == nil || !strings.Contains(err.Error(), "no Junos line") {
		t.Errorf("no release: %v", err)
	}
	if _, err := parseVersion("Welcome\nsomething else\n"); err == nil || !strings.Contains(err.Error(), `starts "Welcome"`) {
		t.Errorf("neither: %v", err)
	}
	if _, err := parseAuthorization("Current user: alice\nPermissions:\n    all\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("no class: %v", err)
	}
	if _, err := parseAuthorization("Current user: alice login: alice class: super-user\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("no permissions: %v", err)
	}
	if lg, err := parseAuthorization("Current user: alice login: alice class: eng\nPermissions:\n    configure view\n"); err != nil || lg.CanCommit() {
		t.Errorf("a narrower class may commit: %+v %v", lg, err)
	}
	// an answer with no location line is not a configure-mode answer
	if _, ok := configAnswer("configuration check succeeds\n"); ok {
		t.Error("no [edit] line taken for an answer")
	}
	if b, ok := configAnswer("configuration check succeeds\n\n{master:0}[edit]\n"); !ok || !exactly(b, textCheckOK) {
		t.Errorf("%q %v", b, ok)
	}
	// a compare cut at a block boundary: the location line is missing, and
	// the parser never sees it
	if _, ok := configAnswer("[edit system]\n+  accounting {\n+      events login;\n+  }\n"); ok {
		t.Error("a cut compare was taken whole")
	}
}

func TestShapesStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "device-apply")
	s := OpenShapes(dir)
	lines := []string{"[aaa]", "set system accounting events login"}
	h := plan.ShapeHash(lines)
	if err := s.Confirm("000000000000", lines, Confirmation{Device: "a"}); err == nil {
		t.Error("lines filed under another hash")
	}
	if ok, err := s.Confirmed(h); ok || err != nil {
		t.Fatal(ok, err)
	}
	at := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	if err := s.Confirm(h, lines, Confirmation{Device: "b", At: at.Add(time.Hour), By: "alice", ID: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Confirm(h, lines, Confirmation{Device: "a", At: at, By: "alice", Seeded: true}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Load()
	if err != nil || len(m[h].Confirmed) != 2 || m[h].Confirmed[0].Device != "a" || m[h].Algo != plan.ShapeAlgo {
		t.Fatalf("%+v %v", m, err)
	}
	fi, err := os.Stat(filepath.Join(dir, ShapesFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v %v", fi, err)
	}
	di, _ := os.Stat(dir)
	if di.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", di.Mode())
	}
	// an older algorithm is re-filed from its lines
	if err := os.WriteFile(filepath.Join(dir, ShapesFile), []byte(`{"old":{"algo":0,"lines":["[aaa]","set system accounting events login"],"confirmed":[{"device":"c","at":"2026-10-13T00:00:00Z","by":"x"}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Confirmed(h); !ok {
		t.Error("not re-filed")
	}
}

func TestNameMatchesAndID(t *testing.T) {
	for _, c := range []struct {
		rep   string
		names []string
		ok    bool
	}{
		{"SW1", []string{"sw1"}, true},
		{"sw1", []string{"sw1.lab.example.net"}, true},
		{"sw1", []string{"x", "sw1.example.net"}, true},
		{"sw1.lab.example.net", []string{"sw1"}, false},
		{"sw2", []string{"sw1"}, false},
		{"", []string{""}, false},
	} {
		if NameMatches(c.rep, c.names...) != c.ok {
			t.Errorf("%q %q", c.rep, c.names)
		}
	}
	if _, err := NewID(testStart, nil); err == nil {
		t.Error("no random source accepted")
	}
	id, err := NewID(testStart, strings.NewReader("\xab\xcd"))
	if err != nil || id != "tacctl-20261013T140000Z-abcd" {
		t.Errorf("%q %v", id, err)
	}
	if !plan.IsApplyWord(plan.ApplyCommitConfirmed(10, id, "alice")) {
		t.Error("the id is not an apply word")
	}
}

func TestMasker(t *testing.T) {
	m := newMasker(desiredLines())
	for _, s := range []string{
		"error: could not set " + secretKey,
		`set system tacplus-server 192.0.2.11 secret "` + secretKey + `"`,
		"community " + secretComm + " is bad",
	} {
		if out := m.text(s); strings.Contains(out, secretKey) || strings.Contains(out, secretComm) {
			t.Errorf("%q -> %q", s, out)
		}
	}
	if m.text("set system accounting events login") != "set system accounting events login" {
		t.Error("a plain statement changed")
	}
}
