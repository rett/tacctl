package devrollout

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
	if !strings.Contains(o.Reason, "the allow-list is not ready (nothing was sent)") || indexOf(o.Log, plan.RolloutConfigure) >= 0 {
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
	if !strings.Contains(o.Reason, "another rollout is running on the device: example-sw1") || len(o.Log) != 0 {
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
	if indexOf(o.Log, plan.RolloutRollback1) >= 0 || !strings.Contains(o.Reason, "too little of the window was left to cancel") {
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
	ourC.Comment, ourC.RollbackIn = "tacctl rollout "+id+" by alice", 10
	conf := at("14:01:00")
	conf.Comment = "tacctl rollout confirm " + id + " by alice"
	canc := at("14:01:00")
	canc.Comment = "tacctl rollout cancel " + id
	exp := CommitEntry{TimeText: "2026-10-13 14:10:00 UTC", User: "root", Via: "other"}
	other := CommitEntry{TimeText: "2026-10-13 14:02:00 UTC", User: "bob", Via: "cli"}
	cases := []struct {
		h    History
		pre  CommitEntry
		want Exit
	}{
		{History{pre}, pre, ExitNothingCommitted},
		{History{other, pre}, pre, ExitUnknown},
		{History{ourC, pre}, pre, ExitPending},
		{History{conf, ourC, pre}, pre, ExitApplied},
		{History{canc, ourC, pre}, pre, ExitRolledBack},
		{History{exp, ourC, pre}, pre, ExitRolledBack},
		{History{other, ourC, pre}, pre, ExitAppliedByOther},
		// a confirm after the device's own rollback: the rollback stands
		{History{conf, exp, ourC, pre}, pre, ExitRolledBack},
		{History{pre}, CommitEntry{}, ExitUnknown},
	}
	for i, c := range cases {
		if e, _, _ := settle(c.h, id, c.pre); e != c.want {
			t.Errorf("%d: %s, want %s", i, e, c.want)
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
	h, err := parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli commit confirmed, rollback in 10mins\n    tacctl rollout x by alice\n1   2026-10-12 01:00:00 UTC by root via other\n")
	if err != nil || len(h) != 2 || h[0].RollbackIn != 10 || h[0].Comment != "tacctl rollout x by alice" || h[0].Until() != "2026-10-13 14:10:00 UTC" {
		t.Errorf("%+v %v", h, err)
	}
	if _, err := parseVersion("Model: ex\nJunos: 25.4R1\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("no hostname: %v", err)
	}
	if _, err := parseVersion("Hostname: a\nJunos: 1\nHostname: b\nJunos: 1\n"); !errors.Is(err, ErrUnrecognised) {
		t.Errorf("two hostnames: %v", err)
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
	dir := filepath.Join(t.TempDir(), "device-rollout")
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
	if !plan.IsRolloutWord(plan.RolloutCommitConfirmed(10, id, "alice")) {
		t.Error("the id is not a rollout word")
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
