package shell

import (
	"context"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/ui"
)

// lockTestMu guards the variables lockOptions shares with a test that reads
// them while the session still runs.
var lockTestMu sync.Mutex

// lockOptions are the options of a session held to a required password
// change until 'passwd' has run.
func lockOptions(locked *bool, ran *[]string, refused *[]string) Options {
	return Options{
		Prompt:   "host> ",
		Complete: testCompleter,
		Exec: func(_ context.Context, words []string, _ io.Reader) int {
			lockTestMu.Lock()
			defer lockTestMu.Unlock()
			*ran = append(*ran, strings.Join(words, " "))
			if len(words) == 1 && words[0] == "passwd" {
				*locked = false
			}
			return 0
		},
		Help: func([]string) (string, bool) { return "a help\n", true },
		SystemShell: func(context.Context, bool) int {
			lockTestMu.Lock()
			defer lockTestMu.Unlock()
			*ran = append(*ran, "system-shell")
			return 0
		},
		Locked: func() bool {
			lockTestMu.Lock()
			defer lockTestMu.Unlock()
			return *locked
		},
		LockWords:  []string{"passwd"},
		LockNotice: "locked: only passwd",
		LockRefused: func(w []string) {
			lockTestMu.Lock()
			defer lockTestMu.Unlock()
			*refused = append(*refused, strings.Join(w, " "))
		},
	}
}

// A locked session runs 'passwd' and 'exit' alone and nothing else; each
// other line is refused with the notice, status 1 and a word for the log; the
// lock lifts the moment the answer does.
func TestLockedSessionRunsOnlyTheLockWords(t *testing.T) {
	locked := true
	var ran, refused []string
	var out, errb strings.Builder
	o := lockOptions(&locked, &ran, &refused)
	o.Out = ui.Output{Stdout: &out, Stderr: &errb}
	sh := New(o)
	ctx := context.Background()
	for _, line := range []string{"user list", "help", "help user", "history", "system-shell", "console forget", "passwd now", "passwd --help",
		"tacctl", "sudo tacctl user list", "tacctl passwd extra", "exit now", "  ", "status 3"} {
		status, quit := sh.run(ctx, line, nil)
		if strings.TrimSpace(line) == "" {
			if status != 0 || quit {
				t.Errorf("a blank line: %d %t", status, quit)
			}
			continue
		}
		want := 1
		if line == "exit now" {
			want = 1 // refused as the notice says: exit takes no arguments
		}
		if status != want || quit {
			t.Errorf("%q: status %d quit %t, want a refusal", line, status, quit)
		}
	}
	if len(ran) != 0 {
		t.Errorf("a locked session ran %q", ran)
	}
	if got := strings.Count(errb.String(), "locked: only passwd"); got != 13 {
		t.Errorf("%d notices:\n%s", got, errb.String())
	}
	if len(refused) != 13 || refused[0] != "user list" || refused[8] != "" {
		t.Errorf("refused %q", refused)
	}
	// the change runs, alone, and unlocks
	if status, quit := sh.run(ctx, "passwd", nil); status != 0 || quit || locked {
		t.Errorf("passwd: %d %t, locked %t", status, quit, locked)
	}
	if status, _ := sh.run(ctx, "user list", nil); status != 0 {
		t.Errorf("after the change: %d", status)
	}
	if strings.Join(ran, ";") != "passwd;user list" {
		t.Errorf("ran %q", ran)
	}
	// 'exit' and 'quit' end a locked session
	locked = true
	for _, w := range []string{"exit", "quit"} {
		if status, quit := sh.run(ctx, w, nil); status != 0 || !quit {
			t.Errorf("%s: %d %t", w, status, quit)
		}
	}
}

// A batch of lines in a locked session stops at the first refusal.
func TestLockedBatchStopsAtTheFirstRefusal(t *testing.T) {
	locked := true
	var ran, refused []string
	o := lockOptions(&locked, &ran, &refused)
	var out, errb strings.Builder
	o.Out = ui.Output{Stdout: &out, Stderr: &errb}
	if status := New(o).Batch(context.Background(), strings.NewReader("user list\npasswd\n")); status != 1 || len(ran) != 0 {
		t.Errorf("status %d, ran %q", status, ran)
	}
	locked = true
	if status := New(o).Batch(context.Background(), strings.NewReader("passwd\nuser list\n")); status != 0 || strings.Join(ran, ";") != "passwd;user list" {
		t.Errorf("status %d, ran %q", status, ran)
	}
	// -c
	locked, ran = true, nil
	if status := New(o).Command(context.Background(), "user list", nil); status != 1 || len(ran) != 0 {
		t.Errorf("-c: %d %q", status, ran)
	}
	if status := New(o).Command(context.Background(), "passwd", nil); status != 0 || len(ran) != 1 {
		t.Errorf("-c passwd: %d %q", status, ran)
	}
}

// At the prompt of a locked session the lists name exit and what the
// completer offers, not help, history or system-shell, and a typed 'help'
// is refused; once the lock lifts the lists are whole again.
func TestInProcessLockedLists(t *testing.T) {
	locked := true
	var ran, refused []string
	o := lockOptions(&locked, &ran, &refused)
	o.Complete = func(words []string, partial string) []Candidate {
		if len(words) == 0 {
			return []Candidate{{Word: "passwd", Desc: "Change your own password", Fixed: true, Command: true}}
		}
		return nil
	}
	p := startInProcess(t, o, 24, 80)
	p.send("?")
	p.expect(`Possible completions:`)
	p.expect(`passwd`)
	p.expect(`host> `)
	// a locked session completes no word that does not run: 'hel' stays
	// 'hel' (it would be 'help ' otherwise), and is refused as typed
	p.send("hel\t")
	p.send("\r")
	p.expect(`locked: only passwd`)
	p.expect(`\[exit 1\]`)
	p.expect(`host> `)
	p.send("passwd\r")
	p.expect(`host> `)
	// unlocked, the word completes and runs
	p.send("hel\t\r")
	p.expect(`a help`)
	p.expect(`host> `)
	p.send("exit\r")
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	if strings.Join(ran, ";") != "passwd" || len(refused) != 1 || refused[0] != "hel" {
		t.Errorf("ran %q refused %q", ran, refused)
	}
}

// Opening runs before the first prompt: ended, the session has no prompt and
// ends with its status (EndLocked); not ended, the prompt follows.
func TestOpeningEndsOrOpensTheSession(t *testing.T) {
	for _, end := range []bool{true, false} {
		opened := make(chan struct{}, 1)
		o := Options{Prompt: "host> ", Exec: func(context.Context, []string, io.Reader) int { return 0 },
			Opening: func(context.Context) (bool, int) {
				opened <- struct{}{}
				return end, 130
			}}
		p := startInProcessNoPrompt(t, o, 24, 80)
		select {
		case <-opened:
		case <-time.After(5 * time.Second):
			t.Fatal("Opening did not run")
		}
		if end {
			if s := p.ends(); s != 130 {
				t.Errorf("status %d", s)
			}
			if r, _ := p.sh.End(); r != EndLocked {
				t.Errorf("reason %q", r)
			}
			if strings.Contains(string(p.buf), "host> ") {
				t.Errorf("a prompt after an ended opening: %q", p.buf)
			}
			continue
		}
		p.expect(`host> `)
		p.send("exit\r")
		if s := p.ends(); s != 0 {
			t.Errorf("status %d", s)
		}
	}
}

// A line typed while the session is locked (a password typed at the prompt
// after the dialog failed, say) is not recorded in the history file; the
// lines of the unlocked session are. -c is held to it too.
func TestLockedSessionRecordsNothingInTheHistory(t *testing.T) {
	path := t.TempDir() + "/history"
	locked := true
	var ran, refused []string
	o := lockOptions(&locked, &ran, &refused)
	o.History = NewHistory(path, nil)
	p := startInProcess(t, o, 24, 80)
	p.send("hunter2-typed-as-a-line\r")
	p.expect(`locked: only passwd`)
	p.expect(`host> `)
	p.send("passwd\r")
	p.expect(`host> `)
	p.send("user list\r")
	p.expect(`host> `)
	p.send("exit\r")
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); strings.Contains(got, "hunter2") || strings.Contains(got, "passwd") || !strings.Contains(got, "user list") {
		t.Errorf("history file:\n%s", got)
	}
	// -c
	locked = true
	h := NewHistory("", nil)
	o = lockOptions(&locked, &ran, &refused)
	o.History = h
	var out, errb strings.Builder
	o.Out = ui.Output{Stdout: &out, Stderr: &errb}
	sh := New(o)
	sh.Command(context.Background(), "hunter2", nil)
	locked = false
	sh.Command(context.Background(), "user list", nil)
	if e := h.Entries(); len(e) != 1 || e[0] != "user list" {
		t.Errorf("entries %q", e)
	}
}

// The opening is held to the idle time: a dialog that is never answered ends
// the session as an idle one, with the context of the opening cancelled; an
// opening that finishes in time is unaffected.
func TestOpeningIsHeldToTheIdleTime(t *testing.T) {
	cancelled := make(chan struct{}, 1)
	o := Options{Prompt: "host> ", Idle: 300 * time.Millisecond, Exec: func(context.Context, []string, io.Reader) int { return 0 },
		Opening: func(ctx context.Context) (bool, int) {
			select {
			case <-ctx.Done():
				cancelled <- struct{}{}
			case <-time.After(10 * time.Second):
			}
			return false, 0
		}}
	p := startInProcessNoPrompt(t, o, 24, 80)
	p.expect(`idle timeout after 300ms`)
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	select {
	case <-cancelled:
	default:
		t.Error("the context of the opening was not cancelled")
	}
	if r, _ := p.sh.End(); r != EndIdle {
		t.Errorf("reason %q", r)
	}
	if strings.Contains(string(p.buf), "host> ") {
		t.Errorf("a prompt after the idle opening: %q", p.buf)
	}
	// finished in time: the prompt follows
	o.Opening = func(context.Context) (bool, int) { return false, 0 }
	p = startInProcessNoPrompt(t, o, 24, 80)
	p.expect(`host> `)
	p.send("exit\r")
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
}

// Relock is asked for each line the lock would refuse, not for the lines it
// allows, and lifts the lock for the line that finds the requirement gone.
func TestRelockLiftsTheLockForTheLineThatFindsItGone(t *testing.T) {
	locked := true
	asked := 0
	var ran, refused []string
	var out, errb strings.Builder
	o := lockOptions(&locked, &ran, &refused)
	o.Out = ui.Output{Stdout: &out, Stderr: &errb}
	o.Relock = func() {
		asked++
		if asked == 2 {
			locked = false
		}
	}
	sh := New(o)
	ctx := context.Background()
	if status, _ := sh.run(ctx, "user list", nil); status != 1 || asked != 1 || len(ran) != 0 {
		t.Errorf("first: status %d asked %d ran %q", status, asked, ran)
	}
	// exit is allowed while locked: no question
	if _, quit := sh.run(ctx, "exit", nil); !quit || asked != 1 {
		t.Errorf("exit: quit %t asked %d", quit, asked)
	}
	if status, _ := sh.run(ctx, "user list", nil); status != 0 || asked != 2 || len(ran) != 1 || ran[0] != "user list" {
		t.Errorf("second: status %d asked %d ran %q", status, asked, ran)
	}
	// unlocked, nothing is asked
	sh.run(ctx, "user show bob", nil)
	if asked != 2 {
		t.Errorf("asked %d", asked)
	}
	o.LockNoticeFunc = func() string { return "dynamic notice" }
	locked = true
	o.Relock = nil
	sh = New(o)
	sh.run(ctx, "user list", nil)
	if !strings.Contains(errb.String(), "dynamic notice") {
		t.Errorf("stderr %q", errb.String())
	}
}

// While the session is locked the line editor recalls nothing: Up and the
// Ctrl-R search find no earlier line (they are the account's, and 'history'
// is refused as well); once the lock lifts, they recall again.
func TestLockedSessionRecallsNothingFromTheHistory(t *testing.T) {
	path := t.TempDir() + "/history"
	if err := os.WriteFile(path, []byte("user show alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := true
	var ran, refused []string
	o := lockOptions(&locked, &ran, &refused)
	o.History = NewHistory(path, nil)
	p := startInProcess(t, o, 24, 80)
	p.send("\x1b[A\r")
	p.expect(`host> `)
	p.send("\x12user\r")
	p.expect(`host> `)
	lockTestMu.Lock()
	if len(refused) != 0 || len(ran) != 0 {
		t.Errorf("a line was recalled while locked: refused %q ran %q", refused, ran)
	}
	lockTestMu.Unlock()
	p.send("passwd\r")
	p.expect(`host> `)
	p.send("\x1b[A\r")
	p.expect(`host> `)
	p.send("exit\r")
	if s := p.ends(); s != 0 {
		t.Errorf("status %d", s)
	}
	if strings.Join(ran, "|") != "passwd|user show alice" {
		t.Errorf("ran %q", ran)
	}
}
