package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

func TestValue(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"", "-"},
		{"alice", "alice"},
		{"core-sw1", "core-sw1"},
		{"192.0.2.10:22", "192.0.2.10:22"},
		{"pts/3", "pts/3"},
		{"admin@web1.example.net", "admin@web1.example.net"},
		{"a+b", "a+b"},
		{"core,lab", "core,lab"},
		{"20261021_093015_412,20261021_093016_001", "20261021_093015_412,20261021_093016_001"},
		{"a, b", `"a, b"`},
		{"two words", `"two words"`},
		{`say "hi"`, `"say \"hi\""`},
		{"a=b c", `"a=b c"`},
		{"line\nbreak", `"line\nbreak"`},
		{"tab\there", `"tab\there"`},
		{"café", `"café"`},
		{"bad\xffbyte", `"bad\xffbyte"`},
		{strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{strings.Repeat("a", 65), strings.Repeat("a", 64) + "..."},
		{strings.Repeat("a", 200), strings.Repeat("a", 64) + "..."},
		{strings.Repeat("a b ", 30), `"` + strings.Repeat("a b ", 16) + `..."`},
	} {
		if got := Value(c.in); got != c.want {
			t.Errorf("Value(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// A cut never ends in the middle of a character.
func TestValueCutsOnACharacterBoundary(t *testing.T) {
	v := strings.Repeat("a", 63) + "éé"
	got := Value(v)
	want := strings.Repeat("a", 63) + "..."
	if got != want {
		t.Errorf("Value = %s, want %s", got, want)
	}
}

func TestLine(t *testing.T) {
	r := &fake.Runner{}
	w := New(Options{Runner: r, SID: "k3x9a0bq"})
	w.Line(Notice, "user add", Pair("name", "alice"), Pair("scopes", "core,lab"), Pair("reason", "new hire"), Pair("tty", ""))
	// A comma is in the plain alphabet, so a list is written as it is.
	want := `user add name=alice scopes=core,lab reason="new hire" tty=- sid=k3x9a0bq`
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.notice", want) {
		t.Errorf("calls %q, want the line %s", r.Argvs(), want)
	}
	// A line with no fields is the event and the sid.
	w.Line(Info, "log clear")
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "log clear sid=k3x9a0bq") {
		t.Errorf("calls %q", r.Argvs())
	}
}

func TestRawKeepsTheWordsAndAddsTheSID(t *testing.T) {
	r := &fake.Runner{}
	w := New(Options{Runner: r, SID: "k3x9a0bq"})
	w.Raw(Info, "host forget name=web1 by=root")
	// The gate's lines end in a space when the command has no sub-verb: the
	// sid follows one space.
	w.Raw(Warning, "tier DENY user=bob tier=none cmd=version ")
	for _, want := range []struct{ prio, line string }{
		{"auth.info", "host forget name=web1 by=root sid=k3x9a0bq"},
		{"auth.warning", "tier DENY user=bob tier=none cmd=version sid=k3x9a0bq"},
	} {
		if !r.Called("logger", "-t", "tacctl", "-p", want.prio, want.line) {
			t.Errorf("calls %q, want %q at %s", r.Argvs(), want.line, want.prio)
		}
	}
}

func TestNoSIDMeansNoSIDKey(t *testing.T) {
	r := &fake.Runner{}
	New(Options{Runner: r}).Raw(Info, "x y ")
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "x y ") {
		t.Errorf("calls %q", r.Argvs())
	}
}

func TestWithTagSharesTheSIDAndTheWarning(t *testing.T) {
	r := &fake.Runner{}
	r.Fail([]string{"logger"}, 1, "")
	var warned []string
	w := New(Options{Runner: r, SID: "abcd1234", Warn: func(m string) { warned = append(warned, m) }})
	c := w.WithTag("tacctl-console")
	c.Raw(Info, "console start session=0123456789ab")
	w.Raw(Info, "ssh user=alice")
	c.Raw(Info, "console end session=0123456789ab")
	if !r.Called("logger", "-t", "tacctl-console", "-p", "auth.info", "console start session=0123456789ab sid=abcd1234") ||
		!r.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh user=alice sid=abcd1234") {
		t.Errorf("calls %q", r.Argvs())
	}
	if c.SID() != "abcd1234" || len(warned) != 1 {
		t.Errorf("sid %q, warnings %q (one for the process, whatever the tag)", c.SID(), warned)
	}
}

// The lines are written although the process context is done: a hangup that
// ends a command does not drop its last line.
func TestLinesAreWrittenOnACancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &fake.Runner{}
	w := New(Options{Runner: r, Ctx: ctx, SID: "abcd1234"})
	w.Line(Info, "ssh end", Pair("status", "129"))
	if !r.Called("logger", "-t", "tacctl", "-p", "auth.info", "ssh end status=129 sid=abcd1234") {
		t.Errorf("calls %q", r.Argvs())
	}
	if w.Failure() != "" {
		t.Errorf("Failure = %q", w.Failure())
	}
}

func TestLoggerMissingWarnsOnce(t *testing.T) {
	r := &fake.Runner{}
	r.Missing("logger")
	var warned []string
	w := New(Options{Runner: r, SID: "abcd1234", Warn: func(m string) { warned = append(warned, m) }})
	w.Line(Info, "one")
	w.Line(Info, "two")
	want := "The audit line was not written (logger: not found); the command continues."
	if len(warned) != 1 || warned[0] != want {
		t.Errorf("warnings %q, want one: %s", warned, want)
	}
	if w.Failure() != "not found" {
		t.Errorf("Failure = %q", w.Failure())
	}
}

func TestLoggerFailingWarnsOnce(t *testing.T) {
	r := &fake.Runner{}
	r.Fail([]string{"logger"}, 1, "logger: socket /dev/log: Connection refused\nmore")
	var warned []string
	w := New(Options{Runner: r, Warn: func(m string) { warned = append(warned, m) }})
	w.Raw(Info, "one")
	w.Raw(Info, "two")
	want := "The audit line was not written (logger: exit status 1: logger: socket /dev/log: Connection refused); the command continues."
	if len(warned) != 1 || warned[0] != want {
		t.Errorf("warnings %q, want one: %s", warned, want)
	}
	// A later line that is written clears the failure.
	r.On([]string{"logger"}, execx.Result{})
	w.Raw(Info, "three")
	if w.Failure() != "" {
		t.Errorf("Failure = %q after a line that was written", w.Failure())
	}
}

func TestLoggerThatCannotBeRun(t *testing.T) {
	r := &fake.Runner{}
	r.When(func(c execx.Cmd) bool { return c.Name == "logger" }, execx.Result{Code: 126}, errors.New("permission denied"))
	w := New(Options{Runner: r})
	w.Raw(Info, "x")
	if got := w.Failure(); !strings.HasPrefix(got, "cannot be run: ") {
		t.Errorf("Failure = %q", got)
	}
}

func TestAWriterWithNoWarnIsSilent(t *testing.T) {
	r := &fake.Runner{}
	r.Missing("logger")
	w := New(Options{Runner: r})
	w.Raw(Info, "x")
	if w.Failure() == "" {
		t.Error("the failure is not remembered")
	}
}

func TestActor(t *testing.T) {
	if got := ActorOf("alice", "1001"); got != (Actor{User: "alice", UID: "1001", Origin: OriginSudo}) {
		t.Errorf("ActorOf(alice) = %+v", got)
	}
	if got := ActorOf("", ""); got != (Actor{User: "root", UID: "0", Origin: OriginRoot}) {
		t.Errorf("ActorOf(none) = %+v", got)
	}
	r := &fake.Runner{}
	w := New(Options{Runner: r, Actor: ActorOf("alice", "1001")})
	f := w.Actor().Fields()
	var line bytes.Buffer
	for _, kv := range f {
		line.WriteString(kv.Key + "=" + Value(kv.Value) + " ")
	}
	if got := strings.TrimSpace(line.String()); got != "user=alice uid=1001 origin=sudo tty=- console=-" {
		t.Errorf("fields %q", got)
	}
	w.SetTerminal("pts/3", "0123456789ab")
	if a := w.Actor(); a.TTY != "pts/3" || a.Console != "0123456789ab" {
		t.Errorf("actor %+v", a)
	}
}

func TestNewSID(t *testing.T) {
	sid := NewSID(bytes.NewReader([]byte{0, 1, 25, 26, 35, 36, 255, 100}))
	if sid != "abz09ad2" {
		t.Fatalf("sid %q, want abz09ad2", sid)
	}
	for _, c := range sid {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			t.Errorf("sid %q: %q is outside [a-z0-9]", sid, c)
		}
	}
	// The same bytes, the same id (TACCTL_TEST_RANDOM makes lines stable).
	b := []byte{9, 8, 7, 6, 5, 4, 3, 2}
	first, second := NewSID(bytes.NewReader(b)), NewSID(bytes.NewReader(b))
	if first != second {
		t.Error("the id is not a function of the bytes")
	}
	// A source that fails still gives an id.
	if s := NewSID(bytes.NewReader(nil)); len(s) != 8 {
		t.Errorf("fallback sid %q", s)
	}
}

// Touch runs the registered start function once, however many callers reach
// it (and from several goroutines); without one it does nothing.
func TestTouchRunsTheStartOnce(t *testing.T) {
	w := New(Options{Runner: &fake.Runner{}, SID: "k3x9a0bq"})
	w.Touch() // no start registered
	if w.Touched() {
		t.Fatal("touched with no start function")
	}
	n := 0
	w.SetStart(func() string { n++; return w.Line(Info, "cmd start") })
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); w.Touch() }()
	}
	wg.Wait()
	w.Touch()
	if n != 1 || !w.Touched() {
		t.Errorf("start ran %d times, touched %v", n, w.Touched())
	}
	var nilWriter *Writer
	nilWriter.Touch() // a nil writer is a no-op
}

func TestSnapshotsAreRemembered(t *testing.T) {
	w := New(Options{Runner: &fake.Runner{}})
	w.NoteSnapshot("")
	w.NoteSnapshot("20261021_093015_412")
	w.NoteSnapshot("20261021_093016_001")
	if got := strings.Join(w.Snapshots(), " "); got != "20261021_093015_412 20261021_093016_001" {
		t.Errorf("snapshots %q", got)
	}
}

// Wide keeps 512 bytes of a value instead of 64, and quotes as Value does.
func TestWideKeepsMore(t *testing.T) {
	r := &fake.Runner{}
	w := New(Options{Runner: r})
	long := strings.Repeat("ab ", 100)
	w.Line(Info, "cmd start", Wide("args", long), Pair("x", long))
	line := r.Calls()[0].Args[4]
	if !strings.Contains(line, `args="`+strings.Repeat("ab ", 100)+`"`) {
		t.Errorf("wide value cut: %s", line)
	}
	if !strings.Contains(line, ` x="`+strings.Repeat("ab ", 21)+`a..."`) {
		t.Errorf("narrow value not cut at 64: %s", line)
	}
	huge := strings.Repeat("z", 600)
	r2 := &fake.Runner{}
	New(Options{Runner: r2}).Line(Info, "e", Wide("args", huge))
	if got := r2.Calls()[0].Args[4]; got != "e args="+strings.Repeat("z", 512)+"..." {
		t.Errorf("huge wide value: %s", got)
	}
}

// recovered runs fn and returns the *Refusal it panicked with, nil when it
// did not panic.
func recovered(t *testing.T, fn func()) (ref *Refusal) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			var ok bool
			if ref, ok = r.(*Refusal); !ok {
				panic(r)
			}
		}
	}()
	fn()
	return nil
}

// With SetStrict, a start line that logger did not write refuses the command:
// Touch panics with the refusal, again on every later call (so nothing
// deferred writes), and the D248 warning is not printed beside it.
func TestStrictTouchRefusesWhenTheStartLineIsNotWritten(t *testing.T) {
	r := &fake.Runner{}
	r.Fail([]string{"logger"}, 1, "logger: socket /dev/log: Connection refused")
	var warned []string
	w := New(Options{Runner: r, Warn: func(m string) { warned = append(warned, m) }})
	w.SetStrict(true)
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	ref := recovered(t, w.Touch)
	if ref == nil {
		t.Fatal("Touch did not refuse")
	}
	want := "The audit line cannot be written (logger: exit status 1: logger: socket /dev/log: Connection refused) and audit.strict is set; nothing was changed."
	if ref.Error() != want {
		t.Errorf("message\n got %s\nwant %s", ref.Error(), want)
	}
	if again := recovered(t, w.Touch); again == nil || again != ref {
		t.Errorf("a later Touch returned %v, want the same refusal", again)
	}
	w.Line(Info, "cmd end") // the end line of a refused command
	if len(warned) != 0 {
		t.Errorf("warnings beside a refusal: %q", warned)
	}
}

// A start line that is written does not refuse; the failure of a later line
// (the end line) is the D248 warning and nothing else.
func TestStrictTouchPassesWhenTheStartLineIsWritten(t *testing.T) {
	r := &fake.Runner{}
	var warned []string
	w := New(Options{Runner: r, Warn: func(m string) { warned = append(warned, m) }})
	w.SetStrict(true)
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	if ref := recovered(t, w.Touch); ref != nil {
		t.Fatalf("refused: %v", ref)
	}
	r.Fail([]string{"logger"}, 1, "gone")
	w.Line(Info, "cmd end")
	if len(warned) != 1 || !strings.Contains(warned[0], "The audit line was not written (logger: exit status 1: gone); the command continues.") {
		t.Errorf("warnings %q", warned)
	}
	if ref := recovered(t, w.Touch); ref != nil {
		t.Errorf("a later Touch refused after the end line failed: %v", ref)
	}
}

// Without SetStrict a failed start line is the D248 warning, as before.
func TestNotStrictTouchWarnsAndGoesOn(t *testing.T) {
	r := &fake.Runner{}
	r.Missing("logger")
	var warned []string
	w := New(Options{Runner: r, Warn: func(m string) { warned = append(warned, m) }})
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	if ref := recovered(t, w.Touch); ref != nil {
		t.Fatalf("refused without audit.strict: %v", ref)
	}
	if len(warned) != 1 {
		t.Errorf("warnings %q", warned)
	}
}

// Callers that wait while another goroutine writes the start line are refused
// with it.
func TestStrictTouchRefusesTheWaitingCallersToo(t *testing.T) {
	r := &fake.Runner{}
	r.Missing("logger")
	w := New(Options{Runner: r})
	w.SetStrict(true)
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	var wg sync.WaitGroup
	var mu sync.Mutex
	refused := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if recovered(t, w.Touch) != nil {
				mu.Lock()
				refused++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if refused != 8 {
		t.Errorf("%d of 8 callers refused", refused)
	}
}

// The refusal is decided on the start line's own write: a line another
// goroutine writes successfully after it does not hide that it failed.
func TestStrictTouchDecidesOnTheStartLineItself(t *testing.T) {
	r := &fake.Runner{}
	r.Func(func(c execx.Cmd) bool { return c.Name == "logger" }, func(c execx.Cmd) (execx.Result, error) {
		if strings.Contains(strings.Join(c.Args, " "), "cmd start") {
			return execx.Result{Code: 1, Stderr: []byte("busy")}, nil
		}
		return execx.Result{}, nil
	})
	w := New(Options{Runner: r})
	w.SetStrict(true)
	w.SetStart(func() string {
		reason := w.Line(Info, "cmd start")
		w.Line(Info, "from another goroutine") // succeeds, and clears Failure
		return reason
	})
	if ref := recovered(t, w.Touch); ref == nil || !strings.Contains(ref.Error(), "exit status 1: busy") {
		t.Errorf("refusal %v", ref)
	}
}

// Under audit.strict the warning of a line written before the start line
// waits for the outcome: dropped when the command is refused, shown once when
// the start line is written or when the command ends without one.
func TestStrictHoldsTheWarningOfAnEarlierLine(t *testing.T) {
	r := &fake.Runner{}
	r.Missing("logger")
	var warned []string
	w := New(Options{Runner: r, Warn: func(m string) { warned = append(warned, m) }})
	w.SetStrict(true)
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	w.Line(Info, "earlier") // fails, warning held
	if len(warned) != 0 {
		t.Fatalf("warned early: %q", warned)
	}
	if recovered(t, w.Touch) == nil {
		t.Fatal("not refused")
	}
	w.FlushWarning()
	if len(warned) != 0 {
		t.Errorf("warnings beside a refusal: %q", warned)
	}

	// A command that never touches (a read) gets its warning at the end.
	warned = nil
	w2 := New(Options{Runner: r, Warn: func(m string) { warned = append(warned, m) }})
	w2.SetStrict(true)
	w2.SetStart(func() string { return w2.Line(Info, "cmd start") })
	w2.Line(Info, "secret-read")
	w2.FlushWarning()
	w2.FlushWarning()
	if len(warned) != 1 || !strings.Contains(warned[0], "logger: not found") {
		t.Errorf("read: warnings %q", warned)
	}

	// A start line that is written releases the held warning.
	warned = nil
	r3 := &fake.Runner{}
	n := 0
	r3.Func(func(c execx.Cmd) bool { return c.Name == "logger" }, func(execx.Cmd) (execx.Result, error) {
		n++
		if n == 1 {
			return execx.Result{Code: 1, Stderr: []byte("busy")}, nil
		}
		return execx.Result{}, nil
	})
	w3 := New(Options{Runner: r3, Warn: func(m string) { warned = append(warned, m) }})
	w3.SetStrict(true)
	w3.SetStart(func() string { return w3.Line(Info, "cmd start") })
	w3.Line(Info, "earlier")
	if recovered(t, w3.Touch) != nil {
		t.Fatal("refused with a start line that was written")
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "exit status 1: busy") {
		t.Errorf("warnings %q", warned)
	}
}

// Concurrent failing lines while a strict start line is written: the start
// line written, one warning in all; the start line not written, a refusal and
// none. (Run with -race.)
func TestStrictWarningsUnderConcurrentWrites(t *testing.T) {
	for _, startFails := range []bool{false, true} {
		r := &fake.Runner{}
		r.Func(func(c execx.Cmd) bool { return c.Name == "logger" }, func(c execx.Cmd) (execx.Result, error) {
			if strings.Contains(strings.Join(c.Args, " "), "cmd start") && !startFails {
				return execx.Result{}, nil
			}
			return execx.Result{Code: 1, Stderr: []byte("busy")}, nil
		})
		var mu sync.Mutex
		var warned []string
		w := New(Options{Runner: r, Warn: func(m string) { mu.Lock(); warned = append(warned, m); mu.Unlock() }})
		w.SetStrict(true)
		w.SetStart(func() string { return w.Line(Info, "cmd start") })
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				w.Line(Info, "other")
				if i%4 == 0 {
					_ = recovered(t, w.Touch)
				}
			}()
		}
		wg.Wait()
		w.FlushWarning()
		want := 1
		if startFails {
			want = 0
		}
		if len(warned) != want {
			t.Errorf("start line failing %v: %d warnings %q, want %d", startFails, len(warned), warned, want)
		}
	}
}

// Reveal writes the line of a secret about to be shown. Without strict it is
// Line: a failure is the warning and nothing is refused.
func TestRevealWithoutStrictIsLine(t *testing.T) {
	r := &fake.Runner{}
	r.Missing("logger")
	var warned []string
	w := New(Options{Runner: r, SID: "k3x9a0bq", Warn: func(m string) { warned = append(warned, m) }})
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	if ref := recovered(t, func() { w.Reveal(Info, "secret-read", Pair("kind", "scope"), Pair("name", "lab")) }); ref != nil {
		t.Fatalf("refused without strict: %v", ref)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "the command continues") {
		t.Errorf("warnings %q", warned)
	}
	if got := r.Calls()[0].Args[4]; got != "secret-read kind=scope name=lab sid=k3x9a0bq" {
		t.Errorf("line %q", got)
	}
}

// With strict, a reveal whose line is written passes; one whose line is not
// written panics with the reveal's refusal (and every later Touch and Reveal
// repeats it), with no D248 warning beside it.
func TestStrictRevealRefusesWhenTheLineIsNotWritten(t *testing.T) {
	r := &fake.Runner{}
	w := New(Options{Runner: r, Warn: func(string) { t.Error("warned") }})
	w.SetStrict(true)
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	if ref := recovered(t, func() { w.Reveal(Info, "secret-read") }); ref != nil {
		t.Fatalf("refused with a working logger: %v", ref)
	}
	r2 := &fake.Runner{}
	r2.Fail([]string{"logger"}, 1, "busy")
	var warned []string
	w = New(Options{Runner: r2, Warn: func(m string) { warned = append(warned, m) }})
	w.SetStrict(true)
	w.SetStart(func() string { return w.Line(Info, "cmd start") })
	ref := recovered(t, func() { w.Reveal(Info, "secret-read") })
	if ref == nil || !ref.Reveal {
		t.Fatalf("refusal %+v", ref)
	}
	if want := "The audit line cannot be written (logger: exit status 1: busy) and audit.strict is set; nothing was shown."; ref.Error() != want {
		t.Errorf("message %q", ref.Error())
	}
	if again := recovered(t, w.Touch); again != ref {
		t.Errorf("a later Touch: %v", again)
	}
	if again := recovered(t, func() { w.Reveal(Info, "secret-read") }); again != ref {
		t.Errorf("a later Reveal: %v", again)
	}
	w.FlushWarning()
	if len(warned) != 0 {
		t.Errorf("warnings beside the refusal: %q", warned)
	}
}
