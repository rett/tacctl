package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
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
	// A comma is outside the plain alphabet of D245, so a list is quoted.
	want := `user add name=alice scopes="core,lab" reason="new hire" tty=- sid=k3x9a0bq`
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
