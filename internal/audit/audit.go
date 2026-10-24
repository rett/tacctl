// Package audit writes tacctl's audit lines to syslog through logger(1)
// (an external command on purpose, docs/plans/go-rewrite.md 3.6).
//
// One Writer is made per process (app.App.Audit). It runs logger on a
// context that no signal cancels, so a line is not lost because SIGINT,
// SIGTERM or SIGHUP is ending the command (exec.CommandContext will not
// start a program on a cancelled context); it appends the process's session
// id (sid=) to every line; and it tells the operator, once, when logger
// could not write (docs/plans/0.2.17-plan.md D244-D248).
//
// The package imports execx and the standard library only, so that every
// package that writes a line can be handed the writer without a cycle.
package audit

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/execx"
)

// Tag is the syslog tag of the lines of a tacctl command. The console's own
// lines carry its tag (console.LogTag) through Writer.WithTag.
const Tag = "tacctl"

// Syslog priorities of the facility auth: Info for an action, Notice for
// the weighty ones, Warning for a denial, a failure or a mismatch.
const (
	Info    = "auth.info"
	Notice  = "auth.notice"
	Warning = "auth.warning"
)

// writeTimeout bounds one logger run. The writer's context is not cancelled
// by a signal, so a logger that hangs (a syslog socket that does not answer)
// would otherwise hold the command until SIGKILL.
const writeTimeout = 10 * time.Second

// maxValue is how many bytes of a value a line keeps (Value).
const maxValue = 64

// MaxWide is how many bytes of a value Wide keeps.
const MaxWide = 512

// KV is one key=value field of a line. Build it with Pair or Wide.
type KV struct {
	Key, Value string
	// Max is how many bytes of the value the line keeps (0: maxValue).
	Max int
}

// Pair is the field key=value.
func Pair(key, value string) KV { return KV{Key: key, Value: value} }

// Wide is the field key=value for a value that is itself a list of words
// the caller has capped (the command line of a central line): quoted as
// Value quotes, kept up to MaxWide bytes instead of 64.
func Wide(key, value string) KV { return KV{Key: key, Value: value, Max: MaxWide} }

// Value is v as one field value of a line: written as it is when it is
// non-empty and holds only [A-Za-z0-9._:/@+,-], else Go-quoted
// (strconv.Quote: spaces, quotes, control characters and bytes that are not
// UTF-8 are escaped, so a line is always one line and a collector can split
// on spaces outside quotes); '-' when empty. A value longer than 64 bytes
// is cut there (on a character boundary) and ends in '...'.
func Value(v string) string { return valueMax(v, maxValue) }

// valueMax is Value with a cut at max bytes.
func valueMax(v string, max int) string {
	if v == "" {
		return "-"
	}
	if len(v) > max {
		n := max
		for n > 0 && !utf8.RuneStart(v[n]) {
			n--
		}
		v = v[:n] + "..."
	}
	if plain(v) {
		return v
	}
	return strconv.Quote(v)
}

// plain reports whether v needs no quoting.
func plain(v string) bool {
	for i := 0; i < len(v); i++ {
		switch c := v[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("._:/@+,-", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// Origins of a command (Actor.Origin).
const (
	// OriginSudo: the account named by SUDO_USER, which the gate has checked
	// against SUDO_UID, ran tacctl through sudo.
	OriginSudo = "sudo"
	// OriginRoot: no SUDO_USER, a root shell or a script run as root. The
	// log holds no login identity for it, as sudo's does not either.
	OriginRoot = "root"
)

// Actor is who ran the command (D246).
type Actor struct {
	User, UID, Origin string
	// TTY is the terminal the command runs on ("pts/3"), Console the
	// console session it runs in; "" for none (written as '-').
	TTY, Console string
}

// ActorOf is the actor of a process whose environment has SUDO_USER and
// SUDO_UID as given: that user with origin sudo, and with no SUDO_USER root
// (uid 0) with origin root.
func ActorOf(sudoUser, sudoUID string) Actor {
	if sudoUser == "" {
		return Actor{User: "root", UID: "0", Origin: OriginRoot}
	}
	return Actor{User: sudoUser, UID: sudoUID, Origin: OriginSudo}
}

// Fields are the actor's fields of a central line, in their order.
func (a Actor) Fields() []KV {
	return []KV{Pair("user", a.User), Pair("uid", a.UID), Pair("origin", a.Origin), Pair("tty", a.TTY), Pair("console", a.Console)}
}

// NewSID is a session id: 8 characters of [a-z0-9] made from r. The bytes
// map to the 36 characters by remainder, so the id is for grep, not a key
// (D247). When r fails the id comes from the clock.
func NewSID(r io.Reader) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	if _, err := io.ReadFull(r, b); err != nil {
		s := strconv.FormatInt(time.Now().UnixNano(), 36)
		for len(s) < 8 {
			s = "0" + s
		}
		return s[len(s)-8:]
	}
	for i, c := range b {
		b[i] = alphabet[int(c)%len(alphabet)]
	}
	return string(b)
}

// Options are what New makes a Writer from.
type Options struct {
	// Runner runs logger.
	Runner execx.Runner
	// Ctx is the process context; the writer uses context.WithoutCancel of
	// it. nil is context.Background.
	Ctx context.Context
	// SID is appended to every line as sid=<SID> ("": no sid).
	SID string
	// Actor is who runs the command.
	Actor Actor
	// Warn prints a line of the [WARN] kind on the operator's standard
	// error. nil prints nothing.
	Warn func(msg string)
}

// state is what a Writer and the writers made from it with WithTag share.
type state struct {
	run   execx.Runner
	ctx   context.Context
	sid   string
	warn  func(string)
	once  sync.Once
	mu    sync.Mutex
	actor Actor
	// failure is why the last line was not written, "" when it was.
	failure string

	// start writes the central 'cmd start' line (SetStart); Touch runs it
	// once, before the first write of the command.
	start     func() string
	command   string
	touch     sync.Once
	touched   bool
	snapshots []string
	// strict: a start line that could not be written refuses the command
	// (SetStrict). refused is the refusal once it has happened; every later
	// Touch repeats it, so nothing deferred on the way out writes.
	strict  bool
	refused *Refusal
	// startDone: the start line was written (or strict is off): from then on a
	// failed line is warned about at once. Before it, under strict, the D248
	// warning of a failed line waits in pending for the outcome: dropped if
	// the command is refused (the refusal says it), shown by FlushWarning
	// otherwise.
	startDone bool
	pending   string
}

// Refusal is a command refused because its start line could not be written
// and audit.strict is set (D257). Touch panics with it before anything is
// written; the dispatcher recovers it as the command's error.
type Refusal struct {
	// Reason is why logger did not write (Failure).
	Reason string
}

// Error is the message the operator reads.
func (r *Refusal) Error() string {
	return "The audit line cannot be written (logger: " + r.Reason + ") and audit.strict is set; nothing was changed."
}

// Writer writes audit lines. It is safe for concurrent use (the device
// pulls log from their pool).
type Writer struct {
	*state
	tag string
}

// New is a Writer for o.
func New(o Options) *Writer {
	ctx := o.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	return &Writer{
		state: &state{run: o.Runner, ctx: context.WithoutCancel(ctx), sid: o.SID, warn: o.Warn, actor: o.Actor},
		tag:   Tag,
	}
}

// WithTag is a writer for the same process (same sid, actor, warning and
// failure state) whose lines carry another syslog tag.
func (w *Writer) WithTag(tag string) *Writer { return &Writer{state: w.state, tag: tag} }

// SID is the process's session id ("" if it has none).
func (w *Writer) SID() string { return w.sid }

// Actor is who runs the command.
func (w *Writer) Actor() Actor {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.actor
}

// SetTerminal says on which terminal and in which console session the
// command runs, for the actor's tty and console fields.
func (w *Writer) SetTerminal(tty, console string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.actor.TTY, w.actor.Console = tty, console
}

// SetCommand says which command runs: the words of the start line's cmd=,
// without arguments. The snapshot manifest records it (D256).
func (w *Writer) SetCommand(words string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.command = words
}

// Command is the command's words ("" before SetCommand).
func (w *Writer) Command() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.command
}

// SetStart registers the function that writes the command's central start
// line. Touch runs it, once, the first time anything is about to be written;
// without one (the console process) Touch does nothing. fn returns why that
// line was not written ("" when it was: what Line returns), so that audit.strict
// decides on the start line itself and not on whichever line another
// goroutine wrote last.
func (w *Writer) SetStart(fn func() string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.start = fn
}

// SetStrict says that a start line that could not be written refuses the
// command (audit.strict, D257): Touch then panics with a *Refusal.
func (w *Writer) SetStrict(on bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.strict = on
}

// Touch says that the command is about to change something: the start line
// is written now, before anything is, if it has not been written yet. It is
// idempotent and safe for concurrent use; a caller that arrives while the
// line is being written waits for it.
//
// With SetStrict, a start line that logger did not write makes Touch panic
// with a *Refusal, here and in every later call, so the write that follows
// never happens; the caller of the command recovers it (cli.auditFinish). The
// panic must reach the goroutine that runs the command: a verb that can first
// reach a write choke point on a worker goroutine touches before it starts
// the workers.
func (w *Writer) Touch() {
	if w == nil {
		return
	}
	w.mu.Lock()
	fn := w.start
	r := w.refused
	w.mu.Unlock()
	if r != nil {
		panic(r)
	}
	if fn == nil {
		return
	}
	w.touch.Do(func() {
		w.mu.Lock()
		w.touched = true
		w.mu.Unlock()
		reason := fn()
		w.mu.Lock()
		if w.strict && reason != "" {
			w.refused = &Refusal{Reason: reason}
			w.pending = ""
		} else {
			w.startDone = true
		}
		r := w.refused
		w.mu.Unlock()
		if r != nil {
			panic(r)
		}
		w.FlushWarning()
	})
	// A caller that waited for the line while another wrote it.
	w.mu.Lock()
	r = w.refused
	w.mu.Unlock()
	if r != nil {
		panic(r)
	}
}

// Touched reports whether the start line was written (Touch ran).
func (w *Writer) Touched() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.touched
}

// NoteSnapshot records the id of a snapshot the command took, for the end
// line (Snapshots).
func (w *Writer) NoteSnapshot(id string) {
	if id == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.snapshots = append(w.snapshots, id)
}

// Snapshots are the ids of the snapshots the command took, in order.
func (w *Writer) Snapshots() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.snapshots...)
}

// Failure is why the last line could not be written, "" when it was (or
// none was tried).
func (w *Writer) Failure() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.failure
}

// Line writes '<event> <key>=<value>...' with the fields in the order given
// (each value as Value writes it) and the process's sid last. It returns why
// the line was not written, "" when it was (Failure says the same of the
// last line of the process; this is of this one).
func (w *Writer) Line(priority, event string, kv ...KV) string {
	var b strings.Builder
	b.WriteString(event)
	for _, f := range kv {
		b.WriteByte(' ')
		b.WriteString(f.Key)
		b.WriteByte('=')
		max := f.Max
		if max <= 0 {
			max = maxValue
		}
		b.WriteString(valueMax(f.Value, max))
	}
	return w.Raw(priority, b.String())
}

// Raw writes msg as it is, with the sid appended. It is for the lines that
// were written before Line existed and keep their words; a trailing space
// is dropped before the sid so the key follows a single space. It returns what
// Line returns.
func (w *Writer) Raw(priority, msg string) string {
	if w.sid != "" {
		msg = strings.TrimRight(msg, " ") + " sid=" + w.sid
	}
	return w.write(priority, msg)
}

// write runs logger. A failure is not the command's: it is remembered
// (Failure) and the operator is told once per process (D248). It returns the
// reason this line was not written, "" when it was.
func (w *Writer) write(priority, msg string) string {
	ctx, cancel := context.WithTimeout(w.ctx, writeTimeout)
	defer cancel()
	res, err := w.run.Run(ctx, execx.Cmd{Name: "logger", Args: []string{"-t", w.tag, "-p", priority, msg}})
	reason := failureReason(res, err)
	w.mu.Lock()
	w.failure = reason
	if reason == "" || w.warn == nil {
		w.mu.Unlock()
		return reason
	}
	warning := fmt.Sprintf("The audit line was not written (logger: %s); the command continues.", reason)
	// Decided in one critical section with FlushWarning's and Touch's: under
	// audit.strict the outcome of the start line is not known yet (hold), is a
	// refusal that says it all (drop), or is known (warn).
	hold, drop := false, false
	if w.strict && w.start != nil {
		drop = w.refused != nil
		hold = !drop && !w.startDone
		if hold && w.pending == "" {
			w.pending = warning
		}
	}
	w.mu.Unlock()
	if !hold && !drop {
		w.once.Do(func() { w.warn(warning) })
	}
	return reason
}

// FlushWarning prints the D248 warning that audit.strict held back, when the
// command was not refused. The dispatcher calls it as the last thing the
// command does (after its DENY and end lines), and Touch calls it when the
// start line was written.
func (w *Writer) FlushWarning() {
	if w == nil {
		return
	}
	w.mu.Lock()
	msg, refused := w.pending, w.refused != nil
	w.pending = ""
	w.mu.Unlock()
	if msg == "" || refused || w.warn == nil {
		return
	}
	w.once.Do(func() { w.warn(msg) })
}

// failureReason says why logger did not write: "" when it did.
func failureReason(res execx.Result, err error) string {
	switch {
	case err != nil && res.Code == 127:
		return "not found"
	case err != nil:
		return "cannot be run: " + err.Error()
	case res.Code == 0:
		return ""
	}
	reason := "exit status " + strconv.Itoa(res.Code)
	if first, _, _ := strings.Cut(strings.TrimSpace(string(res.Stderr)), "\n"); first != "" {
		if len(first) > 80 {
			first = first[:80] + "..."
		}
		reason += ": " + first
	}
	return reason
}
