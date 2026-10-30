package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/app"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/testpty"
)

// 'device config apply' end to end, in-process, against the configure model
// of the fake Junos device (tests/fixtures/devconf/fake/junos-apply): the
// two phases, the records, the interrupts and the hold. The transaction is
// pinned by internal/devapply; these pin the verb around it.

// applyBox is a pull box that serves a copy of the junos-apply fixture.
type applyBox struct {
	*pullBox
	runner *fake.Runner
	// script, when set, adjusts the fake runner of a run (after route).
	script func(*fake.Runner)
	// ctx, when set, is the invocation's context (its cancellation is the
	// first Ctrl-C of a real run).
	ctx context.Context
}

func newApplyBox(t *testing.T) *applyBox {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join("..", "..", "tests", "fixtures", "devconf", "fake", "junos-apply")
	ents, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// the CLI echoes a command as typed, with no trailing blank
	b := &applyBox{pullBox: newPullBoxIn(t, dir)}
	b.knob("echo.plain", "")
	return b
}

// knob writes one of the fake device's knob files.
func (b *applyBox) knob(name, text string) {
	b.t.Helper()
	if err := os.WriteFile(filepath.Join(b.dir, name), []byte(text), 0o644); err != nil {
		b.t.Fatal(err)
	}
}

// register writes the registry: each name at its own address, all of them
// the one fake device, which calls itself example-sw1 (the hostname field
// makes that a name each may report).
func (b *applyBox) register(names ...string) {
	b.t.Helper()
	var sb strings.Builder
	sb.WriteString("version: 1\nsettings:\n  stale_days: 30\ndevices:\n")
	for i, n := range names {
		sb.WriteString("  " + n + ":\n    address: 192.168.1." + strconv.Itoa(20+i) + "\n    vendor: juniper\n    hostname: example-sw1\n")
		sb.WriteString("    host_keys:\n    - " + b.srv.HostKey() + "\n")
	}
	b.sb.write("state/devices.yaml", sb.String(), 0o600)
}

// committed is the configuration the fake device runs.
func (b *applyBox) committed() string { return b.srv.Committed() }

// start runs 'device config apply args' as alice in the background: stdin
// is in (a pty's slave for a terminal; nil: no input), stdout and stderr the
// buffers.
func (b *applyBox) start(in io.Reader, out, errb *lockedBuf, args ...string) chan int {
	b.t.Helper()
	return b.startCmd(in, out, errb, append([]string{"device", "config", "apply"}, args...)...)
}

// startCmd runs 'tacctl args' as alice in the background, as start does.
func (b *applyBox) startCmd(in io.Reader, out, errb *lockedBuf, args ...string) chan int {
	b.t.Helper()
	r := &fake.Runner{}
	r.On([]string{"systemctl"}, execx.Result{})
	r.On([]string{"logger"}, execx.Result{})
	r.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(r)
	route(r)
	if b.script != nil {
		b.script(r)
	}
	b.runner = r
	if in == nil {
		in = strings.NewReader("")
	}
	a := app.New(args, paths.NewEnv(append(append([]string(nil), b.sb.env...), "SUDO_USER=alice")),
		"/opt/x/dist/tacctl", 1000, app.Stdio{Stdin: in, Stdout: out, Stderr: errb}, r)
	a.SNMP = b.sb.snmp
	a.Resolve = b.sb.resolve
	a.Paths.ConsoleCommand = b.sb.consoleCommand()
	t := b.t
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("stdout:\n%s\nstderr:\n%s", out.String(), errb.String())
		}
	})
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	code := make(chan int, 1)
	go func() {
		code <- exitCode(runWith(ctx, a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}, b.sb.hooks), a.Out)
	}()
	return code
}

// apply runs it to the end with no terminal: the status, stdout, stderr.
func (b *applyBox) apply(args ...string) (int, string, string) {
	b.t.Helper()
	out, errb := &lockedBuf{}, &lockedBuf{}
	return b.wait(b.start(nil, out, errb, args...), out, errb)
}

// wait waits for the end of a run.
func (b *applyBox) wait(code chan int, out, errb *lockedBuf) (int, string, string) {
	b.t.Helper()
	select {
	case c := <-code:
		return c, plain(out.String()), plain(errb.String())
	case <-time.After(240 * time.Second):
		b.t.Fatalf("the apply did not end\n%s\n%s", out.String(), errb.String())
	}
	return 0, "", ""
}

// applied is the apply part of a device's record (nil: none).
func (b *applyBox) applied(name string) *devconf.Applied {
	b.t.Helper()
	if r, ok := b.records().Of(name); ok {
		return r.Applied
	}
	return nil
}

// seed checks the device and files its shape as confirmed, so that
// '--confirmed --yes' applies it with no terminal.
func (b *applyBox) seed(name string) {
	b.t.Helper()
	if code, out, errs := b.apply(name, "--check"); code != 0 {
		b.t.Fatalf("check: %d\n%s\n%s", code, out, errs)
	}
	b.sb.cfgRun("", []string{"device", "config", "shapes", "seed", name, "--yes"}, nil, "SUDO_USER=alice")
	if b.sb.code != 0 {
		b.t.Fatalf("seed: %d %s", b.sb.code, b.sb.err.String())
	}
}

// interrupts makes the runner's Ctrl-Cs come from the returned channel.
func (b *pullBox) interrupts() chan struct{} {
	ch := make(chan struct{}) // unbuffered: a send returns when the runner took it
	b.sb.hooks.interruptSource = func() <-chan struct{} { return ch }
	return ch
}

// terminal is a pty whose slave is the run's stdin.
func terminal(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, s, err := testpty.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = s.Close() })
	// the master's echo is read and dropped, so the pty never fills
	go func() { _, _ = io.Copy(io.Discard, m) }()
	return m, s
}

// --- the exit status of a run that applied nothing ---------------------------------

// '--confirmed --yes' that skips every device did not do what it was
// asked: exit 1, with the line that says so (and the JSON's stop).
func TestApplyConfirmedAllSkippedExits1(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 1 || !strings.Contains(out, "example-sw1  skipped: unknown shape ") || !strings.Contains(out, "1 skipped") ||
		!strings.Contains(out, "Nothing was applied: every device was skipped.") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = b.apply("example-sw1", "--confirmed", "--yes", "--json")
	if code != 1 || !strings.Contains(out, `"stop":"nothing-applied"`) || !strings.Contains(out, `"exit":1`) {
		t.Errorf("json: exit %d\n%s", code, out)
	}
	if b.committed() != before {
		t.Error("a skipped device was changed")
	}
}

// --- the record at the commit, and its failure -------------------------------------

// The pending record is on disk while the change is being verified (a
// tacctl killed then leaves what the next run reconciles), and the two
// Ctrl-Cs of Phase B: the first lets the running device go on and starts
// no other, the second cancels it, the change is rolled back and the run
// ends 130.
func TestApplyPhaseBInterruptsAndPendingRecord(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1", "example-sw2")
	b.seed("example-sw1")
	before := b.committed()
	b.knob("verify.fail", "hang\n")
	ch := b.interrupts()
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(nil, out, errb, "example-sw1,example-sw2", "--confirmed", "--yes", "--pause", "0", "--concurrency", "1")
	waitLong(t, "the commit's pending record", func() bool {
		a := b.applied("example-sw1")
		return a != nil && a.Result == devconf.AppliedPending
	})
	a := b.applied("example-sw1")
	if a.Kind != devconf.AppliedKindApply || !strings.HasPrefix(a.ID, "tacctl-") || a.Until.IsZero() || a.Shape == "" || a.Reason != "committed, verifying" {
		t.Errorf("pending record %+v", a)
	}
	ch <- struct{}{} // the first Ctrl-C
	waitLong(t, "the second device to be reported not started", func() bool { return strings.Contains(plain(out.String()), "example-sw2  not started") })
	never(t, "the first Ctrl-C ended the running device", 300*time.Millisecond, func() bool {
		return len(code) > 0 || strings.Contains(plain(out.String()), "example-sw1  rolled back") || strings.Contains(plain(out.String()), "example-sw1  interrupted")
	})
	ch <- struct{}{} // the second
	status, o, e := b.wait(code, out, errb)
	if status != 130 || !strings.Contains(o, "example-sw1  rolled back: interrupted") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
	if got := b.applied("example-sw1"); got == nil || got.Result != devconf.AppliedRolledBack {
		t.Errorf("record %+v", got)
	}
	if b.committed() != before {
		t.Errorf("the change stayed:\n%s", b.committed())
	}
	if a := b.applied("example-sw2"); a != nil && a.Kind == devconf.AppliedKindApply {
		t.Errorf("a device not started has an apply record: %+v", a)
	}
}

// A pending record that cannot be written is said at once, in red, on
// standard error, and does not stop the transaction: the device is
// verified and confirmed, and the final record is written.
func TestApplyPendingRecordWriteFailure(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.seed("example-sw1")
	var refused atomic.Int32
	b.sb.hooks.applyRecordFault = func(_ string, a devconf.Applied) error {
		if a.Result == devconf.AppliedPending {
			refused.Add(1)
			return errors.New("disk full")
		}
		return nil
	}
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 0 || !strings.Contains(out, "example-sw1  applied ") || !strings.Contains(out, "(the pending record at the commit was not kept: disk full)") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if refused.Load() != 1 || !strings.Contains(errs, "RECORD example-sw1: the confirmed commit tacctl-") ||
		!strings.Contains(errs, "could not be written (disk full): the device may be PENDING until ") {
		t.Errorf("stderr (%d refused):\n%s", refused.Load(), errs)
	}
	if a := b.applied("example-sw1"); a == nil || a.Result != devconf.AppliedApplied {
		t.Errorf("record %+v", a)
	}
}

// --- Phase A's interrupts -------------------------------------------------------------

// The two Ctrl-Cs of Phase A: the first lets the running check go on and
// starts no other device, the second cuts it off; no review is shown,
// nothing is committed, the run ends 130.
func TestApplyPhaseAInterrupts(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1", "example-sw2")
	before := b.committed()
	b.knob(junosReadCmd+".hang", "")
	ch := b.interrupts()
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(nil, out, errb, "example-sw1,example-sw2", "--confirmed", "--yes", "--concurrency", "1")
	waitLong(t, "the device to have the read command", func() bool { return b.served(junosReadCmd) == 1 })
	ch <- struct{}{}
	waitLong(t, "the second device to be reported not started", func() bool { return strings.Contains(plain(out.String()), "example-sw2  not started") })
	never(t, "the first Ctrl-C ended the running check", 300*time.Millisecond, func() bool {
		return len(code) > 0 || strings.Contains(plain(out.String()), "example-sw1  interrupted")
	})
	ch <- struct{}{}
	status, o, e := b.wait(code, out, errb)
	if status != 130 || !strings.Contains(o, "example-sw1  ") || strings.Contains(o, "Shape ") || strings.Contains(o+e, "--yes: every shape") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
	if b.committed() != before || b.srv.Logins() != 1 {
		t.Errorf("committed changed or a second login (%d)", b.srv.Logins())
	}
}

// --- what changed between the phases --------------------------------------------------

// A break-glass hold placed while the review waits, and an address changed
// in the registry, are found at the start of the device's Phase B job:
// nothing is sent, the device fails with the reason.
func TestApplyRechecksBetweenThePhases(t *testing.T) {
	for _, c := range []struct {
		name, want string
		change     func(b *applyBox)
	}{
		{"hold", "failed: break-glass was placed on hold for example-sw1 since the review; nothing was sent", func(b *applyBox) {
			b.sb.write("state/tacctl.yaml", "breakglass_hold:\n  example-sw1:\n    address: 192.168.1.20\n    since: '2026-10-13T14:00:00Z'\n    by: alice\n    reason: console\n", 0o600)
		}},
		{"address", "failed: its registered address changed (192.168.1.20 to 192.168.1.40) since the review; nothing was sent", func(b *applyBox) {
			p := b.sb.path("state", "devices.yaml")
			d, _ := os.ReadFile(p)
			b.sb.write("state/devices.yaml", strings.Replace(string(d), "192.168.1.20", "192.168.1.40", 1), 0o600)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newApplyBox(t)
			b.register("example-sw1")
			before := b.committed()
			master, slave := terminal(t)
			out, errb := &lockedBuf{}, &lockedBuf{}
			code := b.start(slave, out, errb, "example-sw1")
			waitLong(t, "the review's question", func() bool { return strings.Contains(errb.String(), "Type the device name to apply to example-sw1:") })
			logins := b.srv.Logins()
			c.change(b)
			_, _ = master.WriteString("example-sw1\n")
			status, o, e := b.wait(code, out, errb)
			if status != 1 || !strings.Contains(o, "example-sw1  "+c.want) {
				t.Errorf("exit %d\n%s\n%s", status, o, e)
			}
			if b.committed() != before || b.srv.Logins() != logins {
				t.Errorf("the device was reached after the change (%d logins, %d before)", b.srv.Logins(), logins)
			}
		})
	}
}

// --- --hold ---------------------------------------------------------------------------

// --hold reads the answers with one reader the run owns: the first device's
// question times out, and the OK typed for the second device is the second
// device's answer (a reader left behind by the first question would take
// it). Run it with -race.
func TestApplyHoldOneReaderAcrossDevices(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1", "example-sw2")
	var calls atomic.Int32
	b.sb.hooks.applyHoldWait = func(until, now time.Time) time.Duration {
		if calls.Add(1) == 1 {
			return 300 * time.Millisecond
		}
		return 30 * time.Second
	}
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1,example-sw2", "--hold", "--no-canary", "--max-failures", "2", "--pause", "0", "--concurrency", "1")
	askedFor(t, errb, "example-sw1")
	_, _ = master.WriteString("example-sw1\n")
	askedFor(t, errb, "example-sw2")
	_, _ = master.WriteString("example-sw2\n")
	waitLong(t, "the first device to be rolled back", func() bool { return strings.Contains(plain(out.String()), "example-sw1  rolled back") })
	waitLong(t, "the second device's question", func() bool {
		return strings.Count(errb.String(), "Type OK to keep the change") == 2
	})
	_, _ = master.WriteString("OK\n")
	status, o, e := b.wait(code, out, errb)
	if status != 1 || !strings.Contains(o, "example-sw1  rolled back: verification failed") || !strings.Contains(o, "example-sw2  applied ") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
}

// An answer typed before the first question is the first device's answer: it
// sits in the terminal with the review's, and is read with it (D224). The
// word is OK, so the change is kept.
func TestApplyHoldAnswerTypedAheadIsTaken(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.sb.hooks.applyHoldWait = func(until, now time.Time) time.Duration { return 30 * time.Second }
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1", "--hold", "--no-canary", "--pause", "0", "--concurrency", "1")
	askedFor(t, errb, "example-sw1")
	_, _ = master.WriteString("example-sw1\nOK\n")
	status, o, e := b.wait(code, out, errb)
	if status != 0 || !strings.Contains(o, "example-sw1  applied ") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
}

// An answer that comes after the first device's window is not the second
// device's: it is dropped, and the second question waits for its own.
func TestApplyHoldLateAnswerIsDropped(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1", "example-sw2")
	b.sb.hooks.applyHoldWait = func(until, now time.Time) time.Duration { return 300 * time.Millisecond }
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1,example-sw2", "--hold", "--no-canary", "--max-failures", "2", "--pause", "0", "--concurrency", "1")
	askedFor(t, errb, "example-sw1")
	_, _ = master.WriteString("example-sw1\n")
	askedFor(t, errb, "example-sw2")
	_, _ = master.WriteString("example-sw2\n")
	waitLong(t, "the first device to be rolled back", func() bool { return strings.Contains(plain(out.String()), "example-sw1  rolled back") })
	_, _ = master.WriteString("OK\n")
	status, o, e := b.wait(code, out, errb)
	if status != 1 || !strings.Contains(o, "example-sw2  rolled back: verification failed (the hold: the window ran short)") || strings.Contains(o, "example-sw2  applied ") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
}

// --- the per-device review (0.2.17 D265, D266) ----------------------------------------

// askedFor waits for the review's question of one device.
func askedFor(t *testing.T, errb *lockedBuf, name string) {
	t.Helper()
	waitLong(t, "the review's question of "+name, func() bool {
		return strings.Contains(errb.String(), "Type the device name to apply to "+name+": ")
	})
}

// applyLineOf is the device's apply line of Phase B, "" if none.
func applyLineOf(b *applyBox, name string) string {
	for _, l := range auditLines(b.runner) {
		if strings.HasPrefix(l, "device config apply user=alice device="+name+" ") && strings.Contains(l, " commit=") {
			return l
		}
	}
	return ""
}

// One device of two declined: the other is applied, the declined one is a
// skipped row and is never written to, and the run exits 1. Each answer is a
// review line, the approval and the apply lines say mode=attended, and no
// line holds a password. With --json the answers are review objects and the
// summary's stop is not-approved.
func TestApplyReviewOneDeclinedOfTwo(t *testing.T) {
	for _, asJSON := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "json"}[asJSON], func(t *testing.T) {
			b := newApplyBox(t)
			b.register("example-sw1", "example-sw2")
			master, slave := terminal(t)
			out, errb := &lockedBuf{}, &lockedBuf{}
			args := []string{"example-sw1,example-sw2", "--concurrency", "1", "--pause", "0"}
			if asJSON {
				args = append(args, "--json")
			}
			code := b.start(slave, out, errb, args...)
			askedFor(t, errb, "example-sw1")
			_, _ = master.WriteString("example-sw1\n")
			askedFor(t, errb, "example-sw2")
			_, _ = master.WriteString("2\n")
			status, o, e := b.wait(code, out, errb)
			if status != 1 {
				t.Errorf("exit %d\n%s\n%s", status, o, e)
			}
			if asJSON {
				if !strings.Contains(o, `"name":"example-sw1","scope":"lab","vendor":"juniper","phase":"review","status":"approved"`) ||
					!strings.Contains(o, `"name":"example-sw2","scope":"lab","vendor":"juniper","phase":"review","status":"declined","reason":"not approved (the answer typed is not its name)"`) ||
					strings.Count(o, `"mode":"attended"`) != 2 || !strings.Contains(o, `"stop":"not-approved"`) || !strings.Contains(o, `"exit":1`) ||
					!strings.Contains(o, `"phase":"apply","status":"applied"`) {
					t.Errorf("json:\n%s\n%s", o, e)
				}
			} else if !strings.Contains(o, "  example-sw1  shape ") || !strings.Contains(o, "example-sw1  applied ") ||
				!strings.Contains(o, "example-sw2  skipped: not approved (the answer typed is not its name)") || !strings.Contains(o, "1 applied, 1 skipped") {
				t.Errorf("text:\n%s\n%s", o, e)
			}
			for _, want := range []string{
				"device config apply review user=alice device=example-sw1 shape=",
				"device config apply review user=alice device=example-sw2 shape=",
				"device config apply user=alice approved=1 shapes=",
			} {
				if l := auditLine(b.runner, want); l == "" || !strings.HasSuffix(l, " mode=attended") {
					t.Errorf("no %q ... mode=attended in %q", want, auditLines(b.runner))
				}
			}
			if !strings.Contains(auditLine(b.runner, "device config apply review user=alice device=example-sw2 "), " answer=declined ") ||
				!strings.Contains(auditLine(b.runner, "device config apply user=alice approved=1 "), " canary=example-sw1 ") {
				t.Errorf("lines %q", auditLines(b.runner))
			}
			if l := applyLineOf(b, "example-sw1"); !strings.Contains(l, " result=applied ") || !strings.HasSuffix(l, " mode=attended") {
				t.Errorf("apply line %q", l)
			}
			if l := applyLineOf(b, "example-sw2"); l != "" {
				t.Errorf("the declined device was applied: %q", l)
			}
			if a := b.applied("example-sw2"); a == nil || a.Kind != devconf.AppliedKindCheck {
				t.Errorf("the declined device's record: %+v", a)
			}
			noLoggerHas(t, "the review", b.runner, testPassword)
		})
	}
}

// The end of input at the first question declines every device: nothing is
// applied, no approval line, exit 1.
func TestApplyReviewEndOfInput(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1")
	askedFor(t, errb, "example-sw1")
	_, _ = master.WriteString("\x04") // Ctrl-D: the end of input
	status, o, e := b.wait(code, out, errb)
	if status != 1 || !strings.Contains(o, "example-sw1  skipped: not approved (no answer: the input ended)") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
	if b.committed() != before || auditLine(b.runner, "device config apply user=alice approved=") != "" ||
		!strings.Contains(auditLine(b.runner, "device config apply review user=alice device=example-sw1 "), " answer=declined mode=attended") {
		t.Errorf("committed changed or lines %q", auditLines(b.runner))
	}
}

// A Ctrl-C at a question ends the run with nothing applied, exit 130.
func TestApplyReviewCtrlC(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.ctx = ctx
	_, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1")
	askedFor(t, errb, "example-sw1")
	logins := b.srv.Logins()
	cancel()
	status, o, e := b.wait(code, out, errb)
	if status != 130 || !strings.Contains(o, "example-sw1  ") {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
	if b.committed() != before || b.srv.Logins() != logins || auditLine(b.runner, "device config apply user=alice approved=") != "" ||
		auditLine(b.runner, "device config apply review user=alice result=interrupted applied=0 mode=attended") == "" {
		t.Errorf("applied after a Ctrl-C: %q", auditLines(b.runner))
	}
}

// A Ctrl-C that comes after the last answer and before Phase B takes its
// interrupts ends the run with nothing applied (exit 130): no approval line,
// one line and, with --json, one object that say the review was
// interrupted.
func TestApplyReviewCtrlCAfterTheLastAnswer(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.ctx = ctx
	b.sb.hooks.applyReviewed = cancel
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1", "--json")
	askedFor(t, errb, "example-sw1")
	logins := b.srv.Logins()
	_, _ = master.WriteString("example-sw1\n")
	status, o, e := b.wait(code, out, errb)
	if status != 130 || !strings.Contains(o, `"phase":"review","status":"approved"`) ||
		!strings.Contains(o, `"phase":"review","reason":"the review was interrupted: nothing was applied","status":"interrupted"`) ||
		!strings.Contains(o, `"stop":"interrupted"`) || strings.Contains(o, `"phase":"apply"`) {
		t.Errorf("exit %d\n%s\n%s", status, o, e)
	}
	if b.committed() != before || b.srv.Logins() != logins || auditLine(b.runner, "device config apply user=alice approved=") != "" ||
		!strings.HasPrefix(auditLine(b.runner, "device config apply review user=alice result=interrupted "), "device config apply review user=alice result=interrupted applied=0 mode=attended") {
		t.Errorf("applied after a Ctrl-C, or lines %q", auditLines(b.runner))
	}
}

// --check asks nothing and writes no review line; --confirmed --yes answers
// for every device in the scripted form, said on the review, approval and
// apply lines, with no password in any.
func TestApplyReviewCheckAndScripted(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	_ = master
	status, o, e := b.wait(b.start(slave, out, errb, "example-sw1", "--check"), out, errb)
	if status != 0 || strings.Contains(o+e, "Type the device name") || auditLine(b.runner, "device config apply review ") != "" {
		t.Errorf("--check: exit %d\n%s\n%s\n%q", status, o, e, auditLines(b.runner))
	}
	b.seed("example-sw1")
	code, o, e := b.apply("example-sw1", "--confirmed", "--yes")
	if code != 0 || !strings.Contains(o, "--yes: every shape is one another device confirmed; going on.") || strings.Contains(o+e, "Type the device name") {
		t.Fatalf("exit %d\n%s\n%s", code, o, e)
	}
	for _, want := range []string{
		"device config apply review user=alice device=example-sw1 shape=",
		"device config apply user=alice approved=1 shapes=",
	} {
		if l := auditLine(b.runner, want); !strings.HasSuffix(l, " mode=scripted") {
			t.Errorf("no %q ... mode=scripted in %q", want, auditLines(b.runner))
		}
	}
	if l := applyLineOf(b, "example-sw1"); !strings.Contains(l, " result=applied ") || !strings.HasSuffix(l, " mode=scripted") {
		t.Errorf("apply line %q", l)
	}
	noLoggerHas(t, "the scripted apply", b.runner, testPassword)
}

// waitLong is waitUntil with the time a whole transaction on the fake device
// may take (it types each statement and waits for the echo).
func waitLong(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(120 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("gave up waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
