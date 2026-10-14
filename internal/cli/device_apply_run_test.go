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
	r := &fake.Runner{}
	r.On([]string{"systemctl"}, execx.Result{})
	r.On([]string{"logger"}, execx.Result{})
	r.On([]string{"id"}, execx.Result{Stdout: []byte("users\n")})
	fakePasswd(r)
	route(r)
	b.runner = r
	if in == nil {
		in = strings.NewReader("")
	}
	a := app.New(append([]string{"device", "config", "apply"}, args...), paths.NewEnv(append(append([]string(nil), b.sb.env...), "SUDO_USER=alice")),
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
	code := make(chan int, 1)
	go func() {
		code <- exitCode(Run(context.Background(), a, BuildInfo{Version: "0.2.0-test", Commit: "c", Date: "d"}), a.Out)
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
	b.sb.cfgRun("", []string{"device", "config", "shapes", "seed", name, "-y"}, nil, "SUDO_USER=alice")
	if b.sb.code != 0 {
		b.t.Fatalf("seed: %d %s", b.sb.code, b.sb.err.String())
	}
}

// interrupts makes the runner's Ctrl-Cs come from the returned channel.
func interrupts(t *testing.T) chan struct{} {
	ch := make(chan struct{}) // unbuffered: a send returns when the runner took it
	prev := interruptSource
	interruptSource = func() <-chan struct{} { return ch }
	t.Cleanup(func() { interruptSource = prev })
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
	ch := interrupts(t)
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
	applyRecordFault = func(_ string, a devconf.Applied) error {
		if a.Result == devconf.AppliedPending {
			refused.Add(1)
			return errors.New("disk full")
		}
		return nil
	}
	t.Cleanup(func() { applyRecordFault = nil })
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
	ch := interrupts(t)
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
			waitLong(t, "the review's question", func() bool { return strings.Contains(errb.String(), "Type the device name to go on:") })
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
	prev := applyHoldWait
	applyHoldWait = func(until, now time.Time) time.Duration {
		if calls.Add(1) == 1 {
			return 300 * time.Millisecond
		}
		return 30 * time.Second
	}
	t.Cleanup(func() { applyHoldWait = prev })
	master, slave := terminal(t)
	out, errb := &lockedBuf{}, &lockedBuf{}
	code := b.start(slave, out, errb, "example-sw1,example-sw2", "--hold", "--no-canary", "--max-failures", "2", "--pause", "0", "--concurrency", "1")
	waitLong(t, "the review's question", func() bool { return strings.Contains(errb.String(), "Type 2 to go on:") })
	_, _ = master.WriteString("2\n")
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
