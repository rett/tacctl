package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
)

// 'device config apply --pull' (0.2.17 D268): the devices are pulled first
// with the run's one password, a device whose pull failed is not checked,
// and --stale and --differs select from the records the pull has just made.

// Without --pull the selection is the records': a device never pulled is
// not --differs, and nothing is read, asked or written. With --pull the
// same line reads it first, finds it differs, and checks it, with one
// password for the pull and the check.
func TestApplyPullSelectsOnTheFreshRecords(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()

	code, out, errs := b.apply("--differs", "--check")
	if code != 0 || !strings.Contains(out+errs, "No devices to read.") {
		t.Fatalf("without --pull: exit %d\n%s\n%s", code, out, errs)
	}
	if b.pw.asked != 0 {
		t.Errorf("without --pull the password was asked %d times", b.pw.asked)
	}
	if _, ok := b.records().Of("example-sw1"); ok {
		t.Error("without --pull a record was written")
	}
	if hasAuditPrefix(b.runner, "", "device config pull ") {
		t.Errorf("without --pull a pull line was written: %q", auditLines(b.runner))
	}

	code, out, errs = b.apply("--differs", "--check", "--pull", "--exit-code")
	if code != 2 || !strings.Contains(out, "pull: 1 differ") || !strings.Contains(out, "example-sw1  checked") {
		t.Fatalf("with --pull: exit %d\n%s\n%s", code, out, errs)
	}
	if b.pw.asked != 1 || b.pw.done != 1 {
		t.Errorf("the password was asked %d times and ended %d, want once each for the pull and the check", b.pw.asked, b.pw.done)
	}
	rec, ok := b.records().Of("example-sw1")
	if !ok || rec.Pulled.IsZero() || rec.By != "alice" {
		t.Errorf("the pull's record: %+v", rec)
	}
	if a := b.applied("example-sw1"); a == nil || a.Kind != "check" {
		t.Errorf("the check's record: %+v", a)
	}
	if !hasAuditPrefix(b.runner, "auth.info", "device config pull user=alice device=example-sw1 ") ||
		!hasAuditPrefix(b.runner, "auth.info", "device config apply user=alice device=example-sw1 ") {
		t.Errorf("the pull's and the check's lines: %q", auditLines(b.runner))
	}
	noLoggerHas(t, "apply --pull", b.runner, testPassword)
	if b.committed() != before {
		t.Error("--check changed the device")
	}

	// --json: the pull's objects carry "phase":"pull"
	code, out, _ = b.apply("example-sw1", "--check", "--pull", "--json")
	if code != 0 || !strings.Contains(out, `"name":"example-sw1","scope":"lab","vendor":"juniper","phase":"pull","status":"ok"`) ||
		!strings.Contains(out, `"phase":"check","status":"checked"`) {
		t.Errorf("--json: exit %d\n%s", code, out)
	}
}

// A device whose pull fails is a failed row and is not checked (it is
// dialled once, by the pull); the others go on.
func TestApplyPullFailureExcludesTheDevice(t *testing.T) {
	b := newApplyBox(t)
	key := b.srv.HostKey()
	b.sb.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n"+
		"  example-sw1:\n    address: 192.168.1.20\n    vendor: juniper\n    hostname: example-sw1\n    host_keys:\n    - "+key+"\n"+
		"  example-sw2:\n    address: 192.168.1.21\n    vendor: juniper\n    host_keys:\n    - "+key+"\n", 0o600)
	dial := b.sb.hooks.deviceDial
	var sw2 atomic.Int32
	b.sb.hooks.deviceDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.168.1.21:") {
			sw2.Add(1)
			return nil, errors.New("connection refused")
		}
		return dial(ctx, network, addr)
	}
	code, out, errs := b.apply("example-sw1,example-sw2", "--check", "--pull")
	if code != 1 || !strings.Contains(out, "pull: 1 differ, 1 failed") || !strings.Contains(out, "example-sw1  checked") ||
		strings.Contains(out, "example-sw2  checked") || !strings.Contains(out, "1 checked, 1 failed") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if n := sw2.Load(); n != 1 {
		t.Errorf("example-sw2 was dialled %d times, want once (the pull)", n)
	}
	if a := b.applied("example-sw2"); a != nil {
		t.Errorf("example-sw2 was checked: %+v", a)
	}
	if b.pw.asked != 1 {
		t.Errorf("the password was asked %d times", b.pw.asked)
	}

	sw2.Store(0)
	code, out, _ = b.apply("example-sw1,example-sw2", "--check", "--pull", "--json")
	if code != 1 || !strings.Contains(out, `"name":"example-sw2","scope":"lab","vendor":"juniper","phase":"pull","status":"failed"`) ||
		!strings.Contains(out, `"failed":1`) || sw2.Load() != 1 {
		t.Errorf("--json: exit %d\n%s", code, out)
	}
}

// A device that differed at its last pull and runs what tacctl renders now
// is pulled and left out by --differs: nothing is checked, exit 0, and the
// summary names it.
func TestApplyPullDiffersAfterThePull(t *testing.T) {
	b := newSelBox(t)
	if s := b.states()["core-sw2"]; s != "differs" {
		t.Fatalf("core-sw2 is %q before the pull", s)
	}
	b.serve("juniper", b.expected("core-sw2"))
	asked := b.pw.asked
	out := b.run("device", "config", "apply", "--pull", "--differs", "--name", "core-sw2", "--check")
	if b.sb.code != 0 || !strings.Contains(out, "pull: 1 ok") ||
		!strings.Contains(out, "skipped 1 (core-sw2): pulled, and the fresh pull matches what tacctl renders") {
		t.Fatalf("exit %d\n%s\n%s", b.sb.code, out, b.sb.stderr())
	}
	if s := b.states()["core-sw2"]; s != "ok" {
		t.Errorf("core-sw2 is %q after the pull", s)
	}
	if rec, _ := b.records().Of("core-sw2"); rec == nil || rec.Applied != nil {
		t.Errorf("core-sw2 was checked: %+v", rec)
	}
	if b.pw.asked != asked+1 {
		t.Errorf("the password was asked %d times", b.pw.asked-asked)
	}
	out = b.run("device", "config", "apply", "--pull", "--differs", "--name", "core-sw2", "--check", "--json")
	if b.sb.code != 0 || !strings.Contains(out, `"match_after_pull":["core-sw2"]`) {
		t.Errorf("--json: exit %d\n%s", b.sb.code, out)
	}
}

// The refusals stand with --pull and come before any login; --confirmed
// --yes pulls and then skips a shape nobody confirmed; a pull stopped by a
// refused password ends the run with nothing checked.
func TestApplyPullRefusalsAndForms(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"example-sw1", "--pull"}, "No terminal to confirm on"},
		{[]string{"example-sw1", "--pull", "--confirmed", "--yes", "--hold"}, "--hold asks a person to log in and type OK"},
		{[]string{"example-sw1", "--pull", "--check", "--hold"}, "--hold, --pause and --no-canary are for an apply"},
		{[]string{"example-sw1", "--pull", "--yes"}, "--yes answers the review only with --confirmed"},
		{[]string{"example-sw1", "--pull", "--diff", "--check"}, "Unknown option: '--diff'"},
	} {
		code, out, errs := b.apply(c.args...)
		if code != 2 || !strings.Contains(out+errs, c.want) {
			t.Errorf("%v: exit %d, want 2 and %q\n%s\n%s", c.args, code, c.want, out, errs)
		}
	}
	if b.pw.asked != 0 || b.pw.done != 0 {
		t.Errorf("a refusal asked for the password %d times (done %d)", b.pw.asked, b.pw.done)
	}
	if _, ok := b.records().Of("example-sw1"); ok {
		t.Error("a refusal wrote a record")
	}

	code, out, errs := b.apply("example-sw1", "--pull", "--confirmed", "--yes")
	if code != 1 || !strings.Contains(out, "pull: 1 differ") || !strings.Contains(out, "example-sw1  skipped: unknown shape ") {
		t.Errorf("--confirmed --yes: exit %d\n%s\n%s", code, out, errs)
	}
	if rec, _ := b.records().Of("example-sw1"); rec == nil || rec.Pulled.IsZero() {
		t.Errorf("--confirmed --yes did not pull: %+v", rec)
	}

	if b.committed() != before {
		t.Error("the device was changed")
	}
}

// A refused password stops the pull: no device is tried a second time
// (the check would be a second login), nothing is checked, and the source
// is told once and ended once.
func TestApplyPullRefusedPasswordEndsTheRun(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1", "example-sw2")
	before := b.committed()
	dial := b.sb.hooks.deviceDial
	var dials atomic.Int32
	b.sb.hooks.deviceDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return dial(ctx, network, addr)
	}
	b.pw.pw = "wrong-fake-pass"
	code, out, errs := b.apply("example-sw1,example-sw2", "--pull", "--check", "--concurrency", "1", "--json")
	if code != 1 || !strings.Contains(out, `"stop":"auth-failed"`) || strings.Contains(out, `"phase":"check"`) {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("%d login attempts, want one (example-sw1's pull)", n)
	}
	if b.pw.asked != 1 || b.pw.rejected != 1 || b.pw.accepted != 0 || b.pw.done != 1 {
		t.Errorf("password source: asked %d rejected %d accepted %d done %d", b.pw.asked, b.pw.rejected, b.pw.accepted, b.pw.done)
	}
	for _, n := range []string{"example-sw1", "example-sw2"} {
		if a := b.applied(n); a != nil {
			t.Errorf("%s was checked: %+v", n, a)
		}
	}
	if b.committed() != before {
		t.Error("the device was changed")
	}
}

// A pull stopped by --max-failures, and one interrupted, end the run with
// nothing checked and nothing applied.
func TestApplyPullStoppedOrInterruptedChecksNothing(t *testing.T) {
	b := newApplyBox(t)
	key := b.srv.HostKey()
	b.sb.write("state/devices.yaml", "version: 1\nsettings:\n  stale_days: 30\ndevices:\n"+
		"  example-sw0:\n    address: 192.168.1.21\n    vendor: juniper\n    host_keys:\n    - "+key+"\n"+
		"  example-sw1:\n    address: 192.168.1.20\n    vendor: juniper\n    hostname: example-sw1\n    host_keys:\n    - "+key+"\n", 0o600)
	dial := b.sb.hooks.deviceDial
	b.sb.hooks.deviceDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if strings.HasPrefix(addr, "192.168.1.21:") {
			return nil, errors.New("connection refused")
		}
		return dial(ctx, network, addr)
	}
	before := b.committed()
	code, out, errs := b.apply("example-sw0,example-sw1", "--pull", "--confirmed", "--yes", "--concurrency", "1", "--max-failures", "1", "--json")
	if code != 1 || !strings.Contains(out, `"stop":"max-failures"`) || strings.Contains(out, `"phase":"check"`) ||
		!strings.Contains(out, `"name":"example-sw1","scope":"lab","vendor":"juniper","phase":"pull","status":"not-started"`) {
		t.Errorf("--max-failures: exit %d\n%s\n%s", code, out, errs)
	}
	if b.srv.Logins() != 0 || b.applied("example-sw1") != nil {
		t.Errorf("--max-failures: %d logins, record %+v", b.srv.Logins(), b.applied("example-sw1"))
	}

	// the read of example-sw1 (over the command line, as the setting says)
	// never answers until the second Ctrl-C
	b.run("config", "devices", "transport", "ssh")
	if b.sb.code != 0 {
		t.Fatalf("transport ssh: %d %q", b.sb.code, b.sb.stderr())
	}
	b.knob(junosReadCmd+".hang", "")
	ch := b.interrupts()
	outb, errb := &lockedBuf{}, &lockedBuf{}
	run := b.start(nil, outb, errb, "example-sw1", "--pull", "--confirmed", "--yes")
	waitLong(t, "the pull to read", func() bool { return b.served(junosReadCmd) >= 1 })
	ch <- struct{}{}
	ch <- struct{}{}
	status, o, e := b.wait(run, outb, errb)
	if status != 130 || strings.Contains(o, "checked") || strings.Contains(o+e, "--yes: every shape") {
		t.Errorf("interrupted: exit %d\n%s\n%s", status, o, e)
	}
	if b.applied("example-sw1") != nil || b.committed() != before {
		t.Errorf("interrupted: checked or changed: %+v", b.applied("example-sw1"))
	}
}

// A Ctrl-C that cancels the invocation after the pool of the pull ended is
// an interrupted pull: a shape another apply confirmed is not committed by
// '--confirmed --yes', exit 130, and the password source is ended once.
func TestApplyPullCancelledAfterThePullAppliesNothing(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	before := b.committed()
	b.seed("example-sw1")
	checked := b.applied("example-sw1")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	b.ctx = ctx
	b.sb.hooks.applyPullDone = cancel
	*b.pw = staticPasswords{pw: testPassword}
	logins := b.srv.Logins()
	code, out, errs := b.apply("example-sw1", "--pull", "--confirmed", "--yes")
	if code != 130 || strings.Contains(out, "checked") || strings.Contains(out+errs, "--yes: every shape") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if b.committed() != before || b.srv.Logins() != logins+1 {
		t.Errorf("committed changed or more than the pull's login (%d)", b.srv.Logins()-logins)
	}
	if a := b.applied("example-sw1"); a == nil || checked == nil || a.ID != checked.ID {
		t.Errorf("the record of the check changed: %+v", a)
	}
	if b.pw.asked != 1 || b.pw.done != 1 {
		t.Errorf("password source: asked %d done %d", b.pw.asked, b.pw.done)
	}
}

// audit.strict with a logger that fails refuses 'apply --pull' before any
// login: exit 1, nothing pulled, nothing checked.
func TestStrictRefusesAnApplyPullBeforeAnyLogin(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.sb.strictOn()
	b.script = func(r *fake.Runner) { r.Missing("logger") }
	code, _, errs := b.apply("example-sw1", "--pull", "--check")
	if code != 1 || !strings.Contains(errs, fmt.Sprintf(strictRefusal, "not found")) {
		t.Fatalf("exit %d %q", code, errs)
	}
	if b.srv.Logins() != 0 {
		t.Errorf("%d logins before the refusal", b.srv.Logins())
	}
	if rec, ok := b.records().Of("example-sw1"); ok {
		t.Errorf("a record was written: %+v", rec)
	}
}

// A device pulled that --differs leaves out because it cannot be compared
// (here its stored sections cannot be read once the pull has written them)
// is not named as matching: it has a reason of its own, and is not checked.
func TestApplyPullNotComparedIsNotAMatch(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.sb.hooks.applyPullDone = func() {
		if err := os.WriteFile(b.sb.path("var-lib", "device-config", "example-sw1.yaml"), []byte("{not yaml"), 0o600); err != nil {
			t.Error(err)
		}
	}
	code, out, errs := b.apply("--name", "example-sw1", "--pull", "--differs", "--check")
	if code != 0 || !strings.Contains(out, "skipped 1 (example-sw1): pulled, and could not be compared with what tacctl renders after the pull") ||
		strings.Contains(out, "matches what tacctl renders") || strings.Contains(out, "example-sw1  checked") {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	code, out, _ = b.apply("--name", "example-sw1", "--pull", "--differs", "--check", "--json")
	if code != 0 || !strings.Contains(out, `"not_compared_after_pull":["example-sw1"]`) || strings.Contains(out, "match_after_pull") {
		t.Errorf("--json: exit %d\n%s", code, out)
	}
	if a := b.applied("example-sw1"); a != nil {
		t.Errorf("checked: %+v", a)
	}
}
