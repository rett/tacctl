package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx/fake"
)

// audit.strict and the verbs whose writes first happen on a worker goroutine
// (the pull's records): the refusal is raised on the command's own goroutine
// before the workers start, so no device is contacted and no record written.
func TestStrictRefusesAPullBeforeAnyLogin(t *testing.T) {
	b := newPullBox(t)
	b.devices([3]string{"lab-c", "192.168.1.30", "cisco"})
	b.serve("cisco", b.expected("lab-c"))
	b.sb.strictOn()
	b.sb.cfgRun("", []string{"device", "config", "pull", "lab-c"}, func(r *fake.Runner) {
		route(r)
		r.Missing("logger")
	}, "SUDO_USER=alice")
	if b.sb.code != 1 || !strings.Contains(plain(b.sb.stderr()), fmt.Sprintf(strictRefusal, "not found")) {
		t.Fatalf("exit %d %q", b.sb.code, b.sb.stderr())
	}
	if b.srv.Logins() != 0 {
		t.Errorf("%d logins before the refusal", b.srv.Logins())
	}
	if rec, _ := b.records().Of("lab-c"); rec != nil {
		t.Errorf("a record was written: %+v", rec)
	}
	// With a logger that works the same pull runs and writes its pair.
	out := b.run("device", "config", "pull", "lab-c")
	if b.sb.code != 0 || !strings.Contains(out, "ok via ssh") {
		t.Fatalf("exit %d %q %q", b.sb.code, out, b.sb.stderr())
	}
	if lines := centralLines(b.sb.runner); len(lines) != 2 || !strings.Contains(lines[0], `cmd="device config"`) {
		t.Errorf("lines %q", lines)
	}
}

// The same for 'device config apply': the refusal comes on the command's own
// goroutine before the pools start, as an exit status 1 and not a crash, and
// no device is contacted. (With a logger that works, --check writes the
// central pair as any apply does.)
func TestStrictRefusesAnApplyBeforeAnyLogin(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.sb.strictOn()
	b.script = func(r *fake.Runner) { r.Missing("logger") }
	before := b.committed()
	code, _, errs := b.apply("example-sw1", "--check")
	if code != 1 || !strings.Contains(errs, fmt.Sprintf(strictRefusal, "not found")) {
		t.Fatalf("exit %d %q", code, errs)
	}
	if strings.Contains(errs, "the command continues") {
		t.Errorf("the D248 warning beside the refusal: %q", errs)
	}
	if b.srv.Logins() != 0 || b.committed() != before {
		t.Errorf("logins %d, committed changed %v", b.srv.Logins(), b.committed() != before)
	}
	if rec := b.applied("example-sw1"); rec != nil {
		t.Errorf("a record was written: %+v", rec)
	}
	b.script = nil
	if code, _, errs = b.apply("example-sw1", "--check"); code != 0 && strings.Contains(errs, "audit") {
		t.Errorf("with a working logger: exit %d %q", code, errs)
	}
	if lines := centralLines(b.runner); len(lines) != 2 || !strings.Contains(lines[0], `cmd="device config"`) {
		t.Errorf("--check lines %q", lines)
	}
}
