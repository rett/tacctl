package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/devconf"
)

// A pending record of an apply the device rolled back at its window's end
// is settled by the next run from the device's rollbacks: the run prints
// what became of it above the device's own line, audits it, and the settled
// state is shown before the run's own record replaces it.
func TestApplySettlePrintedAndAudited(t *testing.T) {
	b := newApplyBox(t)
	b.register("example-sw1")
	b.seed("example-sw1")
	before := b.committed()
	// a minute of the window lasts a second; the held session drops after
	// the confirmed commit (a dead tacctl): the record says pending
	b.knob("timer.minute", "1\n")
	b.knob("commit.drop", "")
	code, out, errs := b.apply("example-sw1", "--confirmed", "--yes")
	pend := b.applied("example-sw1")
	if code != 1 || pend == nil || pend.Result != devconf.AppliedPending || !strings.HasPrefix(pend.ID, "tacctl-") {
		t.Fatalf("exit %d record %+v\n%s\n%s", code, pend, out, errs)
	}
	if err := os.Remove(filepath.Join(b.dir, "commit.drop")); err != nil {
		t.Fatal(err)
	}
	waitLong(t, "the device's own rollback", func() bool { _, p := b.srv.PendingUntil(); return !p })
	if b.committed() != before {
		t.Fatalf("not rolled back:\n%s", b.committed())
	}

	code, out, errs = b.apply("example-sw1", "--check")
	want := "example-sw1  the earlier apply " + pend.ID + " by alice was rolled back by the device at "
	i, j := strings.Index(out, want), strings.Index(out, "example-sw1  checked: ")
	if code != 0 || i < 0 || j < 0 || i > j {
		t.Errorf("exit %d\n%s\n%s", code, out, errs)
	}
	if !hasAudit(b.runner, "auth.notice", "device config apply settle user=alice device=example-sw1 id="+pend.ID+" result=rolled-back") {
		t.Errorf("no settle audit line: %v", b.runner.Calls())
	}
	// the run's own record follows the settle's
	if a := b.applied("example-sw1"); a == nil || a.Kind != devconf.AppliedKindCheck || a.Result != devconf.AppliedChecked {
		t.Errorf("record %+v", a)
	}

	// --json: the settle is the device object's 'settled'; nothing pending
	// any more, so a second run settles nothing
	code, out, _ = b.apply("example-sw1", "--check", "--json")
	if code != 0 || strings.Contains(out, `"settled"`) {
		t.Errorf("exit %d\n%s", code, out)
	}
}
