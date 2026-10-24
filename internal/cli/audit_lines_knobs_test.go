//go:build testknobs

package cli

import (
	"regexp"
	"testing"
)

// The knob clock and random source make the central lines exact (the id of
// the session and the duration are fixed), and TACCTL_FAULT makes a command
// fail after its snapshot (docs/plans/0.2.17-plan.md D255 2 and 3).
const (
	knobNow    = "TACCTL_TEST_NOW=2026-10-21T09:30:15Z"
	knobRandom = "TACCTL_TEST_RANDOM=000102030405060708090a0b0c0d0e0f"
)

func TestCentralLinesAreExactWithTheKnobs(t *testing.T) {
	sb := newSandbox(t, true)
	sb.run("", []string{"user", "disable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001", knobNow, knobRandom)
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	lines := centralLines(sb.runner)
	const start = `cmd start v=1 user=alice uid=1001 origin=sudo tier=unrestricted tty=- console=- cmd="user disable" args=bob`
	end := regexp.MustCompile(`^cmd end v=1 user=alice cmd="user disable" result=ok status=0 duration=0\.000s snapshot=2026\d{4}_\d{6}_000$`)
	if len(lines) != 2 || lines[0] != start || !end.MatchString(lines[1]) {
		t.Errorf("lines %q", lines)
	}
	if sid, ok := auditSID(sb.runner); !ok || sid != "abcdefgh" {
		t.Errorf("sid %q (shared %v)", sid, ok)
	}
}

// A store apply that fails after its snapshot ends in result=failed with the
// snapshot it took.
func TestCentralEndOfAnApplyThatFailsAfterItsSnapshot(t *testing.T) {
	sb := renderedSandbox(t)
	sb.run("", []string{"user", "disable", "bob"}, "SUDO_USER=alice", "SUDO_UID=1001", "TACCTL_FAULT=render-commit:tacacs", knobNow, knobRandom)
	if sb.code == 0 {
		t.Fatalf("the apply did not fail: %q", sb.out.String())
	}
	lines := centralLines(sb.runner)
	end := regexp.MustCompile(`^cmd end v=1 user=alice cmd="user disable" result=failed status=1 duration=0\.000s snapshot=2026\d{4}_\d{6}_000$`)
	if len(lines) != 2 || !end.MatchString(lines[1]) {
		t.Errorf("lines %q (exit %d, stderr %q)", lines, sb.code, sb.stderr())
	}
	// The change did not happen: no detail line says it did (D253).
	if hasAuditPrefix(sb.runner, "", "user disable") {
		t.Errorf("a detail line for a change that failed: %q", auditLines(sb.runner))
	}
}
