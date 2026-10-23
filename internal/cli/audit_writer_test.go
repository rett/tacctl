package cli

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// Every logger call of a run ends in the same ' sid=<8 characters>', the
// gate's denial included (docs/plans/0.2.17-plan.md D247).
func TestAuditLinesOfARunShareTheSessionID(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	sb.sshRun("alice", nil, "ssh", "core-sw1")
	if sb.code != 0 {
		t.Fatalf("exit %d %q", sb.code, sb.stderr())
	}
	sid, ok := auditSID(sb.runner)
	if !ok || !regexp.MustCompile(`^[a-z0-9]{8}$`).MatchString(sid) {
		t.Fatalf("sid %q, shared %v", sid, ok)
	}
	if !strings.HasPrefix(auditLine(sb.runner, "ssh "), "ssh user=alice device=core-sw1 addr=10.99.0.1") || auditLine(sb.runner, "ssh end ") == "" {
		t.Errorf("lines %q", auditLines(sb.runner))
	}
	if n := len(auditLines(sb.runner)); n != 2 {
		t.Errorf("lines %q, want the start and the end of the session", auditLines(sb.runner))
	}
	for _, c := range sb.runner.Calls() {
		if c.Name == "logger" && !strings.HasSuffix(c.Args[len(c.Args)-1], " sid="+sid) {
			t.Errorf("logger %q does not end in the sid", c.Args)
		}
	}
	// A denial by the gate has the id too, and no blank before it.
	sb.sshRun("carol", func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "carol"}, execx.Result{Stdout: []byte("carol tac-users tac-readonly\n")})
	}, "user", "remove", "bob")
	sid, ok = auditSID(sb.runner)
	if sb.code != 1 || !ok || sid == "" || !hasAudit(sb.runner, "auth.warning", "tier DENY user=carol tier=readonly cmd=user remove") {
		t.Errorf("exit %d, sid %q (shared %v), lines %q", sb.code, sid, ok, auditLines(sb.runner))
	}
}

// A hangup ends the ssh session and cancels the invocation's context; the
// 'ssh end' line is written all the same (it was dropped when the writer used
// the invocation's context).
func TestSSHEndIsWrittenAfterAHangup(t *testing.T) {
	sb, _, _ := sshSandbox(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb.ctx = ctx
	sb.sshRun("alice", func(r *fake.Runner) {
		r.OnFunc([]string{"sudo", "-u", "alice"}, func(execx.Cmd) (execx.Result, error) {
			cancel() // SIGHUP: the session is gone
			return execx.Result{Code: 129}, nil
		})
	}, "ssh", "core-sw1")
	if ctx.Err() == nil {
		t.Fatal("the ssh stub did not run")
	}
	if !hasAuditMatch(sb.runner, "auth.info", `^ssh end user=alice device=core-sw1 status=129 duration=\d+$`) {
		t.Errorf("no 'ssh end' line after the hangup: %q (lines %q)", sb.runner.Argvs(), auditLines(sb.runner))
	}
}

// A logger that is missing or fails is told once on stderr, whatever the
// number of lines; the command's status is the one it had (D248).
func TestLoggerFailureIsToldOnceAndChangesNothing(t *testing.T) {
	for _, c := range []struct {
		name   string
		script func(*fake.Runner)
		reason string
	}{
		{"missing", func(r *fake.Runner) { r.Missing("logger") }, "not found"},
		{"failing", func(r *fake.Runner) { r.Fail([]string{"logger"}, 1, "journal unavailable") }, "exit status 1: journal unavailable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			sb, _, _ := sshSandbox(t)
			sb.sshRun("alice", c.script, "ssh", "core-sw1")
			want := "[WARN] The audit line was not written (logger: " + c.reason + "); the command continues."
			if sb.code != 0 || strings.Count(plain(sb.err.String()), want) != 1 {
				t.Errorf("exit %d, stderr %q, want it once: %s", sb.code, sb.err.String(), want)
			}
			if sb.sshArgv() == "" {
				t.Error("ssh was not started")
			}
		})
	}
}
