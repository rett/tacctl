package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// The list form of 'console file-transfer' and 'console show' say whether
// sshd defines an sftp subsystem (sshd -T through the runner), and warn when
// file transfer is on for someone and sshd starts none: the console is never
// started for it. The superuser tier, which always has file transfer, does
// not make a server warn by itself.
func TestConsoleFileTransferSubsystem(t *testing.T) {
	sshd := func(subsystem string) func(*fake.Runner) {
		return func(r *fake.Runner) {
			r.On([]string{"sshd", "-T"}, execx.Result{Stdout: []byte("port 22\nallowtcpforwarding no\nallowagentforwarding no\n" + subsystem)})
		}
	}
	const warn = "WARNING: sshd defines no sftp subsystem: file transfer cannot start; add `Subsystem sftp ...` to sshd_config."
	sb := consoleSandbox(t)
	list := func(f func(*fake.Runner)) string {
		sb.t.Helper()
		return plain(sb.cfgRun("", []string{"console", "file-transfer"}, f))
	}
	// defined: said, no warning, with or without file transfer opened
	out := list(sshd("subsystem sftp /usr/lib/openssh/sftp-server\n"))
	if sb.code != 0 || !strings.HasSuffix(out, "\nsshd sftp subsystem: /usr/lib/openssh/sftp-server\n") || strings.Contains(out, "WARNING") {
		t.Errorf("defined: %d\n%s", sb.code, out)
	}
	if !sb.runner.Called("sshd", "-T", "-C", "user=root,host=localhost,addr=127.0.0.1") {
		t.Errorf("calls: %q", sb.runner.Argvs())
	}
	// none, and nobody but the superuser tier has file transfer: said, quiet
	out = list(sshd(""))
	if !strings.HasSuffix(out, "\nsshd sftp subsystem: none\n") || strings.Contains(out, "WARNING") {
		t.Errorf("none, not opened:\n%s", out)
	}
	// none, and a tier has it: warned, in red
	sb.con("file-transfer", "operator", "enable")
	out = list(sshd(""))
	if !strings.HasSuffix(out, "\nsshd sftp subsystem: none\n"+warn+"\n") {
		t.Errorf("none, operator tier:\n%s", out)
	}
	if raw := sb.cfgRun("", []string{"console", "file-transfer"}, sshd("")); !strings.Contains(raw, "\x1b[0;31m"+warn) {
		t.Errorf("the warning is not red: %q", raw)
	}
	sb.con("file-transfer", "operator", "disable")
	// none, and one user has it: warned; a disable does not
	sb.con("file-transfer", "user", "carol", "enable")
	if out = list(sshd("")); !strings.Contains(out, warn) {
		t.Errorf("none, a user:\n%s", out)
	}
	sb.con("file-transfer", "user", "carol", "disable")
	if out = list(sshd("")); strings.Contains(out, "WARNING") {
		t.Errorf("none, the user disabled:\n%s", out)
	}
	sb.con("file-transfer", "user", "carol", "clear")
	// sshd that cannot answer: said, the verb still succeeds
	out = list(func(r *fake.Runner) { r.Fail([]string{"sshd"}, 255, "no hostkeys available") })
	if sb.code != 0 || !strings.Contains(out, "sshd sftp subsystem: could not be checked: sshd -T failed: no hostkeys available") {
		t.Errorf("sshd failure: %d\n%s", sb.code, out)
	}
	// a query of one tier does not ask sshd
	if out = plain(sb.cfgRun("", []string{"console", "file-transfer", "operator"}, nil)); strings.Contains(out, "sshd") || sb.runner.Called("sshd") {
		t.Errorf("a tier query:\n%s", out)
	}
	// console show reports it in the server section, with the same warning
	sb.con("file-transfer", "operator", "enable")
	show := func(subsystem string) string {
		return plain(sb.cfgRun("", []string{"console", "show"}, sshd(subsystem)))
	}
	out = show("subsystem sftp internal-sftp\n")
	if !strings.Contains(out, "\nsshd sftp subsystem: internal-sftp\n") || strings.Contains(out, warn) {
		t.Errorf("show, defined:\n%s", out)
	}
	out = show("")
	if !strings.Contains(out, "\nsshd sftp subsystem: none\n"+warn+"\n") {
		t.Errorf("show, none:\n%s", out)
	}
}
