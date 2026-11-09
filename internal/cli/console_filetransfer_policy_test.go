package cli

import (
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

// policyLine is the _console-policy answer for user, in group.
func (sb *sandbox) policyLine(user, group string) string {
	sb.t.Helper()
	return plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", user}, execx.Result{Stdout: []byte(user + " tac-users tac-" + group + "\n")})
	}, "SUDO_USER="+user, "SUDO_UID="+uidOf(user)))
}

// The _console-policy line carries the caller's file transfer to the
// console's own process, which cannot read root's file: off unless the
// settings give it, with the quota and the rate when they do, and the
// console reads the line back as the settings (Remote.FileTransferSettings).
func TestConsolePolicyLineCarriesFileTransfer(t *testing.T) {
	sb := consoleSandbox(t)
	read := func(user, group string) console.FileTransfer {
		sb.t.Helper()
		r, ok := console.ParseRemote(sb.policyLine(user, group))
		if !ok {
			t.Fatalf("%s: the line is not read", user)
		}
		return r.FileTransferSettings()
	}
	// the defaults: a superuser has it, with no quota; the others do not
	if got := sb.policyLine("bob", "operator"); strings.Contains(got, "file_transfer") || strings.Contains(got, "ft_quota") {
		t.Errorf("bob by default: %q", got)
	}
	if got := read("alice", "superuser"); got != (console.FileTransfer{Enabled: true}) {
		t.Errorf("alice: %+v", got)
	}
	if got := read("carol", "readonly"); got != (console.FileTransfer{}) {
		t.Errorf("carol: %+v", got)
	}
	// a tier: its quota (the default, then set) and its rate
	sb.con("file-transfer", "operator", "enable")
	if got := read("bob", "operator"); got != (console.FileTransfer{Enabled: true, Quota: 256 << 20}) {
		t.Errorf("bob enabled: %+v", got)
	}
	if got := sb.policyLine("bob", "operator"); !strings.Contains(got, " file_transfer=yes ft_quota=268435456 ft_rate=0") {
		t.Errorf("bob's line: %q", got)
	}
	sb.con("file-transfer", "quota", "operator", "1G")
	sb.con("file-transfer", "rate", "operator", "512K")
	if got := read("bob", "operator"); got != (console.FileTransfer{Enabled: true, Quota: 1 << 30, Rate: 512 << 10}) {
		t.Errorf("bob with limits: %+v", got)
	}
	// a user's own values over the tier's, and a disable over the tier's enable
	sb.con("file-transfer", "quota", "user", "bob", "unlimited")
	sb.con("file-transfer", "rate", "user", "bob", "2M")
	if got := read("bob", "operator"); got != (console.FileTransfer{Enabled: true, Quota: 0, Rate: 2 << 20}) {
		t.Errorf("bob with his own: %+v", got)
	}
	sb.con("file-transfer", "user", "bob", "disable")
	if got := read("bob", "operator"); got != (console.FileTransfer{}) {
		t.Errorf("bob disabled: %+v", got)
	}
	// a user of a tier that has none, enabled for the tier
	sb.con("file-transfer", "user", "carol", "enable")
	if got := read("carol", "readonly"); got != (console.FileTransfer{Enabled: true, Quota: 256 << 20}) {
		t.Errorf("carol enabled: %+v", got)
	}
	// a caller with no tier restriction (root) has none, whatever the file says
	line := plain(sb.cfgRun("", []string{"_console-policy"}, nil))
	if r, ok := console.ParseRemote(line); !ok || r.FileTransferSettings() != (console.FileTransfer{}) {
		t.Errorf("root: %q", line)
	}
	// a user who is no store user is not honoured under the name
	sb.write("state/console.yaml", "version: 1\nsettings: {file_transfer: {tiers: [superuser], users: {mallory: 'enable:readonly'}}}\n", 0o600)
	line = plain(sb.cfgRun("", []string{"_console-policy"}, func(r *fake.Runner) {
		r.On([]string{"id", "-nG", "--", "mallory"}, execx.Result{Stdout: []byte("mallory tac-users tac-readonly\n")})
	}, "SUDO_USER=mallory", "SUDO_UID=4242"))
	if r, _ := console.ParseRemote(line); r.FileTransferSettings() != (console.FileTransfer{}) {
		t.Errorf("mallory: %q", line)
	}
}
