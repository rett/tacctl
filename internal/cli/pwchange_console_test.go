package cli

import (
	"regexp"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/console"
)

const ptyPolicyChange = ptyPolicyRO + ",password_change=yes"

// A console opened for a caller who must change the password: the notice and
// the dialog straight away, no prompt before the password is changed, then a
// prompt and a session as any other. The log has the opening.
func TestConsolePtyRequiredPasswordChangeOpensWithTheDialog(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, ptyPolicyChange, "carol,tac-users,tac-readonly")
	p.expect(`tacctl console on ` + host + `\. This session is logged\.\r\n`)
	p.expect(`A password change is required of your account\.`)
	p.expect(`No device accepts your login until it is changed, and nothing here runs until then but the change itself\.\r\n`)
	// the dialog is the line 'passwd', run as any other (here a stand-in)
	p.expect(`RAN-PASSWD\r\n`)
	p.expect(`Type 'help'\. Devices: device list\.\r\n`)
	p.expect(host + `> `)
	// unlocked: the session is the usual one, help included
	p.send("user list\r")
	p.expect(`RAN sudo -n TACCTL_CONSOLE=[0-9a-f]{12} ` + regexp.QuoteMeta(testExe) + ` user list\r\n`)
	p.expect(host + `> `)
	p.send("help\r")
	p.expect(`system-shell +Start your system shell`)
	p.expect(host + `> `)
	p.send("exit\r")
	log := p.ends(0)
	joined := strings.Join(log, "\n")
	for _, w := range []string{`console password-change required session=[0-9a-f]{12} user=carol`, `console password-change done session=[0-9a-f]{12} user=carol`,
		`console end session=[0-9a-f]{12} user=carol reason=exit`} {
		if !regexp.MustCompile(w).MatchString(joined) {
			t.Errorf("the log lacks %q:\n%s", w, joined)
		}
	}
	if strings.Contains(joined, "reason=password-change") {
		t.Errorf("a refusal was logged for a session that was not refused:\n%s", joined)
	}
}

// Ctrl-C in the dialog declines it: the session ends, with no prompt and
// nothing else run.
func TestConsolePtyDecliningThePasswordChangeEndsTheSession(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, ptyPolicyChange, "carol,tac-users,tac-readonly", "passwd=130")
	p.expect(`A password change is required of your account\.`)
	p.expect(`RAN-PASSWD\r\n`)
	p.expect(`The password change was declined\. The session ends; nothing else is available until the password is changed\.`)
	log := p.ends(130)
	if strings.Contains(p.Output(), host+"> ") {
		t.Errorf("a prompt after a declined change:\n%s", p.Output())
	}
	joined := strings.Join(log, "\n")
	for _, w := range []string{`console password-change failed session=[0-9a-f]{12} user=carol status=130`, `console end session=[0-9a-f]{12} user=carol reason=` + console.ReasonLocked + ` lines=0 status=130`} {
		if !regexp.MustCompile(w).MatchString(joined) {
			t.Errorf("the log lacks %q:\n%s", w, joined)
		}
	}
}

// A dialog that fails (a wrong current password, a weak new one) leaves the
// session at a prompt that is still locked: the lists offer the change and
// exit, a typed word is refused (and logged without the word when it is not
// a command), and 'passwd' tries again and unlocks.
func TestConsolePtyAFailedChangeLeavesALockedPrompt(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, ptyPolicyChange, "carol,tac-users,tac-readonly", "passwd=1")
	p.expect(`RAN-PASSWD\r\n`)
	p.expect(`The password was not changed\. Type 'passwd' to try again, or 'exit' to leave; nothing else runs until it is changed\.`)
	p.expect(host + `> `)
	p.send("user list\r")
	p.expect(`A password change is required: nothing runs here until it is made but 'passwd' \(and 'exit'\)\.`)
	p.expect(`\[exit 1\]`)
	p.expect(host + `> `)
	p.send("help\r")
	p.expect(`A password change is required: nothing runs here until it is made but 'passwd'`)
	p.expect(host + `> `)
	p.send("hunter2-typed-as-a-line\r")
	p.expect(`A password change is required: nothing runs here until it is made but 'passwd'`)
	p.expect(host + `> `)
	// the lists show what runs: '?' names passwd, and no other command
	p.send("?")
	p.expect(`passwd\S* +Change your own password`)
	p.expect(host + `> `)
	if out := p.Output(); strings.Contains(out[strings.Index(out, "Possible completions"):], "user ") {
		t.Errorf("the list names other commands:\n%s", out)
	}
	p.send("\x15exit\r")
	log := p.ends(0)
	joined := strings.Join(log, "\n")
	for _, w := range []string{`console DENY session=[0-9a-f]{12} user=carol reason=password-change first=user\b`,
		`console DENY session=[0-9a-f]{12} user=carol reason=password-change first=help\b`,
		`console DENY session=[0-9a-f]{12} user=carol reason=password-change first=- len=23`} {
		if !regexp.MustCompile(w).MatchString(joined) {
			t.Errorf("the log lacks %q:\n%s", w, joined)
		}
	}
	if strings.Contains(joined, "hunter2") {
		t.Errorf("a typed word was logged:\n%s", joined)
	}
}

// A line given to the console with -c is held to the change too: refused with
// status 1 (nothing runs), and 'passwd' runs.
func TestConsolePtyCommandLineIsHeldToThePasswordChange(t *testing.T) {
	p := startConsole(t, ptyPolicyChange, "carol,tac-users,tac-readonly", "c=user list")
	p.expect(`A password change is required: nothing runs here until it is made but 'passwd' \(and 'exit'\)\.`)
	log := p.ends(1)
	if strings.Contains(p.Output(), "RAN") {
		t.Errorf("the line ran:\n%s", p.Output())
	}
	if !regexp.MustCompile(`console DENY session=[0-9a-f]{12} user=carol reason=password-change first=user`).MatchString(strings.Join(log, "\n")) {
		t.Errorf("the log:\n%s", strings.Join(log, "\n"))
	}
	p = startConsole(t, ptyPolicyChange, "carol,tac-users,tac-readonly", "c=passwd")
	p.expect(`RAN-PASSWD\r\n`)
	p.ends(0)
}

// A caller who is not held to a change gets the usual banner and prompt,
// whatever the field says for a superuser (the root side never says it, and
// the console does not take it from one either).
func TestConsolePtyNoPasswordChangeNoLock(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, "shell=console,idle=30,system_shell=no,system_shell_path=/bin/bash,tier=superuser,list_max=40,password_change=yes", "alice,tac-users,tac-superuser")
	p.expect(`tacctl console on ` + host + ` — type 'help'\. Devices: device list\. This session is logged\.\r\n`)
	p.expect(host + `> `)
	p.send("user list\r")
	p.expect(`RAN sudo`)
	p.send("exit\r")
	p.ends(0)
}

// No policy answer (sudo fails): a caller who is no superuser gets the notice
// that it could not be read, no dialog, and a locked prompt where a line is
// refused with the matching notice; the log says so.
func TestConsolePtyUnreadPolicyHoldsTheSession(t *testing.T) {
	host := regexp.QuoteMeta(shortHostname())
	p := startConsole(t, "FAIL", "carol,tac-users,tac-operator")
	p.expect(`It could not be read whether a password change is required of your account\.`)
	p.expect(host + `> `)
	if strings.Contains(p.Output(), "RAN-PASSWD") {
		t.Errorf("the dialog opened for a requirement nobody read:\n%s", p.Output())
	}
	p.send("user list\r")
	p.expect(`It could not be read whether a password change is required of your account, so nothing runs here`)
	p.expect(host + `> `)
	p.send("exit\r")
	log := p.ends(0)
	joined := strings.Join(log, "\n")
	for _, w := range []string{`console password-change unknown session=[0-9a-f]{12} user=carol`, `console DENY session=[0-9a-f]{12} user=carol reason=password-change first=user\b`} {
		if !regexp.MustCompile(w).MatchString(joined) {
			t.Errorf("the log lacks %q:\n%s", w, joined)
		}
	}
	// a superuser (known by the system's groups) is not held by it
	p = startConsole(t, "FAIL", "alice,tac-users,tac-superuser")
	p.expect(`tacctl console on ` + host + ` — type 'help'\. Devices: device list\. This session is logged\.\r\n`)
	p.expect(host + `> `)
	p.send("exit\r")
	p.ends(0)
}
