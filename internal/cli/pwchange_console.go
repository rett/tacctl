package cli

// The login console's half of a required password change (0.2.20). The
// root side tells the console, in the policy line it asks for first
// (password_change=yes, only for a caller who is no superuser), and the
// console then opens with a notice and the password change dialog, straight
// away; until the password is changed nothing else runs: every line but the
// change itself, exit and quit is refused, the lists offer only those, and
// declining, interrupting or failing the dialog ends the session. A -c line
// and a batch run are held the same way (they cannot open a dialog; a line
// that is 'passwd' runs). When the change is made the root side is asked
// once more, and the session goes on as any other. The command line holds the
// caller to it as well (pwchange_gate.go): this is the console's own refusal,
// so that nothing is typed to sudo while it stands.

import (
	"context"
	"io"
	"strings"
	"sync/atomic"

	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/shell"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// pwChangeWord is the one command that runs while a password change is
// required.
const pwChangeWord = "passwd"

// pwLockNotice is the refusal of a line of a locked session.
const pwLockNotice = "A password change is required: nothing runs here until it is made but 'passwd' (and 'exit')."

// pwUnknownNotice is the refusal of a line of a session held because it could
// not be told whether a password change is required.
const pwUnknownNotice = "It could not be read whether a password change is required of your account, so nothing runs here: the next line tries again ('passwd' changes the password, 'exit' leaves)."

// pwLock is the state of a session held to a required password change. unknown
// says the session is held because the requirement could not be read, not
// because the answer was yes: it opens with a notice, not with the dialog.
type pwLock struct {
	on      atomic.Bool
	unknown bool
}

func (l *pwLock) locked() bool { return l != nil && l.on.Load() }

// lockedBy is the lock of a session whose policy answer says a password
// change is required of the caller, or does not say (PasswordChangeUnknown:
// the answer could not be read, or the root side could not read the store):
// nil for any other. A superuser is never held, whichever way the answer
// goes: the answer's own tier says so, and when the answer has no tier (the
// store was unreadable, which gives every caller the tier none, or there was
// no answer) the system's groups of the caller do, since tac-superuser is a
// group of the account and needs no store. A session whose requirement is
// unknown and whose caller is no superuser is held: it fails closed.
func lockedBy(pol console.Remote, groups []string) *pwLock {
	if pol.Gate == tier.Superuser || pol.Tier == tier.Superuser {
		return nil
	}
	if !pol.PasswordChange {
		if !pol.PasswordChangeUnknown || sudoTier(groups) == tier.Superuser {
			return nil
		}
	}
	l := &pwLock{unknown: !pol.PasswordChange}
	l.on.Store(true)
	return l
}

// holdSession makes the run's lists, its refusals and its opening those of a
// locked session (runShell, for the console).
func (inv *invocation) holdSession(r shellRun, o *shell.Options) {
	base := inv.view
	inv.view = func() tier.Tier {
		if r.lock.locked() {
			return viewPasswordChange
		}
		if base == nil {
			return ""
		}
		return base()
	}
	o.Locked = r.lock.locked
	o.LockWords = []string{pwChangeWord}
	o.LockNotice = pwLockNotice
	if r.lock.unknown {
		o.LockNotice = pwUnknownNotice
	}
	o.LockRefused = r.lockRefused
	// the change, run in the session, lifts the lock when the root side
	// agrees it is made
	inner := o.Exec
	o.Exec = func(ctx context.Context, words []string, stdin io.Reader) int {
		code := inner(ctx, words, stdin)
		if code == 0 && r.lock.locked() && len(words) == 1 && words[0] == pwChangeWord {
			inv.liftLock(r)
		}
		return code
	}
	if r.mode == shellInteractive {
		exec := o.Exec
		o.Opening = func(ctx context.Context) (bool, int) { return inv.openPasswordChange(ctx, r, exec) }
	}
}

// liftLock lets the session go on once the root side says the password
// change is no longer required (an answer that could not be read counts: the
// command had succeeded).
func (inv *invocation) liftLock(r shellRun) {
	if r.recheck != nil && r.recheck() {
		return
	}
	r.lock.on.Store(false)
}

// openPasswordChange is the opening of an interactive locked session: the
// notice, then the dialog. The password changed, the session goes on as any
// other. The dialog interrupted (Ctrl-C at a prompt) is declined, and ends
// the session. Any other failure (a wrong current password, a password that
// is too weak, two that differ) leaves the session at a prompt that is still
// locked, where 'passwd' tries again and 'exit' leaves.
func (inv *invocation) openPasswordChange(ctx context.Context, r shellRun, exec func(context.Context, []string, io.Reader) int) (end bool, status int) {
	a := inv.app
	event := func(e string, status int) {
		if r.pwEvent != nil {
			r.pwEvent(e, status)
		}
	}
	if r.lock.unknown {
		inv.echo("")
		inv.echo(ui.Bold + "It could not be read whether a password change is required of your account." + ui.NC)
		inv.echo("Nothing runs here until it can be; each line tries again. 'passwd' changes the password, 'exit' leaves.")
		inv.echo("")
		event("unknown", 0)
		return false, 0
	}
	inv.echo("")
	inv.echo(ui.Bold + "A password change is required of your account." + ui.NC)
	inv.echo("No device accepts your login until it is changed, and nothing here runs until then but the change itself.")
	inv.echo("It starts now (Ctrl-C ends this session).")
	inv.echo("")
	event("required", 0)
	// the opening is held to the idle time (shell.Options.Idle): a dialog
	// nobody answers is ended when its deadline passes
	code := exec(execx.EndOnDeadline(ctx), []string{pwChangeWord}, r.tty)
	switch {
	case code == 0 && !r.lock.locked():
		event("done", 0)
		inv.echo("")
		inv.echo("Type 'help'. Devices: device list.")
		return false, 0
	case code == exitInterrupted:
		a.Out.Error("The password change was declined. The session ends; nothing else is available until the password is changed.")
		event("failed", code)
		return true, code
	}
	if code == 0 {
		// the change ran but the root side still requires one
		code = 1
	}
	a.Out.Error("The password was not changed. Type 'passwd' to try again, or 'exit' to leave; nothing else runs until it is changed.")
	event("failed", code)
	return false, 0
}

// exitInterrupted is the status of a command that Ctrl-C ended.
const exitInterrupted = 130

// lockRefusedLog is what the console writes for a line refused while locked:
// the first word when it is a verb of the tool or a word of the console
// (never a word that may be a password), else only the line's length.
func (cs *consoleSession) lockRefusedLog(isCommand func(string) bool) func(words []string) {
	return func(words []string) {
		first := ""
		if len(words) > 0 && (isCommand(words[0]) || words[0] == "help" || words[0] == "history" || words[0] == "exit" || words[0] == "quit" || words[0] == "system-shell") {
			first = words[0]
		}
		cs.log("auth.warning", cs.sess.PasswordChangeDenyLine(first, len(strings.Join(words, " "))))
	}
}
