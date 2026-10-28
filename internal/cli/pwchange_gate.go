package cli

// The command line's half of a required password change (0.2.20). A caller
// who must change the password, and is no superuser, runs nothing but the
// change itself: every command but 'passwd', 'version' and 'help' is refused
// with one message and exit status 1. This covers what the login console does
// not reach (a plain shell, 'ssh <server> tacctl ...', a script); the console
// opens with the dialog and refuses the other words itself (console_mode.go).
// A superuser is never affected, and neither is root or a local administrator
// who is no tacctl user (the unrestricted tier): the requirement is the one
// pwchange.Subject decides, from the group's tier, each time.
//
// 'tacctl shell' and the words that run as the invoking user without sudo
// (hash, completion) have no caller to look at; the shell runs every line it
// executes as 'sudo tacctl <line>', which meets this gate.

import (
	"strings"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/tier"
)

// pwChangeWords are the first words that run while a password change is
// required: the change itself, the version and the help, and the policy line
// the login console asks for first (_console-policy), which is how the console
// learns the requirement.
var pwChangeWords = map[string]bool{
	"passwd": true, "version": true, "--version": true, "-v": true,
	"help": true, "-h": true, "--help": true, "": true,
	"_console-policy": true,
}

// passwordChangeGate refuses the command when the caller must change the
// password: after the tier gate, so that a caller the gate refuses is refused
// by it, and before anything is read or written.
func (inv *invocation) passwordChangeGate() error {
	a := inv.app
	user := a.Env.Get("SUDO_USER")
	if user == "" || user == "root" {
		return nil
	}
	// Only a tier-managed caller is held (the gate gave it a tier): a local
	// administrator with the name of a tacctl user is not that user.
	if inv.callerTier == "" || inv.callerTier == tier.Unrestricted {
		return nil
	}
	if len(a.Args) == 0 || pwChangeWords[a.Args[0]] {
		return nil
	}
	// Three answers: held, not held, and unknown (the store cannot be read,
	// so the group, and with it the tier, is not known). Unknown fails closed
	// for a caller who is not known to be a superuser; a superuser is known by
	// the tier the gate gave (an unreadable store gives every managed caller
	// the tier none, so the gate has refused it already) and is never held.
	unknown := false
	m, err := inv.model()
	if err != nil || m == nil {
		if inv.callerTier == tier.Superuser {
			return nil
		}
		unknown = true
	} else if !pwchange.Subject(a.Conf(), m, m.User(user)) {
		return nil
	}
	// The live names a Tab press asks for in a plain shell are no command of
	// the person's: a held caller's shell offers nothing from them, and a
	// refusal per key press would fill the audit log with denials nobody
	// made. They are refused (no names) without a message or a line.
	if a.Args[0] == "_completion-names" {
		return exit(1)
	}
	// the words the tier gate sees, never the arguments after them
	words := a.Args[0]
	if len(a.Args) > 1 && !strings.HasPrefix(a.Args[1], "-") {
		words += " " + a.Args[1]
	}
	pairs := []audit.KV{audit.Pair("user", user), audit.Pair("tier", string(inv.callerTier)), audit.Pair("cmd", words)}
	if unknown {
		pairs = append(pairs, audit.Pair("state", "unknown"))
		a.Audit().Line(audit.Warning, "password-change DENY", pairs...)
		return inv.usageErr("The store cannot be read, so it cannot be told whether a password change is required of '" + user + "': no command runs until it can be but 'tacctl passwd' (and 'version' and 'help').")
	}
	a.Audit().Line(audit.Warning, "password-change DENY", pairs...)
	return inv.usageErr("A password change is required of '" + user + "': no command runs until it is done but 'tacctl passwd' (and 'version' and 'help'), and no device accepts the login until then. Run: tacctl passwd")
}
