package cli

import (
	"io"
	"os"
	"time"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
)

// hooks are the places where a test of this package replaces something the
// process or the machine provides: a dial, a prompt, a terminal check, a
// look-up of the account database. They are fields of the invocation, never
// package variables, so tests that configure different ones run side by side
// in one process.
//
// The zero value, and a nil *hooks (tacctl itself: Run passes none), mean
// the real thing for every field; each method below answers the real one
// when its field is unset.
type hooks struct {
	// interruptSource is the source of the operator's interrupts instead of
	// the process's signals: the channel each Ctrl-C arrives on, so a test
	// delivers them without a signal that any other code of the process
	// could see.
	interruptSource func() <-chan struct{}
	// deviceDial replaces the TCP dial of every device (the in-process fake
	// device); nil dials the device's own address.
	deviceDial devssh.Dialer
	// devicePasswords is the source of the invocation's device password.
	devicePasswords func(inv *invocation) devicePasswords
	// localPasswords is the source of a local account's password.
	localPasswords func(inv *invocation, account, where string) *terminalPasswords
	// passwordPrompt reads a line from a terminal without echo.
	passwordPrompt func(tty *os.File, prompt string) ([]byte, error)
	// factsTimeout bounds the fact commands of a pull (0: 15 seconds).
	factsTimeout time.Duration
	// keyFallback is the host-key scan of a legacy-ssh device that
	// ssh-keyscan read nothing from.
	keyFallback func(inv *invocation) devreg.KeyFallback
	// applyHoldWait is how long --hold waits for the word.
	applyHoldWait func(until, now time.Time) time.Duration
	// applyRecordFault is asked before each apply record is written; a
	// non-nil answer is the write's failure.
	applyRecordFault func(device string, a devconf.Applied) error
	// hostRenameStep is called by 'host rename' after each step that changed
	// something ("registry", "pins"); a test changes the world at that point.
	hostRenameStep func(step string)
	// applyPullDone is called by 'device config apply --pull' and 'device
	// enroll' when the pull has ended and before its outcome is read; a test
	// interrupts the run, or changes the world, at that point.
	applyPullDone func()
	// applyReviewed is called by 'device config apply' when the review has
	// been answered and before Phase B's interrupts are taken; a test
	// interrupts the run at that point.
	applyReviewed func()
	// deviceWriteStep is called by every write of the device registry after
	// it was checked on a copy and before the lock is taken; a test changes
	// the world at that point.
	deviceWriteStep func()
	// isTerminalWriter reports whether a stream is a terminal.
	isTerminalWriter func(w io.Writer) bool
	// editEuid is the identity this process has.
	editEuid func() int
	// sshAccountOf looks an account up in the local account database.
	sshAccountOf func(name string) (sshAccount, error)
	// sshTerminal reports whether stdin is a terminal.
	sshTerminal func(r io.Reader) bool
	// sshConfigServer names this machine in the client-config fragment.
	sshConfigServer func() string
	// newAskpassAgent makes the password cache's agent.
	newAskpassAgent func(askpass.Options) (*askpass.Agent, error)
	// setNotDumpable marks the process not dumpable.
	setNotDumpable func() error
	// consolePolicy adjusts the policy a console session got.
	consolePolicy func(*console.Remote)
	// terminalLine names the terminal this command runs on ("pts/3").
	terminalLine func() string
	// probeDial is the dialer of every port probe.
	probeDial devreg.Dialer
	// utmpFile is the login-records file ("": the system's).
	utmpFile string
	// askpassFromApp makes the password cache's value the app's
	// environment alone: nothing is read from or removed from the process's
	// own (a test runs beside others in one process).
	askpassFromApp bool
}

// interrupts is the test's source of interrupts, or nil.
func (h *hooks) interrupts() func() <-chan struct{} {
	if h == nil {
		return nil
	}
	return h.interruptSource
}

// pullDone is the test's call at the end of the pull of 'apply --pull'.
func (h *hooks) pullDone() {
	if h != nil && h.applyPullDone != nil {
		h.applyPullDone()
	}
}

// reviewed is the test's call after the review of 'apply'.
func (h *hooks) reviewed() {
	if h != nil && h.applyReviewed != nil {
		h.applyReviewed()
	}
}

// dialer is the test's device dial, or nil.
func (h *hooks) dialer() devssh.Dialer {
	if h == nil {
		return nil
	}
	return h.deviceDial
}

// newDevicePasswords is the source of the invocation's device password: the
// terminal and the session's cache, unless a test replaced it. The process is
// marked not dumpable first (a password it prompted for will live in its
// memory) and the session's password cache variable is read, once, and taken
// out of the environment (password_cache.go).
func (h *hooks) newDevicePasswords(inv *invocation) devicePasswords {
	if h != nil && h.devicePasswords != nil {
		return h.devicePasswords(inv)
	}
	_ = h.markNotDumpable()
	return &terminalPasswords{inv: inv, client: inv.takeAskpass()}
}

// newLocalPasswords is the source of a local account's password ('--login',
// 'device onboard', D136): the terminal only, with no password cache client,
// so nothing is ever asked of the cache, stored in it or forgotten by it.
// account is the device's local account and where the device it is asked
// for.
func (h *hooks) newLocalPasswords(inv *invocation, account, where string) *terminalPasswords {
	if h != nil && h.localPasswords != nil {
		return h.localPasswords(inv, account, where)
	}
	_ = h.markNotDumpable()
	return &terminalPasswords{inv: inv, local: account, where: where}
}

// markNotDumpable marks the process not dumpable.
func (h *hooks) markNotDumpable() error {
	if h != nil && h.setNotDumpable != nil {
		return h.setNotDumpable()
	}
	return askpass.MarkNotDumpable()
}

// prompt reads a line from a terminal without echo.
func (h *hooks) prompt(tty *os.File, prompt string) ([]byte, error) {
	if h != nil && h.passwordPrompt != nil {
		return h.passwordPrompt(tty, prompt)
	}
	return askpass.Prompt(tty, prompt)
}

// factsLimit bounds the fact commands of a pull (all of them together): a
// device that stalls on one costs the pull this much more, never the rest of
// its timeout, and the pull is recorded with the facts it has.
func (h *hooks) factsLimit() time.Duration {
	if h != nil && h.factsTimeout > 0 {
		return h.factsTimeout
	}
	return 15 * time.Second
}

// scanFallback is the host-key fallback the verbs use.
func (h *hooks) scanFallback(inv *invocation) devreg.KeyFallback {
	if h != nil && h.keyFallback != nil {
		return h.keyFallback(inv)
	}
	return realKeyFallback(inv)
}

// holdWait is how long --hold waits for the word: until a minute of the
// window is left (DefaultMinWindow), and at least a second.
func (h *hooks) holdWait(until, now time.Time) time.Duration {
	if h != nil && h.applyHoldWait != nil {
		return h.applyHoldWait(until, now)
	}
	return realHoldWait(until, now)
}

// recordFault is the failure a test asks for before an apply record is
// written, or nil.
func (h *hooks) recordFault(device string, a devconf.Applied) error {
	if h != nil && h.applyRecordFault != nil {
		return h.applyRecordFault(device, a)
	}
	return nil
}

// renameStep tells the test that 'host rename' has finished a step.
func (h *hooks) renameStep(step string) {
	if h != nil && h.hostRenameStep != nil {
		h.hostRenameStep(step)
	}
}

// deviceStep tells the test that a write of the device registry is about
// to take its lock.
func (h *hooks) deviceStep() {
	if h != nil && h.deviceWriteStep != nil {
		h.deviceWriteStep()
	}
}

// terminalWriter reports whether w is a terminal; a stream with its colour
// taken out (app.New) is the terminal it wraps.
func (h *hooks) terminalWriter(w io.Writer) bool {
	if h != nil && h.isTerminalWriter != nil {
		return h.isTerminalWriter(w)
	}
	return realTerminalWriter(w)
}

// euid is the identity this process has.
func (h *hooks) euid() int {
	if h != nil && h.editEuid != nil {
		return h.editEuid()
	}
	return os.Geteuid()
}

// account looks the caller up in the local account database, with the
// supplementary groups.
func (h *hooks) account(name string) (sshAccount, error) {
	if h != nil && h.sshAccountOf != nil {
		return h.sshAccountOf(name)
	}
	return lookupAccount(name)
}

// terminalIn reports whether stdin is a terminal.
func (h *hooks) terminalIn(r io.Reader) bool {
	if h != nil && h.sshTerminal != nil {
		return h.sshTerminal(r)
	}
	return realTerminalIn(r)
}

// serverName names this machine in the client-config fragment's header line.
func (h *hooks) serverName() string {
	if h != nil && h.sshConfigServer != nil {
		return h.sshConfigServer()
	}
	if name, err := os.Hostname(); err == nil && name != "" {
		return name
	}
	return "this server"
}

// agent makes the password cache's agent.
func (h *hooks) agent(o askpass.Options) (*askpass.Agent, error) {
	if h != nil && h.newAskpassAgent != nil {
		return h.newAskpassAgent(o)
	}
	return askpass.New(o)
}

// adjustConsolePolicy lets a test adjust the policy a session got.
func (h *hooks) adjustConsolePolicy(p *console.Remote) {
	if h != nil && h.consolePolicy != nil {
		h.consolePolicy(p)
	}
}

// line is the name of the terminal this command runs on, as the login record
// names it ("pts/3"), or "" without one.
func (h *hooks) line() string {
	if h != nil && h.terminalLine != nil {
		return h.terminalLine()
	}
	return realTerminalLine()
}

// probe is the dialer of the port probes (nil: a net.Dialer).
func (h *hooks) probe() devreg.Dialer {
	if h == nil {
		return nil
	}
	return h.probeDial
}

// loginRecords is the login-records file ("": the system's).
func (h *hooks) loginRecords() string {
	if h == nil {
		return ""
	}
	return h.utmpFile
}
