package cli

// The one-shot local login (docs/plans/0.2.9-rollout-plan.md D136): '--login
// <local-user>' on 'device config pull|diff --pull|plan --pull' logs in to
// one registered Junos device as one of its local accounts instead of the
// invoking user, and 'device onboard' (device_onboard.go) does the same for
// a device that has no TACACS+ server yet.
//
// Where the local password goes: askpass.Prompt reads it on the terminal
// into a []byte (hooks.newLocalPasswords: a terminalPasswords with no cache
// client, so the cache is never asked, never stored into and never told to
// forget); a devssh.PasswordSource makes the string ssh takes from those
// bytes at the send (devssh's passwordMemo hands it over once per
// connection, and a pull's source refuses a second connection); Done zeroes
// the bytes. The promise ends at the string the ssh library holds.

import (
	"errors"
	"regexp"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/tier"
)

// rootCLICommand is the remote command of a root login (D136, lab L4):
// root's login shell on Junos is a csh, and this starts the Junos CLI on the
// channel, with or without a pseudo-terminal. Fixed text; nothing of the
// command line goes into it.
const rootCLICommand = "sh -c 'PATH=$PATH:/usr/sbin:/usr/bin:/sbin:/bin; exec cli'"

// reLocalAccount is a local account name a Junos device accepts: letters,
// digits, '.', '_' and '-', at most 64, starting with a letter or a digit.
var reLocalAccount = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// localLogin is one run's local account: its name and, once asked, the
// password's bytes (owned by the password source, zeroed at its Done).
type localLogin struct {
	account string

	mu     sync.Mutex
	secret []byte
	sent   bool
}

// root reports whether the account is root, whose CLI needs the wrapper.
func (l *localLogin) root() bool { return l.account == "root" }

// cliOptions are the options of every command-line session of the login:
// root's wrapper, nothing for any other account.
func (l *localLogin) cliOptions() []devssh.CLIOption {
	if l.root() {
		return []devssh.CLIOption{devssh.WithCommand(rootCLICommand)}
	}
	return nil
}

// errLocalSent is a second connection asking for a password that is sent
// once.
var errLocalSent = errors.New("the local password is sent once in this run")

// sendOnce is the password source of a pull: the string is made from the
// bytes at the one send, and any later request (a second connection) is
// refused.
func (l *localLogin) sendOnce() devssh.PasswordSource {
	return func() (string, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.sent || len(l.secret) == 0 {
			return "", errLocalSent
		}
		l.sent = true
		return string(l.secret), nil
	}
}

// eachConnection is the password source of an onboard, whose connections
// as the local account are the pre-flight, the transaction and the probe
// after it: the string is made from the bytes at each send.
func (l *localLogin) eachConnection() devssh.PasswordSource {
	return func() (string, error) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if len(l.secret) == 0 {
			return "", errLocalSent
		}
		return string(l.secret), nil
	}
}

// localAccountOf checks the value of --login.
func (inv *invocation) localAccountOf(v, usage string) (string, error) {
	if !reLocalAccount.MatchString(v) {
		return "", inv.argErr("--login takes the name of one of the device's local accounts (letters, digits, '.', '_' and '-'): '"+v+"'", usage)
	}
	return v, nil
}

// localLoginGate is the tier of --login (D141): the superuser's only, checked
// inside the Engineer verb before the selection, as 'forget' is; an engineer
// with the flag gets the tier denial, logged as every denial.
func (inv *invocation) localLoginGate(p Parsed, verb string) error {
	if !p.Has("--login") {
		return nil
	}
	return inv.deviceVerbAllowed("device config", verb+" --login", tier.Superuser)
}

// localLoginOf reads --login and the selection it allows: one device, by
// name. nil when the flag is not given. pull says whether the verb reads the
// device (a diff or a plan without --pull reads nothing: --login is refused).
func (inv *invocation) localLoginOf(p Parsed, verb string, sel selection, pull bool) (*localLogin, error) {
	if !p.Has("--login") {
		return nil, nil
	}
	usage := "Usage: tacctl device config " + deviceConfigUse(verb)
	acct, err := inv.localAccountOf(p.Value("--login"), usage)
	if err != nil {
		return nil, err
	}
	switch {
	case !pull:
		return nil, inv.argErr("--login is the account a read logs in as: give --pull with it.", usage)
	case sel.all || sel.stale || sel.scope != "" || sel.vendor != "" || len(sel.names) != 1:
		return nil, inv.argErr("--login logs in to one device as its local account: name one device (not --all, a selector such as --scope, --vendor, --stale, --differs, --name or --ip, or a list).", usage)
	case acct == "root" && p.Value("--transport") == transportNetconf:
		return nil, inv.argErr("--login root reads over the ssh command line (root's shell is a csh and the CLI is started by a wrapper): not with --transport netconf.", usage)
	}
	return &localLogin{account: acct}, nil
}

// localLoginDevice is the refusal of a device a local login may not read
// (D136): only a registered Junos device with a pinned host key that a scope
// answers, and root only on a device never pulled as the invoking user's own
// login. Nothing is asked or sent before it passes.
func (inv *invocation) localLoginDevice(l *localLogin, chosen *chosenDevices) error {
	if len(chosen.entries) != 1 {
		return inv.usageErr("--login logs in to one registered device.")
	}
	e := chosen.entries[0]
	switch {
	case e.Vendor != devssh.VendorJuniper:
		return inv.usageErr("--login is for Junos devices: '" + e.Name + "' is " + e.Vendor + ". Nothing was sent.")
	case len(e.HostKeys) == 0:
		return inv.usageErr("'"+e.Name+"' has no pinned host key, and a local password goes only to a device whose key was verified. Nothing was sent.",
			"Pin it after comparing it with the device console: tacctl device hostkey "+e.Name+" accept")
	}
	// a break-glass hold refuses a local login as it refuses every pull (the
	// hold's rule, D126)
	if _, held := inv.holdOf(e.Name, e.Address); held {
		return inv.usageErr(holdRefusal(e.Name) + ": release it first. Nothing was sent.")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if _, covered := m.LookupAddr(e.Address); !covered {
		return inv.usageErr("'" + e.Name + "' (" + dashAddrText(e.Address) + ") is answered by no scope: no scope's prefixes cover its address. Nothing was sent.")
	}
	if l.root() {
		// a record file that cannot be read is not 'never read as you'
		recs, err := inv.configStore().Load()
		if err != nil {
			return inv.usageErr(strings.Join(msgs(err), " ") + ": whether '" + e.Name + "' was read as your own login is not known, and --login root is only for a device that never was. Nothing was sent.")
		}
		if rec, ok := recs.Of(e.Name); ok && rec.PulledAsUser() {
			return inv.usageErr("--login root is for a device that was never read as your own login, and '"+e.Name+"' was. Nothing was sent.",
				"Read it as you (tacctl device config pull "+e.Name+"), or with --login as another local account.")
		}
	}
	return nil
}

// localLoginText is the record's and the audit line's word for the login.
func localLoginText(acct string) string { return devconf.LocalLoginPrefix + acct }
