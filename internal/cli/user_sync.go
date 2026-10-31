package cli

// The accounts after a user change (0.2.23, D313). A user verb that changes
// an account on this server (add, remove, rename, move, scope, enable,
// disable, require-password-change, and a reset that enables a disabled
// user) syncs this server's own accounts at once, when the server is
// enrolled (host enroll --local): the new user must log in here to change
// the password, and has no UID before the sync. It is the sync of 'host sync
// <this server>' (the accounts-only script, run locally), started after the
// store write, its snapshot and the restart of the service are done and the
// store's lock is let go, so it takes no snapshot of its own. The script's
// lines are held back: one INFO line says what was done, and what went
// wrong (a warning, an error of the script) is shown after it. A sync that
// fails is a WARN with the retry command; the store change stands and the
// verb exits 0.
//
// The other enrolled hosts the change reaches are told in one WARN with the
// command (noticeHosts); on a terminal the verb asks whether to sync them
// now, and with no terminal the notice is all. INFO says what was done (the
// store change, the restart, the sync); WARN says that something failed or
// that the operator has to act (a sync that failed, hosts left to sync, a
// lockout risk); a fact is said once.

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/ui"
)

// attLine is one line of a held-back output that a person has to see.
type attLine struct {
	stderr bool
	text   string
}

// attention are the lines of the buffer a person has to see: all of stderr,
// and the warnings the script prints on stdout. Its other lines (the INFO
// lines of the script, of the sync) are dropped: the verb says what was done
// in one line of its own. The lines are cut again from the writes, which may
// hold several.
func (b *hostBuf) attention() []attLine {
	b.mu.Lock()
	chunks := b.chunks
	b.chunks = nil
	b.mu.Unlock()
	var out []attLine
	var partial [2][]byte
	emit := func(stderr bool, line []byte) {
		if text := string(line); stderr || strings.Contains(text, "[WARN]") {
			out = append(out, attLine{stderr, text})
		}
	}
	for _, c := range chunks {
		i := 0
		if c.stderr {
			i = 1
		}
		partial[i] = append(partial[i], c.b...)
		for {
			n := bytes.IndexByte(partial[i], '\n')
			if n < 0 {
				break
			}
			emit(c.stderr, partial[i][:n])
			partial[i] = partial[i][n+1:]
		}
	}
	for i, p := range partial {
		if len(p) > 0 {
			emit(i == 1, p)
		}
	}
	return out
}

// replayAttention writes the lines of attention to o, as they were written.
func (b *hostBuf) replayAttention(o ui.Output) {
	for _, l := range b.attention() {
		w := o.Stdout
		if l.stderr {
			w = o.Stderr
		}
		_, _ = io.WriteString(w, l.text+"\n")
	}
}

// reLevel is the level word and the colour of a line of output.
var reLevel = regexp.MustCompile("\x1b\\[[0-9;]*m|^\\[(ERROR|WARN|INFO)\\] ")

// detailLines are the lines of attention as plain detail, two spaces in, with
// no level and no colour: what a failure says under the one warning of the
// verb.
func detailLines(ls []attLine) []string {
	var out []string
	for _, l := range ls {
		t := reLevel.ReplaceAllString(reLevel.ReplaceAllString(l.text, ""), "")
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, "  "+t)
		}
	}
	return out
}

// quietly runs fn with the invocation's output held in a buffer. The prompter
// is made first, so that its questions still reach the terminal.
func (inv *invocation) quietly(fn func() error) (*hostBuf, error) {
	a := inv.app
	a.Prompter()
	saved := a.Out
	buf := &hostBuf{}
	a.Out = buf.output()
	defer func() { a.Out = saved }()
	return buf, fn()
}

// syncOwnAccounts syncs this server's own accounts after the user verb that
// has just written the store: who are the users the verb concerns. It says
// nothing when this server is not enrolled. The error it returns is an
// interrupt only; a sync that fails is a warning.
func (inv *invocation) syncOwnAccounts(who ...string) error {
	a := inv.app
	e, ok, err := inv.localHost()
	if err == nil && !ok {
		return nil
	}
	if err != nil {
		a.Out.WarnE("The host registry cannot be read (" + msgsJoin(err) + "), so this server's accounts were not synced: tacctl host sync <name of this server>")
		return nil
	}
	retry := "tacctl host sync " + e.Name
	// the model the verb read before it wrote is not the one to sync from
	inv.loaded = false
	var he *hosts.Env
	var failed bool
	buf, err := inv.quietly(func() error {
		var err error
		he, failed, err = inv.syncLocalAccounts(e)
		return err
	})
	if errors.Is(err, ui.ErrInterrupted) {
		buf.replayAttention(a.Out)
		return err
	}
	if err != nil || failed {
		// one failure, one warning: what the script said is its detail
		reason := ""
		if err != nil {
			if r := msgsJoin(err); r != "" {
				reason = " (" + r + ")"
			}
		}
		a.Out.WarnE("This server's accounts were not synced" + reason + "; the change reaches them at the next sync: " + retry)
		for _, l := range detailLines(buf.attention()) {
			inv.echo(l)
		}
		return nil
	}
	a.Out.InfoE("This server's accounts were synced: " + ownSyncText(he, who, inv.userUID) + ".")
	buf.replayAttention(a.Out)
	if he != nil && he.Summary != nil && len(he.Summary.Refused) > 0 {
		a.Out.WarnE("The sync refused " + plurals(len(he.Summary.Refused), "account", "accounts") + " on this server (see above); fix the cause, then: " + retry)
	}
	return nil
}

// syncLocalAccounts is the sync of 'host sync <this server>' without the
// set-up of the server's own login scope (managedSetup), which writes the
// store and the registry with a snapshot of its own: the checks of the
// verb, the UID ledger, and the accounts-only run of the host (syncOne).
// failed says the sync did not succeed (it has said why); he holds the
// accounts the script reported.
func (inv *invocation) syncLocalAccounts(e hosts.Entry) (he *hosts.Env, failed bool, err error) {
	if err = inv.confReadable(); err != nil {
		return nil, true, nil
	}
	reg, err := inv.registry()
	if err != nil {
		return nil, false, err
	}
	if err = inv.hostHeldErr(e, "tacctl host sync "+e.Name); err != nil {
		return nil, true, nil
	}
	exists, err := inv.scopeExists(e.Scope)
	if err != nil {
		return nil, false, err
	}
	if !exists {
		inv.app.Out.ErrorE(e.Name + ": scope '" + e.Scope + "' no longer exists; skipped.")
		return nil, true, nil
	}
	if err = inv.renumberUIDs(true); err != nil {
		return nil, true, nil
	}
	st := inv.sequentialStep()
	he = inv.syncEnv(st)
	// the script's output is held back, so it is not given the terminal
	he.NoTerminal()
	ok, err := inv.syncOne(st, he, e, reg.Method(e.Name), []string{"--accounts-only"}, false)
	return he, !ok, err
}

// ownSyncText says what the sync did in counts: accounts created (with the
// UID, when the one account made is the verb's user), changed, renamed and
// removed. No other user is named.
func ownSyncText(he *hosts.Env, who []string, uid func(string) string) string {
	if he == nil || he.Changes == nil {
		return "no account changed"
	}
	c := he.Changes
	var parts []string
	if n := len(c.Created); n > 0 {
		t := strconv.Itoa(n) + " created"
		if n == 1 && contains(who, c.Created[0]) {
			if u := uid(c.Created[0]); u != "-" {
				t += " (UID " + u + ")"
			}
		}
		parts = append(parts, t)
	}
	if n := len(c.Updated) - len(c.Renamed); n > 0 {
		parts = append(parts, strconv.Itoa(n)+" updated")
	}
	if n := len(c.Renamed); n > 0 {
		parts = append(parts, strconv.Itoa(n)+" renamed")
	}
	if n := len(c.Removed); n > 0 {
		parts = append(parts, strconv.Itoa(n)+" removed")
	}
	if len(parts) == 0 {
		return "no account changed"
	}
	return strings.Join(parts, ", ")
}

// otherHostsWith are the enrolled hosts but this server whose account of one
// of names the change alters: the row of the user as the host sees it (an
// active row, an expired account, none; linuxAccounts with the held users of
// a host that is not this server) differs between the model before the change
// and the model after it. Those are the hosts a change of those users reaches
// at their next sync. before is nil when the model could not be read before
// the change. A name that is no Linux account name and the accounting sink
// have no account on any host.
func (inv *invocation) otherHostsWith(before *model.Model, names ...string) []hosts.Entry {
	reg, err := inv.registry()
	if err != nil || len(names) == 0 {
		return nil
	}
	after, err := inv.app.LoadModel()
	if err != nil {
		return nil
	}
	c := inv.app.Conf()
	var out []hosts.Entry
	for _, e := range reg.Entries() {
		if e.Target == hosts.Local {
			continue
		}
		for _, name := range names {
			if !hosts.LinuxName(name) || accountingSink(before, name) || accountingSink(after, name) {
				continue
			}
			if accountRow(c, before, e.Scope, name) != accountRow(c, after, e.Scope, name) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// accountingSink reports whether name is the accounting sink in m (nil: no).
func accountingSink(m *model.Model, name string) bool {
	if m == nil {
		return false
	}
	u := m.User(name)
	return u != nil && u.AccountingSink
}

// accountRow is how a host enrolled in scope sees the user name in the model m:
// its linux-users row (name and priv-lvl), "expired" for an account the sync
// expires (disabled, or held to a password change), "" for none. A nil model
// gives "".
func accountRow(c *conf.Config, m *model.Model, scope, name string) string {
	if m == nil {
		return ""
	}
	held := pwchange.HostHeld(c, m, false)
	for _, r := range m.LinuxUsersHeld(scope, held) {
		if n, _, _ := strings.Cut(r, "|"); n == name {
			return r
		}
	}
	for _, n := range m.LinuxInactiveHeld(scope, held) {
		if n == name {
			return "expired"
		}
	}
	return ""
}

// hostsSyncCommand is the command that syncs es: their names, or --all when
// they are many.
func hostsSyncCommand(es []hosts.Entry) string {
	if len(es) > 4 {
		return "tacctl host sync --all"
	}
	return "tacctl host sync " + strings.Join(hostNames(es), " ")
}

// hostNames are the names of the registry entries es.
func hostNames(es []hosts.Entry) []string {
	names := make([]string, len(es))
	for i, e := range es {
		names[i] = e.Name
	}
	return names
}

// noticeHosts is the one notice of the enrolled hosts a change reaches: what
// their next sync does (cause is that, given the count of the hosts in words,
// "2 enrolled hosts"), and the command. It is a warning, as the hosts are left
// as they were until someone syncs them. With offer, the caller is a person
// who can sync them: a terminal is asked whether to sync them now (the answer
// is never taken from --yes or any option; with no terminal the notice is
// all). Without it (a user's own password change) the notice is information.
// The error it returns is an interrupt only.
func (inv *invocation) noticeHosts(es []hosts.Entry, cause func(hostsText string) string, offer bool) error {
	if len(es) == 0 {
		return nil
	}
	a := inv.app
	cmd := hostsSyncCommand(es)
	if !offer {
		a.Out.InfoE(cause(hostsText(len(es))) + ": " + cmd)
		return nil
	}
	a.Out.WarnE(cause(hostsText(len(es))) + ": " + cmd)
	if !a.Prompter().Interactive() || !a.Prompter().Confirm("  Sync these hosts now? [y/N]: ") {
		return nil
	}
	// The sync of these hosts shows its own output, as 'host sync' does: a
	// host's ssh or sudo may ask for a password on this terminal.
	err := inv.hostSync(hostNames(es))
	if errors.Is(err, ui.ErrInterrupted) {
		return err
	}
	if err != nil {
		reason := "see above"
		if r := msgsJoin(err); r != "" && !isExit(err) {
			reason = r
		}
		a.Out.WarnE("Not every host was synced (" + reason + "): " + cmd)
		return nil
	}
	synced := " was synced."
	if len(es) > 1 {
		synced = " were synced."
	}
	a.Out.InfoE(hostsText(len(es)) + synced)
	return nil
}

// afterUserChange ends a user verb that has written the store: this server's
// accounts are synced at once, then the other hosts the change reaches are
// told (and offered), cause saying what their next sync does. before is the
// model before the write; who the users the verb concerns, the ones the hosts
// are looked up for. The blank line that ends the output of the verb is
// printed here.
func (inv *invocation) afterUserChange(before *model.Model, who []string, cause func(string) string) error {
	if err := inv.syncOwnAccounts(who...); err != nil {
		return err
	}
	err := inv.noticeHosts(inv.otherHostsWith(before, who...), cause, true)
	inv.echo("")
	return err
}
