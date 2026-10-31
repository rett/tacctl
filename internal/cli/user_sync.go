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

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
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
