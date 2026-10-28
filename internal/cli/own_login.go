package cli

// This machine's own login, set up by 'tacctl install' and 'tacctl upgrade'
// (0.2.21). The managed server login (managed_scope.go: the scope tacctl
// manages, this server's registry entry, the PAM and sshd client setup and
// the accounts) is what 'host enroll --local' and 'host sync' make; install
// and upgrade make it too, so that every user can log in to the server and
// its console without a command of its own. 'host enroll --local' stays the
// way to rebuild, move or repair a server.
//
// The setup is the enrolment's (hostEnroll, with every safeguard of it: the
// client script checks sshd with 'sshd -t' before it reloads and undoes the
// change, local administrators and root are not touched, the PAM files are
// backed up), not a copy of it. This file decides whether it is needed and
// whether the operator agrees; it never fails the command that called it:
// what cannot be done is one line, with the command to run, and nothing is
// half applied.
//
//   - a server with no registry entry is set up when the operator agrees
//     (install -y; a question otherwise, which an upgrade asks only on a
//     terminal);
//   - an entry that is not in the managed scope, or whose scope, secret,
//     address or PAM files are gone (a rebuilt server), is set up again by
//     the enrolment, with no question: the server was enrolled before;
//   - a managed scope whose prefixes drifted is repaired (managedSetup, 'Repaired
//     the managed server login.');
//   - a healthy setup prints nothing.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
)

// ownLoginCommand is the command that sets up this machine's own login.
const ownLoginCommand = "tacctl host enroll --local"

// ownLoginNeed is what a server's own login needs.
type ownLoginNeed int

const (
	// ownLoginHealthy: nothing.
	ownLoginHealthy ownLoginNeed = iota
	// ownLoginRecord: only the setting server.addresses is missing.
	ownLoginRecord
	// ownLoginRepair: the managed scope's prefixes drifted.
	ownLoginRepair
	// ownLoginSetup: the enrolment sets it up (again).
	ownLoginSetup
)

// pamFilesPresent reports whether the PAM files the client script writes are
// all there.
func (inv *invocation) pamFilesPresent() bool {
	for _, f := range hosts.PAMFiles {
		if st, err := os.Stat(filepath.Join(inv.app.Paths.PAMDir, f)); err != nil || !st.Mode().IsRegular() {
			return false
		}
	}
	return true
}

// ownLoginNeeds is what this server's own login needs, given the registry's
// entry of the server (cur, when have) and the server address it should use.
func (inv *invocation) ownLoginNeeds(reg *hosts.Registry, cur hosts.Entry, have bool, addr string) (ownLoginNeed, error) {
	if !have || cur.Scope != pwchange.ManagedScope {
		return ownLoginSetup, nil
	}
	m, err := inv.model()
	if err != nil {
		return ownLoginSetup, err
	}
	sc := m.Scope(pwchange.ManagedScope)
	if sc == nil || !inv.secretUsable(sc.Secret) || canonAddr(cur.Server) != addr || !inv.pamFilesPresent() {
		return ownLoginSetup, nil
	}
	if !equalStrings(canonList(sc.Prefixes), pwchange.Server{Scope: pwchange.ManagedScope, Address: addr}.Prefixes()) {
		return ownLoginRepair, nil
	}
	if inv.app.Conf().ServerAddress() != addr {
		return ownLoginRecord, nil
	}
	return ownLoginHealthy, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// terminal reports whether a terminal can answer a question.
func (inv *invocation) terminal() bool {
	if inv.app.HostsTTY != nil {
		return inv.app.HostsTTY()
	}
	return inv.app.Prompter().Interactive()
}

// quiet runs fn with the error lines it prints held back, and returns them
// as one text ("" when there are none): a step of the setup that is refused
// is one line of the setup's own, not a failure of the command.
func (inv *invocation) quiet(fn func() error) (string, error) {
	a := inv.app
	var buf bytes.Buffer
	real := a.Out.Stderr
	a.Out.Stderr = &buf
	err := fn()
	a.Out.Stderr = real
	var lines []string
	for _, l := range strings.Split(strings.TrimRight(buf.String(), "\n"), "\n") {
		if l = strings.TrimSuffix(strings.TrimPrefix(stripColour(l), "[ERROR] "), " Nothing was changed."); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) == 0 && err != nil {
		var ee *ExitError
		if !errors.As(err, &ee) || ee.Err != nil {
			lines = msgs(err)
		}
	}
	return strings.Join(lines, " "), err
}

// ownLoginSkipped says, in one line, what was left undone and the command
// that does it. warn: something failed (a warning); else the operator's own
// choice, or a run that could not ask.
func (inv *invocation) ownLoginSkipped(warn bool, why, command string) {
	line := "This machine's own login was not set up (" + why + "); to set it up: " + command
	if warn {
		inv.app.Out.WarnE(line)
		return
	}
	inv.app.Out.InfoE(line)
}

// ownLogin is install's and upgrade's setup of this machine's own login
// (lifecycle.Host.OwnLogin). It never returns an error.
func (inv *invocation) ownLogin(_ context.Context, o lifecycle.OwnLoginOptions) {
	a := inv.app
	command := ownLoginCommand
	if o.Server != "" {
		command += " --server " + o.Server
	}
	// skip says what was left undone: why is what the step printed (held
	// back by quiet), else the error's own words.
	skip := func(why string, err error) {
		if why == "" && err != nil {
			why = strings.Join(msgs(err), " ")
		}
		inv.ownLoginSkipped(true, why, command)
	}
	if model.Mode(a.Paths.StoreFile) != "store" {
		inv.ownLoginSkipped(true, "this install has no store: it runs in legacy read-only mode", command)
		return
	}
	reg, err := inv.registry()
	if err != nil {
		skip("", err)
		return
	}
	cur, have := inv.localEntryOf(reg)
	if !have && !o.Yes && !o.Install && !inv.terminal() {
		// no entry, and nobody to ask: said before an address is detected
		inv.ownLoginSkipped(false, "an upgrade does not ask without a terminal", command)
		return
	}
	// The server address: the one given, else the recorded one, else the
	// detected one (said in one line, every time).
	var addr string
	if why, err := inv.quiet(func() (err error) { addr, err = inv.localServerAddress(reg, o.Server); return }); err != nil {
		skip(why, err)
		return
	}
	need, err := inv.ownLoginNeeds(reg, cur, have, addr)
	if err != nil {
		skip("", err)
		return
	}
	switch need {
	case ownLoginHealthy:
		return
	case ownLoginRecord:
		if err := inv.recordServerAddress(addr); err != nil {
			skip("", err)
			return
		}
		a.Out.InfoE("The server address " + addr + " is recorded in tacctl.yaml (server.addresses).")
		return
	case ownLoginRepair:
		if why, err := inv.quiet(inv.snapshotFirst); err != nil {
			skip(why, err)
			return
		}
		if why, err := inv.quiet(func() error { _, err := inv.managedSetup(reg, addr, false); return err }); err != nil {
			skip(why, err)
			return
		}
		if err := inv.recordServerAddress(addr); err != nil {
			skip("", err)
		}
		return
	}

	// The enrolment: with no entry of the server's yet, the operator agrees.
	if !have {
		switch {
		case o.Yes:
		default:
			inv.echo("This makes every tacctl user able to log in to this server and its console: it installs the")
			inv.echo("PAM client and sshd's drop-in here (sshd is checked first and the change undone if it refuses")
			inv.echo("it; root and the local administrators are left as they are).")
			if !a.Prompter().Confirm("Set up this machine's own login now, with " + addr + " as the server address? [y/N]: ") {
				inv.ownLoginSkipped(false, "not asked for", command)
				return
			}
		}
	}
	if why, err := inv.quiet(inv.snapshotFirst); err != nil {
		skip(why, err)
		return
	}
	method := ""
	if have {
		method = reg.Method(cur.Name)
	}
	if method == "" {
		method = inv.linuxDefaultMethod()
	}
	// pam_tacplus is built from the source tarball the enrolment embeds.
	if he := inv.hostsEnv(); method == hosts.Tacplus && !isRegularFile(he.Paths.Tarball()) {
		if err := he.BuildTarball(inv.ctx); err != nil {
			inv.reportOnly(inv.hostsDone(err))
			skip("the pam_tacplus source could not be prepared, see above", nil)
			return
		}
	}
	args := []string{"--local", "--server", addr}
	if have {
		args = append(args, "--name", cur.Name)
	}
	if err := inv.hostEnroll(args); err != nil {
		inv.reportOnly(err)
		skip("the enrolment stopped, see above; nothing is half applied", nil)
	}
}
