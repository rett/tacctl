package cli

// 'device onboard <address> --login <local-user>' (docs/plans/0.2.9-rollout-
// plan.md D136, D141): a blank Junos device, reached with one of its local
// accounts, is identified, registered through 'device add', read, planned by
// the ordinary planner and, after the one review, committed under a confirmed
// commit as the local account; every session after the commit is the
// invoking user's own TACACS+ login, which proves the change before it is
// confirmed in the held local session. The steps, in order:
//
//  1. identity: the host keys are scanned and shown, and ONE question is
//     asked before any login (or --host-key names the key);
//  2. pre-flight as the local account: show version, no pending commit, no
//     TACACS+ or RADIUS server already, a class that may commit;
//  3. the name and the registration ('device add', the keys of step 1), the
//     device's own location and description in the empty fields (never its
//     host name: the registry's hostname is what ssh dials);
//  4. the pull as the local account (the record says login=local:<account>);
//  5. the plan and 6. the check (the transaction driver, as the local
//     account); --check stops there;
//  7. the review, then the user's own TACACS+ password;
//  8. the commit as the local account, proven by a fresh TACACS+ login (its
//     'Current user' the rendered template user of the invoking user's
//     group, with that class) and confirmed in the held local session (a
//     refused or wrong fresh login rolls the change back and leaves the local
//     account as it was);
//  9. the local account is never probed afterwards, root included: a login
//     would send its password to the TACACS+ server.
//
// The local password: device_config_login.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rett/tacctl/internal/askpass"
	"github.com/rett/tacctl/internal/devapply"
	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devconf/batch"
	"github.com/rett/tacctl/internal/devconf/plan"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// onboardUse is the usage line of the verb.
const onboardUse = "Usage: tacctl device onboard <address> --login <local-user> [--name <name>] [--host-key SHA256:<fp>] [--legacy-ssh] [--check] [--section <list>] [--json]"

// onboard is one run.
type onboard struct {
	inv  *invocation
	user string
	pr   *ui.Prompter

	addr, name, hostKey string
	check, asJSON       bool
	legacy              bool
	sections            []string
	local               *localLogin
	src                 *terminalPasswords

	scope string
	// template and class are the rendered template user of the invoking
	// user's group and its class: what the fresh login after the commit
	// must report (never a local account of the person's own name).
	template, class string
	// reported is the host name the device reported in the pre-flight, a
	// name the transaction's identity check accepts beside the registry's.
	reported string
	// reuse is the registered device an earlier onboard left (never read as
	// the user's own login), nil for a new one.
	reuse *devreg.Entry
	port  int
	// keys are the host keys the local login dials with: the trusted scan
	// (a new device) or the pinned ones (reuse).
	keys []devreg.HostKey

	entry devreg.Entry
	// out is the final row; probe is the machine word of the local account's
	// probe after the commit (probeNotProbed).
	out   *applyOutcome
	probe string
}

// deviceOnboard is 'device onboard'.
func (inv *invocation) deviceOnboard(args []string) error {
	p, err := Parse(deviceSpecs["onboard"], args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.argErr(msg, onboardUse)
	}
	if err := inv.deviceVerbAllowed("device", "onboard", tier.Superuser); err != nil {
		return err
	}
	user, err := inv.configLogin("device onboard")
	if err != nil {
		return err
	}
	ob := &onboard{inv: inv, user: user, pr: inv.app.Prompter(), name: p.Value("--name"), hostKey: p.Value("--host-key"),
		check: p.Has("--check"), asJSON: p.Has("--json"), legacy: p.Has("--legacy-ssh")}
	if err := ob.args(p); err != nil {
		return err
	}
	saved := inv.app.Out.Stdout
	if ob.asJSON {
		// the progress goes to standard error, the object to standard output
		inv.app.Out.Stdout = inv.app.Out.Stderr
	}
	code, err := ob.run()
	inv.app.Out.Stdout = saved
	if ob.src != nil {
		ob.src.Done()
	}
	ob.local.mu.Lock()
	ob.local.secret = nil
	ob.local.mu.Unlock()
	if err != nil {
		ob.audit("refused")
		return err
	}
	ob.audit(ob.word())
	if ob.asJSON {
		ob.printJSON(code)
	}
	if code != 0 {
		return exit(code)
	}
	return nil
}

// args checks what needs no device and no registry (exit 2).
func (ob *onboard) args(p Parsed) error {
	inv := ob.inv
	addr, err := devreg.NormalizeAddress(p.Args[0])
	if err != nil {
		return inv.argErr(strings.Join(msgs(err), " "), onboardUse)
	}
	ob.addr = addr
	if !p.Has("--login") {
		return inv.argErr("--login <local-user> names the device's local account onboard logs in as (a blank device has no other login).", onboardUse)
	}
	acct, err := inv.localAccountOf(p.Value("--login"), onboardUse)
	if err != nil {
		return err
	}
	if strings.EqualFold(acct, ob.user) {
		return inv.argErr("--login names a local account, and '"+acct+"' is your own login: the TACACS+ login that proves the change could be that account's. Nothing was sent.", onboardUse)
	}
	ob.local = &localLogin{account: acct}
	if p.Has("--host-key") && !devreg.ValidFingerprint(ob.hostKey) {
		return inv.argErr("Invalid --host-key '"+ob.hostKey+"': expected SHA256:<fingerprint> as ssh prints it.", onboardUse)
	}
	if p.Has("--name") {
		if err := devreg.ValidateName(ob.name); err != nil {
			return inv.argErr(strings.Join(msgs(err), " "), onboardUse)
		}
	}
	if p.Has("--section") {
		for _, s := range strings.Split(p.Value("--section"), ",") {
			s = strings.TrimSpace(s)
			if !contains(planSections, s) {
				return inv.argErr("--section takes sections of "+strings.Join(planSections, ", ")+": '"+s+"'", onboardUse)
			}
			if !contains(ob.sections, s) {
				ob.sections = append(ob.sections, s)
			}
		}
		if !contains(ob.sections, "aaa") {
			return inv.argErr("--section must include aaa: onboard proves the change by a TACACS+ login, which only the aaa section sets up. Nothing was sent.", onboardUse)
		}
	}
	// The identity question and the review are a person's: without a
	// terminal --host-key names the key, and only --check (which commits
	// nothing) runs.
	switch {
	case !ob.pr.Interactive() && ob.hostKey == "":
		return inv.argErr("No terminal to answer the identity question on: a blank device's keys are trusted by a person. "+
			"Give --host-key SHA256:<fp> (the fingerprint read on the device's console). Nothing was sent.", onboardUse)
	case !ob.pr.Interactive() && !ob.check:
		return inv.argErr("No terminal to review the change on: it is answered by typing the device's name back. "+
			"Without a terminal only --check runs (it registers and checks, and commits nothing). Nothing was sent.", onboardUse)
	}
	return nil
}

// run is the whole onboard; the code is the exit status (an error is a
// refusal before any change, already printed).
func (ob *onboard) run() (int, error) {
	inv := ob.inv
	if err := ob.admissible(); err != nil {
		return 0, err
	}

	// 1. Identity.
	if err := ob.identity(); err != nil {
		return 0, err
	}
	// 2. The local account's password, then the pre-flight. From the dial to
	// the end of the check a Ctrl-C cancels (nothing is committed before the
	// review), within twice the per-device timeout of a pull.
	ob.src = inv.hooks.newLocalPasswords(inv, ob.local.account, ob.addr)
	pw, err := ob.src.Password(inv.ctx, ob.local.account)
	if err != nil {
		return 0, err
	}
	ob.local.mu.Lock()
	ob.local.secret = pw
	ob.local.mu.Unlock()
	ctx, stop := ob.interruptible(false, 2*inv.deviceConfigSettings().timeout)
	defer stop()
	j, id, raw, err := ob.preflight(ctx)
	if err != nil {
		return 0, err
	}
	closeJ := true
	defer func() {
		if closeJ {
			_ = j.Close()
		}
	}()

	// 3. The name and the registration.
	if err := ob.register(id, raw); err != nil {
		return 0, err
	}
	e := ob.entry
	render := inv.newManagedRender(managedOptions{}, inv.callerScopes().restricted)
	render.prepare([]devreg.Entry{e})
	expected, err := render.Expected(e)
	if err != nil {
		return 0, inv.usageErr("Registered "+e.Name+", but its configuration cannot be rendered: "+strings.Join(msgs(err), " "), "Nothing was sent to the device.")
	}
	if !ob.check {
		if err := ob.templateOf(expected); err != nil {
			return 0, err
		}
	}
	confirm, _ := inv.applySettings()
	ar := &applyRun{inv: inv, user: ob.user, render: render, store: inv.configStore(),
		shapes: devapply.OpenShapes(inv.app.Paths.ApplyDir), stateDir: inv.app.Paths.ApplyDir, sections: ob.sections, minutes: confirm}

	// 4. The pull as the local account, from the pre-flight's read.
	rp, err := ar.planRead(e, expected, raw, j.ReadPlain(ctx), j.LocalAddr())
	if err != nil {
		return 0, inv.usageErr("Registered "+e.Name+", but its configuration could not be read: "+shortReason(err), "Nothing was sent to the device.")
	}
	if err := ob.recordLocal(e, rp, id); err != nil {
		inv.app.Out.Warn("the pull's record was not kept: " + strings.Join(msgs(err), " "))
	}
	missing := differingSections(rp.results)
	inv.echo(fmt.Sprintf("  %s  read as %s: %s", e.Name, localLoginText(ob.local.account), readSummary(missing)))

	// 5-6. The plan and the check, as the local account, on the same login.
	st := &applyState{}
	in := ob.input(ar, e, expected, j, st, confirm, nil)
	closeJ = false
	var drv devapply.Driver
	out := drv.Check(ctx, in)
	stop()
	o := &applyOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Phase: "check", Out: &out}
	if st.first != nil {
		o.Delta, o.HasDelta = st.first.delta, true
	}
	ar.keep(e, o, st, false)
	ob.out = o
	inv.echo(fmt.Sprintf("  %s  %s", e.Name, cleanLine(o.line())))
	switch {
	case out.Exit == devapply.ExitNoChange:
		inv.echo("  Registered " + e.Name + "; the device already has what tacctl renders: nothing to commit.")
		return batch.ExitOK, nil
	case out.Exit != devapply.ExitChecked || st.first == nil:
		if out.Interrupted {
			return batch.ExitInterrupted, nil
		}
		inv.echo("  Registered " + e.Name + "; nothing was committed.")
		return batch.ExitFailed, nil
	case ob.check:
		inv.echo("  Registered " + e.Name + "; nothing was committed: --check ends after the device's own commit check.")
		return batch.ExitOK, nil
	}

	// 7. The review, then the user's own password.
	if !ob.review(o) {
		return batch.ExitFailed, nil
	}
	tp := inv.hooks.newDevicePasswords(inv)
	tpw, err := tp.Password(inv.ctx, ob.user)
	if err != nil {
		inv.app.Out.ErrorE(err.Error())
		inv.echo("  Nothing was committed.")
		return batch.ExitFailed, nil
	}
	tacacs := string(tpw)
	askpass.Zero(tpw)
	defer func() {
		tacacs = ""
		if d, ok := tp.(interface{ Done() }); ok {
			d.Done()
		}
	}()

	// 8. The commit as the local account; every session after it is the
	// user's TACACS+ login.
	ctxB, stopB := ob.interruptible(true, time.Duration(confirm+2)*time.Minute)
	code := ob.commit(ctxB, ar, e, expected, st.first.delta, confirm, tp, func() string { return tacacs })
	stopB()
	// 9. Nothing logs in as the local account again, root included.
	if ob.out.Out != nil && committedSomething(ob.out.Out.Exit) {
		ob.noteNotProbed()
	}
	return code, nil
}

// interruptible is the context of a phase that talks to the device, with
// limit as its deadline: SIGTERM and SIGHUP cancel it; Ctrl-C cancels it
// too, except in the commit's transaction (held), where the first one lets
// the transaction run to its end (the change proven, or rolled back) and the
// second cancels it, as 'device config apply' does.
func (ob *onboard) interruptible(held bool, limit time.Duration) (context.Context, func()) {
	inv := ob.inv
	base, interrupts, stopSignals := inv.batchInterrupts()
	ctx, cancel := context.WithTimeout(base, limit)
	done := make(chan struct{})
	go func() {
		n := 0
		for {
			select {
			case <-interrupts:
				n++
				if held && n == 1 {
					inv.stderrLine("  interrupted: the transaction runs to its end (the change is proven or rolled back); a second Ctrl-C cancels it")
					continue
				}
				cancel()
			case <-done:
				return
			}
		}
	}()
	var once sync.Once
	return ctx, func() {
		once.Do(func() {
			close(done)
			cancel()
			stopSignals()
		})
	}
}

// admissible is what is refused before anything is scanned or sent: the
// scope that answers the address, the invoking user's own login after the
// commit, a break-glass hold, an address registered to a device that is
// read the normal way.
func (ob *onboard) admissible() error {
	inv := ob.inv
	m, err := inv.model()
	if err != nil {
		return err
	}
	info, covered := m.LookupAddr(ob.addr)
	if !covered {
		return inv.usageErr("No scope answers "+ob.addr+": no scope's prefixes cover it, so there is nothing to render for it. Nothing was sent.",
			"Add them first: tacctl scope prefixes <scope> add <cidr>")
	}
	ob.scope = info.Scope
	if !ob.check {
		if msg := loginProblem(m, ob.user, ob.scope); msg != "" {
			return inv.usageErr(msg+": every session after the commit is your own login, so the change could not be proven. Nothing was sent.",
				"--check registers and checks without it.")
		}
		u := m.User(ob.user)
		g := m.Group(u.Group)
		if g == nil || g.JuniperClass == "" {
			return inv.usageErr("Your group '"+u.Group+"' has no Juniper class: the TACACS+ login after the commit would map to no template user, so the change could not be proven. Nothing was sent.",
				"--check registers and checks without it.")
		}
		ob.template = g.JuniperClass
	}
	// a break-glass hold refuses the local login as it refuses every pull
	if h, held := inv.holdAt(ob.addr); held {
		return inv.usageErr(holdRefusal(h.Device) + ": release it first. Nothing was sent.")
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	ob.port = devssh.DefaultPort
	if e, ok := res.Lookup(ob.addr, devreg.ScopeFilter{}); ok && e.Address == ob.addr {
		if e.Source == devreg.SourceHost {
			return inv.usageErr("'" + e.Name + "' at " + ob.addr + " is an enrolled Linux host, not a network device. Nothing was sent.")
		}
		recs, err := inv.configStore().Load()
		if err != nil {
			return inv.usageErr(strings.Join(msgs(err), " ") + ": whether '" + e.Name + "' was read as your own login is not known, so it is not taken over. Nothing was sent.")
		}
		if rec, ok := recs.Of(e.Name); ok && rec.PulledAsUser() {
			return inv.usageErr(ob.addr+" is registered as '"+e.Name+"' and was read as your own login: it is reached by the normal flow. Nothing was sent.",
				"tacctl device config pull "+e.Name+", then tacctl device config apply "+e.Name)
		}
		if e.Vendor != devssh.VendorJuniper {
			return inv.usageErr(ob.addr + " is registered as '" + e.Name + "' with vendor '" + e.Vendor + "': onboard is for Junos devices. Nothing was sent.")
		}
		if ob.name != "" && !strings.EqualFold(ob.name, e.Name) {
			return inv.usageErr(ob.addr+" is registered as '"+e.Name+"' by an earlier onboard: it is onboarded under that name. Nothing was sent.",
				"Drop --name, or rename it first: tacctl device rename "+e.Name+" "+ob.name)
		}
		if len(e.HostKeys) == 0 {
			return inv.usageErr("'"+e.Name+"' has no pinned host key. Nothing was sent.", "Pin it after comparing it with the device console: tacctl device hostkey "+e.Name+" accept")
		}
		ob.reuse = &e
		ob.name = e.Name
		ob.port = e.SSHPort()
		ob.legacy = ob.legacy || e.LegacySSH
		return nil
	}
	if ob.name != "" {
		// A device registered under a name with upper case is onboarded
		// above; a name for a new registration is lower case.
		if err := names.RequireLower(ob.name); err != nil {
			return err
		}
		if err := res.CheckName(ob.name, devssh.VendorJuniper, false, ""); err != nil {
			return err
		}
	}
	return nil
}

// identity is step 1: the keys the device offers, shown; one question
// before any login, or the key --host-key names. A device registered by an
// earlier onboard is dialled with the keys pinned then.
func (ob *onboard) identity() error {
	inv := ob.inv
	offered, err := inv.scanKeys(ob.addr, ob.port, ob.legacy, "Nothing was sent.")
	if err != nil {
		return err
	}
	inv.echo("  " + ob.addr + " offers:")
	inv.echoKeys("    ", offered)
	pinned := offered
	if ob.reuse != nil {
		pinned = devreg.ParseHostKeys(ob.reuse.HostKeys)
		inv.echo("  Pinned for '" + ob.reuse.Name + "' by an earlier onboard:")
		inv.echoKeys("    ", pinned)
	}
	if ob.hostKey != "" {
		k, ok := devreg.MatchFingerprint(offered, ob.hostKey)
		if !ok {
			return inv.usageErr("No host key "+ob.addr+" offers matches "+ob.hostKey+". Nothing was sent.",
				"Check the fingerprint on the device console: "+devreg.VerifyHint(devssh.VendorJuniper)+".")
		}
		if ob.reuse != nil {
			if _, ok := devreg.MatchFingerprint(pinned, ob.hostKey); !ok {
				return inv.usageErr("The key "+ob.hostKey+" is not the one pinned for '"+ob.reuse.Name+"'. Nothing was sent.",
					"Verify the device, then re-pin it: tacctl device hostkey "+ob.reuse.Name+" set "+ob.hostKey)
			}
			ob.keys = pinned
		} else {
			ob.keys = []devreg.HostKey{k}
		}
		inv.echo("  " + ob.hostKey + " matches --host-key.")
		return nil
	}
	inv.echo("  A blank device has no other proof: compare one with its console (" + devreg.VerifyHint(devssh.VendorJuniper) + ").")
	if !ob.pr.Confirm("Trust these keys and send the local password of '" + ob.local.account + "' to " + ob.addr + "? [y/N] ") {
		return inv.usageErr("Not trusted. Nothing was sent.")
	}
	ob.keys = pinned
	return nil
}

// target is the local account's login at the address, with the keys of
// step 1 (or, after the registration, the pinned ones: the same).
func (ob *onboard) target(keys []string) devssh.Target {
	return devssh.Target{Host: ob.addr, Port: ob.port, User: ob.local.account, HostKeys: keys, Legacy: ob.legacy,
		Password: ob.local.eachConnection(), ConnectTimeout: devssh.DefaultConnectTimeout, Dialer: ob.inv.deviceDialer()}
}

// dialLocal is the local account's transport; a handshake that fails on the
// algorithms is tried once more with the legacy set, and the device is then
// registered --legacy-ssh.
func (ob *onboard) dialLocal(ctx context.Context, keys []string) (*devapply.JunosCLI, error) {
	j, err := devapply.DialJunosWith(ctx, ob.target(keys), ob.local.cliOptions()...)
	var ae devssh.AlgorithmError
	if err != nil && !ob.legacy && errors.As(err, &ae) {
		ob.legacy = true
		ob.inv.echo("  The handshake needs the legacy algorithms; tried again with them (the device is registered --legacy-ssh).")
		j, err = devapply.DialJunosWith(ctx, ob.target(keys), ob.local.cliOptions()...)
	}
	return j, err
}

// dialRefusal is a local login that did not come up, in words.
func (ob *onboard) dialRefusal(ctx context.Context, err error) error {
	var hk devssh.ErrHostKey
	switch {
	case errors.Is(err, devssh.ErrAuth):
		return ob.inv.usageErr(ob.addr + " refused the password of its local account '" + ob.local.account + "'. Nothing was changed.")
	case errors.As(err, &hk):
		return ob.inv.usageErr(ob.addr+" presented a host key that is not the trusted one ("+hk.Error()+"). Nothing was sent.",
			"Compare the keys with the device console before anything else.")
	}
	_, reason, _ := resultOf(ctx, ob.addr, err)
	return ob.inv.usageErr("The local login at " + ob.addr + " failed: " + reason + ". Nothing was changed.")
}

// preflight is step 2: the local login, 'show version', the pending marker,
// the read (no TACACS+ or RADIUS server may be there) and the class.
func (ob *onboard) preflight(ctx context.Context) (*devapply.JunosCLI, devapply.Identity, string, error) {
	inv := ob.inv
	var id devapply.Identity
	j, err := ob.dialLocal(ctx, devreg.KeyStrings(ob.keys))
	if err != nil {
		return nil, id, "", ob.dialRefusal(ctx, err)
	}
	fail := func(lines ...string) (*devapply.JunosCLI, devapply.Identity, string, error) {
		_ = j.Close()
		return nil, id, "", inv.usageErr(lines...)
	}
	if id, err = j.Identity(ctx); err != nil {
		return fail("Pre-flight: 'show version' as "+ob.local.account+": "+shortReason(err)+". Nothing was changed.",
			"onboard is for Junos devices.")
	}
	st, err := j.State(ctx)
	if err != nil {
		return fail("Pre-flight: 'show system commit': " + shortReason(err) + ". Nothing was changed.")
	}
	if st.Pending {
		return fail("Pre-flight: a confirmed commit is pending " + st.Until() + " on " + ob.addr + "; nothing was sent. Do not type commit or commit check on it before then.")
	}
	raw, err := j.Read(ctx)
	if err != nil {
		return fail("Pre-flight: the read as " + ob.local.account + ": " + shortReason(err) + ". Nothing was changed.")
	}
	if hasAAAServer(raw) {
		return fail("refused: the device already has a TACACS+ or RADIUS server; it is reached by the normal flow (device add, device config pull)")
	}
	if hasLocalUser(raw, ob.user) {
		return fail("refused: the device has a local account named '"+ob.user+"', your own login: a login as you could be that account's, not TACACS+, so the change could not be proven. Nothing was changed.",
			"Remove or rename that account on the device first.")
	}
	lg, err := j.Login(ctx)
	if err != nil {
		return fail("Pre-flight: 'show cli authorization': " + shortReason(err) + ". Nothing was changed.")
	}
	if !j.Confirms() {
		return fail("The local account '" + ob.local.account + "' (class " + cleanLine(lg.Class) + ") cannot commit: onboard needs a class that may configure and commit. Nothing was changed.")
	}
	ob.reported = id.Hostname
	what := cleanLine(strings.TrimSpace(strings.Join([]string{"Junos " + id.Release, id.Model}, "  ")))
	inv.echo(fmt.Sprintf("  %s  %s  device reports host name %s; no TACACS+ or RADIUS server", ob.addr, what, reportedName(id.Hostname)))
	return j, id, raw, nil
}

// reportedName is a name the device reported, for a terminal line: its
// control characters replaced, "-" for none.
func reportedName(n string) string {
	if n == "" {
		return "-"
	}
	return cleanLine(n)
}

// systemStatement is a read's line without its 'set' (or 'deactivate') and
// a 'groups <name>' prefix: the words of a statement under system, nil for
// any other line.
func systemStatement(l string) []string {
	f := strings.Fields(l)
	if len(f) == 0 || (f[0] != "set" && f[0] != "deactivate") {
		return nil
	}
	f = f[1:]
	if len(f) >= 2 && f[0] == "groups" {
		f = f[2:]
	}
	if len(f) < 2 || f[0] != "system" {
		return nil
	}
	return f[1:]
}

// hasAAAServer reports whether a configuration read ('display set', with
// or without 'display inheritance') has a TACACS+ or RADIUS server under
// system, directly or in a group: 'system tacplus-server', 'system
// radius-server', or 'system accounting destination tacplus|radius server'
// (the one blocker of the backlog).
func hasAAAServer(raw string) bool {
	for _, l := range strings.Split(raw, "\n") {
		f := systemStatement(l)
		switch {
		case len(f) == 0:
		case f[0] == "tacplus-server", f[0] == "radius-server":
			return true
		case len(f) >= 4 && f[0] == "accounting" && f[1] == "destination" && (f[2] == "tacplus" || f[2] == "radius") && f[3] == "server":
			return true
		}
	}
	return false
}

// hasLocalUser reports whether a configuration read has 'system login user
// <name>' (directly or in a group), the name compared without case.
func hasLocalUser(raw, name string) bool {
	for _, l := range strings.Split(raw, "\n") {
		f := systemStatement(l)
		if len(f) >= 3 && f[0] == "login" && f[1] == "user" && strings.EqualFold(strings.Trim(f[2], `"`), name) {
			return true
		}
	}
	return false
}

// templateOf finds, in the rendering, the template user of the invoking
// user's group (the group's Juniper class) and the class it is bound to:
// the fresh login after the commit must report both. A rendering without
// one is refused before anything is committed.
func (ob *onboard) templateOf(expected []devices.Section) error {
	prefix := "set system login user " + ob.template + " class "
	for _, s := range expected {
		for _, l := range s.Lines {
			if c, ok := strings.CutPrefix(strings.TrimSpace(l), prefix); ok && c != "" && !strings.Contains(c, " ") {
				ob.class = c
				return nil
			}
		}
	}
	return ob.inv.usageErr("Registered " + ob.name + ", but its rendering has no template user '" + ob.template + "' for your group's class: the TACACS+ login after the commit could not be proven. Nothing was sent to the device.")
}

// verifyLogin is the fresh login's proof (D136): its 'Current user' is the
// rendered template user of the invoking user's group, with that class, and
// never a local account of the person's own name.
func (ob *onboard) verifyLogin(lg devapply.Login) error {
	switch {
	case lg.User == "" || lg.Class == "":
		return errors.New("'show cli authorization' names no current user and class")
	case strings.EqualFold(lg.User, ob.user) || strings.EqualFold(lg.User, ob.local.account):
		return fmt.Errorf("the current user is '%s', a local account, not the template user '%s': not a TACACS+ login", lg.User, ob.template)
	case lg.User != ob.template:
		return fmt.Errorf("the current user is '%s', not the template user '%s' of your group", lg.User, ob.template)
	case lg.Class != ob.class:
		return fmt.Errorf("the class is '%s', not '%s' of the template user '%s'", lg.Class, ob.class, ob.template)
	}
	return nil
}

// readSummary is the pull's words for the sections that differ.
func readSummary(missing []string) string {
	if len(missing) == 0 {
		return "every managed section agrees"
	}
	return strings.Join(missing, ", ") + " differ from what tacctl renders"
}

// register is step 3: the name (--name, the reported host name, else asked),
// 'device add' (the keys of step 1 pinned: the same code as every
// registration), and the device's own location and description in the
// registry's empty fields.
func (ob *onboard) register(id devapply.Identity, raw string) error {
	inv := ob.inv
	if ob.reuse == nil {
		name, err := ob.chooseName(id)
		if err != nil {
			return err
		}
		args := []string{name, ob.addr, "--vendor", devssh.VendorJuniper, "--no-lookup"}
		if ob.legacy {
			args = append(args, "--legacy-ssh")
		}
		if err := inv.deviceAddWith(args, ob.keys); err != nil {
			return err
		}
		ob.name = name
	} else {
		inv.echo("  " + ob.name + " is registered already (an earlier onboard that never committed): it is taken again.")
	}
	ob.fillFields(raw)
	_, res, err := inv.deviceLoad()
	if err != nil {
		return err
	}
	e, ok := res.Lookup(ob.name, devreg.ScopeFilter{})
	if !ok {
		return inv.usageErr("'" + ob.name + "' is not in the registry after the registration. Nothing was sent to the device.")
	}
	if !e.Configured {
		return inv.usageErr("'" + e.Name + "' is in no scope after the registration. Nothing was sent to the device.")
	}
	ob.entry = e
	return nil
}

// chooseName is the device's name: --name, else the name it reports, else
// (a generic or unusable one) asked for at the terminal.
func (ob *onboard) chooseName(id devapply.Identity) (string, error) {
	inv := ob.inv
	if ob.name != "" {
		return ob.name, nil
	}
	_, res, err := inv.deviceLoad()
	if err != nil {
		return "", err
	}
	// What the device reports is not case-sensitive for the device, and a
	// new name is lower case: it is lowercased, as 'device add' offers it.
	name := strings.ToLower(id.Hostname)
	if name != "" && devreg.ValidateNewName(name) == nil && res.CheckName(name, devssh.VendorJuniper, false, "") == nil {
		return name, nil
	}
	if !ob.pr.Interactive() {
		return "", inv.usageErr("The device calls itself '"+reportedName(id.Hostname)+"', which is not a name to register (generic, taken or not a name). Nothing was changed.",
			"Give one: --name <name>")
	}
	inv.echo("  The device calls itself '" + reportedName(id.Hostname) + "', which is generic, taken or not a name.")
	name = ob.pr.Ask("  Name to register it as: ")
	if err := devreg.ValidateNewName(name); err != nil {
		return "", err
	}
	if err := res.CheckName(name, devssh.VendorJuniper, false, ""); err != nil {
		return "", err
	}
	return name, nil
}

// deviceValue is the value of a 'set <path> <value>' line of the read, its
// quotes removed ("" when the read has none).
func deviceValue(raw, path string) string {
	for _, l := range strings.Split(raw, "\n") {
		l = strings.TrimSpace(l)
		if v, ok := strings.CutPrefix(l, "set "+path+" "); ok {
			v = strings.TrimSpace(v)
			if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
				v = v[1 : len(v)-1]
			}
			return v
		}
	}
	return ""
}

// fillFields fills the registry's empty location and description from the
// device's own 'snmp location' and 'snmp description' (the helper's
// bootstrap): a field that is set is never replaced, and a value the
// registry does not accept is left out with a line. The hostname field is
// never filled from the device: ssh dials it instead of the address, so the
// device would name its own target.
func (ob *onboard) fillFields(raw string) {
	inv := ob.inv
	vals := []struct{ field, value string }{
		{"location", deviceValue(raw, "snmp location")},
		{"description", deviceValue(raw, "snmp description")},
	}
	var filled, refused []string
	_, err := inv.deviceWrite(func(f *devreg.File, _ *devreg.Resolver) error {
		filled, refused = nil, nil
		d := f.Find(ob.name)
		if d == nil {
			return errors.New("not registered")
		}
		for _, v := range vals {
			if v.value == "" || fieldValue(d, v.field) != "" {
				continue
			}
			c := d.Clone()
			if err := setField(&c, v.field, v.value, false); err != nil {
				refused = append(refused, "  The device's "+v.field+" '"+cleanLine(v.value)+"' is not stored: "+cleanLine(strings.Join(msgs(err), " ")))
				continue
			}
			_ = setField(d, v.field, v.value, false)
			filled = append(filled, fmt.Sprintf("%s %q", v.field, v.value))
		}
		if len(filled) == 0 {
			return errNothingToFill
		}
		return nil
	})
	for _, l := range refused {
		inv.echo(l)
	}
	switch {
	case errors.Is(err, errNothingToFill):
	case err != nil:
		inv.app.Out.Warn("the device's own values were not stored: " + strings.Join(msgs(err), " "))
	default:
		inv.echo("  From the device: " + cleanLine(strings.Join(filled, "; ")))
	}
}

// errNothingToFill ends a registry write that would change nothing.
var errNothingToFill = errors.New("nothing to fill")

// recordLocal keeps the pre-flight's read as the device's pull record, made
// as the local account (step 4: login=local:<account>).
func (ob *onboard) recordLocal(e devreg.Entry, rp *readPlan, id devapply.Identity) error {
	pr := &pullRun{inv: ob.inv, user: ob.user, store: ob.inv.configStore()}
	facts := devconf.Facts{Release: devconf.JunosRelease(rp.raw), Model: id.Model}
	if facts.Release == "" {
		facts.Release = id.Release
	}
	o := &pullOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Transport: transportSSH, Netconf: netconfNotProbed,
		Facts: devconf.CleanFacts(facts), Login: localLoginText(ob.local.account)}
	return pr.recordSuccess(o, e, rp.ext, rp.results, rp.plain)
}

// input is the driver's input of one transaction as the local account: the
// allow-list protects the local account as the invoking login (D133), the
// device may report the name it reported in the pre-flight. fresh is the
// TACACS+ login the driver reads on after the commit (nil: none).
func (ob *onboard) input(ar *applyRun, e devreg.Entry, expected []devices.Section, t *devapply.JunosCLI, st *applyState, minutes int,
	fresh func() *devapply.JunosCLI) devapply.Input {
	inv := ob.inv
	names := applyNames(e)
	if ob.reported != "" {
		names = append(names, ob.reported)
	}
	return devapply.Input{
		Device: e.Name, Names: names, User: ob.user, Transport: t,
		Plan:           ob.planner(ar, e, expected, t, st, fresh),
		Allow:          plan.Allow{Login: ob.local.account, Expected: expected},
		ConfirmMinutes: minutes,
		Clock:          inv.app.Knobs.Now, Rand: inv.app.Knobs.Rand(),
		StateDir: ar.stateDir,
	}
}

// planner is the driver's Plan: the first read is the local account's (the
// record keeps it with login=local), the second the convergence read on the
// fresh TACACS+ login, kept in memory until the change stuck. The plain view
// is read on the login the driver read raw on: the fresh TACACS+ login once
// there is one, else the held local one.
func (ob *onboard) planner(ar *applyRun, e devreg.Entry, expected []devices.Section, t *devapply.JunosCLI, st *applyState,
	fresh func() *devapply.JunosCLI) func(context.Context, string, net.IP) (plan.Delta, error) {
	return func(ctx context.Context, raw string, from net.IP) (plan.Delta, error) {
		st.calls++
		r := t
		if fresh != nil {
			if v := fresh(); v != nil {
				r = v
			}
		}
		rp, err := ar.planRead(e, expected, raw, r.ReadPlain(ctx), from)
		if err != nil {
			return plan.Delta{}, err
		}
		switch st.calls {
		case 1:
			st.first = rp
			st.pre = rp.fingerprints(e.Vendor)
			_ = ob.recordLocal(e, rp, devapply.Identity{})
		case 2:
			st.after = rp
		}
		return rp.delta, nil
	}
}

// review is step 7's question (D134), for the one device: its change with
// every secret elided, then its name typed back.
func (ob *onboard) review(o *applyOutcome) bool {
	inv := ob.inv
	w := inv.app.Out.Stdout
	pf := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	d := o.Delta
	head := "No shape"
	if o.Out.Shape != "" {
		head = "Shape " + o.Out.Shape
	}
	pf("\n%s, 1 device (%s), first-time plan:\n", head, o.Name)
	cur := ""
	for _, l := range d.Lines {
		if l.Section != cur {
			cur = l.Section
			if why := d.Of(cur).Why; why != "" {
				pf("  %-8s %s\n", cur, cleanLine(why))
			} else {
				pf("  %s\n", cur)
			}
		}
		pf("    %s\n", cleanLine(l.Shown()))
	}
	for _, w2 := range d.Warnings {
		pf("  warning: %s\n", cleanLine(w2))
	}
	for _, s := range d.Skipped {
		pf("  not planned: %s: %s\n", s.Section, cleanLine(s.Why))
	}
	pf("  never written: the local account '%s', root, the break-glass accounts, system services, interfaces\n\n", ob.local.account)
	pf("Apply to %s under commit confirmed %d, as '%s', kept only after a TACACS+ login as %s works and what landed is what the check showed?\n",
		o.Name, ob.minutes(), ob.local.account, ob.user)
	if got := ob.pr.Ask("  Type the device name to go on: "); got != o.Name {
		inv.app.Out.ErrorE("The answer typed is not '" + o.Name + "'. Nothing was committed; the device stays registered.")
		return false
	}
	shape := o.Out.Shape
	if shape == "" {
		shape = "-"
	}
	inv.app.Audit().Raw("auth.notice", fmt.Sprintf("device onboard user=%s device=%s approved=1 shape=%s login=%s mode=attended",
		ob.user, o.Name, shape, localLoginText(ob.local.account)))
	return true
}

// minutes is the window of the confirmed commit.
func (ob *onboard) minutes() int {
	m, _ := ob.inv.applySettings()
	return m
}

// commit is step 8: the transaction as the local account, held from
// 'configure exclusive' to the confirm; the verification is a fresh login
// as the invoking user (TACACS+), at the address.
func (ob *onboard) commit(ctx context.Context, ar *applyRun, e devreg.Entry, expected []devices.Section, reviewed plan.Delta, minutes int,
	tp devicePasswords, tacacs func() string) int {
	inv := ob.inv
	inv.echo(fmt.Sprintf("  %s  committing as %s, verifying as %s ...", e.Name, ob.local.account, ob.user))
	j, err := ob.dialLocal(ctx, e.HostKeys)
	if err != nil {
		_ = ob.dialRefusal(ctx, err)
		ob.out = &applyOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Phase: "apply", Reason: "the local login failed; nothing was committed"}
		return batch.ExitFailed
	}
	st := &applyState{}
	// the fresh TACACS+ login the driver reads on after the commit (set and
	// read on the driver's goroutine)
	var fresh *devapply.JunosCLI
	in := ob.input(ar, e, expected, j, st, minutes, func() *devapply.JunosCLI { return fresh })
	var accept sync.Once
	verify := devssh.Target{Host: e.Address, Port: e.SSHPort(), User: ob.user, HostKeys: e.HostKeys, Legacy: e.LegacySSH,
		Password: func() (string, error) { return tacacs(), nil }, ConnectTimeout: devssh.DefaultConnectTimeout, Dialer: inv.deviceDialer()}
	in.Verify = func(ctx context.Context) (devapply.Reader, error) {
		v, err := devapply.DialJunos(ctx, verify)
		if err != nil {
			// a refusal of the fresh login is a verification failure, never a
			// wrong password (D131): the cache is not told
			return nil, err
		}
		accept.Do(tp.Accepted)
		fresh = v
		return v, nil
	}
	in.VerifyLogin = ob.verifyLogin
	var drv devapply.Driver
	start := inv.app.Knobs.Now()
	out := drv.Apply(ctx, in, reviewed)
	o := &applyOutcome{Name: e.Name, Scope: e.Scope, Vendor: e.Vendor, Phase: "apply", Out: &out, Duration: inv.app.Knobs.Now().Sub(start)}
	if st.first != nil {
		o.Delta, o.HasDelta = st.first.delta, true
	}
	ar.keep(e, o, st, true)
	// the record of the commit says it was the onboard's
	if out.Exit != devapply.ExitNoChange && out.Exit != devapply.ExitInterrupted {
		_ = ar.writeApplied(e, ar.appliedOf(out, devconf.AppliedKindOnboard, st.pre))
	}
	ob.out = o
	inv.echo(fmt.Sprintf("  %s  %s", e.Name, cleanLine(o.line())))
	if out.LoginRefused {
		inv.echo("  The fresh login as " + ob.user + " was refused: the change was rolled back and the local account '" + ob.local.account + "' is as it was.")
	}
	switch out.Exit {
	case devapply.ExitPending, devapply.ExitWindowShort, devapply.ExitUnknown:
		inv.stderrLine(ui.Red + "PENDING " + e.Name + ui.NC + ": do not type commit or commit check on the device before " +
			out.Until.Format("15:04:05") + "; it rolls the change back by itself then unless someone commits.")
	}
	switch {
	case out.Interrupted:
		return batch.ExitInterrupted
	case out.Exit == devapply.ExitApplied, out.Exit == devapply.ExitNoChange:
		return batch.ExitOK
	}
	return batch.ExitFailed
}

// committedSomething reports whether a transaction got as far as a commit,
// after which the run says the local account was not probed.
func committedSomething(e devapply.Exit) bool {
	switch e {
	case devapply.ExitApplied, devapply.ExitAppliedByOther, devapply.ExitRolledBack, devapply.ExitPending, devapply.ExitWindowShort, devapply.ExitUnknown:
		return true
	}
	return false
}

// probeNotProbed is the value of the 'probe' field of --json after a commit:
// a stable word, since the local account is never tried again.
const probeNotProbed = "not-probed"

// noteNotProbed is step 9: the local account is not probed, for any account
// (root too): with 'authentication-order tacplus' a login sends its password
// to the TACACS+ server. Nothing connects.
func (ob *onboard) noteNotProbed() {
	ob.probe = probeNotProbed
	ob.inv.echo("  The local account '" + ob.local.account + "' was not probed: a login would send its password to the TACACS+ server.")
}

// word is the run's result for the audit line.
func (ob *onboard) word() string {
	if ob.out == nil {
		return "failed"
	}
	return ob.out.word()
}

// audit is the run's audit line (D141): never a password, never a value.
func (ob *onboard) audit(result string) {
	inv := ob.inv
	name := ob.name
	if ob.entry.Name != "" {
		name = ob.entry.Name
	}
	acct := "-"
	if ob.local != nil {
		acct = localLoginText(ob.local.account)
	}
	inv.app.Audit().Raw("auth.info", fmt.Sprintf("device onboard user=%s device=%s addr=%s login=%s result=%s",
		ob.user, dash(name), dash(ob.addr), acct, result))
}

// onboardJSON is the object --json prints at the end.
type onboardJSON struct {
	applyJSON
	Address string `json:"address"`
	Login   string `json:"login"`
	Probe   string `json:"probe,omitempty"`
	Exit    int    `json:"exit"`
}

// printJSON prints the run's object.
func (ob *onboard) printJSON(code int) {
	j := onboardJSON{Address: ob.addr, Login: localLoginText(ob.local.account), Probe: ob.probe, Exit: code}
	if ob.out != nil {
		j.applyJSON = ob.out.json(applyJSON{})
	} else {
		j.Name, j.Status = ob.name, "failed"
	}
	b, _ := json.Marshal(j)
	ob.inv.write(string(b) + "\n")
}
