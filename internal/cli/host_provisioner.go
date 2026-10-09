package cli

// 'host provisioner <name> rotate <user> (--key <file>|--password)
// [--remove-old [--remove-home]] [--dry-run] [--yes]': change the account
// tacctl logs in to a host with (the provisioning account) without ever
// being locked out of it. The steps, in this order:
//
//  0. take the host's lock on this server (one rotation of a host at a
//     time) and validate locally; nothing has changed yet;
//  1. create the new account over the login in use (a small script of its
//     own, run through RunScript), below tacctl's UID range: with --key the
//     public key only (written as the account) and a locked password, with
//     --password a password the operator types into the host's own passwd
//     (it never passes through tacctl); its sudoers line comes last;
//  2. prove it with a fresh login in a NEW connection that reaches root
//     through sudo, whose ssh trusts the host's pinned keys only (a host
//     with none pinned: the keys it shows are listed for the operator to
//     confirm, and --password is refused);
//  3. only then rewrite the registry as 'host target' does (snapshot first,
//     the entry read again under the lock, the old login recorded in the
//     host's record);
//  4. with --remove-old, remove the old account last, over the new one.
//
// A proof that fails takes back what this run did: an account it created is
// removed, an adopted one is left (an earlier run made it) without the
// sudoers line this run wrote. 'rotate' is the only subcommand.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

// hostProvisionerUsage is the usage line of 'host provisioner'.
const hostProvisionerUsage = "Usage: tacctl host provisioner <name> rotate <user> (--key <file>|--password) [--remove-old [--remove-home]] [--dry-run] [--yes]"

// rotateOpts are the arguments of 'host provisioner ... rotate'.
type rotateOpts struct {
	name, user, keyFile                               string
	key, password, removeOld, removeHome, dryRun, yes bool
}

func (inv *invocation) hostProvisioner(args []string) error {
	var o rotateOpts
	var pos []string
	for i := 0; i < len(args); i++ {
		switch w := args[i]; w {
		case "--key":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return inv.usageErr("--key needs a file.", hostProvisionerUsage)
			}
			o.key, o.keyFile = true, args[i+1]
			i++
		case "--password":
			o.password = true
		case "--remove-old":
			o.removeOld = true
		case "--remove-home":
			o.removeHome = true
		case "--dry-run":
			o.dryRun = true
		case "--yes":
			o.yes = true
		default:
			if strings.HasPrefix(w, "-") {
				return inv.usageErr("Unknown option: '"+w+"'", hostProvisionerUsage)
			}
			pos = append(pos, w)
		}
	}
	if len(pos) == 0 {
		return inv.usageErr(hostProvisionerUsage)
	}
	// 'rotate' is the only subcommand.
	if len(pos) >= 2 && pos[1] != "rotate" {
		return inv.usageErr("Unknown subcommand: 'provisioner "+pos[1]+"'. The only one is 'rotate'.", hostProvisionerUsage)
	}
	if len(pos) < 3 {
		return inv.usageErr(hostProvisionerUsage)
	}
	if len(pos) > 3 {
		return inv.usageErr("Unexpected argument: '"+pos[3]+"'", hostProvisionerUsage)
	}
	o.name, o.user = pos[0], pos[2]
	return inv.hostRotate(o)
}

// rotation is what validation worked out.
type rotation struct {
	o     rotateOpts
	entry hosts.Entry
	// oldLogin is the user of the registry target ("" when it has none);
	// hostPart its host.
	oldLogin, hostPart string
	newTarget          string
	auth               string
	// keyFile is the absolute path of the --key file; pub its public key
	// line ("" while the key is yet to be generated); generate says so.
	keyFile  string
	pub      string
	generate bool
	rng      hosts.Range
	avoid    []hosts.Range
	// pins are the host's pinned ssh keys ('type base64'); none means the
	// proof cannot check the host (see proofProblem).
	pins []string
	// resume: the registry points at the new account already; only the old
	// one is left to remove.
	resume bool
	he     *hosts.Env
}

func (r *rotation) authText() string {
	if r.auth == hosts.AuthKey {
		return "key login"
	}
	return "password login"
}

// hostRotate is 'host provisioner <name> rotate <user> ...'.
func (inv *invocation) hostRotate(o rotateOpts) error {
	a := inv.app
	// One command at a time per host: the lock is held to the end, and what
	// is validated below is read under it.
	if !o.dryRun {
		if reg, err := inv.registry(); err != nil {
			return err
		} else if _, ok := reg.Find(o.name); ok {
			unlock, err := hosts.LockHost(filepath.Join(a.Paths.StateDir, "locks"), o.name)
			switch {
			case errors.Is(err, hosts.ErrRotationBusy):
				return inv.usageErr("Another rotation of '"+o.name+"' is running; nothing was changed.",
					"Run this again when it has finished.")
			case err != nil:
				return err
			}
			defer unlock()
		}
	}
	r, err := inv.rotateValidate(o)
	if err != nil {
		return err
	}
	if o.dryRun {
		return inv.rotateDryRun(r)
	}
	inv.rotatePlan(r)
	if err := inv.rotateConfirm(r); err != nil {
		return err
	}
	he := r.he
	e := r.entry
	by := inv.sudoUser()
	audit := func(extra string) string {
		return "host provisioner rotate name=" + o.name + " old=" + dash(r.oldLogin) + " new=" + o.user + " auth=" + r.auth + extra + " by=" + by
	}
	if r.resume {
		return inv.rotateRemoveOld(r)
	}

	// A missing --key file is made now, by ssh-keygen as the invoking user.
	if r.generate {
		a.Out.InfoE("Generating " + r.keyFile + " (ssh-keygen -t ed25519; it asks for the passphrase, empty is your choice)...")
		if err := r.he.GenerateKey(inv.ctx, r.keyFile); err != nil {
			if errors.Is(err, ui.ErrInterrupted) {
				return err
			}
			return inv.usageErr("Could not generate the key " + r.keyFile + "; nothing was changed.")
		}
		pub, err := r.he.PublicKeyOf(inv.ctx, r.keyFile)
		if err != nil {
			return inv.usageErr("Could not read the public key of " + r.keyFile + "; nothing was changed on " + o.name + ".")
		}
		r.pub = pub
		if fp := r.he.Fingerprint(inv.ctx, pub); fp != "" {
			a.Out.InfoE("Key " + fp)
		}
	}

	// Create the account over the login in use.
	he.KeepOpen = true
	closed := false
	closeSession := func() {
		if !closed {
			closed = true
			he.CloseSession(inv.ctx, e.Target, e.Port, e.Identity)
		}
	}
	defer closeSession()
	a.Out.InfoE("Creating the account '" + o.user + "' on " + o.name + " over " + targetText(e) + "...")
	create := hosts.RotateCreate{Account: o.user, Auth: r.auth, PubKey: r.pub, Range: r.rng, Avoid: r.avoid}
	code, st, err := he.RunRotateScript(inv.ctx, e.Target, e.Port, e.Identity, create.Script())
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			a.Out.WarnE("Interrupted. The account '" + o.user + "' may be on " + o.name + " (the script takes back what it did when the connection ends; if the output above does not say so, check the host); run the same command again to adopt it. The registry was not changed.")
		}
		return err
	}
	if code != 0 {
		return inv.usageErr("The account '"+o.user+"' could not be created on "+o.name+" (see above); the registry was not changed.",
			"The script takes back every step it did (an account it made, the sudoers line it wrote); an account that was there before is left as it was,",
			"except that an adopted account's ~/.ssh is emptied once the script gets to it. Check the output above for anything it names as left.")
	}

	// Prove it with a fresh login in a new connection.
	a.Out.InfoE("Proving the new login to " + o.user + "@" + r.hostPart + " in a new connection...")
	login := hosts.Login{Target: r.newTarget, Port: e.Port, Auth: r.auth}
	if r.auth == hosts.AuthKey {
		login.Identity = r.keyFile
	}
	if len(r.pins) > 0 {
		kh, cleanup, err := hosts.TempKnownHosts(o.name, pinStrings(r.pins))
		if err != nil {
			return inv.rotateProofFailed(r, st, "the pinned host keys could not be made ready for the proof: "+strings.Join(msgs(err), " "), audit(" step=prove"))
		}
		defer cleanup()
		login.KnownHosts, login.HostKeyAlias = kh, o.name
	}
	p := he.ProveLogin(inv.ctx, login)
	if inv.ctx.Err() != nil {
		a.Out.WarnE("Interrupted. The account '" + o.user + "' is on " + o.name + " with its sudoers line; run the same command again to adopt it. The registry was not changed.")
		return ui.ErrInterrupted
	}
	if problem := inv.proofProblem(r, p); problem != "" {
		return inv.rotateProofFailed(r, st, problem, audit(" step=prove"))
	}

	// The registry changes only now: the entry is read again (a 'host
	// move' or 'host target' may have run meanwhile) and only its login is
	// changed.
	if err := inv.snapshotFirst(); err != nil {
		a.Out.WarnE("The account '" + o.user + "' works on " + o.name + " but the registry was not changed; run the same command again to adopt it.")
		return err
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	cur, ok := reg.Find(o.name)
	if !ok || cur.Line == "" {
		a.Out.ErrorE("The host '" + o.name + "' is no longer enrolled; the registry was not changed. The account '" + o.user + "' is on the host.")
		return exit(1)
	}
	if cur.Target != e.Target || cur.Port != e.Port || cur.Identity != e.Identity {
		a.Out.ErrorE("How tacctl reaches '" + o.name + "' changed while this ran (now " + targetText(cur) + "); the registry was not rewritten. The account '" + o.user + "' is on the host; run the same command again to adopt it.")
		return exit(1)
	}
	e = cur
	next := cur
	next.Target = r.newTarget
	next.Identity = ""
	if r.auth == hosts.AuthKey {
		next.Identity = r.keyFile
	}
	if err := reg.Replace(next); err != nil {
		return err
	}
	at := a.Knobs.Now().Format("2006-01-02T15:04:05Z07:00")
	if err := inv.hostRecords().Update(o.name, func(rec *hosts.Record) {
		rec.Provisioner = &hosts.ProvisionerRecord{At: at, By: by, Old: r.oldLogin, New: o.user, Auth: r.auth}
	}); err != nil {
		a.Out.WarnE(o.name + ": the record could not be written: " + strings.Join(msgs(err), " "))
	}
	a.Logger(inv.ctx, "auth.info", audit(""))
	a.Out.InfoE("Host '" + o.name + "' is now reached at " + targetText(next) + " (scope, server and method unchanged).")
	closeSession()
	he.KeepOpen = false

	if !o.removeOld {
		if r.oldLogin != "" && r.oldLogin != "root" {
			a.Out.InfoE("The old login '" + r.oldLogin + "' is still on " + o.name + ". Remove it, over the new one: " + inv.rotateCommandLine(r) + " --remove-old")
		}
		return nil
	}
	return inv.rotateRemoveOld(r)
}

// rotateCommandLine is the command that repeats the rotation.
func (inv *invocation) rotateCommandLine(r *rotation) string {
	s := "tacctl host provisioner " + r.o.name + " rotate " + r.o.user
	if r.auth == hosts.AuthKey {
		return s + " --key " + r.keyFile
	}
	return s + " --password"
}

// rotateValidate checks everything that can be checked without touching the
// host or the registry, and works out the plan.
func (inv *invocation) rotateValidate(o rotateOpts) (*rotation, error) {
	if o.key == o.password {
		return nil, inv.usageErr("Give --key <file> or --password (one of them).", hostProvisionerUsage)
	}
	if o.removeHome && !o.removeOld {
		return nil, inv.usageErr("--remove-home goes with --remove-old.", hostProvisionerUsage)
	}
	if !hosts.ValidAccountName(o.user) {
		return nil, inv.usageErr("Invalid account name '"+o.user+"': lower case letters, digits, '_' and '-', at most 32, not starting with a digit.", hostProvisionerUsage)
	}
	if o.user == "root" {
		return nil, inv.usageErr("The provisioning account cannot be 'root'.")
	}
	reg, err := inv.registry()
	if err != nil {
		return nil, err
	}
	e, ok := reg.Find(o.name)
	if !ok || e.Line == "" {
		return nil, inv.usageErr("No enrolled host named '" + o.name + "'. See 'tacctl host list'.")
	}
	if e.Target == hosts.Local {
		return nil, inv.usageErr("'" + o.name + "' is this server (enrolled with --local); it is not reached over ssh, so it has no provisioning account to rotate.")
	}
	r := &rotation{o: o, entry: e, he: inv.hostsEnv()}
	r.hostPart = e.Target
	if u, h, found := strings.Cut(e.Target, "@"); found {
		r.oldLogin, r.hostPart = u, h
	}
	r.auth = hosts.AuthKey
	if o.password {
		r.auth = hosts.AuthPassword
		if !r.he.TTYAvailable() {
			return nil, inv.usageErr("--password needs a terminal: the password is typed into the host's own passwd and into ssh's and sudo's prompts; tacctl never sees it. Nothing was changed.")
		}
	}
	// The pinned keys are what the proof's ssh trusts. With none, nothing
	// authenticates the host: a password would be typed to whoever answers.
	devs, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return nil, err
	}
	r.pins = devs.HostKeysOf(o.name)
	if len(r.pins) == 0 && o.password {
		return nil, inv.usageErr("--password is refused: no ssh host key is pinned for '"+o.name+"', so the password would be typed to a peer nothing has authenticated.",
			"Pin the keys first ('tacctl host sync "+o.name+"' pins them), or use --key. Nothing was changed.")
	}
	r.newTarget = o.user + "@" + r.hostPart

	// The logins involved: the current one, and the new one.
	login, explicit, oldIsUser, err := inv.provisioningLogin(e.Target)
	if err != nil {
		return nil, err
	}
	if _, _, newIsUser, err := inv.provisioningLogin(r.newTarget); err != nil {
		return nil, err
	} else if newIsUser {
		return nil, inv.usageErr("'"+o.user+"' is a tacctl user; the provisioning account must be a local account that does not authenticate through tacctl. Nothing was changed.",
			"Choose another name for the new account.")
	}
	if o.user == login {
		// The registry may point at the new account already (an interrupted
		// rotation): then only the old account is left to remove.
		rec, _ := inv.hostRecords().Load(o.name)
		pr := rec.Provisioner
		if explicit && o.removeOld && pr != nil && pr.New == o.user && pr.Old != "" && !pr.OldRemoved {
			r.resume = true
			r.oldLogin = pr.Old
		} else {
			return nil, inv.usageErr("'" + o.user + "' is the login tacctl uses for " + o.name + " now; choose another account name. Nothing was changed.")
		}
	}
	if o.removeOld {
		switch {
		case !explicit && !r.resume:
			return nil, inv.usageErr("--remove-old needs a registry target with an explicit user (user@host): "+o.name+" is reached at '"+e.Target+"', which logs in as the invoking user, so there is no old account to name.",
				"Set one first: tacctl host target "+o.name+" <user>@"+r.hostPart)
		case r.oldLogin == "root":
			return nil, inv.usageErr("The old login is 'root'; there is nothing to remove. Nothing was changed.")
		case oldIsUser && !r.resume:
			return nil, inv.usageErr("The old login '" + login + "' is a tacctl user; its account belongs to 'host sync' and is not removed here. Nothing was changed.")
		}
		if !r.resume && r.oldLogin == o.user {
			return nil, inv.usageErr("The old and the new account are both '" + o.user + "'. Nothing was changed.")
		}
	}

	// The UID range: the new account stays below it and out of the ones
	// the server used before.
	rng, err := inv.uidRange()
	if err != nil {
		return nil, err
	}
	r.rng = rng
	r.he.Range = rng
	cur, prev, err := r.he.UIDs().Recorded()
	if err != nil {
		return nil, err
	}
	r.avoid = append(r.avoid, prev...)
	if !cur.IsZero() && cur != rng {
		r.avoid = append(r.avoid, cur)
	}
	r.avoid = append(r.avoid, hosts.LegacyRange)

	if o.key && !r.resume {
		if err := inv.rotateKey(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// rotateKey resolves the --key file: its absolute path, its public key, or
// that it is to be generated. Every access runs as the invoking user.
func (inv *invocation) rotateKey(r *rotation) error {
	he := r.he
	path := r.o.keyFile
	if strings.ContainsAny(path, "|\n") {
		return inv.usageErr("Invalid --key path.")
	}
	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return inv.usageErr("Cannot make '" + path + "' absolute: " + err.Error())
		}
		path = filepath.Join(wd, path)
	}
	path = filepath.Clean(path)
	r.keyFile = path
	st := he.StatAsUser(inv.ctx, path)
	if !st.Exists {
		dir := he.StatAsUser(inv.ctx, filepath.Dir(path))
		if !dir.Exists || !dir.Dir {
			return inv.usageErr("The directory of --key " + path + " does not exist; nothing was changed.")
		}
		if !he.TTYAvailable() && !r.o.dryRun {
			return inv.usageErr("The key file "+path+" does not exist; generating it needs a terminal (ssh-keygen asks for the passphrase). Nothing was changed.",
				"Generate it first: ssh-keygen -t ed25519 -f "+path)
		}
		r.generate = true
		return nil
	}
	if !st.Regular {
		return inv.usageErr(path + " is not a regular file. Nothing was changed.")
	}
	pub, err := he.PublicKeyOf(inv.ctx, path)
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			return err
		}
		return inv.usageErr("Could not read the public key of " + path + " (give the private key file). Nothing was changed.")
	}
	r.pub = pub
	return nil
}

// rotatePlan prints what the rotation will do.
func (inv *invocation) rotatePlan(r *rotation) {
	o, e := r.o, r.entry
	row := func(k, v string) { inv.echo("  " + padTo(k+":", 16) + " " + v) }
	inv.echo("")
	inv.echoE(ui.Bold + "Rotate the provisioning account of " + o.name + ui.NC)
	inv.echo(ui.Rule("Rotate the provisioning account of " + o.name))
	row("Host", o.name+" (scope "+e.Scope+")")
	row("Login now", e.Target)
	if r.resume {
		row("Remove", "the old account '"+r.oldLogin+"', over "+r.newTarget+" (the registry reaches the new account already)")
		inv.echo("")
		return
	}
	row("New account", o.user+" ("+r.authText()+")")
	row("Create", hosts.UseraddLine(o.user, r.rng))
	row("Sudoers", hosts.RotateSudoersFile+": "+hosts.ProvisionerSudoersLine(o.user, r.auth))
	if r.auth == hosts.AuthKey {
		switch {
		case r.generate:
			row("Key", r.keyFile+" (does not exist; ssh-keygen -t ed25519 makes it, as you)")
		default:
			fp := r.he.Fingerprint(inv.ctx, r.pub)
			row("Key", r.keyFile+"  "+fp)
		}
		row("Proof", "a new connection as "+r.newTarget+" runs 'sudo -n id -u' and must print 0; "+inv.proofHostText(r))
	} else {
		row("Password", "typed into the host's own passwd on this terminal; tacctl never sees it")
		row("Proof", "a new connection as "+r.newTarget+" runs 'sudo id -u' (you type the password) and must print 0; "+inv.proofHostText(r))
	}
	next := e
	next.Target = r.newTarget
	next.Identity = ""
	if r.auth == hosts.AuthKey {
		next.Identity = r.keyFile
	}
	row("Order", "the key (or password) is set first and the sudoers line last; a failure takes back what this run did")
	row("Registry", e.Formatted())
	row("  becomes", next.Formatted())
	if o.removeOld {
		home := "its home is moved out of reach and made root's"
		if o.removeHome {
			home = "its home is deleted"
		}
		row("Then", "remove the old account '"+r.oldLogin+"' over "+r.newTarget+": its processes end, userdel, "+home)
	}
	inv.echo("")
}

// proofHostText says how the proof checks the host, for the plan.
func (inv *invocation) proofHostText(r *rotation) string {
	if len(r.pins) > 0 {
		return "its ssh trusts the host's pinned keys only (strict host key checking, your known_hosts is not used)"
	}
	return "no host key is pinned, so ssh goes by your own known_hosts and the keys the host shows are listed afterwards for you to confirm"
}

// pinStrings are the pinned keys as 'type base64' lines (their canonical form).
func pinStrings(pins []string) []string {
	return devreg.KeyStrings(devreg.ParseHostKeys(pins))
}

// rotateConfirm asks before anything changes (a terminal), or needs --yes.
func (inv *invocation) rotateConfirm(r *rotation) error {
	if r.o.yes {
		return nil
	}
	p := inv.app.Prompter()
	if !p.Interactive() {
		return inv.usageErr("Rotating the provisioning account of " + r.o.name + " changes the host and the registry; nothing was changed. Confirm with --yes.")
	}
	if !p.Confirm("Rotate the provisioning account of " + r.o.name + " to '" + r.o.user + "'? [y/N] ") {
		inv.app.Out.InfoE("Nothing was changed.")
		return exit(1)
	}
	if r.o.removeOld && !r.o.removeHome {
		if p.Confirm("Delete the home directory of '" + r.oldLogin + "' on " + r.o.name + " too? (No: it is kept, moved out of reach and made root's.) [y/N] ") {
			r.o.removeHome = true
		}
	}
	return nil
}

// proofProblem is why the proof failed ("" when it holds): no login, sudo
// that did not give root, or a host whose keys are not the pinned ones. The
// ssh of the proof already refused any other host when keys are pinned (it
// trusts the pinned keys only); the keys the login then read are compared
// too (the same comparison 'host target' makes), which also catches a host
// that offers more than one identity. A host with nothing pinned has nothing
// to compare with: the keys it shows are listed and the operator confirms
// them (--yes confirms).
func (inv *invocation) proofProblem(r *rotation, p hosts.Proof) string {
	a := inv.app
	name := r.o.name
	switch {
	case !p.Connected:
		return "the new login did not work (ssh did not log in, sudo refused, or the host's key is not the pinned one; see above)"
	case p.UID != "0":
		if p.UID == "" {
			return "the new login did not reach root through sudo"
		}
		return "the new login reached sudo as UID " + p.UID + ", not root"
	}
	switch v, detail := inv.comparePinnedKeys("host provisioner", name, r.pins, p.Keys, p.KeysErr); v {
	case keysUnread:
		return "the host's ssh keys could not be read over the new login, so it cannot be told to be '" + name + "'"
	case keysDiffer:
		for _, l := range detail {
			a.Out.ErrorE(l)
		}
		return "the host reached is not '" + name + "' as pinned: its ssh keys differ"
	case keysUnpinned:
		var own []devreg.HostKey
		if p.KeysErr == nil {
			own = devreg.ParsePubKeys(p.Keys)
		}
		if len(own) == 0 {
			return "no host key is pinned and the host's ssh keys could not be read, so there is nothing to confirm it is '" + name + "'"
		}
		a.Out.WarnE(name + ": no host key is pinned, so nothing but your own known_hosts vouched for the host. It answered with:")
		for _, k := range own {
			a.Out.InfoE("  " + k.Display())
		}
		if r.o.yes {
			a.Out.InfoE("--yes: continuing with these keys (tacctl host sync " + name + " pins them).")
			return ""
		}
		if !a.Prompter().Confirm("Is that the host '" + name + "'? Switch to the new account? [y/N] ") {
			return "the host's ssh keys were not confirmed"
		}
	}
	return ""
}

// rotateProofFailed takes back what this run did over the login in use, and
// says what is left if that fails or does not apply. An account this run
// created is removed with its home and its line; an adopted one (an earlier
// run made it, possibly another operator's, still in use) is never deleted:
// only the sudoers line this run added is taken out. What the run did is
// what the create script reported (st); when it reported nothing, nothing is
// deleted and the output names what may be there.
func (inv *invocation) rotateProofFailed(r *rotation, st hosts.RotateStatus, problem, line string) error {
	a := inv.app
	o, e := r.o, r.entry
	a.Logger(inv.ctx, "auth.warning", line)
	a.Out.ErrorE("The proof failed: " + problem + ".")
	file := hosts.RotateSudoersFile
	switch st.Origin {
	case hosts.OriginCreated:
		a.Out.InfoE("Removing the new account '" + o.user + "' from " + o.name + " again...")
		rm := hosts.RotateRemove{Account: o.user, RemoveHome: true, Range: r.rng, Avoid: r.avoid}
		code, _, err := r.he.RunRotateScript(inv.ctx, e.Target, e.Port, e.Identity, rm.Script())
		if err == nil && code == 0 {
			a.Out.ErrorE("The new account '" + o.user + "' and its sudoers line were removed from " + o.name + "; nothing is left there. The registry is unchanged.")
			return exit(1)
		}
		a.Out.ErrorE("The new account '" + o.user + "' could not be removed from " + o.name + ". Left there: the account '" + o.user + "' with its home, and its line in " + file + ".")
		a.Out.ErrorE("Remove them by hand (userdel -r " + o.user + ", delete its line), or run the same command again, which adopts the account. The registry is unchanged.")
	case hosts.OriginAdopted:
		a.Out.InfoE("The account '" + o.user + "' was made by an earlier run, not by this one, so it is not deleted.")
		switch st.Sudoers {
		case hosts.SudoersAdded:
			rm := hosts.RotateRemove{Account: o.user, SudoersOnly: true, Range: r.rng, Avoid: r.avoid}
			code, _, err := r.he.RunRotateScript(inv.ctx, e.Target, e.Port, e.Identity, rm.Script())
			if err == nil && code == 0 {
				a.Out.ErrorE("The sudoers line this run added for '" + o.user + "' was taken out of " + file + " on " + o.name + ". Left there: the account '" + o.user + "', its home and its key (its ~/.ssh was emptied and holds the new key only). The registry is unchanged.")
			} else {
				a.Out.ErrorE("The sudoers line this run added for '" + o.user + "' could not be taken out of " + file + " on " + o.name + ". Left there: the account '" + o.user + "' with its home and key, and that line. The registry is unchanged.")
				a.Out.ErrorE("Delete the line by hand (visudo -f " + file + "), or run the same command again.")
			}
		case hosts.SudoersChanged:
			a.Out.ErrorE("The account's sudoers line in " + file + " was replaced by this run (it had another); it is left as the rotation wrote it: check it. Left there: the account '" + o.user + "', its home and its key. The registry is unchanged.")
		default:
			a.Out.ErrorE("The account's sudoers line in " + file + " was there before this run and is left. Left there: the account '" + o.user + "', its home and its key. The registry is unchanged.")
		}
	default:
		a.Out.ErrorE("The create script did not say what it did, so nothing was removed. Check " + o.name + ": the account '" + o.user + "', its home, and its line in " + file + " may be there. The registry is unchanged.")
	}
	return exit(1)
}

// rotateRemoveOld removes the old account, last, over the new one. It
// refuses when old and new are the same, the old one is root or a tacctl
// user, or the registry does not point at the new account yet.
func (inv *invocation) rotateRemoveOld(r *rotation) error {
	a := inv.app
	o := r.o
	old := r.oldLogin
	_, _, oldIsUser, err := inv.provisioningLogin(old + "@x")
	if err != nil {
		return err
	}
	reg, err := inv.registry()
	if err != nil {
		return err
	}
	cur, _ := reg.Find(o.name)
	if why := removeOldRefusal(old, o.user, oldIsUser, cur.Target); why != "" {
		return inv.usageErr(why)
	}
	a.Out.InfoE("Removing the old account '" + old + "' from " + o.name + " over " + targetText(cur) + "...")
	rm := hosts.RotateRemove{Account: old, RemoveHome: o.removeHome, Range: r.rng, Avoid: r.avoid}
	he := r.he
	he.KeepOpen = false
	code, _, err := he.RunRotateScript(inv.ctx, cur.Target, cur.Port, cur.Identity, rm.Script())
	if err != nil {
		if errors.Is(err, ui.ErrInterrupted) {
			a.Out.WarnE("Interrupted. The registry reaches " + o.name + " as '" + o.user + "'; the old account '" + old + "' may still be there: " + inv.rotateCommandLine(r) + " --remove-old")
		}
		return err
	}
	if code != 0 {
		a.Out.ErrorE("The old account '" + old + "' could not be removed from " + o.name + " (see above). The registry already reaches the new account; left on the host: '" + old + "' and what the output above names.")
		a.Out.ErrorE("Try again: " + inv.rotateCommandLine(r) + " --remove-old")
		return exit(1)
	}
	if err := inv.hostRecords().Update(o.name, func(rec *hosts.Record) {
		if rec.Provisioner != nil && rec.Provisioner.New == o.user {
			rec.Provisioner.OldRemoved = true
		}
	}); err != nil {
		a.Out.WarnE(o.name + ": the record could not be written: " + strings.Join(msgs(err), " "))
	}
	a.Logger(inv.ctx, "auth.info", "host provisioner remove-old name="+o.name+" old="+old+" new="+o.user+" by="+inv.sudoUser())
	a.Out.InfoE("The old account '" + old + "' is removed from " + o.name + ".")
	return nil
}

// removeOldRefusal is why the old account of a rotation is not removed ("" when
// it is): there is none to name, it is the new account, it is root (nothing to
// remove), it is a user of tacctl (its account belongs to 'host sync'), or the
// registry (regTarget) does not point at the new account yet.
func removeOldRefusal(old, newUser string, oldIsTacctlUser bool, regTarget string) string {
	switch {
	case old == "":
		return "There is no old account to remove."
	case old == newUser:
		return "The old and the new account are both '" + newUser + "'; nothing was removed."
	case old == "root":
		return "The old login is 'root'; there is nothing to remove."
	case oldIsTacctlUser:
		return "The old login '" + old + "' is a tacctl user; its account belongs to 'host sync' and is not removed here."
	case !strings.HasPrefix(regTarget, newUser+"@"):
		return "The registry does not reach the host as '" + newUser + "' yet; the old account '" + old + "' is not removed."
	}
	return ""
}

// rotateDryRun prints the plan and reads what it can from the host without
// changing anything: a test login to the current target, whether the new
// account exists, and the host's password setting.
func (inv *invocation) rotateDryRun(r *rotation) error {
	a := inv.app
	o, e := r.o, r.entry
	inv.rotatePlan(r)
	he := r.he
	a.Out.InfoE("Dry run: testing " + o.name + " at " + targetText(e) + "...")
	p := he.TestTarget(inv.ctx, e.Target, e.Port, e.Identity)
	if inv.ctx.Err() != nil {
		return ui.ErrInterrupted
	}
	if !p.Connected {
		return inv.usageErr("Could not log in to " + targetText(e) + " (ssh failed, see above); the rotation would fail the same way.")
	}
	switch p.Root {
	case "root":
		a.Out.InfoE("The login on " + o.name + " is root.")
	case "sudo":
		a.Out.InfoE("The login on " + o.name + " reaches root through sudo without a password.")
	case "sudo-password":
		if he.TTYAvailable() {
			a.Out.WarnE("sudo on " + o.name + " asks for a password (or the login may not sudo); the rotation asks for it on this terminal.")
		} else {
			a.Out.WarnE("sudo on " + o.name + " asks for a password (or the login may not sudo) and there is no terminal; the rotation would fail.")
		}
	}
	accounts, err := he.Accounts(inv.ctx, e.Target, e.Port, e.Identity)
	switch {
	case err != nil:
		a.Out.WarnE("Could not list the accounts of " + o.name + " (getent passwd failed).")
	default:
		var found *hosts.Account
		for i := range accounts {
			if accounts[i].Name == o.user {
				found = &accounts[i]
			}
		}
		if found == nil {
			a.Out.InfoE("No account '" + o.user + "' on " + o.name + "; the rotation creates it.")
		} else {
			// Root's record on the host proves an account is tacctl's; the
			// comment field does not.
			acct, uid, ok := he.RotateState(inv.ctx, e.Target, e.Port, e.Identity, o.user)
			ok = ok && acct == o.user
			switch {
			case ok && uid == found.UID:
				a.Out.InfoE("The account '" + o.user + "' (UID " + found.UID + ") was made by tacctl (root's record on " + o.name + " agrees); the rotation adopts it and empties its ~/.ssh.")
			case ok:
				a.Out.ErrorE("An account '" + o.user + "' (UID " + found.UID + ") exists on " + o.name + " and root's record of it names UID " + uid + "; the rotation would refuse it.")
			default:
				a.Out.ErrorE("An account '" + o.user + "' (UID " + found.UID + ") exists on " + o.name + " and no readable record shows that tacctl made it (the comment field is not proof); the rotation would refuse it.")
			}
		}
	}
	if v, ok := he.SSHDPasswordAuth(inv.ctx, e.Target, e.Port, e.Identity); ok {
		msg := "sshd on " + o.name + ": passwordauthentication " + v
		if v == "no" && r.auth == hosts.AuthPassword {
			a.Out.WarnE(msg + "; a --password proof would always fail there.")
		} else {
			a.Out.InfoE(msg)
		}
	} else {
		a.Out.InfoE("sshd on " + o.name + ": passwordauthentication could not be read (it needs root there).")
	}
	he.CloseSession(inv.ctx, e.Target, e.Port, e.Identity)
	a.Out.InfoE("Dry run: nothing was changed.")
	return nil
}
