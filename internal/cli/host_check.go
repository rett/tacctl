package cli

// 'host show <name> --check': log in to the host read-only, as 'host
// target' tests a login (the invoking user's ssh; sudo, with a terminal
// for its password), and compare it with what tacctl would make it: the
// tac groups and their GIDs, who is in the sudo groups, each account's UID, primary group and home
// mode, the PAM files tacctl writes, the client script protocol and the
// host's ssh keys against the pins. Nothing changes there or here. Each
// difference is one line with the command that fixes it.

import (
	"context"
	"strconv"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// reenrollCommand is the enroll that writes the host's PAM files again
// (scope, server and method are kept from the registry).
func reenrollCommand(e hosts.Entry) string {
	if e.Target == hosts.Local {
		return "tacctl host enroll --local --name " + e.Name
	}
	c := "tacctl host enroll " + e.Target + " --name " + e.Name
	if e.Port != "" {
		c += " --port " + e.Port
	}
	if e.Identity != "" {
		c += " --identity " + e.Identity
	}
	return c
}

// hostCheck reads e as root over ssh and compares it with v (the accounts
// the next sync makes). A login or sudo that fails is an error (exit 1)
// after its message. For --json (toStderr) what the host prints besides
// the check (a banner, ssh's messages) goes to stderr, so stdout is the
// JSON alone.
func (inv *invocation) hostCheck(e hosts.Entry, v *hostShowJSON, toStderr bool) (*hostCheckJSON, error) {
	c, failed, err := inv.hostCheckRun(inv.ctx, inv.hostCheckEnv(inv.sequentialStep(), toStderr), e, v)
	if err != nil {
		return nil, err
	}
	if failed != "" {
		return nil, inv.usageErr("Could not check " + e.Name + ": " + failed)
	}
	return c, nil
}

// hostCheckEnv is the environment of a read-only run: what the host prints
// besides the check goes to stderr when toStderr.
func (inv *invocation) hostCheckEnv(st *hostStep, toStderr bool) *hosts.Env {
	he := inv.hostsEnv()
	if toStderr {
		he.Out = ui.Output{Stdout: inv.app.Out.Stderr, Stderr: inv.app.Out.Stderr}
	}
	st.quiet(he)
	return he
}

// hostCheckRun is hostCheck's run in he: failed says why the read-only run
// did not complete ("" when it did; nothing was compared then), err is what
// ends the command (an interrupt, a registry that cannot be read). It uses
// nothing of the invocation that another host's run changes, so hosts can
// run side by side.
func (inv *invocation) hostCheckRun(ctx context.Context, he *hosts.Env, e hosts.Entry, v *hostShowJSON) (c *hostCheckJSON, failed string, err error) {
	a := inv.app
	local := e.Target == hosts.Local
	rng := he.UIDRange()
	names := make([]string, 0, len(v.Accounts.Users))
	for _, u := range v.Accounts.Users {
		names = append(names, u.Name)
	}
	if !local {
		he.Out.InfoE("Checking " + e.Name + " at " + targetText(e) + " (read-only)...")
	}
	st, code, err := he.Check(ctx, e.Target, e.Port, e.Identity, names)
	if err != nil {
		return nil, "", err
	}
	if ctx.Err() != nil {
		return nil, "", ui.ErrInterrupted
	}
	if code != 0 {
		where := "this server"
		if !local {
			where = targetText(e)
		}
		return nil, "the read-only run as root on " + where + " failed (see above); nothing was compared.", nil
	}

	c = &hostCheckJSON{Differences: []hostDiffJSON{}, Notes: []string{}}
	sync := "tacctl host sync " + e.Name
	diff := func(text, fix string) { c.Differences = append(c.Differences, hostDiffJSON{Text: text, Fix: fix}) }

	// The groups and their fixed GIDs.
	for _, g := range hosts.HostGroups(local) {
		want := strconv.Itoa(hosts.GroupGID(g, rng))
		switch got, ok := st.Groups[g]; {
		case !ok:
			diff("group "+g+" is missing", sync)
		case got != want:
			diff("group "+g+" has GID "+got+", not "+want, sync)
		}
	}
	// The accounts.
	usersGID := strconv.Itoa(hosts.GroupGID("tac-users", rng))
	for _, u := range v.Accounts.Users {
		acct := st.Accounts[u.Name]
		if !acct.Exists {
			diff(u.Name+" has no account", sync)
			continue
		}
		if u.UID != "" && acct.UID != u.UID {
			diff(u.Name+" has UID "+acct.UID+", not "+u.UID, sync)
		}
		if acct.GID != usersGID {
			diff(u.Name+"'s primary group is GID "+acct.GID+", not tac-users ("+usersGID+")", sync)
		}
		if mode, err := strconv.ParseUint(acct.HomeMode, 8, 32); err == nil && mode&0o077 != 0 {
			diff(u.Name+"'s home "+acct.Home+" is 0"+acct.HomeMode+", open to others (tacctl makes it private: 0700)", sync)
		}
	}
	// An engineer still in tac-superuser (full sudo) from before the engineer
	// tier: the next sync moves them to tac-engineer.
	super := map[string]bool{}
	for _, m := range st.Members["tac-superuser"] {
		super[m] = true
	}
	for _, u := range v.Accounts.Users {
		if u.Tier == string(tier.Engineer) && super[u.Name] {
			diff(u.Name+" is an engineer but is still in tac-superuser (full sudo; the engineer tier gets tac-engineer)", sync)
		}
	}
	// The PAM files tacctl writes, as it wrote them.
	reenroll := reenrollCommand(e)
	present := true
	for _, f := range hosts.PAMFiles {
		sum := st.PAM[f]
		switch written, ok := st.PAMWritten[f]; {
		case sum == "":
			diff("/etc/pam.d/"+f+" is missing", reenroll)
			present = false
		case ok && written != sum:
			diff("/etc/pam.d/"+f+" is not the text tacctl wrote there", reenroll)
		}
	}
	if present && len(st.PAMWritten) == 0 {
		c.Notes = append(c.Notes, "The PAM files are there; the host has no record of the text tacctl wrote (enrolled before 0.2.2), so it was not compared. Enrolling it again records it: "+reenroll)
	}
	// The client script protocol.
	switch st.Protocol {
	case hosts.ScriptProtocol:
	case "":
		diff("the host has no record of the client script protocol it ran (last enrolled or synced before 0.2.2)", sync)
	default:
		diff("the host ran client script protocol "+st.Protocol+"; this tacctl writes "+hosts.ScriptProtocol, sync)
	}
	// sshd's lockdown drop-in against the scope's lockdown.
	locked := inv.lockdownState(e.Scope, e.Name) != ""
	switch {
	case st.Lockdown == "unreloaded":
		diff("the host's lockdown drop-in was removed but sshd was not told to reload it, so it may still enforce the lockdown", sync)
	case st.Lockdown == "nosshd" && locked:
		// a sync cannot change it: there is nothing to close
		c.Notes = append(c.Notes, "Scope "+e.Scope+" is locked down; "+e.Name+" has no sshd, so there is no ssh login to close and the lockdown writes no drop-in there.")
	case st.Lockdown == "noinclude" && locked:
		diff("scope "+e.Scope+" is locked down, but the host's sshd_config does not include sshd_config.d, so the lockdown cannot be applied (key logins and forwarding are open there)", "add the Include line (OpenSSH 8.2 or later) or close those logins another way, then: "+sync)
	case st.Lockdown == "absent" && locked:
		if login, _, isUser, perr := inv.provisioningLogin(e.Target); perr == nil && isUser && e.Target != hosts.Local {
			if m, merr := inv.model(); merr == nil {
				if u := m.User(login); u != nil && !inv.groupIsSuperuser(m, u.Group) {
					diff("scope "+e.Scope+" is locked down, but the host is provisioned through '"+login+"', a tacctl user that is not a superuser, so the sync refuses to lock it down (it would close its own key)", "enroll it through a local account: tacctl host enroll <account>@<host> --name "+e.Name)
					break
				}
			}
		}
		diff("scope "+e.Scope+" is locked down, but the host has no lockdown drop-in (key logins and forwarding are open there)", sync)
	case st.Lockdown == "present" && !locked:
		diff("the host has sshd's lockdown drop-in, but scope "+e.Scope+" is not locked down", sync)
	}
	// The host's keys against the pins (this server is not reached over ssh).
	if !local {
		f, err := devreg.Load(a.Paths.DevicesFile)
		if err != nil {
			return nil, "", err
		}
		pinned := f.HostKeysOf(e.Name)
		own := devreg.ParsePubKeys(st.Keys)
		accept := "check on the host (" + devreg.VerifyHint(devreg.VendorLinux) + "), then: tacctl device hostkey " + e.Name + " accept"
		cmp := devreg.Compare(pinned, own)
		switch {
		case len(own) == 0:
			diff("the host's ssh keys (/etc/ssh/ssh_host_*_key.pub) could not be read", "check them on the host: "+devreg.VerifyHint(devreg.VendorLinux))
		case len(pinned) == 0:
			diff("no host key is pinned for "+e.Name, sync)
		case cmp.Changed:
			diff("the host's ssh keys differ from the pinned ones (pinned: "+devreg.Displays(devreg.ParseHostKeys(pinned))+"; on the host: "+devreg.Displays(own)+")", accept)
		default:
			if len(cmp.Added) > 0 {
				diff("the host has keys of types not pinned: "+devreg.Displays(cmp.Added), accept)
			}
			if len(cmp.Missing) > 0 {
				diff("pinned keys the host no longer has: "+devreg.Displays(cmp.Missing), accept)
			}
		}
	}
	return c, "", nil
}

// hostCheckText prints the findings of --check.
func (inv *invocation) hostCheckText(v *hostShowJSON) {
	c := v.Check
	inv.echo("Check (read on the host now)")
	if len(c.Differences) == 0 {
		inv.echo("  " + v.Name + " is as tacctl would make it.")
	}
	for _, d := range c.Differences {
		inv.echo("  - " + d.Text + ". Fix: " + d.Fix)
	}
	for _, n := range c.Notes {
		inv.echo("  " + n)
	}
	if n := len(c.Differences); n > 0 {
		inv.echo("  " + howMany(n, "difference") + ".")
	}
	inv.echo("")
}
