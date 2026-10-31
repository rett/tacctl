package cli

// The emergency lockdown on the enrolled hosts (0.2.23, D309-D311). The
// devices are closed by the render (emergency.go); a Linux host is closed by
// one sshd drop-in that the client script writes at a 'host sync' (the header's
// TAC_LOCKDOWN, hosts.Script.Lockdown), so 'enable' and 'disable' change the
// devices as before and then offer the sync of the scope's hosts.
//
// The record keeps the hosts the drop-in is not settled on in
// emergency.lockdown.<scope>.pending: at 'enable' every host of the scope
// (the lockdown has not reached it), at a full 'disable' every enrolled host
// of the scope (a host on the list may still hold the file: a failed enrolment
// after the script wrote it, a dropped connection; a sync of a host that has
// none removes nothing). The hosts are read inside the record's own update,
// after the name was typed, not when the plan was made. A successful sync or
// enrolment of a host takes it off the list, but only when the script it ran
// was written for what the record still says (a sync started before a
// 'disable' must not clear the host the 'disable' just listed); a list that
// empties on a record with no group removes the record. A record with no group and a list is a lifted lockdown
// whose hosts still hold the drop-in: it locks nothing on the devices, is
// shown by 'status', and is completed by the same sync. The host a sync
// finds on the list of a standing lockdown gets TAC_LOCKDOWN=on-end (the
// drop-in and the end of the live sessions: the 'enable' step it missed);
// one that is not on it gets "on", so a sync later never ends a session.

import (
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/ui"
)

// lockdownHostNames are the names of the hosts enrolled in scope, sorted.
func (inv *invocation) lockdownHostNames(scope string) []string {
	reg, err := inv.registry()
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range reg.Entries() {
		if e.Scope == scope {
			out = append(out, e.Name)
		}
	}
	sort.Strings(out)
	return out
}

// lockdownState is the TAC_LOCKDOWN a script for a host of scope gets: ""
// when the scope is not locked down (the script removes the drop-in), "on" for
// a host the drop-in has reached or that is not one of the scope's yet (a
// script written by hand), "on-end" for a host still waiting for the step that
// began the lockdown.
func (inv *invocation) lockdownState(scope, host string) string {
	if l := inv.lockdownOf(scope); l != nil {
		return lockdownImplied(*l, host)
	}
	return ""
}

// lockdownImplied is the TAC_LOCKDOWN a host gets from a record: "" for a
// lifted one, on-end for a host on the list of a standing one, on for any
// other host of it (or one that is not named, a script written by hand).
func lockdownImplied(l conf.Lockdown, host string) string {
	switch {
	case len(l.Groups) == 0:
		return ""
	case host != "" && slices.Contains(l.Pending, host):
		return hosts.LockdownOnEnd
	}
	return hosts.LockdownOn
}

// lockdownRecordOf is the record of scope that stands or is lifted with hosts
// still to sync (nil: none).
func (inv *invocation) lockdownRecordOf(scope string) *conf.Lockdown {
	if l := inv.lockdownOf(scope); l != nil {
		return l
	}
	for _, l := range inv.app.Conf().LockdownLifts() {
		if l.Scope == scope {
			l := l
			return &l
		}
	}
	return nil
}

// lockdownWaiting are the hosts of the record's list that are still enrolled
// in its scope, sorted: a host that was forgotten or moved is no one to wait
// for.
func (inv *invocation) lockdownWaiting(l conf.Lockdown) []string {
	enrolled := inv.lockdownHostNames(l.Scope)
	var out []string
	for _, n := range l.Pending {
		if slices.Contains(enrolled, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// lockdownHostDone takes the host off the list of its scope's record after a
// sync or an enrolment that succeeded. A record left with no group and no
// host is the end of a lifted lockdown and goes. It says nothing when the
// host was not on a list.
//
// sent is the TAC_LOCKDOWN value (hosts.Lockdown*, "" for none) the script that
// succeeded was written with. The host comes off the list only when that is
// what the record implies for it now: "on-end" for a host on the list of a
// standing lockdown, "on" for another host of it, "" for a lifted record or
// none.
func (inv *invocation) lockdownHostDone(e hosts.Entry, sent string) {
	inv.lockdownEditPending(e.Scope, func(cur conf.Lockdown) []string {
		if lockdownImplied(cur, e.Name) != sent {
			return cur.Pending
		}
		return slices.DeleteFunc(slices.Clone(cur.Pending), func(n string) bool { return n == e.Name })
	})
}

// lockdownHostGone takes a forgotten or unenrolled host off every list.
func (inv *invocation) lockdownHostGone(name string) {
	for _, l := range append(inv.app.Conf().Lockdowns(), inv.app.Conf().LockdownLifts()...) {
		inv.lockdownEditPending(l.Scope, func(cur conf.Lockdown) []string {
			return slices.DeleteFunc(slices.Clone(cur.Pending), func(n string) bool { return n == name })
		})
	}
}

// lockdownHostRenamed follows a host's rename on every list.
func (inv *invocation) lockdownHostRenamed(oldName, newName string) {
	for _, l := range append(inv.app.Conf().Lockdowns(), inv.app.Conf().LockdownLifts()...) {
		inv.lockdownEditPending(l.Scope, func(cur conf.Lockdown) []string {
			out := slices.Clone(cur.Pending)
			for i, n := range out {
				if n == oldName {
					out[i] = newName
				}
			}
			return out
		})
	}
}

// lockdownEditPending rewrites the list of a scope's record with fn; a record
// that ends with no group and no host is removed. The record is not written
// when nothing changes. A failure is a warning: the list is a hint for the
// next sync, never the lockdown itself.
func (inv *invocation) lockdownEditPending(scope string, fn func(cur conf.Lockdown) []string) {
	err := inv.app.Conf().UpdateLockdown(scope, func(cur *conf.Lockdown) (*conf.Lockdown, error) {
		if cur == nil {
			return nil, nil
		}
		next := *cur
		next.Pending = fn(*cur)
		if len(next.Pending) == 0 {
			next.Pending = nil
		}
		if len(next.Groups) == 0 && len(next.Pending) == 0 {
			return nil, nil
		}
		return &next, nil
	})
	if err != nil {
		inv.app.Out.WarnE("The list of hosts the lockdown of scope '" + scope + "' waits for could not be written: " + msgsJoin(err) + ". Run: tacctl host sync --all")
	}
}

// lockdownHostsSyncCommand is the command that syncs the hosts: their names,
// or --all when they are many (hostsSyncCommand's rule).
func lockdownHostsSyncCommand(names []string) string {
	if len(names) > 4 {
		return "tacctl host sync --all"
	}
	return "tacctl host sync " + strings.Join(names, " ")
}

// lockdownWaitingHosts are the entries of the hosts the records of scopes
// wait for, in registry order.
func (inv *invocation) lockdownWaitingHosts(scopes []string) []hosts.Entry {
	reg, err := inv.registry()
	if err != nil {
		return nil
	}
	waiting := map[string]bool{}
	for _, s := range scopes {
		if l := inv.lockdownRecordOf(s); l != nil {
			for _, n := range inv.lockdownWaiting(*l) {
				waiting[s+"\x00"+n] = true
			}
		}
	}
	var out []hosts.Entry
	for _, e := range reg.Entries() {
		if waiting[e.Scope+"\x00"+e.Name] {
			out = append(out, e)
		}
	}
	return out
}

// lockdownHostsStep is what 'enable' and 'disable' end with: the hosts of the
// scopes that the sshd drop-in has not been settled on are named with the
// command, and a terminal is asked whether to sync them now. The answer is
// never taken from an option but the long --yes (yes), and with no terminal
// the notice is all and nothing runs. What the sync leaves is named again with
// the command. The audit line says which hosts were waiting and which still
// are, never an account. The error it returns is an interrupt only.
func (inv *invocation) lockdownHostsStep(scopes []string, enable, yes bool) error {
	// hosts that are not enrolled any more are no one to wait for
	for _, s := range scopes {
		if l := inv.lockdownRecordOf(s); l != nil && len(inv.lockdownWaiting(*l)) != len(l.Pending) {
			enrolled := inv.lockdownHostNames(s)
			inv.lockdownEditPending(s, func(cur conf.Lockdown) []string {
				return slices.DeleteFunc(slices.Clone(cur.Pending), func(n string) bool { return !slices.Contains(enrolled, n) })
			})
		}
	}
	waiting := inv.lockdownWaitingHosts(scopes)
	if len(waiting) == 0 {
		return nil
	}
	a := inv.app
	names := hostNames(waiting)
	cmd := lockdownHostsSyncCommand(names)
	var cause, done string
	if enable {
		cause = "The lockdown has not reached " + hostsText(len(names)) + " (ssh key logins, forwarding and open sessions of the accounts that are not superusers stay open there)"
		done = "The lockdown is in force on the hosts."
	} else {
		cause = "sshd's lockdown drop-in is still on " + hostsText(len(names))
		done = "The lockdown is lifted on the hosts."
	}
	action := map[bool]string{true: "enable", false: "disable"}[enable]
	if yes {
		a.Out.InfoE(cause + ": syncing them now (--yes)")
	} else {
		a.Out.WarnE(cause + ": " + cmd)
	}
	synced := false
	if yes || a.Prompter().Interactive() && a.Prompter().Confirm("  Sync these hosts now? [y/N]: ") {
		synced = true
		// Held hosts are not logged in to: they are said and stay waiting.
		reg, err := inv.registry()
		if err != nil {
			return err
		}
		try, err := inv.hostSkipHeld(reg, names, "the lockdown")
		if err != nil {
			a.Out.WarnE("The hosts were not synced: " + msgsJoin(err) + ". " + cmd)
			try = nil
		}
		if len(try) > 0 {
			// The sync of these hosts shows its own output, as 'host sync'
			// does: a host's ssh or sudo may ask for a password here.
			if err := inv.hostSync(try); errors.Is(err, ui.ErrInterrupted) {
				return err
			}
		}
	}
	var left []string
	for _, e := range inv.lockdownWaitingHosts(scopes) {
		left = append(left, e.Name)
	}
	kv := []audit.KV{kvp("action", action), kvp("scopes", strings.Join(scopes, ",")), kvp("hosts", strings.Join(names, ",")),
		kvp("synced", yesNo(synced)), kvp("pending", strings.Join(left, ","))}
	inv.detailAt(audit.Notice, "emergency lockdown hosts", kv...)
	switch {
	case len(left) > 0 && synced:
		a.Out.WarnE(hostsText(len(left)) + " not settled (" + strings.Join(left, ", ") + "; see above; a host that is held, unreachable or refused stays on the lockdown's list): " + lockdownHostsSyncCommand(left))
	case len(left) == 0:
		a.Out.InfoE(done)
	}
	return nil
}

// lockdownHeld is what a restore of a snapshot has to know of the lockdowns
// that stand before it: each scope that has a record (standing, with its
// groups, or lifted, with none) is a scope whose hosts may hold sshd's
// drop-in.
func (inv *invocation) lockdownHeld() map[string][]string {
	out := map[string][]string{}
	for _, l := range inv.app.Conf().Lockdowns() {
		out[l.Scope] = l.Groups
	}
	for _, l := range inv.app.Conf().LockdownLifts() {
		out[l.Scope] = nil
	}
	return out
}

// lockdownAfterRestore makes the record of every scope whose lockdown the
// restore changed say what the hosts need: the hosts keep sshd's drop-in
// whatever tacctl.yaml says, so a restore that ends a lockdown (a snapshot taken
// before it) leaves a lifted record that lists every enrolled host of the scope
// (the next host sync removes the file), and one that brings a lockdown back or
// changes its groups lists every host as waiting. A scope whose standing
// lockdown is the same is left as the snapshot has it. It returns the hosts that
// were listed, by name, for the report.
func (inv *invocation) lockdownAfterRestore(before map[string][]string) []string {
	c := inv.app.Conf()
	after := conf.Load(inv.app.Paths.Overrides, inv.app.Backends().IDs())
	stands := map[string][]string{}
	for _, l := range after.Lockdowns() {
		stands[l.Scope] = l.Groups
	}
	scopes := map[string]bool{}
	for sc := range before {
		scopes[sc] = true
	}
	for sc := range stands {
		scopes[sc] = true
	}
	var listed []string
	by, now := inv.sudoUser(), inv.app.Knobs.Now().Format(time.RFC3339)
	for sc := range scopes {
		bg, held := before[sc]
		ag, standing := stands[sc]
		if standing && held && bg != nil && slices.Equal(bg, ag) {
			continue
		}
		if !standing && !held {
			continue
		}
		hostNames := inv.lockdownHostNames(sc)
		err := c.UpdateLockdown(sc, func(cur *conf.Lockdown) (*conf.Lockdown, error) {
			var next conf.Lockdown
			switch {
			case cur != nil && len(cur.Groups) > 0:
				next = *cur
			default:
				if len(hostNames) == 0 {
					return nil, nil
				}
				next = conf.Lockdown{Scope: sc, Since: now, By: by}
			}
			next.Pending = hostNames
			return &next, nil
		})
		if err != nil {
			inv.app.Out.WarnE("The list of hosts the lockdown of scope '" + sc + "' waits for could not be written after the restore: " + msgsJoin(err) + ". Run: tacctl host sync --all")
			continue
		}
		listed = append(listed, hostNames...)
	}
	sort.Strings(listed)
	return slices.Compact(listed)
}
