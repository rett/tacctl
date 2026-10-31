package lifecycle

// The emergency lockdown on the enrolled hosts (0.2.23, D309-D311) in a
// rollback. A host is closed by an sshd drop-in that only the client script of
// this release writes and removes, and the record keeps the hosts the drop-in
// has not been settled on (emergency.lockdown.<scope>.pending, a leaf every
// older schema refuses). A release before 0.2.23 cannot lift a lockdown on a
// host: its 'emergency lockdown disable' renders the devices and its 'host
// sync' never removes the file, so the host would stay closed with nothing
// that says so. Every target is therefore refused, in the dry run and --apply
// alike, while a lockdown stands on a scope that has an enrolled host, or a
// lifted one still waits for a host to drop the file; the lockdowns of scopes
// with no host, which the 0.2.19 to 0.2.22 targets take over as they stand,
// are not stopped.

import (
	"slices"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/hosts"
)

// planLockdownHosts refuses the rollback while a lockdown has hosts.
func (p *RollbackPlan) planLockdownHosts() error {
	c := p.in.Conf
	standing, lifts := c.Lockdowns(), c.LockdownLifts()
	if len(standing) == 0 && len(lifts) == 0 {
		return nil
	}
	reg, err := hosts.LoadRegistry(p.in.Paths.LinuxHosts)
	if err != nil {
		return &RollbackRefusal{Lines: []string{p.in.Paths.LinuxHosts + " cannot be read (" + strings.TrimSuffix(err.Error(), ".") + "), so the hosts of a lockdown cannot be ruled out; fix it first."}}
	}
	byScope := map[string][]string{}
	for _, e := range reg.Entries() {
		byScope[e.Scope] = append(byScope[e.Scope], e.Name)
	}
	var lines []string
	var sync []string
	var waiting []string
	for _, l := range standing {
		names := slices.Clone(byScope[l.Scope])
		if len(names) == 0 {
			continue
		}
		sort.Strings(names)
		lines = append(lines, "Scope "+l.Scope+" is locked down and has enrolled hosts ("+strings.Join(names, ", ")+"): the lockdown is an sshd drop-in on them.")
		sync = append(sync, "tacctl emergency lockdown "+l.Scope+" disable")
	}
	for _, l := range lifts {
		for _, n := range l.Pending {
			if slices.Contains(byScope[l.Scope], n) {
				waiting = append(waiting, n)
			}
		}
	}
	if len(waiting) > 0 {
		sort.Strings(waiting)
		lines = append(lines, "A lockdown that was lifted still has its sshd drop-in on "+strings.Join(waiting, ", ")+".")
	}
	// a list that names hosts that are not enrolled any more is a leaf the
	// older schema refuses, and the next 'enable' or 'disable' of the scope
	// drops it
	var stale []string
	for _, l := range append(slices.Clone(standing), lifts...) {
		var gone []string
		for _, n := range l.Pending {
			if !slices.Contains(byScope[l.Scope], n) {
				gone = append(gone, n)
			}
		}
		if len(gone) == 0 {
			continue
		}
		lines = append(lines, "The list of hosts the lockdown of scope "+l.Scope+" waits for names hosts that are not enrolled any more ("+strings.Join(gone, ", ")+"): "+p.target()+" refuses it.")
		if len(l.Groups) > 0 {
			stale = append(stale, "tacctl emergency lockdown "+l.Scope+" enable "+strings.Join(l.Groups, ","))
		} else {
			stale = append(stale, "tacctl emergency lockdown "+l.Scope+" disable")
		}
	}
	if len(lines) == 0 {
		return nil
	}
	var then []string
	if len(sync) > 0 {
		then = append(then, strings.Join(sync, "; "))
	}
	all := append(slices.Clone(waiting), hostsOfLockdowns(standing, byScope)...)
	sort.Strings(all)
	all = slices.Compact(all)
	if len(all) > 0 {
		then = append(then, "tacctl host sync "+strings.Join(all, " "))
		lines = append(lines, p.target()+" cannot lift a lockdown on a host: it does not write or remove the drop-in, so the hosts would stay closed.")
	}
	then = append(then, stale...)
	lines = append(lines, "Lift it first and sync the hosts: "+strings.Join(then, "; ")+". Nothing was changed.")
	return &RollbackRefusal{Lines: lines}
}

// hostsOfLockdowns are the hosts of the scopes that the standing lockdowns lock.
func hostsOfLockdowns(standing []conf.Lockdown, byScope map[string][]string) []string {
	var out []string
	for _, l := range standing {
		out = append(out, byScope[l.Scope]...)
	}
	return out
}
