package lifecycle

// The scope of this server's own login (0.2.21, pwchange.ManagedScope) in a
// rollback. This release makes every user a member of the scope the server
// is registered in when tacctl manages it, without the scope in the user's
// own list in store.yaml. Every earlier release answers the server's logins
// (the console, the server's Linux accounts) only for the users that have
// the scope in their own list; the scope itself, its name, its prefixes and
// its secret are ones every earlier release reads as an ordinary scope. So
// each target keeps the users' server login by adding the scope to the
// scopes of every user who is a member of it now and lacks it (the users
// pwchange.Implicit names: not the accounting sink, a name that can be a
// Linux account, a tier other than none), after the snapshot --apply takes
// first. It is a warning (--yes): the older release lists the scope with
// each user, and a user who leaves it there keeps the server login.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
)

// planManagedScope reads the registry and the store for the users the
// managed scope is to be added to. Nothing when the server is not registered
// in it, the scope is not in the store, or there is no store; a registry or
// a store that cannot be read is an error (the users' server login must not
// be lost unseen).
func (p *RollbackPlan) planManagedScope() error {
	if !p.in.HasStore {
		return nil
	}
	pa := p.in.Paths
	reg, err := hosts.LoadRegistry(pa.LinuxHosts)
	if err != nil {
		return &RollbackRefusal{Lines: []string{pa.LinuxHosts + " cannot be read, so the users' login to this server cannot be kept (" + strings.TrimSuffix(err.Error(), ".") + "); fix it first."}}
	}
	local := false
	for _, e := range reg.Entries() {
		if e.Target == hosts.Local && e.Scope == pwchange.ManagedScope {
			local = true
		}
	}
	if !local {
		return nil
	}
	_, m, err := model.LoadStore(pa.StoreFile)
	if err != nil {
		return &RollbackRefusal{Lines: []string{pa.StoreFile + " cannot be read, so the users' login to this server cannot be kept (" + strings.TrimSuffix(err.Error(), ".") + "); fix it first (tacctl config validate)."}}
	}
	if m.Scope(pwchange.ManagedScope) == nil {
		return nil
	}
	for _, u := range m.Users {
		if !slices.Contains(u.Scopes, pwchange.ManagedScope) && pwchange.Implicit(p.in.Conf, m, u) {
			p.managedUsers = append(p.managedUsers, u.Name)
		}
	}
	slices.Sort(p.managedUsers)
	return nil
}

// addManagedScope adds the step and the warning of the managed scope to the
// plan of any target, before the step of the required password change (both
// write the store; this one is a step of its own).
func (p *RollbackPlan) addManagedScope() {
	if len(p.managedUsers) == 0 {
		return
	}
	target, sf, n := p.target(), p.in.Paths.StoreFile, len(p.managedUsers)
	s := RollbackStep{Title: sf + ": add scope '" + pwchange.ManagedScope + "' to the users' own scopes", Todo: true,
		Lines: []string{"add scope " + pwchange.ManagedScope + " to " + strconv.Itoa(n) + " " + plural(n, "user", "users") + ": " + strings.Join(p.managedUsers, ", "),
			"(this release lets every user log in to this server through scope " + pwchange.ManagedScope + ", which it manages; " + target + " answers only the users that have it in their own scopes)"}}
	at := len(p.Steps)
	for i := range p.Steps {
		switch p.Steps[i].Title {
		case "leave " + sf + " untouched":
			p.Steps = slices.Delete(p.Steps, i, i+1)
			at = i
		case "leave every other file untouched":
			at = i
			if len(p.Steps[i].Lines) > 0 {
				p.Steps[i].Lines[0] = strings.Replace(p.Steps[i].Lines[0], sf+", ", "", 1)
			}
		default:
			continue
		}
		break
	}
	p.Steps = slices.Insert(p.Steps, at, s)
	p.Warnings = append(p.Warnings, RollbackWarning{
		Title: "Every user gets the scope of this server's own login in the store",
		Lines: []string{
			strconv.Itoa(n) + " " + plural(n, "user logs", "users log") + " in to this server (the console, its Linux accounts) without scope " + pwchange.ManagedScope + " in " + plural(n, "its", "their") + " own scopes; " +
				target + " needs it there, so it is added to " + plural(n, "that user's", "each one's") + " scopes and " + target + " lists it with them.",
			"Taking it off a user there takes the user's login to this server away. The scopes stay as they were in the snapshot --apply takes first (tacctl backup list).",
		}})
}

// applyManagedScope is the write of addManagedScope's step.
func (p *RollbackPlan) applyManagedScope() (string, error) {
	if len(p.managedUsers) == 0 {
		return "", nil
	}
	sf := p.in.Paths.StoreFile
	added, err := store.RollbackAddScope(sf, pwchange.ManagedScope, p.managedUsers)
	if err != nil {
		return "", err
	}
	if len(added) == 0 {
		return "", nil
	}
	return sf + ": added scope " + pwchange.ManagedScope + " to " + strconv.Itoa(len(added)) + " " + plural(len(added), "user", "users"), nil
}

// planRollback0220 completes p for the release before this one: 0.2.20 reads
// every file this release writes but the server address of tacctl.yaml
// (server.addresses, conf.Added0221), which it refuses, so the plan removes
// that key, adds the managed scope's step (every target) and leaves the
// rest.
func planRollback0220(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.keys = p.in.Conf.RollbackKeys0220()
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0220), RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the sudoers drop-ins, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0220 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0220 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
