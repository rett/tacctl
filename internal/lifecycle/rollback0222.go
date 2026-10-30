package lifecycle

// The rollback to 0.2.22, the release before this one. 0.2.22 reads every
// file this release writes but what a step of rollbackAdditions
// (rollback_additions.go) undoes, so the plan of the target converts nothing
// of its own: it leaves every file alone, and a change of this release that
// 0.2.22 refuses (the users' email addresses, rollback_email.go) is a step of
// that list, which reaches this target and every older one. When a step has
// something to do the target converts a file, takes the snapshot and needs
// --yes if the step warns.
//
// What 0.2.22 has that every older target lacks stays: the server name and
// the timing scale (the additions of 0.2.22 are undone by the older targets
// only), the users' login to this server through the managed scope (no scope
// is added to the users' own lists), the server address, the user names with
// a period (0.2.22 reads a stored one; a new one is refused only where it is
// made), the emergency lockdown, the required password change, the
// management filter mode and the console settings of 0.2.20.

// planRollback0222 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0222(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0222), RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the sudoers drop-ins, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0222 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0222 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
