package lifecycle

// The rollback to 0.2.23, the release before this one. This release changed
// no stored file (the manual page's margin, and tacquito built from the
// project's fork), so 0.2.23 reads every file this one writes and the plan of
// the target converts nothing: it leaves every file alone, the per-tier
// sudoers drop-in included (0.2.23 and this release write the same text), and
// takes no snapshot. No step of rollbackAdditions fires for it either: they
// undo what 0.2.23 and older releases changed, for the targets older than
// the release that made the change.
//
// What the target does not touch is the checkout of tacquito in the deploy
// directory: it keeps pointing at the project's fork, which has the same
// history as the upstream clone 0.2.23 made, so 0.2.23's own pull carries on
// from the commit that is checked out.

// planRollback0223 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0223(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0223))
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the per-tier and the group sudoers drop-ins, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0223 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0223 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
