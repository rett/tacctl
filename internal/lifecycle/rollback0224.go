package lifecycle

// The rollback to 0.2.24, the release before this one. This release changed
// no stored file 0.2.24 reads strictly: its changes are the shapes list, the
// help and the documentation, the spelling of the NETCONF capabilities and the
// reasons of a failed hello (the device check records the same four words,
// hello ok, port closed, no hello and not probed), the reader of a device's
// shell session and of a Junos virtual chassis's commit answers, and the
// cleaning of a device's text. So 0.2.24 reads every file this one writes and
// the plan of the target converts nothing: it leaves every file alone, the
// per-tier sudoers drop-in included (0.2.24 and this release write the same
// text), and takes no snapshot. No step of rollbackAdditions fires for it
// either: they undo what 0.2.24 and older releases changed, for the targets
// older than the release that made the change, so the break-glass firewall of
// 0.2.24 (the setting, the nftables table, the rules file and the boot unit)
// stays as it is.
//
// What this release changed outside the stored files is 0.2.24's to undo or
// keep, and needs no step here: the next 'device config pull' with 0.2.24
// records a Junos device's NETCONF as 'no hello' again (0.2.24 reads only the
// RFC 6241 spelling of the capabilities), and its apply to a Junos virtual
// chassis whose master prints its own label rolls back as it did.

// planRollback0224 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0224(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.keys = p.in.Conf.RollbackKeys0225()
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0224))
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the per-tier and the group sudoers drop-ins, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0224 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0224 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
