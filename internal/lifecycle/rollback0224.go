package lifecycle

// The rollback to 0.2.24, the release before 0.2.25 (rollback0225.go). 0.2.25
// changed no stored file 0.2.24 reads strictly (the shapes list, the help and
// the documentation, the spelling of the NETCONF capabilities and the reasons
// of a failed hello, the readers of a device's shell session and of a Junos
// virtual chassis's commit answers and the cleaning of a device's text are
// code only), so 0.2.24 reads the same files as 0.2.25 and the plan of the
// target is the one of 0.2.25 (planRollbackAfter0224): it removes the limits
// of the stored reports of this release (the two keys of tacctl.yaml, and the
// users' own limits through a step of rollbackAdditions), puts back the
// per-tier sudoers drop-in of 0.2.24 and 0.2.25 (the same text) when this
// release's differs, and leaves every other file alone. No other step of
// rollbackAdditions fires for it: they undo what 0.2.24 and older releases
// changed, for the targets older than the release that made the change, so
// the break-glass firewall of 0.2.24 (the setting, the nftables table, the
// rules file and the boot unit) stays as it is.
//
// What this release and 0.2.25 changed outside the stored files is 0.2.24's
// to undo or keep, and needs no step here: the next 'device config pull' with
// 0.2.24 records a Junos device's NETCONF as 'no hello' again (0.2.24 reads
// only the RFC 6241 spelling of the capabilities), and its apply to a Junos
// virtual chassis whose master prints its own label rolls back as it did.

// planRollback0224 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for 0.2.24.
func planRollback0224(p *RollbackPlan) (*RollbackPlan, error) {
	return planRollbackAfter0224(p, RollbackTarget0224)
}
