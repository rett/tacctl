package lifecycle

// The rollback to 0.2.27, the release before this one. This release changed
// no stored file 0.2.27 reads strictly: what it changed is the code that
// reads the answer of a Cisco IOS device to a long command (the tail of the
// echo that the device cuts and redraws is dropped as well, so a support
// bundle no longer starts its identity lines with it), and the documentation.
// The stored state files, the per-tier sudoers text, the keys of tacctl.yaml,
// the fields of the store, the format of the pull records and of the reports
// in the users' homes are all as 0.2.27 reads them. So 0.2.27 reads every
// file this one writes and the plan of the target converts nothing: it leaves
// every file alone, the per-tier sudoers drop-in included (0.2.27 and this
// release write the same text), removes no key (the limits of the stored
// reports, reports.max_size and reports.max_count in tacctl.yaml and a user's
// own limits in the store, stay: 0.2.27 has them) and takes no snapshot. The
// reports in the users' homes stay too, the PDF ones included (0.2.27 reads
// them), and so does the marker /var/lib/tacctl/pdf-tools-offered, which this
// release and 0.2.27 write alike. No step of rollbackAdditions fires for it
// either: they undo what 0.2.26 and older releases changed, for the targets
// older than the release that made the change.
//
// What this release changed outside the stored files is 0.2.27's to undo or
// keep, and needs no step here: the next support bundle of a device with
// 0.2.27 starts the identity lines of an IOS device with the tail of a long
// command's echo again, as it did before.

// planRollback0227 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0227(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0227))
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the per-tier and the group sudoers drop-ins, the SNMP credentials, the pull records, the reports in the users' homes, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0227 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0227 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
