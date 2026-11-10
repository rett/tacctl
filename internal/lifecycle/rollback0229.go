package lifecycle

// The rollback to 0.2.29, the release before this one. This release changed no
// stored file 0.2.29 reads strictly: what it changed is how a new user name is
// checked (a name must start with a lower case letter; 'user add' and the new
// name of 'user rename' refuse the others, and 'config validate' warns of an
// existing name that has no Linux account), a check in the code that creates
// a user and not a form of a file: a user stored under a name the check would
// refuse is read, listed and kept by 0.2.29 and by this release alike. The
// stored state files, the per-tier sudoers text, the keys of tacctl.yaml, the
// fields of the store, the format of the pull records and of the reports in
// the users' homes are all as 0.2.29 reads them. So 0.2.29 reads every file
// this release writes and the plan of the target converts nothing: it leaves
// every file alone, the per-tier sudoers drop-in included (0.2.29 and this
// release write the same text), removes no key and no field (the limits of the
// stored reports and the file transfer settings stay: 0.2.29 has them) and
// takes no snapshot. The reports in the users' homes stay too, the PDF ones
// included, and so does the marker /var/lib/tacctl/pdf-tools-offered. No step
// of rollbackAdditions fires for it either: they undo what 0.2.28 and older
// releases changed, for the targets older than the release that made the
// change.
//
// What this release changed outside the stored files is 0.2.29's to undo or
// keep, and needs no step here: with 0.2.29 installed again 'user add' and
// 'user rename' take a new name that starts with a digit, '-' or '_', as they
// did.

// planRollback0229 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0229(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0229))
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the per-tier and the group sudoers drop-ins, the SNMP credentials, the pull records, the reports in the users' homes, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0229 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0229 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
