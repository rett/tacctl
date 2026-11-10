package lifecycle

// The rollback to 0.2.26, the release before 0.2.27 (rollback0227.go). 0.2.27
// changed no stored file 0.2.26 reads strictly: what it changed is the reader
// of the 'show switch' table of an IOS stack (a blank H/W version column),
// what the reports of a user below the operator tier hold (no model, serial
// number, release or chassis members, as 'device show' leaves them out), the
// audit line a prune of another user's reports writes, the PDF format of the
// reports and the offer of its tools (a report file in the user's home, and a
// marker no release reads but 0.2.27 and the ones after it), the wording of
// two notes, and the documentation. The stored state files, the per-tier
// sudoers text, the keys of tacctl.yaml, the fields of the store and the
// format of the pull records are all as 0.2.26 reads them. So 0.2.26 reads
// every file 0.2.27 to 0.2.29 and this release write and the plan of the target
// converts nothing: it leaves every file alone, the per-tier sudoers drop-in
// included (0.2.26 to 0.2.29 and this release write the same text), removes no
// key (the limits of the stored reports, reports.max_size and
// reports.max_count in tacctl.yaml and a user's own limits in the store, stay:
// 0.2.26 has them) and takes no snapshot but for the file below. The reports in the users' homes
// stay too: 0.2.26 reads them (a PDF one as text, which is why the upgrade
// pages say to fetch it with the scp line of 'show'). The one file it does
// not read as this release writes it is console.yaml with the file transfer
// settings of 0.2.28 (settings.file_transfer, an unknown key to its reader),
// which an entry of rollbackAdditions removes (rollback_filetransfer.go). No
// other step of rollbackAdditions fires for it either: they undo what 0.2.26 and older
// releases changed, for the targets older than the release that made the
// change.
//
// What 0.2.27 to 0.2.29 and this release changed outside the stored files is 0.2.26's to
// undo or keep, and needs no step here: the next 'device config pull' with
// 0.2.26 records a stack member with a blank H/W version column as it did
// before (the row is not read), and a report made by a user below the
// operator tier holds the facts of the pull again.

// planRollback0226 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for 0.2.26.
func planRollback0226(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0226))
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the per-tier and the group sudoers drop-ins, the SNMP credentials, the pull records, the reports in the users' homes, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0226 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0226 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
