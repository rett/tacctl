package lifecycle

// The rollback to 0.2.28, the release before 0.2.29 (rollback0229.go). 0.2.29
// changed no stored file 0.2.28 reads strictly: what it changed is how the
// console's file transfer sets the mode of a file a client uploads (the
// owner's execute bit of a script copied with scp now survives, a change in
// the code that serves the transfer and not in a file), a test, and the
// documentation; this release only checks the name of a new user more
// strictly, which writes no new form of a file. The stored
// state files, the per-tier sudoers text, the keys of tacctl.yaml (the
// settings.file_transfer of console.yaml is 0.2.28's own), the fields of the
// store, the format of the pull records and of the reports in the users' homes
// are all as 0.2.28 reads them. So 0.2.28 reads every file 0.2.29 and this
// release write and the plan of the target converts nothing: it leaves every
// file alone, the per-tier sudoers drop-in included (0.2.28 to 0.2.29 and this
// release write the same text), removes no key and no field (the limits of the
// stored reports and the file transfer settings stay: 0.2.28 has them) and
// takes no snapshot. The reports in the users' homes stay too, the PDF ones
// included, and so does the marker /var/lib/tacctl/pdf-tools-offered. No step
// of rollbackAdditions fires for it either: they undo what 0.2.28 and older
// releases changed, for the targets older than the release that made the
// change.
//
// What 0.2.29 and this release changed outside the stored files is 0.2.28's to
// undo or keep, and needs no step here: with 0.2.28 installed again a file a
// client uploads through the console is created with the mode 0644 (0600
// after the umask) whatever mode the client asks for, as it was, and a new
// user name is checked as 0.2.28 checks it (a name that starts with a digit,
// '-' or '_' is accepted again).

// planRollback0228 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for 0.2.28.
func planRollback0228(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0228))
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the per-tier and the group sudoers drop-ins, the SNMP credentials, the pull records, the reports in the users' homes, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0228 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0228 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
