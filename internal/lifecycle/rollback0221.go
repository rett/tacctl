package lifecycle

// The rollback to 0.2.21, the release before this one. 0.2.21 reads every
// file this release writes but one key of tacctl.yaml: the name of the server
// in the console (server.name, conf.Added0222), which its schema refuses (its
// 'config validate' reports "unknown config key" and its 'backup restore'
// refuses a snapshot that has it). So the plan removes that key and nothing
// else.
//
// What 0.2.21 has that every older target lacks stays: the users' login to
// this server through the managed scope (no scope is added to the users'
// own lists, as the older targets do), the server address, the user names
// with a period (0.2.20 and 0.2.21 allowed one, so the rollback is not
// refused for one), the emergency lockdown, the required password change,
// the management filter mode and the console settings of 0.2.20. Changes of
// this release that 0.2.21 does not need a conversion for: the user name
// rule (a name with a period is read as before; a new one is refused only
// where it is made), the verbs 'server show', 'server listen' and 'server
// metrics' (the keys they write are the ones 'config listen' and 'config
// metrics' wrote), and the checks of the host-key scan and of the Junos
// virtual chassis (no stored format).

// planRollback0221 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0221(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.keys = p.in.Conf.RollbackKeys0221()
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0221), RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the sudoers drop-ins, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0221 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0221 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}
