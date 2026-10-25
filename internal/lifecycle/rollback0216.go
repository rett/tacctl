package lifecycle

// The rollback to 0.2.16 (docs/plans/0.2.17-plan.md D257): the part of
// PlanRollback that runs when RollbackInput.Target is RollbackTarget0216.
// The file header of rollback.go has the table of what the other targets do;
// ApplyRollback is shared. 0.2.17 added one key to the schema of
// tacctl.yaml, audit.strict (conf.Added0217): 0.2.16's schema refuses it
// ('config validate' reports "unknown config key" and 'backup restore'
// refuses a snapshot that has it, verified against the 0.2.16 tag by
// conf.TestAdded0217IsNotInTheSchemaOfTheTag), so it is removed. No other
// file changed in a way 0.2.16 reads strictly but devices.yaml, whose
// configuration syntax key 0.2.18 renamed (written back under config_syntax,
// syntaxKeyStep): console.yaml, store.yaml, the SNMP credentials, the
// blocks, the apply state, the hosts, the sudoers drop-ins and the rendered
// backend files need no conversion. The snapshot manifests gained keys that
// nothing reads.

// planRollback0216 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for 0.2.16.
func planRollback0216(p *RollbackPlan) (*RollbackPlan, error) {
	in := p.in
	p.keys = in.Conf.RollbackKeys0216()
	if err := p.planSyntaxKey(); err != nil {
		return nil, err
	}
	p.Steps = append(p.Steps, p.confStep0216(), p.syntaxKeyStep(), p.otherStep0216())
	if in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0216 + ": 0.2.17 changed nothing on the hosts; no host is synced"}})
	}
	p.Warnings = p.warnings0216()
	p.Notes = p.notes0216()
	return p, nil
}

func (p *RollbackPlan) confStep0216() RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys " + RollbackTarget0216 + " does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (audit.strict is not set)"}
		return s
	}
	for _, k := range p.keys {
		s.Lines = append(s.Lines, "remove "+k)
	}
	s.Lines = append(s.Lines, "("+RollbackTarget0216+"'s schema refuses it: its 'config validate' reports it and its 'backup restore' refuses a snapshot that has it; every other key is one it has and stays)")
	return s
}

func (p *RollbackPlan) otherStep0216() RollbackStep {
	pt := p.in.Paths
	return RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.ConsoleFile + ", " + pt.StoreFile + ", the SNMP credentials, the blocks, the apply state directory and the rendered backend files are in formats " + RollbackTarget0216 + " reads (0.2.17 and 0.2.18 changed none of them);",
			"the sudoers drop-ins are left: sudo accepts them, and " + RollbackTarget0216 + "'s upgrade rewrites the tiers file;",
			"nothing is re-rendered or restarted, and no device is contacted"}}
}

// auditStrictWarning is the warning that removing audit.strict, set to true,
// loosens the audit: the release rolled back to writes the same kind of lines
// but does not refuse a command whose start line cannot be written. It is
// shared by the three targets.
func (p *RollbackPlan) auditStrictWarning(target string) []RollbackWarning {
	for _, k := range p.keys {
		if k != "audit.strict" {
			continue
		}
		if v, _ := p.in.Conf.Get(k, ""); v == "true" {
			return []RollbackWarning{{Title: "audit.strict is set and is dropped",
				Lines: []string{"With audit.strict a command that changes state is refused when its audit line cannot be written. " + target + " has no such setting: it runs the command and the line is lost.",
					"The key is removed from tacctl.yaml; it stays in the snapshot --apply takes first (tacctl backup list)."}}}
		}
	}
	return nil
}

func (p *RollbackPlan) warnings0216() []RollbackWarning {
	out := p.auditStrictWarning(RollbackTarget0216)
	if !p.in.HasStore && p.PendingFiles() {
		out = append(out, RollbackWarning{
			Title: "No snapshot can be taken",
			Lines: []string{"This install has no store (legacy read-only mode) and snapshots are taken of the store, so --apply cannot back up the files it converts.",
				"Copy " + p.in.Paths.Overrides + " yourself before you go on."}})
	}
	return out
}

func (p *RollbackPlan) notes0216() []string {
	var out []string
	if p.PendingFiles() {
		out = append(out, "The snapshot --apply takes holds the 0.2.18 form of tacctl.yaml and devices.yaml: restore it with 0.2.18 ('tacctl backup restore'), not with "+RollbackTarget0216+", whose restore refuses a key it does not know.")
	}
	return out
}
