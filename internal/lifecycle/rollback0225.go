package lifecycle

// The rollback to 0.2.25, the release before 0.2.26 (rollback0226.go). 0.2.26
// added the reports of 'tacctl device reports' (docs/plans/0.2.26-plan.md): the verbs,
// the report files in each user's home, the chassis members a pull records
// (the key 'members' of the pull records), the limits of the stored reports
// (D326) and their rows in the per-tier sudoers drop-in. What 0.2.25 cannot
// read strictly is the limits, in two places:
//
//	tacctl.yaml    reports.max_size and reports.max_count (conf.Added0226): the
//	               0.2.25 schema refuses them, its 'config validate' reports
//	               them and its 'backup restore' refuses a snapshot that has
//	               them. They are removed (the key list of the target).
//	store.yaml     users.<name>.reports_max_size and reports_max_count: the
//	               0.2.25 validator refuses the fields ("unknown field").
//	               They are removed, after a warning that --apply needs --yes
//	               for (rollbackAdditions: rollback_reportlimits.go).
//
// What the target leaves alone: the pull records, whose 'members' key the
// 0.2.25 decoder ignores (it reads the keys it knows and skips the others), and
// every report file, which is the user's own file in the user's home and which
// 0.2.25, having no 'device reports' verb, never opens. It takes a snapshot
// only when a key or a field is removed (PendingFiles), and the per-tier
// sudoers drop-in is rewritten with 0.2.25's text only when the text 0.2.26
// and the releases after it write differs from it (the rows of 'device reports',
// tier.Sudoers0225).

import "github.com/rett/tacctl/internal/tier"

// planRollback0225 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for 0.2.25.
func planRollback0225(p *RollbackPlan) (*RollbackPlan, error) {
	return planRollbackAfter0224(p, RollbackTarget0225)
}

// planRollbackAfter0224 is the plan of the targets 0.2.25 and 0.2.24, which read
// the same files: the keys of the limits of the stored reports are removed, the
// per-tier sudoers drop-in is put back when it differs, and every other file is
// left.
func planRollbackAfter0224(p *RollbackPlan, target string) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.keys = p.in.Conf.RollbackKeys0225()
	p.Steps = append(p.Steps, p.lockdownKeysStep(target))
	p.Steps = append(p.Steps, p.tiers0225Step(target)...)
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the group sudoers drop-in, the SNMP credentials, the pull records, the reports in the users' homes, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + target + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + target + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}

// tiers0225Step plans the per-tier sudoers drop-in for the targets 0.2.25 and
// 0.2.24: exactly this release's text is rewritten with the text those
// releases wrote (tier.Sudoers0225), which takes out the rows of 'device
// reports'. A file that is already that text, or absent, needs no step; any
// other text is left and said so.
func (p *RollbackPlan) tiers0225Step(target string) []RollbackStep {
	tiers := p.tiersPlan(tier.Sudoers0225(), tier.Sudoers())
	p.sudoers = []sudoersPlan{tiers}
	if tiers.state != "rewrite" && tiers.state != "left" {
		return nil
	}
	return []RollbackStep{p.tiersStep(target, tiers, "the rows of 'device reports' are taken out")}
}
