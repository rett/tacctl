package lifecycle

// The rollback to 0.2.22, the release before this one. 0.2.22 reads every
// file this release writes but what a step of rollbackAdditions
// (rollback_additions.go) undoes, so the plan of the target converts nothing
// of its own: it leaves every file alone but the per-tier sudoers drop-in
// when it is exactly this release's text (it loses the engineer's row of
// 'device clone', tier.Sudoers0222, and the same goes for 0.2.21 and 0.2.20,
// which wrote the same text), and a change of this release that
// 0.2.22 refuses (the users' email addresses, rollback_email.go) is a step of
// that list, which reaches this target and every older one. When a step has
// something to do the target converts a file, takes the snapshot and needs
// --yes if the step warns.
//
// What 0.2.22 has that every older target lacks stays: the server name and
// the timing scale (the additions of 0.2.22 are undone by the older targets
// only), the users' login to this server through the managed scope (no scope
// is added to the users' own lists), the server address, the user names with
// a period (0.2.22 reads a stored one; a new one is refused only where it is
// made), the emergency lockdown, the required password change, the
// management filter mode and the console settings of 0.2.20.

import "github.com/rett/tacctl/internal/tier"

// planRollback0222 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0222(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0222))
	p.Steps = append(p.Steps, p.tiers0222Step(RollbackTarget0222)...)
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the group sudoers drop-in, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0222 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0222 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}

// tiers0222Step plans the per-tier sudoers drop-in for a target that
// reads this release's files and wrote the text of 0.2.20 to 0.2.22
// (tier.Sudoers0222): exactly this release's text is rewritten with it, which
// takes out the engineer's row of 'device clone'. A file that is already that
// text, or absent, needs no step; any other text is left and said so.
func (p *RollbackPlan) tiers0222Step(target string) []RollbackStep {
	tiers := p.tiersPlan(tier.Sudoers0222(), tier.Sudoers())
	p.sudoers = []sudoersPlan{tiers}
	if tiers.state != "rewrite" && tiers.state != "left" {
		return nil
	}
	return []RollbackStep{p.tiersStep(target, tiers, "the engineer's rule of 'device clone' is taken out")}
}
