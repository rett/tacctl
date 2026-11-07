package lifecycle

// The rollback to 0.2.23, the release before 0.2.24 (rollback0224.go). 0.2.24
// changed no stored file 0.2.23 reads strictly but the break-glass firewall
// setting (a step of rollbackAdditions undoes it, rollback_firewall.go), so
// 0.2.23 reads every file 0.2.24 and this release write, and the plan of the
// target converts nothing but the per-tier sudoers drop-in: when it is
// exactly 0.2.24's text (this release writes the same) it is rewritten with
// 0.2.23's (tier.Sudoers0223, without the operator's 'log failures *', which
// 0.2.23 does not know; sudo would accept the row, but 0.2.23's upgrade
// compares the file with its own text). A file that is already 0.2.23's, an
// absent one, and one that is not 0.2.24's text (edited, or not written by
// tacctl) need no rewrite and are left, as every other target leaves them. No
// snapshot is taken for the drop-in: the snapshot holds files of tacctl's own,
// and the drop-in is not one. The other steps of rollbackAdditions undo what
// 0.2.23 and older releases changed, for the targets older than the release
// that made the change, so none of them fires for this target.
//
// What 0.2.24 changed outside the stored files is 0.2.23's to undo or keep,
// and needs no step here: 0.2.23's upgrade, which ends the rollback, writes
// the console's sshd drop-in from its own text (without the block of users
// held to a password change); it keeps the tacquito 0.2.24 built until a new
// commit on the fork's main rebuilds it, so accounting records keep "Device"
// (patch 0006), which 0.2.23 shows as written; and a device whose
// single-connection 0.2.24 removed reads as missing it in 0.2.23's plan.
//
// What the target does not touch is the tacquito clone (TACQUITO_SRC,
// /opt/tacquito-src): it keeps pointing at the project's fork, which has the
// same history as the upstream clone 0.2.23 made, so 0.2.23's own pull carries
// on from the commit that is checked out.

import "github.com/rett/tacctl/internal/tier"

// planRollback0223 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for 0.2.23.
func planRollback0223(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.keys = p.in.Conf.RollbackKeys0223()
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0223))
	p.Steps = append(p.Steps, p.tiers0223Step(RollbackTarget0223)...)
	p.Steps = append(p.Steps, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.StoreFile + ", " + pt.DevicesFile + ", " + pt.ConsoleFile + ", the group sudoers drop-in, the SNMP credentials, the blocks, the apply state directory, the host registry and the rendered backend files are in formats " + RollbackTarget0223 + " reads;",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0223 + ": this release changed nothing on the enrolled hosts; no host is synced"}})
	}
	return p, nil
}

// tiers0223Step plans the per-tier sudoers drop-in for the target: exactly
// the text of 0.2.24 and this release is rewritten with 0.2.23's (tier.Sudoers0223), which
// takes out the operator's row of 'log failures *'. A file that is already
// that text, or absent, needs no step; any other text is left and said so.
func (p *RollbackPlan) tiers0223Step(target string) []RollbackStep {
	tiers := p.tiersPlan(tier.Sudoers0223(), tier.Sudoers(), tier.Sudoers0225())
	p.sudoers = []sudoersPlan{tiers}
	if tiers.state != "rewrite" && tiers.state != "left" {
		return nil
	}
	return []RollbackStep{p.tiersStep(target, tiers, "the operator's rule of 'log failures *' is taken out")}
}
