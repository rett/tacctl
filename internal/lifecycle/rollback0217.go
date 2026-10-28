package lifecycle

// The rollback to 0.2.17 (docs/plans/0.2.18-plan.md D273): the part of
// PlanRollback that runs when RollbackInput.Target is RollbackTarget0217.
// 0.2.18 renamed three verbs and dropped the old names ('device
// config-syntax' is 'device ios-syntax', 'device notices' is 'device notice
// list', 'device ssh-config' is 'device client-config'), so the per-tier
// sudoers drop-in this release writes grants the new names where 0.2.17's
// grants the old: a 0.2.17 binary under this release's file refuses a tier
// user's 'sudo tacctl device notices' (and the other two) until 0.2.17's
// upgrade rewrites the file. A file that is exactly this release's text is rewritten
// with 0.2.17's (tier.Sudoers0217, through 'visudo -cf'); any other is left.
// 0.2.18 also renamed devices.yaml's key of the configuration syntax setting
// (config_syntax is ios_syntax), which 0.2.17 refuses: it is written back
// under the old key (syntaxKeyStep). 0.2.19 added the emergency lockdown
// record, which a rollback refuses while a group is locked; a partial record
// that locks nothing is removed (conf.Added0219), and the system blocks that
// hold 0.2.19's statements are listed in a warning (blocksWarning). No other
// file changed: console.yaml, store.yaml, the SNMP credentials, the apply
// state, the group drop-in, the hosts and the rendered backend files are in
// formats 0.2.17 reads.

import (
	"github.com/rett/tacctl/internal/tier"
)

// planRollback0217 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0217(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	p.keys = p.in.Conf.RollbackKeys0218()
	tiers := p.tiersPlan(tier.Sudoers0217(), tier.Sudoers(), tier.Sudoers0219(), tier.Sudoers0218())
	p.sudoers = []sudoersPlan{tiers}
	s := p.tiersStep(RollbackTarget0217, tiers, "the rules of 'device ios-syntax', 'device notice list' and 'device client-config' become "+RollbackTarget0217+"'s 'device config-syntax', 'device notices' and 'device ssh-config', and the engineer's rules of 'device config apply', 'device enroll', 'device collect', 'device onboard', 'device sync' and 'device support-bundle' are taken out")
	if err := p.planSyntaxKey(); err != nil {
		return nil, err
	}
	p.Steps = append(p.Steps, p.syntaxKeyStep())
	if len(p.keys) > 0 {
		p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0217))
	}
	p.Steps = append(p.Steps, s, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.ConsoleFile + ", " + pt.StoreFile + ", the group sudoers drop-in, the SNMP credentials, the blocks, the apply state directory and the rendered backend files are in formats " + RollbackTarget0217 + " reads (0.2.18 changed none of them, and 0.2.19 none but the blocks: see the warning, if any);",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0217 + ": 0.2.18 changed nothing on the hosts; no host is synced"}})
	}
	p.Warnings = append(p.mgmtModeWarning(RollbackTarget0217), p.blocksWarning(RollbackTarget0217)...)
	return p, nil
}
