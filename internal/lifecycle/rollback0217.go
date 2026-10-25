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
// under the old key (syntaxKeyStep). No other file changed: tacctl.yaml,
// console.yaml, store.yaml, the SNMP credentials, the blocks, the apply
// state, the group drop-in, the hosts and the rendered backend files are in
// formats 0.2.17 reads.

import (
	"os"

	"github.com/rett/tacctl/internal/tier"
)

// planRollback0217 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply) for the release before this one.
func planRollback0217(p *RollbackPlan) (*RollbackPlan, error) {
	pt := p.in.Paths
	tiers := sudoersPlan{label: "the per-tier drop-in", file: pt.TierSudoersFile, state: "absent"}
	if b, err := os.ReadFile(pt.TierSudoersFile); err == nil {
		switch string(b) {
		case tier.Sudoers():
			tiers.state, tiers.body = "rewrite", tier.Sudoers0217()
		case tier.Sudoers0217():
			tiers.state = "done"
		default:
			tiers.state = "left"
		}
	}
	p.sudoers = []sudoersPlan{tiers}
	s := RollbackStep{Title: "put back the per-tier sudoers drop-in " + RollbackTarget0217 + " writes", Todo: tiers.state == "rewrite"}
	switch tiers.state {
	case "rewrite":
		s.Lines = []string{"rewrite " + tiers.file + " (" + RollbackTarget0217 + "'s text, after 'visudo -cf': the rules of 'device ios-syntax', 'device notice list' and 'device client-config' become " + RollbackTarget0217 + "'s 'device config-syntax', 'device notices' and 'device ssh-config')"}
		if p.in.InstallSudoers == nil {
			s.Lines[0] += " [not rewritten: no installer]"
		}
	case "done":
		s.Lines = []string{tiers.file + " is already the text " + RollbackTarget0217 + " writes"}
	case "left":
		s.Lines = []string{"leaves " + tiers.file + ": it is not the text this release writes (edited, or another release's); " + RollbackTarget0217 + "'s upgrade rewrites it with its own text"}
	default:
		s.Lines = []string{"no per-tier drop-in is installed (" + tiers.file + ")"}
	}
	if err := p.planSyntaxKey(); err != nil {
		return nil, err
	}
	p.Steps = append(p.Steps, p.syntaxKeyStep(), s, RollbackStep{Title: "leave every other file untouched",
		Lines: []string{pt.Overrides + ", " + pt.ConsoleFile + ", " + pt.StoreFile + ", the group sudoers drop-in, the SNMP credentials, the blocks, the apply state directory and the rendered backend files are in formats " + RollbackTarget0217 + " reads (0.2.18 changed none of them);",
			"nothing is re-rendered or restarted, and no device is contacted"}})
	if p.in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0217 + ": 0.2.18 changed nothing on the hosts; no host is synced"}})
	}
	return p, nil
}
