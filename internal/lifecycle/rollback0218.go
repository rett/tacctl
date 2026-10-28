package lifecycle

// The rollback to 0.2.18 (the release before this one): the part of
// PlanRollback that runs when RollbackInput.Target is RollbackTarget0218.
// 0.2.19 changed four things a 0.2.18 binary reads:
//
//   - the per-tier sudoers drop-in grants the engineer the rows of 'device
//     config apply', 'device enroll', 'device collect', 'device onboard',
//     'device sync' and 'device support-bundle'; 0.2.18's upgrade rewrites
//     the file, and a 0.2.18 binary under this one only has rules it does not
//     enforce, so a file that is exactly this release's text is rewritten with
//     0.2.18's (tier.Sudoers0218, through 'visudo -cf'); any other is left;
//   - the emergency lockdown record (emergency.lockdown.<scope>.*): a
//     lockdown that locks a group refuses the rollback (LockdownRefusal), and
//     what is left, a partial record that locks nothing, is removed because
//     0.2.18's schema refuses it (conf.Added0219);
//   - the grammar of the system blocks (the closed rule tables, the login
//     announcement, 'absent' lines and the IOS motd and exec banners): 0.2.18
//     lints a block that holds one as an error. The block files are not
//     rewritten (they are the operator's text); the plan lists the blocks that
//     hold such statements, by level and count, in a warning;
//   - nothing in devices.yaml, console.yaml, store.yaml, the SNMP credentials,
//     the apply state, the hosts or the rendered backend files.

import (
	"os"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/tier"
)

// planRollback0218 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply or lockdown) for the release before this
// one.
func planRollback0218(p *RollbackPlan) (*RollbackPlan, error) {
	in := p.in
	pt := in.Paths
	p.keys = in.Conf.RollbackKeys0218()
	tiers := p.tiersPlan(tier.Sudoers0218(), tier.Sudoers(), tier.Sudoers0219(), tier.Sudoers0218())
	p.sudoers = []sudoersPlan{tiers}
	p.Steps = append(p.Steps, p.lockdownKeysStep(RollbackTarget0218), p.tiersStep(RollbackTarget0218, tiers,
		"the engineer's rules of 'device config apply', 'device enroll', 'device collect', 'device onboard', 'device sync' and 'device support-bundle' are taken out"),
		RollbackStep{Title: "leave every other file untouched",
			Lines: []string{pt.DevicesFile + ", " + pt.ConsoleFile + ", " + pt.StoreFile + ", the group sudoers drop-in, the SNMP credentials, the blocks, the apply state directory and the rendered backend files are in formats " + RollbackTarget0218 + " reads (the blocks: see the warning, if any);",
				"nothing is re-rendered or restarted, and no device is contacted"}})
	if in.WithHosts {
		p.Steps = append(p.Steps, RollbackStep{Title: "the enrolled Linux hosts (--hosts)",
			Lines: []string{"nothing to do for " + RollbackTarget0218 + ": 0.2.19 changed nothing on the hosts; no host is synced"}})
	}
	p.Warnings = p.blocksWarning(RollbackTarget0218)
	return p, nil
}

// tiersPlan is the plan of the per-tier drop-in for a target: the file is
// rewritten with body when its text is one of the rewritable ones, done when
// it is body already, left when it is anything else, absent when there is
// none.
func (p *RollbackPlan) tiersPlan(body string, rewritable ...string) sudoersPlan {
	pt := p.in.Paths
	tiers := sudoersPlan{label: "the per-tier drop-in", file: pt.TierSudoersFile, state: "absent"}
	b, err := os.ReadFile(pt.TierSudoersFile)
	if err != nil {
		return tiers
	}
	switch got := string(b); {
	case got == body:
		tiers.state = "done"
	case containsString(rewritable, got):
		tiers.state, tiers.body = "rewrite", body
	default:
		tiers.state = "left"
	}
	return tiers
}

func containsString(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// tiersStep is the step of the per-tier drop-in for a target; what is the
// parenthesis of the rewrite line.
func (p *RollbackPlan) tiersStep(target string, tiers sudoersPlan, what string) RollbackStep {
	s := RollbackStep{Title: "put back the per-tier sudoers drop-in " + target + " writes", Todo: tiers.state == "rewrite"}
	switch tiers.state {
	case "rewrite":
		s.Lines = []string{"rewrite " + tiers.file + " (" + target + "'s text, after 'visudo -cf': " + what + ")"}
		if p.in.InstallSudoers == nil {
			s.Lines[0] += " [not rewritten: no installer]"
		}
	case "done":
		s.Lines = []string{tiers.file + " is already the text " + target + " writes"}
	case "left":
		s.Lines = []string{"leaves " + tiers.file + ": it is not the text this release writes (edited, or another release's); " + target + "'s upgrade rewrites it with its own text"}
	default:
		s.Lines = []string{"no per-tier drop-in is installed (" + tiers.file + ")"}
	}
	return s
}

// lockdownKeysStep is the step that removes what is left of the lockdown
// record of 0.2.19 from tacctl.yaml, for a target whose schema lacks it.
func (p *RollbackPlan) lockdownKeysStep(target string) RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys " + target + " does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (no emergency lockdown is recorded)"}
		return s
	}
	for _, k := range p.keys {
		s.Lines = append(s.Lines, "remove "+k)
	}
	s.Lines = append(s.Lines, "(the record of an emergency lockdown is 0.2.19's; "+target+"'s schema refuses it: its 'config validate' reports it and its 'backup restore' refuses a snapshot that has it; every other key is one it has and stays)")
	return s
}

// blocksWarning is the warning about the system blocks that hold statements
// 0.2.19 added, which every release before it lints as errors; nil when none
// does or the install has no blocks.
func (p *RollbackPlan) blocksWarning(target string) []RollbackWarning {
	use := blocks.NewStore(p.in.Paths.BlocksDir).FindSince0219()
	if len(use) == 0 {
		return nil
	}
	lines := []string{target + " does not know every statement of these system blocks (0.2.19 added the syslog, login-policy, ssh and summer-time statements, the login announcement, the 'absent' lines and the IOS motd and exec banners), so it lints them as errors and plans nothing for the devices they reach:"}
	for _, u := range use {
		lines = append(lines, "  "+u.String())
	}
	lines = append(lines, "The files stay in "+p.in.Paths.BlocksDir+" as they are; take the statements out before the upgrade ('tacctl scope block ... system edit', 'tacctl device block ... system edit'), or expect the errors.")
	return []RollbackWarning{{Title: "System blocks use statements " + target + " does not know", Lines: lines}}
}
