package lifecycle

// The rollback to 0.2.18 (the one before the emergency lockdown): the part of
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
//   - nothing in devices.yaml, store.yaml, the SNMP credentials,
//     the apply state, the hosts or the rendered backend files.
//
// 0.2.20's management filter mode of a scope (scope_mgmt_acl.mode.<scope>,
// conf.Added0220) is removed for every target, after a snapshot, because the
// older schema refuses it; the rollback is not refused (the warning of
// mgmtModeWarning names the scopes that were strict).

import (
	"os"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/blocks"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/tier"
)

// planRollback0218 completes p (a plan whose tacctl.yaml was read and whose
// records hold no unsettled apply or lockdown) for 0.2.18.
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
	p.Warnings = append(append(p.mgmtModeWarning(RollbackTarget0218), p.blocksWarning(RollbackTarget0218)...), p.consoleWideningWarning()...)
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

// lockdownKeysStep is the step that removes the keys of p.keys from
// tacctl.yaml: what is left of the lockdown record of 0.2.19, for a target
// whose schema lacks it, and the management filter mode of 0.2.20.
func (p *RollbackPlan) lockdownKeysStep(target string) RollbackStep {
	s := RollbackStep{Title: p.in.Paths.Overrides + ": remove the keys " + target + " does not know", Todo: len(p.keys) > 0}
	if len(p.keys) == 0 {
		s.Lines = []string{"nothing to remove (no emergency lockdown is recorded)"}
		switch target {
		case RollbackTarget0219:
			s.Lines = []string{"nothing to remove (no scope has a management filter mode)"}
		case RollbackTarget0220:
			s.Lines = []string{"nothing to remove (no server address, server name or timeout scale is set)"}
		case RollbackTarget0221:
			s.Lines = []string{"nothing to remove (no server name or timeout scale is set)"}
		case RollbackTarget0222:
			s.Lines = []string{"nothing to remove (every key of tacctl.yaml is one " + target + " knows)"}
		}
		return s
	}
	for _, k := range p.keys {
		s.Lines = append(s.Lines, "remove "+k)
	}
	var what []string
	for _, k := range p.keys {
		switch {
		case conf.Added0219Key(k) && !slices.Contains(what, "the record of an emergency lockdown is 0.2.19's"):
			what = append(what, "the record of an emergency lockdown is 0.2.19's")
		case conf.Added0220Key(k) && !slices.Contains(what, "the management filter mode of a scope is 0.2.20's"):
			what = append(what, "the management filter mode of a scope is 0.2.20's")
		case conf.Added0221Key(k) && !slices.Contains(what, "the server address is 0.2.21's (this server's registry entry keeps a copy, which the older release reads)"):
			what = append(what, "the server address is 0.2.21's (this server's registry entry keeps a copy, which the older release reads)")
		case k == conf.ServerNameKey && !slices.Contains(what, "the server name is 0.2.22's (the console shows the host name again)"):
			what = append(what, "the server name is 0.2.22's (the console shows the host name again)")
		case conf.Added0222Key(k) && k != conf.ServerNameKey && !slices.Contains(what, "the timeout scale is 0.2.22's (the fixed timings apply again)"):
			what = append(what, "the timeout scale is 0.2.22's (the fixed timings apply again)")
		}
	}
	s.Lines = append(s.Lines, "("+strings.Join(what, ", ")+"; "+target+"'s schema refuses it: its 'config validate' reports it and its 'backup restore' refuses a snapshot that has it; every other key is one it has and stays)")
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
