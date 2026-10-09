package cli

// 'group privilege reset <group> [--dry-run] [--yes]' and 'group commands
// reset <group> [--dry-run] [--yes]' (docs/plans/0.2.3-plan.md D51, WP10.5h):
// 'group reset <group> --only privileges|commands' for any one group, with
// the shipped default as the canonical state. The diff and the writes are
// those of 'group reset' (group_reset.go); what differs is that a group that
// is neither built in nor a role has a canonical state too, "none shipped",
// so the reset removes its override (a true unset, never an empty list), and
// that there is no --preset: the role preset's values come with 'group reset
// <group> --preset'.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
)

const (
	groupPrivilegeResetUsage = "Usage: tacctl group privilege reset <group> [--dry-run] [--yes]"
	groupCommandsResetUsage  = "Usage: tacctl group commands reset <group> [--dry-run] [--yes]"
)

// sectionReset is what differs between the two verbs.
type sectionReset struct {
	spec   string // its key in groupSpecs
	usage  string
	verb   string // as the audit line names it
	family string // 'group <family> list' reviews the result
	what   string // 'the <what> of group' in the prompt
	noun   string // what the group carries, in the messages
}

var sectionResets = map[string]sectionReset{
	sectionPrivileges: {"privilege reset", groupPrivilegeResetUsage, "group privilege reset", "privilege", "the privileges", "privileges"},
	sectionCommands:   {"commands reset", groupCommandsResetUsage, "group commands reset", "commands", "the command rules", "command rules"},
}

// shippedCanonical is the canonical state of group with the shipped values:
// what a fresh install gives a built-in group, and nothing for any other
// group: the engineer has no rules and no privileges of its own until the
// preset's are asked for ('group reset engineer').
func shippedCanonical(group string) policy.Canonical {
	if canon, ok := policy.CanonicalGroup(group, false); ok && canon.Builtin {
		return canon
	}
	return policy.Canonical{Group: group, Rules: policy.DefaultLines(group), Privileges: policy.DefaultPrivileges(group)}
}

func (inv *invocation) groupSectionReset(section string, args []string) error {
	a := inv.app
	r := sectionResets[section]
	p, err := Parse(groupSpecs[r.spec], args)
	if err != nil {
		return inv.usageErr(err.Error(), r.usage)
	}
	group := p.Args[0]
	dry, yes := p.Has("--dry-run"), p.Has("--yes")
	if !dry {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	if exists, err := inv.groupExists(group); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("Group '" + group + "' does not exist.")
	}
	c := a.Conf()
	if prob := c.Problem(); prob != "" {
		return inv.usageErr(c.Path + " cannot be read (" + prob + "); nothing was changed.")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	canon := shippedCanonical(group)
	plan := &resetPlan{group: group, canon: canon}
	var s *resetSection
	switch section {
	case sectionPrivileges:
		s = planPrivileges(c, canon)
		if level, _, _ := groupField(m.GroupInfo(), group); s.changed() && level != "" {
			removed, _, _ := diffSequences(nonBlankLines(policy.Privileges(c, group)), nonBlankLines(canon.Privileges))
			planDeviceLines(s, removed, canon.Privileges, level)
		}
	case sectionCommands:
		s = planCommands(c, canon)
	}
	plan.sections = []*resetSection{s}
	if section == sectionCommands {
		plan.planGuard(m, c, m.Group(group))
	}
	plan.title = "Reset of the " + r.noun + " of group '" + group + "' to the shipped default"

	if !plan.changed() {
		a.Out.Info("Group '" + group + "' is already canonical (" + section + "); nothing to change.")
		return nil
	}
	inv.printReset(plan, false)
	if dry {
		a.Out.Info("Dry run: nothing was written.")
		return nil
	}
	if !yes {
		if !a.Prompter().Interactive() {
			return inv.usageErr("No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes.")
		}
		if !a.Prompter().ConfirmPrefix("  Apply these changes to " + r.what + " of group '" + group + "'? [y/N]: ") {
			a.Out.Info("Aborted.")
			return nil
		}
	}

	if err := inv.applyWith(func() error { return inv.applyReset(plan) }); err != nil {
		return err
	}
	a.Logger(inv.ctx, "auth.info", r.verb+" name="+group+" by="+inv.sudoUser())
	if len(nonBlankLines(shippedLines(section, canon))) > 0 {
		a.Out.Info("Group '" + group + "': the " + r.noun + " are back to the shipped default.")
	} else {
		a.Out.Info("Group '" + group + "': the override of its " + r.noun + " is removed; none are shipped for it, so it has none.")
	}
	if len(plan.guard) > 0 {
		a.Out.Info("Auto-seeded permit-* catchall on sibling groups at priv-lvl " + plan.guardLevel + ": " + strings.Join(plan.guard, " "))
	}
	inv.echo("  Review with: tacctl group " + r.family + " list " + group)
	inv.echo("")
	return nil
}

// shippedLines are the lines of the section in the canonical state.
func shippedLines(section string, canon policy.Canonical) []string {
	if section == sectionPrivileges {
		return canon.Privileges
	}
	return canon.Rules
}

// planDeviceLines adds to the privileges section the warning that devices
// keep the 'privilege' lines of the entries it removes, and the lines that
// take them away. removed are the entries the reset drops, keep the
// canonical ones (an entry whose mode and command the canonical list also
// has stays on the device), level the group's priv-lvl.
func planDeviceLines(s *resetSection, removed, keep []string, level string) {
	still := map[string]bool{}
	for _, e := range keep {
		mode, cmd, _ := names.SplitPrivEntry(e)
		still[mode+"|"+cmd] = true
	}
	var lines []string
	for _, e := range removed {
		mode, cmd, _ := names.SplitPrivEntry(e)
		if still[mode+"|"+cmd] {
			continue
		}
		line := "no privilege " + mode + " level " + level + " " + cmd
		if !slices.Contains(lines, line) {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return
	}
	s.warns = append(s.warns, "devices keep the old 'privilege exec level "+level+" ...' lines until you re-paste tacctl config cisco and remove them (no privilege exec level "+level+" ...):")
	s.notes = lines
}
