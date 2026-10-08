package cli

// The per-group device settings of 0.2.2 on the command line
// (docs/plans/0.2.2-plan.md §5.1-5.3, D27): 'group junos' (the Junos deny
// sets), 'group edit <g> wti-level|tier', 'group add --wti-level/--tier'
// and 'group show'. The settings live in tacctl.yaml (internal/policy);
// every group, built-in or custom, is edited the same way.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/render/radius"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

func groupJunosUsage(overrides string) string {
	return Usage("group-junos", UsageVars{"overrides": overrides})
}

// patterns is "1 pattern" / "3 patterns".
func patterns(n int) string {
	if n == 1 {
		return "1 pattern"
	}
	return strconv.Itoa(n) + " patterns"
}

// junosSize is "<bytes> of <limit> bytes" for a set.
func junosSize(attr string, items []string) string {
	return fmt.Sprintf("%d of %d bytes", len(conf.JunosValue(items)), conf.JunosLimit(attr))
}

// groupJunos is 'group junos <group> <attr>|list|clear ...'.
func (inv *invocation) groupJunos(args []string) error {
	a := inv.app
	group, word := arg(args, 0), arg(args, 1)
	switch group {
	case "", "-h", "--help", "help":
		inv.write(groupJunosUsage(a.Paths.Overrides))
		if group == "" {
			return exit(1)
		}
		return nil
	}
	attr, isAttr := policy.JunosAttrOf(word)
	verb := arg(args, 2)
	if word == "list" || word == "clear" {
		verb = word
	}
	if !isAttr && word != "list" && word != "clear" || isAttr && !slices.Contains([]string{"list", "add", "remove", "clear"}, verb) {
		a.Out.ErrorE("Usage: tacctl group junos <group> list|clear | deny-commands|deny-configuration list|add|remove|clear [<regex>]")
		return exit(1)
	}
	if verb != "list" {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	g := m.Group(group)
	if g == nil {
		return inv.usageErr("Group '" + group + "' does not exist.")
	}
	c := a.Conf()
	attrs := conf.JunosAttrs
	if isAttr {
		attrs = []string{attr}
	}

	switch verb {
	case "list":
		inv.groupJunosList(g, attrs)
	case "add", "remove":
		pattern := arg(args, 3)
		if pattern == "" {
			return inv.usageErr("Usage: tacctl group junos " + group + " " + conf.JunosArg(attr) + " " + verb + " '<regex>'")
		}
		items := policy.JunosSet(c, group, attr)
		where := conf.JunosArg(attr) + " of group '" + group + "'"
		if verb == "remove" {
			i := slices.Index(items, pattern)
			if i < 0 {
				a.Out.WarnE("Pattern not in " + where + ".")
				return nil
			}
			items = slices.Delete(slices.Clone(items), i, i+1)
		} else {
			if why := conf.JunosItemProblem(pattern); why != "" {
				return inv.usageErr("Pattern '" + pattern + "' " + why + ".")
			}
			if slices.Contains(items, pattern) {
				a.Out.Info("Pattern already present in " + where + "; no change.")
				return nil
			}
			items = append(slices.Clone(items), pattern)
			if p := policy.JunosProblem(group, attr, items); p != nil {
				return inv.usageErr(p...)
			}
		}
		if err := inv.applyWith(func() error { return policy.WriteJunosSet(a.Conf(), group, attr, items) }); err != nil {
			return err
		}
		done := "Added to "
		if verb == "remove" {
			done = "Removed from "
		}
		a.Out.Info(done + where + " (now " + patterns(len(items)) + ", " + junosSize(attr, items) + ").")
		inv.echo("")
	case "clear":
		var set []string
		for _, at := range attrs {
			if len(policy.JunosSet(c, group, at)) > 0 {
				set = append(set, conf.JunosArg(at))
			}
		}
		if len(set) == 0 {
			a.Out.Info("Group '" + group + "' has no Junos rules there; nothing to clear.")
			return nil
		}
		if !a.Prompter().ConfirmPrefix("  Clear " + strings.Join(set, " and ") + " of group '" + group + "'? [y/N]: ") {
			a.Out.Info("Aborted.")
			return nil
		}
		if err := inv.applyWith(func() error {
			for _, at := range attrs {
				if err := policy.WriteJunosSet(a.Conf(), group, at, nil); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		a.Out.Info("Cleared " + strings.Join(set, " and ") + " of group '" + group + "'.")
		inv.echo("")
	}
	return nil
}

// groupJunosList prints the group's sets (§5.1).
func (inv *invocation) groupJunosList(g *model.Group, attrs []string) {
	c := inv.app.Conf()
	title := "Junos rules for group '" + g.Name + "' (class " + g.JuniperClass + ")"
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	for _, attr := range attrs {
		items := policy.JunosSet(c, g.Name, attr)
		if len(items) == 0 {
			inv.echo(fmt.Sprintf("  %-20s none", conf.JunosArg(attr)))
			continue
		}
		inv.echo(fmt.Sprintf("  %-20s %-12s %s", conf.JunosArg(attr), patterns(len(items)), junosSize(attr, items)))
		for _, it := range items {
			inv.echo("    " + it)
		}
	}
	inv.echo("  Sent at login over TACACS+ (junos-exec) and RADIUS (Juniper VSAs) to the")
	inv.echo("  scopes that serve Juniper devices.")
	inv.echo("")
}

// wtiLabel is a level as the WTI menus name it (SuperUser, ...).
func wtiLabel(level string) string {
	_, label := radius.WTISuper(policy.WTIPrivLvl(level))
	return label
}

// groupEditWTILevel is 'group edit <g> wti-level <level>|auto' (§5.2).
func (inv *invocation) groupEditWTILevel(g *model.Group, value string) error {
	a := inv.app
	if value != "auto" && !slices.Contains(conf.WTILevels, value) {
		return inv.usageErr("Unknown WTI level '" + value + "'. Use: auto, " + strings.Join(conf.WTILevels, ", "))
	}
	if err := inv.applyWith(func() error { return policy.WriteWTILevel(a.Conf(), g.Name, value) }); err != nil {
		return err
	}
	if value == "auto" {
		auto := policy.WTILevelOf(privOf(g))
		a.Out.Info(fmt.Sprintf("Group '%s' WTI level is automatic again (priv-lvl %d → %s).", g.Name, privOf(g), wtiLabel(auto)))
		return nil
	}
	lv := policy.WTIPrivLvl(value)
	super, _ := radius.WTISuper(lv)
	a.Out.Info(fmt.Sprintf("Group '%s' WTI level set to %s (TACACS+: service wti priv-lvl %d; RADIUS: WTI-Super %d).", g.Name, value, lv, super))
	a.Out.Warn("Units must send Service Name 'wti' (the factory default; 'tacctl config wti' shows the step).")
	return nil
}

// groupEditTier is 'group edit <g> tier <tier>|auto' (D18).
func (inv *invocation) groupEditTier(g *model.Group, value string) error {
	a := inv.app
	if value != "auto" && !slices.Contains(conf.Tiers, value) {
		return inv.usageErr("Unknown tier '" + value + "'. Use: auto, " + strings.Join(conf.Tiers, ", "))
	}
	if err := inv.applyWith(func() error { return policy.WriteGroupTier(a.Conf(), g.Name, value) }); err != nil {
		return err
	}
	if value == "auto" {
		a.Out.Info(fmt.Sprintf("Group '%s' tacctl tier is automatic again (priv-lvl %d → %s).", g.Name, privOf(g), bandTier(g)))
	} else {
		a.Out.Info("Group '" + g.Name + "' tacctl tier set to " + value + ".")
	}
	a.Out.Info("Linux hosts take the change at their next sync: tacctl host sync --all")
	return nil
}

// privOf is the group's priv-lvl (0 for a hand-edited store without one).
func privOf(g *model.Group) int {
	if g.PrivLvl == nil {
		return 0
	}
	return *g.PrivLvl
}

// bandTier is the tier the group's priv-lvl band gives.
func bandTier(g *model.Group) string {
	return string(tier.ForPrivLvl(strconv.Itoa(privOf(g))))
}

// groupShow is 'group show <group>' (§5.3, D27): every setting and where
// it comes from.
func (inv *invocation) groupShow(args []string) error {
	group := arg(args, 0)
	if group == "" {
		return inv.usageErr("Usage: tacctl group show <name>")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	g := m.Group(group)
	if g == nil {
		return inv.usageErr("Group '" + group + "' does not exist.")
	}
	c := inv.app.Conf()
	title := "Group '" + group + "'"
	row := func(label, value string) { inv.echo(fmt.Sprintf("  %-18s %s", label+":", value)) }
	hint := func(value, cmd string) string {
		if len(value) > 32 {
			return value + "\n" + strings.Repeat(" ", 21) + cmd
		}
		return fmt.Sprintf("%-32s %s", value, cmd)
	}
	inv.echo("")
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	row("Cisco priv-lvl", strconv.Itoa(privOf(g)))
	row("Juniper class", g.JuniperClass)
	if t := policy.GroupTier(c, group); t != "" {
		row("tacctl tier", t+" (set; auto would be "+bandTier(g)+")")
	} else {
		row("tacctl tier", bandTier(g)+" (auto, from priv-lvl)")
	}
	level, over := policy.WTILevel(c, group, privOf(g))
	if over {
		row("WTI level", wtiLabel(level)+" (set; auto would be "+wtiLabel(policy.WTILevelOf(privOf(g)))+")")
	} else {
		row("WTI level", wtiLabel(level)+" (auto, from priv-lvl)")
	}
	rules := policy.Lines(c, group)
	desc := "none"
	if len(rules) > 0 {
		desc = fmt.Sprintf("%d rules, default %s", len(rules), policy.DefaultAction(c, group))
	}
	row("Command rules", hint(desc, "tacctl group commands list "+group))
	var sets []string
	for _, attr := range conf.JunosAttrs {
		if items := policy.JunosSet(c, group, attr); len(items) > 0 {
			sets = append(sets, fmt.Sprintf("%s %d/%d bytes", conf.JunosArg(attr), len(conf.JunosValue(items)), conf.JunosLimit(attr)))
		}
	}
	if len(sets) == 0 {
		sets = []string{"none"}
	}
	row("Junos rules", hint(strings.Join(sets, ", "), "tacctl group junos "+group+" list"))
	row("Users", strconv.Itoa(len(m.GroupUsers(group))))
	inv.echo("")
	return nil
}

// groupHasSettings is whether tacctl.yaml holds any per-group device
// setting of group.
func groupHasSettings(c *conf.Config, group string) bool {
	_, over := policy.WTILevel(c, group, 0)
	if over || policy.GroupTier(c, group) != "" {
		return true
	}
	for _, attr := range conf.JunosAttrs {
		if len(policy.JunosSet(c, group, attr)) > 0 {
			return true
		}
	}
	return false
}
