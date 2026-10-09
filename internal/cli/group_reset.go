package cli

// 'group reset <group> [--preset] [--only <sections>] [--dry-run] [--yes]'
// (docs/plans/0.2.3-plan.md D51): a group put back to its canonical state
// (internal/policy/canonical.go) with the difference shown first and a
// confirmation. The plan is computed before anything is written; it is
// printed in four sections (settings, commands, privileges, junos), and the
// writes are the setters 'group edit', 'group commands', 'group privilege'
// and 'group junos' use, in one apply, so the backends render and restart
// once and the snapshot StoreApply takes comes first.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

// The sections of a reset, in the order they are shown and written.
const (
	sectionSettings   = "settings"
	sectionCommands   = "commands"
	sectionPrivileges = "privileges"
	sectionJunos      = "junos"
)

var resetSections = []string{sectionSettings, sectionCommands, sectionPrivileges, sectionJunos}

const groupResetUsage = "Usage: tacctl group reset <group> [--preset] [--only settings,commands,privileges,junos] [--dry-run] [--yes]"

// resetSection is one section of the plan: what it shows, the warnings that
// go with it, and how it is written.
type resetSection struct {
	name  string
	lines []string // the difference; none: the section is unchanged
	warns []string
	// notes are lines printed under the warnings (the device lines to
	// remove, for 'group privilege reset').
	notes []string
	// fields are the store fields to set on the group (settings); writes the
	// changes to tacctl.yaml.
	fields []string
	writes []func(*conf.Config) error
}

func (s *resetSection) changed() bool { return len(s.lines) > 0 }

// resetPlan is everything a reset would do.
type resetPlan struct {
	group    string
	canon    policy.Canonical
	title    string          // the heading; none: the one 'group reset' prints
	sections []*resetSection // the selected ones, in order
	// guard are the groups at the group's priv-lvl without command rules,
	// which get a permit catch-all (policy.SeedSiblings), and the level.
	guard      []string
	guardLevel string
	// levels are the groups' priv-lvls after the reset (model_group_info
	// lines), for the guard.
	levels policy.GroupLevels
}

func (p *resetPlan) changed() bool {
	for _, s := range p.sections {
		if s.changed() {
			return true
		}
	}
	return false
}

// changedNames are the sections that change something.
func (p *resetPlan) changedNames() []string {
	var out []string
	for _, s := range p.sections {
		if s.changed() {
			out = append(out, s.name)
		}
	}
	return out
}

func (p *resetPlan) section(name string) *resetSection {
	for _, s := range p.sections {
		if s.name == name {
			return s
		}
	}
	return nil
}

// onlySections parses --only: the section words, comma separated, in the
// order the reset knows them; every section for none. The second result is
// what is wrong with the value ("" when nothing).
func onlySections(value string) ([]string, string) {
	if value == "" {
		return slices.Clone(resetSections), ""
	}
	want := map[string]bool{}
	for _, w := range strings.Split(value, ",") {
		if !slices.Contains(resetSections, w) {
			return nil, "Unknown section '" + w + "' for --only. Use: " + strings.Join(resetSections, ", ")
		}
		want[w] = true
	}
	var out []string
	for _, s := range resetSections {
		if want[s] {
			out = append(out, s)
		}
	}
	return out, ""
}

func (inv *invocation) groupReset(args []string) error {
	a := inv.app
	p, err := Parse(groupSpecs["reset"], args)
	if err != nil {
		return inv.usageErr(err.Error(), groupResetUsage)
	}
	group := p.Args[0]
	only, problem := onlySections(p.Value("--only"))
	if problem != "" {
		return inv.usageErr(problem, groupResetUsage)
	}
	preset, dry, yes := p.Has("--preset"), p.Has("--dry-run"), p.Has("--yes")
	if !dry {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	canon, ok := policy.CanonicalGroup(group, preset)
	if !ok {
		if exists, err := inv.groupExists(group); err != nil {
			return err
		} else if !exists {
			return inv.usageErr("Group '" + group + "' does not exist.")
		}
		return inv.usageErr("Group '" + group + "' is not a built-in or role group, so it has no canonical defaults; group commands reset " + group + " drops its command overrides.")
	}
	c := a.Conf()
	if prob := c.Problem(); prob != "" {
		return inv.usageErr(c.Path + " cannot be read (" + prob + "); nothing was changed.")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if m.Group(group) == nil && !slices.Contains(only, sectionSettings) {
		return inv.usageErr("Group '"+group+"' does not exist yet; the reset creates it with its settings, so --only must include settings.", groupResetUsage)
	}
	plan := inv.planReset(m, c, canon, only)
	if slices.Contains(only, sectionJunos) {
		for _, attr := range conf.JunosAttrs {
			if prob := policy.JunosProblem(group, attr, canon.JunosItems(attr)); prob != nil {
				return inv.usageErr(prob...)
			}
		}
	}

	if !plan.changed() {
		msg := "Group '" + group + "' is already canonical"
		if len(only) < len(resetSections) {
			msg += " (" + strings.Join(only, ", ") + ")"
		}
		a.Out.Info(msg + "; nothing to change.")
		return nil
	}
	inv.printReset(plan, preset)
	if dry {
		a.Out.Info("Dry run: nothing was written.")
		return nil
	}
	if !yes {
		if !a.Prompter().Interactive() {
			return inv.usageErr("No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes.")
		}
		if !a.Prompter().ConfirmPrefix("  Apply these changes to group '" + group + "'? [y/N]: ") {
			a.Out.Info("Aborted.")
			return nil
		}
	}

	watch := inv.watchServerTiers()
	if err := inv.applyWith(func() error { return inv.applyReset(plan) }); err != nil {
		return err
	}
	done := plan.changedNames()
	a.Logger(inv.ctx, "auth.info", "group reset name="+group+" sections="+strings.Join(done, ",")+" by="+inv.sudoUser())
	a.Out.Info("Group '" + group + "' reset (" + strings.Join(done, ", ") + ").")
	if len(plan.guard) > 0 {
		a.Out.Info("Auto-seeded permit-* catchall on sibling groups at priv-lvl " + plan.guardLevel + ": " + strings.Join(plan.guard, " "))
	}
	inv.echo("  Review with: tacctl group show " + group)
	inv.echo("")
	return watch.lowered("'"+group+"'", "Members of '"+group+"' keep their old groups")
}

// planReset is the difference between the group's state and canon, for the
// sections in only. Nothing is written.
func (inv *invocation) planReset(m *model.Model, c *conf.Config, canon policy.Canonical, only []string) *resetPlan {
	group := canon.Group
	g := m.Group(group)
	p := &resetPlan{group: group, canon: canon}
	for _, name := range only {
		var s *resetSection
		switch name {
		case sectionSettings:
			s = planSettings(m, c, g, canon)
		case sectionCommands:
			s = planCommands(c, canon)
		case sectionPrivileges:
			s = planPrivileges(c, canon)
		case sectionJunos:
			s = planJunos(c, canon)
		}
		p.sections = append(p.sections, s)
	}
	p.planGuard(m, c, g)
	return p
}

// planGuard is the lockout guard of 'group commands' (SeedSiblings): a group
// that has command rules after the reset must not leave a group at its
// priv-lvl without any, or the level's 'aaa authorization commands' line
// would deny that group every command (tacctl config cisco leaves the line
// commented out when a group at the level has none). Only the groups the
// reset moves to a level or gives rules are looked at.
func (p *resetPlan) planGuard(m *model.Model, c *conf.Config, g *model.Group) {
	set, cmds := p.section(sectionSettings), p.section(sectionCommands)
	if (set == nil || !set.changed()) && (cmds == nil || !cmds.changed()) {
		return
	}
	rules := policy.Lines(c, p.group)
	if cmds != nil {
		rules = p.canon.Rules
	}
	for _, l := range m.GroupInfo() {
		if policy.Field(l, 1) == p.group {
			continue
		}
		p.levels = append(p.levels, l)
	}
	priv := strconv.Itoa(p.canon.PrivLvl)
	if set == nil && g != nil {
		priv = strconv.Itoa(privOf(g))
	}
	p.levels = append(p.levels, p.group+"|"+priv+"|"+p.canon.Class)
	if len(nonBlankLines(rules)) == 0 {
		warn := "group '" + p.group + "' has no command rules at priv-lvl " + priv + ", so tacctl config cisco leaves 'aaa authorization commands " +
			priv + "' commented out; run: tacctl group commands default " + p.group + " permit"
		switch {
		case set != nil && set.changed():
			set.warns = append(set.warns, warn)
		case cmds != nil && cmds.changed():
			cmds.warns = append(cmds.warns, warn)
		}
		return
	}
	level, bare := policy.BareSiblings(c, p.levels, p.group)
	p.guard, p.guardLevel = bare, level
}

func nonBlankLines(lines []string) []string {
	var out []string
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// tierSettingText is a tier setting as 'group show' words it.
func tierSettingText(setting string, priv int) string {
	switch setting {
	case tier.InvalidSetting:
		return "readonly (the setting in tacctl.yaml is not a tier)"
	case "":
		return string(tier.ForPrivLvl(strconv.Itoa(priv))) + " (auto, from priv-lvl)"
	}
	return setting + " (set)"
}

// wtiSettingText is a WTI level setting as 'group show' words it.
func wtiSettingText(setting string, priv int) string {
	if setting == "" {
		return wtiLabel(policy.WTILevelOf(priv)) + " (auto, from priv-lvl)"
	}
	return wtiLabel(setting) + " (set)"
}

func planSettings(m *model.Model, c *conf.Config, g *model.Group, canon policy.Canonical) *resetSection {
	s := &resetSection{name: sectionSettings}
	group := canon.Group
	row := func(label, from, to string) {
		s.lines = append(s.lines, fmt.Sprintf("%-16s %s -> %s", label, from, to))
	}
	privTo := strconv.Itoa(canon.PrivLvl)
	cur := canon.PrivLvl // the priv-lvl the group has now (a group to create has none: the band it will have)
	if g != nil {
		cur = privOf(g)
	}
	if g == nil {
		s.lines = append(s.lines, fmt.Sprintf("%-16s does not exist: it is created with Cisco priv-lvl %s and Juniper class %s", "group:", privTo, canon.Class))
		s.fields = []string{"priv_lvl=" + privTo, "juniper_class=" + canon.Class}
	} else {
		if g.PrivLvl == nil || *g.PrivLvl != canon.PrivLvl {
			from := "none"
			if g.PrivLvl != nil {
				from = strconv.Itoa(*g.PrivLvl)
			}
			row("Cisco priv-lvl:", from, privTo)
			s.fields = append(s.fields, "priv_lvl="+privTo)
			s.warns = append(s.warns, "Cisco logins and the per-level authorization lines change; re-paste tacctl config cisco")
		}
		if g.JuniperClass != canon.Class {
			from := g.JuniperClass
			if from == "" {
				from = "none"
			}
			row("Juniper class:", from, canon.Class)
			s.fields = append(s.fields, "juniper_class="+canon.Class)
			s.warns = append(s.warns, "the Junos template user of the class changes; re-paste tacctl config juniper Step 1")
		}
	}
	have := policy.GroupTier(c, group)
	if have != canon.Tier {
		row("tacctl tier:", ifGroup(g, tierSettingText(have, cur)), tierSettingText(canon.Tier, canon.PrivLvl))
		t := canon.Tier
		s.writes = append(s.writes, func(c *conf.Config) error { return policy.WriteGroupTier(c, group, t) })
		before := tier.ForGroup(have, strconv.Itoa(cur))
		after := tier.ForGroup(canon.Tier, privTo)
		if n := len(m.GroupUsers(group)); g != nil && n > 0 && tier.Rank(after) < tier.Rank(before) {
			s.warns = append(s.warns, fmt.Sprintf("the tier of its %d user(s) falls from %s to %s; this server's accounts are synced after the reset", n, before, after))
		}
	}
	level, over := policy.WTILevel(c, group, cur)
	haveWTI := ""
	if over {
		haveWTI = level
	}
	if haveWTI != canon.WTI {
		row("WTI level:", ifGroup(g, wtiSettingText(haveWTI, cur)), wtiSettingText(canon.WTI, canon.PrivLvl))
		w := canon.WTI
		s.writes = append(s.writes, func(c *conf.Config) error { return policy.WriteWTILevel(c, group, w) })
	}
	return s
}

// ifGroup is the current value of a setting of a group that exists; a group
// the reset creates has none.
func ifGroup(g *model.Group, text string) string {
	if g == nil {
		return "none"
	}
	return text
}

func planCommands(c *conf.Config, canon policy.Canonical) *resetSection {
	s := &resetSection{name: sectionCommands}
	have := policy.Lines(c, canon.Group)
	if policy.SameLines(have, canon.Rules) {
		return s
	}
	removed, added, moved := diffSequences(nonBlankLines(have), nonBlankLines(canon.Rules))
	for _, l := range removed {
		s.lines = append(s.lines, "- "+ruleText(l))
	}
	for _, l := range added {
		s.lines = append(s.lines, "+ "+ruleText(l))
	}
	for _, l := range moved {
		s.lines = append(s.lines, "~ "+ruleText(l)+"  (moved)")
	}
	if from, to := policy.DefaultActionOf(have), policy.DefaultActionOf(canon.Rules); from != to {
		s.lines = append(s.lines, "default action: "+from+" -> "+to)
	}
	rules := canon.Rules
	if !canon.RulesOverride {
		rules = nil // no commands.<group> of its own: the shipped rules apply
	}
	s.writes = append(s.writes, func(c *conf.Config) error { return policy.Write(c, canon.Group, rules) })
	return s
}

// ruleText is a rule line as 'group commands list' shows its columns.
func ruleText(line string) string {
	return strings.TrimRight(fmt.Sprintf("%-12s %-6s %s", policy.Field(line, 1), policy.Field(line, 2), ruleMatch(line)), " ")
}

func planPrivileges(c *conf.Config, canon policy.Canonical) *resetSection {
	s := &resetSection{name: sectionPrivileges}
	have := policy.Privileges(c, canon.Group)
	if slices.Equal(nonBlankLines(have), nonBlankLines(canon.Privileges)) {
		return s
	}
	removed, added, moved := diffSequences(nonBlankLines(have), nonBlankLines(canon.Privileges))
	for _, l := range removed {
		s.lines = append(s.lines, "- "+l)
	}
	for _, l := range added {
		s.lines = append(s.lines, "+ "+l)
	}
	for _, l := range moved {
		s.lines = append(s.lines, "~ "+l+"  (moved)")
	}
	s.writes = append(s.writes, func(c *conf.Config) error { return policy.ClearPrivileges(c, canon.Group) })
	return s
}

func planJunos(c *conf.Config, canon policy.Canonical) *resetSection {
	s := &resetSection{name: sectionJunos}
	for _, attr := range conf.JunosAttrs {
		have, want := policy.JunosSet(c, canon.Group, attr), canon.JunosItems(attr)
		if slices.Equal(have, want) {
			continue
		}
		size := func(items []string) string {
			if len(items) == 0 {
				return "none"
			}
			return fmt.Sprintf("%d/%d bytes", len(conf.JunosValue(items)), conf.JunosLimit(attr))
		}
		s.lines = append(s.lines, fmt.Sprintf("%s: %s -> %s", conf.JunosArg(attr), size(have), size(want)))
		removed, added, moved := diffSequences(have, want)
		for _, l := range removed {
			s.lines = append(s.lines, "  - "+l+"  ("+strconv.Itoa(len(l))+" bytes)")
		}
		for _, l := range added {
			s.lines = append(s.lines, "  + "+l+"  ("+strconv.Itoa(len(l))+" bytes)")
		}
		for _, l := range moved {
			s.lines = append(s.lines, "  ~ "+l+"  (moved)")
		}
		attr, want := attr, want
		s.writes = append(s.writes, func(c *conf.Config) error { return policy.WriteJunosSet(c, canon.Group, attr, want) })
	}
	return s
}

// diffSequences is the difference of two ordered lists: the items of have
// that are not in want (removed), those of want that are not in have
// (added), and those both have in a different relative order (moved). It
// keeps the longest common subsequence in place; an item outside it that
// the other list also has is moved.
func diffSequences(have, want []string) (removed, added, moved []string) {
	n, m := len(have), len(want)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if have[i] == want[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var loseH, loseW []string
	for i, j := 0, 0; i < n || j < m; {
		switch {
		case i < n && j < m && have[i] == want[j]:
			i, j = i+1, j+1
		case j == m || i < n && lcs[i+1][j] >= lcs[i][j+1]:
			loseH = append(loseH, have[i])
			i++
		default:
			loseW = append(loseW, want[j])
			j++
		}
	}
	left := map[string]int{}
	for _, l := range loseW {
		left[l]++
	}
	gone := map[string]int{}
	for _, l := range loseH {
		if left[l] > 0 {
			left[l]--
			gone[l]++
			moved = append(moved, l)
			continue
		}
		removed = append(removed, l)
	}
	for _, l := range loseW {
		if gone[l] > 0 {
			gone[l]--
			continue
		}
		added = append(added, l)
	}
	return removed, added, moved
}

// printReset is the plan as the user reads it before confirming.
func (inv *invocation) printReset(p *resetPlan, preset bool) {
	what := "its canonical defaults"
	switch {
	case p.canon.Group == "engineer":
		what = "the role preset's engineer"
	case preset:
		what = "the role preset's values"
	}
	title := "Reset of group '" + p.group + "' to " + what
	if p.title != "" {
		title = p.title
	}
	inv.echo("")
	inv.echo(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	for _, s := range p.sections {
		inv.echo("  " + ui.Bold + s.name + ui.NC)
		if !s.changed() {
			inv.echo("    unchanged")
			continue
		}
		for _, l := range s.lines {
			inv.echo("    " + l)
		}
		for _, w := range s.warns {
			inv.echo("    " + ui.Yellow + "warning:" + ui.NC + " " + w)
		}
		for _, n := range s.notes {
			inv.echo("      " + n)
		}
	}
	if len(p.guard) > 0 {
		inv.echo("  Groups at priv-lvl " + p.guardLevel + " without command rules get a permit-* catchall, so that Cisco does not deny them every command: " + strings.Join(p.guard, " "))
	}
	inv.echo("")
}

// applyReset writes the plan; it runs inside the apply.
func (inv *invocation) applyReset(p *resetPlan) error {
	if set := p.section(sectionSettings); set != nil && len(set.fields) > 0 {
		fields := set.fields
		if err := inv.mutate(func(s *store.Store) error { return s.GroupSet(p.group, fields...) }); err != nil {
			return err
		}
	}
	for _, s := range p.sections {
		for _, w := range s.writes {
			if err := w(inv.app.Conf()); err != nil {
				return err
			}
		}
	}
	if len(p.guard) > 0 {
		if _, _, err := policy.SeedSiblings(inv.app.Conf(), p.levels, p.group); err != nil {
			return err
		}
	}
	return nil
}
