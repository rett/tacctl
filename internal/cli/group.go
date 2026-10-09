package cli

// The 'group' family (lib/groups.sh cmd_group at 0.1.16), native since
// WP2.4b. Groups live in the store; their command rules and priv-exec
// mappings live in tacctl.yaml (internal/policy). Every message, prompt,
// exit status and the order of the checks are the bash's.

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/shellquote"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// groupSpecs are the arguments of each verb, for completion (args.go); the
// verbs of 'commands' and 'privilege' are under "commands <verb>" and
// "privilege <verb>".
var groupSpecs = map[string]Spec{
	"list": {},
	"add": {MinArgs: 3, MaxArgs: 3, Args: []string{"", "", ""}, Flags: []Flag{
		{Names: []string{"--tier"}, Value: true, Kind: "readonly|operator|engineer|superuser"},
		{Names: []string{"--wti-level"}, Value: true, Kind: "viewonly|user|superuser|administrator"}}},
	"remove": {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}},
	"edit":   {MinArgs: 3, MaxArgs: 3, Args: []string{KindGroups, "priv-lvl|juniper-class|wti-level|tier", ""}},
	"show":   {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}},
	"preset roles": {Flags: []Flag{
		{Names: []string{"--dry-run"}}, {Names: []string{"--force"}}}},
	"reset": {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}, Flags: []Flag{
		{Names: []string{"--preset"}}, {Names: []string{"--only"}, Value: true, Kind: "settings|commands|privileges|junos" + KindList},
		{Names: []string{"--dry-run"}}, {Names: []string{"--yes"}}}},
	"junos": {MinArgs: 2, MaxArgs: 4, Args: []string{KindGroups, "list|clear|deny-commands|deny-configuration", "list|add|remove|clear", ""}},

	"commands list":    {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}},
	"commands default": {MinArgs: 2, MaxArgs: 2, Args: []string{KindGroups, "permit|deny"}},
	"commands add": {MinArgs: 2, MaxArgs: 2, Args: []string{KindGroups, ""}, Flags: []Flag{
		{Names: []string{"--match"}, Value: true, Repeat: true}, {Names: []string{"--action"}, Value: true, Kind: "permit|deny"},
		{Names: []string{"--before"}, Value: true}, {Names: []string{"--first"}}}},
	"commands remove": {MinArgs: 2, MaxArgs: 2, Args: []string{KindGroups, ""}, Flags: []Flag{
		{Names: []string{"--match"}, Value: true, Repeat: true}, {Names: []string{"--action"}, Value: true, Kind: "permit|deny"},
		{Names: []string{"--all"}}}},
	"commands reset": {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}, Flags: []Flag{{Names: []string{"--dry-run"}}, {Names: []string{"--yes"}}}},
	"commands seed":  {MaxArgs: 1, Args: []string{"readonly|operator|superuser"}, Flags: []Flag{{Names: []string{"--force"}}}},

	"privilege list":   {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}},
	"privilege add":    {MinArgs: 2, MaxArgs: 2, Args: []string{KindGroups, privModeWords}},
	"privilege remove": {MinArgs: 2, MaxArgs: 2, Args: []string{KindGroups, ""}},
	"privilege reset":  {MinArgs: 1, MaxArgs: 1, Args: []string{KindGroups}, Flags: []Flag{{Names: []string{"--dry-run"}}, {Names: []string{"--yes"}}}},
	"privilege seed":   {MaxArgs: 1, Args: []string{"readonly|operator|superuser"}, Flags: []Flag{{Names: []string{"--force"}}}},
}

// privModeWords are what completion offers for the entry of 'privilege
// add': the mode prefixes an entry may start with (names.PrivModes).
var privModeWords = "exec:|exec all:|configure:|configure all:"

func groupCmd(inv *invocation) *cobra.Command {
	n := func(run func([]string) error) func(*cobra.Command, []string) error {
		return inv.native(withPreflight, run)
	}
	// The verbs of a sub-family run its dispatcher with the verb put back
	// in front, as bash's case statement sees it.
	sub := func(family func([]string) error, word string) func(*cobra.Command, []string) error {
		return n(func(args []string) error { return family(append([]string{word}, args...)) })
	}
	cmds := verb("commands {list|default|add|remove|reset|seed} <group> ...", "Per-group authorized commands",
		withRun(verb("list <group>", "Show rules + default action"), sub(inv.groupCommands, "list")),
		withRun(verb("default <group> <permit|deny>", "Set default action (catchall)"), sub(inv.groupCommands, "default")),
		withRun(verb("add <group> <name> [--match <regex>]... [--action permit|deny]", "Add a rule"), sub(inv.groupCommands, "add")),
		withRun(verb("remove <group> <name>", "Drop a rule"), sub(inv.groupCommands, "remove")),
		withRun(verb("reset <group> [--dry-run] [--yes]", "Revert the rules to the shipped defaults (diff, confirms)"), sub(inv.groupCommands, "reset")),
		withRun(verb("seed [<group>] [--force]", "Re-apply legacy seed set (recovery tool)"), sub(inv.groupCommands, "seed")),
	)
	cmds.RunE = n(inv.groupCommands)
	priv := verb("privilege {list|add|remove|reset|seed} <group> ...", "Per-group Cisco priv-exec mappings",
		withRun(verb("list <group>", "Show mappings (explicit or default)"), sub(inv.groupPrivilege, "list")),
		withRun(verb("add <group> '<cmd>'[,'<cmd>'...]", "Move one or more commands to the priv-lvl"), sub(inv.groupPrivilege, "add")),
		withRun(verb("remove <group> '<cmd>'[,'<cmd>'...]", "Remove mapping(s)"), sub(inv.groupPrivilege, "remove")),
		withRun(verb("reset <group> [--dry-run] [--yes]", "Revert the mappings to the shipped default (diff, confirms)"), sub(inv.groupPrivilege, "reset")),
		withRun(verb("seed [<group>] [--force]", "Populate built-ins with safe defaults"), sub(inv.groupPrivilege, "seed")),
	)
	priv.RunE = n(inv.groupPrivilege)
	preset := verb("preset roles [--dry-run] [--force]", "Starting values for the roles",
		withRun(verb("roles [--dry-run] [--force]", "Starting values for viewer, operator, engineer and superuser"), sub(inv.groupPreset, "roles")),
	)
	preset.RunE = n(inv.groupPreset)
	c := verb("group <subcommand>", "Group management (list, add, edit, remove)",
		withRun(verb("list", "List all groups"), n(inv.groupList)),
		withRun(verb("show <name>", "Every setting of a group and where it comes from, Junos patterns too"), n(inv.groupShow)),
		withRun(verb("add <name> <priv-lvl> <juniper-class> [--tier <tier>] [--wti-level <level>]", "Add a new group"), n(inv.groupAdd)),
		withRun(verb("remove <name>", "Remove a custom group"), n(inv.groupRemove)),
		withRun(verb("edit <name> {priv-lvl <0-15>|juniper-class <class>|wti-level <level>|tier <tier>}", "Change one setting of a group"), n(inv.groupEdit)),
		withRun(verb("junos <group> {list|clear|deny-commands|deny-configuration} ...", "Per-group Junos deny rules"), n(inv.groupJunos)),
		withRun(verb("reset <name> [--preset] [--only <sections>] [--dry-run] [--yes]", "Revert a group to its canonical defaults, with a diff and a confirmation"), n(inv.groupReset)),
		cmds, priv, preset,
	)
	// No sub-command, help or an unknown word: the usage, exit 1.
	c.RunE = n(func([]string) error {
		inv.write(groupUsage())
		return exit(1)
	})
	return c
}

// groupExists is model_group_exists, a model read error returned.
func (inv *invocation) groupExists(name string) (bool, error) {
	m, err := inv.model()
	if err != nil {
		return false, err
	}
	return m.Exists("groups", name), nil
}

// rePrivLvl is '[[ "$v" =~ ^[0-9]+$ ]]'.
var rePrivLvl = regexp.MustCompile(`^[0-9]+$`)

// privLvlOK is the 0-15 check of add and edit (an over-long number is not
// one bash's arithmetic takes: it fails the test too).
func privLvlOK(v string) bool {
	if !rePrivLvl.MatchString(v) {
		return false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return err == nil && n >= 0 && n <= 15
}

// --- list / add / remove / edit ---------------------------------------------

func (inv *invocation) groupList([]string) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	t := ui.NewTable("Groups", ui.Left("GROUP"), ui.Left("CISCO PRIV-LVL"), ui.Left("JUNIPER CLASS"), ui.Left("USERS"))
	for _, row := range m.GroupRows() {
		f := strings.SplitN(row, "|", 4)
		for len(f) < 4 {
			f = append(f, "")
		}
		if f[0] == "" {
			continue
		}
		t.Add(f[0], f[1], f[2], f[3])
	}
	inv.echo("")
	inv.write(t.String())
	inv.echo("")
	return nil
}

func (inv *invocation) groupAdd(args []string) error {
	a := inv.app
	spec := groupSpecs["add"]
	spec.MinArgs = 0
	p, err := Parse(spec, args)
	if err != nil {
		return inv.usageErr(err.Error(), "Usage: tacctl group add <name> <cisco-priv-lvl> <juniper-class> [--tier <tier>] [--wti-level <level>]")
	}
	args = p.Args
	tierV, wtiV := p.Value("--tier"), p.Value("--wti-level")
	group, privlvl, class := arg(args, 0), arg(args, 1), arg(args, 2)
	if group == "" || privlvl == "" || class == "" {
		a.Out.Error("Usage: tacctl group add <name> <cisco-priv-lvl> <juniper-class> [--tier <tier>] [--wti-level <level>]")
		inv.stderrLine("  Example: tacctl group add helpdesk 5 HELPDESK-CLASS")
		return exit(1)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if err := names.ValidateGroupName(group); err != nil {
		return inv.validated(err)
	}
	if exists, err := inv.groupExists(group); err != nil {
		return err
	} else if exists {
		return inv.usageErr("Group '" + group + "' already exists.")
	}
	if !privLvlOK(privlvl) {
		return inv.usageErr("Cisco privilege level must be 0-15.")
	}
	if err := names.ValidateClassName(class); err != nil {
		return inv.validated(err)
	}
	if p.Has("--tier") && !slices.Contains(conf.Tiers, tierV) {
		return inv.usageErr("Unknown tier '" + tierV + "'. Use: " + strings.Join(conf.Tiers, ", "))
	}
	if p.Has("--wti-level") && !slices.Contains(conf.WTILevels, wtiV) {
		return inv.usageErr("Unknown WTI level '" + wtiV + "'. Use: " + strings.Join(conf.WTILevels, ", "))
	}
	add := func(s *store.Store) error { return s.GroupSet(group, "priv_lvl="+privlvl, "juniper_class="+class) }
	// A group in the superuser band always has an explicit tier (the band
	// alone cannot tell a superuser group from an engineer group whose
	// setting was lost): without --tier it is written as superuser, what
	// the band gives.
	recorded := false
	if lvl, _ := strconv.Atoi(privlvl); tierV == "" && policy.NeedsTier(group, &lvl) {
		tierV, recorded = "superuser", true
	}
	// tacctl.yaml may still hold the tier, WTI level and Junos rules of an
	// earlier group of this name (a store import or a restore dropped the
	// group, not its settings): a new group starts with none of them, or it
	// would take over what the old one was given (a tier above its band).
	// Only the flags of this command set them; commands and privileges
	// overrides are not group-keyed identity and stay.
	leftover := staleKinds(a.Conf(), group)
	if tierV == "" && wtiV == "" && len(leftover) == 0 {
		err = inv.applyStore(add)
	} else {
		// One apply, so the backends render the group with its settings once.
		err = inv.applyWith(func() error {
			if err := inv.mutate(add); err != nil {
				return err
			}
			if len(leftover) > 0 {
				if err := policy.ForgetGroup(a.Conf(), group); err != nil {
					return err
				}
			}
			if err := policy.WriteGroupTier(a.Conf(), group, tierV); err != nil {
				return err
			}
			return policy.WriteWTILevel(a.Conf(), group, wtiV)
		})
	}
	if err != nil {
		return err
	}
	if len(leftover) > 0 {
		a.Out.Warn("tacctl.yaml still held " + strings.Join(leftover, ", ") + " settings of an earlier group '" + group +
			"'; they were cleared, so the new group starts from its priv-lvl band" + clearedFlags(tierV, wtiV) + ".")
	}
	a.Out.Info("Group '" + group + "' added (Cisco priv-lvl " + privlvl + ", Juniper " + class + ").")
	if recorded {
		a.Out.Info("tacctl tier: superuser (recorded, as every group at priv-lvl 15 has one; change it with: tacctl group edit " + group + " tier <tier>).")
	} else if tierV != "" {
		a.Out.Info("tacctl tier: " + tierV + ".")
	}
	if wtiV != "" {
		a.Out.Info("WTI level: " + wtiV + " (units must send Service Name 'wti').")
	}
	a.Out.Warn("On Juniper devices, create the template user: set system login user " + class + " class <junos-class>")
	inv.echo("")
	return nil
}

// clearedFlags is the sentence tail naming what the flags of 'group add' set
// again after the leftover settings went.
func clearedFlags(tierV, wtiV string) string {
	var set []string
	if tierV != "" {
		set = append(set, "--tier")
	}
	if wtiV != "" {
		set = append(set, "--wti-level")
	}
	if len(set) == 0 {
		return ""
	}
	return " (and what " + strings.Join(set, " and ") + " gives it)"
}

// staleKinds are the identity settings (tier, wti-level, junos) tacctl.yaml
// holds for group.
func staleKinds(c *conf.Config, group string) []string {
	var out []string
	if policy.GroupTier(c, group) != "" {
		out = append(out, "tier")
	}
	if _, over := policy.WTILevel(c, group, 0); over {
		out = append(out, "wti-level")
	}
	for _, attr := range conf.JunosAttrs {
		if len(policy.JunosSet(c, group, attr)) > 0 {
			out = append(out, "junos")
			break
		}
	}
	return out
}

// staleGroupLines are the warnings for the tier, WTI-level and Junos
// settings of tacctl.yaml that name a group the store does not have: one
// line per group. A group that arrives under such a name (a store import, a
// restore) takes the setting over; 'group add' clears it.
func (inv *invocation) staleGroupLines(m *model.Model) []string {
	var out []string
	for _, s := range policy.StaleGroups(inv.app.Conf(), func(g string) bool { return m.Exists("groups", g) }) {
		out = append(out, "tacctl.yaml has "+strings.Join(s.Kinds, ", ")+" settings for group '"+s.Group+
			"', which does not exist: a group that arrives under that name (a store import, a restore) would take them over. "+
			"Remove them from tacctl.yaml ('tacctl group add' clears them for a group it creates).")
	}
	return out
}

// warnStaleGroupSettings prints staleGroupLines for the store as it is now,
// after a step that replaced the store and kept tacctl.yaml.
func (inv *invocation) warnStaleGroupSettings() {
	if model.Mode(inv.app.Paths.StoreFile) != "store" {
		return
	}
	m, err := inv.app.LoadModel()
	if err != nil {
		return
	}
	for _, l := range inv.staleGroupLines(m) {
		inv.app.Out.Warn(l)
	}
}

func (inv *invocation) groupRemove(args []string) error {
	a := inv.app
	group := arg(args, 0)
	if group == "" {
		return inv.usageErr("Usage: tacctl group remove <name>")
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if contains(policy.Builtins, group) {
		return inv.usageErr("Cannot remove built-in group '" + group + "'.")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("groups", group) {
		return inv.usageErr("Group '" + group + "' does not exist.")
	}
	if n := len(m.GroupUsers(group)); n > 0 {
		return inv.usageErr(fmt.Sprintf("Cannot remove group '%s' — %d user(s) are assigned to it.", group, n),
			"Reassign those users first.")
	}
	inv.echo("")
	if !a.Prompter().Confirm("  Remove group '" + group + "'? [y/N]: ") {
		a.Out.Info("Cancelled.")
		return nil
	}
	del := func(s *store.Store) error { return s.GroupDel(group) }
	watch := inv.watchServerTiers()
	if !groupHasSettings(a.Conf(), group) {
		err = inv.applyStore(del)
	} else {
		// Its device settings in tacctl.yaml go with it (0.2.2).
		err = inv.applyWith(func() error {
			if err := inv.mutate(del); err != nil {
				return err
			}
			return policy.ForgetGroup(a.Conf(), group)
		})
	}
	if err != nil {
		return err
	}
	a.Out.Info("Group '" + group + "' removed.")
	inv.echo("")
	// Only a group without members can be removed, so no tier falls; the
	// watch is the same as every other verb that writes tiers has.
	return watch.lowered("'"+group+"'", "Members of '"+group+"' keep their old groups")
}

func (inv *invocation) groupEdit(args []string) error {
	a := inv.app
	group, field, value := arg(args, 0), arg(args, 1), arg(args, 2)
	if group == "" || field == "" || value == "" {
		a.Out.Error("Usage: tacctl group edit <name> <priv-lvl|juniper-class|wti-level|tier> <value>")
		inv.stderrLine("  Example: tacctl group edit operator priv-lvl 10")
		inv.stderrLine("  Example: tacctl group edit operator juniper-class NEW-CLASS")
		inv.stderrLine("  Example: tacctl group edit engineer wti-level superuser")
		inv.stderrLine("  Example: tacctl group edit engineer tier engineer")
		return exit(1)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if exists, err := inv.groupExists(group); err != nil {
		return err
	} else if !exists {
		return inv.usageErr("Group '" + group + "' does not exist.")
	}
	switch field {
	case "priv-lvl":
		if !privLvlOK(value) {
			return inv.usageErr("Cisco privilege level must be 0-15.")
		}
		watch := inv.watchServerTiers()
		set := func(s *store.Store) error { return s.GroupSet(group, "priv_lvl="+value) }
		// The tier setting follows the band across 15 (a group at priv-lvl
		// 15 always has one): raised into the band, a group with none gets
		// superuser (its band); lowered out of it, a superuser setting that
		// only recorded the band goes, so the lower band decides again.
		m, err := inv.model()
		if err != nil {
			return err
		}
		lvl, _ := strconv.Atoi(value)
		var tierNote string
		var tierWrite func() error
		switch cur := policy.GroupTier(a.Conf(), group); {
		case cur == "" && policy.NeedsTier(group, &lvl):
			tierNote = "tacctl tier: superuser (recorded, as every group at priv-lvl 15 has one; change it with: tacctl group edit " + group + " tier <tier>)."
			tierWrite = func() error { return policy.WriteGroupTier(a.Conf(), group, "superuser") }
		case cur == "superuser" && lvl < policy.SuperuserBand && group != "superuser" && privOf(m.Group(group)) >= policy.SuperuserBand:
			tierNote = "tacctl tier: automatic again (the superuser setting recorded the priv-lvl band; priv-lvl " + value + " → " + string(tier.ForPrivLvl(value)) + ")."
			tierWrite = func() error { return policy.WriteGroupTier(a.Conf(), group, "auto") }
		}
		if tierWrite == nil {
			err = inv.applyStore(set)
		} else {
			err = inv.applyWith(func() error {
				if err := inv.mutate(set); err != nil {
					return err
				}
				return tierWrite()
			})
		}
		if err != nil {
			return err
		}
		a.Out.Info("Group '" + group + "' Cisco priv-lvl changed to " + value + ".")
		if tierNote != "" {
			a.Out.Info(tierNote)
		}
		// The band is the tier of a group with none set: a lower priv-lvl
		// can lower it (and its members' groups on this server).
		if err := watch.lowered("'"+group+"'", "Members of '"+group+"' keep their old groups"); err != nil {
			return err
		}
	case "juniper-class":
		if err := names.ValidateClassName(value); err != nil {
			return inv.validated(err)
		}
		if err := inv.applyStore(func(s *store.Store) error { return s.GroupSet(group, "juniper_class="+value) }); err != nil {
			return err
		}
		a.Out.Info("Group '" + group + "' Juniper class changed to " + value + ".")
		a.Out.Warn("On Juniper devices: set system login user " + value + " class <junos-class>")
	case "wti-level", "tier":
		m, err := inv.model()
		if err != nil {
			return err
		}
		if field == "tier" {
			err = inv.groupEditTier(m.Group(group), value)
		} else {
			err = inv.groupEditWTILevel(m.Group(group), value)
		}
		if err != nil {
			return err
		}
	default:
		return inv.usageErr("Unknown field '" + field + "'. Use: priv-lvl, juniper-class, wti-level or tier")
	}
	inv.echo("")
	return nil
}

// --- commands ---------------------------------------------------------------

// groupSeedSiblings is seed_command_rules_safely with its two info lines.
func (inv *invocation) groupSeedSiblings(group string) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	privlvl, seeded, err := policy.SeedSiblings(inv.app.Conf(), m.GroupInfo(), group)
	if err != nil {
		return err
	}
	if len(seeded) > 0 {
		inv.app.Out.Info("Auto-seeded permit-* catchall on sibling groups at priv-lvl " + privlvl + ": " + strings.Join(seeded, " "))
		inv.app.Out.Info("(prevents lockout once Cisco 'aaa authorization commands " + privlvl + "' is applied.)")
	}
	return nil
}

func (inv *invocation) groupCommands(args []string) error {
	a := inv.app
	sub := arg(args, 0)
	switch sub {
	case "", "-h", "--help", "help":
		inv.write(groupCommandsUsage(a.Paths.Overrides))
		return nil
	case "seed":
		return inv.groupCommandsSeed(args[1:])
	case "reset":
		return inv.groupSectionReset(sectionCommands, args[1:])
	case "list", "default", "add", "remove":
	default:
		a.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(groupCommandsUsage(a.Paths.Overrides))
		return exit(1)
	}
	group := arg(args, 1)
	rest := args[min(2, len(args)):]
	if group == "" {
		return inv.usageErr("Usage: tacctl group commands " + sub + " <group> ...")
	}
	if sub != "list" {
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

	switch sub {
	case "list":
		rules := policy.Lines(c, group)
		b, nc := ui.Bold, ui.NC
		title := "Command rules for group '" + group + "'"
		inv.echo("")
		if len(rules) == 0 {
			inv.echoE(b + title + nc)
			inv.echo(ui.Rule(title))
			inv.echoE("  Default action: " + b + policy.DefaultAction(c, group) + nc)
			inv.echo("")
			inv.echo("  (no commands — custom group with no rules; all commands permitted)")
			inv.echo("")
			return nil
		}
		// '#' is the rule's position (what 'add --before/--first' and the
		// 'remove' messages count), so a skipped line still takes a number.
		t := ui.NewTable(title, ui.Right("#"), ui.Left("NAME"), ui.Left("ACTION"), ui.Left("MATCH"))
		catchall := false
		for i, r := range rules {
			name, action, match := policy.Field(r, 1), policy.Field(r, 2), ruleMatch(r)
			if name == "" {
				continue
			}
			color := ui.Green
			if action == "deny" {
				color = ui.Red
			}
			shown := name
			if name == policy.Catchall {
				catchall = true
				shown = name + " (catchall)"
			}
			t.Add(strconv.Itoa(i+1), shown, ui.Styled(color, action), match)
		}
		inv.write(t.String())
		inv.echo("")
		inv.echoE("  Default action: " + b + policy.DefaultAction(c, group) + nc)
		if !catchall {
			a.Out.Warn("No '*' catchall — tacquito will FAIL any unmatched command.")
			a.Out.Warn("Set the default explicitly with 'tacctl group commands default " + group + " permit|deny'.")
		}
		inv.echo("")
	case "default":
		action := arg(rest, 0)
		if action != "permit" && action != "deny" {
			return inv.usageErr("Usage: tacctl group commands default <group> <permit|deny>")
		}
		if err := inv.applyWith(func() error {
			if err := inv.groupSeedSiblings(group); err != nil {
				return err
			}
			return policy.UpdateCatchall(a.Conf(), group, action)
		}); err != nil {
			return err
		}
		a.Out.Info("Group '" + group + "' default action set to " + action + ".")
		inv.echo("")
	case "add":
		return inv.groupCommandsAdd(group, rest)
	case "remove":
		return inv.groupCommandsRemove(group, rest)
	}
	return nil
}

// commandRuleWarnings is policy.LintRules over every group that has
// commands in the merged tacctl.yaml, one line per finding.
func (inv *invocation) commandRuleWarnings() []string {
	c := inv.app.Conf()
	v, _ := c.Merged().Get("commands")
	groups, ok := v.(*yamlpy.Map)
	if !ok {
		return nil
	}
	keys := groups.Keys()
	sort.Strings(keys)
	var out []string
	for _, g := range keys {
		for _, f := range policy.LintRules(policy.Lines(c, g)) {
			out = append(out, "group '"+g+"' rule #"+strconv.Itoa(f.Pos)+" '"+policy.Field(f.Line, 1)+"': "+f.Msg)
		}
	}
	return out
}

// ruleMatch is the third field of 'IFS="|" read -r name action match': the
// rest of the line after the second '|'.
func ruleMatch(line string) string {
	f := strings.SplitN(line, "|", 3)
	if len(f) < 3 {
		return ""
	}
	return f[2]
}

// groupCommandsRemove is 'group commands remove <group> <name>': --match
// (repeatable, the rule's list as stored) and --action narrow the rules of
// that name to one; several are refused unless --all.
func (inv *invocation) groupCommandsRemove(group string, args []string) error {
	a := inv.app
	name := arg(args, 0)
	if name == "" {
		return inv.usageErr("Usage: tacctl group commands remove <group> <name> [--match <regex>]... [--action permit|deny] [--all]")
	}
	if name == policy.Catchall {
		return inv.usageErr("Cannot remove the '*' catchall. Use 'tacctl group commands default' to change its action,",
			"or 'tacctl group commands reset "+group+"' to revert this group to shipped defaults.")
	}
	var matches []string
	action, all := "", false
	rest := args[1:]
	for len(rest) > 0 {
		switch rest[0] {
		case "--match":
			if len(rest) < 2 {
				return inv.usageErr("--match needs a regex.")
			}
			matches = append(matches, rest[1])
			rest = rest[2:]
		case "--action":
			action = arg(rest, 1)
			if action != "permit" && action != "deny" {
				return inv.usageErr("--action must be 'permit' or 'deny'.")
			}
			rest = rest[2:]
		case "--all":
			all = true
			rest = rest[1:]
		default:
			return inv.usageErr("Unknown flag: '" + rest[0] + "'")
		}
	}
	c := a.Conf()
	if len(policy.RulesWhere(c, group, name, nil, "")) == 0 {
		a.Out.WarnE("No rule named '" + name + "' in group '" + group + "'.")
		return nil
	}
	switch n := len(policy.RulesWhere(c, group, name, matches, action)); {
	case n == 0:
		a.Out.WarnE("No rule named '" + name + "' in group '" + group + "' has that --match/--action.")
		return nil
	case n > 1 && !all:
		a.Out.ErrorE((&policy.AmbiguousError{Group: group, Name: name, Count: n}).Error())
		return exit(1)
	}
	var gone []policy.Numbered
	if err := inv.applyWith(func() error {
		var err error
		gone, err = policy.RemoveRuleWhere(a.Conf(), group, name, matches, action, all)
		return err
	}); err != nil {
		return err
	}
	for _, r := range gone {
		// Info, not InfoE: a match such as a\x2cb is printed as given.
		a.Out.Info("Removed rule #" + strconv.Itoa(r.Pos) + " '" + name + "' (" + policy.Field(r.Line, 2) +
			", match=[" + ruleMatch(r.Line) + "]) from group '" + group + "'.")
	}
	inv.echo("")
	return nil
}

func (inv *invocation) groupCommandsAdd(group string, args []string) error {
	a := inv.app
	name := arg(args, 0)
	if name == "" {
		return inv.usageErr("Usage: tacctl group commands add <group> <name> [--match <regex>]... [--action permit|deny] [--before <name>|--first]")
	}
	if err := names.ValidateCommandName(name); err != nil {
		return inv.validated(err)
	}
	if name == policy.Catchall {
		return inv.usageErr("Use 'tacctl group commands default " + group + " permit|deny' to change the catchall.")
	}
	action, matches := "permit", ""
	var where policy.Where
	rest := args[1:]
	for len(rest) > 0 {
		switch rest[0] {
		case "--match":
			rx := arg(rest, 1)
			if rx == "" {
				return inv.usageErr("--match needs a regex; an empty one is skipped by tacquito, so it matches nothing.",
					"Omit --match to cover any arguments.")
			}
			if err := names.ValidateRegex(rx); err != nil {
				return inv.validated(err)
			}
			// The rule line form ('name|action|m1,m2') joins the matches
			// with commas, so a comma inside one would split it on the
			// next write. (Printed without echo -e: the hint is literal.)
			if strings.Contains(rx, ",") {
				a.Out.Error(`A comma cannot be used in --match (the rule line form splits on it); use \x2c`)
				return exit(1)
			}
			if names.CommandMatchIsDead(name, rx) {
				return inv.usageErr("--match '"+rx+"' can never match for rule '"+name+"'.",
					"tacquito tests --match against the command's ARGUMENTS only (the",
					"cmd-arg values after '"+name+"', e.g. 'running-config' for",
					"'"+name+" running-config'), never the full command line.",
					"Omit --match to cover any arguments, or match the args alone",
					"(e.g. --match 'running-config').")
			}
			if matches != "" {
				matches += ","
			}
			matches += rx
			// 'shift 2' past the end fails, which ends the command (set -e).
			if len(rest) < 2 {
				return exit(1)
			}
			rest = rest[2:]
		case "--action":
			action = arg(rest, 1)
			if action != "permit" && action != "deny" {
				return inv.usageErr("--action must be 'permit' or 'deny'.")
			}
			rest = rest[2:]
		case "--before":
			where.Before = arg(rest, 1)
			if where.Before == "" {
				return inv.usageErr("--before needs the name of a rule.")
			}
			rest = rest[2:]
		case "--first":
			where.First = true
			rest = rest[1:]
		default:
			return inv.usageErr("Unknown flag: '" + rest[0] + "'")
		}
	}
	if where.First && where.Before != "" {
		return inv.usageErr("--before and --first cannot be used together.")
	}
	if where.Before != "" && where.Before != policy.Catchall && len(policy.RulesWhere(a.Conf(), group, where.Before, nil, "")) == 0 {
		return inv.usageErr((&policy.NoRuleError{Group: group, Name: where.Before}).Error())
	}
	// The same name with the same matches is a no-op; the same name with
	// other matches is another rule.
	for _, r := range policy.Lines(a.Conf(), group) {
		if strings.HasPrefix(r, name+"|") && policy.Field(r, 1) == name && ruleMatch(r) == matches {
			a.Out.InfoE("Rule '" + name + "' (match='" + matches + "') already present; no change.")
			inv.echo("")
			return nil
		}
	}
	if err := inv.applyWith(func() error {
		if err := inv.groupSeedSiblings(group); err != nil {
			return err
		}
		return policy.InsertRuleAt(a.Conf(), group, name, action, matches, where)
	}); err != nil {
		return err
	}
	a.Out.InfoE("Added rule '" + name + "' (action=" + action + ", match=[" + matches + "]) to group '" + group + "'.")
	// The mistakes tacquito does not report: a prefix form that matches the
	// exact arguments only, a rule an earlier one makes unreachable.
	line := name + "|" + action + "|" + matches
	for _, f := range policy.LintRules(policy.Lines(a.Conf(), group)) {
		if f.Line == line {
			a.Out.Warn("Rule #" + strconv.Itoa(f.Pos) + " '" + name + "': " + f.Msg + ".")
		}
	}
	inv.echo("")
	return nil
}

// groupSeedArgs is the argument loop of both seed commands: --force, one
// optional group, any other flag an error (after which the usage is
// printed by the caller's usage function).
func (inv *invocation) groupSeedArgs(args []string, usage func() string) (target string, force bool, err error) {
	for _, x := range args {
		switch {
		case x == "--force":
			force = true
		case strings.HasPrefix(x, "-"):
			inv.app.Out.ErrorE("Unknown flag: '" + x + "'")
			inv.write(usage())
			return "", false, exit(1)
		case target != "":
			return "", false, inv.usageErr("seed takes at most one group name; got extra '" + x + "'")
		default:
			target = x
		}
	}
	return target, force, nil
}

func (inv *invocation) groupCommandsSeed(args []string) error {
	a := inv.app
	target, force, err := inv.groupSeedArgs(args, func() string { return groupCommandsUsage(a.Paths.Overrides) })
	if err != nil {
		return err
	}
	candidates := policy.Builtins
	if target != "" {
		if _, _, ok := policy.DefaultRules(target); !ok {
			return inv.usageErr("seed only supports the built-in groups (readonly, operator, superuser).",
				"Got '"+target+"'. Custom groups must be configured with 'tacctl group commands add'.")
		}
		candidates = []string{target}
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	var touched, skipped []string
	if err := inv.applyWith(func() error {
		touched, skipped = nil, nil
		for _, g := range candidates {
			if exists, err := inv.groupExists(g); err != nil {
				return err
			} else if !exists {
				a.Out.Warn("Group '" + g + "' does not exist in config; skipping.")
				continue
			}
			if len(policy.Lines(a.Conf(), g)) > 0 && !force {
				a.Out.Warn("Group '" + g + "' already has command rules; skipping (pass --force to overwrite).")
				skipped = append(skipped, g)
				continue
			}
			if err := inv.groupSeedSiblings(g); err != nil {
				return err
			}
			if _, err := policy.ApplyDefaultRules(a.Conf(), g); err != nil {
				return err
			}
			touched = append(touched, g)
		}
		return nil
	}); err != nil {
		return err
	}
	if len(touched) > 0 {
		a.Out.Info("Seeded default command rules for: " + strings.Join(touched, " "))
		inv.echo("")
		inv.echo("  Review with:")
		for _, g := range touched {
			inv.echo("    tacctl group commands list " + g)
		}
		inv.echo("")
		inv.echo("  Preview the device config with:")
		inv.echo("    tacctl config cisco")
		inv.echo("    tacctl config juniper")
		inv.echo("")
		return nil
	}
	a.Out.Info("No groups seeded.")
	if len(skipped) > 0 {
		a.Out.Info("(Skipped: " + strings.Join(skipped, " ") + ". Pass --force to overwrite.)")
	}
	inv.echo("")
	return nil
}

// groupUsage is cmd_group's usage block.
func groupUsage() string { return Usage("group", nil) }

// groupPrivilegeUsage is cmd_group_privilege_usage.
func groupPrivilegeUsage() string { return Usage("group-privilege", nil) }

// groupCommandsUsage is cmd_group_commands_usage.
func groupCommandsUsage(overrides string) string {
	return Usage("group-commands", UsageVars{"overrides": overrides})
}

// --- privilege --------------------------------------------------------------

// privList is the comma-separated '<cmd>' list of privilege add|remove:
// 'IFS=, read -ra' of the first line, each entry through 'echo | xargs',
// empty ones skipped; check, when set, validates each (the first refusal
// ends the command).
func (inv *invocation) privList(input string, check bool) ([]string, error) {
	if i := strings.IndexByte(input, '\n'); i >= 0 {
		input = input[:i]
	}
	var out []string
	for _, raw := range strings.Split(input, ",") {
		w, err := shellquote.XargsEcho(raw)
		if err != nil {
			inv.stderrLine("xargs: " + err.Error())
			return nil, exit(1)
		}
		if w == "" {
			continue
		}
		// An entry may start with a mode (exec:, exec all:, configure:,
		// configure all:); it is kept in its stored form, so 'exec: x' and
		// 'x' are the same mapping.
		if check {
			entry, err := names.ValidatePrivEntry(w)
			if err != nil {
				return nil, inv.validated(err)
			}
			w = entry
		} else if mode, cmd, ok := names.SplitPrivEntry(w); ok {
			w = names.PrivEntry(mode, cmd)
		}
		out = append(out, w)
	}
	if len(out) == 0 {
		return nil, inv.usageErr("No commands provided.")
	}
	return out, nil
}

func (inv *invocation) groupPrivilege(args []string) error {
	a := inv.app
	sub := arg(args, 0)
	switch sub {
	case "", "-h", "--help", "help":
		inv.write(groupPrivilegeUsage())
		return nil
	case "seed":
		return inv.groupPrivilegeSeed(args[1:])
	case "reset":
		return inv.groupSectionReset(sectionPrivileges, args[1:])
	case "list", "add", "remove":
	default:
		a.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(groupPrivilegeUsage())
		return exit(1)
	}
	group, input := arg(args, 1), arg(args, 2)
	if group == "" {
		return inv.usageErr("Usage: tacctl group privilege " + sub + " <group> ...")
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if !m.Exists("groups", group) {
		return inv.usageErr("Group '" + group + "' does not exist.")
	}
	privlvl, _, _ := groupField(m.GroupInfo(), group)
	if privlvl == "" {
		return inv.usageErr("Group '" + group + "' has no Cisco priv-lvl; nothing to map.")
	}
	c := a.Conf()
	path := "privileges." + group

	switch sub {
	case "list":
		merged := policy.Privileges(c, group)
		b, nc := ui.Bold, ui.NC
		inv.echo("")
		inv.echoE(b + "Cisco priv-exec mappings for group '" + group + "' (priv-lvl " + privlvl + ")" + nc)
		inv.echo(ui.Rule("Cisco priv-exec mappings for group '" + group + "' (priv-lvl " + privlvl + ")"))
		switch {
		case captured(merged) == "":
			inv.echo("  (no mappings — group's priv-lvl uses Cisco defaults)")
		case c.HasOverride(path):
			inv.echoE("  Source: " + b + "explicit" + nc + " (tacctl.yaml: " + path + ")")
			inv.echo("")
			inv.privLines(merged, "")
		default:
			inv.echoE("  Source: " + b + "default" + nc + " (built-in safe defaults; override via 'tacctl group privilege add')")
			inv.echo("")
			inv.privLines(merged, "  (default)")
		}
		inv.echo("")
	case "add", "remove":
		if input == "" {
			return inv.usageErr("Usage: tacctl group privilege " + sub + " <group> '<command>'[,'<command>'...]")
		}
		requested, err := inv.privList(input, sub == "add")
		if err != nil {
			return err
		}
		current := policy.Privileges(c, group)
		// No explicit mappings: start from the defaults, so the first add
		// does not drop them and a remove acts on a known set.
		if captured(current) == "" {
			current = policy.DefaultPrivileges(group)
		}
		var changed, skipped []string
		for _, x := range requested {
			has := contains(current, x)
			switch {
			case sub == "add" && !has:
				changed = append(changed, x)
				current = append(current, x)
			case sub == "remove" && has:
				changed = append(changed, x)
				current = without(current, x)
			default:
				skipped = append(skipped, "'"+x+"'")
			}
		}
		if len(changed) == 0 {
			if sub == "add" {
				a.Out.Info("No new mappings to add for group '" + group + "' (already present: " + strings.Join(skipped, ", ") + ").")
				inv.echo("")
			} else {
				a.Out.Warn("Nothing to remove for group '" + group + "' (not mapped: " + strings.Join(skipped, ", ") + ").")
			}
			return nil
		}
		if err := policy.WritePrivileges(c, group, current); err != nil {
			return err
		}
		if sub == "add" {
			a.Out.Info(fmt.Sprintf("Added %d priv-exec mapping(s) for group '%s' (level %s):", len(changed), group, privlvl))
		} else {
			a.Out.Info(fmt.Sprintf("Removed %d priv-exec mapping(s) for group '%s':", len(changed), group))
		}
		for _, x := range changed {
			inv.echo("    - " + x)
		}
		if len(skipped) > 0 {
			if sub == "add" {
				a.Out.Info("(Already present, unchanged: " + strings.Join(skipped, ", ") + ")")
			} else {
				a.Out.Info("(Not mapped, skipped: " + strings.Join(skipped, ", ") + ")")
			}
		}
		inv.echo("")
	}
	return nil
}

// privLines lists privilege mappings with their mode in a column (exec,
// exec all, configure, configure all), each line ended by suffix.
func (inv *invocation) privLines(entries []string, suffix string) {
	for _, e := range strings.Split(captured(entries), "\n") {
		if e == "" {
			continue
		}
		mode, cmd, _ := names.SplitPrivEntry(e)
		inv.echo(fmt.Sprintf("  - %-13s  %s%s", mode, cmd, suffix))
	}
}

// groupField is the priv-lvl and class text of group in model_group_info's
// lines ('name|priv|class'), as 'model_group <g> priv_lvl' prints them ("" for
// none); ok is false when the group is not listed.
func groupField(info []string, group string) (priv, class string, ok bool) {
	for _, l := range info {
		f := strings.SplitN(l, "|", 3)
		if len(f) == 3 && f[0] == group {
			return f[1], f[2], true
		}
	}
	return "", "", false
}

func (inv *invocation) groupPrivilegeSeed(args []string) error {
	a := inv.app
	target, force, err := inv.groupSeedArgs(args, groupPrivilegeUsage)
	if err != nil {
		return err
	}
	candidates := policy.Builtins
	if target != "" {
		if len(policy.DefaultPrivileges(target)) == 0 && !contains(policy.Builtins, target) {
			return inv.usageErr("seed only supports the built-in groups (readonly, operator, superuser).")
		}
		candidates = []string{target}
	}
	c := a.Conf()
	var touched, skipped []string
	for _, g := range candidates {
		if exists, err := inv.groupExists(g); err != nil {
			return err
		} else if !exists {
			a.Out.Warn("Group '" + g + "' does not exist; skipping.")
			continue
		}
		if captured(policy.Privileges(c, g)) != "" && !force {
			a.Out.Warn("Group '" + g + "' already has explicit priv mappings; skipping (pass --force to overwrite).")
			skipped = append(skipped, g)
			continue
		}
		if err := policy.WritePrivileges(c, g, policy.DefaultPrivileges(g)); err != nil {
			return err
		}
		touched = append(touched, g)
	}
	if len(touched) > 0 {
		a.Out.Info("Seeded default priv-exec mappings for: " + strings.Join(touched, " "))
		inv.echo("")
		inv.echo("  Review with:")
		for _, g := range touched {
			inv.echo("    tacctl group privilege list " + g)
		}
		inv.echo("")
		inv.echo("  Preview Cisco device config:")
		inv.echo("    tacctl config cisco")
		inv.echo("")
		return nil
	}
	a.Out.Info("No groups seeded.")
	if len(skipped) > 0 {
		a.Out.Info("(Skipped: " + strings.Join(skipped, " ") + ". Pass --force to overwrite.)")
	}
	inv.echo("")
	return nil
}
