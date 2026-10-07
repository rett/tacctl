package cli

// 'group preset roles' (docs/plans/0.2.2-plan.md §5.7, D11, D20, D21,
// D27): the role preset's starting values (internal/policy/preset.go)
// written through the group setters, in one apply. A value already there
// is "unchanged"; a different one is kept unless --force. No user moves.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// presetStep is one setting the preset would write.
type presetStep struct {
	what  string // "WTI level superuser", ...
	state string // "set", "unchanged", "kept (pass --force)"
	apply func(c *conf.Config) error
	store func(s *store.Store) error
}

func (p presetStep) writes() bool { return p.state == "set" || p.state == "replaced" }

// presetState is a step's state: have is what is there now ("" for
// nothing), want what the preset sets.
func presetState(have, want string, force bool) string {
	switch {
	case have == want:
		return "unchanged"
	case have == "":
		return "set"
	case force:
		return "replaced"
	}
	return "kept (pass --force)"
}

func (inv *invocation) groupPreset(args []string) error {
	a := inv.app
	const usage = "Usage: tacctl group preset roles [--dry-run] [--force] [--mgmt-filter <name>]"
	if arg(args, 0) != "roles" {
		return inv.usageErr(usage)
	}
	p, err := Parse(groupSpecs["preset roles"], args[1:])
	if err != nil {
		return inv.usageErr(err.Error(), usage)
	}
	force, dry, filter := p.Has("--force"), p.Has("--dry-run"), p.Value("--mgmt-filter")
	if p.Has("--mgmt-filter") {
		if err := names.ValidateClassName(filter); err != nil {
			return inv.usageErr("Invalid --mgmt-filter '" + filter + "': use the name of the Junos firewall filter on the management interface.")
		}
	}
	if !dry {
		if err := inv.requireStore(); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	c := a.Conf()
	roles := policy.RolePreset(filter)
	for _, r := range roles {
		for attr, items := range r.Junos {
			if prob := policy.JunosProblem(r.Group, attr, items); prob != nil {
				return inv.usageErr(prob...)
			}
		}
	}

	steps := map[string][]presetStep{}
	for _, r := range roles {
		steps[r.Group] = inv.presetSteps(m, c, r, force)
	}

	inv.echo("")
	title := "Role preset: viewer (readonly) / operator / engineer / superuser"
	inv.echoE(ui.Bold + title + ui.NC)
	inv.echo(ui.Rule(title))
	changes, kept := 0, 0
	for _, r := range roles {
		name := r.Group
		if r.Label != "" {
			name += " (" + r.Label + ")"
		}
		inv.echo("  " + name)
		for _, s := range steps[r.Group] {
			inv.echo(fmt.Sprintf("    %-48s %s", s.what, s.state))
			if s.writes() {
				changes++
			} else if s.state != "unchanged" {
				kept++
			}
		}
	}
	if filter == "" {
		inv.echo("")
		inv.echo("  engineer's deny-configuration leaves out the management filter: pass")
		inv.echo("  --mgmt-filter <name> to deny engineers 'firewall ... <name>' as well.")
	}
	inv.echo("")
	if changes == 0 {
		if kept > 0 {
			a.Out.Info(fmt.Sprintf("Nothing to change; %d setting(s) differ from the preset and were kept (--force replaces them).", kept))
		} else {
			a.Out.Info("Nothing to change.")
		}
		inv.presetHints(m)
		return nil
	}
	if dry {
		a.Out.Info(fmt.Sprintf("Dry run: %d setting(s) would change; nothing was written.", changes))
		return nil
	}
	if !a.Prompter().ConfirmPrefix("  Apply? [y/N]: ") {
		a.Out.Info("Aborted.")
		return nil
	}
	if err := inv.applyWith(func() error {
		for _, r := range roles {
			for _, s := range steps[r.Group] {
				if !s.writes() {
					continue
				}
				if s.store != nil {
					if err := inv.mutate(s.store); err != nil {
						return err
					}
				}
				if s.apply != nil {
					if err := s.apply(a.Conf()); err != nil {
						return err
					}
				}
			}
		}
		return nil
	}); err != nil {
		return err
	}
	a.Out.Info(fmt.Sprintf("Role preset applied: %d setting(s) changed.", changes))
	m, err = inv.model()
	if err != nil {
		return err
	}
	inv.presetHints(m)
	return nil
}

// presetSteps are the settings of one role, with their states.
func (inv *invocation) presetSteps(m *model.Model, c *conf.Config, r policy.Role, force bool) []presetStep {
	var out []presetStep
	group := r.Group
	g := m.Group(group)
	if g == nil {
		priv, class := strconv.Itoa(r.PrivLvl), r.Class
		out = append(out, presetStep{what: "create (priv-lvl " + priv + ", class " + class + ")", state: "set",
			store: func(s *store.Store) error { return s.GroupSet(group, "priv_lvl="+priv, "juniper_class="+class) }})
	} else if r.Class != "" {
		// An existing group keeps its priv-lvl; its class only with --force (D20).
		class := r.Class
		out = append(out, presetStep{what: "Juniper class " + class, state: presetState(g.JuniperClass, class, force),
			store: func(s *store.Store) error { return s.GroupSet(group, "juniper_class="+class) }})
	}
	if r.Tier != "" {
		t := r.Tier
		out = append(out, presetStep{what: "tacctl tier " + t, state: presetState(policy.GroupTier(c, group), t, force),
			apply: func(c *conf.Config) error { return policy.WriteGroupTier(c, group, t) }})
	}
	have := ""
	if level, over := policy.WTILevel(c, group, 0); over {
		have = level
	}
	wti := r.WTI
	out = append(out, presetStep{what: "WTI level " + wti, state: presetState(have, wti, force),
		apply: func(c *conf.Config) error { return policy.WriteWTILevel(c, group, wti) }})
	for _, attr := range conf.JunosAttrs {
		items, ok := r.Junos[attr]
		if !ok {
			continue
		}
		what := fmt.Sprintf("Junos %s (%d/%d bytes)", conf.JunosArg(attr), len(conf.JunosValue(items)), conf.JunosLimit(attr))
		out = append(out, presetStep{what: what,
			state: presetState(strings.Join(policy.JunosSet(c, group, attr), "\n"), strings.Join(items, "\n"), force),
			apply: func(c *conf.Config) error { return policy.WriteJunosSet(c, group, attr, items) }})
	}
	if r.Commands != nil {
		lines := r.Commands
		state := "unchanged"
		if !policy.SameLines(policy.Lines(c, group), lines) {
			state = presetState(strings.Join(policy.Lines(c, group), "\n"), "-", force)
		}
		levels := m.GroupInfo()
		if g == nil {
			levels = append(levels, group+"|"+strconv.Itoa(r.PrivLvl)+"|"+r.Class)
		}
		out = append(out, presetStep{what: fmt.Sprintf("Cisco command rules (%d, default permit)", len(lines)), state: state,
			apply: func(c *conf.Config) error {
				// The other groups at its priv-lvl keep working once
				// devices ask per command (as 'group commands' does).
				if _, _, err := policy.SeedSiblings(c, levels, group); err != nil {
					return err
				}
				return policy.Write(c, group, lines)
			}})
	}
	return out
}

// presetHints are the closing lines: users are not moved, and where the
// device side of the preset is shown.
func (inv *invocation) presetHints(m *model.Model) {
	inv.echo("  Users are not moved. To make someone an engineer:")
	inv.echo("    tacctl user move <user> engineer")
	if n := len(m.GroupUsers("engineer")); n > 0 {
		inv.echo(fmt.Sprintf("  (group 'engineer' has %d user(s) already)", n))
	}
	inv.echo("  On this server, group 'engineer' (priv-lvl 15) is the superuser tier until")
	inv.echo("  0.2.3 brings the engineer tier: keep engineers out of this server's own scope.")
	inv.echo("  The device side of the roles:")
	inv.echo("    tacctl config juniper    the classes and template users (" + policy.EngineerClass + " for engineer)")
	inv.echo("    tacctl config cisco      the AAA lines that ask the server per command")
	inv.echo("    tacctl config wti        Service Name 'wti', which the WTI levels need")
	inv.echo("")
}
