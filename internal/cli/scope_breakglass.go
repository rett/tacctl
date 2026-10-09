package cli

// 'tacctl scope breakglass <scope> list | add <name> [--role admin|operator|
// readonly] | remove <name>' (decision D55 of docs/plans/0.2.3-plan.md): the
// local accounts a scope's devices keep for the day the server cannot be
// reached. Only the names and roles are recorded, in tacctl.yaml
// (breakglass_scope.<scope>.users); the walkthroughs render the account
// lines with a placeholder where the credential goes. tacctl never stores
// one. Superuser-only: the tier gate sees two words, 'scope breakglass', and
// has no row for them.

import (
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devices"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/ui"
)

const scopeBreakGlassUsage = "Usage: tacctl scope breakglass <scope> [list | add <name> [--role admin|operator|readonly] | remove <name>]"

// breakGlassReserved are the names no device account may take: the Junos
// accounting sink and the service user (names.ReservedUsers, names.SinkUsers).
func breakGlassReserved(name string) bool {
	return containsFold(names.ReservedUsers, name) || containsFold(names.SinkUsers, name)
}

// containsFold is contains without regard to case: device user names are
// compared that way (the template names always were).
func containsFold(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

// breakGlassNameProblem is why name cannot be a break-glass user of scope,
// "" when it can: not device-safe, reserved, a tacctl user of the scope (the
// device's local account would shadow the server's), or a template-user or
// class name of the Junos walkthrough.
func breakGlassNameProblem(m *model.Model, scope, name string) string {
	switch {
	case !names.MatchBreakGlass(name):
		return "'" + name + "' is not a device-safe user name: a letter, then up to 31 letters, digits, '_' or '-'."
	case breakGlassReserved(name):
		return "'" + name + "' is reserved (the Junos accounting sink and the service user)."
	case containsFold(devices.JunosSystemAccounts, name):
		return "'" + name + "' is a Junos system account ('remote' is the template account of every remote user without a local-user-name)."
	case containsFold(m.Members(scope), name):
		return "'" + name + "' is a tacctl user of scope '" + scope + "': a local account of that name would shadow the server's."
	}
	for _, c := range devices.TemplateUserNames(m) {
		if strings.EqualFold(c, name) {
			return "'" + name + "' is a template-user or class name of the device walkthroughs (" + c + ")."
		}
	}
	return ""
}

func (inv *invocation) scopeBreakGlass(args []string) error {
	p, err := Parse(scopeSpecs["breakglass"], args)
	if err != nil {
		return inv.usageErr(err.Error(), scopeBreakGlassUsage)
	}
	scope, sub, name := arg(p.Args, 0), arg(p.Args, 1), arg(p.Args, 2)
	if scope == "" {
		return inv.usageErr(scopeBreakGlassUsage)
	}
	if err := inv.scopeRequire(scope); err != nil {
		return err
	}
	c := inv.app.Conf()
	users := policy.BreakGlassUsers(c, scope)
	if p.Has("--role") && sub != "add" {
		return inv.usageErr("--role belongs to 'add'.", scopeBreakGlassUsage)
	}

	switch sub {
	case "", "list":
		if sub == "list" && name != "" {
			return inv.usageErr("Unknown argument: '"+name+"'", scopeBreakGlassUsage)
		}
		inv.scopeBreakGlassList(scope, users)
		return nil
	case "add":
		return inv.scopeBreakGlassAdd(scope, name, p.Value("--role"), p.Has("--role"), users)
	case "remove":
		if name == "" {
			return inv.usageErr("Usage: tacctl scope breakglass " + scope + " remove <name>")
		}
		var kept []policy.BreakGlassUser
		for _, u := range users {
			if !strings.EqualFold(u.Name, name) {
				kept = append(kept, u)
			}
		}
		if len(kept) == len(users) {
			return inv.usageErr("Scope '" + scope + "' has no break-glass user '" + name + "'.")
		}
		if err := policy.WriteBreakGlassUsers(c, scope, kept); err != nil {
			return err
		}
		inv.app.Logger(inv.ctx, "auth.info", "scope breakglass remove scope="+scope+" name="+name+" by="+inv.sudoUser())
		inv.app.Out.Info("Break-glass user '" + name + "' removed from scope '" + scope + "'.")
		inv.echo("")
		inv.echo("  The devices keep the account until it is deleted there; tacctl only stops listing it.")
		if len(kept) == 0 {
			inv.app.Out.Warn("Scope '" + scope + "' now has no break-glass user: with the server unreachable, nobody can log in to a device that has no other local account.")
		}
		inv.echo("")
		return nil
	}
	return inv.usageErr("Unknown subcommand: '"+sub+"'", scopeBreakGlassUsage)
}

// scopeBreakGlassList is 'scope breakglass <scope> [list]'.
func (inv *invocation) scopeBreakGlassList(scope string, users []policy.BreakGlassUser) {
	inv.echo("")
	if len(users) == 0 {
		inv.echo("  Scope '" + scope + "' has no break-glass local user.")
		inv.echo("  With the server unreachable and no local account on a device, nobody can log in to it.")
	} else {
		inv.echo("  Scope '" + scope + "' break-glass local users:")
		for _, u := range users {
			inv.echo("    " + u.Name + "  (" + u.Role + ")")
		}
	}
	inv.echo("")
	inv.echo("  The device walkthroughs ('tacctl config cisco|juniper|wti --scope " + scope + "') render each account with a")
	inv.echo("  placeholder where the credential goes. tacctl stores no password or hash.")
	inv.echo("")
	inv.echo("  Usage: tacctl scope breakglass " + scope + " add <name> [--role admin|operator|readonly]   (default role: admin)")
	inv.echo("         tacctl scope breakglass " + scope + " remove <name>")
	inv.echo("")
}

// scopeBreakGlassAdd is 'scope breakglass <scope> add <name> [--role r]'.
func (inv *invocation) scopeBreakGlassAdd(scope, name, role string, roleGiven bool, users []policy.BreakGlassUser) error {
	if name == "" {
		return inv.usageErr("Usage: tacctl scope breakglass " + scope + " add <name> [--role admin|operator|readonly]")
	}
	if !roleGiven {
		role = conf.BreakGlassAdmin
	}
	if !conf.ValidBreakGlassRole(role) {
		return inv.usageErr("Unknown role '"+role+"'. Roles: "+strings.Join(conf.BreakGlassRoles, ", "), scopeBreakGlassUsage)
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	if why := breakGlassNameProblem(m, scope, name); why != "" {
		return inv.usageErr(why)
	}
	for _, u := range users {
		if strings.EqualFold(u.Name, name) {
			return inv.usageErr("Scope '" + scope + "' already has break-glass user '" + u.Name + "' (" + u.Role + "). Remove it first to change its role.")
		}
	}
	if len(users) >= conf.MaxBreakGlassUsers {
		return inv.usageErr("Scope '" + scope + "' already has the most break-glass users it may record (" + strconv.Itoa(conf.MaxBreakGlassUsers) + ").")
	}
	if err := policy.WriteBreakGlassUsers(inv.app.Conf(), scope, append(users, policy.BreakGlassUser{Name: name, Role: role})); err != nil {
		return err
	}
	inv.app.Logger(inv.ctx, "auth.info", "scope breakglass add scope="+scope+" name="+name+" role="+role+" by="+inv.sudoUser())
	inv.app.Out.Info("Break-glass user '" + name + "' (" + role + ") recorded for scope '" + scope + "'.")
	inv.echo("")
	inv.echo("  tacctl stores no password or hash. 'tacctl config cisco|juniper|wti --scope " + scope + "' now renders the")
	inv.echo("  account with a placeholder where the credential goes, and names it on its 'Unfilled' line. tacctl")
	inv.echo("  cannot tell whether you have put in a credential of your own, so the line stays while the")
	inv.echo("  account is recorded.")
	inv.echo("")
	return nil
}

// scopeBreakGlassMove carries a scope's break-glass record to its new name
// (newName "": the scope is gone, so is its record). It is part of 'scope
// rename' and 'scope remove' (scopeConfKeysMove).
func (inv *invocation) scopeBreakGlassMove(old, newName string) error {
	c := inv.app.Conf()
	from := conf.BreakGlassPath(old)
	if !c.HasOverride(from) {
		return nil
	}
	value, _ := c.Value(from)
	if err := c.Unset(from); err != nil {
		return err
	}
	if newName != "" {
		if err := c.SetValue(conf.BreakGlassPath(newName), value); err != nil {
			inv.app.Out.Warn(from + " holds a value tacctl.yaml does not take; it was not carried over to '" + newName + "'.")
		}
	}
	return nil
}

// scopeBreakGlassSummary is the 'Break-glass:' line of 'scope show'.
func (inv *invocation) scopeBreakGlassSummary(scope string) string {
	users := policy.BreakGlassUsers(inv.app.Conf(), scope)
	if len(users) == 0 {
		return ui.Red + "none" + ui.NC + " — a lockout risk with the server unreachable (tacctl scope breakglass " + scope + " add <name>)"
	}
	parts := make([]string, len(users))
	for i, u := range users {
		parts[i] = u.Name + " (" + u.Role + ")"
	}
	return strings.Join(parts, ", ")
}

// breakGlassNames is '_completion-names breakglass-users <scope>': the
// names recorded for the scope, in the order they were added. The verb it
// completes is the superuser's, so a restricted caller (the lower tiers)
// is told nothing: the helper is open to every tier and the names are the
// local accounts of a scope's devices.
func (inv *invocation) breakGlassNames(args []string) []string {
	if inv.callerScopes().restricted {
		return nil
	}
	var out []string
	for _, u := range policy.BreakGlassUsers(inv.app.Conf(), arg(args, 0)) {
		out = append(out, u.Name)
	}
	return out
}

// quoteJoin is the names in single quotes, comma-separated.
func quoteJoin(list []string) string {
	q := make([]string, len(list))
	for i, s := range list {
		q[i] = "'" + s + "'"
	}
	return strings.Join(q, ", ")
}

// breakGlassClash is the refusal for a tacctl user name equal (without
// regard to case) to a break-glass account recorded for one of scopes, ""
// when there is none: the device's local account of that name would answer
// for the user with its own class or privilege, not the group's (always on
// Junos, first with aaa-order local-first on Cisco).
func breakGlassClash(c *conf.Config, name string, scopes []string) string {
	for _, s := range scopes {
		for _, u := range policy.BreakGlassUsers(c, s) {
			if strings.EqualFold(u.Name, name) {
				return "'" + name + "' is a break-glass local user of scope '" + s + "' (" + u.Role + "): the device's local account of that name " +
					"would answer for the user with its own class. Remove the break-glass user first " +
					"(tacctl scope breakglass " + s + " remove " + u.Name + ") or pick another name."
			}
		}
	}
	return ""
}
