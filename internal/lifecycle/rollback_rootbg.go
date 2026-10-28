package lifecycle

// The Junos root account as a break-glass entry of a scope (0.2.20, 'scope
// breakglass <scope> add root', stored as root:admin in
// breakglass_scope.<scope>.users). The schema of every release a rollback
// goes to accepts the entry (a name of the device-safe shape and a role), so
// it is not removed and it refuses nothing. What is lost is what this release
// makes of it: every older release takes 'root' for a local user like any
// other. Its Junos walkthrough renders a commented 'set system login user root
// class ... authentication encrypted-password' line, which Junos refuses (it
// keeps root under 'system root-authentication'), and neither of the two
// statements of root's access; its Cisco and WTI walkthroughs render a root
// account where this release renders none; and the releases that compare
// (0.2.4 on) expect that login line on every Junos device of the scope, so the
// breakglass section reads differs until the entry goes. Removing it would
// change what the operator recorded, so it is a warning that names the scopes
// and the command that removes the entry, and --apply needs --yes.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/yamlpy"
)

// rootBreakGlassScopes are the scopes, sorted, whose break-glass users
// include the Junos root account.
func (p *RollbackPlan) rootBreakGlassScopes() []string {
	top, ok := p.in.Conf.Value("breakglass_scope")
	m, isMap := top.(*yamlpy.Map)
	if !ok || !isMap {
		return nil
	}
	var out []string
	for scope := range m.All() {
		if slices.ContainsFunc(policy.BreakGlassUsers(p.in.Conf, scope), func(u policy.BreakGlassUser) bool { return u.Name == conf.BreakGlassRoot }) {
			out = append(out, scope)
		}
	}
	slices.Sort(out)
	return out
}

// rootBreakGlassWarning is the warning about the scopes that record root:
// nil when none does.
func (p *RollbackPlan) rootBreakGlassWarning() []RollbackWarning {
	scopes := p.rootBreakGlassScopes()
	if len(scopes) == 0 {
		return nil
	}
	target := p.target()
	lines := []string{
		target + " has no break-glass entry for the Junos root account (0.2.20): " + pluralScopes(scopes) + " " + strings.Join(scopes, ", ") + " " +
			plural(len(scopes), "records", "record") + " 'root'. " + target + "'s schema accepts the entry, so it stays in tacctl.yaml, and " + target + " takes 'root' for a local user like any other:",
		"  its Junos walkthrough renders a commented 'set system login user root class ... authentication encrypted-password' line, which Junos refuses (root is under system root-authentication), in place of 'set system root-authentication encrypted-password' and 'set system services ssh root-login allow';",
		"  its Cisco walkthrough renders a commented 'username root privilege 15 ...' line and its WTI walkthrough a 'root' account of the unit's user directory, where this release renders none;",
	}
	if target != RollbackTarget {
		lines = append(lines, "  its 'device config pull' and 'device config diff' expect that 'system login user root' line on every Junos device of "+plural(len(scopes), "that scope", "those scopes")+", so the breakglass section reads differs (or missing) until the entry is removed.")
	}
	var cmds []string
	for _, s := range scopes {
		cmds = append(cmds, "tacctl scope breakglass "+s+" remove root")
	}
	lines = append(lines, "To keep "+target+"'s walkthroughs and comparisons right, remove the entry before the rollback: "+strings.Join(cmds, "; ")+" (and record it again after the next upgrade to this release).")
	return []RollbackWarning{{Title: "Scopes that record the Junos root account for break-glass", Lines: lines}}
}
