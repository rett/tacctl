package policy

// The per-scope break-glass local users (decision D55 of
// docs/plans/0.2.3-plan.md): breakglass_scope.<scope>.users in tacctl.yaml,
// a list of 'name:role'. Only names and roles are recorded; the walkthroughs
// render the account lines with a placeholder where the credential goes, and
// tacctl never holds one.

import (
	"github.com/rett/tacctl/internal/conf"
)

// BreakGlassUser is one local account of a scope's devices.
type BreakGlassUser struct {
	Name string
	Role string // one of conf.BreakGlassRoles
}

// BreakGlassUsers are the scope's break-glass users in the order they were
// added; an entry that is not 'name:role' (a hand edit `config validate`
// reports) is skipped.
func BreakGlassUsers(c *conf.Config, scope string) []BreakGlassUser {
	var out []BreakGlassUser
	for _, e := range c.GetList(conf.BreakGlassPath(scope)) {
		if name, role, ok := conf.SplitBreakGlass(e); ok {
			out = append(out, BreakGlassUser{name, role})
		}
	}
	return out
}

// WriteBreakGlassUsers stores the scope's break-glass users; none at all
// removes the key (and breakglass_scope.<scope>), so a scope without them
// leaves tacctl.yaml as it was.
func WriteBreakGlassUsers(c *conf.Config, scope string, users []BreakGlassUser) error {
	if len(users) == 0 {
		return c.Unset(conf.BreakGlassPath(scope))
	}
	items := make([]string, len(users))
	for i, u := range users {
		items[i] = conf.BreakGlassEntry(u.Name, u.Role)
	}
	return c.SetList(conf.BreakGlassPath(scope), items)
}
