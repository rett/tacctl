package cli

// The server's accounts after a lowered tier (docs/plans/0.2.3-plan.md S2).
// A user whose tier drops keeps the local groups of the old tier on this
// server until the server is synced (an engineer made from a superuser
// keeps tac-superuser, and its root). Every verb that can lower a tier
// (group edit tier, group edit priv-lvl, group remove, user move, disable,
// remove and scope remove|replace|remove --all, group reset, group preset roles
// --force) takes the tiers of the users this server's accounts cover before
// it writes and, once it has written, runs the same local sync when any of
// them is lower (a user who is gone from the model or from the server's
// scope is none). The verbs that replace the state wholesale (store import
// and rollback, backup restore) cannot say whose tier fell: they print the
// line that names the sync (warnServerSync).

import (
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/tier"
)

// tierWatch is the tiers of the users with an account on this server, from
// before a change.
type tierWatch struct {
	inv    *invocation
	scope  string
	before map[string]tier.Tier
}

// watchServerTiers takes the tiers now: the users of the scope this server
// is enrolled in, or every user when it is not enrolled (nothing says whose
// accounts it holds then). A model that cannot be read watches nothing.
func (inv *invocation) watchServerTiers() *tierWatch {
	w := &tierWatch{inv: inv}
	if e, ok, _ := inv.localHost(); ok {
		w.scope = e.Scope
	}
	if m, err := inv.model(); err == nil {
		w.before = serverTiers(m, inv.app.Conf(), w.scope, inv.hasTierSettings())
	}
	return w
}

// serverTiers is the tier of each user of scope ("": every user) under the
// model and tacctl.yaml given; a member of an ambiguous group (hold) is an
// operator, as the syncs and the gate have it.
func serverTiers(m *model.Model, c *conf.Config, scope string, hold bool) map[string]tier.Tier {
	names := m.UserNames()
	if scope != "" {
		names = m.Members(scope)
	}
	out := map[string]tier.Tier{}
	for _, n := range names {
		u := m.User(n)
		if u == nil {
			continue
		}
		t := tier.ForGroup(policy.GroupTier(c, u.Group), m.UserPrivLvl(n))
		// A member of an ambiguous group is synced as an operator.
		if g := m.Group(u.Group); hold && tier.Rank(t) > tier.Rank(tier.Operator) && g != nil && policy.NeedsTier(u.Group, g.PrivLvl) && policy.GroupTier(c, u.Group) == "" {
			t = tier.Operator
		}
		out[n] = t
	}
	return out
}

// lowered syncs this server's accounts when the change just written lowered
// the tier of any watched user: what names the cause ("The tier of <what>
// is lower now"), left what remains if the sync cannot be done ("Members of
// 'ops' keep their old groups"). A user whose rank fell is one whose tier is
// lower in tier.Managed, or who is now none.
func (w *tierWatch) lowered(what, left string) error {
	inv := w.inv
	if w.before == nil {
		// The model could not be read before the change: whose tier fell
		// cannot be told, so say what may remain.
		inv.warnServerSync(left)
		return nil
	}
	m, err := inv.app.LoadModel()
	if err != nil {
		// Whose tier fell cannot be told: say what remains.
		inv.warnServerSync(left)
		return nil
	}
	after := serverTiers(m, inv.app.Conf(), w.scope, inv.hasTierSettings())
	var down []string
	for n, was := range w.before {
		now := tier.None
		if t, ok := after[n]; ok {
			now = t
		}
		if tier.Rank(now) < tier.Rank(was) {
			down = append(down, n)
		}
	}
	if len(down) == 0 {
		return nil
	}
	return inv.syncServerAfterLowering(what, left)
}

// warnServerSync is the red line of a change that may have lowered tiers
// without being able to say whose: left is what remains, and the sync that
// ends it. Nothing is printed when this server is not enrolled (nothing
// holds accounts to sync).
func (inv *invocation) warnServerSync(left string) {
	if e, ok, _ := inv.localHost(); ok {
		inv.app.Out.ErrorE(left + " on this server until: tacctl host sync " + e.Name)
	}
}

// storeGroups are the names of the groups the store holds now (none when
// there is no store or it cannot be read): taken before an import, they are
// the groups that import did not bring.
func (inv *invocation) storeGroups() []string {
	if model.Mode(inv.app.Paths.StoreFile) != "store" {
		return nil
	}
	m, err := inv.app.LoadModel()
	if err != nil {
		return nil
	}
	return m.GroupNames()
}

// pinGroupTiers is the step after a store import (and a legacy restore):
// every group the import brought (one that is not in before, the groups
// the store held) at priv-lvl 15 without a tier setting gets the one 0.2.2
// gave it (lifecycle.PinImportedGroupTiers). A group the store already had
// is never pinned here: its missing setting is a loss, not a migration.
func (inv *invocation) pinGroupTiers(before []string) {
	a := inv.app
	lifecycle.PinImportedGroupTiers(a.Paths, a.Conf(), a.Out, func() error { _, err := a.Snapshots().Take(); return err }, before)
}
