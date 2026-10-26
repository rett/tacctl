package cli

// 'tacctl emergency lockdown <scope> enable|disable [<group>[,<group>...]]
// [--tier <tier>] [--reason <text>] [--dry-run] | --all-scopes enable|disable
// [<groups>] | status [<scope>] [--json]' (0.2.19): refuse the logins of the
// chosen groups on every device and Linux host of a scope. The record is
// emergency.lockdown.<scope> in tacctl.yaml (internal/conf); both renderers
// take the scope out of the users of the locked groups (model.WithoutMembers),
// so the server answers FAIL or Reject and never stays silent (silence is the
// break-glass hold's, and makes a device fall back to its local accounts).
// store.yaml is not changed, so 'disable' restores the rendered files. A user
// of a superuser group is never locked. There is no expiry. The verb is the
// superuser's (the tier table has no row for it); a lockdown is shown by
// every command that names the scope, to the engineers of the scope too.

import (
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/ui"
)

const (
	emergencyUseLockdown = "lockdown <scope> enable|disable [<group>[,<group>...]] [--tier <tier>] [--reason <text>] [--dry-run] | lockdown --all-scopes enable|disable [<groups>] | lockdown status [<scope>] [--json]"
	emergencyUsage       = "Usage: tacctl emergency " + emergencyUseLockdown
)

// emergencySpecs are the arguments of each verb (completion and parsing).
var emergencySpecs = map[string]Spec{
	"lockdown": {MaxArgs: 3, Args: []string{Either("status", KindScopes), Cond("status", KindScopes, "enable|disable"), KindGroups + KindList},
		Flags: []Flag{
			{Names: []string{"--all-scopes"}},
			{Names: []string{"--tier"}, Value: true, Kind: "readonly|operator|engineer"},
			{Names: []string{"--reason"}, Value: true},
			{Names: []string{"--dry-run"}},
			flagJSON,
		}},
}

func init() {
	registerFamily(emergencyCmd)
	registerSpecs("emergency", emergencySpecs)
	shellHelpBlocks["emergency"] = func(*invocation) string { return emergencyHelp() }
}

func emergencyCmd(inv *invocation) *cobra.Command {
	c := verb("emergency <subcommand>", "Emergency measures (lockdown: refuse the logins of groups on a scope)")
	c.RunE = inv.native(withPreflight, inv.emergency)
	c.AddCommand(withRun(verb(emergencyUseLockdown, "Refuse the logins of chosen groups on every device and host of a scope, or lift it (the superuser's)"),
		inv.native(withPreflight, func(args []string) error {
			return inv.emergency(append([]string{"lockdown"}, args...))
		})))
	return c
}

// emergencyHelp is the usage of the family.
func emergencyHelp() string {
	var b strings.Builder
	b.WriteString("\n" + ui.Bold + "Emergency Lockdown" + ui.NC + "\n\nUsage: tacctl emergency <subcommand> [arguments]\n\nSubcommands:\n")
	b.WriteString("  lockdown <scope> enable [<groups>]    Refuse the logins of the groups on the scope's devices and hosts\n")
	b.WriteString("  lockdown <scope> disable [<groups>]   Lift it, for the groups named or all\n")
	b.WriteString("  lockdown --all-scopes enable|disable  The same for every scope\n")
	b.WriteString("  lockdown status [<scope>] [--json]    Show the lockdowns that stand\n")
	b.WriteString(`      --all-scopes                      (lockdown) Every scope instead of one
      --tier <tier>                     (lockdown) Lock the groups of that tier (readonly, operator or engineer)
      --reason <text>                   (lockdown) Why, 1 to 256 characters; kept with the record and in the log
      --dry-run                         (lockdown) Print who loses access and change nothing
      --json                            (lockdown status) Print the lockdowns as a JSON array

'enable' with no group locks every group that is not a superuser's; with a
list, those groups, added to what is locked already. The users of those groups
are taken out of the scope when the backends render, so the server answers
every login and every further command authorization with a refusal; a session
that is open on a Junos device, a WTI unit or a Linux host stays until it logs
in again or runs sudo. A user of a superuser group is never locked. 'enable'
shows who loses access and who keeps it, and asks for the scope's name typed
back (for --all-scopes the word all). A lockdown stands until 'disable' (there
is no timer). The device's own local accounts are not tacctl users and are
not locked: 'status' names the ways they remain.

Examples:
  tacctl emergency lockdown site-a enable --reason "credential leak"
  tacctl emergency lockdown site-a enable ops,readonly
  tacctl emergency lockdown site-a disable
  tacctl emergency lockdown status

`)
	return b.String()
}

// emergency dispatches.
func (inv *invocation) emergency(args []string) error {
	var rest []string
	if len(args) > 1 {
		rest = args[1:]
	}
	switch sub := arg(args, 0); sub {
	case "", "-h", "--help", "help":
		inv.write(emergencyHelp())
		return nil
	case "lockdown":
		return inv.emergencyLockdown(rest)
	default:
		inv.app.Out.ErrorE("Unknown subcommand: '" + sub + "'")
		inv.write(emergencyHelp())
		return exit(1)
	}
}

// --- groups and users ---------------------------------------------------------

// groupIsSuperuser reports whether the members of the group are
// superusers: its tier is superuser and the group is not ambiguous (a group
// at priv-lvl 15 or more with no tier setting is held at operator).
func (inv *invocation) groupIsSuperuser(m *model.Model, name string) bool {
	g := m.Group(name)
	if g == nil || g.PrivLvl == nil {
		return false
	}
	c := inv.app.Conf()
	setting := policy.GroupTier(c, name)
	if policy.NeedsTier(name, g.PrivLvl) && setting == "" {
		return false
	}
	return tier.ForGroup(setting, strconv.Itoa(*g.PrivLvl)) == tier.Superuser
}

// groupTierOf is the tier of a group ("none" for one with no priv-lvl).
func (inv *invocation) groupTierOf(m *model.Model, name string) tier.Tier {
	g := m.Group(name)
	if g == nil || g.PrivLvl == nil {
		return tier.None
	}
	return tier.ForGroup(policy.GroupTier(inv.app.Conf(), name), strconv.Itoa(*g.PrivLvl))
}

// lockableGroups are the groups of the model that are not a superuser's,
// sorted.
func (inv *invocation) lockableGroups(m *model.Model) []string {
	var out []string
	for _, n := range m.GroupNames() {
		if !inv.groupIsSuperuser(m, n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// lockdownGroups are the groups a lockdown command names: the list, or the
// groups of --tier, or every group that is not a superuser's.
func (inv *invocation) lockdownGroups(m *model.Model, list, tierName string) ([]string, error) {
	switch {
	case list != "" && tierName != "":
		return nil, inv.usageErr("Give the groups or --tier, not both.", emergencyUsage)
	case tierName != "":
		switch tier.Tier(tierName) {
		case tier.Readonly, tier.Operator, tier.Engineer:
		case tier.Superuser:
			return nil, inv.usageErr("Superusers are never locked: --tier superuser names the one tier a lockdown cannot take.", emergencyUsage)
		default:
			return nil, inv.usageErr("--tier takes readonly, operator or engineer, not '"+tierName+"'.", emergencyUsage)
		}
		var out []string
		for _, n := range inv.lockableGroups(m) {
			if inv.groupTierOf(m, n) == tier.Tier(tierName) {
				out = append(out, n)
			}
		}
		if len(out) == 0 {
			return nil, inv.usageErr("No group has the tier '" + tierName + "'.")
		}
		return out, nil
	case list == "":
		out := inv.lockableGroups(m)
		if len(out) == 0 {
			return nil, inv.usageErr("There is no group that is not a superuser's to lock.")
		}
		return out, nil
	}
	var out []string
	for _, n := range strings.Split(list, ",") {
		n = strings.TrimSpace(n)
		switch {
		case n == "":
			return nil, inv.usageErr("The group list has an empty name.", emergencyUsage)
		case m.Group(n) == nil:
			return nil, inv.usageErr("There is no group '"+n+"'.", emergencyUsage)
		case inv.groupIsSuperuser(m, n):
			return nil, inv.usageErr("Group '"+n+"' is a superuser group, and superusers are never locked. Nothing was changed.", emergencyUsage)
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out, nil
}

// --- the message ---------------------------------------------------------------

// lockdownLine is the one line that says a lockdown stands.
func (inv *invocation) lockdownLine(l conf.Lockdown) string {
	s := "EMERGENCY LOCKDOWN on scope '" + l.Scope + "' since " + lockdownTime(l) + " by " + l.By + " (" + lockdownAge(l, inv.app.Knobs.Now()) +
		"): logins of groups " + strings.Join(l.Groups, ", ") + " are refused; superusers keep access."
	if l.Reason != "" {
		s += " Reason: " + l.Reason
	}
	return s
}

func lockdownTime(l conf.Lockdown) string {
	if t := l.SinceTime(); !t.IsZero() {
		return t.Local().Format("2006-01-02 15:04")
	}
	return l.Since
}

func lockdownAge(l conf.Lockdown, now time.Time) string {
	t := l.SinceTime()
	if t.IsZero() {
		return "unknown time"
	}
	return durationText(now.Sub(t))
}

// lockdownNotice writes the red line of every lockdown the command touches,
// once per process, on stderr: the scope named among the arguments, the scope
// of a device or host named, and every lockdown for the commands that show
// all (status, list, validate). An engineer sees those of their own scopes.
func (inv *invocation) lockdownNotice() {
	if inv.lockdownShown {
		return
	}
	inv.lockdownShown = true
	all := inv.app.Conf().Lockdowns()
	if len(all) == 0 {
		return
	}
	args := inv.app.Args
	if len(args) > 0 && args[0] == "emergency" {
		return
	}
	filter := inv.callerScopes()
	var show []conf.Lockdown
	for _, l := range all {
		if filter.allows(l.Scope) {
			show = append(show, l)
		}
	}
	if len(show) == 0 {
		return
	}
	scopes := inv.lockdownScopesOf(args, show)
	for _, l := range show {
		if scopes[l.Scope] || lockdownShowsAll(args) {
			inv.stderrLine(ui.Red + ui.Bold + inv.lockdownLine(l) + ui.NC)
		}
	}
}

// lockdownShowsAll reports the commands that are about no one scope and so
// show every lockdown.
func lockdownShowsAll(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "status":
		return true
	case "config":
		return len(args) > 1 && args[1] == "validate"
	case "scope", "device", "host":
		return len(args) > 1 && args[1] == "list"
	}
	return false
}

// lockdownScopesOf are the scopes with a lockdown that the arguments name:
// a word that is a scope, or the name of a registered device or enrolled
// host that a scope answers.
func (inv *invocation) lockdownScopesOf(args []string, locks []conf.Lockdown) map[string]bool {
	out := map[string]bool{}
	words := map[string]bool{}
	for _, a := range args {
		for _, w := range strings.Split(a, ",") {
			words[strings.ToLower(strings.TrimPrefix(strings.SplitN(w, "=", 2)[0], "--"))] = true
		}
	}
	var rest []conf.Lockdown
	for _, l := range locks {
		if words[strings.ToLower(l.Scope)] {
			out[l.Scope] = true
		} else {
			rest = append(rest, l)
		}
	}
	if len(rest) == 0 {
		return out
	}
	f, err := devreg.Load(inv.app.Paths.DevicesFile)
	if err != nil {
		return out
	}
	m, err := inv.model()
	if err != nil {
		return out
	}
	var reg *hosts.Registry
	if r, err := inv.registry(); err == nil {
		reg = r
	}
	for _, e := range devreg.NewResolver(f, reg, m).All() {
		if words[strings.ToLower(e.Name)] || words[strings.ToLower(e.Address)] {
			for _, l := range rest {
				if l.Scope == e.Scope {
					out[l.Scope] = true
				}
			}
		}
	}
	return out
}

// --- the verb ------------------------------------------------------------------

// lockdownResidual are the ways a device's local accounts stay usable under
// a lockdown: they are in no tacctl group.
var lockdownResidual = []string{
	"a device's own local accounts are not tacctl users and are not locked; they stay out of the way only because of the device's method list",
	"not closed: a Cisco console line, the Junos root account on the console, a scope that lists local accounts first (aaa-order local-first), local ssh keys, sessions that are open, a device that cannot reach this server",
}

func (inv *invocation) emergencyLockdown(args []string) error {
	p, err := Parse(emergencySpecs["lockdown"], args)
	if err != nil {
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			return inv.usageErr("Unknown option: '"+uf.Flag+"'", emergencyUsage)
		}
		return inv.usageErr(err.Error(), emergencyUsage)
	}
	pos := p.Args
	if len(pos) > 0 && pos[0] == "status" {
		if len(pos) > 2 {
			return inv.usageErr("Unknown argument: '"+pos[2]+"'", emergencyUsage)
		}
		return inv.lockdownStatus(arg(pos, 1), p.Has("--json"))
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	var scopes []string
	verbWord := ""
	var groupList string
	switch {
	case p.Has("--all-scopes"):
		if len(pos) < 1 || len(pos) > 2 {
			return inv.usageErr(emergencyUsage)
		}
		verbWord, groupList = pos[0], arg(pos, 1)
		scopes = m.ScopesByRouting()
		if len(scopes) == 0 {
			return inv.usageErr("There are no scopes. Nothing was changed.")
		}
	case len(pos) == 0:
		return inv.usageErr(emergencyUsage)
	case len(pos) == 1:
		return inv.lockdownStatus(pos[0], p.Has("--json"))
	default:
		if m.Scope(pos[0]) == nil {
			return inv.usageErr("There is no scope '"+pos[0]+"'.", emergencyUsage)
		}
		scopes, verbWord, groupList = []string{pos[0]}, pos[1], arg(pos, 2)
	}
	if verbWord != "enable" && verbWord != "disable" {
		return inv.usageErr("Unknown action: '"+verbWord+"' (enable or disable)", emergencyUsage)
	}
	if f := inv.callerScopes(); f.restricted {
		return inv.deniedUsage(reasonSuperuser, "'tacctl emergency lockdown' is the superuser's. Nothing was changed.")
	}
	reason := strings.TrimSpace(p.Value("--reason"))
	if p.Has("--reason") {
		if why := conf.HoldReasonProblem(reason); why != "" {
			return inv.usageErr("--reason "+why+".", emergencyUsage)
		}
	}
	if verbWord == "enable" {
		return inv.lockdownEnable(m, scopes, groupList, p.Value("--tier"), reason, p.Has("--all-scopes"), p.Has("--dry-run"))
	}
	return inv.lockdownDisable(m, scopes, groupList, p.Has("--all-scopes"), p.Has("--dry-run"))
}

// lockdownPlan is what a command does to one scope.
type lockdownPlan struct {
	scope string
	// before is the record that stands (nil when none), groups the groups
	// that are locked afterwards (empty: the record goes).
	before *conf.Lockdown
	groups []string
}

func (inv *invocation) lockdownOf(scope string) *conf.Lockdown {
	for _, l := range inv.app.Conf().Lockdowns() {
		if l.Scope == scope {
			l := l
			return &l
		}
	}
	return nil
}

func (inv *invocation) lockdownEnable(m *model.Model, scopes []string, list, tierName, reason string, all, dry bool) error {
	groups, err := inv.lockdownGroups(m, list, tierName)
	if err != nil {
		return err
	}
	var plans []lockdownPlan
	for _, s := range scopes {
		cur := inv.lockdownOf(s)
		union := slices.Clone(groups)
		if cur != nil {
			for _, g := range cur.Groups {
				if !slices.Contains(union, g) {
					union = append(union, g)
				}
			}
		}
		sort.Strings(union)
		if cur != nil && slices.Equal(cur.Groups, union) {
			continue
		}
		plans = append(plans, lockdownPlan{scope: s, before: cur, groups: union})
	}
	if len(plans) == 0 {
		inv.echo("Already locked: " + strings.Join(groups, ", ") + " on " + quoteNames(scopes) + ". Nothing was changed.")
		return nil
	}
	inv.echo("")
	for _, pl := range plans {
		inv.lockdownPreview(m, pl, true)
	}
	if all {
		inv.echo("  Every scope is included, and so is this server's own login when a scope covers it (superusers keep it).")
		inv.echo("")
	}
	for _, l := range lockdownResidual {
		inv.echo("  " + l + ".")
	}
	for _, pl := range plans {
		if inv.confGet("aaa.order."+pl.scope, "tacacs-first") == "local-first" {
			inv.echo("  " + ui.Red + "Scope '" + pl.scope + "' lists local accounts first (aaa-order local-first): its devices let a local account in before they ask this server." + ui.NC)
		}
	}
	inv.echo("")
	if dry {
		inv.echo("Dry run: nothing was changed.")
		return nil
	}
	pr := inv.app.Prompter()
	if !pr.Interactive() {
		return inv.usageErr("No terminal to confirm on: a lockdown is a person's act, and the scope's name is typed back. Nothing was changed.")
	}
	want := scopes[0]
	prompt := "  Type the scope name to go on: "
	if all {
		want, prompt = "all", "  Type all to lock every scope: "
	}
	if typed := pr.Ask(prompt); typed != want {
		return inv.usageErr("What was typed is not '" + want + "'. Nothing was changed.")
	}
	now := inv.app.Knobs.Now().Format(time.RFC3339)
	by := inv.sudoUser()
	res, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		for _, pl := range plans {
			pl := pl
			if err := inv.app.Conf().UpdateLockdown(pl.scope, func(cur *conf.Lockdown) (*conf.Lockdown, error) {
				next := conf.Lockdown{Scope: pl.scope, Since: now, By: by, Reason: reason}
				groups := slices.Clone(groups)
				if cur != nil {
					next.Since, next.By = cur.Since, cur.By
					if reason == "" {
						next.Reason = cur.Reason
					}
					for _, g := range cur.Groups {
						if !slices.Contains(groups, g) {
							groups = append(groups, g)
						}
					}
				}
				sort.Strings(groups)
				next.Groups = groups
				return &next, nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	for _, pl := range plans {
		l := inv.lockdownOf(pl.scope)
		if l == nil {
			continue
		}
		out := inv.lockedOutNames(m, l.Scope, l.Groups)
		inv.app.Audit().Raw("auth.notice", "emergency lockdown enable scope="+l.Scope+" groups="+strings.Join(l.Groups, ",")+
			" exempt="+strings.Join(inv.lockdownExempt(m, l.Scope), ",")+" reason="+strconv.Quote(l.Reason)+" by="+by+
			" locked="+strconv.Itoa(len(out))+" result=ok")
		inv.echo(ui.Red + ui.Bold + inv.lockdownLine(*l) + ui.NC)
	}
	inv.echo("  Rendered: " + lockdownRendered(res))
	inv.echo("  Lift it with: tacctl emergency lockdown " + lockdownTarget(scopes, all) + " disable")
	if len(res.RestartFailed) > 0 {
		inv.app.Out.Error("The lockdown is recorded and the rendered files are kept, but it is not in force until the backend named under Rendered is restarted; 'tacctl emergency lockdown " + lockdownTarget(scopes, all) + " disable' removes the record.")
		return exit(1)
	}
	return nil
}

func lockdownTarget(scopes []string, all bool) string {
	if all {
		return "--all-scopes"
	}
	return scopes[0]
}

// lockdownRendered says which backends were rendered and restarted.
func lockdownRendered(res backend.Result) string {
	var parts []string
	for _, id := range res.Changed {
		failed := slices.ContainsFunc(res.RestartFailed, func(f backend.RestartFailure) bool { return f.ID == id })
		if failed {
			parts = append(parts, id+" rendered, NOT restarted")
		} else {
			parts = append(parts, id+" rendered and restarted")
		}
	}
	if len(parts) == 0 {
		return "no backend file changed"
	}
	return strings.Join(parts, "; ")
}

func (inv *invocation) lockdownDisable(m *model.Model, scopes []string, list string, all, dry bool) error {
	var plans []lockdownPlan
	var named []string
	if list != "" {
		for _, n := range strings.Split(list, ",") {
			n = strings.TrimSpace(n)
			if n == "" || m.Group(n) == nil {
				return inv.usageErr("There is no group '"+n+"'.", emergencyUsage)
			}
			named = append(named, n)
		}
	}
	for _, s := range scopes {
		cur := inv.lockdownOf(s)
		if cur == nil {
			continue
		}
		var keep []string
		for _, g := range cur.Groups {
			if len(named) > 0 && !slices.Contains(named, g) {
				keep = append(keep, g)
			}
		}
		if len(named) > 0 && len(keep) == len(cur.Groups) {
			continue
		}
		plans = append(plans, lockdownPlan{scope: s, before: cur, groups: keep})
	}
	if len(plans) == 0 {
		inv.echo("No lockdown stands on " + quoteNames(scopes) + " for those groups. Nothing was changed.")
		return nil
	}
	if dry {
		for _, pl := range plans {
			inv.echo("Would lift " + strings.Join(liftedGroups(pl), ", ") + " on scope '" + pl.scope + "'.")
		}
		inv.echo("Dry run: nothing was changed.")
		return nil
	}
	by := inv.sudoUser()
	res, err := inv.app.Backends().StoreApply(inv.ctx, backend.ApplyOptions{}, func() error {
		for _, pl := range plans {
			pl := pl
			if err := inv.app.Conf().UpdateLockdown(pl.scope, func(cur *conf.Lockdown) (*conf.Lockdown, error) {
				if cur == nil {
					return nil, nil
				}
				var keep []string
				for _, g := range cur.Groups {
					if len(named) > 0 && !slices.Contains(named, g) {
						keep = append(keep, g)
					}
				}
				if len(keep) == 0 {
					return nil, nil
				}
				next := *cur
				next.Groups = keep
				return &next, nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
	inv.loaded = false
	if err != nil {
		return err
	}
	now := inv.app.Knobs.Now()
	for _, pl := range plans {
		inv.app.Audit().Raw("auth.notice", "emergency lockdown disable scope="+pl.scope+" groups="+strings.Join(liftedGroups(pl), ",")+
			" held="+strings.ReplaceAll(lockdownAge(*pl.before, now), " ", "")+" by="+by+" result=ok")
		if len(pl.groups) == 0 {
			inv.echo(ui.Green + "Emergency lockdown LIFTED" + ui.NC + " on scope '" + pl.scope + "' (it stood " + lockdownAge(*pl.before, now) + ").")
		} else {
			inv.echo(ui.Yellow + "Emergency lockdown narrowed" + ui.NC + " on scope '" + pl.scope + "': " + strings.Join(liftedGroups(pl), ", ") + " lifted, " + strings.Join(pl.groups, ", ") + " still locked.")
		}
	}
	inv.echo("  Rendered: " + lockdownRendered(res))
	if len(res.RestartFailed) > 0 {
		inv.app.Out.Error("The record is removed and the rendered files are kept, but the lockdown is not lifted until the backend named under Rendered is restarted.")
		return exit(1)
	}
	return nil
}

// liftedGroups are the groups a disable plan lifts.
func liftedGroups(pl lockdownPlan) []string {
	var out []string
	for _, g := range pl.before.Groups {
		if !slices.Contains(pl.groups, g) {
			out = append(out, g)
		}
	}
	return out
}

// lockedOutNames are the users of the scope in the locked groups.
func (inv *invocation) lockedOutNames(m *model.Model, scope string, groups []string) []string {
	var out []string
	for _, u := range m.LockedOut(scope, groups) {
		out = append(out, u.Name)
	}
	sort.Strings(out)
	return out
}

// lockdownExempt are the members of the scope the lockdown leaves: the
// users of the superuser groups.
func (inv *invocation) lockdownExempt(m *model.Model, scope string) []string {
	var out []string
	for _, n := range m.Members(scope) {
		if u := m.User(n); u != nil && inv.groupIsSuperuser(m, u.Group) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// lockdownPreview prints who loses access on a scope and who keeps it.
func (inv *invocation) lockdownPreview(m *model.Model, pl lockdownPlan, enable bool) {
	s := m.Scope(pl.scope)
	inv.echo("Lock the logins of " + strings.Join(pl.groups, ", ") + " on scope '" + pl.scope + "'?")
	out := inv.lockedOutNames(m, pl.scope, pl.groups)
	if len(out) == 0 {
		inv.echo("  No user of the scope is in those groups.")
	} else {
		inv.echo("  Lose access (" + strconv.Itoa(len(out)) + "): " + strings.Join(out, ", "))
	}
	keep := inv.lockdownExempt(m, pl.scope)
	var others []string
	for _, n := range m.Members(pl.scope) {
		if !slices.Contains(out, n) && !slices.Contains(keep, n) {
			others = append(others, n)
		}
	}
	inv.echo("  Keep access, superusers (" + strconv.Itoa(len(keep)) + "): " + orNone(keep))
	if len(others) > 0 {
		inv.echo("  Keep access, groups not locked (" + strconv.Itoa(len(others)) + "): " + strings.Join(others, ", "))
	}
	if s != nil {
		for _, p := range s.Prefixes {
			if cidr.ContainsAddr(p, "127.0.0.1") {
				inv.echo("  " + ui.Yellow + "The scope covers this server (" + p + "): its own console logins are refused for the locked groups too." + ui.NC)
				break
			}
		}
	}
	inv.echo("  Open sessions on Junos devices, WTI units and Linux hosts stay until they log in again or run sudo.")
	inv.echo("")
}

func orNone(l []string) string {
	if len(l) == 0 {
		return "none"
	}
	return strings.Join(l, ", ")
}

// --- status --------------------------------------------------------------------

// lockdownJSON is one lockdown in 'status --json'.
type lockdownJSON struct {
	Scope       string   `json:"scope"`
	Groups      []string `json:"groups"`
	Since       string   `json:"since"`
	LockedSecs  int64    `json:"locked_seconds"`
	By          string   `json:"by"`
	Reason      string   `json:"reason"`
	LockedUsers []string `json:"locked_users"`
	Exempt      []string `json:"exempt"`
}

func (inv *invocation) lockdownStatus(scope string, asJSON bool) error {
	m, err := inv.model()
	if err != nil {
		return err
	}
	filter := inv.callerScopes()
	if scope != "" && m.Scope(scope) == nil {
		return inv.usageErr("There is no scope '"+scope+"'.", emergencyUsage)
	}
	var rows []conf.Lockdown
	for _, l := range inv.app.Conf().Lockdowns() {
		if (scope == "" || l.Scope == scope) && filter.allows(l.Scope) {
			rows = append(rows, l)
		}
	}
	now := inv.app.Knobs.Now()
	if asJSON {
		out := make([]lockdownJSON, 0, len(rows))
		for _, l := range rows {
			j := lockdownJSON{Scope: l.Scope, Groups: l.Groups, Since: l.Since, By: l.By, Reason: l.Reason,
				LockedUsers: inv.lockedOutNames(m, l.Scope, l.Groups), Exempt: inv.lockdownExempt(m, l.Scope)}
			if t := l.SinceTime(); !t.IsZero() {
				j.LockedSecs = int64(now.Sub(t) / time.Second)
			}
			if j.LockedUsers == nil {
				j.LockedUsers = []string{}
			}
			if j.Exempt == nil {
				j.Exempt = []string{}
			}
			out = append(out, j)
		}
		b, err := json.MarshalIndent(out, "", "  ")
		if err != nil {
			return err
		}
		inv.echo(string(b))
		return nil
	}
	if len(rows) == 0 {
		if scope != "" {
			inv.echo("No emergency lockdown stands on scope '" + scope + "'.")
		} else {
			inv.echo("No emergency lockdown stands.")
		}
		return nil
	}
	for _, l := range rows {
		inv.echo(ui.Red + ui.Bold + inv.lockdownLine(l) + ui.NC)
		out := inv.lockedOutNames(m, l.Scope, l.Groups)
		inv.echo("  Locked out (" + strconv.Itoa(len(out)) + "): " + orNone(out))
		inv.echo("  Superusers who keep access: " + orNone(inv.lockdownExempt(m, l.Scope)))
		if held := inv.holdsOnScope(m, l.Scope); len(held) > 0 {
			inv.echo("  " + ui.Yellow + "Break-glass is held on " + strings.Join(held, ", ") + ": a held device falls back to its local accounts." + ui.NC)
		}
		if inv.confGet("aaa.order."+l.Scope, "tacacs-first") == "local-first" {
			inv.echo("  " + ui.Red + "The scope lists local accounts first (aaa-order local-first): its devices let a local account in before they ask this server." + ui.NC)
		}
		for _, r := range lockdownResidual {
			inv.echo("  " + r + ".")
		}
		inv.echo("  Lift it with: tacctl emergency lockdown " + l.Scope + " disable")
	}
	return nil
}

// holdsOnScope are the names of the break-glass holds whose address a
// prefix of the scope covers.
func (inv *invocation) holdsOnScope(m *model.Model, scope string) []string {
	s := m.Scope(scope)
	if s == nil {
		return nil
	}
	var out []string
	for _, h := range inv.holds() {
		for _, p := range s.Prefixes {
			if cidr.ContainsAddr(p, h.Address) {
				out = append(out, h.Device)
				break
			}
		}
	}
	return out
}

// --- the records follow the names -----------------------------------------------

// scopeLockdownMove follows a scope's rename (newName set) or removal
// (newName empty): its lockdown record moves or goes.
func (inv *invocation) scopeLockdownMove(old, newName string) error {
	l := inv.lockdownOf(old)
	if l == nil {
		return nil
	}
	c := inv.app.Conf()
	if err := c.UpdateLockdown(old, func(*conf.Lockdown) (*conf.Lockdown, error) { return nil, nil }); err != nil {
		return err
	}
	if newName == "" {
		return nil
	}
	moved := *l
	return c.UpdateLockdown(newName, func(*conf.Lockdown) (*conf.Lockdown, error) { return &moved, nil })
}

// lockdownsNaming are the scopes whose lockdown locks the group.
func (inv *invocation) lockdownsNaming(group string) []string {
	var out []string
	for _, l := range inv.app.Conf().Lockdowns() {
		if l.Locks(group) {
			out = append(out, l.Scope)
		}
	}
	return out
}

// lockdownForgetGroup takes a removed group out of every lockdown; a record
// left with no group goes.
func (inv *invocation) lockdownForgetGroup(group string) error {
	c := inv.app.Conf()
	for _, scope := range inv.lockdownsNaming(group) {
		if err := c.UpdateLockdown(scope, func(cur *conf.Lockdown) (*conf.Lockdown, error) {
			if cur == nil {
				return nil, nil
			}
			next := *cur
			next.Groups = nil
			for _, g := range cur.Groups {
				if g != group {
					next.Groups = append(next.Groups, g)
				}
			}
			if len(next.Groups) == 0 {
				return nil, nil
			}
			return &next, nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// statusLockdowns is the Emergency lockdown line of the Security Posture
// section of 'status': none (green), or one red line per lockdown.
func (inv *invocation) statusLockdowns() {
	filter := inv.callerScopes()
	var rows []conf.Lockdown
	for _, l := range inv.app.Conf().Lockdowns() {
		if filter.allows(l.Scope) {
			rows = append(rows, l)
		}
	}
	if len(rows) == 0 {
		inv.echoE("    " + ui.Green + "Emergency lockdown: none" + ui.NC)
		return
	}
	for _, l := range rows {
		inv.echoE("    " + ui.Red + "Emergency lockdown: scope " + l.Scope + " since " + lockdownTime(l) + " by " + l.By + " (" + lockdownAge(l, inv.app.Knobs.Now()) +
			"): groups " + strings.Join(l.Groups, ", ") + " are refused (tacctl emergency lockdown status)" + ui.NC)
	}
}

// lockdownFindings are the lockdown records 'config validate' names: each
// one that stands (a warning), and what is wrong with it (a group or scope
// that is gone, a superuser group, a record that locks nothing).
func (inv *invocation) lockdownFindings(m *model.Model) []validateFinding {
	var out []validateFinding
	add := func(level, text, fix string) {
		out = append(out, validateFinding{Section: "emergency_lockdown", Level: level, Text: text, Fix: fix})
	}
	now := inv.app.Knobs.Now()
	for _, l := range inv.app.Conf().Lockdowns() {
		fix := "tacctl emergency lockdown " + l.Scope + " disable"
		add(levelWarning, "scope "+l.Scope+" is locked down since "+lockdownTime(l)+" by "+l.By+" ("+lockdownAge(l, now)+"): groups "+strings.Join(l.Groups, ", ")+" are refused", fix)
		if m == nil {
			continue
		}
		if m.Scope(l.Scope) == nil {
			add(levelError, "the lockdown of scope "+l.Scope+" names a scope that does not exist", fix)
		}
		for _, g := range l.Groups {
			switch {
			case m.Group(g) == nil:
				add(levelError, "the lockdown of scope "+l.Scope+" names the group "+g+", which does not exist", "tacctl emergency lockdown "+l.Scope+" disable "+g)
			case inv.groupIsSuperuser(m, g):
				add(levelError, "the lockdown of scope "+l.Scope+" locks the group "+g+", which is a superuser group now", "tacctl emergency lockdown "+l.Scope+" disable "+g)
			}
		}
	}
	for _, d := range inv.app.Conf().LockdownDefects() {
		add(levelError, "emergency.lockdown."+d.Scope+" "+d.Defect, "tacctl emergency lockdown "+d.Scope+" disable")
	}
	return out
}

// lockdownReadForm reports the command lines of 'emergency lockdown' that
// change nothing: status, a bare scope, a dry run, and the help.
func lockdownReadForm(rest []string) bool {
	var pos []string
	for _, a := range rest {
		switch {
		case a == "--dry-run" || a == "-h" || a == "--help":
			return true
		case strings.HasPrefix(a, "-"):
		default:
			pos = append(pos, a)
		}
	}
	return len(pos) == 0 || pos[0] == "status" || len(pos) == 1 && !slices.Contains(rest, "--all-scopes")
}
