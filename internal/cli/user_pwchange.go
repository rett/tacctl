package cli

// The required password change in the 'user' verbs (0.2.20): 'user add' and
// 'user passwd' (the administrator's reset) require it by default,
// --no-change-required skips it, 'user require-password-change' flags or
// clears users on demand, and 'tacctl passwd' (the user's own change) clears
// it. What the flag does is elsewhere: the renderers keep a flagged user off
// every device (internal/pwchange, internal/render), the CLI refuses the
// commands but the password change (pwchange_gate.go) and the login console
// opens with the dialog (console_mode.go).
//
// A flag is set only where the user can do what it asks: log in to this
// tacctl server and change the password there. A superuser never is held to
// it, and a user who has no login on the server (the server is not enrolled,
// the user is not in its scope, or has no account there) could never change
// the password, so the flag is not set and the verb says why.

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/tier"
)

// noChangeRequired is the option that skips the required password change.
const noChangeRequired = "--no-change-required"

// pwBarrier is why a user cannot, or need not, be required to change the
// password: why is the reason in words ("" when the user can be), and
// exempt says it is the tier (a superuser), not a missing login.
type pwBarrier struct {
	why    string
	exempt bool
}

// pwCtx is what the barrier and the findings need, read once: the model and
// this server's registry entry.
type pwCtx struct {
	inv      *invocation
	m        *model.Model
	entry    hosts.Entry
	enrolled bool
	err      error
}

// pwContext reads the registry for a run of questions about the model m.
func (inv *invocation) pwContext(m *model.Model) *pwCtx {
	e, ok, err := inv.localHost()
	return &pwCtx{inv: inv, m: m, entry: e, enrolled: ok, err: err}
}

// barrier is the barrier of a user, existing or about to be: its group, its
// scopes and whether it can log in at all.
func (c *pwCtx) barrier(name, group string, scopes []string, disabled bool) pwBarrier {
	if pwchange.GroupTier(c.inv.app.Conf(), c.m, group) == tier.Superuser {
		return pwBarrier{why: "a superuser is never required to change the password", exempt: true}
	}
	if disabled {
		return pwBarrier{why: "it is disabled, so it cannot log in"}
	}
	e := c.entry
	switch {
	case c.err != nil:
		return pwBarrier{why: "the host registry cannot be read (" + msgsJoin(c.err) + "), so the server's scope is unknown"}
	case !c.enrolled:
		return pwBarrier{why: "this server is not enrolled (tacctl host enroll --local), so no user has a login on it to change the password at"}
	case !hosts.LinuxName(name):
		return pwBarrier{why: "its name is no Linux account name (a period), so it has no login on this server"}
	case !slices.Contains(scopes, e.Scope) && (!pwchange.ServerOf(e).ManagedIn(c.m) || !c.implicit(name, group)):
		return pwBarrier{why: "it is not in scope '" + e.Scope + "', the scope of this server, so it has no login on it"}
	}
	srv := c.inv.localServer(e)
	for _, addr := range srv.LoginAddresses() {
		if got := c.m.ScopeOf(addr, srv.Protocol); got != e.Scope {
			return pwBarrier{why: "scope '" + e.Scope + "' does not answer " + addr + " for " + hosts.MethodLabel(e.EffectiveMethod()) + ", where this server's own logins come from, so nobody logs in to it"}
		}
	}
	if ids, err := c.inv.app.Backends().Enabled(); err == nil && !slices.Contains(ids, srv.Protocol) {
		return pwBarrier{why: "backend '" + srv.Protocol + "', which answers this server's own " + hosts.MethodLabel(e.EffectiveMethod()) + " logins, is not enabled, so nobody logs in to it"}
	}
	return pwBarrier{}
}

// implicit reports whether a user of that name and group is a member of the
// managed scope without having it (pwchange.Implicit; an existing accounting
// sink is not).
func (c *pwCtx) implicit(name, group string) bool {
	if u := c.m.User(name); u != nil && u.AccountingSink {
		return false
	}
	return hosts.LinuxName(name) && pwchange.GroupTier(c.inv.app.Conf(), c.m, group) != tier.None
}

// pwBarrier is the barrier of a user, existing or about to be.
func (inv *invocation) pwBarrier(m *model.Model, name, group string, scopes []string, disabled bool) pwBarrier {
	return inv.pwContext(m).barrier(name, group, scopes, disabled)
}

// userBarrier is pwBarrier of a user of the model.
func (inv *invocation) userBarrier(m *model.Model, u *model.User) pwBarrier {
	return inv.pwBarrier(m, u.Name, u.Group, u.Scopes, u.IsDisabled())
}

// sharedPrefixes are the prefixes of this server's scope that answer more
// than the server: the devices in them still authenticate a user held to a
// password change, as the renderers can cut by scope only. Nil when the scope
// is the server's alone or the server is not enrolled.
func (c *pwCtx) sharedPrefixes() []string {
	if !c.enrolled {
		return nil
	}
	s := c.m.Scope(c.entry.Scope)
	if s == nil {
		return nil
	}
	return c.inv.localServer(c.entry).SharedPrefixes(s)
}

// sharedNote is the warning for a scope that has such prefixes, "" otherwise.
func (c *pwCtx) sharedNote() string {
	shared := c.sharedPrefixes()
	if len(shared) == 0 {
		return ""
	}
	return "Scope '" + c.entry.Scope + "', this server's, also answers " + strings.Join(shared, ", ") + ": a device there still accepts a user who must change the password, " +
		"because the user stays in the scope the server's own logins use. Give the server's login a scope of its own to keep the devices out: tacctl host enroll --local"
}

// sharedScopeNote is the warning that this server's scope answers more than
// the server ("" when it does not, or the server is not enrolled).
func (inv *invocation) sharedScopeNote(m *model.Model) string {
	return inv.pwContext(m).sharedNote()
}

// reportRequired is what a verb says after it has flagged users: they can log
// in to tacctl only, until the password is changed.
func (inv *invocation) reportRequired(m *model.Model, names []string) {
	if len(names) == 0 {
		return
	}
	if note := inv.sharedScopeNote(m); note != "" {
		inv.app.Out.WarnE(note)
	}
}

// reportHostsSync tells what the next sync of the other enrolled hosts does
// with a change of the flag of names (users the flag holds, or held until
// now): every host but this server expires the account of a user who must
// change the password and opens it again once the change is made, at its next
// 'host sync' (linuxAccounts), and until then the host is as it was. Nothing
// is said when no such host has one of the users in its scope.
func (inv *invocation) reportHostsSync(m *model.Model, names []string, required bool) {
	reg, err := inv.registry()
	if err != nil || len(names) == 0 {
		return
	}
	n := 0
	for _, e := range reg.Entries() {
		if e.Target == hosts.Local {
			continue
		}
		for _, name := range names {
			if u := m.User(name); u != nil && hosts.LinuxName(name) && slices.Contains(u.Scopes, e.Scope) {
				n++
				break
			}
		}
	}
	if n == 0 {
		return
	}
	who := "'" + strings.Join(names, "', '") + "'"
	if required {
		inv.app.Out.WarnE(who + " can still log in to " + hostsText(n) + " until each host's next sync, which expires the account there: tacctl host sync --all")
		return
	}
	inv.app.Out.InfoE(who + " can log in to " + hostsText(n) + " again after each host's next sync: tacctl host sync --all")
}

// detailPwChange is the audit line of a flag set or cleared: for whom, by
// whom (the writer adds by=), and through which verb.
func (inv *invocation) detailPwChange(name string, required bool, via string) {
	state := "cleared"
	if required {
		state = "required"
	}
	inv.detail("user password-change", kvp("name", name), kvp("state", state), kvp("via", via))
}

// userRequirePasswordChange is 'user require-password-change <user>|--all
// [on|off]': flag (on, the default) or clear (off) one user or every user,
// in one write. On skips what the flag cannot bind (a superuser) or could
// never be met (no login on this server) and says how many it skipped and
// flagged; off clears every flag it finds, a superuser's included.
func (inv *invocation) userRequirePasswordChange(args []string) error {
	a := inv.app
	const usage = "Usage: tacctl user require-password-change <username>|--all [on|off]"
	p, err := Parse(userSpecs["require-password-change"], args)
	if err != nil {
		msg := err.Error()
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			msg = "Unknown option: '" + uf.Flag + "'"
		}
		return inv.usageErr(msg, usage)
	}
	all := p.Has("--all")
	state := "on"
	var target string
	switch {
	case all && len(p.Args) > 1, !all && len(p.Args) == 0, !all && len(p.Args) > 2:
		return inv.usageErr(usage)
	case all && len(p.Args) == 1:
		state = p.Args[0]
	case !all:
		target = p.Args[0]
		if len(p.Args) == 2 {
			state = p.Args[1]
		}
	}
	if state != "on" && state != "off" {
		if strings.Contains(state, "@") {
			// an email address typed in the place of the state is not repeated
			return inv.usageErr("The state is neither on nor off.", usage)
		}
		return inv.usageErr("'"+state+"' is neither on nor off.", usage)
	}
	if err := inv.requireStore(); err != nil {
		return err
	}
	if target != "" {
		if err := inv.newUsername(target); err != nil {
			return err
		}
	}
	m, err := inv.model()
	if err != nil {
		return err
	}
	var users []*model.User
	if all {
		for _, n := range m.UserNames() {
			if u := m.User(n); !u.AccountingSink {
				users = append(users, u)
			}
		}
	} else if u := m.User(target); u != nil {
		users = append(users, u)
	} else {
		return inv.usageErr("User '" + target + "' does not exist.")
	}
	required := state == "on"

	var change, skipped []string
	already, superusers := 0, 0
	for _, u := range users {
		switch {
		case !required && u.PasswordChangeRequired:
			change = append(change, u.Name)
		case !required:
			already++
		case u.PasswordChangeRequired && !inv.userBarrier(m, u).exempt:
			already++
		default:
			b := inv.userBarrier(m, u)
			switch {
			case b.why != "":
				skipped = append(skipped, u.Name+" ("+b.why+")")
				if b.exempt {
					superusers++
				}
			default:
				change = append(change, u.Name)
			}
		}
	}

	out := a.Out
	inv.echo("")
	if len(change) > 0 {
		if err := inv.storeApply(func(s *store.Store) error {
			for _, n := range change {
				if err := s.UserSet(n, "password_change_required="+map[bool]string{true: "true", false: "false"}[required]); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			return err
		}
		for _, n := range change {
			inv.detailPwChange(n, required, "require")
		}
	}
	switch {
	case required:
		for _, s := range skipped {
			out.WarnE("Skipped " + s + ".")
		}
		if len(change) > 0 {
			out.InfoE("Password change required of " + strings.Join(change, ", ") + ": each can log in to tacctl only, and no device accepts the user, until the password is changed.")
		}
		out.InfoE("Flagged " + strconv.Itoa(len(change)) + ", skipped " + strconv.Itoa(len(skipped)) + skippedSuperusers(superusers, len(skipped)) + ", already required " + strconv.Itoa(already) + ".")
		inv.reportRequired(m, change)
		inv.reportHostsSync(m, change, true)
		if err := inv.syncIfChanged(change); err != nil {
			return err
		}
	default:
		if len(change) > 0 {
			out.InfoE("Password change no longer required of " + strings.Join(change, ", ") + ".")
		}
		out.InfoE("Cleared " + strconv.Itoa(len(change)) + ", not required " + strconv.Itoa(already) + ".")
		var held []string
		for _, n := range change {
			if pwchange.Subject(a.Conf(), m, m.User(n)) {
				held = append(held, n)
			}
		}
		inv.reportHostsSync(m, held, false)
		if err := inv.syncIfChanged(change); err != nil {
			return err
		}
	}
	inv.echo("")
	return nil
}

// syncIfChanged syncs this server's accounts when the verb flagged or cleared
// some users (once, for all of them).
func (inv *invocation) syncIfChanged(change []string) error {
	if len(change) == 0 {
		return nil
	}
	return inv.syncOwnAccounts(change...)
}

// skippedSuperusers is " (n superusers)" after the count of the skipped when
// some of them are superusers, so the count says why in the common case.
func skippedSuperusers(superusers, skipped int) string {
	if skipped == 0 || superusers == 0 {
		return ""
	}
	return " (" + plurals(superusers, "superuser", "superusers") + ")"
}

func plurals(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// requiredLine is the cell 'user list' adds to the date of a user held to a
// password change, "" for everyone else: "(change required)", or the words of
// the standing when the user cannot log in to change it or the devices of a
// shared scope still accept the password.
func (c *pwCtx) requiredLine(u *model.User) string {
	if !pwchange.Subject(c.inv.app.Conf(), c.m, u) {
		return ""
	}
	if t := c.standing(u).text(); t != "" {
		return " (" + t + ")"
	}
	return " (change required)"
}
