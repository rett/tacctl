package cli

// How a user who must change the password stands (0.2.20): whether the user
// can log in to this server to do it, and whether the devices are really kept
// out. A flagged user who cannot log in to the server is locked out of
// everything, the change included, so the verbs that would leave one refuse
// (pwGuard, pwWriteGuard, pwHostGuard); the others are shown wherever the flag is shown.

import (
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
)

// The words for a flagged user who cannot change the password, and for one
// whom the devices of a shared scope still accept.
const (
	pwTextStranded = "flagged, cannot log in to change it"
	pwTextShared   = "flagged, devices in a scope shared with the server still accept the password"
)

// pwKind is how a flagged user stands.
type pwKind int

const (
	pwFine     pwKind = iota // can change it at the server, and no device accepts the password
	pwStranded               // has no login on the server
	pwShared                 // can change it, but devices in the shared scope still accept the password
)

// pwStanding is a pwKind and, for pwStranded, the reason in words.
type pwStanding struct {
	kind pwKind
	why  string
}

// text is the standing in the words of the lists ("" for pwFine).
func (s pwStanding) text() string {
	switch s.kind {
	case pwStranded:
		return pwTextStranded
	case pwShared:
		return pwTextShared
	}
	return ""
}

// standing is how u stands: pwFine for everyone the flag does not hold now (a
// superuser, an unflagged user, a disabled one, who cannot log in whatever
// the flag says).
func (c *pwCtx) standing(u *model.User) pwStanding {
	if u == nil || u.IsDisabled() || !pwchange.Subject(c.inv.app.Conf(), c.m, u) {
		return pwStanding{}
	}
	if b := c.barrier(u.Name, u.Group, u.Scopes, false); b.why != "" && !b.exempt {
		return pwStanding{kind: pwStranded, why: b.why}
	}
	if len(c.sharedPrefixes()) > 0 {
		return pwStanding{kind: pwShared}
	}
	return pwStanding{}
}

// stranded are the names of the flagged users who cannot log in to change
// the password, sorted.
func (c *pwCtx) stranded() []string {
	var out []string
	for _, u := range pwchange.Pending(c.inv.app.Conf(), c.m) {
		if c.standing(u).kind == pwStranded {
			out = append(out, u.Name)
		}
	}
	sort.Strings(out)
	return out
}

// shared are the names of the flagged users whom devices still accept.
func (c *pwCtx) shared() []string {
	var out []string
	for _, u := range pwchange.Pending(c.inv.app.Conf(), c.m) {
		if c.standing(u).kind == pwShared {
			out = append(out, u.Name)
		}
	}
	sort.Strings(out)
	return out
}

// clearCommands are the commands that lift the requirement of names, the way
// out a refusal names.
func clearCommands(names []string) []string {
	if len(names) > 3 {
		return []string{"tacctl user require-password-change --all off"}
	}
	var out []string
	for _, n := range names {
		out = append(out, "tacctl user require-password-change "+n+" off")
	}
	return out
}

// pwRefusal prints a refusal for a change that would leave the users without
// a login to change the password at, with the way out, and is exit status 1.
func (inv *invocation) pwRefusal(names []string, what string) error {
	lines := []string{what + " would leave " + strings.Join(names, ", ") + ", who must change the password, without a login on this server to do it at.",
		"Lift the requirement first, change this, then require it again:"}
	for _, c := range clearCommands(names) {
		lines = append(lines, "  "+c)
	}
	lines = append(lines, "Nothing was changed.")
	return inv.usageErr(lines...)
}

// pwGuard looks at a store change before it is made. It refuses (the error)
// one that would leave a user who must change the password without a login on
// this server: the change is tried on a copy of the store first (fn must
// only change the store it is given), before anything is snapshotted or
// written, and a user who already could not log in is not counted (nothing
// new is lost). The function returned, which the caller runs once the change
// is written, warns of users the change newly leaves with devices that still
// accept the password (a prefix added to the server's scope). Both are nil
// when nobody is flagged, fn fails (the caller reports that itself) or the
// change leaves everyone as they were.
func (inv *invocation) pwGuard(fn func(*store.Store) error) (func(), error) {
	path := inv.app.Paths.StoreFile
	before, err := store.Load(path)
	if err != nil {
		return nil, nil
	}
	bm := model.FromStore(before)
	if len(pwchange.Pending(inv.app.Conf(), bm)) == 0 {
		return nil, nil
	}
	after, err := store.Load(path)
	if err != nil || fn(after) != nil {
		return nil, nil
	}
	bc, ac := inv.pwContext(bm), inv.pwContext(model.FromStore(after))
	newly := newlyIn
	if lost := newly(bc.stranded(), ac.stranded()); len(lost) > 0 {
		return nil, inv.pwRefusal(lost, "This change")
	}
	// users flagged by this very change are told by the verb that flags them
	held := map[string]bool{}
	for _, u := range pwchange.Pending(inv.app.Conf(), bm) {
		held[u.Name] = true
	}
	var open []string
	for _, n := range newly(bc.shared(), ac.shared()) {
		if held[n] {
			open = append(open, n)
		}
	}
	if len(open) == 0 {
		return nil, nil
	}
	note := ac.sharedNote()
	return func() {
		inv.app.Out.WarnE(strings.Join(open, ", ") + " must change the password, and devices in the server's scope still accept the old one.")
		inv.app.Out.WarnE(note)
	}, nil
}

// newlyIn are the names of now that are not in was, in now's order.
func newlyIn(was, now []string) []string {
	seen := map[string]bool{}
	for _, n := range was {
		seen[n] = true
	}
	var out []string
	for _, n := range now {
		if !seen[n] {
			out = append(out, n)
		}
	}
	return out
}

// pwStrandedNow are the flagged users who cannot log in to this server to
// change the password, as the files are now: the store read again (never the
// invocation's model, which a writer may have left behind), tacctl.yaml as
// loaded (the tiers, the enabled backends) and the host registry. ok is false
// when the store cannot be read or flags nobody.
func (inv *invocation) pwStrandedNow() ([]string, bool) {
	st, err := store.Load(inv.app.Paths.StoreFile)
	if err != nil {
		return nil, false
	}
	m := model.FromStore(st)
	for _, u := range m.Users {
		if u.PasswordChangeRequired {
			return inv.pwContext(m).stranded(), true
		}
	}
	return nil, false
}

// pwWriteGuard is the one guard of the common write path (storeApplyThen,
// applyWith, backend disable): it wraps a writer that runs under the apply
// lock, reads how the flagged users stand before and after it, and fails the
// write, which the apply then rolls back (store.yaml and tacctl.yaml as they
// were, nothing rendered), when a user who could log in to this server to
// change the password no longer can. That covers whatever the writer changes:
// a scope that now answers the server's address before the server's own (scope
// add), a group's tier that newly holds its members, the backend of the
// server's own logins. pwGuard refuses a store change earlier, before the
// snapshot, with the same message; this one is the net under every writer.
func (inv *invocation) pwWriteGuard(writer func() error) func() error {
	return func() error {
		before, ok := inv.pwStrandedNow()
		if err := writer(); err != nil || !ok {
			return err
		}
		inv.app.Conf().Reload() // a writer may have replaced tacctl.yaml
		after, _ := inv.pwStrandedNow()
		if lost := newlyIn(before, after); len(lost) > 0 {
			return inv.pwRefusal(lost, "This change")
		}
		return nil
	}
}

// pwHostGuard refuses a change of this server's registration (its scope, its
// method, or the registration itself) while users must change the password:
// their logins at the server are where the scope and the method say, and the
// backends' files are rendered from that (pwchange.Server), so they would be
// left as the old registration wrote them, or without a login. what names the
// change; to is the registration it leads to ("" for none).
func (inv *invocation) pwHostGuard(what string, to *hosts.Entry) error {
	m, err := inv.model()
	if err != nil {
		return nil
	}
	e, ok, err := inv.localHost()
	if err != nil {
		return nil
	}
	if ok && to != nil && e.Scope == to.Scope && e.EffectiveMethod() == to.EffectiveMethod() {
		// The same scope and method: the backends render as before, but the
		// server's address (--server) is where its logins come from, which
		// the scope must still answer.
		next := *to
		next.Target = hosts.Local
		bc := inv.pwContext(m)
		ac := &pwCtx{inv: inv, m: m, entry: next, enrolled: true}
		if lost := newlyIn(bc.stranded(), ac.stranded()); len(lost) > 0 {
			return inv.pwRefusal(lost, what)
		}
		return nil
	}
	var names []string
	for _, u := range pwchange.Pending(inv.app.Conf(), m) {
		if !u.IsDisabled() {
			names = append(names, u.Name)
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	lines := []string{what + " changes the scope or the method this server's own logins use, and " + strings.Join(names, ", ") + " must change the password there; the files the backends read are rendered with them in that scope.",
		"Lift the requirement first, change this, then require it again:"}
	for _, c := range clearCommands(names) {
		lines = append(lines, "  "+c)
	}
	lines = append(lines, "Nothing was changed.")
	return inv.usageErr(lines...)
}
