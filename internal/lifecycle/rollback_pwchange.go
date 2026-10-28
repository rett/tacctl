package lifecycle

// The required password change (0.2.20, users.<name>.password_change_required
// in store.yaml) in a rollback. Every release before 0.2.20 refuses the key
// ("user '<name>': unknown field 'password_change_required'" on every store
// command, and 'backup restore' refuses a snapshot that has it), so each
// target removes it from the store (store.RollbackPasswordChange), after the
// snapshot --apply takes first. The precedent is the strict management filter
// mode (mgmtModeWarning): the key cannot stay, and what it did is lost, so
// the plan says who is affected and --apply refuses without --yes.
//
// What is lost is a protection: a flagged user, other than a superuser, is
// kept off every device by the renderers until the password is changed at
// tacctl. The older release renders the user into every scope of theirs
// again, so the users regain access to the devices with the password an
// administrator set (or knew), which they were to change. The warning names
// them. A flagged superuser is not named: the flag never bound one.
//
// The rendered backend files are not touched by the rollback (nothing is
// re-rendered or restarted), so the running TACACS+ and RADIUS files keep the
// users off the devices until the older release renders for another reason.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/pwchange"
	"github.com/rett/tacctl/internal/store"
)

// pwFlag is a user of the store that has the key.
type pwFlag struct {
	name string
	// held: the user is held to the change now (no superuser): the ones that
	// regain device access.
	held bool
}

// planPasswordChange reads the store for the users that have the key. An
// install without a store has none; a store that cannot be read is an error
// (a flag that cannot be seen must not be hidden).
func (p *RollbackPlan) planPasswordChange() error {
	if !p.in.HasStore {
		return nil
	}
	pa := p.in.Paths
	names, err := store.PasswordChangeKeys(pa.StoreFile)
	if err != nil {
		return &RollbackRefusal{Lines: []string{
			pa.StoreFile + " cannot be read, so a required password change cannot be ruled out (" + strings.TrimSuffix(err.Error(), ".") + "); fix it first (tacctl config validate)."}}
	}
	var m *model.Model
	if len(names) > 0 {
		if _, m, err = model.LoadStore(pa.StoreFile); err != nil {
			m = nil
		}
	}
	for _, n := range names {
		// A model that cannot be read leaves every user held (the safe side
		// for a warning).
		held := m == nil || pwchange.Subject(p.in.Conf, m, m.User(n))
		p.pwStore = append(p.pwStore, pwFlag{n, held})
	}
	return nil
}

// heldNames are the users of pwStore that regain device access.
func (p *RollbackPlan) heldNames() []string {
	var out []string
	for _, f := range p.pwStore {
		if f.held {
			out = append(out, f.name)
		}
	}
	return out
}

// addPasswordChange adds the step and the warning of the flags to the plan
// of any target: the step goes where the store's 'leave untouched' line was
// (the 0.2.3 plan has a step of its own for it, the others name the file in
// the line of the files left), and the warning after the plan's others.
func (p *RollbackPlan) addPasswordChange() {
	if len(p.pwStore) == 0 {
		return
	}
	target, sf := p.target(), p.in.Paths.StoreFile
	s := RollbackStep{Title: sf + ": remove the required password change " + target + " does not know", Todo: true}
	for _, f := range p.pwStore {
		line := "remove password_change_required of " + f.name
		if !f.held {
			line += " (a superuser: the flag never bound one)"
		}
		s.Lines = append(s.Lines, line)
	}
	s.Lines = append(s.Lines, "("+target+"'s schema refuses the key (\"unknown field 'password_change_required'\"); every other field of the store stays)")
	at := len(p.Steps)
	for i := range p.Steps {
		switch {
		case p.Steps[i].Title == "leave "+sf+" untouched":
			// the 0.2.3 plan: the step is replaced
			p.Steps = slices.Delete(p.Steps, i, i+1)
			at = i
		case p.Steps[i].Title == "leave every other file untouched":
			at = i
			if len(p.Steps[i].Lines) > 0 {
				p.Steps[i].Lines[0] = strings.Replace(p.Steps[i].Lines[0], sf+", ", "", 1)
			}
		default:
			continue
		}
		break
	}
	p.Steps = slices.Insert(p.Steps, at, s)

	held := p.heldNames()
	if len(held) == 0 {
		return
	}
	p.Warnings = append(p.Warnings, RollbackWarning{
		Title: "Users who must change their password get their device access back",
		Lines: []string{
			target + " has no required password change (0.2.20): " + strings.Join(held, ", ") + " " + plural(len(held), "is", "are") +
				" flagged, so the TACACS+ and RADIUS files keep " + plural(len(held), "that user", "those users") + " off every device until the password is changed at tacctl.",
			"The flag is removed from the store (" + target + "'s schema refuses it). Once " + target + " renders the files, " + plural(len(held), "the user is", "the users are") +
				" in every scope of theirs again and can log in to the devices with the password an administrator set or knew, the one to be changed. The rendered files are not touched here: they keep the flagged users off the devices until then.",
			"Have them change it first (they log in to tacctl and are asked, 'tacctl user require-password-change' lists nothing once they have), or keep this release.",
			"The flags stay in the snapshot --apply takes first (tacctl backup list).",
		}})
}
