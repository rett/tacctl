package lifecycle

// The email address of a user (0.2.23, users.<name>.email in store.yaml) in a
// rollback. Every release before 0.2.23 refuses the key ("user '<name>':
// unknown field 'email'" on every store command, and 'backup restore'
// refuses a snapshot that has it), so every target removes it from the store
// (store.RollbackEmail), after the snapshot --apply takes first. Unlike the
// files 0.2.22 reads as they are, this makes the 0.2.22 target convert a
// file, so that target takes a snapshot too when any user has an address.
//
// The snapshot is the record: the plan names the users who have an address
// (never the address), the apply names the snapshot and says what was
// dropped, and 'tacctl backup recover' puts the addresses back from it once
// this release is installed again. The older release prunes backups/ by its
// own retention and knows no KeepID, so the apply (internal/cli/rollback.go)
// also keeps the snapshot ('backup keep': a copy in paths.KeptDir, which no
// retention reaches) with a note that says what the rollback dropped. What is lost until then is only the
// address, which no rendered file holds; it needs an answer all the same
// because nothing but the snapshot has it afterwards, so the plan warns and
// --apply refuses without --yes.

import (
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/store"
)

// emailRelease is the release that made the change (its entry in rollbackAdditions).
const emailRelease = "0.2.23"

// planEmail reads the store for the users that have an address. An install
// without a store has none; a store that cannot be read is an error (an
// address that cannot be seen must not be hidden).
func (p *RollbackPlan) planEmail() error {
	if !p.in.HasStore {
		return nil
	}
	pa := p.in.Paths
	names, err := store.EmailKeys(pa.StoreFile)
	if err != nil {
		return &RollbackRefusal{Lines: []string{
			pa.StoreFile + " cannot be read, so an email address cannot be ruled out (" + strings.TrimSuffix(err.Error(), ".") + "); fix it first (tacctl config validate)."}}
	}
	p.emailUsers = names
	return nil
}

// EmailUsers are the users whose address the rollback removes, by name.
func (p *RollbackPlan) EmailUsers() []string { return slices.Clone(p.emailUsers) }

// addEmail adds the step and the warning to the plan of any target older
// than 0.2.23.
func (p *RollbackPlan) addEmail() {
	if len(p.emailUsers) == 0 {
		return
	}
	target, sf := p.target(), p.in.Paths.StoreFile
	s := RollbackStep{Title: sf + ": remove the email addresses " + target + " does not know", Todo: true}
	for _, n := range p.emailUsers {
		s.Lines = append(s.Lines, "remove email of "+n)
	}
	s.Lines = append(s.Lines, "("+target+"'s schema refuses the key (\"unknown field 'email'\"); every other field of the store stays)")
	// The step goes where the store's 'leave untouched' line was: the 0.2.3
	// plan has a step of its own for it, the others name the file in the
	// line of the files left.
	at := len(p.Steps)
	for i := range p.Steps {
		switch p.Steps[i].Title {
		case "leave " + sf + " untouched":
			p.Steps = slices.Delete(p.Steps, i, i+1)
			at = i
		case "leave every other file untouched":
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

	n := len(p.emailUsers)
	p.Warnings = append(p.Warnings, RollbackWarning{
		Title: "Email addresses are removed from the store",
		Lines: []string{
			target + " has no email address of a user (" + emailRelease + "): " + strings.Join(p.emailUsers, ", ") + " " + plural(n, "has one", "have one each") + ", removed from the store (" + target + "'s schema refuses the key).",
			"No rendered file holds an address, so no login changes. The addresses stay in the snapshot --apply takes first (tacctl backup list), whose id the apply names, and --apply keeps that snapshot in " + p.in.Paths.KeptDir + " ('tacctl backup keep': " + target + " prunes backups/ by its own retention and does not know the copy; no retention reaches it). Once " + emailRelease + " is installed again, 'tacctl backup recover <snapshot> --only email' puts them back.",
		}})
}
