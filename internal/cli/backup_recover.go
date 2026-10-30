package cli

// 'tacctl backup recover <snapshot> [--only <kind>[,<kind>...]] [--dry-run]
// [--yes]' (docs/plans/0.2.23-plan.md D302): put back from a snapshot only
// what a rollback dropped, and leave everything else as it is. A rollback to
// a release that does not know a key removes it after a snapshot; this
// verb, run on this release again, reads that snapshot and sets what it
// held on the users that still exist. 'backup restore' brings back the
// whole state; this brings back a kind of data.
//
// What can be recovered is recoverKinds, the one list: the verb's spec, its
// usage and its messages are made from it, and a release that adds a kind
// appends an entry (a plan of the kind, from the snapshot's directory) and
// nothing else. A kind that is listed but cannot be recovered yet is
// reserved: it is accepted by name and refused, so a script that names it
// is told so and not that the word is unknown.
//
// The snapshot is looked up as every verb that takes an id does (snapDir):
// in backups/, else among the copies 'backup keep' made in backups-kept/,
// which no retention reaches. A rollback keeps the snapshot it names there,
// so the data it dropped can be recovered after the older release's own
// retention has pruned backups/.
//
// Nothing printed or logged holds an address: the lines name users, and the
// audit line carries counts and the snapshot ids.

import (
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/ui"
)

// recoverPlan is what recovering one kind from one snapshot would do.
type recoverPlan interface {
	// Lines say, per user, what would be restored and what is skipped and
	// why (names only).
	Lines() []string
	// Pending is how many items would be restored.
	Pending() int
	// Skipped is how many items are skipped.
	Skipped() int
	// Apply restores the items and reports how many it restored and how many
	// it skipped when it ran (the state may have changed since the plan).
	Apply(inv *invocation) (restored, skipped int, err error)
}

// recoverKind is one kind of data 'backup recover' puts back.
type recoverKind struct {
	name string
	// what is the plural noun of the kind in messages.
	what string
	// reserved: the kind is named in the usage but cannot be recovered yet;
	// it is refused with "not available yet" and has no plan.
	reserved bool
	// plan reads the snapshot in dir (and the live state) for the kind.
	plan func(inv *invocation, dir string) (recoverPlan, error)
}

// recoverKinds is the list of kinds, in the order the usage names them.
var recoverKinds = []recoverKind{
	{name: "email", what: "email addresses", plan: planRecoverEmail},
	{name: "snmp-users", what: "SNMPv3 users", reserved: true},
}

// recoverKindNames are the names of the kinds, the reserved ones included.
func recoverKindNames() []string {
	out := make([]string, len(recoverKinds))
	for i, k := range recoverKinds {
		out[i] = k.name
	}
	return out
}

const backupRecoverUsage = "Usage: tacctl backup recover <snapshot> [--only <kind>[,<kind>...]] [--dry-run] [--yes]"

// recoverKindsLine is the sentence that names the kinds.
func recoverKindsLine() string { return "Kinds: " + strings.Join(recoverKindNames(), ", ") + "." }

// recoverSpec is the arguments of 'backup recover', its kinds from the list.
func recoverSpec() Spec {
	return Spec{MinArgs: 1, MaxArgs: 1, Args: []string{KindBackups}, Flags: []Flag{
		{Names: []string{"--only"}, Value: true, Kind: strings.Join(recoverKindNames(), "|") + KindList, Arg: "<kind>[,<kind>...]",
			Desc: "Recover only these kinds of data",
			Long: "Recover only the listed kinds of data: " + strings.Join(recoverKindNames(), ", ") + ". Without it every kind that can be recovered is"},
		{Names: []string{"--dry-run"}, Desc: "List what would be recovered and change nothing"},
		{Names: []string{"--yes"}, Desc: "Do not ask for confirmation"},
	}}
}

// recoverKindsFor are the kinds the command line asks for: the --only list
// (an unknown or a reserved kind is refused), or every kind that can be
// recovered.
func (inv *invocation) recoverKindsFor(p Parsed) ([]recoverKind, error) {
	if !p.Has("--only") {
		var out []recoverKind
		for _, k := range recoverKinds {
			if !k.reserved {
				out = append(out, k)
			}
		}
		return out, nil
	}
	var out []recoverKind
	for _, w := range strings.Split(p.Value("--only"), ",") {
		if w = strings.TrimSpace(w); w == "" {
			continue
		}
		i := slices.IndexFunc(recoverKinds, func(k recoverKind) bool { return k.name == w })
		switch {
		case i < 0:
			if strings.Contains(w, "@") {
				// an email address typed in the place of a kind is not repeated
				return nil, inv.usageErr("Unknown kind. "+recoverKindsLine(), backupRecoverUsage)
			}
			return nil, inv.usageErr("Unknown kind '"+w+"'. "+recoverKindsLine(), backupRecoverUsage)
		case recoverKinds[i].reserved:
			return nil, inv.usageErr("'"+w+"' is not available yet: this release cannot recover "+recoverKinds[i].what+". Nothing was changed.", recoverKindsLine())
		case !slices.ContainsFunc(out, func(k recoverKind) bool { return k.name == w }):
			out = append(out, recoverKinds[i])
		}
	}
	if len(out) == 0 {
		return nil, inv.usageErr(backupRecoverUsage, recoverKindsLine())
	}
	return out, nil
}

// backupRecover is the command.
func (inv *invocation) backupRecover(args []string) error {
	a := inv.app
	p, err := Parse(backupSpecs["recover"], args)
	if err != nil {
		var uf *UnknownFlagError
		if errors.As(err, &uf) {
			return inv.usageErr("Unknown option '"+uf.Flag+"'. "+backupRecoverUsage, recoverKindsLine())
		}
		return inv.usageErr(backupRecoverUsage, recoverKindsLine(), "Run 'tacctl backup list' to see available snapshots.")
	}
	kinds, err := inv.recoverKindsFor(p)
	if err != nil {
		return err
	}
	id := p.Args[0]
	if !inv.storeMode() {
		return inv.usageErr("No store yet: there is nothing to recover into. " + store.NotInitialisedMsg)
	}
	dir, kept := inv.snapDir(id)
	if dir == "" {
		if _, ok := inv.legacyPath(id); ok {
			return inv.usageErr(id + " is an old-style backup: it holds no users to recover from. Nothing was changed.")
		}
		return inv.usageErr("Backup not found: "+id, "Run 'tacctl backup list' to see available backups.")
	}
	if errs, err := store.ValidateFile(filepath.Join(dir, "store.yaml")); err != nil || len(errs) > 0 {
		return inv.usageErr("Snapshot " + id + " cannot be read: its store.yaml is missing or not valid. Nothing was changed.")
	}

	plans := make([]recoverPlan, len(kinds))
	pending, skipped := 0, 0
	inv.echo("")
	inv.echoE(ui.Bold + "Recover from snapshot " + id + ui.NC)
	if kept {
		inv.echo("  (a kept copy, " + dir + ")")
	}
	for i, k := range kinds {
		pl, err := k.plan(inv, dir)
		if err != nil {
			return err
		}
		plans[i] = pl
		inv.echo("")
		inv.echo("  " + k.what + ":")
		for _, l := range pl.Lines() {
			inv.echo("    " + l)
		}
		pending += pl.Pending()
		skipped += pl.Skipped()
	}
	inv.echo("")
	if pending == 0 {
		inv.echo("Nothing to recover.")
		return nil
	}
	if p.Has("--dry-run") {
		inv.echo("This was a dry run: nothing was changed. To recover: tacctl backup recover " + id + recoverOnlyArg(p) + " --yes")
		return nil
	}
	if !p.Has("--yes") && !a.Prompter().Confirm("  Recover "+strconv.Itoa(pending)+" item"+plural(pending, "", "s")+" from this snapshot? [y/N]: ") {
		a.Out.Info("Cancelled.")
		return nil
	}

	// The current state first, so that the recovery can be undone with a
	// restore; retention must not take the snapshot being read.
	a.Snapshots().KeepID = id
	preID, err := inv.snapshotFirstID()
	if err != nil {
		return err
	}
	restored, skippedNow := 0, 0
	for _, pl := range plans {
		r, s, err := pl.Apply(inv)
		if err != nil {
			return err
		}
		restored += r
		skippedNow += s
	}
	inv.detail("backup recover", kvp("id", id), kvp("pre", preID), kvp("kinds", strings.Join(kindNames(kinds), ",")),
		kvp("restored", strconv.Itoa(restored)), kvp("skipped", strconv.Itoa(skippedNow)))
	a.Out.InfoE("Recovered " + strconv.Itoa(restored) + " item" + plural(restored, "", "s") + " from snapshot " + id + ".")
	if skippedNow > 0 {
		a.Out.WarnE(strconv.Itoa(skippedNow) + " item" + plural(skippedNow, " was", "s were") + " skipped (listed above).")
	}
	if preID != "" {
		a.Out.Info("The state from before is in snapshot " + preID + " (tacctl backup list).")
	}
	if kept {
		a.Out.Info("Snapshot " + id + " is a kept copy; 'tacctl backup unkeep " + id + "' removes it once the data is recovered.")
	}
	inv.echo("")
	return nil
}

func kindNames(kinds []recoverKind) []string {
	out := make([]string, len(kinds))
	for i, k := range kinds {
		out[i] = k.name
	}
	return out
}

// recoverOnlyArg is " --only <kinds>" as typed, "" when it was not given.
func recoverOnlyArg(p Parsed) string {
	if !p.Has("--only") {
		return ""
	}
	return " --only " + p.Value("--only")
}

// --- email -----------------------------------------------------------------

// emailItem is one user of the snapshot that has an address.
type emailItem struct {
	user, address string
	// why is the reason it is skipped, "" when it is restored.
	why string
}

// emailPlan is the plan of the email addresses: the snapshot's users that
// have one, against the users now.
type emailPlan struct {
	snap  map[string]string
	items []emailItem
}

// planRecoverEmail reads the snapshot's store for its addresses and decides
// each against the live users.
func planRecoverEmail(inv *invocation, dir string) (recoverPlan, error) {
	_, sm, err := model.LoadStore(filepath.Join(dir, "store.yaml"))
	if err != nil {
		return nil, inv.usageErr("Snapshot " + filepath.Base(dir) + " cannot be read: its store.yaml is not valid. Nothing was changed.")
	}
	live, err := inv.model()
	if err != nil {
		return nil, err
	}
	pl := &emailPlan{snap: map[string]string{}}
	for _, n := range sm.UserNames() {
		if u := sm.User(n); u.Email != "" {
			pl.snap[n] = u.Email
		}
	}
	pl.items = decideEmails(pl.snap, live)
	return pl, nil
}

// decideEmails decides each address of the snapshot against the live
// model, in user order: a user that is gone is skipped; one that has the
// address already needs nothing; one that has another address keeps it; an
// address another user holds now is skipped, naming that user. The snapshot
// is a valid store, so its addresses are valid and each belongs to one user.
func decideEmails(snap map[string]string, live *model.Model) []emailItem {
	var out []emailItem
	for _, n := range sortedStringKeys(snap) {
		addr := snap[n]
		it := emailItem{user: n, address: addr}
		u := live.User(n)
		switch {
		case u == nil:
			it.why = "no longer exists"
		case u.Email != "" && names.SameEmail(u.Email, addr):
			it.why = emailHasIt
		case u.Email != "":
			it.why = "has a different address now, kept"
		default:
			if h := live.EmailHolder(addr, n); h != "" {
				it.why = "the address belongs to user '" + h + "' now"
			}
		}
		out = append(out, it)
	}
	return out
}

// emailHasIt is the reason of a user that has the snapshot's address
// already: nothing to do, and not a skip.
const emailHasIt = "has it already"

func sortedStringKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (pl *emailPlan) Lines() []string {
	if len(pl.items) == 0 {
		return []string{"the snapshot holds none"}
	}
	var out []string
	for _, it := range pl.items {
		switch it.why {
		case "":
			out = append(out, it.user+": restore")
		case emailHasIt:
			out = append(out, it.user+": "+it.why)
		default:
			out = append(out, it.user+": skip, "+it.why)
		}
	}
	return out
}

func (pl *emailPlan) Pending() int {
	n := 0
	for _, it := range pl.items {
		if it.why == "" {
			n++
		}
	}
	return n
}

// Skipped counts the items that are skipped for a reason; a user that has
// the address already is neither pending nor skipped.
func (pl *emailPlan) Skipped() int {
	n := 0
	for _, it := range pl.items {
		if it.why != "" && it.why != emailHasIt {
			n++
		}
	}
	return n
}

// Apply sets the addresses in one store write, deciding each again against
// the store under the lock (a user may have changed since the plan).
func (pl *emailPlan) Apply(inv *invocation) (restored, skipped int, err error) {
	err = inv.storeApply(func(s *store.Store) error {
		restored, skipped = 0, 0
		for _, it := range decideEmails(pl.snap, model.FromStore(s)) {
			switch it.why {
			case "":
				if err := s.UserSet(it.user, "email="+it.address); err != nil {
					return err
				}
				restored++
			case emailHasIt:
			default:
				skipped++
			}
		}
		return nil
	})
	return restored, skipped, err
}
