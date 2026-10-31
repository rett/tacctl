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
// Nothing printed or logged holds an address or a passphrase: the email lines
// name users, the SNMPv3 lines name levels and count users, and the audit
// line carries counts and the snapshot ids.

import (
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/snmpcred"
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
	{name: "snmp-users", what: "SNMPv3 users", plan: planRecoverSNMP},
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

// --- SNMPv3 users ----------------------------------------------------------

// The reasons an SNMPv3 item is skipped or needs nothing.
const (
	snmpHasIt     = "has it already"
	snmpLevelGone = "no longer exists"
	snmpHeld      = "the name is held by "
	snmpKeepsDef  = "keeps its current default"
	snmpNoChoice  = "the user it chose is not there"
)

// snmpItem is one user (or the default) of one level of the snapshot.
type snmpItem struct {
	level snmpcred.Level
	// user is the user to restore; for the default, def is its name.
	user snmpcred.User
	def  string
	// why is the reason the item is skipped or needs nothing, "" when it is
	// restored.
	why string
}

// snmpPlan is the plan of the SNMPv3 users: the users of the snapshot's
// credential files against the pools now.
type snmpPlan struct {
	snap  snmpcred.Store
	items []snmpItem
}

// planRecoverSNMP reads the snapshot's credential files and decides each
// user against the live pools.
func planRecoverSNMP(inv *invocation, dir string) (recoverPlan, error) {
	pl := &snmpPlan{snap: snmpcred.Store{File: filepath.Join(dir, "snmp.yaml"), Dir: filepath.Join(dir, "snmp")}}
	items, err := inv.decideSNMP(pl.snap)
	if err != nil {
		return nil, err
	}
	pl.items = items
	return pl, nil
}

// snmpSnapshotLevels are the levels the snapshot has a credential file for:
// the default level, the scopes, the devices.
func snmpSnapshotLevels(snap snmpcred.Store) ([]snmpcred.Level, error) {
	levels := []snmpcred.Level{{Kind: snmpcred.LevelDefault}}
	scopes, err := snmpcred.ScopeNames(snap.Dir)
	if err != nil {
		return nil, err
	}
	for _, n := range scopes {
		levels = append(levels, snmpcred.Level{Kind: snmpcred.LevelScope, Name: n})
	}
	devs, err := snmpcred.DeviceNames(snap.Dir)
	if err != nil {
		return nil, err
	}
	for _, n := range devs {
		levels = append(levels, snmpcred.Level{Kind: snmpcred.LevelDevice, Name: n})
	}
	return levels, nil
}

// decideSNMP decides each user of the snapshot against the pools now, level
// by level: a scope or a device that is gone is skipped; a user the level has
// already needs nothing; a name another pool that can see it holds (the
// config's, the scope's, a device's: the unique-names rule) is skipped, and
// the current one kept; the rest is restored. A default is restored only
// where the level has none, naming a user that is there; a current default is
// never overwritten.
func (inv *invocation) decideSNMP(snap snmpcred.Store) ([]snmpItem, error) {
	live := inv.snmpStore()
	levels, err := snmpSnapshotLevels(snap)
	if err != nil {
		return nil, err
	}
	_, res, rerr := inv.deviceLoad()
	var out []snmpItem
	// will are the users this run restores, by level: the levels come in the
	// order config, scopes, devices, so a level sees what the levels a device
	// or scope may share names with are about to get (a device's default may
	// name a user restored in the config or its scope in the same run, and
	// two restored users never take one name).
	will := map[snmpcred.Level]map[string]bool{}
	willHold := func(name string, at ...snmpcred.Level) (snmpcred.Level, bool) {
		for _, l := range at {
			if will[l][name] {
				return l, true
			}
		}
		return snmpcred.Level{}, false
	}
	for _, l := range levels {
		sc, err := snap.Load(l)
		if err != nil {
			// A file of the snapshot that cannot be read has nothing to give.
			continue
		}
		if len(sc.Users) == 0 && sc.Default == "" {
			continue
		}
		gone := func() snmpItem { return snmpItem{level: l, why: snmpLevelGone} }
		var scopeOfDev string
		var devsOfScope []string
		switch l.Kind {
		case snmpcred.LevelScope:
			ok, err := inv.scopeExists(l.Name)
			if err != nil {
				return nil, err
			}
			if !ok {
				for range sc.Users {
					out = append(out, gone())
				}
				continue
			}
			if rerr == nil {
				for _, e := range res.All() {
					if e.Source == devreg.SourceDevice && e.Scope == l.Name {
						devsOfScope = append(devsOfScope, e.Name)
					}
				}
			}
		case snmpcred.LevelDevice:
			var e devreg.Entry
			ok := false
			if rerr == nil {
				e, ok = res.Lookup(l.Name, devreg.ScopeFilter{})
			}
			if !ok || e.Source != devreg.SourceDevice {
				for range sc.Users {
					out = append(out, gone())
				}
				continue
			}
			scopeOfDev = e.Scope
		}
		cur, err := inv.liveSNMPCreds(live, l)
		if err != nil {
			return nil, err
		}
		peers, err := live.Peers(l, scopeOfDev, devsOfScope)
		if err != nil {
			return nil, err
		}
		// The levels whose restored users a user of this level shares names with.
		seen := []snmpcred.Level{{Kind: snmpcred.LevelDefault}}
		if l.Kind == snmpcred.LevelDevice && scopeOfDev != "" {
			seen = append(seen, snmpcred.Level{Kind: snmpcred.LevelScope, Name: scopeOfDev})
		}
		if l.Kind == snmpcred.LevelDefault {
			seen = nil
		}
		restoring := map[string]bool{}
		for _, u := range sc.Users {
			it := snmpItem{level: l, user: u}
			if _, ok := cur.Find(u.Name); ok {
				it.why = snmpHasIt
			} else if h, ok := snmpcred.Holder(u.Name, peers); ok {
				it.why = snmpHeld + h.Label()
			} else if h, ok := willHold(u.Name, seen...); ok {
				it.why = snmpHeld + h.Label()
			} else {
				restoring[u.Name] = true
				if will[l] == nil {
					will[l] = map[string]bool{}
				}
				will[l][u.Name] = true
			}
			out = append(out, it)
		}
		if sc.Default == "" || sc.Default == cur.Default {
			continue
		}
		it := snmpItem{level: l, def: sc.Default}
		_, inCur := cur.Find(sc.Default)
		_, inPeers := snmpcred.Holder(sc.Default, peers)
		_, inWill := willHold(sc.Default, seen...)
		// A default that named a user of this level's own pool in the snapshot
		// is not given to another level's user of the same name: that is
		// another credential.
		_, ownInSnap := sc.Find(sc.Default)
		if ownInSnap {
			inPeers, inWill = false, false
		}
		switch {
		case cur.Default != "":
			it.why = snmpKeepsDef
		case !inCur && !restoring[sc.Default] && (l.Kind != snmpcred.LevelDevice || (!inPeers && !inWill)):
			it.why = snmpNoChoice
		}
		out = append(out, it)
	}
	return out, nil
}

// liveSNMPCreds is the credentials the level has now: a device's are the file
// that is in force.
func (inv *invocation) liveSNMPCreds(live snmpcred.Store, l snmpcred.Level) (snmpcred.Creds, error) {
	if l.Kind == snmpcred.LevelDevice {
		if d := inv.deviceNamed(l.Name); d != nil {
			own, err := inv.deviceSNMPOwnOf(*d)
			return own.Creds, err
		}
	}
	return live.Load(l)
}

// Lines say, per level, how many users would be restored and why the others
// are not: levels and counts, never a user's name or a passphrase.
func (pl *snmpPlan) Lines() []string {
	if len(pl.items) == 0 {
		return []string{"the snapshot holds none"}
	}
	type group struct {
		level          snmpcred.Level
		restore        int
		skipped        map[string]int
		has            int
		restoreDefault bool
	}
	var order []snmpcred.Level
	groups := map[snmpcred.Level]*group{}
	for _, it := range pl.items {
		g := groups[it.level]
		if g == nil {
			g = &group{level: it.level, skipped: map[string]int{}}
			groups[it.level] = g
			order = append(order, it.level)
		}
		switch {
		case it.def != "" && it.why == "":
			g.restoreDefault = true
		case it.def != "":
			g.skipped["its default: "+it.why]++
		case it.why == "":
			g.restore++
		case it.why == snmpHasIt:
			g.has++
		default:
			g.skipped[it.why]++
		}
	}
	var out []string
	for _, l := range order {
		g := groups[l]
		var parts []string
		if g.restore > 0 {
			parts = append(parts, "restore "+strconv.Itoa(g.restore)+" "+plural(g.restore, "user", "users"))
		}
		if g.restoreDefault {
			parts = append(parts, "restore its default")
		}
		if g.has > 0 {
			parts = append(parts, strconv.Itoa(g.has)+" "+plural(g.has, "has", "have")+" it already")
		}
		for _, why := range sortedKeys(g.skipped) {
			n := g.skipped[why]
			parts = append(parts, "skip "+strconv.Itoa(n)+", "+why)
		}
		out = append(out, levelLabel(l)+": "+strings.Join(parts, "; "))
	}
	return out
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func (pl *snmpPlan) Pending() int {
	n := 0
	for _, it := range pl.items {
		if it.why == "" {
			n++
		}
	}
	return n
}

// Skipped counts the items skipped for a reason; a user the level has
// already is neither pending nor skipped.
func (pl *snmpPlan) Skipped() int {
	n := 0
	for _, it := range pl.items {
		if it.why != "" && it.why != snmpHasIt {
			n++
		}
	}
	return n
}

// Apply decides again against the pools as they are now (they may have
// changed since the plan) and writes each level once.
func (pl *snmpPlan) Apply(inv *invocation) (restored, skipped int, err error) {
	items, err := inv.decideSNMP(pl.snap)
	if err != nil {
		return 0, 0, err
	}
	live := inv.snmpStore()
	var order []snmpcred.Level
	byLevel := map[snmpcred.Level][]snmpItem{}
	for _, it := range items {
		switch it.why {
		case "":
			if _, ok := byLevel[it.level]; !ok {
				order = append(order, it.level)
			}
			byLevel[it.level] = append(byLevel[it.level], it)
			restored++
		case snmpHasIt:
		default:
			skipped++
		}
	}
	for _, l := range order {
		cur, err := inv.liveSNMPCreds(live, l)
		if err != nil {
			return restored, skipped, err
		}
		cur = snmpcred.Creds{Community: cur.Community, Users: slices.Clone(cur.Users), Default: cur.Default}
		for _, it := range byLevel[l] {
			if it.def != "" {
				cur.Default = it.def
			} else {
				cur.Put(it.user)
			}
		}
		inv.app.Audit().Touch()
		if err := live.Save(l, cur); err != nil {
			return restored, skipped, err
		}
	}
	return restored, skipped, nil
}
