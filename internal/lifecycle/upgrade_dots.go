package lifecycle

// A user name is letters, digits, '_' and '-' again (0.2.22): every user has
// an account on the tacctl server, and a name with a period cannot be a Linux
// account name. A store written by 0.2.20 or 0.2.21 can still hold one, and
// the upgrade renames it: every period becomes '_' (alice.smith is
// alice_smith), with everything that follows a user name following it, the
// way 'user rename' does it (the store record with its email, scopes, flags
// and limits; the UID line of linux-uids; the user's settings in
// console.yaml). Nothing is renamed when a new name is not a user name, when
// console.yaml or the ledger cannot take the renames (checked before the
// snapshot and before any write: the store is renamed first), or when the
// snapshot that comes first cannot be made.
//
// The renames are recorded in a small journal before the store is written
// and the journal is removed when the ledger and console.yaml have followed.
// An upgrade that stopped in between (a crash, a power cut) leaves it, and
// the next upgrade finishes the move for the users the store holds under
// their new names: nothing is guessed from the names. A key with a period in
// console.yaml that no rename covers (a hand edit, a user who is gone) is
// dropped with a line naming it, since it would make the file unreadable and
// belongs to nobody.
//
// A name with a period never had a Linux account, on this server or on a
// host (hosts.ScopeUsers skips it with a warning), so no account is renamed
// anywhere. The new name is a valid account name, and gets one at the next
// sync like any user.

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/audit"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/console"
	"github.com/rett/tacctl/internal/hosts"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/paths"
	"github.com/rett/tacctl/internal/policy"
	"github.com/rett/tacctl/internal/snapshot"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// DottedUser is a store user, with the scopes of its record (a break-glass
// account of one of them is checked against the new name of a user whose name
// has a period).
type DottedUser struct {
	Name   string
	Scopes []string
}

// DottedUserPlan is what the upgrade does about the store's users whose name
// has a period: Renames, in the order of the store, or Clashes, one line each
// for the users who cannot be given a name (then nothing is renamed).
type DottedUserPlan struct {
	Renames []console.UserRename
	Clashes []string
}

// NameWithoutPeriods is the name the upgrade gives a user: each period is a
// '_'. A user whose name that is taken gets a suffix after it
// (PlanDottedUsers).
func NameWithoutPeriods(name string) string { return strings.ReplaceAll(name, ".", "_") }

const (
	// suffixLen is the length of the random suffix, after its '_'.
	suffixLen = 4
	// maxNameLen is the longest name a Linux account has (hosts.LinuxName);
	// a suffixed name is kept within it by shortening the part before the
	// suffix.
	maxNameLen = 32
	// suffixTries bounds the draws for one name, so a source that always
	// answers the same cannot loop for ever.
	suffixTries = 1000
	suffixAlpha = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// RandomSuffix is the suffix of a renamed user whose new name is taken:
// suffixLen lowercase letters or digits from the system's random source.
func RandomSuffix() string {
	out := make([]byte, 0, suffixLen)
	buf := make([]byte, 16)
	// 252 is the largest multiple of len(suffixAlpha) below 256: a byte
	// from 252 up is dropped, so every character is equally likely.
	for len(out) < suffixLen {
		if _, err := rand.Read(buf); err != nil {
			panic("tacctl: no system random source: " + err.Error())
		}
		for _, b := range buf {
			if b < 252 && len(out) < suffixLen {
				out = append(out, suffixAlpha[int(b)%len(suffixAlpha)])
			}
		}
	}
	return string(out)
}

// PlanDottedUsers decides the renames for a store holding users (all of them,
// in the order of the store, with the scopes of each). A user's new name is
// its name with each period a '_'. When that name is a user already, when an
// earlier name with a period became it too, or when it is a break-glass local
// account of one of the user's scopes (c; the clash 'user rename' refuses),
// the user gets a suffix instead: '_' and suffixLen letters or digits from
// suffix (nil: RandomSuffix), drawn again until the name is free of every
// user, every other new name, every name a user with a period would get
// without a suffix, and the break-glass accounts of the user's scopes. A
// name too long for a Linux account with its suffix has the part before it
// shortened. A new name that is not a user name at all is a clash, and so is
// a name for which no free suffix is found: then nothing is renamed.
func PlanDottedUsers(c *conf.Config, users []DottedUser, suffix func() string) DottedUserPlan {
	if suffix == nil {
		suffix = RandomSuffix
	}
	taken := map[string]bool{} // the users with no period and the names given so far
	plain := map[string]bool{} // what each name with a period becomes without a suffix
	for _, u := range users {
		if strings.Contains(u.Name, ".") {
			plain[NameWithoutPeriods(u.Name)] = true
		} else {
			taken[u.Name] = true
		}
	}
	var plan DottedUserPlan
	for _, u := range users {
		if !strings.Contains(u.Name, ".") {
			continue
		}
		to := NameWithoutPeriods(u.Name)
		line := "  " + u.Name + " -> " + to + ": "
		if names.ValidateUsername(to) != nil {
			plan.Clashes = append(plan.Clashes, line+"not a name a user can have")
			continue
		}
		free := func(name string) bool {
			if taken[name] {
				return false
			}
			_, _, held := policy.BreakGlassMatch(c, name, u.Scopes)
			return !held
		}
		if !free(to) {
			base := to
			if len(base)+1+suffixLen > maxNameLen {
				base = base[:maxNameLen-1-suffixLen]
			}
			to = ""
			for range suffixTries {
				cand := base + "_" + suffix()
				if names.ValidateUsername(cand) == nil && !plain[cand] && free(cand) {
					to = cand
					break
				}
			}
			if to == "" {
				plan.Clashes = append(plan.Clashes, line+"taken, and no free name with a suffix was found")
				continue
			}
		}
		taken[to] = true
		plan.Renames = append(plan.Renames, console.UserRename{Old: u.Name, New: to})
	}
	return plan
}

// storeUsersOf reads the users of the store (none when the install has no
// store), with the scopes of each. A store that cannot be read is an error.
func storeUsersOf(pa paths.Paths) ([]DottedUser, error) {
	if !isRegular(pa.StoreFile) {
		return nil, nil
	}
	raw, err := store.LoadRaw(pa.StoreFile)
	if err != nil {
		return nil, err
	}
	root, _ := raw.(*yamlpy.Map)
	if root == nil {
		return nil, nil
	}
	section, _ := root.Get("users")
	users, _ := section.(*yamlpy.Map)
	if users == nil {
		return nil, nil
	}
	var out []DottedUser
	for name, rec := range users.All() {
		u := DottedUser{Name: name}
		if r, ok := rec.(*yamlpy.Map); ok {
			if sc, ok := r.Get("scopes"); ok {
				list, _ := sc.([]any)
				for _, s := range list {
					if str, ok := s.(string); ok {
						u.Scopes = append(u.Scopes, str)
					}
				}
			}
		}
		out = append(out, u)
	}
	return out, nil
}

// dottedPlan reads the store and plans with the suffixes of suffix. A store that cannot be read is said
// so and does not stop the upgrade (ok false): the store gate the backends
// run later reports the file, and an upgrade is what may put it right. The
// warning is said once, by the first look (warn). users are the store's users.
func (h *Host) dottedPlan(warn bool, suffix func() string) (plan DottedUserPlan, users []DottedUser, ok bool) {
	users, err := storeUsersOf(h.Paths)
	if err != nil {
		if !warn {
			return plan, nil, false
		}
		h.Out.Warn(h.Paths.StoreFile + " cannot be read, so a user name with a period was not looked for (" +
			errLine(err) + "); the upgrade goes on, and the store gate reports the file")
		return plan, nil, false
	}
	return PlanDottedUsers(h.Conf, users, suffix), users, true
}

// journalPath is the file that records the renames between the write of the
// store and the end of the move of the ledger and console.yaml.
func (h *Host) journalPath() string { return filepath.Join(h.Paths.StateDir, "upgrade-renames") }

// readJournal is the renames an interrupted upgrade recorded: one line each,
// "<old> <new>". A file that is absent or cannot be read records none.
func readJournal(path string) []console.UserRename {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []console.UserRename
	for _, l := range strings.Split(string(data), "\n") {
		if f := strings.Fields(l); len(f) == 2 {
			out = append(out, console.UserRename{Old: f[0], New: f[1]})
		}
	}
	return out
}

// writeJournal records renames (none: removes the file).
func writeJournal(path string, renames []console.UserRename) error {
	if len(renames) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	var b strings.Builder
	b.WriteString("# renames of users whose name had a period, recorded by 'tacctl upgrade'; removed when they are done\n")
	for _, r := range renames {
		b.WriteString(r.Old + " " + r.New + "\n")
	}
	return writeFileAtomic(path, []byte(b.String()), 0o600)
}

// pendingRenames are the renames of an interrupted upgrade that have to be
// finished: the store holds the user under the new name and no longer under
// the old one. An entry whose old name is still a store user was never
// written (the new plan covers it), and one with neither name is for a user
// who is gone.
func (h *Host) pendingRenames(users []DottedUser) []console.UserRename {
	var out []console.UserRename
	for _, r := range readJournal(h.journalPath()) {
		inStore := func(name string) bool {
			return slices.ContainsFunc(users, func(u DottedUser) bool { return u.Name == name })
		}
		if !inStore(r.Old) && inStore(r.New) {
			out = append(out, r)
		}
	}
	return out
}

// dottedCanFollow says whether the UID ledger and console.yaml can take the
// renames, and which keys with a period console.yaml would lose (no rename
// covers them). The error says which file and why. The store is renamed
// before them, so this is asked first.
func (h *Host) dottedCanFollow(renames []console.UserRename) (dropped []string, err error) {
	if len(renames) > 0 {
		if err := (hosts.UIDs{Path: h.Paths.LinuxUIDs}).CanMove(); err != nil {
			return nil, fmt.Errorf("%s cannot be moved: %s", h.Paths.LinuxUIDs, errLine(err))
		}
	}
	dropped, err = console.CheckRenameUsers(h.Paths.ConsoleFile, renames)
	if err != nil {
		return nil, fmt.Errorf("%s cannot take the renames: %s", h.Paths.ConsoleFile, errLine(err))
	}
	return dropped, nil
}

// How far an upgrade got when it stops for a new name that is not a user
// name.
const (
	refusedEarly  = iota // before anything was changed
	refusedReexec        // after the update of the installed command by an older release's upgrade
	refusedLate          // under the apply lock, after the state migration and the builds
)

// dottedUsersGate is the upgrade's first look at the store for a user name
// with a period, before anything is changed: it prints the refusal and
// returns backend.ErrFailed when a user cannot be given a name, so the
// upgrade stops with the state as it was. (A taken name is no reason to stop:
// the user gets a suffix.) The rename itself comes later, under the apply
// lock (renameDottedUsers), which draws the suffixes; this look only decides
// whether to go on.
//
// An upgrade started by a release before 0.2.22 has no such check: it moves
// the state, pulls and rebuilds, replaces the installed command and
// re-executes it (ReexecEnv=1), and this gate is the new command's. The
// refusal then says what was done and what was not.
func (h *Host) dottedUsersGate() error {
	plan, users, ok := h.dottedPlan(true, RandomSuffix)
	if !ok {
		return nil
	}
	stage := refusedEarly
	if h.Environ.Get(ReexecEnv) == "1" {
		stage = refusedReexec
	}
	if len(plan.Clashes) > 0 {
		for _, l := range UpgradeDottedUsersRefusal(plan, stage, h.Paths.StoreFile) {
			h.Out.Error(l)
		}
		return backend.ErrFailed
	}
	renames := slices.Concat(plan.Renames, h.pendingRenames(users))
	if len(renames) == 0 {
		return nil
	}
	if _, err := h.dottedCanFollow(renames); err != nil {
		for _, l := range UpgradeDottedFollowRefusal(err, stage) {
			h.Out.Error(l)
		}
		return backend.ErrFailed
	}
	return nil
}

// UpgradeDottedFollowRefusal is the refusal of an upgrade that has users to
// rename while console.yaml or the UID ledger cannot take the renames: the
// store is renamed first, and a file that fails after it is the half-done
// state this refusal avoids. why names the file and the reason; stage is as
// for UpgradeDottedUsersRefusal.
func UpgradeDottedFollowRefusal(why error, stage int) []string {
	return []string{
		"The upgrade renames a user whose name has a period, but " + errLine(why) + ".",
		"Repair the file, then run the upgrade again. No user was renamed.",
		refusalTail(stage),
	}
}

// refusalTail says what an upgrade that stopped for a user name changed.
func refusalTail(stage int) string {
	switch stage {
	case refusedReexec:
		return "tacctl and the tacquito build were updated; the store, the configuration and the services were not."
	case refusedLate:
		return "The store was not changed."
	}
	return "Nothing was changed."
}

// UpgradeDottedUsersRefusal is the refusal of an upgrade while a user whose
// name has a period cannot be given a name: each such user with the reason.
// stage says what the upgrade changed before it stopped: nothing, the
// installed command and the tacquito build (the upgrade was re-executed by
// the command an older release replaced), or the state migration and the
// builds, but not the store. storePath is the file whose key is edited, as no
// command renames a name that is not a user name.
func UpgradeDottedUsersRefusal(plan DottedUserPlan, stage int, storePath string) []string {
	n := len(plan.Clashes)
	out := []string{"The upgrade renames a user whose name has a period (a user name is letters, digits, '_' and '-') by replacing each period with '_', but " +
		fmt.Sprint(n) + " " + pluralWord(n, "user cannot", "users cannot") + " be given a name:"}
	out = append(out, plan.Clashes...)
	out = append(out, "No user was renamed. No command renames a name that is not a user name, so edit the "+pluralWord(n, "key", "keys")+
		" under 'users:' in "+storePath+", then run the upgrade again.")
	return append(out, refusalTail(stage))
}

// renameDottedUsers is the upgrade's conversion of the store's users whose
// name has a period (see the top of this file). It runs under the apply
// lock, after the state migration. Before anything is changed it checks that
// console.yaml and the ledger can take the renames; then a snapshot is taken
// and named, the renames are recorded in the journal, the store is changed in
// one write, the ledger and console.yaml follow each rename, and the journal
// is removed. A journal an interrupted upgrade left is finished first-hand:
// the users it names that the store holds under the new name get their ledger
// line and console settings moved. With nothing of that and no key with a
// period in console.yaml it does nothing, and takes no snapshot.
func (h *Host) renameDottedUsers() error {
	plan, users, ok := h.dottedPlan(false, h.NameSuffix)
	if !ok {
		return nil
	}
	out := h.Out
	if len(plan.Clashes) > 0 {
		for _, l := range UpgradeDottedUsersRefusal(plan, refusedLate, h.Paths.StoreFile) {
			out.Error(l)
		}
		return backend.ErrFailed
	}
	pending := h.pendingRenames(users)
	all := slices.Concat(plan.Renames, pending)
	dropped, ferr := h.dottedCanFollow(all)
	if len(all) == 0 && (ferr != nil || len(dropped) == 0) {
		// nothing to rename and nothing in console.yaml to drop; a file that
		// cannot be read is not this step's business
		if ferr == nil {
			_ = writeJournal(h.journalPath(), nil)
		}
		return nil
	}
	if ferr != nil {
		for _, l := range UpgradeDottedFollowRefusal(ferr, refusedLate) {
			out.Error(l)
		}
		return backend.ErrFailed
	}
	n := len(plan.Renames)
	switch {
	case n > 0:
		out.Info("Renaming " + fmt.Sprint(n) + " " + pluralWord(n, "user", "users") + " whose name has a period (a Linux account name cannot hold one):")
	case len(pending) > 0:
		out.Info("Finishing the rename of " + fmt.Sprint(len(pending)) + " " + pluralWord(len(pending), "user", "users") +
			" whose name had a period (an earlier upgrade stopped after the store was changed):")
	default:
		out.Info("Removing settings of users with a period in the name from " + h.Paths.ConsoleFile + ":")
	}
	id, err := h.snapshotBeforeRename()
	if err != nil {
		out.Error("A snapshot could not be made, so no user was renamed: " + errLine(err))
		return backend.ErrFailed
	}
	out.Info("  snapshot " + id + " holds the state before the rename (tacctl backup restore " + id + ")")

	if err := writeJournal(h.journalPath(), all); err != nil {
		out.Error("The renames could not be recorded in " + h.journalPath() + ", so no user was renamed: " + errLine(err))
		return backend.ErrFailed
	}
	if n > 0 {
		_, err = store.Mutate(h.Paths.StoreFile, store.MutateOptions{Now: h.Now}, func(s *store.Store) error {
			for _, r := range plan.Renames {
				if err := s.UserRename(r.Old, r.New); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			_ = writeJournal(h.journalPath(), pending)
			out.Error("The store was not changed, and no user was renamed: " + errLine(err))
			return backend.ErrFailed
		}
	}
	if h.AfterStoreRename != nil {
		if err := h.AfterStoreRename(); err != nil {
			return err
		}
	}

	// The rest follows the names; a part that fails is said with the way
	// back, as 'user rename' does: the store has changed already, and the
	// journal stays so that the next upgrade finishes the move.
	failed := func(what string, err error) error {
		out.Error("The users were renamed in the store, but " + what + " could not be updated: " + errLine(err) +
			". Fix the file and run the upgrade again, which finishes the move, or restore snapshot " + id + " (tacctl backup restore " + id + ").")
		return backend.ErrFailed
	}
	uids := hosts.UIDs{Path: h.Paths.LinuxUIDs}
	moves := make([]hosts.UIDMove, len(all))
	for i, r := range all {
		if moves[i] = uids.MoveUser(r.Old, r.New); moves[i].Err != nil {
			return failed(h.Paths.LinuxUIDs, moves[i].Err)
		}
	}
	res, err := console.RenameUsers(h.Paths.ConsoleFile, all)
	if err != nil {
		return failed(h.Paths.ConsoleFile, err)
	}
	settings := res.Moves
	if err := writeJournal(h.journalPath(), nil); err != nil {
		out.Warn("The record of the renames, " + h.journalPath() + ", could not be removed: " + errLine(err) + "; remove it")
	}
	for i, r := range all {
		var with []string
		if moves[i].Moved {
			with = append(with, "UID "+moves[i].UID+" carried")
		}
		if settings[i].Had() {
			with = append(with, "console settings moved")
		}
		if plain := NameWithoutPeriods(r.Old); r.New != plain {
			with = append(with, plain+" was taken")
		}
		line := "  renamed user " + r.Old + " to " + r.New
		if i >= n {
			line = "  finished the rename of user " + r.Old + " to " + r.New
		}
		if len(with) > 0 {
			line += " (" + strings.Join(with, ", ") + ")"
		}
		out.Info(line)
		if moves[i].HeldBy != "" {
			out.Warn("'" + r.New + "' already has UID " + moves[i].HeldBy + " in linux-uids; the account '" + r.Old + "' (UID " + moves[i].UID +
				") is removed on hosts and '" + r.New + "' created with " + moves[i].HeldBy)
		}
		uidWord := "-"
		if moves[i].Moved {
			uidWord = "carried"
		}
		h.auditLine("user rename", audit.Pair("from", r.Old), audit.Pair("to", r.New), audit.Pair("uid", uidWord))
	}
	for _, d := range res.Dropped {
		out.Warn("  dropped the console settings of '" + d + "' in " + h.Paths.ConsoleFile + ": no user of that name is in the store, and a name with a period is not read there")
	}
	if len(all) == 0 {
		return nil
	}
	out.Info("Tell " + pluralWord(len(all), "this user", "these users") + " to log in with the new name: the name typed at a device's login changed, and the old one no longer works.")
	out.Info("A name with a period never had a Linux account, so no account on this server or on a host is renamed; the new " +
		pluralWord(len(all), "name gets its account", "names get theirs") + " at the next sync.")
	return nil
}

// errLine is the lines of err on one, without the full stop that ends it.
func errLine(err error) string { return strings.TrimSuffix(strings.Join(lines(err), " "), ".") }

// snapshotBeforeRename takes the snapshot of the state the rename changes
// and returns its id: the one just made, or the newest when the state is the
// same as that one already.
func (h *Host) snapshotBeforeRename() (string, error) {
	if h.Snapshots == nil {
		return "", errors.New("no snapshot is available")
	}
	id, err := h.Snapshots.Take()
	if err != nil {
		return "", err
	}
	if id == "" {
		if ids := snapshot.IDs(h.Paths.BackupDir); len(ids) > 0 {
			id = ids[0]
		}
	}
	if id == "" {
		return "", errors.New("no snapshot was made")
	}
	return id, nil
}
