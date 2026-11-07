package lifecycle

// A user name is letters, digits, '_' and '-' again (0.2.22): every user has
// an account on the tacctl server, and a name with a period cannot be a Linux
// account name. A store written by 0.2.20 or 0.2.21 can still hold one, and
// the upgrade renames it: every period becomes '_' (alice.smith is
// alice_smith), with everything that follows a user name following it, the
// way 'user rename' does it (the store record with its email, scopes, flags
// and limits; the UID line of linux-uids; the user's settings in
// console.yaml). Nothing is renamed when any new name is taken, or when the
// snapshot that comes first cannot be made.
//
// A name with a period never had a Linux account, on this server or on a
// host (hosts.ScopeUsers skips it with a warning), so no account is renamed
// anywhere. The new name is a valid account name, and gets one at the next
// sync like any user.

import (
	"crypto/rand"
	"errors"
	"fmt"
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
// warning is said once, by the first look (warn).
func (h *Host) dottedPlan(warn bool, suffix func() string) (plan DottedUserPlan, ok bool) {
	users, err := storeUsersOf(h.Paths)
	if err != nil {
		if !warn {
			return plan, false
		}
		h.Out.Warn(h.Paths.StoreFile + " cannot be read, so a user name with a period was not looked for (" +
			errLine(err) + "); the upgrade goes on, and the store gate reports the file")
		return plan, false
	}
	return PlanDottedUsers(h.Conf, users, suffix), true
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
	plan, ok := h.dottedPlan(true, RandomSuffix)
	if !ok || len(plan.Clashes) == 0 {
		return nil
	}
	stage := refusedEarly
	if h.Environ.Get(ReexecEnv) == "1" {
		stage = refusedReexec
	}
	for _, l := range UpgradeDottedUsersRefusal(plan, stage, h.Paths.StoreFile) {
		h.Out.Error(l)
	}
	return backend.ErrFailed
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
	switch stage {
	case refusedReexec:
		return append(out, "tacctl and the tacquito build were updated; the store, the configuration and the services were not.")
	case refusedLate:
		return append(out, "The store was not changed.")
	}
	return append(out, "Nothing was changed.")
}

// renameDottedUsers is the upgrade's conversion of the store's users whose
// name has a period (see the top of this file). It runs under the apply
// lock, after the state migration: a snapshot is taken first and named, the
// store is changed in one write, and the ledger and console.yaml follow each
// rename. With no such user it does nothing, and takes no snapshot.
func (h *Host) renameDottedUsers() error {
	plan, ok := h.dottedPlan(false, h.NameSuffix)
	if !ok || len(plan.Renames)+len(plan.Clashes) == 0 {
		return nil
	}
	out := h.Out
	if len(plan.Clashes) > 0 {
		for _, l := range UpgradeDottedUsersRefusal(plan, refusedLate, h.Paths.StoreFile) {
			out.Error(l)
		}
		return backend.ErrFailed
	}
	n := len(plan.Renames)
	out.Info("Renaming " + fmt.Sprint(n) + " " + pluralWord(n, "user", "users") + " whose name has a period (a Linux account name cannot hold one):")
	id, err := h.snapshotBeforeRename()
	if err != nil {
		out.Error("A snapshot could not be made, so no user was renamed: " + errLine(err))
		return backend.ErrFailed
	}
	out.Info("  snapshot " + id + " holds the state before the rename (tacctl backup restore " + id + ")")

	_, err = store.Mutate(h.Paths.StoreFile, store.MutateOptions{Now: h.Now}, func(s *store.Store) error {
		for _, r := range plan.Renames {
			if err := s.UserRename(r.Old, r.New); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		out.Error("The store was not changed, and no user was renamed: " + errLine(err))
		return backend.ErrFailed
	}

	// The rest follows the names; a part that fails is said with the way
	// back, as 'user rename' does: the store has changed already.
	failed := func(what string, err error) error {
		out.Error("The users were renamed in the store, but " + what + " could not be updated: " + errLine(err) +
			". Restore snapshot " + id + " (tacctl backup restore " + id + "), fix the file, and run the upgrade again.")
		return backend.ErrFailed
	}
	uids := hosts.UIDs{Path: h.Paths.LinuxUIDs}
	moves := make([]hosts.UIDMove, n)
	for i, r := range plan.Renames {
		if moves[i] = uids.MoveUser(r.Old, r.New); moves[i].Err != nil {
			return failed(h.Paths.LinuxUIDs, moves[i].Err)
		}
	}
	settings, err := console.RenameUsers(h.Paths.ConsoleFile, plan.Renames)
	if err != nil {
		return failed(h.Paths.ConsoleFile, err)
	}
	for i, r := range plan.Renames {
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
	out.Info("Tell " + pluralWord(n, "this user", "these users") + " to log in with the new name: the name typed at a device's login changed, and the old one no longer works.")
	out.Info("A name with a period never had a Linux account, so no account on this server or on a host is renamed; the new " +
		pluralWord(n, "name gets its account", "names get theirs") + " at the next sync.")
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
