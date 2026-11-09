package console

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
)

// The settings of one user in console.yaml follow the user when the name
// changes: 'user rename' and the upgrade's rename of a user whose name had a
// period (0.2.20 and 0.2.21 allowed one) carry them here.

// UserSettingsMove is what a move did to a user's own settings in the file:
// the system shell (settings.system_shell_users: ShellHad, with value
// ShellOn), the password cache (settings.password_cache_users: CacheHad,
// always on) and the file transfer settings (settings.file_transfer: FileHad,
// with FileWhat saying what they were, such as "enable:operator, quota 1G").
// Err says the file could not be read or written.
type UserSettingsMove struct {
	ShellHad, ShellOn, CacheHad bool
	FileHad                     bool
	FileWhat                    string
	Err                         error
}

// Had reports whether the user had any of them.
func (m UserSettingsMove) Had() bool { return m.ShellHad || m.CacheHad || m.FileHad }

// fileTransferOf says what the user's own file transfer settings are
// ("enable:operator, quota 1G, rate 1M"), "" when there are none.
func (f *File) fileTransferOf(user string) string {
	var w []string
	if on, ok := f.FileTransferUsers[user]; ok {
		w = append(w, word(on))
		if on {
			w[0] += ":" + string(f.FileTransferUserTiers[user])
		}
	}
	if n, ok := f.FileTransferQuotaUsers[user]; ok {
		w = append(w, "quota "+QuotaWord(n))
	}
	if n, ok := f.FileTransferRateUsers[user]; ok {
		w = append(w, "rate "+RateWord(n))
	}
	return strings.Join(w, ", ")
}

// moveFileTransfer carries the file transfer settings of oldname to newname
// (newname "": drops them) and says what they were.
func (f *File) moveFileTransfer(oldname, newname string) string {
	what := f.fileTransferOf(oldname)
	if what == "" {
		return ""
	}
	on, hasOn := f.FileTransferUsers[oldname]
	was := f.FileTransferUserTiers[oldname]
	q, hasQ := f.FileTransferQuotaUsers[oldname]
	r, hasR := f.FileTransferRateUsers[oldname]
	f.dropFileTransferOf(oldname)
	if newname != "" {
		f.dropFileTransferOf(newname)
		if hasOn {
			f.SetFileTransferUser(newname, on, was)
		}
		if hasQ {
			f.FileTransferQuotaUsers[newname] = q
		}
		if hasR {
			f.FileTransferRateUsers[newname] = r
		}
	}
	return what
}

// dropFileTransferOf removes every file transfer setting of the user.
func (f *File) dropFileTransferOf(user string) {
	f.DropFileTransferUser(user)
	delete(f.FileTransferQuotaUsers, user)
	delete(f.FileTransferRateUsers, user)
}

// moveUser carries the settings of oldname to newname (newname "": drops
// them) in f and says what it moved. An entry already under newname
// (hand-edited) is replaced by the carried one, or dropped by the removal.
func (f *File) moveUser(oldname, newname string) UserSettingsMove {
	on, shellHad := f.SystemShellUsers[oldname]
	was := f.SystemShellUserTiers[oldname]
	cacheHad := f.PasswordCacheUsers[oldname]
	m := UserSettingsMove{ShellHad: shellHad, ShellOn: on, CacheHad: cacheHad}
	f.DropSystemShellUser(oldname)
	delete(f.PasswordCacheUsers, oldname)
	m.FileWhat = f.moveFileTransfer(oldname, newname)
	m.FileHad = m.FileWhat != ""
	if newname != "" {
		if shellHad {
			f.SetSystemShellUser(newname, on, was)
		}
		if cacheHad {
			f.PasswordCacheUsers[newname] = true
		}
	}
	return m
}

// MoveUserSettings carries the settings of oldname to newname (newname "":
// drops them) in the file at path, under its lock, as part of the user verb
// that follows the store's change (the snapshot the verb took first holds
// console.yaml). A person who is renamed keeps the access they had, a user
// who is removed leaves none behind for the next user of the name; a file
// without a setting for oldname is not touched, and an absent file is not
// created.
func MoveUserSettings(path, oldname, newname string) UserSettingsMove {
	f, err := Load(path)
	if err != nil {
		return UserSettingsMove{Err: err}
	}
	if _, shell := f.SystemShellUsers[oldname]; !shell && !f.PasswordCacheUsers[oldname] && f.fileTransferOf(oldname) == "" {
		return UserSettingsMove{}
	}
	// What is carried is read under the file's lock, in the same step that
	// writes it: a setting changed meanwhile is moved as it is now.
	var m UserSettingsMove
	_, m.Err = Mutate(path, nil, func(f *File) error {
		m = f.moveUser(oldname, newname)
		return nil
	})
	return m
}

// UserRename is one name that changes, Old to New.
type UserRename struct{ Old, New string }

// UserRenames is what RenameUsers did: Moves, one per rename in the order
// given, and Dropped, the names with a period that no rename covered, whose
// settings were removed.
type UserRenames struct {
	Moves   []UserSettingsMove
	Dropped []string
}

// RenameUsers carries the per-user settings of every rename in the file at
// path (the system shell, the password cache and the ignored override of
// the 'users' mapping), under its lock, in one write: the step of the
// upgrade that renames the users whose names had a period. The file is read
// without the rule on user names, since the names it holds are the ones
// being replaced; what is written follows the rule. A key with a period that
// no rename covers (a hand edit, a user who is gone) would make the file
// unreadable, and its settings belong to nobody: they are dropped, not
// renamed, so that a user who is given that name later does not inherit a
// system shell or a password cache, and the names are returned. Any other
// name the rule refuses stops the write, and nothing is written. An absent
// file is not created, and one with nothing to change is not rewritten.
func RenameUsers(path string, renames []UserRename) (UserRenames, error) {
	res := UserRenames{Moves: make([]UserSettingsMove, len(renames))}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return res, nil
		}
		return res, fail("Cannot read " + path + ": " + errText(err))
	}
	unlock, err := Lock(path)
	if err != nil {
		return res, err
	}
	defer unlock()
	data, text, res, err := renamedText(path, renames)
	if err != nil {
		return res, err
	}
	if !bytes.Equal(data, text) {
		if err := atomicWrite(path, text, 0o600); err != nil {
			return res, err
		}
	}
	return res, nil
}

// CheckRenameUsers is RenameUsers without the write: it names the keys that
// would be dropped, or says why the file cannot take the renames (it cannot
// be read, a name the rule refuses is left, the lock cannot be taken). The
// upgrade asks before it changes anything, since the store is renamed before
// this file is. An absent file can take them.
func CheckRenameUsers(path string, renames []UserRename) (dropped []string, err error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fail("Cannot read " + path + ": " + errText(err))
	}
	unlock, err := Lock(path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	_, _, res, err := renamedText(path, renames)
	return res.Dropped, err
}

// renamedText reads the file at path, applies the renames and the drops, and
// returns what was read, the text to write and what was done.
func renamedText(path string, renames []UserRename) (data, text []byte, res UserRenames, err error) {
	res.Moves = make([]UserSettingsMove, len(renames))
	data, err = os.ReadFile(path)
	if err != nil {
		return nil, nil, res, fail("Cannot read " + path + ": " + errText(err))
	}
	f, err := parse(data, func(f *File) error { return f.check(func(string) bool { return true }) })
	if err != nil {
		return nil, nil, res, fail(path + ": " + strings.Join(msgs(err), " "))
	}
	for i, r := range renames {
		res.Moves[i] = f.moveUser(r.Old, r.New)
		if on, had := f.IgnoredUsers[r.Old]; had {
			delete(f.IgnoredUsers, r.Old)
			f.IgnoredUsers[r.New] = on
		}
	}
	res.Dropped = f.dropDotted()
	text, err = f.Text()
	if err != nil {
		return nil, nil, res, fail(path + ": " + strings.Join(msgs(err), " "))
	}
	return data, text, res, nil
}

// dropDotted removes every per-user key that has a period from the
// per-user mappings and returns the names, sorted.
func (f *File) dropDotted() []string {
	out := f.dottedUsers()
	for _, u := range out {
		f.DropSystemShellUser(u)
		delete(f.PasswordCacheUsers, u)
		delete(f.IgnoredUsers, u)
		f.dropFileTransferOf(u)
	}
	return out
}

// dottedUsers are the names with a period in the per-user mappings,
// sorted.
func (f *File) dottedUsers() []string {
	seen := map[string]bool{}
	for u := range f.SystemShellUsers {
		seen[u] = true
	}
	for u := range f.PasswordCacheUsers {
		seen[u] = true
	}
	for u := range f.IgnoredUsers {
		seen[u] = true
	}
	for u := range f.FileTransferUsers {
		seen[u] = true
	}
	for u := range f.FileTransferQuotaUsers {
		seen[u] = true
	}
	for u := range f.FileTransferRateUsers {
		seen[u] = true
	}
	var out []string
	for u := range seen {
		if strings.Contains(u, ".") {
			out = append(out, u)
		}
	}
	slices.Sort(out)
	return out
}

// DroppedSetting is one per-user setting that DropDottedUserKeys removed:
// the user's name with a period and what the key held.
type DroppedSetting struct{ User, What string }

// DropDottedUserKeys reads the console.yaml at path, which may hold per-user
// keys with a period in the name (a snapshot of 0.2.25 or earlier, from the
// releases that allowed one in a user name), and returns the text a live file
// can hold: every such key of the system shell, the password cache and the
// ignored 'users' mapping removed, each other setting kept. Load refuses a
// name with a period, so a file that kept one would make the console's policy
// unreadable, which holds every user below the superuser at the password
// change until the upgrade renames the user; the dropped keys are returned in
// the order of the names so that the caller can say them. A file with none is
// returned as it is, byte for byte. A name the rule refuses that has no
// period is an error, as is a file that cannot be read.
func DropDottedUserKeys(path string) (text []byte, dropped []DroppedSetting, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fail("Cannot read " + path + ": " + errText(err))
	}
	f, err := parse(data, func(f *File) error { return f.check(func(string) bool { return true }) })
	if err != nil {
		return nil, nil, fail(path + ": " + strings.Join(msgs(err), " "))
	}
	for _, u := range f.dottedUsers() {
		if on, ok := f.SystemShellUsers[u]; ok {
			what := "disable"
			if on {
				what = "enable:" + string(f.SystemShellUserTiers[u])
			}
			dropped = append(dropped, DroppedSetting{u, "system shell " + what})
		}
		if f.PasswordCacheUsers[u] {
			dropped = append(dropped, DroppedSetting{u, "password cache on"})
		}
		if on, ok := f.IgnoredUsers[u]; ok {
			dropped = append(dropped, DroppedSetting{u, "'users' override " + word(on)})
		}
		if what := f.fileTransferOf(u); what != "" {
			dropped = append(dropped, DroppedSetting{u, "file transfer " + what})
		}
	}
	if len(dropped) == 0 {
		return data, nil, nil
	}
	f.dropDotted()
	text, err = f.Text()
	if err != nil {
		return nil, nil, fail(path + ": " + strings.Join(msgs(err), " "))
	}
	return text, dropped, nil
}
