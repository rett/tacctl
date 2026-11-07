package console

// The settings of one user in console.yaml follow the user when the name
// changes: 'user rename' and the upgrade's rename of a user whose name had a
// period (0.2.20 and 0.2.21 allowed one) carry them here.

// UserSettingsMove is what a move did to a user's own settings in the file:
// the system shell (settings.system_shell_users: ShellHad, with value
// ShellOn) and the password cache (settings.password_cache_users: CacheHad,
// always on). Err says the file could not be read or written.
type UserSettingsMove struct {
	ShellHad, ShellOn, CacheHad bool
	Err                         error
}

// Had reports whether the user had any of them.
func (m UserSettingsMove) Had() bool { return m.ShellHad || m.CacheHad }

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
	if _, shell := f.SystemShellUsers[oldname]; !shell && !f.PasswordCacheUsers[oldname] {
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
