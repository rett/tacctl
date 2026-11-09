package console

// Writing console.yaml the way a tacctl 0.2.3 binary reads it
// (docs/plans/0.2.4-plan.md D73, 'tacctl rollback 0.2.3'). 0.2.4 added one
// key, 'settings.password_cache' (the tiers whose sessions may keep the
// user's network password, and the idle and maximum lifetimes; written only
// when one of them is not the default), and 0.2.3's parser answers
// "settings: unknown key 'password_cache'" for it (the console then falls
// back to the defaults and a console write fails). The test
// TestRollbackTextIsReadBy023 holds the key to a fixture of that parser. The
// keys 0.2.3 itself added ('tiers.engineer', 'settings.space_completion')
// stay: they are 0.2.3's. 0.2.20 added two settings that every older release
// rejects (Keys0220: settings.color, written only when it is on or off, and
// a list_max of -1, never ask); the rollback to any release takes them out
// (RollbackSince0220 for those that have the cache), as the key of
// space_completion is written only when it is off.
//
// 0.2.20 also stopped writing 'tiers' and 'users' (the console switches of a
// tier and of a user, now ignored) and keeps the ones a file has. An older
// release reads them as it always did, and a file without them as the
// console on for everyone, so the rollback leaves them.

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Keys023 are the keys of the newer file that 0.2.3 rejects, as dotted paths:
// the password cache's settings (0.2.4, docs/plans/0.2.4-plan.md D70). The
// keys 0.2.3 itself added ('tiers.engineer', 'settings.space_completion')
// are 0.2.3's own and stay; a 0.2.2 binary rejects those, which is the
// business of 'tacctl rollback 0.2.2' of the 0.2.3 release.
var Keys023 = []string{"settings.password_cache"}

// Keys0220 are the settings 0.2.20 added that every older release rejects:
// 'settings.color' (written only when it is not auto), the value -1 of
// 'settings.list_max' (never ask), which the older readers' range 1 to 1000
// refuses, 'settings.system_shell_users' (the users with a system-shell
// setting of their own, written only when there is one) and
// 'settings.password_cache_users' (the users who turned the password cache on). The rollback to any
// release removes the keys and writes the largest list_max the older readers
// accept (RollbackSince0220; the same handling as settings.space_completion,
// written only when set, for 0.2.2). The per-tier list
// settings.system_shell_tiers is an older key and stays: the user settings go,
// and an older release has the tiers' setting alone.
var Keys0220 = []string{"settings.color", "settings.list_max", "settings.system_shell_users", "settings.password_cache_users"}

// Keys0228 is the setting 0.2.28 added that every older release rejects, 0.2.27
// included ("settings: unknown key 'file_transfer'", which makes the console
// fall back to its defaults and every console write fail): 'settings.
// file_transfer', the file transfer's tiers, users, quotas and rates, written
// only when something in it is not the built-in setting. The rollback to any
// release removes it (PlanRollbackSince0228 for the releases from 0.2.20 on,
// which read everything else; the other plans take it out with the rest).
var Keys0228 = []string{"settings.file_transfer"}

// RollbackPlan is what writing the file for an older release changes.
type RollbackPlan struct {
	// Exists: the file is there.
	Exists bool
	// Remove are the keys the file has that the release rejects, with a word
	// on what each holds.
	Remove []string
	// Set are the values written in place of ones the release rejects.
	Set []string
	// Text is the file as the release reads it; nil when nothing changes.
	Text []byte

	// level says which settings the plan takes out (the rollbackLevel
	// constants).
	level rollbackLevel
}

// rollbackLevel is how far back a plan goes.
type rollbackLevel int

const (
	// levelSince0228 is the plan for a release that reads everything but the
	// settings of 0.2.28: 0.2.20 to 0.2.27.
	levelSince0228 rollbackLevel = iota
	// levelSince0220 is the plan for a release with the password cache but
	// before 0.2.20: the settings of 0.2.20 go too.
	levelSince0220
	// levelAll is the plan for 0.2.3, which also rejects the password cache.
	levelAll
)

// Summary says what writing the plan removes and sets, for the line that
// reports it ('removed settings.password_cache, settings.color').
func (p RollbackPlan) Summary() string {
	var out []string
	if len(p.Remove) > 0 {
		var keys []string
		for _, r := range p.Remove {
			k, _, _ := strings.Cut(r, ": ")
			keys = append(keys, k)
		}
		out = append(out, "removed "+strings.Join(keys, ", "))
	}
	for _, s := range p.Set {
		out = append(out, "set "+s)
	}
	return strings.Join(out, ", ")
}

// PlanRollback reads the file at path and says what writing it for 0.2.3
// changes: the password cache's settings go (0.2.3's parser rejects them),
// and so do the settings of 0.2.20 (Keys0220). A file this release cannot
// read is an error, so the rollback refuses before it changes anything. A
// missing file, and one without the keys, change nothing (it is not
// rewritten: 0.2.3 reads it as it is).
func PlanRollback(path string) (RollbackPlan, error) { return planRollback(path, levelAll) }

// PlanRollbackSince0220 is PlanRollback for a release that has the password
// cache (0.2.4 and later): only the settings of 0.2.20 go.
func PlanRollbackSince0220(path string) (RollbackPlan, error) {
	return planRollback(path, levelSince0220)
}

// PlanRollbackSince0228 is PlanRollback for a release from 0.2.20 to 0.2.27,
// which reads the settings of 0.2.20 and the password cache: only the file
// transfer settings of 0.2.28 go.
func PlanRollbackSince0228(path string) (RollbackPlan, error) {
	return planRollback(path, levelSince0228)
}

func planRollback(path string, level rollbackLevel) (RollbackPlan, error) {
	cache := level == levelAll
	old := level != levelSince0228
	p := RollbackPlan{level: level}
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return p, nil
	case err != nil:
		return p, fail("Cannot read " + path + ": " + errText(err))
	}
	p.Exists = true
	f, err := Load(path)
	if err != nil {
		return p, err
	}
	v, err := pyyaml.LoadBytes(data)
	if err != nil {
		return p, fail(path + ": not valid YAML: " + firstLine(err.Error()))
	}
	if root, ok := v.(*yamlpy.Map); ok {
		if settings, ok := root.Get("settings"); ok {
			if m, ok := settings.(*yamlpy.Map); ok {
				if _, has := m.Get("password_cache"); has && cache {
					p.Remove = append(p.Remove, "settings.password_cache: "+cacheWord(f))
				}
				if _, has := m.Get("color"); has && old {
					p.Remove = append(p.Remove, "settings.color: "+f.Color)
				}
				if _, has := m.Get("system_shell_users"); has && old {
					p.Remove = append(p.Remove, "settings.system_shell_users: "+systemShellUsersWord(f))
				}
				if _, has := m.Get("password_cache_users"); has && old {
					p.Remove = append(p.Remove, "settings.password_cache_users: "+strings.Join(f.PasswordCacheUserNames(), ", ")+" (on)")
				}
				if _, has := m.Get("file_transfer"); has {
					p.Remove = append(p.Remove, "settings.file_transfer: "+fileTransferWord(f))
				}
			}
		}
	}
	if f.ListMax == ListMaxNever && old {
		p.Set = append(p.Set, "settings.list_max to "+strconv.Itoa(MaxListMax)+" (it never asked)")
	}
	if len(p.Remove) == 0 && len(p.Set) == 0 {
		return p, nil
	}
	text, err := f.rollbackText(level)
	if err != nil {
		return p, err
	}
	p.Text = text
	return p, nil
}

// systemShellUsersWord says what the users' system-shell settings are, for
// the plan.
func systemShellUsersWord(f *File) string {
	var w []string
	for _, u := range f.SystemShellUserNames() {
		w = append(w, u+" "+word(f.SystemShellUsers[u]))
	}
	if len(w) == 0 {
		return "none"
	}
	return strings.Join(w, ", ")
}

// fileTransferWord says what the file transfer settings are, for the plan:
// the tiers that have it and how many users, quotas and rates are set.
func fileTransferWord(f *File) string {
	tiers := "none"
	if len(f.FileTransferTiers) > 0 {
		var w []string
		for _, t := range f.FileTransferTiers {
			w = append(w, string(t))
		}
		tiers = strings.Join(w, ",")
	}
	out := "tiers " + tiers
	for _, c := range []struct {
		n            int
		one, several string
	}{
		{len(f.FileTransferUsers), "user switch", "user switches"}, {len(f.FileTransferQuota) + len(f.FileTransferQuotaUsers), "quota", "quotas"},
		{len(f.FileTransferRate) + len(f.FileTransferRateUsers), "rate", "rates"},
	} {
		switch {
		case c.n == 1:
			out += ", 1 " + c.one
		case c.n > 1:
			out += ", " + strconv.Itoa(c.n) + " " + c.several
		}
	}
	return out
}

// cacheWord says what the cache's settings are, for the plan.
func cacheWord(f *File) string {
	tiers := "none"
	if len(f.PasswordCacheTiers) > 0 {
		var w []string
		for _, t := range f.PasswordCacheTiers {
			w = append(w, string(t))
		}
		tiers = strings.Join(w, ",")
	}
	return "tiers " + tiers + ", idle " + strconv.Itoa(f.PasswordCacheIdle) + " min, max " + strconv.Itoa(f.PasswordCacheMax) + " h"
}

// Text023 is the file as a tacctl 0.2.3 reads it: no
// 'settings.password_cache' (the cache's tiers and lifetimes are forgotten,
// so the cache is off for every tier, which is what 0.2.3 has), and none of
// the settings of 0.2.20 (Keys0220). Everything else is written as the
// current tacctl writes it (0.2.4 writes 0.2.3's form of every other
// setting), and read back with the reader the file is read with.
func (f *File) Text023() ([]byte, error) { return f.rollbackText(levelAll) }

// Text0219 is the file as a release with the password cache and before
// 0.2.20 reads it: the settings of 0.2.20 (Keys0220) and of 0.2.28 (Keys0228)
// are gone.
func (f *File) Text0219() ([]byte, error) { return f.rollbackText(levelSince0220) }

// Text0227 is the file as a release from 0.2.20 to 0.2.27 reads it: the file
// transfer settings of 0.2.28 (Keys0228) are gone, everything else stays.
func (f *File) Text0227() ([]byte, error) { return f.rollbackText(levelSince0228) }

func (f *File) rollbackText(level rollbackLevel) ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	doc := f.doc()
	if settings, ok := doc.Get("settings"); ok {
		m := settings.(*yamlpy.Map)
		m.Delete("file_transfer")
		if level == levelAll {
			m.Delete("password_cache")
		}
		if level != levelSince0228 {
			m.Delete("color")
			m.Delete("system_shell_users")
			m.Delete("password_cache_users")
			if f.ListMax == ListMaxNever {
				m.Set("list_max", MaxListMax)
			}
		}
	}
	out, err := yamlpy.EmitChecked(doc, yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the console settings (" + firstLine(err.Error()) + "); nothing was written")
	}
	return out, nil
}

// Rollback writes the file for 0.2.3 under the file's lock: before runs
// first (a snapshot; an error stops the write), then the file is planned
// again under the lock (it may have changed since the plan) and replaced
// through a temporary file (0600, fsync, rename). changed is false when
// nothing needed changing.
func Rollback(path string, before func() error) (changed bool, err error) {
	return rollback(path, before, levelAll)
}

// RollbackSince0220 is Rollback for a release with the password cache: only
// the settings of 0.2.20 are taken out.
func RollbackSince0220(path string, before func() error) (changed bool, err error) {
	return rollback(path, before, levelSince0220)
}

// RollbackSince0228 is Rollback for a release from 0.2.20 to 0.2.27: only the
// file transfer settings of 0.2.28 are taken out.
func RollbackSince0228(path string, before func() error) (changed bool, err error) {
	return rollback(path, before, levelSince0228)
}

func rollback(path string, before func() error, level rollbackLevel) (changed bool, err error) {
	if before != nil {
		if err := before(); err != nil {
			return false, err
		}
	}
	unlock, err := Lock(path)
	if err != nil {
		return false, err
	}
	defer unlock()
	p, err := planRollback(path, level)
	if err != nil || p.Text == nil {
		return false, err
	}
	if cur, err := os.ReadFile(path); err == nil && bytes.Equal(cur, p.Text) {
		return false, nil
	}
	if err := atomicWrite(path, p.Text, 0o600); err != nil {
		return false, err
	}
	return true, nil
}
