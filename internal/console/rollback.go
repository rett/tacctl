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
// stay: they are 0.2.3's.

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

// RollbackPlan is what writing the file for 0.2.3 changes.
type RollbackPlan struct {
	// Exists: the file is there.
	Exists bool
	// Remove are the keys of Keys023 the file has, with a word on what
	// each holds.
	Remove []string
	// Text is the file as 0.2.3 reads it; nil when nothing changes.
	Text []byte
}

// PlanRollback reads the file at path and says what writing it for 0.2.3
// changes. A file this release cannot read is an error, so the rollback
// refuses before it changes anything. A missing file, and one without the
// key, change nothing (it is not rewritten: 0.2.3 reads it as it is).
func PlanRollback(path string) (RollbackPlan, error) {
	var p RollbackPlan
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
				if _, has := m.Get("password_cache"); has {
					p.Remove = append(p.Remove, "settings.password_cache: "+cacheWord(f))
				}
			}
		}
	}
	if len(p.Remove) == 0 {
		return p, nil
	}
	text, err := f.Text023()
	if err != nil {
		return p, err
	}
	p.Text = text
	return p, nil
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
// so the cache is off for every tier, which is what 0.2.3 has). Everything
// else is written as the current tacctl writes it (0.2.4 writes 0.2.3's
// form of every other setting), and read back with the reader the file is
// read with.
func (f *File) Text023() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	doc := f.doc()
	if settings, ok := doc.Get("settings"); ok {
		settings.(*yamlpy.Map).Delete("password_cache")
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
	p, err := PlanRollback(path)
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
