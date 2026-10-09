package console

// Writing console.yaml the way a tacctl 0.2.2 binary reads it
// (docs/plans/0.2.3-plan.md D50). 0.2.2's parser knows three tiers under
// 'tiers' and seven keys under 'settings'; 0.2.3 writes 'tiers.engineer' on
// every write and 'settings.space_completion' while the setting is off, and
// 0.2.2 rejects both (the console then falls back to the defaults, a console
// write fails, and the upgrade skips sshd's drop-in). The test
// TestRollbackToTheOldParser holds the two keys to a fixture of that parser.

import (
	"bytes"
	"errors"
	"io/fs"
	"os"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Keys022 are the two keys of the 0.2.3 file that 0.2.2 rejects, as dotted
// paths.
var Keys022 = []string{"tiers.engineer", "settings.space_completion"}

// RollbackPlan is what writing the file for 0.2.2 changes.
type RollbackPlan struct {
	// Exists: the file is there.
	Exists bool
	// Remove are the keys of Keys022 the file has, with their values as
	// words (enable, disable, false).
	Remove []string
	// Text is the file as 0.2.2 reads it; nil when nothing changes.
	Text []byte
}

// PlanRollback reads the file at path and says what writing it for 0.2.2
// changes. A file 0.2.3 cannot read is an error, so the rollback refuses
// before it changes anything. A missing file, and one without the two keys,
// change nothing (it is not rewritten: 0.2.2 reads it as it is).
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
		if tiers, ok := root.Get("tiers"); ok {
			if m, ok := tiers.(*yamlpy.Map); ok {
				if val, has := m.Get("engineer"); has {
					p.Remove = append(p.Remove, "tiers.engineer: "+wordOf(val))
				}
			}
		}
		if settings, ok := root.Get("settings"); ok {
			if m, ok := settings.(*yamlpy.Map); ok {
				if val, has := m.Get("space_completion"); has {
					p.Remove = append(p.Remove, "settings.space_completion: "+wordOf(val))
				}
			}
		}
	}
	if len(p.Remove) == 0 {
		return p, nil
	}
	text, err := f.Text022()
	if err != nil {
		return p, err
	}
	p.Text = text
	return p, nil
}

func wordOf(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	}
	return "?"
}

// Text022 is the file as a tacctl 0.2.2 reads it: no 'tiers.engineer' and no
// 'settings.space_completion' (the engineer tier's switch is always on in
// 0.2.3 and has no meaning in 0.2.2; the space-completion setting is
// forgotten). Everything else is written as 0.2.3 writes it, and read back
// with the reader the file is read with.
func (f *File) Text022() ([]byte, error) {
	if err := f.validate(); err != nil {
		return nil, err
	}
	doc := f.doc()
	if tiers, ok := doc.Get("tiers"); ok {
		tiers.(*yamlpy.Map).Delete("engineer")
	}
	if settings, ok := doc.Get("settings"); ok {
		settings.(*yamlpy.Map).Delete("space_completion")
	}
	out, err := yamlpy.EmitChecked(doc, yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return nil, fail("cannot write the console settings (" + firstLine(err.Error()) + "); nothing was written")
	}
	return out, nil
}

// Rollback writes the file for 0.2.2 under the file's lock: before runs
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
