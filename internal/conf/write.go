package conf

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// ParseError is the refusal to write over a tacctl.yaml that cannot be
// used (Decision 11e): read as empty, it would be replaced by a file
// holding only the key being set. Nothing is written.
type ParseError struct {
	Path string
	Why  string
}

// Error is the first line, as written (before echo -e).
func (e *ParseError) Error() string {
	return "tacctl.yaml: could not parse " + e.Path + ": " + e.Why
}

// Lines are the two lines lib/conf.sh prints with error(), after its
// 'echo -e' (ui.Output.ErrorLines prints each as "[ERROR] <line>").
func (e *ParseError) Lines() []string {
	return []string{
		echoE(e.Error()),
		echoE("Fix or remove the file ('tacctl config validate' checks it); nothing was written."),
	}
}

// ValidationError is a value the schema refuses, or a listener that would
// collide with another. lib/conf.sh prints Error() as a plain line on
// stderr (no "[ERROR] " tag) and the command fails.
type ValidationError struct {
	Path string
	Msg  string
	// Clash is a listener collision: the message names its own path.
	Clash bool
}

func (e *ValidationError) Error() string {
	if e.Clash {
		return "tacctl config: " + e.Msg
	}
	return "tacctl config: " + e.Path + ": " + e.Msg
}

// ErrBadJSON is the text a SetJSON payload that does not parse is refused
// with: ValidationError.Msg is "invalid JSON payload (<json.loads error>)".
var ErrBadJSON = errors.New("invalid JSON payload")

// The write modes of _conf_write.
const (
	modeSet     = "set"
	modeSetList = "set_list"
	modeSetJSON = "set_json"
	modeUnset   = "unset"
)

// Set is conf_set <path> <value>: value as a command line gives it,
// coerced by CoerceScalar, validated, stored (or removed when it equals
// the default).
func (c *Config) Set(path, value string) error {
	return c.write(modeSet, path, CoerceScalar(value), nil)
}

// SetList is conf_set_list <path> with items (ListItems turns conf_set_list's
// stdin into them); an empty list is the default of every list path but
// the backends.
func (c *Config) SetList(path string, items []string) error {
	list := make([]any, len(items))
	for i, s := range items {
		list[i] = s
	}
	return c.write(modeSetList, path, list, nil)
}

// SetJSON is conf_set_json <path> <json>: the payload parsed by json.loads
// ("" is null) and validated as it is; a listener is stored compacted.
func (c *Config) SetJSON(path, payload string) error {
	var v any
	if payload != "" {
		var err error
		if v, err = py.Loads(payload); err != nil {
			return c.write(modeSetJSON, path, nil, err)
		}
	}
	return c.write(modeSetJSON, path, v, nil)
}

// SetValue is SetJSON with the value already built (*yamlpy.Map, []any,
// string, int, bool, nil): what Go callers use.
func (c *Config) SetValue(path string, v any) error {
	return c.write(modeSetJSON, path, v, nil)
}

// Unset is conf_unset <path>: the key leaves the file (an unknown or
// absent key is no error), and so do the mappings it leaves empty.
func (c *Config) Unset(path string) error {
	return c.write(modeUnset, path, nil, nil)
}

// ListItems is how conf_set_list reads its stdin: one item per line
// ('\r\n' and '\r' end lines too), blank lines dropped, nothing else
// trimmed but the line end.
func ListItems(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	var out []string
	for _, line := range strings.SplitAfter(text, "\n") {
		if py.Strip(line) == "" {
			continue
		}
		out = append(out, strings.TrimRight(line, "\n"))
	}
	return out
}

// getNested is get_nested: nil when the path is missing.
func getNested(d *yamlpy.Map, path string) any {
	v, _ := walk(d, path, false)
	return v
}

// setNested is set_nested: intermediate values that are not mappings are
// replaced by empty ones.
func setNested(d *yamlpy.Map, path string, val any) {
	parts := strings.Split(path, ".")
	cur := d
	for _, p := range parts[:len(parts)-1] {
		next, ok := cur.Get(p)
		m, isMap := next.(*yamlpy.Map)
		if !ok || !isMap {
			m = yamlpy.NewMap()
			cur.Set(p, m)
		}
		cur = m
	}
	cur.Set(parts[len(parts)-1], val)
}

// unsetNested is unset_nested: delete the leaf, then every mapping along
// the path that is left empty, from the leaf up. A path that is not there
// changes nothing.
func unsetNested(d *yamlpy.Map, path string) {
	parts := strings.Split(path, ".")
	chain := []*yamlpy.Map{d}
	var cur any = d
	for _, p := range parts[:len(parts)-1] {
		m, ok := cur.(*yamlpy.Map)
		if !ok || !m.Has(p) {
			return
		}
		cur, _ = m.Get(p)
		if next, isMap := cur.(*yamlpy.Map); isMap {
			chain = append(chain, next)
		} else {
			chain = append(chain, nil)
		}
	}
	if m, ok := cur.(*yamlpy.Map); ok {
		m.Delete(parts[len(parts)-1])
	}
	for i := len(parts) - 2; i >= 0; i-- {
		parent := chain[i]
		if parent == nil {
			continue
		}
		if v, _ := parent.Get(parts[i]); v != nil {
			if m, isMap := v.(*yamlpy.Map); isMap && m.Len() == 0 {
				parent.Delete(parts[i])
			}
		}
	}
}

// defaultFor is _default_for: the defaults file's value, else the
// schema's implicit default; ok false when there is neither.
func (c *Config) defaultFor(path string) (any, bool) {
	if v := getNested(Defaults(), path); v != nil {
		return v, true
	}
	return c.Schema.ImplicitDefault(path)
}

// write is _conf_write: validate, then mutate the file's mapping and
// write it (or remove the file when nothing is left).
func (c *Config) write(mode, path string, value any, jsonErr error) error {
	dir := filepath.Dir(c.Path)
	if err := os.MkdirAll(dir, 0o777); err != nil {
		return fmt.Errorf("tacctl.yaml: cannot create %s: %w", dir, err)
	}
	unlock, err := lockDir(dir)
	if err != nil {
		return err
	}
	defer unlock()
	defer c.Reload()

	overrides, problem := ReadOverrides(c.Path)
	if problem != "" {
		return &ParseError{Path: c.Path, Why: problem}
	}
	// Past the parse check, 0.1.16 gives the file to tacquito whatever
	// the outcome.
	defer c.chown()

	switch mode {
	case modeSet, modeSetList:
		if msg := c.Schema.Validate(path, value, mode == modeSetList); msg != "" {
			return &ValidationError{Path: path, Msg: msg}
		}
	case modeSetJSON:
		if jsonErr != nil {
			return &ValidationError{Path: path, Msg: fmt.Sprintf("%s (%v)", ErrBadJSON, jsonErr)}
		}
		_, isList := py.List(value)
		if msg := c.Schema.Validate(path, value, isList); msg != "" {
			return &ValidationError{Path: path, Msg: msg}
		}
		if r, _ := c.Schema.RuleFor(path); r.Type == TypeListener {
			value = ListenerCompact(strings.Split(path, ".")[1], value)
		}
	}

	// Python compares with None when there is no default, so a null
	// value with no default unsets too.
	if mode == modeUnset {
		unsetNested(overrides, path)
	} else if def, _ := c.defaultFor(path); py.Equal(def, value) {
		unsetNested(overrides, path)
	} else {
		setNested(overrides, path, value)
	}

	if strings.HasPrefix(path, "listeners.") && mode != modeUnset {
		if clash := ListenersProblems(overrides, path, true); len(clash) > 0 {
			return &ValidationError{Path: path, Msg: clash[0], Clash: true}
		}
	}

	if overrides.Len() == 0 {
		if err := os.Remove(c.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("tacctl.yaml: cannot remove %s: %w", c.Path, err)
		}
		return syncDir(dir)
	}
	data, err := yamlpy.EmitChecked(overrides, yamlpy.ConfOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	return c.replace(dir, data)
}

// replace writes data to a temporary file in dir (0640, fsynced) and
// renames it over the file, then fsyncs the directory.
func (c *Config) replace(dir string, data []byte) error {
	tmp, err := os.CreateTemp(dir, "tmp")
	if err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	if err := os.Rename(name, c.Path); err != nil {
		return fmt.Errorf("tacctl.yaml: cannot write %s: %w", c.Path, err)
	}
	ok = true
	return syncDir(dir)
}

// chown is 0.1.16's 'chown tacquito:tacquito tacctl.yaml 2>/dev/null ||
// true': best effort, silent.
func (c *Config) chown() {
	if c.Owner == nil {
		return
	}
	uid, gid, ok := c.Owner()
	if !ok {
		return
	}
	_ = os.Chown(c.Path, uid, gid)
}

// lockDir takes an exclusive flock on the directory itself (no lock file
// appears next to tacctl.yaml), serialising writers.
func lockDir(dir string) (func(), error) {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tacctl.yaml: cannot lock %s: %w", dir, err)
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX)
		if !errors.Is(err, unix.EINTR) {
			break
		}
	}
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tacctl.yaml: cannot lock %s: %w", dir, err)
	}
	return func() {
		_ = unix.Flock(fd, unix.LOCK_UN)
		_ = unix.Close(fd)
	}, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil // the rename is done; durability is best effort
	}
	_ = d.Sync()
	return d.Close()
}
