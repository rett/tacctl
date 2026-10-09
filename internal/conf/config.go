package conf

import (
	"io"
	"math/big"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/ui"
	"github.com/rett/tacctl/internal/yamlpy"
)

// DefaultBackends is the backend registry of tacctl 0.1.16 (BACKEND_IDS,
// in registration order), for callers that have no registry yet.
var DefaultBackends = []string{"tacacs", "radius"}

// Config is tacctl.yaml as one invocation sees it: the overrides read
// from the file and the merged view (defaults deep-merged with the
// overrides: scalars and lists replace, mappings merge), what lib/conf.sh
// keeps in _TACCTL_CFG_CACHE. Writes go to the file and reload the view.
type Config struct {
	// Path is the overrides file (paths.Paths.Overrides).
	Path string
	// Schema validates writes and the file scan.
	Schema *Schema
	// Owner is who tacctl.yaml belongs to after a write, as the
	// best-effort 'chown tacquito:tacquito' of 0.1.16; ok false skips the
	// chown. The default looks up the tacquito user and group.
	Owner func() (uid, gid int, ok bool)

	overrides *yamlpy.Map
	problem   string
	missing   bool
	merged    *yamlpy.Map
	warned    bool
}

// Load reads path; backends is the registry (the values backends.enabled
// accepts). A file that cannot be used is not an error here: the view is
// the defaults and Problem says why (see Warning).
func Load(path string, backends []string) *Config {
	c := &Config{Path: path, Schema: NewSchema(backends), Owner: tacquitoOwner}
	c.Reload()
	return c
}

// Reload reads the file again (the cache invalidation of lib/conf.sh).
func (c *Config) Reload() {
	c.overrides, c.problem = ReadOverrides(c.Path)
	_, err := os.Stat(c.Path)
	c.missing = c.Path != "" && err != nil
	c.merged = merge(Defaults(), c.overrides)
}

// tacquitoOwner looks up tacquito:tacquito.
func tacquitoOwner() (int, int, bool) {
	u, err := user.Lookup("tacquito")
	if err != nil {
		return 0, 0, false
	}
	g, err := user.LookupGroup("tacquito")
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(g.Gid)
	return uid, gid, err1 == nil && err2 == nil
}

// merge is lib/conf.sh's merge(a, b): a copy of a with b's keys on top,
// mappings merged recursively. Neither argument is modified.
func merge(a, b *yamlpy.Map) *yamlpy.Map {
	out := yamlpy.NewMap()
	for k, v := range a.All() {
		out.Set(k, v)
	}
	for k, v := range b.All() {
		bm, bIsMap := v.(*yamlpy.Map)
		cur, _ := out.Get(k)
		am, aIsMap := cur.(*yamlpy.Map)
		if bIsMap && aIsMap {
			out.Set(k, merge(am, bm))
		} else {
			out.Set(k, v)
		}
	}
	return out
}

// Problem is why the overrides file could not be used ("" when it could).
func (c *Config) Problem() string { return c.problem }

// Missing is whether there is no overrides file (tacctl removes it when
// the last override goes, so it is also the state of an install that never
// set one).
func (c *Config) Missing() bool { return c.missing }

// Overrides is the operator's mapping as read (empty when there is no
// file or it cannot be used). Callers must not modify it.
func (c *Config) Overrides() *yamlpy.Map { return c.overrides }

// Merged is the view readers see. Callers must not modify it.
func (c *Config) Merged() *yamlpy.Map { return c.merged }

// Warning is the text readers warn with when the file cannot be used,
// "" when it can.
func (c *Config) Warning() string {
	if c.problem == "" {
		return ""
	}
	return "tacctl.yaml: could not parse " + c.Path + ": " + c.problem +
		"; using the defaults (fix the file; 'tacctl config validate' checks it)."
}

// WarnOnce writes the warning to w (stderr) as lib/conf.sh does, once per
// Config: "[WARN] <Warning>" through warn(), whose 'echo -e' interprets
// backslash escapes. Nothing is written when the file can be used.
func (c *Config) WarnOnce(w io.Writer) {
	if c.problem == "" || c.warned {
		return
	}
	c.warned = true
	_, _ = io.WriteString(w, ui.Yellow+"[WARN]"+ui.NC+" "+echoE(c.Warning())+"\n")
}

// walk follows a dotted path ("" is the whole document when whole is
// true, as conf_get treats it) through mappings.
func walk(doc *yamlpy.Map, path string, whole bool) (any, bool) {
	var cur any = doc
	if path == "" && whole {
		return cur, true
	}
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(*yamlpy.Map)
		if !ok {
			return nil, false
		}
		if cur, ok = m.Get(part); !ok {
			return nil, false
		}
	}
	return cur, true
}

// Value returns the merged value at a dotted path, and whether the path
// exists (an explicit null exists and is nil).
func (c *Config) Value(path string) (any, bool) { return walk(c.merged, path, true) }

// Get is conf_get <path> [fallback]: the line conf_get prints, and false
// when it prints nothing (the value is a list or mapping). A missing path
// or a null is the fallback; a bool is true/false; numbers and strings are
// Python's str().
func (c *Config) Get(path, fallback string) (string, bool) {
	v, _ := walk(c.merged, path, true)
	switch x := v.(type) {
	case nil:
		return fallback, true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	case *yamlpy.Map:
		return "", false
	}
	if _, isList := py.List(v); isList {
		return "", false
	}
	return py.Str(v), true
}

// GetList is conf_get_list <path>: the items of a list, each as Python's
// str() (a mapping item prints as its repr); nothing for anything else.
func (c *Config) GetList(path string) []string {
	v, _ := walk(c.merged, path, true)
	items, ok := py.List(v)
	if !ok {
		return nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = py.Str(item)
	}
	return out
}

// GetKeys is conf_get_keys <path>: the keys of a mapping, in order.
func (c *Config) GetKeys(path string) []string {
	v, _ := walk(c.merged, path, true)
	if m, ok := v.(*yamlpy.Map); ok {
		return m.Keys()
	}
	return nil
}

// GetJSON is conf_get_json <path>: json.dumps of the merged value ("null"
// when missing).
func (c *Config) GetJSON(path string) (string, error) {
	v, _ := walk(c.merged, path, false)
	return py.Dumps(v)
}

// HasOverride is conf_has_override <path>: whether the file itself sets
// the path (a file that cannot be used sets nothing).
func (c *Config) HasOverride(path string) bool {
	_, ok := walk(c.overrides, path, false)
	return ok
}

// Tunables are the values lib/conf.sh resolves when it is sourced, each
// clamped to its range (a value outside it, or not a plain number, is the
// default).
type Tunables struct {
	PasswordMaxAgeDays int // password.max_age_days: >= 1, default 90
	BcryptCost         int // bcrypt.cost: 10..14, default 12
	PasswordMinLength  int // password.min_length: 8..64, default 12
	SecretMinLength    int // secret.min_length: 16..128, default 16
}

var reDigits = regexp.MustCompile(`^[0-9]+$`)

// clamp is the source-time check: the conf_get text must be digits and in
// lo..hi (hi < 0: no upper bound), else def.
func (c *Config) clamp(path string, def, lo, hi int) int {
	text, _ := c.Get(path, strconv.Itoa(def))
	if !reDigits.MatchString(text) {
		return def
	}
	n, _ := new(big.Int).SetString(text, 10)
	if n.Cmp(big.NewInt(int64(lo))) < 0 || (hi >= 0 && n.Cmp(big.NewInt(int64(hi))) > 0) || !n.IsInt64() {
		return def
	}
	return int(n.Int64())
}

// Tunables resolves the four source-time tunables from the merged view.
func (c *Config) Tunables() Tunables {
	return Tunables{
		PasswordMaxAgeDays: c.clamp("password.max_age_days", 90, 1, -1),
		BcryptCost:         c.clamp("bcrypt.cost", 12, 10, 14),
		PasswordMinLength:  c.clamp("password.min_length", 12, 8, 64),
		SecretMinLength:    c.clamp("secret.min_length", 16, 16, 128),
	}
}
