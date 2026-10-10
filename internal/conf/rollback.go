package conf

// What a rollback takes out of tacctl.yaml (docs/plans/0.2.3-plan.md D50 for
// 0.2.3's tool, docs/plans/0.2.4-plan.md D73 for 0.2.4's): the key families
// the release being left added, and any other key the older binary does not
// know. 0.2.2's 'backup restore' refuses a snapshot whose tacctl.yaml has a
// key its schema lacks, and 0.2.3's 'config validate' reports one, so the
// keys have to go before the old release is installed.
//
// The tables below are the whole knowledge: Known022 lists every key
// family the schema of 0.2.2 has, Added023 every family 0.2.3 added and
// Added024 every one 0.2.4 added. What 0.2.3 knows is Known022 and Added023
// together (Unknown023), what 0.2.4 added is Added024. A test
// (rollback_test.go) holds them to the current schema, so a key family added
// to schema.go without a decision here fails the build, and, where the 0.2.2
// and 0.2.3 tags are in the repository, to the schemas of those tags.

import (
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Family is a key of the schema (Path) or, with Prefix, every key under a
// wildcard prefix ("snmp_scope." is every key that starts with it).
type Family struct {
	Path   string
	Prefix bool
}

// Known022 are the key families the schema of tacctl 0.2.2 has, as
// internal/conf/schema.go of that tag lists them (its exact keys and its
// wildcards). A key outside Known022 and Added023 is unknown to both.
var Known022 = []Family{
	{"password.max_age_days", false},
	{"password.min_length", false},
	{"secret.min_length", false},
	{"bcrypt.cost", false},
	{"scope.default", false},
	{"host.default_method", false},
	{"linux.uid_min", false},
	{"linux.uid_max", false},
	{"mgmt_acl.names.cisco", false},
	{"mgmt_acl.names.juniper", false},
	{"mgmt_acl.permits", false},
	{"backends.enabled", false},
	{"backends.tacacs.level", false},
	{"backends.tacacs.metrics_address", false},
	{"snmp.version", false},
	{"snmp.port", false},
	{"snmp.timeout", false},
	{"snmp.v3.auth", false},
	{"snmp.v3.priv", false},
	{"privileges.", true},
	{"commands.", true},
	{"aaa.order.", true},
	{"exec_timeout.", true},
	{"tacacs_group.", true},
	{"radius_group.", true},
	{"scope_auth_method.", true},
	{"scope_mgmt_acl.names.cisco.", true},
	{"scope_mgmt_acl.names.juniper.", true},
	{"scope_mgmt_acl.permits.", true},
	{"listeners.", true},
	{"junos.", true},
	{"wti_level.", true},
	{"tier.", true},
}

// Added023 are the key families 0.2.3 added to the schema, which a 0.2.2
// binary does not know: what a rollback removes. 'tier.<group>' is not here:
// 0.2.2 has the key (and the value 'engineer'), though it derives the tier
// of a user from the priv-lvl band alone.
var Added023 = []Family{
	{"linux.engineer_sudo", false},
	{"snmp_scope.", true},
	{"breakglass_scope.", true},
}

// Added024 are the key families 0.2.4 added: 'device config pull|diff' read
// them (device.config.*). A 0.2.2 binary does not know them either (they
// are outside Known022, so Unknown022 reports them); 'tacctl rollback 0.2.3'
// removes exactly these.
var Added024 = []Family{
	{"device.config.max_concurrency", false},
	{"device.config.transport", false},
	{"device.config.timeout", false},
}

// Added024Key reports whether path is a key 0.2.4 added.
func Added024Key(path string) bool { return inFamilies(Added024, path) }

// Matches reports whether the dotted path is in the family: the key itself,
// or, for a prefix family, the family's own key (the prefix without its
// dot) or anything under it.
func (f Family) Matches(path string) bool {
	if !f.Prefix {
		return path == f.Path
	}
	return strings.HasPrefix(path, f.Path) || path == strings.TrimSuffix(f.Path, ".")
}

func inFamilies(fs []Family, path string) bool {
	return slices.ContainsFunc(fs, func(f Family) bool { return f.Matches(path) })
}

// Added023Key reports whether path is a key 0.2.3 added.
func Added023Key(path string) bool { return inFamilies(Added023, path) }

// Unknown022 reports whether a tacctl 0.2.2 binary does not know the key at
// path: a family 0.2.3 added, or a key that is in neither table (the current
// schema does not know it either). The listeners are one section, checked
// as a whole, and are the same in both releases.
func Unknown022(path string) bool {
	if path == "listeners" || strings.HasPrefix(path, "listeners.") {
		return false
	}
	return !inFamilies(Known022, path)
}

// Unknown023 reports whether a tacctl 0.2.3 binary does not know the key at
// path: a family 0.2.4 added, or a key that is in no table (the current
// schema does not know it either). The listeners are one section, checked
// as a whole, and are the same in all three releases.
func Unknown023(path string) bool {
	if path == "listeners" || strings.HasPrefix(path, "listeners.") {
		return false
	}
	return !inFamilies(Known022, path) && !inFamilies(Added023, path)
}

// RollbackKeys023 are the leaf keys of the overrides that a 0.2.3 binary
// does not know, in file order: the dotted path of each (the device.config
// keys of 0.2.4, and any key neither release knows). A mapping that holds
// nothing yields no key.
func (c *Config) RollbackKeys023() []string {
	var out []string
	walkLeaves(c.Overrides(), "", func(p string, _ any) {
		if c.unknown023(p) {
			out = append(out, p)
		}
	})
	return out
}

// unknown023 is Unknown023 with the schema's shape as well, as unknown022
// is for 0.2.2: a key the current schema does not know (a path too deep or
// too short for its family, a typo) is not known to 0.2.3 either.
func (c *Config) unknown023(path string) bool {
	if Unknown023(path) {
		return true
	}
	if path == "listeners" || strings.HasPrefix(path, "listeners.") {
		return false
	}
	_, ok := c.Schema.RuleFor(path)
	return !ok
}

// RollbackKeys022 are the leaf keys of the overrides that a 0.2.2 binary
// does not know, in file order: the dotted path of each. A mapping that
// holds nothing yields no key (0.2.2 reads it as it reads an empty one).
func (c *Config) RollbackKeys022() []string {
	var out []string
	walkLeaves(c.Overrides(), "", func(p string, _ any) {
		if c.unknown022(p) {
			out = append(out, p)
		}
	})
	return out
}

// unknown022 is Unknown022 with the schema's shape as well: a key the
// current schema does not know (a path too deep or too short for its
// family, a typo) is not known to 0.2.2 either, whatever prefix it shares
// with a family.
func (c *Config) unknown022(path string) bool {
	if Unknown022(path) {
		return true
	}
	if path == "listeners" || strings.HasPrefix(path, "listeners.") {
		return false
	}
	_, ok := c.Schema.RuleFor(path)
	return !ok
}

// UnsetMany removes the keys at paths in one write, as Unset does for one
// (the mappings they leave empty go too; the file goes when nothing is
// left). Nothing is written when none of them is there. It is Unset's
// locking, parse check, atomic replace and ownership.
func (c *Config) UnsetMany(paths []string) error {
	dir := filepath.Dir(c.Path)
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
	defer c.chown()

	changed := false
	for _, p := range paths {
		if getNested(overrides, p) != nil || hasLeaf(overrides, p) {
			changed = true
		}
		unsetNested(overrides, p)
	}
	if !changed {
		return nil
	}
	if overrides.Len() == 0 {
		if err := os.Remove(c.Path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return syncDir(dir)
	}
	data, err := yamlpy.EmitChecked(overrides, yamlpy.ConfOptions, Header, pyyaml.LoadBytes)
	if err != nil {
		return err
	}
	return c.replace(dir, data)
}

// hasLeaf is whether the dotted path names a key, whatever its value (a key
// set to null reads as missing through getNested).
func hasLeaf(d *yamlpy.Map, path string) bool {
	cur := d
	parts := strings.Split(path, ".")
	for i, p := range parts {
		v, ok := cur.Get(p)
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			return true
		}
		next, isMap := v.(*yamlpy.Map)
		if !isMap {
			return false
		}
		cur = next
	}
	return false
}
