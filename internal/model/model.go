// Package model is tacctl's read side of the users, groups, scopes and
// filters (lib/model.sh at the 0.1.16 tag): the typed model readers use,
// the accessors (model_users, model_user <name> [field], ...), the canned
// views with their '|'-separated or key=value lines (model_user_rows,
// scope-lookup, status, ...), and the model JSON of 'store show --json'.
//
// The document a store (or, from WP1.4b, the legacy loader) yields is a
// *store.Store; FromStore builds the typed Model from it. The views take
// the model as either loader built it, so dangling references (a user in a
// scope that is gone) are reported, not hidden. No view prints a secret or
// a hash.
package model

import (
	"os"
	"sort"

	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// Group is one group.
type Group struct {
	Name         string
	PrivLvl      *int // nil when null or not an integer
	JuniperClass string
	Builtin      bool

	// privText is str() of the stored priv_lvl ("" for null), what the
	// views print even when a hand-edited store holds a non-integer.
	privText string
	// classNull: juniper_class is null (config-show says NOT FOUND).
	classNull bool
}

// User is one user. Hash is the lower-case hex bcrypt hash ("" when
// null); PasswordChanged is YYYY-MM-DD or "".
type User struct {
	Name            string
	Group           string
	Scopes          []string
	Hash            string
	Disabled        bool
	PasswordChanged string
	AccountingSink  bool
}

// IsDisabled is user_is_disabled: the user cannot authenticate (flagged,
// the accounting sink, or without a password). The renderers emit the
// disabled marker in the same cases.
func (u *User) IsDisabled() bool { return u.Disabled || u.AccountingSink || u.Hash == "" }

// Device is one tagged address of a scope.
type Device struct{ CIDR, Vendor string }

// Scope is one scope. Protocols is nil when the scope is served by every
// enabled backend; VendorAttrs and Devices are empty unless set.
type Scope struct {
	Name        string
	Prefixes    []string // stored (render) order
	Secret      string
	Protocols   []string
	VendorAttrs []string
	Devices     []Device // stored order
}

// ServedBy reports whether protocol may serve the scope ('protocols'
// absent, or naming it).
func (s *Scope) ServedBy(protocol string) bool {
	if len(s.Protocols) == 0 {
		return true
	}
	for _, p := range s.Protocols {
		if p == protocol {
			return true
		}
	}
	return false
}

// Filters are the prefix filters.
type Filters struct{ Allow, Deny []string }

// Model is the typed model. Every list is sorted by name, and a scope's
// devices by their CIDR string: 0.1.16 handed the model to its readers as
// JSON written with sort_keys=True, so every mapping they walked was in
// key order, whichever loader built it.
type Model struct {
	Groups  []*Group
	Users   []*User
	Scopes  []*Scope
	Filters Filters

	groups map[string]*Group
	users  map[string]*User
	scopes map[string]*Scope
}

// Group returns the named group, or nil.
func (m *Model) Group(name string) *Group { return m.groups[name] }

// User returns the named user, or nil.
func (m *Model) User(name string) *User { return m.users[name] }

// Scope returns the named scope, or nil.
func (m *Model) Scope(name string) *Scope { return m.scopes[name] }

// Mode is model_mode: "store" when a store file exists at storePath,
// "legacy" otherwise.
func Mode(storePath string) string {
	if st, err := os.Stat(storePath); err == nil && st.Mode().IsRegular() {
		return "store"
	}
	return "legacy"
}

// LoadStore is model_load's store branch: the store at path (store.Load,
// not validated) and its typed model. The legacy branch (no store, read
// tacquito.yaml) is model.LegacyLoad (WP1.4b).
func LoadStore(path string) (*store.Store, *Model, error) {
	s, err := store.Load(path)
	if err != nil {
		return nil, nil, err
	}
	return s, FromStore(s), nil
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return store.PyStr(v)
}

func strList(v any) []string {
	l, _ := v.([]any)
	var out []string
	for _, x := range l {
		out = append(out, str(x))
	}
	return out
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case *yamlpy.Map:
		return x.Len() > 0
	}
	return true
}

func get(m *yamlpy.Map, k string) any {
	v, _ := m.Get(k)
	return v
}

func section(doc *yamlpy.Map, key string) *yamlpy.Map {
	m, _ := get(doc, key).(*yamlpy.Map)
	if m == nil {
		return yamlpy.NewMap()
	}
	return m
}

// FromStore builds the typed model from a store document. A value of the
// wrong type (only a hand-edited store has one; every write refuses it)
// is read leniently: a scalar where a string belongs as its Python str(),
// anything else as empty.
func FromStore(s *store.Store) *Model {
	doc := sortedCopy(s.Doc()).(*yamlpy.Map)
	m := &Model{groups: map[string]*Group{}, users: map[string]*User{}, scopes: map[string]*Scope{}}
	for name, v := range section(doc, "groups").All() {
		e, _ := v.(*yamlpy.Map)
		g := &Group{Name: name}
		if e != nil {
			if p, ok := get(e, "priv_lvl").(int); ok {
				g.PrivLvl = &p
			}
			g.privText = str(get(e, "priv_lvl"))
			g.classNull = get(e, "juniper_class") == nil
			g.JuniperClass = str(get(e, "juniper_class"))
			g.Builtin = truthy(get(e, "builtin"))
		}
		m.Groups = append(m.Groups, g)
		m.groups[name] = g
	}
	for name, v := range section(doc, "users").All() {
		e, _ := v.(*yamlpy.Map)
		u := &User{Name: name}
		if e != nil {
			u.Group = str(get(e, "group"))
			u.Scopes = strList(get(e, "scopes"))
			u.Hash = str(get(e, "hash"))
			u.Disabled = truthy(get(e, "disabled"))
			u.PasswordChanged = str(get(e, "password_changed"))
			u.AccountingSink = truthy(get(e, "accounting_sink"))
		}
		m.Users = append(m.Users, u)
		m.users[name] = u
	}
	for name, v := range section(doc, "scopes").All() {
		e, _ := v.(*yamlpy.Map)
		sc := &Scope{Name: name}
		if e != nil {
			sc.Prefixes = strList(get(e, "prefixes"))
			sc.Secret = str(get(e, "secret"))
			sc.Protocols = strList(get(e, "protocols"))
			sc.VendorAttrs = strList(get(e, "vendor_attrs"))
			if d, ok := get(e, "devices").(*yamlpy.Map); ok {
				for c, vendor := range d.All() {
					sc.Devices = append(sc.Devices, Device{CIDR: c, Vendor: str(vendor)})
				}
			}
		}
		m.Scopes = append(m.Scopes, sc)
		m.scopes[name] = sc
	}
	f := section(doc, "filters")
	m.Filters = Filters{Allow: strList(get(f, "allow")), Deny: strList(get(f, "deny"))}
	return m
}

// UserNames, GroupNames and ScopeNames are the names sorted (the list
// accessors' order).
func (m *Model) UserNames() []string {
	out := make([]string, 0, len(m.Users))
	for _, u := range m.Users {
		out = append(out, u.Name)
	}
	sort.Strings(out)
	return out
}

// GroupNames returns every group name, sorted.
func (m *Model) GroupNames() []string {
	out := make([]string, 0, len(m.Groups))
	for _, g := range m.Groups {
		out = append(out, g.Name)
	}
	sort.Strings(out)
	return out
}

// ScopeNames returns every scope name, sorted.
func (m *Model) ScopeNames() []string {
	out := make([]string, 0, len(m.Scopes))
	for _, s := range m.Scopes {
		out = append(out, s.Name)
	}
	sort.Strings(out)
	return out
}
