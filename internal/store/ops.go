package store

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The typed mutations of lib/store.sh (op_*). Each takes the arguments the
// bash wrapper took ('<field>=<value>' strings after the name), changes
// the store in place and returns an *Error with 0.1.16's message when it
// refuses. Nothing is validated here beyond what the op itself checks;
// Write (through Mutate) canonicalises and validates the result.

type kvPair struct{ k, v string }

// kv is _kv: '<field>=<value>' arguments as an ordered dict (a repeated
// field keeps its first position and takes its last value).
func kv(args []string) ([]kvPair, error) {
	var out []kvPair
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok {
			return nil, storeErr("expected <field>=<value>, got %s", PyRepr(a))
		}
		found := false
		for i := range out {
			if out[i].k == k {
				out[i].v = v
				found = true
			}
		}
		if !found {
			out = append(out, kvPair{k, v})
		}
	}
	return out, nil
}

func hasKey(fields []kvPair, k string) bool {
	for _, f := range fields {
		if f.k == k {
			return true
		}
	}
	return false
}

// csv is _csv: comma-separated, each item stripped, empty items dropped.
func csv(value string) []any {
	out := []any{}
	for _, x := range strings.Split(value, ",") {
		if x = pyStrip(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func boolArg(field, value string) (bool, error) {
	if value != "true" && value != "false" {
		return false, storeErr("%s must be true or false", field)
	}
	return value == "true", nil
}

func isNullArg(v string) bool { return v == "" || v == "null" }

// UserSet is op_user_set (store_user_set <name> [group=<g>]
// [scopes=<a,b>] [hash=<hex|$2b$..|null>] [disabled=true|false]
// [password_changed=<YYYY-MM-DD|today|null>]). group= is required for a
// new user; a new user given hash= starts enabled unless disabled= says
// otherwise, without one it starts disabled; 'root' is always the
// accounting sink and refuses hash=.
func (s *Store) UserSet(name string, fields ...string) error {
	if name == "" {
		return &Error{Msg: "user name required"}
	}
	kvs, err := kv(fields)
	if err != nil {
		return err
	}
	users := s.section("users")
	_, exists := users.Get(name)
	isNew := !exists
	sink := inList(sinkUsers, name)
	if isNew {
		if !hasKey(kvs, "group") {
			return storeErr("user '%s': group is required when creating a user", name)
		}
		users.Set(name, yamlpy.NewMap("group", nil, "scopes", []any{}, "hash", nil, "disabled", true,
			"password_changed", nil, "accounting_sink", sink))
	}
	u, ok := mapOf(get(users, name))
	if !ok {
		return storeErr("user %s: must be a mapping", PyRepr(name))
	}
	for _, f := range kvs {
		switch f.k {
		case "group":
			u.Set("group", f.v)
		case "scopes":
			u.Set("scopes", csv(f.v))
		case "hash":
			if sink {
				return storeErr("user '%s' is the accounting sink and never carries a password", name)
			}
			if isNullArg(f.v) {
				u.Set("hash", nil)
			} else {
				h, ok := NormalizeHash(f.v)
				if !ok {
					return storeErr("user '%s': hash is not a bcrypt hash", name)
				}
				if h == hash.DisabledMarkerHex {
					return storeErr("user '%s': the disabled marker is not a password hash; use disabled=true", name)
				}
				u.Set("hash", h)
			}
			if isNew && !hasKey(kvs, "disabled") {
				u.Set("disabled", get(u, "hash") == nil)
			}
		case "disabled":
			b, err := boolArg("disabled", f.v)
			if err != nil {
				return err
			}
			u.Set("disabled", b)
		case "password_changed":
			switch {
			case isNullArg(f.v):
				u.Set("password_changed", nil)
			case f.v == "today":
				u.Set("password_changed", s.now().Format("2006-01-02"))
			default:
				u.Set("password_changed", f.v)
			}
		default:
			return storeErr("user '%s': unknown field '%s'", name, f.k)
		}
	}
	return nil
}

// UserDel is op_user_del.
func (s *Store) UserDel(name string) error {
	if name == "" {
		return &Error{Msg: "user name required"}
	}
	if !s.section("users").Delete(name) {
		return storeErr("user '%s' does not exist", name)
	}
	return nil
}

// UserRename is op_user_rename: the entry moves to the new name, and the
// accounting-sink flag follows the new name.
func (s *Store) UserRename(old, newName string) error {
	users := s.section("users")
	if !users.Has(old) {
		return storeErr("user '%s' does not exist", old)
	}
	if users.Has(newName) {
		return storeErr("user '%s' already exists", newName)
	}
	u := get(users, old)
	users.Delete(old)
	if m, ok := mapOf(u); ok {
		m.Set("accounting_sink", inList(sinkUsers, newName))
	}
	users.Set(newName, u)
	return nil
}

var reDigits = regexp.MustCompile(`^[0-9]+$`)

// GroupSet is op_group_set (store_group_set <name> [priv_lvl=<0-15>]
// [juniper_class=<class>]); both fields are required for a new group.
func (s *Store) GroupSet(name string, fields ...string) error {
	if name == "" {
		return &Error{Msg: "group name required"}
	}
	kvs, err := kv(fields)
	if err != nil {
		return err
	}
	groups := s.section("groups")
	if !groups.Has(name) {
		var missing []string
		for _, f := range []string{"priv_lvl", "juniper_class"} {
			if !hasKey(kvs, f) {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			return storeErr("group '%s': %s required when creating a group", name, strings.Join(missing, " and "))
		}
		groups.Set(name, yamlpy.NewMap("priv_lvl", nil, "juniper_class", nil, "builtin", false))
	}
	g, ok := mapOf(get(groups, name))
	if !ok {
		return storeErr("group %s: must be a mapping", PyRepr(name))
	}
	for _, f := range kvs {
		switch f.k {
		case "priv_lvl":
			if !reDigits.MatchString(f.v) {
				return storeErr("group '%s': priv_lvl must be 0-15", name)
			}
			n, err := strconv.Atoi(f.v)
			if err != nil {
				n = math.MaxInt // a huge number: the validator says 0-15
			}
			g.Set("priv_lvl", n)
		case "juniper_class":
			g.Set("juniper_class", f.v)
		default:
			return storeErr("group '%s': unknown field '%s'", name, f.k)
		}
	}
	return nil
}

// usersWhere returns the sorted names of the users for which pred holds.
func (s *Store) usersWhere(pred func(u *yamlpy.Map) bool) []string {
	users := s.section("users")
	var out []string
	for _, n := range sortedKeys(users) {
		if u, ok := mapOf(get(users, n)); ok && pred(u) {
			out = append(out, n)
		}
	}
	return out
}

// GroupDel is op_group_del: refuses a built-in group and a group users are
// assigned to.
func (s *Store) GroupDel(name string) error {
	if name == "" {
		return &Error{Msg: "group name required"}
	}
	groups := s.section("groups")
	if !groups.Has(name) {
		return storeErr("group '%s' does not exist", name)
	}
	if IsBuiltinGroup(name) {
		return storeErr("cannot remove built-in group '%s'", name)
	}
	members := s.usersWhere(func(u *yamlpy.Map) bool { return get(u, "group") == name })
	if len(members) > 0 {
		return storeErr("cannot remove group '%s': %d user(s) are assigned to it", name, len(members))
	}
	groups.Delete(name)
	return nil
}

// ScopeSet is op_scope_set (store_scope_set <name> [prefixes=<cidr,cidr>]
// [secret=<key>] [protocols=<a,b|null>] [vendor_attrs=<a,b|null>]
// [devices=<cidr>=<vendor>,...|null]). prefixes=, vendor_attrs= and
// devices= replace the whole list or mapping; prefixes= and secret= are
// required for a new scope.
func (s *Store) ScopeSet(name string, fields ...string) error {
	if name == "" {
		return &Error{Msg: "scope name required"}
	}
	kvs, err := kv(fields)
	if err != nil {
		return err
	}
	scopes := s.section("scopes")
	if !scopes.Has(name) {
		var missing []string
		for _, f := range []string{"prefixes", "secret"} {
			if !hasKey(kvs, f) {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			return storeErr("scope '%s': %s required when creating a scope", name, strings.Join(missing, " and "))
		}
		scopes.Set(name, yamlpy.NewMap("prefixes", []any{}, "secret", nil, "protocols", nil))
	}
	sc, ok := mapOf(get(scopes, name))
	if !ok {
		return storeErr("scope %s: must be a mapping", PyRepr(name))
	}
	for _, f := range kvs {
		switch f.k {
		case "prefixes":
			items := csv(f.v)
			for _, c := range items {
				if _, ok := CanonicalCIDR(c); !ok {
					return storeErr("scope '%s': invalid CIDR %s", name, PyRepr(c))
				}
			}
			sc.Set("prefixes", items)
		case "secret":
			sc.Set("secret", f.v)
		case "protocols":
			if isNullArg(f.v) {
				sc.Set("protocols", nil)
			} else {
				sc.Set("protocols", csv(f.v))
			}
		case "vendor_attrs":
			if isNullArg(f.v) {
				sc.Set("vendor_attrs", []any{})
			} else {
				sc.Set("vendor_attrs", csv(f.v))
			}
		case "devices":
			devices := yamlpy.NewMap()
			var items []any
			if !isNullArg(f.v) {
				items = csv(f.v)
			}
			for _, it := range items {
				item := it.(string)
				c, vendor, sep := strings.Cut(item, "=")
				canon, ok := CanonicalCIDR(c)
				if !sep || !ok {
					return storeErr("scope '%s': devices: invalid entry %s (expected <cidr>=<vendor>)", name, PyRepr(item))
				}
				devices.Set(canon, vendor)
			}
			sc.Set("devices", devices)
		default:
			return storeErr("scope '%s': unknown field '%s'", name, f.k)
		}
	}
	return nil
}

func scopeList(u *yamlpy.Map) []any {
	l, _ := get(u, "scopes").([]any)
	return l
}

func listHas(l []any, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// ScopeDel is op_scope_del: refuses a scope users still reference unless
// stripUsers, which removes it from their lists ('--strip-users').
func (s *Store) ScopeDel(name string, stripUsers bool) error {
	if name == "" {
		return &Error{Msg: "scope name required"}
	}
	scopes := s.section("scopes")
	if !scopes.Has(name) {
		return storeErr("scope '%s' does not exist", name)
	}
	members := s.usersWhere(func(u *yamlpy.Map) bool { return listHas(scopeList(u), name) })
	if len(members) > 0 && !stripUsers {
		return storeErr("cannot remove scope '%s': %d user(s) still reference it", name, len(members))
	}
	users := s.section("users")
	for _, n := range members {
		u, _ := mapOf(get(users, n))
		out := []any{}
		for _, x := range scopeList(u) {
			if x != name {
				out = append(out, x)
			}
		}
		u.Set("scopes", out)
	}
	scopes.Delete(name)
	return nil
}

// ScopeRename is op_scope_rename: the entry moves to the new name and
// every user's scope list is rewritten in place.
func (s *Store) ScopeRename(old, newName string) error {
	scopes := s.section("scopes")
	if !scopes.Has(old) {
		return storeErr("scope '%s' does not exist", old)
	}
	if scopes.Has(newName) {
		return storeErr("scope '%s' already exists", newName)
	}
	v := get(scopes, old)
	scopes.Delete(old)
	scopes.Set(newName, v)
	for _, uv := range s.section("users").All() {
		u, ok := mapOf(uv)
		if !ok {
			continue
		}
		out := []any{}
		for _, x := range scopeList(u) {
			if x == old {
				x = newName
			}
			out = append(out, x)
		}
		u.Set("scopes", out)
	}
	return nil
}

// FiltersSet is op_filters_set (store_filters_set allow|deny
// <cidr>[,<cidr>...]): replaces one list; an empty list clears it.
func (s *Store) FiltersSet(which, cidrs string) error {
	if !inList(FilterKeys, which) {
		return &Error{Msg: "usage: allow|deny <cidr>[,<cidr>...]"}
	}
	items := csv(cidrs)
	for _, c := range items {
		if _, ok := CanonicalCIDR(c); !ok {
			return storeErr("filters.%s: invalid CIDR %s", which, PyRepr(c))
		}
	}
	s.section("filters").Set(which, items)
	return nil
}

// SeedFresh is op_seed_fresh: the scope, then SeedUsers as its members.
func (s *Store) SeedFresh(scope, prefixes, secret string) error {
	if err := s.ScopeSet(scope, "prefixes="+prefixes, "secret="+secret); err != nil {
		return err
	}
	for _, u := range SeedUsers {
		if err := s.UserSet(u.Name, "group="+u.Group, "scopes="+scope); err != nil {
			return err
		}
	}
	return nil
}
