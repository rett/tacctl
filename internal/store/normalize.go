package store

import (
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/pyyaml"
	"github.com/rett/tacctl/internal/yamlpy"
)

// fieldDefaults are the optional fields store_normalize fills in.
var fieldDefaults = map[string][]struct {
	name string
	val  any
}{
	"groups": {{"builtin", false}},
	"users":  {{"password_changed", nil}, {"accounting_sink", false}},
	"scopes": {{"protocols", nil}},
}

func cloneMap(m *yamlpy.Map) *yamlpy.Map {
	out := yamlpy.NewMap()
	for k, v := range m.All() {
		out.Set(k, v)
	}
	return out
}

// Normalize is store_normalize: a raw store (LoadRaw's value) becomes
// the model document, with every optional field present and YAML-native
// dates (yamlpy.Date) in password_changed turned into 'YYYY-MM-DD'
// strings. It fails (*Error) only when the shape is too broken to walk;
// field-level problems are Validate's. The raw value is not changed.
func Normalize(raw any) (*Store, error) {
	if raw == nil {
		raw = yamlpy.NewMap()
	}
	rm, ok := mapOf(raw)
	if !ok {
		return nil, &Error{Msg: "store is not a YAML mapping"}
	}
	version, present := rm.Get("version")
	if !present {
		version = Version
	}
	filters := yamlpy.NewMap("allow", []any{}, "deny", []any{})
	doc := yamlpy.NewMap(
		"version", version,
		"groups", yamlpy.NewMap(),
		"users", yamlpy.NewMap(),
		"scopes", yamlpy.NewMap(),
		"filters", filters,
	)
	for k, v := range rm.All() {
		if !inList(TopKeys, k) {
			doc.Set(k, v) // kept so Validate reports it
		}
	}
	for _, sec := range schema {
		body := get(rm, sec.key)
		if body == nil {
			continue
		}
		bm, ok := mapOf(body)
		if !ok {
			return nil, storeErr("'%s' must be a mapping keyed by name", sec.key)
		}
		out := get(doc, sec.key).(*yamlpy.Map)
		for name, ent := range bm.All() {
			em, ok := mapOf(ent)
			if !ok {
				return nil, storeErr("%s %s: must be a mapping", sec.label, PyRepr(name))
			}
			e := cloneMap(em)
			for _, d := range fieldDefaults[sec.key] {
				if !e.Has(d.name) {
					e.Set(d.name, d.val)
				}
			}
			out.Set(name, e)
		}
	}
	for _, uv := range get(doc, "users").(*yamlpy.Map).All() {
		u := uv.(*yamlpy.Map)
		if d, ok := get(u, "password_changed").(yamlpy.Date); ok {
			u.Set("password_changed", d.String())
		}
	}
	if fv := get(rm, "filters"); fv != nil {
		fm, ok := mapOf(fv)
		if !ok {
			return nil, &Error{Msg: "'filters' must be a mapping with allow and deny"}
		}
		for k, v := range fm.All() {
			if v == nil {
				v = []any{}
			}
			filters.Set(k, v)
		}
	}
	return &Store{doc: doc}, nil
}

// Canonicalize is store_canonicalize: prefixes and filters canonical and
// sorted, hashes lower-case, user scope lists de-duplicated (order kept),
// the builtin flag derived from the name, vendor fields canonical (see
// canonicalVendorFields). Values the validator will refuse are left alone.
func (s *Store) Canonicalize() {
	for name, gv := range s.section("groups").All() {
		if g, ok := mapOf(gv); ok {
			g.Set("builtin", IsBuiltinGroup(name))
		}
	}
	for _, uv := range s.section("users").All() {
		u, ok := mapOf(uv)
		if !ok {
			continue
		}
		if h, ok := get(u, "hash").(string); ok {
			u.Set("hash", strings.ToLower(h))
		}
		if list, ok := get(u, "scopes").([]any); ok {
			var seen []any
			for _, x := range list {
				dup := false
				for _, y := range seen {
					if yamlpy.Equal(x, y) {
						dup = true
						break
					}
				}
				if !dup {
					seen = append(seen, x)
				}
			}
			if seen == nil {
				seen = []any{}
			}
			u.Set("scopes", seen)
		}
	}
	for _, sv := range s.section("scopes").All() {
		if sc, ok := mapOf(sv); ok {
			// s.get('prefixes'): a missing key becomes prefixes: None.
			sc.Set("prefixes", canonicalCIDRList(get(sc, "prefixes")))
			canonicalVendorFields(sc)
		}
	}
	f := s.section("filters")
	for _, k := range f.Keys() {
		f.Set(k, canonicalCIDRList(get(f, k)))
	}
}

// canonicalVendorFields: vendor_attrs in KNOWN_VENDORS order, each once;
// devices keyed by canonical CIDR in render order (the first of two keys
// with the same canonical form wins). Both are dropped when empty or null.
func canonicalVendorFields(scope *yamlpy.Map) {
	attrs, hasAttrs := scope.Get("vendor_attrs")
	if list, ok := attrs.([]any); ok {
		all := true
		for _, v := range list {
			if !isIn(knownVendors, v) {
				all = false
			}
		}
		if all {
			out := []any{}
			for _, v := range knownVendors {
				for _, x := range list {
					if x == v {
						out = append(out, v)
						break
					}
				}
			}
			scope.Set("vendor_attrs", out)
		}
	}
	if hasAttrs && (attrs == nil || isEmptyList(attrs)) {
		scope.Delete("vendor_attrs")
	}
	devices, hasDevices := scope.Get("devices")
	if dm, ok := mapOf(devices); ok {
		all := true
		for _, c := range dm.Keys() {
			if _, ok := CanonicalCIDR(c); !ok {
				all = false
			}
		}
		if all {
			canon := yamlpy.NewMap()
			for c, vendor := range dm.All() {
				cc, _ := CanonicalCIDR(c)
				if !canon.Has(cc) {
					canon.Set(cc, vendor)
				}
			}
			keys := canon.Keys()
			sort.SliceStable(keys, func(i, j int) bool { return cidrKeyOf(keys[i]).Less(cidrKeyOf(keys[j])) })
			out := yamlpy.NewMap()
			for _, k := range keys {
				out.Set(k, get(canon, k))
			}
			scope.Set("devices", out)
		}
	}
	if hasDevices && (devices == nil || isEmptyMap(devices)) {
		scope.Delete("devices")
	}
}

func isEmptyList(v any) bool {
	l, ok := v.([]any)
	return ok && len(l) == 0
}

func isEmptyMap(v any) bool {
	m, ok := v.(*yamlpy.Map)
	return ok && m.Len() == 0
}

// truthy is Python's bool() of a decoded value.
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

func listCopy(v any) []any {
	l, _ := v.([]any)
	return append([]any{}, l...)
}

// DiskForm is store_disk_form: the document written to store.yaml, names
// sorted, fields in a fixed order, optional fields left out when unset.
// It expects a store that validates (Write calls it only then).
func (s *Store) DiskForm() *yamlpy.Map {
	f := s.section("filters")
	out := yamlpy.NewMap(
		"version", Version,
		"groups", yamlpy.NewMap(),
		"users", yamlpy.NewMap(),
		"scopes", yamlpy.NewMap(),
		"filters", yamlpy.NewMap("allow", listCopy(get(f, "allow")), "deny", listCopy(get(f, "deny"))),
	)
	groups := s.section("groups")
	for _, name := range sortedKeys(groups) {
		g, _ := mapOf(get(groups, name))
		ent := yamlpy.NewMap("priv_lvl", get(g, "priv_lvl"), "juniper_class", get(g, "juniper_class"))
		if truthy(get(g, "builtin")) {
			ent.Set("builtin", true)
		}
		get(out, "groups").(*yamlpy.Map).Set(name, ent)
	}
	users := s.section("users")
	for _, name := range sortedKeys(users) {
		u, _ := mapOf(get(users, name))
		ent := yamlpy.NewMap("group", get(u, "group"), "scopes", listCopy(get(u, "scopes")),
			"hash", get(u, "hash"), "disabled", get(u, "disabled"))
		if pc := get(u, "password_changed"); truthy(pc) {
			ent.Set("password_changed", pc)
		}
		if truthy(get(u, "accounting_sink")) {
			ent.Set("accounting_sink", true)
		}
		get(out, "users").(*yamlpy.Map).Set(name, ent)
	}
	scopes := s.section("scopes")
	for _, name := range sortedKeys(scopes) {
		sc, _ := mapOf(get(scopes, name))
		ent := yamlpy.NewMap("prefixes", listCopy(get(sc, "prefixes")), "secret", get(sc, "secret"))
		if p := get(sc, "protocols"); truthy(p) {
			ent.Set("protocols", listCopy(p))
		}
		if v := get(sc, "vendor_attrs"); truthy(v) {
			ent.Set("vendor_attrs", listCopy(v))
		}
		if d := get(sc, "devices"); truthy(d) {
			if dm, ok := mapOf(d); ok {
				ent.Set("devices", cloneMap(dm))
			}
		}
		get(out, "scopes").(*yamlpy.Map).Set(name, ent)
	}
	return out
}

func sortedKeys(m *yamlpy.Map) []string {
	keys := m.Keys()
	sort.Strings(keys)
	return keys
}

// Text is store_dump_text: Header followed by the disk form as PyYAML's
// safe_dump(sort_keys=False, default_flow_style=None, width=4096) writes
// it, checked by reading it back with the store's reader (yamlpy.EmitChecked
// with pyyaml.LoadBytes). It expects a store that validates.
func (s *Store) Text() ([]byte, error) {
	return yamlpy.EmitChecked(s.DiskForm(), yamlpy.StoreOptions, Header, pyyaml.LoadBytes)
}
