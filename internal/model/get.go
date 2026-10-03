package model

import (
	"sort"

	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// emit is _emit: the lines print() writes for one field value (nothing for
// null, true/false, one line per list item, 'key value' per mapping pair).
func emit(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case bool:
		if x {
			return []string{"true"}
		}
		return []string{"false"}
	case []any:
		out := []string{}
		for _, it := range x {
			out = append(out, store.PyStr(it))
		}
		return out
	case *yamlpy.Map:
		out := []string{}
		for k, it := range x.All() {
			out = append(out, k+" "+store.PyStr(it))
		}
		return out
	}
	return []string{store.PyStr(v)}
}

// Get is model_get, the accessors over a store document:
//
//	Get(s, "users")                 every name, sorted (model_users)
//	Get(s, "users", name)           the entry as JSON with "name" added
//	Get(s, "users", name, field)    one field: a scalar as text (true/false,
//	                                nothing for null), a list one item per line,
//	                                devices one '<cidr> <vendor>' line each
//	Get(s, "filters")               both lists as JSON
//	Get(s, "filters", "allow")      one list, a CIDR per line
//
// (and the same for "groups" and "scopes"). A missing entry is code 1 with
// no lines; an unknown field or filter list is a *store.Error.
func Get(s *store.Store, kind string, args ...string) (lines []string, code int, err error) {
	// The accessors read the model as 0.1.16 did: through JSON written
	// with sort_keys=True, so a mapping (devices) comes out in key order.
	doc := sortedCopy(s.Doc()).(*yamlpy.Map)
	if kind == "filters" {
		f := section(doc, "filters")
		if len(args) == 0 {
			j, err := JSON(f)
			if err != nil {
				return nil, 1, err
			}
			return []string{j}, 0, nil
		}
		for _, k := range store.FilterKeys {
			if args[0] == k {
				v := get(f, k)
				if !truthy(v) {
					v = []any{}
				}
				return emit(v), 0, nil
			}
		}
		return nil, 1, &store.Error{Msg: "filters: unknown list '" + args[0] + "'"}
	}
	fields, label := store.Fields(kind)
	if fields == nil {
		return nil, 1, &store.Error{Msg: "internal: unknown section '" + kind + "'"}
	}
	sec := section(doc, kind)
	if len(args) == 0 {
		names := sec.Keys()
		sort.Strings(names)
		return names, 0, nil
	}
	name := args[0]
	ev, ok := sec.Get(name)
	if !ok || ev == nil {
		return nil, 1, nil
	}
	ent, _ := ev.(*yamlpy.Map)
	if len(args) == 1 {
		withName := yamlpy.NewMap()
		for k, v := range ent.All() {
			withName.Set(k, v)
		}
		withName.Set("name", name)
		j, err := JSON(withName)
		if err != nil {
			return nil, 1, err
		}
		return []string{j}, 0, nil
	}
	for _, f := range fields {
		if f == args[1] {
			return emit(get(ent, f)), 0, nil
		}
	}
	return nil, 1, &store.Error{Msg: label + ": unknown field '" + args[1] + "'"}
}

// Exists is model_user_exists / model_group_exists / model_scope_exists
// (the 'has' view): an empty name is never found.
func (m *Model) Exists(kind, name string) bool {
	if name == "" {
		return false
	}
	switch kind {
	case "users":
		return m.users[name] != nil
	case "groups":
		return m.groups[name] != nil
	case "scopes":
		return m.scopes[name] != nil
	}
	return false
}
