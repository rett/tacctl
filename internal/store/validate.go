package store

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/yamlpy"
)

var sprintf = fmt.Sprintf

type fieldType int

const (
	tInt fieldType = iota
	tBool
	tString
	tStringList
	tEnumList
	tVendorMap
	tCIDRList
	tSecret
	tBcryptHex
	tDate
)

type fieldSpec struct {
	name     string
	typ      fieldType
	min, max int
	pattern  func(string) bool
	values   []string
	minItems int
	required bool
	nullable bool
}

type sectionSpec struct {
	key    string
	label  string
	name   func(string) bool
	fields []fieldSpec
}

// schema is STORE_SCHEMA, in its order.
var schema = []sectionSpec{
	{key: "groups", label: "group", name: names.MatchGroup, fields: []fieldSpec{
		{name: "priv_lvl", typ: tInt, min: 0, max: 15, required: true},
		{name: "juniper_class", typ: tString, pattern: names.MatchClass, required: true},
		{name: "builtin", typ: tBool},
	}},
	{key: "users", label: "user", name: names.MatchUser, fields: []fieldSpec{
		{name: "group", typ: tString, required: true},
		{name: "scopes", typ: tStringList, required: true},
		{name: "hash", typ: tBcryptHex, nullable: true, required: true},
		{name: "disabled", typ: tBool, required: true},
		{name: "password_changed", typ: tDate, nullable: true},
		{name: "accounting_sink", typ: tBool},
	}},
	{key: "scopes", label: "scope", name: names.MatchScope, fields: []fieldSpec{
		{name: "prefixes", typ: tCIDRList, minItems: 1, required: true},
		{name: "secret", typ: tSecret, required: true},
		{name: "protocols", typ: tEnumList, values: names.KnownProtocols, minItems: 1, nullable: true},
		{name: "vendor_attrs", typ: tEnumList, values: names.KnownVendors},
		{name: "devices", typ: tVendorMap},
	}},
}

func sectionOf(key string) *sectionSpec {
	for i := range schema {
		if schema[i].key == key {
			return &schema[i]
		}
	}
	return nil
}

// Fields returns the field names of a section ("groups", "users",
// "scopes") in schema order, and its singular label; nil for anything
// else.
func Fields(section string) (fields []string, label string) {
	sec := sectionOf(section)
	if sec == nil {
		return nil, ""
	}
	for _, f := range sec.fields {
		fields = append(fields, f.name)
	}
	return fields, sec.label
}

// isInt is is_int: an integer that is not a bool.
func isInt(v any) (int, bool) {
	i, ok := v.(int)
	return i, ok
}

var reDate = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`)
var reLowerHex = regexp.MustCompile(`^[0-9a-f]+$`)

// BcryptHexOK is bcrypt_hex_ok: a lower-case hex string that decodes to
// ASCII beginning with '$2a$', '$2b$' or '$2y$'.
func BcryptHexOK(v any) bool {
	h, ok := v.(string)
	if !ok || len(h)%2 != 0 || !reLowerHex.MatchString(h) {
		return false
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return false
	}
	for _, b := range raw {
		if b >= 0x80 {
			return false
		}
	}
	return len(raw) >= 4 && raw[0] == '$' && raw[1] == '2' &&
		(raw[2] == 'a' || raw[2] == 'b' || raw[2] == 'y') && raw[3] == '$'
}

// NormalizeHash is normalize_hash: a raw '$2b$...' hash or hex of either
// case becomes canonical (lower-case) hex; anything else is false. The
// value is stripped first.
func NormalizeHash(v string) (string, bool) {
	return hash.Normalize(pyStrip(v))
}

func hasDuplicates(items []any) bool {
	for i := range items {
		for j := 0; j < i; j++ {
			if yamlpy.Equal(items[i], items[j]) {
				return true
			}
		}
	}
	return false
}

// checkField is _check_field: a problem description for one value, or "".
// It never echoes the value of a 'secret' or 'bcrypt_hex' field.
func checkField(spec fieldSpec, val any) string {
	if val == nil {
		if spec.nullable {
			return ""
		}
		return "must not be null"
	}
	switch spec.typ {
	case tInt:
		i, ok := isInt(val)
		if !ok {
			return "must be an integer"
		}
		if i < spec.min || i > spec.max {
			return sprintf("must be %d-%d", spec.min, spec.max)
		}
	case tBool:
		if _, ok := val.(bool); !ok {
			return "must be true or false"
		}
	case tString:
		s, ok := val.(string)
		if !ok || s == "" {
			return "must be a non-empty string"
		}
		if spec.pattern != nil && !spec.pattern(s) {
			return "contains characters that are not allowed"
		}
	case tStringList:
		items, ok := val.([]any)
		if !ok {
			return "must be a list of names"
		}
		for _, x := range items {
			if s, ok := x.(string); !ok || s == "" {
				return "must be a list of names"
			}
		}
		if hasDuplicates(items) {
			return "lists the same name twice"
		}
	case tEnumList:
		items, ok := val.([]any)
		bad := !ok
		for _, x := range items {
			if !isIn(spec.values, x) {
				bad = true
			}
		}
		if bad {
			return "must be a list drawn from: " + strings.Join(spec.values, ", ")
		}
		if hasDuplicates(items) {
			return "lists the same value twice"
		}
		if len(items) < spec.minItems {
			return "must not be empty (omit it to mean every enabled backend)"
		}
	case tVendorMap:
		m, ok := val.(*yamlpy.Map)
		if !ok {
			return "must be a mapping of CIDR to vendor"
		}
		for c, vendor := range m.All() {
			canon, ok := CanonicalCIDR(c)
			if !ok {
				return sprintf("has an invalid CIDR (%s)", PyRepr(c))
			}
			if canon != c {
				return sprintf("has a non-canonical CIDR (%s, canonical form %s)", PyRepr(c), canon)
			}
			if !isIn(knownVendors, vendor) {
				return sprintf("%s: vendor must be one of: %s", c, strings.Join(knownVendors, ", "))
			}
		}
	case tCIDRList:
		items, ok := val.([]any)
		if !ok {
			return "must be a list of CIDRs"
		}
		for _, c := range items {
			canon, ok := CanonicalCIDR(c)
			if !ok {
				return sprintf("contains an invalid CIDR (%s)", PyRepr(c))
			}
			if canon != c {
				return sprintf("contains a non-canonical CIDR (%s, canonical form %s)", PyRepr(c), canon)
			}
		}
		if hasDuplicates(items) {
			return "lists the same CIDR twice"
		}
		if len(items) < spec.minItems {
			return "must list at least one CIDR"
		}
	case tSecret:
		s, ok := val.(string)
		if !ok || s == "" {
			return "must be a non-empty string"
		}
		for _, r := range s {
			if r < 0x20 || r == 0x7f {
				return "contains control characters"
			}
		}
	case tBcryptHex:
		if s, ok := val.(string); ok && strings.ToLower(s) == hash.DisabledMarkerHex {
			return "is the disabled marker (store the real hash or null, and set disabled: true)"
		}
		if !BcryptHexOK(val) {
			return "is not a hex-encoded bcrypt hash"
		}
	case tDate:
		s, ok := val.(string)
		if !ok || !reDate.MatchString(s) {
			return "must be a YYYY-MM-DD date"
		}
		if !realDate(s) {
			return "is not a real calendar date"
		}
	}
	return ""
}

// realDate is datetime.date.fromisoformat on a string already known to be
// NNNN-NN-NN.
func realDate(s string) bool {
	y, _ := strconv.Atoi(s[0:4])
	m, _ := strconv.Atoi(s[5:7])
	d, _ := strconv.Atoi(s[8:10])
	if y < 1 || m < 1 || m > 12 || d < 1 {
		return false
	}
	t := time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC)
	return t.Day() == d && int(t.Month()) == m
}

func mapOf(v any) (*yamlpy.Map, bool) {
	m, ok := v.(*yamlpy.Map)
	return m, ok && m != nil
}

func get(m *yamlpy.Map, key string) any {
	v, _ := m.Get(key)
	return v
}

// Validate is store_validate: every problem with a store document (raw
// from LoadRaw, or normalised), one message each, in 0.1.16's order
// and wording. An empty result means valid.
func Validate(store any) []string {
	root, ok := mapOf(store)
	if !ok {
		return []string{"store is not a YAML mapping"}
	}
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, sprintf(format, args...)) }
	for _, k := range root.Keys() {
		if !inList(TopKeys, k) {
			add("unknown top-level key '%s'", k)
		}
	}
	if v, ok := isInt(get(root, "version")); !ok || v != Version {
		add("version must be %d", Version)
	}

	sections := map[string]*yamlpy.Map{}
	for _, sec := range schema {
		body := get(root, sec.key)
		if body == nil {
			body = yamlpy.NewMap()
		}
		m, ok := mapOf(body)
		if !ok {
			add("'%s' must be a mapping keyed by name", sec.key)
			m = yamlpy.NewMap()
		}
		sections[sec.key] = m
		for name, ent := range m.All() {
			if !sec.name(name) {
				add("%s %s: invalid name", sec.label, PyRepr(name))
				continue
			}
			e, ok := mapOf(ent)
			if !ok {
				add("%s '%s': must be a mapping", sec.label, name)
				continue
			}
			for _, f := range e.Keys() {
				if !sec.hasField(f) {
					add("%s '%s': unknown field '%s'", sec.label, name, f)
				}
			}
			for _, f := range sec.fields {
				v, present := e.Get(f.name)
				if !present {
					if f.required {
						add("%s '%s': missing '%s'", sec.label, name, f.name)
					}
					continue
				}
				if p := checkField(f, v); p != "" {
					add("%s '%s': %s %s", sec.label, name, f.name, p)
				}
			}
		}
	}
	groups, users, scopes := sections["groups"], sections["users"], sections["scopes"]

	for _, b := range BuiltinGroups {
		g, ok := mapOf(get(groups, b.Name))
		switch {
		case !ok:
			add("built-in group '%s' is missing", b.Name)
		case get(g, "builtin") != true:
			add("group '%s': built-in group must carry builtin: true", b.Name)
		}
	}
	for name, g := range groups.All() {
		if m, ok := mapOf(g); ok && get(m, "builtin") == true && !IsBuiltinGroup(name) {
			add("group '%s': builtin: true is reserved for the built-in groups", name)
		}
	}

	for name, uv := range users.All() {
		u, ok := mapOf(uv)
		if !ok {
			continue
		}
		if inList(reservedUsers, name) {
			add("user '%s': reserved name (matches the service user)", name)
		}
		if grp, ok := get(u, "group").(string); ok && grp != "" && !groups.Has(grp) {
			add("user '%s': group '%s' does not exist", name, grp)
		}
		if list, ok := get(u, "scopes").([]any); ok {
			for _, s := range list {
				if s, ok := s.(string); ok && s != "" && !scopes.Has(s) {
					add("user '%s': scope '%s' does not exist", name, s)
				}
			}
		}
		sink := get(u, "accounting_sink") == true
		if inList(sinkUsers, name) && !sink {
			add("user '%s': reserved name, allowed only as the accounting sink (accounting_sink: true)", name)
		}
		if sink {
			if !inList(sinkUsers, name) {
				add("user '%s': accounting_sink is reserved for: %s", name, strings.Join(sinkUsers, ", "))
			}
			if get(u, "hash") != nil {
				add("user '%s': the accounting sink must not carry a password hash", name)
			}
			if get(u, "disabled") != true {
				add("user '%s': the accounting sink must stay disabled", name)
			}
		}
	}

	// One prefix, one scope (only the identical network is exclusive).
	owner := map[string]string{}
	for name, sv := range scopes.All() {
		s, ok := mapOf(sv)
		if !ok {
			continue
		}
		list, ok := get(s, "prefixes").([]any)
		if !ok {
			continue
		}
		for _, c := range list {
			canon, ok := CanonicalCIDR(c)
			if !ok {
				continue
			}
			if o, seen := owner[canon]; seen && o != name {
				add("prefix %s is claimed by scopes '%s' and '%s' (one scope per prefix)", canon, o, name)
			}
			if _, seen := owner[canon]; !seen {
				owner[canon] = name
			}
		}
	}

	for _, p := range DeviceProblems(deviceScopes(scopes)) {
		errs = append(errs, p.Msg)
	}

	if fv := get(root, "filters"); fv != nil {
		f, ok := mapOf(fv)
		if !ok {
			add("'filters' must be a mapping with allow and deny")
		} else {
			for k, v := range f.All() {
				if !inList(FilterKeys, k) {
					add("filters: unknown key '%s'", k)
					continue
				}
				if v == nil {
					v = []any{}
				}
				if p := checkField(fieldSpec{typ: tCIDRList}, v); p != "" {
					add("filters.%s %s", k, p)
				}
			}
		}
	}
	return errs
}

func (sec *sectionSpec) hasField(f string) bool {
	for _, x := range sec.fields {
		if x.name == f {
			return true
		}
	}
	return false
}

// deviceScopes is the input of DeviceProblems from a scopes section.
func deviceScopes(scopes *yamlpy.Map) []DeviceScope {
	var out []DeviceScope
	for name, sv := range scopes.All() {
		ds := DeviceScope{Name: name}
		if s, ok := mapOf(sv); ok {
			if list, ok := get(s, "prefixes").([]any); ok {
				ds.Prefixes = list
			}
			if d, ok := mapOf(get(s, "devices")); ok {
				ds.Devices = d.Keys()
			}
		}
		out = append(out, ds)
	}
	return out
}
