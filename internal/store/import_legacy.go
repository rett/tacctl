package store

import (
	"encoding/json"
	"errors"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The legacy tacquito.yaml loader: legacy_load and its helpers in
// lib/model.sh (_model_py) at 0.1.16. It builds the model from the value
// yaml.safe_load returns (ReadLegacyYAML), so anchor layout, section
// comments and spacing are irrelevant, and it always returns the model a
// forced import would produce, plus a report. No message contains a
// secret or a hash.

// LegacyReport is legacy_load's report.
type LegacyReport struct {
	// Dropped is content the store cannot represent (an import fails
	// unless forced).
	Dropped []string
	// Errors are problems no flag can fix (an import always fails).
	Errors []string
	// Notes are things the operator should know that lose nothing.
	Notes []string
	// Extras are the per-group device settings found in the file, which
	// live in tacctl.yaml, not in the store (0.2.2): kept only so the
	// render's read-back can check them. Keyed by group name.
	Extras map[string]*GroupExtras
}

// GroupExtras is what a group's services carried beyond the store: the
// Junos set_values by argument name (deny-commands, ...; the first
// value) and the priv-lvl of a 'wti' service (nil when it has none).
type GroupExtras struct {
	Junos map[string]string
	WTI   any
}

// junosExtraValues are the junos-exec set_values kept in Extras.
var junosExtraValues = []string{"deny-commands", "deny-configuration", "allow-commands", "allow-configuration"}

func (r *LegacyReport) extras(group string) *GroupExtras {
	if r.Extras == nil {
		r.Extras = map[string]*GroupExtras{}
	}
	if r.Extras[group] == nil {
		r.Extras[group] = &GroupExtras{Junos: map[string]string{}}
	}
	return r.Extras[group]
}

// firstValue is the first value of a set_values entry (nil for none).
func firstValue(sv *yamlpy.Map) any {
	values := orEmpty(get(sv, "values"))
	vals, ok := values.([]any)
	if values != nil && !ok {
		vals = []any{values}
	}
	if len(vals) == 0 {
		return nil
	}
	return vals[0]
}

// legacyWTI is a group's 'wti' service: its priv-lvl into Extras, and a
// note (the level is wti_level.<group> in tacctl.yaml).
func legacyWTI(name string, svc *yamlpy.Map, rep *LegacyReport) {
	rep.note("group '%s': service 'wti': the WTI level lives in tacctl.yaml (wti_level.%s); not stored", name, name)
	setValues, _ := orEmpty(get(svc, "set_values")).([]any)
	for _, x := range setValues {
		if sv, ok := mapOf(x); ok && pyStrip(pyStr(get(sv, "name"))) == "priv-lvl" {
			rep.extras(name).WTI = firstValue(sv)
			return
		}
	}
	rep.extras(name)
}

func (r *LegacyReport) drop(format string, a ...any) {
	r.Dropped = append(r.Dropped, sprintf(format, a...))
}

func (r *LegacyReport) fail(format string, a ...any) {
	r.Errors = append(r.Errors, sprintf(format, a...))
}

func (r *LegacyReport) note(format string, a ...any) {
	r.Notes = append(r.Notes, sprintf(format, a...))
}

// The type constants of a tacquito.yaml (LEGACY_CONSTANTS, LEGACY_TOP_KEYS,
// T_*).
var (
	legacyConstants = []string{"authenticator_type_bcrypt", "action_deny", "action_permit",
		"accounter_type_file", "handler_type_start", "provider_type_prefix"}
	legacyTopKeys = []string{"users", "secrets", "prefix_allow", "prefix_deny"}
)

const (
	tBcryptAuth     = 1
	tFileAccounter  = 3
	tHandlerStart   = 1
	tProviderPrefix = 1
)

var reUser = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// --- Python semantics of the values safe_load returns ------------------------

// pyIsInt is is_int: an integer, not a bool.
func pyIsInt(v any) bool {
	switch v.(type) {
	case int, bigInt:
		return true
	}
	return false
}

// pyEqInt is 'v == n' for a small integer n (True == 1, 1.0 == 1).
func pyEqInt(v any, n int) bool {
	switch x := v.(type) {
	case int:
		return x == n
	case bool:
		return (n == 1 && x) || (n == 0 && !x)
	case float64:
		return x == float64(n)
	}
	return false
}

// pyStr is str(v).
func pyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case bigInt:
		return string(x)
	case yamlpy.Date:
		return x.String()
	}
	return PyRepr(v)
}

// pyNum is a numeric value as Python compares it, or false.
func pyNum(v any) (float64, bool) {
	switch x := v.(type) {
	case int:
		return float64(x), true
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	case float64:
		return x, true
	}
	return 0, false
}

// pyEqual is Python's == on two values safe_load returned (dicts compare
// as sets of pairs, numbers across int, bool and float).
func pyEqual(a, b any) bool {
	if x, ok := a.(int); ok {
		if y, ok := b.(int); ok {
			return x == y
		}
	}
	if x, ok := pyNum(a); ok {
		y, ok := pyNum(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case bigInt:
		y, ok := b.(bigInt)
		return ok && x == y
	case yamlpy.Date:
		y, ok := b.(yamlpy.Date)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEqual(x[i], y[i]) {
				return false
			}
		}
		return true
	case *yamlpy.Map:
		y, ok := b.(*yamlpy.Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		if x == y {
			return true
		}
		for k, v := range x.All() {
			w, ok := y.Get(k)
			if !ok || !pyEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// orEmpty is 'v or []': a falsy value becomes nil (no items).
func orEmpty(v any) any {
	if !truthy(v) {
		return nil
	}
	return v
}

// keysOnly reports whether every key of m is in allowed (set(m) <= ...).
func keysOnly(m *yamlpy.Map, allowed ...string) bool {
	for _, k := range m.Keys() {
		if !inList(allowed, k) {
			return false
		}
	}
	return true
}

func fileAccounterOK(v any) bool {
	a, ok := mapOf(v)
	if !ok || !keysOnly(a, "name", "type", "options") {
		return false
	}
	name, _ := get(a, "name").(string)
	return name == "tacquito_accounter" && pyEqInt(get(a, "type"), tFileAccounter) && !truthy(get(a, "options"))
}

// sidecar is _sidecar: the stripped content of <dir>/<name>, or false when
// there is none. A file that exists but cannot be read is noted.
func sidecar(dir, name string, rep *LegacyReport) (string, bool) {
	if dir == "" {
		return "", false
	}
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
			return "", false
		}
		rep.note("%s: sidecar file not readable (%s); ignored", name, strerror(err))
		return "", false
	}
	return pyStrip(string(data)), true
}

// --- groups -------------------------------------------------------------------

// legacyGroup is _legacy_group: one inlined group mapping becomes
// {priv_lvl, juniper_class, builtin}. refs collects the mappings it
// reaches.
func legacyGroup(g *yamlpy.Map, rep *LegacyReport, refs map[*yamlpy.Map]bool) *yamlpy.Map {
	name := get(g, "name").(string)
	label := "group '" + name + "'"
	for _, k := range g.Keys() {
		if !inList([]string{"name", "services", "commands", "accounter", "authenticator"}, k) {
			rep.drop("%s: unsupported key '%s'", label, k)
		}
	}
	if auth := get(g, "authenticator"); auth != nil {
		ref(refs, auth)
		rep.drop("%s: group-level authenticator (the store keeps one per user)", label)
	}
	if acc := get(g, "accounter"); acc != nil {
		ref(refs, acc)
		if !fileAccounterOK(acc) {
			rep.drop("%s: accounter other than the file accounter", label)
		}
	}
	var priv, cls any
	services := orEmpty(get(g, "services"))
	list, ok := services.([]any)
	if services != nil && !ok {
		rep.fail("%s: services is not a list", label)
	}
	for _, sv := range list {
		svc, ok := mapOf(sv)
		if !ok {
			rep.fail("%s: a service entry is not a mapping", label)
			continue
		}
		refs[svc] = true
		sname := ""
		if v, ok := svc.Get("name"); ok {
			sname = pyStrip(pyStr(v))
		}
		var want string
		var have any
		switch sname {
		case "shell", "exec":
			want, have = "priv-lvl", priv
		case "junos-exec":
			want, have = "local-user-name", cls
		case "wti":
			legacyWTI(name, svc, rep)
			continue
		default:
			rep.drop("%s: service '%s' (only shell and junos-exec are stored)", label, sname)
			continue
		}
		slabel := label + ": service '" + sname + "'"
		if have != nil {
			rep.drop("%s: second definition of the same service", slabel)
			continue
		}
		for _, k := range svc.Keys() {
			if !inList([]string{"name", "set_values", "match", "is_optional"}, k) {
				rep.drop("%s: unsupported key '%s'", slabel, k)
			}
		}
		if truthy(get(svc, "match")) {
			rep.drop("%s: match conditions", slabel)
		}
		if truthy(get(svc, "is_optional")) {
			rep.drop("%s: is_optional", slabel)
		}
		var val any
		setValues := orEmpty(get(svc, "set_values"))
		svList, ok := setValues.([]any)
		if setValues != nil && !ok {
			rep.fail("%s: set_values is not a list", slabel)
		}
		for _, x := range svList {
			sv, ok := mapOf(x)
			if !ok {
				rep.fail("%s: a set_values entry is not a mapping", slabel)
				continue
			}
			vname := ""
			if v, ok := sv.Get("name"); ok {
				vname = pyStrip(pyStr(v))
			}
			if sname == "junos-exec" && inList(junosExtraValues, vname) {
				rep.note("%s: set_value '%s' lives in tacctl.yaml (junos.%s.%s); not stored",
					slabel, vname, name, strings.ReplaceAll(vname, "-", "_"))
				if v := firstValue(sv); v != nil {
					rep.extras(name).Junos[vname] = pyStr(v)
				}
				continue
			}
			if vname != want {
				rep.drop("%s: extra set_value '%s'", slabel, vname)
				continue
			}
			if val != nil {
				rep.drop("%s: second '%s' set_value", slabel, vname)
				continue
			}
			for _, k := range sv.Keys() {
				if !inList([]string{"name", "values", "is_optional"}, k) {
					rep.drop("%s: set_value '%s': unsupported key '%s'", slabel, vname, k)
				}
			}
			if truthy(get(sv, "is_optional")) {
				rep.drop("%s: set_value '%s': is_optional", slabel, vname)
			}
			values := orEmpty(get(sv, "values"))
			vals, ok := values.([]any)
			if values != nil && !ok {
				vals = []any{values}
			}
			if len(vals) > 1 {
				rep.drop("%s: set_value '%s': more than one value (first kept)", slabel, vname)
			}
			if len(vals) > 0 {
				// A value of None (values: [~]) counts as no value, as in
				// the Python ('if val is None: continue').
				val = vals[0]
			}
		}
		if val == nil {
			continue
		}
		if want == "priv-lvl" {
			if p, ok := privLevel(val); ok {
				priv = p
				if sname == "exec" {
					rep.note("%s: legacy service name 'exec' is stored as the Cisco shell service "+
						"(rendered as 'shell', what 'tacctl upgrade' already migrates to)", label)
				}
			} else {
				rep.fail("%s: priv-lvl is not a number", label)
			}
		} else {
			cls = pyStrip(pyStr(val))
		}
	}
	if priv == nil {
		reported := false
		for _, e := range rep.Errors {
			if strings.HasPrefix(e, label+": priv-lvl") {
				reported = true
			}
		}
		if !reported {
			rep.fail("%s: no shell service with a priv-lvl value", label)
		}
	}
	if cls == nil {
		rep.fail("%s: no junos-exec service with a local-user-name value", label)
	}
	return yamlpy.NewMap("priv_lvl", priv, "juniper_class", cls, "builtin", IsBuiltinGroup(name))
}

var reDigitsOnly = regexp.MustCompile(`^[0-9]+$`)

// privLevel is int(val) for an integer or a string of digits. An integer
// beyond int64 (Python's are unbounded) becomes math.MaxInt: the
// validator refuses it as out of range either way.
func privLevel(val any) (int, bool) {
	switch x := val.(type) {
	case int:
		return x, true
	case bigInt:
		return math.MaxInt, true
	case string:
		t := pyStrip(x)
		if !reDigitsOnly.MatchString(t) {
			return 0, false
		}
		n, err := strconv.Atoi(t)
		if err != nil {
			return math.MaxInt, true
		}
		return n, true
	}
	return 0, false
}

func ref(refs map[*yamlpy.Map]bool, v any) {
	if m, ok := mapOf(v); ok {
		refs[m] = true
	}
}

// parsePrefixBlock is _parse_prefix_block: the 'prefixes: |' JSON block as
// a list of strings, the way tacctl always read it (JSON first, a scrape
// of the double-quoted strings as the fallback).
func parsePrefixBlock(block string) []any {
	if block == "" {
		return nil
	}
	var arr any
	if json.Unmarshal([]byte(block), &arr) == nil {
		if list, ok := arr.([]any); ok {
			var out []any
			for _, c := range list {
				if s, ok := c.(string); ok {
					out = append(out, s)
				}
			}
			return out
		}
	}
	var out []any
	for _, m := range reQuotedJSON.FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

var reQuotedJSON = regexp.MustCompile(`"([^"]+)"`)

// --- the loader -----------------------------------------------------------------

// legacyLoad is legacy_load: the model (the document store_normalize
// would build, not canonicalised) and the report.
func legacyLoad(path, datesDir, disabledDir string) (*yamlpy.Map, *LegacyReport, error) {
	raw, err := ReadLegacyYAML(path)
	if err != nil {
		return nil, nil, err
	}
	if raw == nil {
		raw = yamlpy.NewMap()
	}
	doc, ok := mapOf(raw)
	if !ok {
		return nil, nil, &Error{Msg: path + ": top level is not a YAML mapping"}
	}
	rep := &LegacyReport{}
	groups, users, scopes := yamlpy.NewMap(), yamlpy.NewMap(), yamlpy.NewMap()
	allow, deny := []any{}, []any{}
	refs := map[*yamlpy.Map]bool{}
	groupSrc := map[string]*yamlpy.Map{}

	registerGroup := func(gv any, where string) (string, bool) {
		g, ok := mapOf(gv)
		var name string
		if ok {
			name, _ = get(g, "name").(string)
		}
		if name == "" {
			rep.fail("%s: group entry without a usable name (quote names that YAML reads as numbers or booleans)", where)
			return "", false
		}
		refs[g] = true
		if prev, ok := groupSrc[name]; ok {
			if prev != g && !pyEqual(prev, g) {
				rep.fail("group '%s' is defined more than once with different content", name)
			}
			return name, true
		}
		groupSrc[name] = g
		groups.Set(name, legacyGroup(g, rep, refs))
		return name, true
	}

	// ---- users ----
	userList := orEmpty(get(doc, "users"))
	ul, ok := userList.([]any)
	if userList != nil && !ok {
		rep.fail("'users' is not a list")
	}
	for idx, uv := range ul {
		u, ok := mapOf(uv)
		if !ok {
			rep.fail("users[%d]: not a mapping", idx)
			continue
		}
		name, _ := get(u, "name").(string)
		if name == "" {
			rep.fail("users[%d]: no usable name (quote names that YAML reads as numbers or booleans)", idx)
			continue
		}
		label := "user '" + name + "'"
		if users.Has(name) {
			rep.fail("%s: defined more than once", label)
			continue
		}
		for _, k := range u.Keys() {
			if !inList([]string{"name", "scopes", "groups", "services", "commands", "authenticator", "accounter"}, k) {
				rep.drop("%s: unsupported key '%s'", label, k)
			}
		}
		if truthy(get(u, "services")) {
			rep.drop("%s: user-level services override", label)
		}
		if truthy(get(u, "commands")) {
			rep.drop("%s: user-level commands override", label)
		}

		gs := orEmpty(get(u, "groups"))
		gl, ok := gs.([]any)
		if gs != nil && !ok {
			gl = []any{gs}
		}
		if len(gl) != 1 {
			if len(gl) == 0 {
				rep.drop("%s: no group, so the user itself cannot be stored (exactly one group is required)", label)
				continue
			}
			rep.drop("%s: %d groups (only the first is kept)", label, len(gl))
		}
		gname, ok := registerGroup(gl[0], label)
		for _, extra := range gl[1:] {
			ref(refs, extra)
		}
		if !ok {
			continue
		}

		sink := inList(sinkUsers, name)
		var hashVal any
		disabled := true
		auth, hasAuth := u.Get("authenticator")
		ref(refs, auth)
		am, isMap := mapOf(auth)
		switch {
		case !hasAuth || auth == nil:
			rep.drop("%s: no authenticator of its own; stored as disabled with no password", label)
		case !isMap || !pyEqInt(get(am, "type"), tBcryptAuth):
			rep.drop("%s: non-bcrypt authenticator; stored as disabled with no password", label)
		default:
			opts, _ := mapOf(orEmpty(get(am, "options")))
			keys := am.Keys()
			if opts != nil {
				keys = append(keys, opts.Keys()...)
			}
			for _, k := range keys {
				if !inList([]string{"type", "options", "hash"}, k) {
					rep.drop("%s: authenticator: unsupported key '%s'", label, k)
				}
			}
			var h any
			if opts != nil {
				h = get(opts, "hash")
			}
			if pyIsInt(h) {
				// An unquoted hash whose hex happens to be all digits
				// loads as a YAML integer. Every bcrypt hex starts with
				// "2432", so the decimal text is exactly what the file
				// says.
				h = pyStr(h)
			}
			hs, isStr := h.(string)
			low := strings.ToLower(pyStrip(hs))
			switch {
			case isStr && (low == hash.DisabledMarkerHex || pyStrip(hs) == "DISABLED"):
				// Disabled account. 'user disable' parks the real hash
				// in a sidecar; seeded accounts never had one.
				if !sink && reUser.MatchString(name) {
					if saved, ok := sidecar(disabledDir, name+".hash", rep); ok {
						norm, ok := NormalizeHash(saved)
						if !ok || norm == hash.DisabledMarkerHex {
							rep.drop("%s: saved hash of the disabled account is not a bcrypt hash "+
								"('user enable' would have nothing to restore)", label)
						} else {
							hashVal = norm
						}
					}
				}
			case isStr && BcryptHexOK(low):
				if sink {
					rep.drop("%s: carries a real password hash; the accounting sink is stored without one and stays disabled", label)
				} else {
					hashVal, disabled = low, false
				}
			default:
				rep.drop("%s: password hash is not a bcrypt hash; stored as disabled with no password", label)
			}
		}

		if acc := get(u, "accounter"); acc == nil {
			rep.note("%s: has no accounter of its own; the rendered config always attaches the file accounter", label)
		} else {
			ref(refs, acc)
			if !fileAccounterOK(acc) {
				rep.drop("%s: accounter other than the file accounter", label)
			}
		}

		sv := get(u, "scopes")
		if sv == nil {
			sv = []any{}
			rep.note("%s: has no scopes and can authenticate from nowhere", label)
		}
		sl, isList := sv.([]any)
		allStr := isList
		for _, s := range sl {
			if _, ok := s.(string); !ok {
				allStr = false
			}
		}
		userScopes := []any{}
		if !allStr {
			rep.fail("%s: scopes is not a list of names (quote names that YAML reads as numbers or booleans)", label)
		}
		for _, s := range sl {
			if _, ok := s.(string); ok {
				userScopes = append(userScopes, s)
			}
		}

		var changed any
		if reUser.MatchString(name) {
			if date, ok := sidecar(datesDir, name+".date", rep); ok && date != "" {
				if checkField(fieldSpec{typ: tDate}, date) == "" {
					changed = date
				} else {
					rep.note("%s: password-date file does not hold a YYYY-MM-DD date; ignored", label)
				}
			}
		}

		users.Set(name, yamlpy.NewMap("group", gname, "scopes", userScopes, "hash", hashVal,
			"disabled", disabled, "password_changed", changed, "accounting_sink", sink))
	}

	// ---- top-level keys: groups no user references, anchors, strays ----
	for key, val := range doc.All() {
		m, ok := mapOf(val)
		if inList(legacyTopKeys, key) || !ok {
			continue
		}
		if _, isList := get(m, "services").([]any); !refs[m] && m.Has("name") && isList {
			registerGroup(m, "top-level '"+key+"'")
		}
	}
	for key, val := range doc.All() {
		if inList(legacyTopKeys, key) {
			continue
		}
		if m, ok := mapOf(val); ok {
			if refs[m] {
				continue
			}
			opts, optsMap := mapOf(get(m, "options"))
			switch {
			case m.Has("name") && m.Has("set_values"):
				rep.note("top-level '%s': service anchor no group uses; ignored", key)
			case m.Has("type") && optsMap && opts.Has("hash"):
				rep.note("top-level '%s': authenticator anchor no user uses; ignored", key)
			case fileAccounterOK(m):
			default:
				rep.drop("unknown top-level key '%s'", key)
			}
		} else if !inList(legacyConstants, key) || !pyIsInt(val) {
			rep.drop("unknown top-level key '%s'", key)
		}
	}

	// ---- scopes: secrets[] entries grouped by name ----
	secrets := orEmpty(get(doc, "secrets"))
	sl, ok := secrets.([]any)
	if secrets != nil && !ok {
		rep.fail("'secrets' is not a list")
	}
	type scopeKeys struct {
		name string
		keys []string
	}
	var keysByScope []*scopeKeys
	for idx, sv := range sl {
		s, ok := mapOf(sv)
		if !ok {
			rep.fail("secrets[%d]: not a mapping", idx)
			continue
		}
		nv := get(s, "name")
		if nv == nil || nv == "" {
			rep.drop("secrets[%d]: entry without a name", idx)
			continue
		}
		name, ok := nv.(string)
		if !ok {
			rep.fail("secrets[%d]: name is not a string (quote names that YAML reads as numbers or booleans)", idx)
			continue
		}
		label := sprintf("scope '%s' (secrets[%d])", name, idx)
		if !pyEqInt(get(s, "type"), tProviderPrefix) {
			rep.drop("%s: non-prefix secret provider; entry skipped", label)
			continue
		}
		for _, k := range s.Keys() {
			if !inList([]string{"name", "secret", "handler", "type", "options"}, k) {
				rep.drop("%s: unsupported key '%s'", label, k)
			}
		}
		handler, ok := mapOf(get(s, "handler"))
		switch {
		case !ok || !pyEqInt(get(handler, "type"), tHandlerStart):
			rep.drop("%s: handler other than the standard start handler", label)
		case truthy(get(handler, "options")) || !keysOnly(handler, "type", "options"):
			rep.drop("%s: handler options", label)
		}
		sec, ok := mapOf(get(s, "secret"))
		if !ok {
			sec = yamlpy.NewMap()
		}
		for _, k := range sec.Keys() {
			if k != "group" && k != "key" {
				rep.drop("%s: secret: unsupported key '%s'", label, k)
			}
		}
		var key any
		if k, ok := get(sec, "key").(string); ok {
			key = k
		} else {
			// A non-string scalar (unquoted digits, yes/no) is read
			// differently by PyYAML and by the daemon; guessing would
			// silently change the shared secret.
			rep.fail("%s: secret.key is missing or not a YAML string (quote it)", label)
		}
		ov := orEmpty(get(s, "options"))
		opts, ok := mapOf(ov)
		if ov != nil && !ok {
			rep.fail("%s: options is not a mapping", label)
		}
		if !ok {
			opts = yamlpy.NewMap()
		}
		for _, k := range opts.Keys() {
			if k != "prefixes" {
				rep.drop("%s: option '%s'", label, k)
			}
		}
		bv := get(opts, "prefixes")
		block, isStr := bv.(string)
		if bv != nil && !isStr {
			rep.fail("%s: prefixes is not a text block", label)
		}
		scv, exists := scopes.Get(name)
		if !exists {
			scv = yamlpy.NewMap("prefixes", []any{}, "secret", key, "protocols", nil)
			scopes.Set(name, scv)
		}
		scope := scv.(*yamlpy.Map)
		if get(scope, "secret") == nil {
			scope.Set("secret", key)
		}
		if ks, ok := key.(string); ok {
			var e *scopeKeys
			for _, x := range keysByScope {
				if x.name == name {
					e = x
				}
			}
			if e == nil {
				e = &scopeKeys{name: name}
				keysByScope = append(keysByScope, e)
			}
			e.keys = append(e.keys, ks)
		}
		for _, c := range parsePrefixBlock(block) {
			canon, ok := CanonicalCIDR(c)
			prefixes := get(scope, "prefixes").([]any)
			switch {
			case !ok:
				rep.drop("%s: invalid prefix %s", label, PyRepr(c))
			case !listHas(prefixes, canon):
				scope.Set("prefixes", append(prefixes, canon))
			}
		}
	}
	for _, e := range keysByScope {
		distinct := map[string]bool{}
		for _, k := range e.keys {
			distinct[k] = true
		}
		if len(distinct) > 1 {
			rep.fail("scope '%s' has %d entries but %d distinct secret.key values "+
				"— entries must share a key", e.name, len(e.keys), len(distinct))
		}
	}

	// ---- prefix filters ----
	for _, f := range []struct {
		src string
		dst *[]any
	}{{"prefix_allow", &allow}, {"prefix_deny", &deny}} {
		items := orEmpty(get(doc, f.src))
		list, ok := items.([]any)
		if items != nil && !ok {
			rep.fail("'%s' is not a list", f.src)
			continue
		}
		for _, c := range list {
			canon, ok := CanonicalCIDR(c)
			switch {
			case !ok:
				rep.drop("%s: invalid prefix %s", f.src, PyRepr(c))
			case !listHas(*f.dst, canon):
				*f.dst = append(*f.dst, canon)
			}
		}
	}

	model := yamlpy.NewMap(
		"version", Version,
		"groups", groups,
		"users", users,
		"scopes", scopes,
		"filters", yamlpy.NewMap("allow", allow, "deny", deny),
	)
	return model, rep, nil
}

// LegacyRaw is legacy_load(path, datesDir, disabledDir): the model a
// forced import of the tacquito.yaml at path would produce, before
// canonicalisation, and the report. datesDir and disabledDir hold the
// sidecar files ('<user>.date', '<user>.hash'); "" means none. A file that
// cannot be read or parsed, or whose top level is not a mapping, is an
// *Error.
func LegacyRaw(path, datesDir, disabledDir string) (*Store, *LegacyReport, error) {
	doc, rep, err := legacyLoad(path, datesDir, disabledDir)
	if err != nil {
		return nil, nil, err
	}
	s, err := Normalize(doc)
	if err != nil {
		return nil, nil, err
	}
	return s, rep, nil
}

// LegacyLoad is the legacy branch of model_load ('dump-legacy'): LegacyRaw
// canonicalised. It is not validated (legacy read-only mode serves a file
// with unrepresentable content).
func LegacyLoad(path, datesDir, disabledDir string) (*Store, *LegacyReport, error) {
	s, rep, err := LegacyRaw(path, datesDir, disabledDir)
	if err != nil {
		return nil, nil, err
	}
	s.Canonicalize()
	return s, rep, nil
}
