package model

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/store"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The equivalence of two tacquito.yaml files (equiv_check and
// _equiv_normalize in lib/model.sh at 0.1.16; plan 4.3 step 3).
//
// "Equivalent" means: tacquito, given either file, answers every client the
// same way. The comparison models what the daemon does with a config
// rather than how the file is spelled (the rules are read off the tacquito
// source: cmds/server/loader, config/secret/prefix,
// config/authorizers/stringy, config/authenticators/bcrypt):
//
//	scalars  compared as the text that was written (store.ReadBaseYAML,
//	         yaml.BaseLoader): the daemon decodes into string fields, so
//	         15 and "15" are one value while 01 and 1 are not.
//	users    keyed by name; scope order irrelevant; the EFFECTIVE
//	         authenticator and accounter (a user without one gets the
//	         first its groups define); groups as written, in order; a
//	         hash compared case-insensitively, 'DISABLED' and the disabled
//	         marker one value.
//	secrets  the set of live (prefix, scope, key) routes: providers in file
//	         order, none for a scope without users, a non-standard
//	         type/handler or prefixes that are not a non-empty JSON list of
//	         strings; a prefix Go's net.ParseCIDR rejects is skipped; a
//	         prefix an earlier provider covers is dead.
//	filters  prefix_allow / prefix_deny as sets of parseable CIDRs.
//
// Groups no user is in, and the routing as it would be if every scope had
// a user, are compared too (a difference confined to them is "latent" and
// still fails). Secrets and hashes are compared, never shown: both sides
// get the same keyed fingerprint, and the key lives only for the call.

// equivSalt is the fingerprint key source (tests replace it).
var equivSalt = func() []byte {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return b
}

// EquivCheck is equiv_check (store_equiv_check): it compares the
// normalised forms of the live and the rendered tacquito.yaml and writes
// to w the notes on the live file, then "EQUIVALENT", or a unified diff of
// the two forms and "NOT EQUIVALENT" (exit status 0 and 1 in 0.1.16). A
// file that cannot be read or parsed is a *store.Error.
func EquivCheck(live, rendered string, w io.Writer) (bool, error) {
	return equivCheck(equivSalt(), live, rendered, w)
}

// EquivCheckRand is EquivCheck with the fingerprint key (16 bytes) read
// from r, the invocation's random source: a test that fixes the source
// (TACCTL_TEST_RANDOM) gets the fingerprints 0.1.16 prints with its
// os.urandom fixed the same way. A source that cannot be read falls back to
// crypto/rand.
func EquivCheckRand(r io.Reader) store.EquivFunc {
	return func(live, rendered string, w io.Writer) (bool, error) {
		key := make([]byte, 16)
		if _, err := io.ReadFull(r, key); err != nil {
			key = equivSalt()
		}
		return equivCheck(key, live, rendered, w)
	}
}

func equivCheck(key []byte, live, rendered string, w io.Writer) (bool, error) {
	fingerprint := func(v string) string {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(v))
		return "<redacted:" + hex.EncodeToString(mac.Sum(nil))[:10] + ">"
	}
	var forms [2]*yamlpy.Map
	var notes []string
	for i, path := range []string{live, rendered} {
		doc, err := store.ReadBaseYAML(path)
		if err != nil {
			return false, err
		}
		form, n := equivNormalize(doc, fingerprint)
		forms[i] = form
		if i == 0 {
			notes = n
		}
	}
	var b strings.Builder
	for _, n := range notes {
		b.WriteString("note: " + live + ": " + n + "\n")
	}
	a, c := forms[0], forms[1]
	if pyEq(a, c) {
		b.WriteString("EQUIVALENT\n")
		_, err := io.WriteString(w, b.String())
		return true, err
	}
	ta, err := JSONIndent(a, 2)
	if err != nil {
		return false, err
	}
	tb, err := JSONIndent(c, 2)
	if err != nil {
		return false, err
	}
	b.WriteString(unifiedDiff(splitLinesKeepEnds(ta), splitLinesKeepEnds(tb),
		"live (normalised)", "rendered (normalised)"))
	serving := func(f *yamlpy.Map) []any {
		sec, _ := f.Get("secrets")
		routes, _ := sec.(*yamlpy.Map).Get("routes")
		return []any{mget(f, "users"), routes, mget(f, "prefix_allow"), mget(f, "prefix_deny")}
	}
	if pyEq(serving(a), serving(c)) {
		b.WriteString("note: the two differ only in groups without users or scopes without users. " +
			"tacquito answers today's clients identically, but the difference takes " +
			"effect as soon as such a group or scope gets a user.\n")
	}
	b.WriteString("NOT EQUIVALENT\n")
	_, err = io.WriteString(w, b.String())
	return false, err
}

func mget(m *yamlpy.Map, k string) any {
	v, _ := m.Get(k)
	return v
}

// pyEq is == on the normalised forms (strings, nil, lists, mappings
// compared as sets of pairs).
func pyEq(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEq(x[i], y[i]) {
				return false
			}
		}
		return true
	case *yamlpy.Map:
		y, ok := b.(*yamlpy.Map)
		if !ok || x.Len() != y.Len() {
			return false
		}
		for k, v := range x.All() {
			w, ok := y.Get(k)
			if !ok || !pyEq(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

// yamlNull is _yaml_null.
func yamlNull(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && (s == "" || s == "~" || s == "null" || s == "Null" || s == "NULL")
}

// asList is _as_list.
func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func asMap(v any) *yamlpy.Map {
	if m, ok := v.(*yamlpy.Map); ok && m != nil {
		return m
	}
	return yamlpy.NewMap()
}

func isMap(v any) bool {
	m, ok := v.(*yamlpy.Map)
	return ok && m != nil
}

// reIntText is what Python's int() accepts in base 10 (ASCII digits).
var reIntText = regexp.MustCompile(`^[+-]?[0-9]+(?:_[0-9]+)*$`)

// isOne is _is_one: int(str(v)) == 1.
func isOne(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false // str() of a list, a mapping or None is never an int
	}
	s = strings.TrimFunc(s, func(r rune) bool { return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) })
	if !reIntText.MatchString(s) {
		return false
	}
	s = strings.TrimLeft(strings.ReplaceAll(s, "_", ""), "+")
	if strings.HasPrefix(s, "-") {
		return false
	}
	s = strings.TrimLeft(s, "0")
	return s == "1"
}

// redact is _equiv_redact: a copy of node with every scalar under an
// authenticator or secret mapping (bar its type and group) replaced by a
// fingerprint.
func redact(node any, fp func(string) string, sensitive bool) any {
	switch x := node.(type) {
	case *yamlpy.Map:
		out := yamlpy.NewMap()
		for k, v := range x.All() {
			inner := sensitive || k == "authenticator" || k == "secret"
			if inner && (k == "type" || k == "group") && !isMap(v) && !isList(v) {
				out.Set(k, v)
			} else {
				out.Set(k, redact(v, fp, inner))
			}
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = redact(v, fp, sensitive)
		}
		return out
	}
	if sensitive && node != nil {
		return fp(store.PyStr(node))
	}
	return node
}

func isList(v any) bool {
	_, ok := v.([]any)
	return ok
}

// equivHash is _equiv_hash: an authenticator with options.hash in its
// comparison form.
func equivHash(auth any) any {
	a, ok := auth.(*yamlpy.Map)
	if !ok || a == nil {
		return auth
	}
	opts, ok := mget(a, "options").(*yamlpy.Map)
	if !ok || opts == nil {
		return auth
	}
	h, ok := mget(opts, "hash").(string)
	if !ok {
		return auth
	}
	folded := strings.ToLower(h)
	if h == "DISABLED" || folded == hash.DisabledMarkerHex {
		folded = "<disabled>"
	}
	no := copyMap(opts)
	no.Set("hash", folded)
	na := copyMap(a)
	na.Set("options", no)
	return na
}

func copyMap(m *yamlpy.Map) *yamlpy.Map {
	out := yamlpy.NewMap()
	for k, v := range m.All() {
		out.Set(k, v)
	}
	return out
}

// reGoCIDR is the shape Go's net.ParseCIDR wants: address/bits.
var reGoCIDR = regexp.MustCompile(`^[0-9A-Fa-f:.]+/[0-9]+$`)

// goCIDR is _go_cidr: a prefix as tacquito parses it, or false.
func goCIDR(v any) (store.Net, bool) {
	s, ok := v.(string)
	if !ok || !reGoCIDR.MatchString(s) {
		return store.Net{}, false
	}
	return store.ParseNet(s)
}

// goPrefixList is _go_prefix_list: options.prefixes as the prefix provider
// reads it (json.Unmarshal into []string), or false when the provider
// would refuse the entry.
func goPrefixList(raw any) ([]string, bool) {
	s, ok := raw.(string)
	if !ok {
		return nil, false
	}
	var arr any
	if json.Unmarshal([]byte(s), &arr) != nil {
		return nil, false
	}
	list, ok := arr.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	var out []string
	for _, c := range list {
		switch x := c.(type) {
		case nil:
		case string:
			out = append(out, x)
		default:
			return nil, false
		}
	}
	return out, true
}

type provider struct {
	idx   int
	scope string
	key   string
	extra *yamlpy.Map
	nets  []store.Net
}

// equivRoutes is _equiv_routes: the live routes of ordered providers,
// sorted by prefix, and notes on the prefixes that never match.
func equivRoutes(providers []provider) ([]any, []string) {
	type live struct {
		net   store.Net
		route *yamlpy.Map
	}
	var lives []live
	var earlier []store.Net
	var notes []string
	for _, p := range providers {
		for _, net := range p.nets {
			covered := false
			for _, n := range earlier {
				if n.Version() == net.Version() && net.SubnetOf(n) {
					notes = append(notes, "secrets["+strconv.Itoa(p.idx)+"] '"+p.scope+"': "+net.String()+
						" never matches a client (an earlier entry already covers it with "+n.String()+")")
					covered = true
					break
				}
			}
			if covered {
				continue
			}
			route := yamlpy.NewMap("prefix", net.String(), "scope", p.scope, "key", p.key)
			if p.extra.Len() > 0 {
				route.Set("nonstandard", p.extra)
			}
			lives = append(lives, live{net, route})
		}
		// The prefixes of one provider share one answer, so only earlier
		// providers can shadow.
		earlier = append(earlier, p.nets...)
	}
	sort.SliceStable(lives, func(i, j int) bool { return lives[i].net.Key().Less(lives[j].net.Key()) })
	routes := make([]any, len(lives))
	for i, l := range lives {
		routes[i] = l.route
	}
	return routes, notes
}

// equivNormalize is _equiv_normalize: a loaded tacquito.yaml reduced to the
// comparison form, and notes on it.
func equivNormalize(doc any, fp func(string) string) (*yamlpy.Map, []string) {
	var notes []string
	users, unused := yamlpy.NewMap(), yamlpy.NewMap()
	secrets := yamlpy.NewMap("routes", []any{}, "routes_if_every_scope_had_users", []any{})
	form := yamlpy.NewMap("users", users, "groups_without_users", unused, "secrets", secrets,
		"prefix_allow", []any{}, "prefix_deny", []any{})
	d, ok := doc.(*yamlpy.Map)
	if !ok || d == nil {
		return form, notes
	}

	// ---- users ----
	usedGroups, scoped := map[string]bool{}, map[string]bool{}
	for _, uv := range asList(mget(d, "users")) {
		u, ok := uv.(*yamlpy.Map)
		if !ok || u == nil {
			continue
		}
		name := store.PyStr(mget(u, "name"))
		ent := yamlpy.NewMap()
		for k, v := range u.All() {
			if k != "name" {
				ent.Set(k, v)
			}
		}
		var groups []*yamlpy.Map
		for _, g := range asList(mget(u, "groups")) {
			if gm, ok := g.(*yamlpy.Map); ok && gm != nil {
				groups = append(groups, gm)
				usedGroups[store.PyStr(mget(gm, "name"))] = true
			}
		}
		for _, field := range []string{"authenticator", "accounter"} {
			eff := mget(u, field)
			if yamlNull(eff) {
				eff = nil
				for _, g := range groups {
					if !yamlNull(mget(g, field)) {
						eff = mget(g, field)
						break
					}
				}
			}
			ent.Set(field, eff)
		}
		ent.Set("authenticator", equivHash(mget(ent, "authenticator")))
		gl := []any{}
		for _, g := range asList(mget(u, "groups")) {
			if gm, ok := g.(*yamlpy.Map); ok && gm != nil && gm.Has("authenticator") {
				ng := copyMap(gm)
				ng.Set("authenticator", equivHash(mget(gm, "authenticator")))
				g = ng
			}
			gl = append(gl, g)
		}
		ent.Set("groups", gl)
		if sl, ok := mget(u, "scopes").([]any); ok {
			set := map[string]bool{}
			for _, s := range sl {
				set[store.PyStr(s)] = true
			}
			names := make([]string, 0, len(set))
			for s := range set {
				names = append(names, s)
				scoped[s] = true
			}
			sort.Strings(names)
			list := make([]any, len(names))
			for i, s := range names {
				list[i] = s
			}
			ent.Set("scopes", list)
		}
		key := name
		for n := 2; users.Has(key); n++ {
			// tacquito lets a later entry override an earlier one per
			// scope; nothing tacctl renders does that, so keep both
			// visible.
			key = name + " (entry " + strconv.Itoa(n) + ")"
		}
		users.Set(key, redact(ent, fp, false))
	}

	// ---- groups nobody is in (latent) ----
	for _, val := range d.All() {
		g, ok := val.(*yamlpy.Map)
		if !ok || g == nil || !g.Has("name") || !isList(mget(g, "services")) || usedGroups[store.PyStr(mget(g, "name"))] {
			continue
		}
		var gv any = g
		if g.Has("authenticator") {
			ng := copyMap(g)
			ng.Set("authenticator", equivHash(mget(g, "authenticator")))
			gv = ng
		}
		unused.Set(store.PyStr(mget(g, "name")), redact(gv, fp, false))
	}

	// ---- secrets ----
	var providers []provider
	for idx, sv := range asList(mget(d, "secrets")) {
		s, ok := sv.(*yamlpy.Map)
		if !ok || s == nil {
			continue
		}
		name := store.PyStr(mget(s, "name"))
		sec := asMap(mget(s, "secret"))
		key := mget(sec, "key")
		keyText := ""
		if !yamlNull(key) {
			keyText = store.PyStr(key)
		}
		fpKey := fp(keyText)
		handler := asMap(mget(s, "handler"))
		opts := asMap(mget(s, "options"))
		// Anything beyond the skeleton tacctl writes rides along, so it
		// shows.
		extra := yamlpy.NewMap()
		for k, v := range s.All() {
			if k != "name" && k != "secret" && k != "handler" && k != "type" && k != "options" {
				extra.Set(k, v)
			}
		}
		without := func(m *yamlpy.Map, drop string) *yamlpy.Map {
			out := yamlpy.NewMap()
			for k, v := range m.All() {
				if k != drop {
					out.Set(k, v)
				}
			}
			return out
		}
		if rest := without(sec, "key"); !pyEq(rest, yamlpy.NewMap("group", "tacquito")) {
			extra.Set("secret", rest)
		}
		if rest := without(handler, "type"); rest.Len() > 0 {
			extra.Set("handler", rest)
		}
		if rest := without(opts, "prefixes"); rest.Len() > 0 {
			extra.Set("options", rest)
		}
		extra = redact(extra, fp, false).(*yamlpy.Map)
		label := "secrets[" + strconv.Itoa(idx) + "] '" + name + "'"
		if !isOne(mget(s, "type")) {
			notes = append(notes, label+": not a prefix provider; tacquito builds nothing for it")
			continue
		}
		if !isOne(mget(handler, "type")) {
			notes = append(notes, label+": no standard handler; tacquito builds nothing for it")
			continue
		}
		prefixes, ok := goPrefixList(mget(opts, "prefixes"))
		if !ok {
			notes = append(notes, label+": prefixes is not a non-empty JSON list of strings; tacquito builds nothing for it")
			continue
		}
		var nets []store.Net
		for _, c := range prefixes {
			net, ok := goCIDR(c)
			if !ok {
				notes = append(notes, label+": prefix "+store.PyRepr(c)+" is not a CIDR tacquito can parse; it is skipped")
				continue
			}
			dup := false
			for _, n := range nets {
				if n.Equal(net) {
					dup = true
				}
			}
			if !dup {
				nets = append(nets, net)
			}
		}
		providers = append(providers, provider{idx, name, fpKey, extra, nets})
	}

	var active []provider
	idle := map[string]bool{}
	for _, p := range providers {
		if scoped[p.scope] {
			active = append(active, p)
		} else {
			idle[p.scope] = true
		}
	}
	idleNames := make([]string, 0, len(idle))
	for n := range idle {
		idleNames = append(idleNames, n)
	}
	sort.Strings(idleNames)
	for _, n := range idleNames {
		notes = append(notes, "scope '"+n+"' has no users; tacquito does not load it")
	}
	routes, shadow := equivRoutes(active)
	latentRoutes, latent := equivRoutes(providers)
	secrets.Set("routes", routes)
	secrets.Set("routes_if_every_scope_had_users", latentRoutes)
	notes = append(notes, shadow...)
	for _, n := range latent {
		if !contains(shadow, n) {
			notes = append(notes, n+" once every scope has a user")
		}
	}

	// ---- prefix filters ----
	for _, k := range []string{"prefix_allow", "prefix_deny"} {
		kept := map[string]store.Net{}
		for _, c := range asList(mget(d, k)) {
			net, ok := goCIDR(c)
			if !ok {
				notes = append(notes, k+": "+store.PyRepr(c)+" is not a CIDR tacquito can parse; it is ignored")
				continue
			}
			kept[net.String()] = net
		}
		nets := make([]store.Net, 0, len(kept))
		for _, n := range kept {
			nets = append(nets, n)
		}
		sort.Slice(nets, func(i, j int) bool { return nets[i].Key().Less(nets[j].Key()) })
		list := make([]any, len(nets))
		for i, n := range nets {
			list[i] = n.String()
		}
		form.Set(k, list)
	}
	return form, notes
}
