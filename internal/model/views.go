package model

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/store"
)

// The views of model_view (lib/model.sh). Each returns the lines the
// python view printed, in the same format; none contains a secret or a
// hash.

// builtinDisplayOrder is BUILTIN_DISPLAY_ORDER.
var builtinDisplayOrder = []string{"readonly", "operator", "superuser"}

var rfc1918 = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

// privOf is the stored priv-lvl text of the user's group ("" when the
// group or its level is missing).
func (m *Model) privOf(u *User) string {
	if g := m.groups[u.Group]; g != nil {
		return g.privText
	}
	return ""
}

// Members is members(): the names of the users granted the scope, sorted
// (model_scope_users).
func (m *Model) Members(scope string) []string {
	var out []string
	for _, n := range m.UserNames() {
		for _, s := range m.users[n].Scopes {
			if s == scope {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

type routingPair struct {
	cidr, scope string
	key         cidr.Key
}

// routingPairs is routing_pairs: (cidr, scope) in the order the daemon
// tries them (as rendered).
func (m *Model) routingPairs() []routingPair {
	var pairs []routingPair
	for _, s := range m.Scopes {
		for _, c := range s.Prefixes {
			if _, ok := store.CanonicalCIDR(c); !ok {
				continue
			}
			k, ok := cidr.SortKey(c)
			if !ok {
				k, _ = cidr.SortKey(strings.TrimSpace(c))
			}
			pairs = append(pairs, routingPair{c, s.Name, k})
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		a, b := pairs[i], pairs[j]
		if a.key != b.key {
			return a.key.Less(b.key)
		}
		return a.scope < b.scope
	})
	return pairs
}

// ScopesByRouting is scope_display_order (model_scopes_by_routing, the
// 'scope-names' view): scopes by where their most specific prefix sits in
// the routing order; scopes without prefixes last, by name.
func (m *Model) ScopesByRouting() []string {
	var order []string
	seen := map[string]bool{}
	for _, p := range m.routingPairs() {
		if !seen[p.scope] {
			seen[p.scope] = true
			order = append(order, p.scope)
		}
	}
	var rest []string
	for _, s := range m.Scopes {
		if !seen[s.Name] {
			rest = append(rest, s.Name)
		}
	}
	sort.Strings(rest)
	return append(order, rest...)
}

// vendorSummary is vendor_summary: the enabled vendors and how many
// addresses are tagged (empty when neither).
func vendorSummary(s *Scope) string {
	var parts []string
	if len(s.VendorAttrs) > 0 {
		parts = append(parts, strings.Join(s.VendorAttrs, ","))
	}
	if len(s.Devices) > 0 {
		parts = append(parts, fmt.Sprintf("%d tagged", len(s.Devices)))
	}
	return strings.Join(parts, " + ")
}

// UserRows is model_user_rows: 'name|group|status|password_changed|
// scope,scope' per user by name, without the accounting sink.
func (m *Model) UserRows() []string {
	var out []string
	for _, n := range m.UserNames() {
		u := m.users[n]
		if u.AccountingSink {
			continue
		}
		status := "active"
		if u.IsDisabled() {
			status = "disabled"
		}
		pc := u.PasswordChanged
		if pc == "" {
			pc = "unknown"
		}
		out = append(out, strings.Join([]string{n, u.Group, status, pc, strings.Join(u.Scopes, ",")}, "|"))
	}
	return out
}

// UserInfo is model_user_info: group, status, password_changed, priv_lvl,
// juniper_class, hash_type, has_hash, then 'scope=<name>|<1|0>' per scope.
// ok is false (no lines) for an unknown user. Never the hash.
func (m *Model) UserInfo(name string) (lines []string, ok bool) {
	u := m.users[name]
	if u == nil {
		return nil, false
	}
	g := m.groups[u.Group]
	if g == nil {
		g = &Group{}
	}
	status, hashType := "active", ""
	if u.IsDisabled() {
		status = "disabled"
	} else {
		hashType = hash.TypePrefix(u.Hash)
	}
	pc := u.PasswordChanged
	if pc == "" {
		pc = "unknown"
	}
	hasHash := "0"
	if u.Hash != "" {
		hasHash = "1"
	}
	lines = []string{
		"group=" + u.Group,
		"status=" + status,
		"password_changed=" + pc,
		"priv_lvl=" + g.privText,
		"juniper_class=" + g.JuniperClass,
		"hash_type=" + hashType,
		"has_hash=" + hasHash,
	}
	for _, s := range u.Scopes {
		e := "0"
		if m.scopes[s] != nil {
			e = "1"
		}
		lines = append(lines, "scope="+s+"|"+e)
	}
	return lines, true
}

// UserPrivLvl is model_user_privlvl: the priv-lvl of the user's group, or
// "" when the user is unknown, disabled, the accounting sink, or its group
// (or the group's level) is missing.
func (m *Model) UserPrivLvl(name string) string {
	u := m.users[name]
	if u == nil || u.IsDisabled() {
		return ""
	}
	return m.privOf(u)
}

// GroupRows is model_group_rows: 'name|priv_lvl|juniper_class|users' by
// priv-lvl, highest first, equal levels in reverse name order; the count
// leaves out the accounting sink.
func (m *Model) GroupRows() []string {
	counts := map[string]int{}
	for _, u := range m.Users {
		if !u.AccountingSink {
			counts[u.Group]++
		}
	}
	gs := append([]*Group(nil), m.Groups...)
	lvl := func(g *Group) int {
		if g.PrivLvl == nil {
			return -1
		}
		return *g.PrivLvl
	}
	sort.SliceStable(gs, func(i, j int) bool {
		if lvl(gs[i]) != lvl(gs[j]) {
			return lvl(gs[i]) > lvl(gs[j])
		}
		return gs[i].Name > gs[j].Name
	})
	var out []string
	for _, g := range gs {
		priv := g.privText
		if priv == "" {
			priv = "n/a"
		}
		class := g.JuniperClass
		if class == "" {
			class = "n/a"
		}
		out = append(out, fmt.Sprintf("%s|%s|%s|%d", g.Name, priv, class, counts[g.Name]))
	}
	return out
}

// GroupUsers is model_group_users: every member of the group (the
// accounting sink included), by name.
func (m *Model) GroupUsers(group string) []string {
	var out []string
	for _, n := range m.UserNames() {
		if m.users[n].Group == group {
			out = append(out, n)
		}
	}
	return out
}

// GroupInfo is model_group_info: 'name|priv_lvl|juniper_class', the
// built-ins first in the shipped order, then the rest by name.
func (m *Model) GroupInfo() []string {
	var order, rest []string
	for _, b := range builtinDisplayOrder {
		if m.groups[b] != nil {
			order = append(order, b)
		}
	}
	for _, g := range m.Groups {
		if !contains(order, g.Name) {
			rest = append(rest, g.Name)
		}
	}
	sort.Strings(rest)
	var out []string
	for _, n := range append(order, rest...) {
		g := m.groups[n]
		out = append(out, n+"|"+g.privText+"|"+g.JuniperClass)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ScopePrefixes is model_scope_prefixes: the scope's prefixes in display
// order (longest prefix first); nothing for an unknown scope.
func (m *Model) ScopePrefixes(scope string) []string {
	s := m.scopes[scope]
	if s == nil {
		return nil
	}
	return store.SortDisplay(s.Prefixes)
}

// PrefixOwner is model_prefix_owner: the scope (first by name) holding
// exactly this network after canonicalisation, or "".
func (m *Model) PrefixOwner(c string) string {
	target, ok := store.CanonicalCIDR(c)
	if !ok {
		return ""
	}
	for _, n := range m.ScopeNames() {
		for _, p := range m.scopes[n].Prefixes {
			if pc, ok := store.CanonicalCIDR(p); ok && pc == target {
				return n
			}
		}
	}
	return ""
}

// ScopeRows is the 'scope-rows' view: one line per (scope, prefix) in
// routing order; the first line of a scope carries the user count, the
// default marker and the vendor summary ('name|cidr|users|yes|vendors'),
// the others leave those columns empty ('|cidr|||').
func (m *Model) ScopeRows(defaultScope string) []string {
	var out []string
	for _, n := range m.ScopesByRouting() {
		s := m.scopes[n]
		pfx := store.SortDisplay(s.Prefixes)
		if len(pfx) == 0 {
			pfx = []string{"(no prefix)"}
		}
		for i, c := range pfx {
			if i == 0 {
				def := ""
				if n == defaultScope {
					def = "yes"
				}
				out = append(out, fmt.Sprintf("%s|%s|%d|%s|%s", n, c, len(m.Members(n)), def, vendorSummary(s)))
			} else {
				out = append(out, "|"+c+"|||")
			}
		}
	}
	return out
}

// ScopeDevices is model_scope_devices: '<cidr>|<vendor>' per tagged
// address in display order; nothing for an unknown scope.
func (m *Model) ScopeDevices(scope string) []string {
	s := m.scopes[scope]
	if s == nil {
		return nil
	}
	devices := append([]Device(nil), s.Devices...)
	sort.SliceStable(devices, func(i, j int) bool {
		return store.DisplayKeyOf(devices[i].CIDR).Less(store.DisplayKeyOf(devices[j].CIDR))
	})
	var out []string
	for _, d := range devices {
		out = append(out, d.CIDR+"|"+d.Vendor)
	}
	return out
}

// DeviceProblems is the 'device-problems' view: what the store validator
// would say about tagged addresses with the scope's prefixes replaced by
// prefixCSV (the scope may be new) and, when tagCIDR is not empty, that
// address tagged tagVendor. Lines are 'scope|cidr|message'; ok is false
// when there is any.
func (m *Model) DeviceProblems(scope, prefixCSV, tagCIDR, tagVendor string) (lines []string, ok bool) {
	var trial []store.DeviceScope
	var prefixes []any
	for _, c := range strings.Split(prefixCSV, ",") {
		if c != "" {
			prefixes = append(prefixes, c)
		}
	}
	found := false
	for _, s := range m.Scopes {
		ds := store.DeviceScope{Name: s.Name}
		for _, c := range s.Prefixes {
			ds.Prefixes = append(ds.Prefixes, c)
		}
		for _, d := range s.Devices {
			ds.Devices = append(ds.Devices, d.CIDR)
		}
		if s.Name == scope {
			found = true
			ds.Prefixes = prefixes
			if tagCIDR != "" && !contains(ds.Devices, tagCIDR) {
				ds.Devices = append(ds.Devices, tagCIDR)
			}
		}
		trial = append(trial, ds)
	}
	if !found {
		ds := store.DeviceScope{Name: scope, Prefixes: prefixes}
		if tagCIDR != "" {
			ds.Devices = []string{tagCIDR}
		}
		trial = append(trial, ds)
	}
	_ = tagVendor // the vendor does not change where an address may be tagged
	for _, p := range store.DeviceProblems(trial) {
		lines = append(lines, p.Scope+"|"+p.CIDR+"|"+p.Msg)
	}
	return lines, len(lines) == 0
}

// VendorGaps is model_vendor_gaps: the scopes RADIUS serves that send no
// vendor attribute (none enabled, nothing tagged) and are not Linux-host
// scopes, by name. hosts maps a scope to the number of enrolled Linux
// hosts using it (field 4 of the host registry); a Linux-host scope is
// one with enrolled hosts whose every prefix is a single address, and no
// more prefixes than hosts.
func (m *Model) VendorGaps(hosts map[string]int) []string {
	var out []string
	for _, n := range m.ScopeNames() {
		s := m.scopes[n]
		if !s.ServedBy("radius") {
			continue
		}
		if len(s.VendorAttrs) > 0 || len(s.Devices) > 0 {
			continue
		}
		var pfx []store.Net
		for _, c := range s.Prefixes {
			if _, ok := store.CanonicalCIDR(c); ok {
				if net, ok := store.ParseNet(c); ok {
					pfx = append(pfx, net)
				}
			}
		}
		allHosts := true
		for _, p := range pfx {
			if !p.IsHost() {
				allHosts = false
			}
		}
		if hosts[n] > 0 && allHosts && len(pfx) <= hosts[n] {
			continue
		}
		out = append(out, n)
	}
	return out
}

// VendorRows is model_vendor_rows: '<scope>|<1 when RADIUS may serve it,
// else 0>|<enabled vendors>|<tagged vendors>|<tagged addresses>' by name.
func (m *Model) VendorRows() []string {
	var out []string
	for _, n := range m.ScopeNames() {
		s := m.scopes[n]
		served := "0"
		if s.ServedBy("radius") {
			served = "1"
		}
		var tagged []string
		for _, v := range names.KnownVendors {
			for _, d := range s.Devices {
				if d.Vendor == v {
					tagged = append(tagged, v)
					break
				}
			}
		}
		out = append(out, strings.Join([]string{n, served, strings.Join(s.VendorAttrs, ","),
			strings.Join(tagged, ","), strconv.Itoa(len(s.Devices))}, "|"))
	}
	return out
}

// ScopeRouting is the 'scope-routing' view: 'scope|cidr|users|yes' for
// every (scope, prefix) by display key, then scope name, then CIDR.
func (m *Model) ScopeRouting(defaultScope string) []string {
	type row struct {
		key         store.DisplayKey
		scope, cidr string
	}
	var rows []row
	for _, s := range m.Scopes {
		pfx := s.Prefixes
		if len(pfx) == 0 {
			pfx = []string{"(no prefix)"}
		}
		for _, c := range pfx {
			rows = append(rows, row{store.DisplayKeyOf(c), s.Name, c})
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.key.Less(b.key) || b.key.Less(a.key) {
			return a.key.Less(b.key)
		}
		if a.scope != b.scope {
			return a.scope < b.scope
		}
		return a.cidr < b.cidr
	})
	var out []string
	for _, r := range rows {
		def := ""
		if r.scope == defaultScope {
			def = "yes"
		}
		out = append(out, fmt.Sprintf("%s|%s|%d|%s", r.scope, r.cidr, len(m.Members(r.scope)), def))
	}
	return out
}

// Lookup codes of ScopeLookup (the exit status of 'tacctl scope lookup').
const (
	LookupFound    = 0
	LookupNotFound = 1
	LookupInvalid  = 2
)

// ScopeLookup is the 'scope-lookup' view ('tacctl scope lookup'): the
// scope tacquito would pick for an address or range (the first prefix in
// routing order that holds it), its vendor tag, and the shadowed scopes
// that also cover it. code is LookupFound, LookupNotFound (no scope owns
// it) or LookupInvalid (not an address or CIDR); the lines go to stdout
// in every case.
func (m *Model) ScopeLookup(query string) (lines []string, code int) {
	isNet := strings.Contains(query, "/")
	q, ok := store.ParseNet(query)
	if !ok {
		what := "address"
		if isNet {
			what = "network"
		}
		return []string{fmt.Sprintf("ERROR: invalid address or CIDR: %s does not appear to be an IPv4 or IPv6 %s",
			store.PyRepr(query), what)}, LookupInvalid
	}
	shown := q.String()
	if !isNet {
		shown = shown[:strings.LastIndexByte(shown, '/')]
	}
	type match struct {
		scope string
		net   store.Net
	}
	var matches []match
	for _, p := range m.routingPairs() {
		pnet, ok := store.ParseNet(p.cidr)
		if !ok {
			pnet, _ = store.ParseNet(strings.TrimSpace(p.cidr))
		}
		if pnet.Version() != q.Version() {
			continue
		}
		if (!isNet && pnet.Contains(q)) || (isNet && (pnet.Equal(q) || q.SubnetOf(pnet))) {
			matches = append(matches, match{p.scope, pnet})
		}
	}
	if len(matches) == 0 {
		if isNet {
			return []string{fmt.Sprintf("No scope owns %s — no prefix covers the full range.", shown)}, LookupNotFound
		}
		return []string{fmt.Sprintf("No scope owns %s — no prefix in any scope contains it.", shown)}, LookupNotFound
	}
	lines = append(lines, fmt.Sprintf("  %s -> scope '%s' (via prefix %s)", shown, matches[0].scope, matches[0].net.String()))
	var best *store.Net
	var bestVendor string
	for _, d := range m.scopes[matches[0].scope].Devices {
		tnet, ok := store.ParseNet(d.CIDR)
		if !ok || tnet.Version() != q.Version() {
			continue
		}
		if q.SubnetOf(tnet) && (best == nil || tnet.PrefixLen() > best.PrefixLen()) {
			t := tnet
			best, bestVendor = &t, d.Vendor
		}
	}
	if best != nil {
		lines = append(lines, fmt.Sprintf("  Tagged %s (scope devices entry %s): over RADIUS it gets that vendor's attribute only",
			bestVendor, best.String()))
	}
	if len(matches) > 1 {
		lines = append(lines, "", "  Also covered by (shadowed — the more specific prefix above wins):")
		for _, mt := range matches[1:] {
			lines = append(lines, fmt.Sprintf("    - scope '%s' via prefix %s", mt.scope, mt.net.String()))
		}
	}
	return lines, LookupFound
}

// ConfigShow is the 'config-show' view: 'scope=<name>|<secret length>|
// <users>' then 'prefix=<cidr>' lines per scope in routing order, the
// built-in groups' levels and classes (cisco_ro..juniper_rw, 'NOT FOUND'
// when missing), and the filters (allow=, deny=, ', '-joined).
func (m *Model) ConfigShow() []string {
	var out []string
	for _, n := range m.ScopesByRouting() {
		s := m.scopes[n]
		out = append(out, fmt.Sprintf("scope=%s|%d|%d", n, utf8.RuneCountInString(s.Secret), len(m.Members(n))))
		for _, c := range store.SortDisplay(s.Prefixes) {
			out = append(out, "prefix="+c)
		}
	}
	for _, row := range []struct{ key, group, field string }{
		{"cisco_ro", "readonly", "priv_lvl"}, {"cisco_op", "operator", "priv_lvl"},
		{"cisco_rw", "superuser", "priv_lvl"}, {"juniper_ro", "readonly", "juniper_class"},
		{"juniper_op", "operator", "juniper_class"}, {"juniper_rw", "superuser", "juniper_class"},
	} {
		val := "NOT FOUND"
		if g := m.groups[row.group]; g != nil {
			if row.field == "juniper_class" {
				if !g.classNull {
					val = g.JuniperClass
				}
			} else if g.privText != "" {
				val = g.privText
			}
		}
		out = append(out, row.key+"="+val)
	}
	out = append(out, "allow="+strings.Join(m.Filters.Allow, ", "), "deny="+strings.Join(m.Filters.Deny, ", "))
	return out
}

// LinuxUsers is the 'linux-users' view: 'name|priv_lvl' for the members
// of a scope that can log in (not the sink, not disabled), by name.
func (m *Model) LinuxUsers(scope string) []string {
	var out []string
	for _, n := range m.Members(scope) {
		u := m.users[n]
		if u.AccountingSink || u.IsDisabled() {
			continue
		}
		out = append(out, n+"|"+m.privOf(u))
	}
	return out
}

// Status is the 'status' view: key=value lines for 'tacctl status'
// (counts, prefix facts, placeholder/weak/empty scopes, orphaned scope
// references, password dates). minSecret is the weak-secret threshold.
func (m *Model) Status(minSecret int) []string {
	var allCIDRs, weak, placeholder, noPrefix []string
	for _, n := range m.ScopeNames() {
		s := m.scopes[n]
		if len(s.Prefixes) == 0 {
			noPrefix = append(noPrefix, n)
		}
		allCIDRs = append(allCIDRs, s.Prefixes...)
		switch l := utf8.RuneCountInString(s.Secret); {
		case strings.Contains(s.Secret, "REPLACE"):
			placeholder = append(placeholder, n)
		case l < minSecret:
			weak = append(weak, fmt.Sprintf("%s:%d", n, l))
		}
	}
	refs := 0
	unused := map[string]bool{}
	for _, s := range m.Scopes {
		unused[s.Name] = true
	}
	var orphans []string
	for _, n := range m.UserNames() {
		for _, s := range m.users[n].Scopes {
			refs++
			if m.scopes[s] != nil {
				delete(unused, s)
			} else {
				orphans = append(orphans, n+":"+s)
			}
		}
	}
	set := map[string]bool{}
	for _, c := range allCIDRs {
		set[c] = true
	}
	unrestricted := len(set) == len(rfc1918)
	for _, c := range rfc1918 {
		if !set[c] {
			unrestricted = false
		}
	}
	hasColon := func(list []string) string {
		for _, c := range list {
			if strings.Contains(c, ":") {
				return "1"
			}
		}
		return "0"
	}
	var empty []string
	for s := range unused {
		empty = append(empty, s)
	}
	sort.Strings(empty)
	out := []string{
		fmt.Sprintf("user_count=%d", len(m.Users)),
		fmt.Sprintf("scope_count=%d", len(m.Scopes)),
		fmt.Sprintf("prefix_count=%d", len(allCIDRs)),
		"prefix_unrestricted=" + map[bool]string{true: "1", false: "0"}[unrestricted],
		"prefix_has_v6=" + hasColon(allCIDRs),
		"allow_has_v6=" + hasColon(m.Filters.Allow),
		"placeholder_scopes=" + strings.Join(placeholder, ","),
		"weak_scopes=" + strings.Join(weak, ","),
		"empty_prefix_scopes=" + strings.Join(noPrefix, ","),
		fmt.Sprintf("total_refs=%d", refs),
		"empty_scopes=" + strings.Join(empty, ","),
	}
	for _, o := range orphans {
		out = append(out, "orphan="+o)
	}
	for _, n := range m.UserNames() {
		if pc := m.users[n].PasswordChanged; pc != "" {
			out = append(out, "pwdate="+n+"|"+pc)
		}
	}
	return out
}

// Validate is the 'validate' view ('config validate'): COUNT:users=,
// COUNT:groups=, COUNT:scopes= then one 'ERROR:<message>' line per
// problem. full adds the reference checks the store validator makes on a
// store, for a legacy model nothing has validated.
func (m *Model) Validate(full bool) []string {
	var errs []string
	if len(m.Users) == 0 {
		errs = append(errs, "No users defined (tacquito refuses to serve such a config)")
	}
	if len(m.Scopes) == 0 {
		errs = append(errs, "No scopes defined (tacquito refuses to serve such a config)")
	}
	for _, n := range m.ScopeNames() {
		s := m.scopes[n]
		if strings.Contains(s.Secret, "REPLACE") {
			errs = append(errs, fmt.Sprintf("Shared secret contains placeholder value (scope '%s')", n))
		}
		if full && s.Secret == "" {
			errs = append(errs, fmt.Sprintf("Scope '%s' has no shared secret", n))
		}
		if full && len(s.Prefixes) == 0 {
			errs = append(errs, fmt.Sprintf("Scope '%s' has no prefixes", n))
		}
	}
	if full {
		for _, n := range m.UserNames() {
			u := m.users[n]
			if contains(names.ReservedUsers, n) {
				errs = append(errs, fmt.Sprintf(`User "%s" uses a reserved name (remove with: tacctl user remove %s)`, n, n))
			}
			if m.groups[u.Group] == nil {
				g := u.Group
				if g == "" {
					g = "None" // str() of a null group
				}
				errs = append(errs, fmt.Sprintf("User '%s' is in nonexistent group '%s'", n, g))
			}
			for _, s := range u.Scopes {
				if m.scopes[s] == nil {
					errs = append(errs, fmt.Sprintf("User '%s' references nonexistent scope '%s'", n, s))
				}
			}
		}
	}
	out := []string{
		fmt.Sprintf("COUNT:users=%d", len(m.Users)),
		fmt.Sprintf("COUNT:groups=%d", len(m.Groups)),
		fmt.Sprintf("COUNT:scopes=%d", len(m.Scopes)),
	}
	for _, e := range errs {
		out = append(out, "ERROR:"+e)
	}
	return out
}

// View runs a view by its model.sh name with string arguments, as
// _model_view did: the lines, the exit status (has: 0/1; user-info: 1 for
// an unknown user; device-problems: 1 when there is any; scope-lookup:
// 0/1/2), and an error for an unknown view or missing arguments.
func (m *Model) View(view string, args ...string) (lines []string, code int, err error) {
	need := func(n int) error {
		if len(args) < n {
			return &store.Error{Msg: fmt.Sprintf("internal: view %s needs %d argument(s)", view, n)}
		}
		return nil
	}
	arg := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}
	switch view {
	case "has":
		if err := need(2); err != nil {
			return nil, 1, err
		}
		if m.has(args[0], args[1]) {
			return nil, 0, nil
		}
		return nil, 1, nil
	case "user-rows":
		return m.UserRows(), 0, nil
	case "user-info":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		l, ok := m.UserInfo(args[0])
		if !ok {
			return nil, 1, nil
		}
		return l, 0, nil
	case "user-privlvl":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		if p := m.UserPrivLvl(args[0]); p != "" {
			return []string{p}, 0, nil
		}
		return nil, 0, nil
	case "group-rows":
		return m.GroupRows(), 0, nil
	case "group-users":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		return m.GroupUsers(args[0]), 0, nil
	case "group-info":
		return m.GroupInfo(), 0, nil
	case "scope-names":
		return m.ScopesByRouting(), 0, nil
	case "scope-prefixes":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		return m.ScopePrefixes(args[0]), 0, nil
	case "scope-users":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		return m.Members(args[0]), 0, nil
	case "prefix-owner":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		if o := m.PrefixOwner(args[0]); o != "" {
			return []string{o}, 0, nil
		}
		return nil, 0, nil
	case "scope-rows":
		return m.ScopeRows(arg(0)), 0, nil
	case "scope-devices":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		return m.ScopeDevices(args[0]), 0, nil
	case "device-problems":
		if err := need(2); err != nil {
			return nil, 1, err
		}
		tagC, tagV := "", ""
		if len(args) > 3 {
			tagC, tagV = args[2], args[3]
		}
		l, ok := m.DeviceProblems(args[0], args[1], tagC, tagV)
		if !ok {
			return l, 1, nil
		}
		return l, 0, nil
	case "vendor-gaps":
		hosts := map[string]int{}
		for _, a := range args {
			i := strings.LastIndexByte(a, '=')
			n, err := strconv.Atoi(a[i+1:])
			if err != nil {
				return nil, 1, &store.Error{Msg: fmt.Sprintf("internal: vendor-gaps: bad count %s", store.PyRepr(a))}
			}
			name := ""
			if i >= 0 {
				name = a[:i]
			}
			hosts[name] = n
		}
		return m.VendorGaps(hosts), 0, nil
	case "vendor-rows":
		return m.VendorRows(), 0, nil
	case "scope-routing":
		return m.ScopeRouting(arg(0)), 0, nil
	case "scope-lookup":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		l, code := m.ScopeLookup(args[0])
		return l, code, nil
	case "config-show":
		return m.ConfigShow(), 0, nil
	case "linux-users":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		return m.LinuxUsers(args[0]), 0, nil
	case "status":
		if err := need(1); err != nil {
			return nil, 1, err
		}
		n, err := strconv.Atoi(strings.TrimSpace(args[0]))
		if err != nil {
			return nil, 1, &store.Error{Msg: fmt.Sprintf("internal: status: bad length %s", store.PyRepr(args[0]))}
		}
		return m.Status(n), 0, nil
	case "validate":
		return m.Validate(arg(0) == "full"), 0, nil
	}
	return nil, 1, &store.Error{Msg: fmt.Sprintf("internal: unknown view %s", store.PyRepr(view))}
}

// has is the 'has' view: membership, without Exists' empty-name rule
// (which is the bash wrappers').
func (m *Model) has(kind, name string) bool {
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
