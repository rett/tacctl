package model_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

// Ports of tests/unit/model.bats (store mode) and tests/unit/yaml.bats
// (store mode: load_fixture tacquito.multiscope.yaml seeds exactly
// store.multiscope.yaml). The legacy-loader halves of both files wait for
// model.LegacyLoad (WP1.4b).

type env struct {
	t    *testing.T
	path string
}

func newEnv(t *testing.T, fixture string) *env {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, path: filepath.Join(dir, "store.yaml")}
	if fixture != "" {
		if err := os.WriteFile(e.path, readFile(t, fixtures+fixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) model() *model.Model {
	e.t.Helper()
	_, m := load(e.t, e.path)
	return m
}

func (e *env) get(kind string, args ...string) (string, int) {
	e.t.Helper()
	s, _ := load(e.t, e.path)
	lines, code, err := model.Get(s, kind, args...)
	if err != nil {
		return store.Report(err), 1
	}
	return strings.Join(lines, "\n"), code
}

func (e *env) view(name string, args ...string) (string, int) {
	e.t.Helper()
	lines, code, err := e.model().View(name, args...)
	if err != nil {
		return store.Report(err), 1
	}
	return strings.Join(lines, "\n"), code
}

func (e *env) mutate(fn func(*store.Store) error) {
	e.t.Helper()
	if _, err := store.Mutate(e.path, store.MutateOptions{}, fn); err != nil {
		e.t.Fatal(store.Report(err))
	}
}

func want(t *testing.T, got string, code int, wantOut string, wantCode int) {
	t.Helper()
	if got != wantOut || code != wantCode {
		t.Errorf("got (status %d):\n%s\nwant (status %d):\n%s", code, got, wantCode, wantOut)
	}
}

func lines(s ...string) string { return strings.Join(s, "\n") }

// --- model.bats ---------------------------------------------------------------

func TestMode(t *testing.T) {
	e := newEnv(t, "")
	if m := model.Mode(e.path); m != "legacy" {
		t.Errorf("no store: %s", m)
	}
	e = newEnv(t, "store.minimal.yaml")
	if m := model.Mode(e.path); m != "store" {
		t.Errorf("store: %s", m)
	}
}

func TestOptionalFieldsDefaulted(t *testing.T) {
	e := newEnv(t, "")
	body := `version: 1
groups:
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  helpdesk: {priv_lvl: 5, juniper_class: HD-CLASS}
users:
  alice: {group: helpdesk, scopes: [lab], hash: null, disabled: true}
scopes:
  lab: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret"}
`
	if err := os.WriteFile(e.path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := e.get("groups", "helpdesk", "builtin")
	want(t, out, code, "false", 0)
	out, code = e.get("users", "alice", "accounting_sink")
	want(t, out, code, "false", 0)
	out, code = e.get("users", "alice", "password_changed")
	want(t, out, code, "", 0)
	out, code = e.get("scopes", "lab", "protocols")
	want(t, out, code, "", 0)
	out, code = e.get("filters")
	want(t, out, code, `{"allow": [], "deny": []}`, 0)
}

func TestUnparseableStore(t *testing.T) {
	e := newEnv(t, "")
	if err := os.WriteFile(e.path, []byte("version: 1\nscopes: {lab: {secret: \"leaky-secret-0123456789\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := model.LoadStore(e.path)
	if err == nil {
		t.Fatal("loaded")
	}
	out := store.Report(err)
	if !strings.Contains(out, "store.yaml") || strings.Contains(out, "leaky-secret") {
		t.Errorf("%s", out)
	}
}

func TestAccessorListsSorted(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	out, code := e.get("users")
	want(t, out, code, lines("alice", "bob", "carol"), 0)
	out, code = e.get("groups")
	want(t, out, code, lines("operator", "readonly", "superuser"), 0)
	out, code = e.get("scopes")
	want(t, out, code, lines("dmz", "lab", "prod", "prod-inner"), 0)
}

func TestAccessorEntryAndField(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	out, code := e.get("scopes", "lab")
	want(t, out, code, `{"name": "lab", "prefixes": ["172.16.0.0/12", "192.168.0.0/16"], "protocols": null, "secret": "lab-secret-0123456789abcdef"}`, 0)
	out, code = e.get("scopes", "lab", "prefixes")
	want(t, out, code, lines("172.16.0.0/12", "192.168.0.0/16"), 0)
	out, code = e.get("users", "carol", "group")
	want(t, out, code, "readonly", 0)
	out, code = e.get("users", "carol", "disabled")
	want(t, out, code, "false", 0)
	out, code = e.get("groups", "superuser")
	want(t, out, code, `{"builtin": true, "juniper_class": "RW-CLASS", "name": "superuser", "priv_lvl": 15}`, 0)
}

func TestAccessorMissingEntry(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	for _, a := range [][]string{{"users", "nobody"}, {"users", "nobody", "group"}, {"groups", "nogroup"}, {"scopes", "noscope"}, {"scopes", "noscope", "secret"}} {
		out, code := e.get(a[0], a[1:]...)
		want(t, out, code, "", 1)
	}
}

func TestAccessorUnknownField(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	out, code := e.get("users", "alice", "shoe_size")
	want(t, out, code, "tacctl store: user: unknown field 'shoe_size'", 1)
	out, code = e.get("filters", "maybe")
	want(t, out, code, "tacctl store: filters: unknown list 'maybe'", 1)
}

func TestReloadSeesWrites(t *testing.T) {
	// model.bats "cache: model_load primes it; a store write invalidates
	// it": Go has no cross-call cache (one load per command); a load after
	// a write sees the write.
	e := newEnv(t, "store.multiscope.yaml")
	e.mutate(func(s *store.Store) error { return s.GroupSet("superuser", "juniper_class=YY-CLASS") })
	out, code := e.get("groups", "superuser", "juniper_class")
	want(t, out, code, "YY-CLASS", 0)
}

// --- yaml.bats ------------------------------------------------------------------

func TestScopesAndExists(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	m := e.model()
	if got := strings.Join(m.ScopeNames(), " "); got != "dmz lab prod prod-inner" {
		t.Error(got)
	}
	for _, c := range []struct {
		kind, name string
		ok         bool
	}{
		{"scopes", "prod", true}, {"scopes", "lab", true}, {"scopes", "nonexistent", false}, {"scopes", "", false},
		{"users", "alice", true}, {"users", "nobody", false}, {"users", "", false},
		{"groups", "operator", true}, {"groups", "nosuch", false}, {"groups", "", false},
	} {
		if m.Exists(c.kind, c.name) != c.ok {
			t.Errorf("Exists(%s, %q) != %v", c.kind, c.name, c.ok)
		}
	}
}

func TestScopePrefixes(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	m := e.model()
	if got := lines(m.ScopePrefixes("prod")...); got != "10.0.0.0/8" {
		t.Error(got)
	}
	// Longest prefix first: /16 before /12.
	if got := lines(m.ScopePrefixes("lab")...); got != lines("192.168.0.0/16", "172.16.0.0/12") {
		t.Error(got)
	}
	if got := m.ScopePrefixes("nonexistent"); len(got) != 0 {
		t.Error(got)
	}
	// The stored order is the render order.
	out, code := e.get("scopes", "lab", "prefixes")
	want(t, out, code, lines("172.16.0.0/12", "192.168.0.0/16"), 0)
}

func TestScopeSecret(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	out, code := e.get("scopes", "prod", "secret")
	want(t, out, code, "prod-secret-0123456789abcdef", 0)
	out, code = e.get("scopes", "lab", "secret")
	want(t, out, code, "lab-secret-0123456789abcdef", 0)
}

func TestPrefixOwner(t *testing.T) {
	m := newEnv(t, "store.multiscope.yaml").model()
	for in, owner := range map[string]string{
		"10.0.0.0/8": "prod", "10.10.99.0/24": "prod-inner", "10.10.99.5/24": "prod-inner",
		"8.8.8.0/24": "", "10.10.0.0/16": "", "": "", "not-a-cidr": "",
	} {
		if got := m.PrefixOwner(in); got != owner {
			t.Errorf("PrefixOwner(%q) = %q, want %q", in, got, owner)
		}
	}
}

func TestUserScopesAndMembers(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	out, code := e.get("users", "alice", "scopes")
	want(t, out, code, lines("prod", "lab"), 0)
	out, code = e.get("users", "carol", "scopes")
	want(t, out, code, lines("lab", "dmz"), 0)
	out, code = e.get("users", "nobody", "scopes")
	want(t, out, code, "", 1)
	m := e.model()
	if got := lines(m.Members("lab")...); got != lines("alice", "bob", "carol") {
		t.Error(got)
	}
	if got := lines(m.Members("prod")...); got != "alice" {
		t.Error(got)
	}
	if len(m.Members("dmz")) != 1 || len(m.Members("prod-inner")) != 0 {
		t.Error("member counts")
	}
}

func TestGroupPrivLvl(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	for g, p := range map[string]string{"readonly": "1", "operator": "7", "superuser": "15"} {
		out, code := e.get("groups", g, "priv_lvl")
		want(t, out, code, p, 0)
	}
	out, code := e.get("groups", "nonexistent", "priv_lvl")
	want(t, out, code, "", 1)
	if got := lines(e.model().GroupNames()...); got != lines("operator", "readonly", "superuser") {
		t.Error(got)
	}
}

func TestUserRows(t *testing.T) {
	m := newEnv(t, "store.multiscope.yaml").model()
	if got := lines(m.UserRows()...); got != lines(
		"alice|superuser|active|unknown|prod,lab",
		"bob|operator|active|unknown|lab",
		"carol|readonly|active|unknown|lab,dmz") {
		t.Error(got)
	}
}

func TestUserInfo(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	m := e.model()
	got, ok := m.UserInfo("alice")
	if !ok || lines(got...) != lines("group=superuser", "status=active", "password_changed=unknown",
		"priv_lvl=15", "juniper_class=RW-CLASS", "hash_type=$2b$12$", "has_hash=1", "scope=prod|1", "scope=lab|1") {
		t.Error(got)
	}
	if strings.Contains(lines(got...), m.User("alice").Hash) {
		t.Error("hash printed")
	}
	if got, ok := m.UserInfo("nobody"); ok || len(got) != 0 {
		t.Error(got)
	}
}

func TestUserPrivLvl(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	m := e.model()
	if m.UserPrivLvl("bob") != "7" || m.UserPrivLvl("nobody") != "" {
		t.Error("priv")
	}
	e.mutate(func(s *store.Store) error { return s.UserSet("bob", "disabled=true") })
	if p := e.model().UserPrivLvl("bob"); p != "" {
		t.Error(p)
	}
}

func TestGroupRows(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	if got := lines(e.model().GroupRows()...); got != lines("superuser|15|RW-CLASS|1", "operator|7|OP-CLASS|1", "readonly|1|RO-CLASS|1") {
		t.Error(got)
	}
	e.mutate(func(s *store.Store) error { return s.GroupSet("alpha", "priv_lvl=7", "juniper_class=A-CLASS") })
	e.mutate(func(s *store.Store) error { return s.GroupSet("zeta", "priv_lvl=7", "juniper_class=Z-CLASS") })
	if got := lines(e.model().GroupRows()...); got != lines("superuser|15|RW-CLASS|1", "zeta|7|Z-CLASS|0",
		"operator|7|OP-CLASS|1", "alpha|7|A-CLASS|0", "readonly|1|RO-CLASS|1") {
		t.Error(got)
	}
}

func TestGroupInfo(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	e.mutate(func(s *store.Store) error { return s.GroupSet("zeta", "priv_lvl=3", "juniper_class=Z-CLASS") })
	e.mutate(func(s *store.Store) error { return s.GroupSet("alpha", "priv_lvl=9", "juniper_class=A-CLASS") })
	if got := lines(e.model().GroupInfo()...); got != lines("readonly|1|RO-CLASS", "operator|7|OP-CLASS",
		"superuser|15|RW-CLASS", "alpha|9|A-CLASS", "zeta|3|Z-CLASS") {
		t.Error(got)
	}
}

func TestGroupUsers(t *testing.T) {
	m := newEnv(t, "store.multiscope.yaml").model()
	if got := lines(m.GroupUsers("operator")...); got != "bob" {
		t.Error(got)
	}
	if got := m.GroupUsers("nosuch"); len(got) != 0 {
		t.Error(got)
	}
}

func TestScopeRowsAndRouting(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	out, code := e.view("scope-rows", "lab")
	want(t, out, code, lines("prod-inner|10.10.99.0/24|0||", "prod|10.0.0.0/8|1||", "lab|192.168.0.0/16|3|yes|",
		"|172.16.0.0/12|||", "dmz|203.0.113.0/24|1||"), 0)
	out, code = e.view("scope-routing", "lab")
	want(t, out, code, lines("prod-inner|10.10.99.0/24|0|", "dmz|203.0.113.0/24|1|", "lab|192.168.0.0/16|3|yes",
		"lab|172.16.0.0/12|3|yes", "prod|10.0.0.0/8|1|"), 0)
}

func TestViewsNeverPrintSecretsOrHashes(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	m := e.model()
	secret, hash := m.Scope("lab").Secret, m.User("alice").Hash
	for _, v := range [][]string{{"user-rows"}, {"user-info", "alice"}, {"group-rows"}, {"group-info"},
		{"scope-rows", "lab"}, {"scope-routing", "lab"}, {"scope-lookup", "10.10.99.1"}, {"config-show"},
		{"status", "16"}, {"linux-users", "lab"}, {"validate", "full"}, {"scope-devices", "lab"},
		{"vendor-rows"}, {"vendor-gaps"}, {"device-problems", "lab", "192.168.0.0/16"}} {
		out, code := e.view(v[0], v[1:]...)
		if code != 0 {
			t.Errorf("%v: status %d", v, code)
		}
		if strings.Contains(out, secret) || strings.Contains(out, hash) {
			t.Errorf("%v prints a secret or hash", v)
		}
	}
}

func TestUnknownView(t *testing.T) {
	out, code := newEnv(t, "store.multiscope.yaml").view("no-such-view")
	want(t, out, code, "tacctl store: internal: unknown view 'no-such-view'", 1)
}

func TestScopeLookup(t *testing.T) {
	// status_and_scope_lookup.bats, on the multiscope store.
	m := newEnv(t, "store.multiscope.yaml").model()
	out, code := m.ScopeLookup("10.10.99.42")
	want(t, lines(out...), code, lines("  10.10.99.42 -> scope 'prod-inner' (via prefix 10.10.99.0/24)", "",
		"  Also covered by (shadowed — the more specific prefix above wins):", "    - scope 'prod' via prefix 10.0.0.0/8"), 0)
	out, code = m.ScopeLookup("192.168.0.0/24")
	want(t, lines(out...), code, "  192.168.0.0/24 -> scope 'lab' (via prefix 192.168.0.0/16)", 0)
	out, code = m.ScopeLookup("8.8.8.8")
	want(t, lines(out...), code, "No scope owns 8.8.8.8 — no prefix in any scope contains it.", 1)
	out, code = m.ScopeLookup("not-an-address")
	want(t, lines(out...), code, "ERROR: invalid address or CIDR: 'not-an-address' does not appear to be an IPv4 or IPv6 address", 2)
}

func TestVendorViewsAndDevices(t *testing.T) {
	e := newEnv(t, "store.multiscope.yaml")
	e.mutate(func(s *store.Store) error {
		return s.ScopeSet("prod", "vendor_attrs=wti,cisco,wti", "devices=10.1.2.3=wti,10.2.0.0/16=juniper,10.0.5.5/24=cisco")
	})
	m := e.model()
	if got := lines(m.ScopeDevices("prod")...); got != lines("10.1.2.3/32|wti", "10.0.5.0/24|cisco", "10.2.0.0/16|juniper") {
		t.Error(got)
	}
	if got := lines(m.VendorRows()...); got != lines("dmz|1|||0", "lab|1|||0", "prod|1|cisco,wti|cisco,juniper,wti|3", "prod-inner|1|||0") {
		t.Error(got)
	}
	if got := lines(m.VendorGaps(map[string]int{"dmz": 1})...); got != lines("dmz", "lab", "prod-inner") {
		t.Error(got)
	}
	got, ok := m.DeviceProblems("lab", "192.168.0.0/16", "10.10.99.1/32", "wti")
	if ok || lines(got...) != "lab|10.10.99.1/32|scope 'lab': devices: 10.10.99.1/32 is not inside a prefix of the scope" {
		t.Error(got)
	}
}

func TestTypedModel(t *testing.T) {
	_, m := load(t, fixtures+"store.radius.yaml")
	if u := m.User("root"); u == nil || !u.AccountingSink || !u.IsDisabled() || u.Hash != "" {
		t.Errorf("root: %+v", u)
	}
	if u := m.User("carol"); u == nil || !u.IsDisabled() || u.Hash == "" {
		t.Errorf("carol: %+v", u)
	}
	if g := m.Group("netops"); g == nil || g.PrivLvl == nil || *g.PrivLvl != 10 || g.Builtin {
		t.Errorf("netops: %+v", g)
	}
	if s := m.Scope("wifi"); s == nil || s.ServedBy("tacacs") || !s.ServedBy("radius") {
		t.Errorf("wifi: %+v", s)
	}
	if s := m.Scope("lab"); s == nil || !s.ServedBy("tacacs") || s.Secret != `it's a "lab" secret ${confdir} #1` {
		t.Errorf("lab: %+v", s)
	}
	if got := strings.Join(m.Filters.Deny, ","); got != "10.66.0.0/16,fd00:10::bad/128" {
		t.Error(got)
	}
	if got := strings.Join(m.UserNames(), ","); got != "alice,bob,carol,dave,erin,root" {
		t.Error(got)
	}
}
