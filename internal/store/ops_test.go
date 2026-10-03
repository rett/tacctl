package store_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/hash"
	"github.com/rett/tacctl/internal/store"
)

// Ports of tests/unit/store.bats: users, groups, scopes, filters, vendor
// attributes; plus SeedFresh (store_seed_fresh).

func TestUserSetCreateWithHash(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	raw := "$2b$12$" + strings.Repeat("A", 53)
	e.mustMutate(userSet("alice", "group=operator", "scopes=lab", "hash="+raw, "password_changed=2026-09-30"))
	equal(t, e.mustGet("users", "alice"), `{"accounting_sink": false, "disabled": false, "group": "operator", "hash": "`+
		hashA+`", "name": "alice", "password_changed": "2026-09-30", "scopes": ["lab"]}`)
}

func TestUserSetCreateWithoutHash(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	contains(t, e.mutate(userSet("alice", "scopes=lab")), "group is required when creating a user")
	e.mustMutate(userSet("alice", "group=readonly"))
	equal(t, e.mustGet("users", "alice", "disabled"), "true")
	equal(t, e.mustGet("users", "alice", "hash"), "")
}

func TestUserSetUpdate(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("alice", "disabled=true"))
	equal(t, e.mustGet("users", "alice", "disabled"), "true")
	equal(t, e.mustGet("users", "alice", "group"), "superuser")
	equal(t, e.mustGet("users", "alice", "scopes"), "prod\nlab")
	e.mustMutate(userSet("alice", "scopes=dmz,lab,dmz", "password_changed=today"))
	equal(t, e.mustGet("users", "alice", "scopes"), "dmz\nlab")
	equal(t, e.mustGet("users", "alice", "password_changed"), e.now.Format("2006-01-02"))
	e.mustMutate(userSet("alice", "scopes=", "password_changed=null"))
	equal(t, e.mustGet("users", "alice", "scopes"), "")
	equal(t, e.mustGet("users", "alice", "password_changed"), "")
}

func TestUserSetRefusals(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	msg := e.mutate(userSet("alice", "hash=definitely-not-bcrypt"))
	contains(t, msg, "hash is not a bcrypt hash")
	refute(t, msg, "definitely-not-bcrypt")
	contains(t, e.mutate(userSet("alice", "hash="+hash.DisabledMarkerHex)), "use disabled=true")
	contains(t, e.mutate(userSet("alice", "shoe_size=9")), "unknown field 'shoe_size'")
	contains(t, e.mutate(userSet("alice", "group")), "expected <field>=<value>, got 'group'")
	contains(t, e.mutate(userSet("alice", "disabled=yes")), "disabled must be true or false")
	contains(t, e.mutate(userSet("", "group=readonly")), "user name required")
}

func TestUserSetRootIsTheSink(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	e.mustMutate(userSet("root", "group=readonly", "scopes=lab"))
	equal(t, e.mustGet("users", "root", "accounting_sink"), "true")
	equal(t, e.mustGet("users", "root", "disabled"), "true")
	contains(t, e.mutate(userSet("root", "hash="+hashA)), "accounting sink")
	contains(t, e.mutate(userSet("root", "disabled=false")), "the accounting sink must stay disabled")
}

func TestUserSetBadNames(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	contains(t, e.mutate(userSet("tacquito", "group=readonly")), "reserved name")
	contains(t, e.mutate(userSet("bad name", "group=readonly")), "invalid name")
}

func TestUserDelAndRename(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(func(s *store.Store) error { return s.UserRename("bob", "robert") })
	if _, code := e.get("users", "bob"); code != 1 {
		t.Error("bob still exists")
	}
	equal(t, e.mustGet("users", "robert", "group"), "operator")
	contains(t, e.mutate(func(s *store.Store) error { return s.UserRename("robert", "alice") }), "user 'alice' already exists")
	e.mustMutate(func(s *store.Store) error { return s.UserDel("robert") })
	equal(t, e.mustGet("users"), "alice\ncarol")
	contains(t, e.mutate(func(s *store.Store) error { return s.UserDel("robert") }), "user 'robert' does not exist")
}

func TestUserRenameToRootBecomesTheSink(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(userSet("bob", "hash=null", "disabled=true"))
	e.mustMutate(func(s *store.Store) error { return s.UserRename("bob", "root") })
	equal(t, e.mustGet("users", "root", "accounting_sink"), "true")
}

func TestGroupSet(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	contains(t, e.mutate(groupSet("helpdesk", "priv_lvl=5")), "juniper_class required when creating a group")
	equal(t, e.mutate(groupSet("helpdesk")), "tacctl store: group 'helpdesk': priv_lvl and juniper_class required when creating a group")
	e.mustMutate(groupSet("helpdesk", "priv_lvl=5", "juniper_class=HELPDESK-CLASS"))
	equal(t, e.mustGet("groups", "helpdesk"), `{"builtin": false, "juniper_class": "HELPDESK-CLASS", "name": "helpdesk", "priv_lvl": 5}`)
	e.mustMutate(groupSet("helpdesk", "priv_lvl=6"))
	equal(t, e.mustGet("groups", "helpdesk", "priv_lvl"), "6")
	contains(t, e.mutate(groupSet("helpdesk", "priv_lvl=16")), "priv_lvl must be 0-15")
	contains(t, e.mutate(groupSet("helpdesk", "priv_lvl=-1")), "priv_lvl must be 0-15")
	contains(t, e.mutate(groupSet("helpdesk", "priv_lvl=99999999999999999999999")), "priv_lvl must be 0-15")
	contains(t, e.mutate(groupSet("helpdesk", "juniper_class=BAD CLASS")), "juniper_class contains characters")
	contains(t, e.mutate(groupSet("Helpdesk", "priv_lvl=5", "juniper_class=X")), "invalid name")
}

func TestGroupSetBuiltinKeepsFlag(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	e.mustMutate(groupSet("operator", "priv_lvl=8"))
	equal(t, e.mustGet("groups", "operator"), `{"builtin": true, "juniper_class": "OP-CLASS", "name": "operator", "priv_lvl": 8}`)
}

func TestGroupDel(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	contains(t, e.mutate(func(s *store.Store) error { return s.GroupDel("superuser") }), "cannot remove built-in group 'superuser'")
	e.mustMutate(groupSet("helpdesk", "priv_lvl=5", "juniper_class=HELPDESK-CLASS"))
	e.mustMutate(userSet("bob", "group=helpdesk"))
	contains(t, e.mutate(func(s *store.Store) error { return s.GroupDel("helpdesk") }), "1 user(s) are assigned to it")
	e.mustMutate(userSet("bob", "group=operator"))
	e.mustMutate(func(s *store.Store) error { return s.GroupDel("helpdesk") })
	if _, code := e.get("groups", "helpdesk"); code != 1 {
		t.Error("helpdesk still exists")
	}
	contains(t, e.mutate(func(s *store.Store) error { return s.GroupDel("helpdesk") }), "does not exist")
}

func TestScopeSetCreate(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	contains(t, e.mutate(scopeSet("prod", "prefixes=10.0.0.0/8")), "secret required when creating a scope")
	e.mustMutate(scopeSet("prod", "prefixes=2001:DB8::/32, 10.0.0.0/8,10.10.99.7/24,10.0.0.0/8", "secret=prod-secret-0123456789"))
	equal(t, e.mustGet("scopes", "prod", "prefixes"), "10.10.99.0/24\n10.0.0.0/8\n2001:db8::/32")
	equal(t, e.mustGet("scopes", "prod", "protocols"), "")
}

func TestScopeSetOnePrefixOneScope(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	contains(t, e.mutate(scopeSet("dmz", "prefixes=203.0.113.0/24,10.10.99.0/24")), "prefix 10.10.99.0/24 is claimed by scopes")
	equal(t, e.mutate(scopeSet("dmz", "prefixes=not-a-cidr")), "tacctl store: scope 'dmz': invalid CIDR 'not-a-cidr'")
	contains(t, e.mutate(scopeSet("dmz", "prefixes=")), "must list at least one CIDR")
}

func TestScopeSetProtocols(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	e.mustMutate(scopeSet("lab", "protocols=radius"))
	equal(t, e.mustGet("scopes", "lab", "protocols"), "radius")
	if n := strings.Count(string(readFile(t, e.path)), "protocols: [radius]"); n != 1 {
		t.Errorf("protocols lines: %d", n)
	}
	if e.mutate(scopeSet("lab", "protocols=ldap")) == "" {
		t.Error("ldap accepted")
	}
	e.mustMutate(scopeSet("lab", "protocols=null"))
	equal(t, e.mustGet("scopes", "lab", "protocols"), "")
	if strings.Contains(string(readFile(t, e.path)), "protocols") {
		t.Error("protocols still written")
	}
}

func TestScopeDel(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	contains(t, e.mutate(func(s *store.Store) error { return s.ScopeDel("lab", false) }), "3 user(s) still reference it")
	e.mustMutate(func(s *store.Store) error { return s.ScopeDel("lab", true) })
	if _, code := e.get("scopes", "lab"); code != 1 {
		t.Error("lab still exists")
	}
	equal(t, e.mustGet("users", "alice", "scopes"), "prod")
	equal(t, e.mustGet("users", "bob", "scopes"), "")
	e.mustMutate(func(s *store.Store) error { return s.ScopeDel("prod-inner", false) })
	equal(t, e.mustGet("scopes"), "dmz\nprod")
}

func TestScopeRename(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(func(s *store.Store) error { return s.ScopeRename("lab", "bench") })
	equal(t, e.mustGet("scopes"), "bench\ndmz\nprod\nprod-inner")
	equal(t, e.mustGet("users", "alice", "scopes"), "prod\nbench")
	contains(t, e.mutate(func(s *store.Store) error { return s.ScopeRename("bench", "prod") }), "scope 'prod' already exists")
}

func TestFiltersSet(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.minimal.yaml")
	setF := func(which, v string) func(*store.Store) error {
		return func(s *store.Store) error { return s.FiltersSet(which, v) }
	}
	e.mustMutate(setF("allow", "192.168.0.0/16,10.5.5.5/8"))
	equal(t, e.mustGet("filters", "allow"), "10.0.0.0/8\n192.168.0.0/16")
	equal(t, e.mustGet("filters"), `{"allow": ["10.0.0.0/8", "192.168.0.0/16"], "deny": []}`)
	e.mustMutate(setF("allow", ""))
	equal(t, e.mustGet("filters", "allow"), "")
	equal(t, e.mutate(setF("maybe", "10.0.0.0/8")), "tacctl store: usage: allow|deny <cidr>[,<cidr>...]")
	contains(t, e.mutate(setF("deny", "nonsense")), "invalid CIDR")
}

func TestScopeVendorFields(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(scopeSet("prod", "vendor_attrs=wti,cisco,wti", "devices=10.1.2.3=wti,10.2.0.0/16=juniper,10.0.5.5/24=cisco"))
	equal(t, e.mustGet("scopes", "prod", "vendor_attrs"), "cisco\nwti")
	equal(t, e.mustGet("scopes", "prod", "devices"), "10.0.5.0/24 cisco\n10.1.2.3/32 wti\n10.2.0.0/16 juniper")
	e.mustMutate(scopeSet("prod", "protocols=radius"))
	text := string(readFile(t, e.path))
	i := strings.Index(text, "  prod:\n")
	block := strings.Split(text[i:], "\n")
	equal(t, block[1], "    prefixes: [10.0.0.0/8]")
	contains(t, block[2], "    secret: ")
	equal(t, block[3], "    protocols: [radius]")
	equal(t, block[4], "    vendor_attrs: [cisco, wti]")
	equal(t, block[5], "    devices: {10.0.5.0/24: cisco, 10.1.2.3/32: wti, 10.2.0.0/16: juniper}")
	contains(t, e.mutate(scopeSet("prod", "devices=10.1.2.3/32")), "devices: invalid entry '10.1.2.3/32' (expected <cidr>=<vendor>)")
	if e.mutate(scopeSet("prod", "vendor_attrs=arista")) == "" {
		t.Error("arista accepted")
	}
	e.mustMutate(scopeSet("prod", "vendor_attrs=null", "devices=null"))
	text = string(readFile(t, e.path))
	if strings.Contains(text, "vendor_attrs") || strings.Contains(text, "devices") {
		t.Error("vendor fields still written")
	}
	equal(t, e.mustGet("scopes", "prod", "vendor_attrs"), "")
}

func TestScopeWithoutVendorFieldsReadsAsBefore(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	out := e.mustGet("scopes", "lab")
	refute(t, out, "vendor_attrs")
	refute(t, out, "devices")
	e.mustMutate(scopeSet("lab", "vendor_attrs=cisco"))
	e.mustMutate(scopeSet("lab", "vendor_attrs=null"))
	refute(t, e.mustGet("scopes", "lab"), "vendor_attrs")
}

func TestVendorFieldsGoWithTheScope(t *testing.T) {
	e := newEnv(t)
	e.useFixture("store.multiscope.yaml")
	e.mustMutate(scopeSet("dmz", "vendor_attrs=juniper", "devices=203.0.113.9=wti"))
	e.mustMutate(func(s *store.Store) error { return s.ScopeRename("dmz", "edge") })
	equal(t, e.mustGet("scopes", "edge", "devices"), "203.0.113.9/32 wti")
	e.mustMutate(func(s *store.Store) error { return s.ScopeDel("edge", true) })
	refute(t, string(readFile(t, e.path)), "203.0.113.9")
}

func TestSeedFresh(t *testing.T) {
	e := newEnv(t)
	if err := store.SeedFresh(e.path, "lab", "192.168.0.0/16", "lab-secret-placeholder-16chars"); err != nil {
		t.Fatal(err)
	}
	equal(t, e.mustGet("users"), "engineer\noperator\nroot\nviewer")
	equal(t, e.mustGet("users", "root", "accounting_sink"), "true")
	equal(t, e.mustGet("users", "engineer", "disabled"), "true")
	equal(t, e.mustGet("users", "viewer", "scopes"), "lab")
	equal(t, e.mustGet("scopes", "lab", "secret"), "lab-secret-placeholder-16chars")
	if m := mode(t, e.path); m != 0o600 {
		t.Errorf("mode %o", m)
	}
	var ee *store.ExistsError
	if err := store.SeedFresh(e.path, "lab", "10.0.0.0/8", "x"); !errors.As(err, &ee) {
		t.Errorf("second seed: %v", err)
	}
	e2 := newEnv(t)
	err := store.SeedFresh(e2.path, "lab", "", "secret")
	if !errors.Is(err, store.ErrSeedUsage) || err.Error() != store.SeedUsage {
		t.Errorf("usage: %v", err)
	}
	if _, err := os.Stat(e2.path); !os.IsNotExist(err) {
		t.Error("a store was written")
	}
	// A refused seed writes nothing.
	err = store.SeedFresh(e2.path, "lab", "not-a-cidr", "secret")
	equal(t, store.Report(err), "tacctl store: scope 'lab': invalid CIDR 'not-a-cidr'")
	if _, err := os.Stat(e2.path); !os.IsNotExist(err) {
		t.Error("a store was written")
	}
}

func TestSeedFreshMatchesTheBashSeed(t *testing.T) {
	// The bytes 0.1.16's store_seed_fresh wrote for the install seed of
	// install_seed.bats (scope lab, 192.168.0.0/16).
	e := newEnv(t)
	if err := store.SeedFresh(e.path, "lab", "192.168.0.0/16", "lab-secret-placeholder-16chars"); err != nil {
		t.Fatal(err)
	}
	want := store.Header + `version: 1
groups:
  operator: {priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}
users:
  engineer:
    group: superuser
    scopes: [lab]
    hash: null
    disabled: true
  operator:
    group: operator
    scopes: [lab]
    hash: null
    disabled: true
  root:
    group: readonly
    scopes: [lab]
    hash: null
    disabled: true
    accounting_sink: true
  viewer:
    group: readonly
    scopes: [lab]
    hash: null
    disabled: true
scopes:
  lab:
    prefixes: [192.168.0.0/16]
    secret: lab-secret-placeholder-16chars
filters:
  allow: []
  deny: []
`
	if got := readFile(t, e.path); !bytes.Equal(got, []byte(want)) {
		t.Errorf("got:\n%s", got)
	}
}
