package store_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rett/tacctl/internal/hash"
)

// Ports of tests/unit/store.bats, section "store_validate".

func TestValidateShippedFixtures(t *testing.T) {
	for _, name := range []string{"store.minimal.yaml", "store.multiscope.yaml", "store.radius.yaml"} {
		out, ok := validateFile(fixtures + name)
		if !ok || out != "" {
			t.Errorf("%s: not valid: %s", name, out)
		}
	}
}

func TestValidateMissingFile(t *testing.T) {
	e := newEnv(t)
	out, ok := validateFile(filepath.Join(e.dir, "nope.yaml"))
	if ok {
		t.Fatal("a missing file validated")
	}
	contains(t, out, "Store not found")
}

func TestValidateWrongVersion(t *testing.T) {
	out, ok := newEnv(t).validateYAML("version: 2\n" + builtins + "\n")
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "version must be 1")
}

func TestValidateUnknownKeyAndField(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
extras: {}
` + builtins + `
scopes:
  lab: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret", colour: red}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "unknown top-level key 'extras'")
	contains(t, out, "scope 'lab': unknown field 'colour'")
}

func TestValidateBuiltinGroups(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
groups:
  readonly:  {priv_lvl: 1,  juniper_class: RO-CLASS, builtin: true}
  operator:  {priv_lvl: 7,  juniper_class: OP-CLASS}
  helpdesk:  {priv_lvl: 5,  juniper_class: HD-CLASS, builtin: true}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "built-in group 'superuser' is missing")
	contains(t, out, "group 'operator': built-in group must carry builtin: true")
	contains(t, out, "group 'helpdesk': builtin: true is reserved")
}

func TestValidateGroupFields(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
  Helpdesk: {priv_lvl: 5,  juniper_class: HD-CLASS}
  toohigh:  {priv_lvl: 16, juniper_class: HD-CLASS}
  badclass: {priv_lvl: 5,  juniper_class: "HD CLASS"}
  nolevel:  {juniper_class: HD-CLASS}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "group 'Helpdesk': invalid name")
	contains(t, out, "group 'toohigh': priv_lvl must be 0-15")
	contains(t, out, "group 'badclass': juniper_class contains characters")
	contains(t, out, "group 'nolevel': missing 'priv_lvl'")
}

func TestValidateUserReferences(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
users:
  alice: {group: wizards, scopes: [lab, mars], hash: null, disabled: true}
scopes:
  lab: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret"}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "user 'alice': group 'wizards' does not exist")
	contains(t, out, "user 'alice': scope 'mars' does not exist")
	refute(t, out, "scope 'lab' does not exist")
}

func TestValidateReservedUsers(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
users:
  tacquito: {group: readonly, scopes: [], hash: null, disabled: true}
  root:     {group: readonly, scopes: [], hash: null, disabled: true}
  bob:      {group: readonly, scopes: [], hash: null, disabled: true, accounting_sink: true}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "user 'tacquito': reserved name")
	contains(t, out, "user 'root': reserved name, allowed only as the accounting sink")
	contains(t, out, "user 'bob': accounting_sink is reserved for: root")
}

func TestValidateSink(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
users:
  root: {group: readonly, scopes: [], hash: "` + hashA + `", disabled: false, accounting_sink: true}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "the accounting sink must not carry a password hash")
	contains(t, out, "the accounting sink must stay disabled")
	refute(t, out, hashA)
}

func TestValidateHash(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: "not-a-hash-value", disabled: false}
  bob:   {group: readonly, scopes: [], hash: "` + hash.DisabledMarkerHex + `", disabled: true}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "user 'alice': hash is not a hex-encoded bcrypt hash")
	contains(t, out, "user 'bob': hash is the disabled marker")
	refute(t, out, "not-a-hash-value")
}

func TestValidatePasswordChanged(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, password_changed: 2026-10-01}
  bob:   {group: readonly, scopes: [], hash: null, disabled: true, password_changed: "2026-13-40"}
  carol: {group: readonly, scopes: [], hash: null, disabled: true, password_changed: "yesterday"}
`)
	if ok {
		t.Fatal("valid")
	}
	refute(t, out, "user 'alice'")
	contains(t, out, "user 'bob': password_changed is not a real calendar date")
	contains(t, out, "user 'carol': password_changed must be a YYYY-MM-DD date")
}

func TestValidatePrefixes(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
scopes:
  a: {prefixes: ["10.1.5.5/24"], secret: "s3cret-s3cret-s3cret"}
  b: {prefixes: [], secret: "s3cret-s3cret-s3cret"}
  c: {prefixes: ["10.9.0.0/16", "10.0.0.0/8"], secret: "s3cret-s3cret-s3cret"}
  d: {prefixes: ["10.9.0.0/16"], secret: "s3cret-s3cret-s3cret"}
  e: {prefixes: ["banana"], secret: "s3cret-s3cret-s3cret"}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "scope 'a': prefixes contains a non-canonical CIDR")
	contains(t, out, "scope 'b': prefixes must list at least one CIDR")
	contains(t, out, "prefix 10.9.0.0/16 is claimed by scopes 'c' and 'd'")
	contains(t, out, "scope 'e': prefixes contains an invalid CIDR")
}

func TestValidateSecret(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
scopes:
  a: {prefixes: ["10.1.0.0/16"], secret: ""}
  b: {prefixes: ["10.2.0.0/16"], secret: 12345678}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "scope 'a': secret must be a non-empty string")
	contains(t, out, "scope 'b': secret must be a non-empty string")
	refute(t, out, "12345678")
}

func TestValidateProtocols(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
scopes:
  a: {prefixes: ["10.1.0.0/16"], secret: "s3cret-s3cret-s3cret", protocols: [tacacs, radius]}
  b: {prefixes: ["10.2.0.0/16"], secret: "s3cret-s3cret-s3cret", protocols: [ldap]}
  c: {prefixes: ["10.3.0.0/16"], secret: "s3cret-s3cret-s3cret", protocols: []}
`)
	if ok {
		t.Fatal("valid")
	}
	refute(t, out, "scope 'a'")
	contains(t, out, "scope 'b': protocols must be a list drawn from: tacacs, radius")
	contains(t, out, "scope 'c': protocols must not be empty")
}

func TestValidateFilters(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
filters:
  allow: ["10.0.0.0/8"]
  deny: ["10.1.1.1/16"]
  maybe: []
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "filters.deny contains a non-canonical CIDR")
	contains(t, out, "filters: unknown key 'maybe'")
	refute(t, out, "filters.allow")
}

func TestValidateMalformedYAML(t *testing.T) {
	e := newEnv(t)
	p := filepath.Join(e.dir, "bad.yaml")
	if err := os.WriteFile(p, []byte("version: 1\nscopes:\n  lab: {secret: \"hunter2-hunter2\", prefixes: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, ok := validateFile(p)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "bad.yaml")
	contains(t, out, "line")
	refute(t, out, "hunter2")
}

func TestValidateVendorFields(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
scopes:
  a: {prefixes: ["10.1.0.0/16"], secret: "s3cret-s3cret-s3cret", vendor_attrs: [cisco, wti], devices: {10.1.2.3/32: juniper}}
  b: {prefixes: ["10.2.0.0/16"], secret: "s3cret-s3cret-s3cret", vendor_attrs: [arista]}
  c: {prefixes: ["10.3.0.0/16"], secret: "s3cret-s3cret-s3cret", vendor_attrs: [cisco, cisco]}
  d: {prefixes: ["10.4.0.0/16"], secret: "s3cret-s3cret-s3cret", devices: {10.4.0.1: cisco}}
  e: {prefixes: ["10.5.0.0/16"], secret: "s3cret-s3cret-s3cret", devices: {10.5.0.1/32: arista}}
  f: {prefixes: ["10.6.0.0/16"], secret: "s3cret-s3cret-s3cret", devices: [10.6.0.1/32]}
  g: {prefixes: ["10.7.0.0/16"], secret: "s3cret-s3cret-s3cret", vendor_attrs: [], devices: {}}
`)
	if ok {
		t.Fatal("valid")
	}
	refute(t, out, "scope 'a'")
	refute(t, out, "scope 'g'")
	contains(t, out, "scope 'b': vendor_attrs must be a list drawn from: cisco, juniper, wti")
	contains(t, out, "scope 'c': vendor_attrs lists the same value twice")
	contains(t, out, "scope 'd': devices has a non-canonical CIDR ('10.4.0.1', canonical form 10.4.0.1/32)")
	contains(t, out, "scope 'e': devices 10.5.0.1/32: vendor must be one of: cisco, juniper, wti")
	contains(t, out, "scope 'f': devices must be a mapping of CIDR to vendor")
}

func TestValidateDeviceOwnership(t *testing.T) {
	out, ok := newEnv(t).validateYAML(`version: 1
` + builtins + `
scopes:
  outer: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret",
          devices: {10.10.99.5/32: cisco, 10.10.0.0/16: wti, 10.99.0.0/16: juniper, 192.0.2.1/32: cisco, 10.20.0.0/24: wti}}
  inner: {prefixes: ["10.10.99.0/24", "10.20.0.0/24"], secret: "s3cret-s3cret-s3cret", devices: {10.10.99.0/24: juniper}}
`)
	if ok {
		t.Fatal("valid")
	}
	contains(t, out, "scope 'outer': devices: 10.10.99.5/32 belongs to scope 'inner' (its prefix 10.10.99.0/24 is the most specific one that contains it)")
	contains(t, out, "scope 'outer': devices: 10.20.0.0/24 belongs to scope 'inner'")
	contains(t, out, "scope 'outer': devices: 192.0.2.1/32 is not inside a prefix of the scope")
	refute(t, out, "10.10.0.0/16")
	refute(t, out, "10.99.0.0/16")
	refute(t, out, "scope 'inner':")
}

// TestValidateExactOutput pins the whole report for one broken store, in
// 0.1.16's order (checked against the python validator of the 0.1.16 tag).
func TestValidateExactOutput(t *testing.T) {
	out, _ := newEnv(t).validateYAML(`version: 1
extras: 1
groups:
  readonly:  {priv_lvl: 1,  juniper_class: RO-CLASS, builtin: true}
  operator:  {priv_lvl: "7",  juniper_class: OP-CLASS, builtin: true, x: 1}
  Bad: {}
users:
  alice: {group: nope, scopes: [lab, lab, 3], hash: abc, disabled: 1}
  root: {group: readonly, scopes: [], hash: null, disabled: false, accounting_sink: true}
scopes:
  lab: {prefixes: [10.0.0.0/8, 10.0.0.0/8, 7], secret: "a\tb", protocols: null}
  "x y": {}
filters: {allow: [10.0.0.1/8], deny: null}
`)
	equal(t, out, `tacctl store: unknown top-level key 'extras'
tacctl store: group 'operator': unknown field 'x'
tacctl store: group 'operator': priv_lvl must be an integer
tacctl store: group 'Bad': invalid name
tacctl store: user 'alice': scopes must be a list of names
tacctl store: user 'alice': hash is not a hex-encoded bcrypt hash
tacctl store: user 'alice': disabled must be true or false
tacctl store: scope 'lab': prefixes contains an invalid CIDR (7)
tacctl store: scope 'lab': secret contains control characters
tacctl store: scope 'x y': invalid name
tacctl store: built-in group 'superuser' is missing
tacctl store: user 'alice': group 'nope' does not exist
tacctl store: user 'root': the accounting sink must stay disabled
tacctl store: filters.allow contains a non-canonical CIDR ('10.0.0.1/8', canonical form 10.0.0.0/8)`)
}
