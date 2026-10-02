#!/usr/bin/env bats
# Unit tests for lib/store.sh: schema validation, the atomic writer and the
# typed mutation helpers.

load ../helpers/setup
load ../helpers/tmpenv

# hex of '$2b$12$' + 53 x 'A'
HASH_A="24326224313224$(printf '41%.0s' {1..53})"

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

use_store_fixture() {
    cp "${TACCTL_SRC}/tests/fixtures/$1" "$STORE_FILE"
    chmod 600 "$STORE_FILE"
}

# Write a store body (YAML on stdin) and validate it.
validate_yaml() {
    cat > "${BATS_TEST_TMPDIR}/candidate.yaml"
    run store_validate "${BATS_TEST_TMPDIR}/candidate.yaml"
}

BUILTINS='groups:
  readonly:  {priv_lvl: 1,  juniper_class: RO-CLASS, builtin: true}
  operator:  {priv_lvl: 7,  juniper_class: OP-CLASS, builtin: true}
  superuser: {priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}'

# --- location and constants -------------------------------------------------

@test "store: STORE_FILE lives under TACCTL_STATE_DIR" {
    [[ "$STORE_FILE" == "${BATS_TEST_TMPDIR}/state/store.yaml" ]]
}

@test "store: python disabled marker equals DISABLED_MARKER_HEX" {
    run _store_python mutate "${BATS_TEST_TMPDIR}/x.yaml" 1 'print(DISABLED_MARKER_HEX)' </dev/null
    assert_success
    assert_output "$DISABLED_MARKER_HEX"
}

# --- store_validate ---------------------------------------------------------

@test "store_validate: shipped store fixtures are valid" {
    run store_validate "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml"
    assert_success
    assert_output ""
    run store_validate "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml"
    assert_success
    assert_output ""
}

@test "store_validate: missing file fails" {
    run store_validate "${BATS_TEST_TMPDIR}/nope.yaml"
    assert_failure
    assert_output --partial "Store not found"
}

@test "store_validate: wrong version" {
    validate_yaml <<YAML
version: 2
$BUILTINS
YAML
    assert_failure
    assert_output --partial "version must be 1"
}

@test "store_validate: unknown top-level key and unknown field" {
    validate_yaml <<YAML
version: 1
extras: {}
$BUILTINS
scopes:
  lab: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret", colour: red}
YAML
    assert_failure
    assert_output --partial "unknown top-level key 'extras'"
    assert_output --partial "scope 'lab': unknown field 'colour'"
}

@test "store_validate: built-in groups must exist and be flagged" {
    validate_yaml <<YAML
version: 1
groups:
  readonly:  {priv_lvl: 1,  juniper_class: RO-CLASS, builtin: true}
  operator:  {priv_lvl: 7,  juniper_class: OP-CLASS}
  helpdesk:  {priv_lvl: 5,  juniper_class: HD-CLASS, builtin: true}
YAML
    assert_failure
    assert_output --partial "built-in group 'superuser' is missing"
    assert_output --partial "group 'operator': built-in group must carry builtin: true"
    assert_output --partial "group 'helpdesk': builtin: true is reserved"
}

@test "store_validate: group name, priv_lvl range and class characters" {
    validate_yaml <<YAML
version: 1
$BUILTINS
  Helpdesk: {priv_lvl: 5,  juniper_class: HD-CLASS}
  toohigh:  {priv_lvl: 16, juniper_class: HD-CLASS}
  badclass: {priv_lvl: 5,  juniper_class: "HD CLASS"}
  nolevel:  {juniper_class: HD-CLASS}
YAML
    assert_failure
    assert_output --partial "group 'Helpdesk': invalid name"
    assert_output --partial "group 'toohigh': priv_lvl must be 0-15"
    assert_output --partial "group 'badclass': juniper_class contains characters"
    assert_output --partial "group 'nolevel': missing 'priv_lvl'"
}

@test "store_validate: user must reference an existing group and scopes" {
    validate_yaml <<YAML
version: 1
$BUILTINS
users:
  alice: {group: wizards, scopes: [lab, mars], hash: null, disabled: true}
scopes:
  lab: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret"}
YAML
    assert_failure
    assert_output --partial "user 'alice': group 'wizards' does not exist"
    assert_output --partial "user 'alice': scope 'mars' does not exist"
    refute_output --partial "scope 'lab' does not exist"
}

@test "store_validate: reserved user names" {
    validate_yaml <<YAML
version: 1
$BUILTINS
users:
  tacquito: {group: readonly, scopes: [], hash: null, disabled: true}
  root:     {group: readonly, scopes: [], hash: null, disabled: true}
  bob:      {group: readonly, scopes: [], hash: null, disabled: true, accounting_sink: true}
YAML
    assert_failure
    assert_output --partial "user 'tacquito': reserved name"
    assert_output --partial "user 'root': reserved name, allowed only as the accounting sink"
    assert_output --partial "user 'bob': accounting_sink is reserved for: root"
}

@test "store_validate: the sink may not carry a hash or be enabled" {
    validate_yaml <<YAML
version: 1
$BUILTINS
users:
  root: {group: readonly, scopes: [], hash: "$HASH_A", disabled: false, accounting_sink: true}
YAML
    assert_failure
    assert_output --partial "the accounting sink must not carry a password hash"
    assert_output --partial "the accounting sink must stay disabled"
    refute_output --partial "$HASH_A"
}

@test "store_validate: hash must be bcrypt hex and never the marker; value is not echoed" {
    validate_yaml <<YAML
version: 1
$BUILTINS
users:
  alice: {group: readonly, scopes: [], hash: "not-a-hash-value", disabled: false}
  bob:   {group: readonly, scopes: [], hash: "$DISABLED_MARKER_HEX", disabled: true}
YAML
    assert_failure
    assert_output --partial "user 'alice': hash is not a hex-encoded bcrypt hash"
    assert_output --partial "user 'bob': hash is the disabled marker"
    refute_output --partial "not-a-hash-value"
}

@test "store_validate: password_changed must be a real date; unquoted dates are accepted" {
    validate_yaml <<YAML
version: 1
$BUILTINS
users:
  alice: {group: readonly, scopes: [], hash: null, disabled: true, password_changed: 2026-10-01}
  bob:   {group: readonly, scopes: [], hash: null, disabled: true, password_changed: "2026-13-40"}
  carol: {group: readonly, scopes: [], hash: null, disabled: true, password_changed: "yesterday"}
YAML
    assert_failure
    refute_output --partial "user 'alice'"
    assert_output --partial "user 'bob': password_changed is not a real calendar date"
    assert_output --partial "user 'carol': password_changed must be a YYYY-MM-DD date"
}

@test "store_validate: prefixes must be canonical, non-empty, and owned by one scope" {
    validate_yaml <<YAML
version: 1
$BUILTINS
scopes:
  a: {prefixes: ["10.1.5.5/24"], secret: "s3cret-s3cret-s3cret"}
  b: {prefixes: [], secret: "s3cret-s3cret-s3cret"}
  c: {prefixes: ["10.9.0.0/16", "10.0.0.0/8"], secret: "s3cret-s3cret-s3cret"}
  d: {prefixes: ["10.9.0.0/16"], secret: "s3cret-s3cret-s3cret"}
  e: {prefixes: ["banana"], secret: "s3cret-s3cret-s3cret"}
YAML
    assert_failure
    assert_output --partial "scope 'a': prefixes contains a non-canonical CIDR"
    assert_output --partial "scope 'b': prefixes must list at least one CIDR"
    assert_output --partial "prefix 10.9.0.0/16 is claimed by scopes 'c' and 'd'"
    assert_output --partial "scope 'e': prefixes contains an invalid CIDR"
}

@test "store_validate: secret must be a non-empty string; value is not echoed" {
    validate_yaml <<YAML
version: 1
$BUILTINS
scopes:
  a: {prefixes: ["10.1.0.0/16"], secret: ""}
  b: {prefixes: ["10.2.0.0/16"], secret: 12345678}
YAML
    assert_failure
    assert_output --partial "scope 'a': secret must be a non-empty string"
    assert_output --partial "scope 'b': secret must be a non-empty string"
    refute_output --partial "12345678"
}

@test "store_validate: protocols must be known and non-empty" {
    validate_yaml <<YAML
version: 1
$BUILTINS
scopes:
  a: {prefixes: ["10.1.0.0/16"], secret: "s3cret-s3cret-s3cret", protocols: [tacacs, radius]}
  b: {prefixes: ["10.2.0.0/16"], secret: "s3cret-s3cret-s3cret", protocols: [ldap]}
  c: {prefixes: ["10.3.0.0/16"], secret: "s3cret-s3cret-s3cret", protocols: []}
YAML
    assert_failure
    refute_output --partial "scope 'a'"
    assert_output --partial "scope 'b': protocols must be a list drawn from: tacacs, radius"
    assert_output --partial "scope 'c': protocols must not be empty"
}

@test "store_validate: filters must be canonical CIDR lists" {
    validate_yaml <<YAML
version: 1
$BUILTINS
filters:
  allow: ["10.0.0.0/8"]
  deny: ["10.1.1.1/16"]
  maybe: []
YAML
    assert_failure
    assert_output --partial "filters.deny contains a non-canonical CIDR"
    assert_output --partial "filters: unknown key 'maybe'"
    refute_output --partial "filters.allow"
}

@test "store_validate: malformed YAML reports position without quoting the line" {
    printf 'version: 1\nscopes:\n  lab: {secret: "hunter2-hunter2", prefixes: [\n' > "${BATS_TEST_TMPDIR}/bad.yaml"
    run store_validate "${BATS_TEST_TMPDIR}/bad.yaml"
    assert_failure
    assert_output --partial "bad.yaml"
    assert_output --partial "line"
    refute_output --partial "hunter2"
}

# --- store_init / legacy mode ----------------------------------------------

@test "store_init: creates a 0600 store with only the built-in groups" {
    run store_init
    assert_success
    [[ "$(stat -c %a "$STORE_FILE")" == "600" ]]
    run store_validate
    assert_success
    run model_groups
    assert_output "operator
readonly
superuser"
    run model_users
    assert_output ""
}

@test "store_init: refuses when a store exists" {
    store_init
    run store_init
    assert_failure
    assert_output --partial "already exists"
}

@test "store writer: an unwritable state directory is a one-line error, not a traceback" {
    STORE_FILE="/proc/1/no-such-dir/store.yaml"
    run store_init
    assert_failure
    assert_output --partial "tacctl store: "
    refute_output --partial "Traceback"
}

@test "store mutations: refused in legacy mode with the import hint" {
    run store_user_set alice group=readonly
    assert_failure
    assert_output --partial "store not initialised"
    assert_output --partial "tacctl store import"
    [[ ! -e "$STORE_FILE" ]]
}

# --- writer behaviour -------------------------------------------------------

@test "store writer: file ends up 0600 and no temp files are left behind" {
    use_store_fixture store.minimal.yaml
    chmod 644 "$STORE_FILE"
    store_scope_set lab secret=another-secret-0123456789
    [[ "$(stat -c %a "$STORE_FILE")" == "600" ]]
    run find "$TACCTL_STATE_DIR" -name '.store.*.tmp'
    assert_output ""
}

@test "store writer: a failed validation leaves the store byte-identical" {
    use_store_fixture store.multiscope.yaml
    cp "$STORE_FILE" "${BATS_TEST_TMPDIR}/before.yaml"
    run store_user_set alice group=wizards
    assert_failure
    assert_output --partial "user 'alice': group 'wizards' does not exist"
    cmp "$STORE_FILE" "${BATS_TEST_TMPDIR}/before.yaml"
    run find "$TACCTL_STATE_DIR" -name '.store.*.tmp'
    assert_output ""
}

@test "store writer: a no-op mutation does not replace the file" {
    use_store_fixture store.multiscope.yaml
    local before
    before=$(stat -c %i "$STORE_FILE")
    store_user_set alice group=superuser
    [[ "$(stat -c %i "$STORE_FILE")" == "$before" ]]
}

@test "store writer: snapshot hook runs before a write once backup_snapshot exists" {
    use_store_fixture store.minimal.yaml
    backup_snapshot() { cp "$STORE_FILE" "${BATS_TEST_TMPDIR}/snap.yaml"; }
    store_scope_set lab secret=another-secret-0123456789
    cmp "${BATS_TEST_TMPDIR}/snap.yaml" "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml"
    run model_scope lab secret
    assert_output "another-secret-0123456789"
}

@test "store writer: a failing snapshot hook blocks the write" {
    use_store_fixture store.minimal.yaml
    backup_snapshot() { return 1; }
    run store_scope_set lab secret=another-secret-0123456789
    assert_failure
    cmp "$STORE_FILE" "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml"
}

@test "store_mutate: custom snippet sees store and args, result is validated" {
    use_store_fixture store.minimal.yaml
    store_mutate 'store["groups"][args[0]] = {"priv_lvl": int(args[1]), "juniper_class": args[2]}' netops 9 NETOPS
    run model_group netops priv_lvl
    assert_output "9"
    run store_mutate 'store["groups"]["x"] = {"priv_lvl": 99, "juniper_class": "X"}'
    assert_failure
    assert_output --partial "group 'x': priv_lvl must be 0-15"
}

@test "store_mutate: argument values survive spaces, quotes and equals signs" {
    use_store_fixture store.minimal.yaml
    store_scope_set lab "secret=it's a \"quoted\" \$ecret, with = and spaces"
    run model_scope lab secret
    assert_output "it's a \"quoted\" \$ecret, with = and spaces"
    run store_scope_set lab "secret=two
lines"
    assert_failure
    assert_output --partial "scope 'lab': secret contains control characters"
}

# --- users ------------------------------------------------------------------

@test "store_user_set: create with hash starts enabled, hash normalised from raw form" {
    use_store_fixture store.minimal.yaml
    local raw
    raw="\$2b\$12\$$(printf 'A%.0s' {1..53})"
    store_user_set alice group=operator scopes=lab "hash=${raw}" password_changed=2026-09-30
    run model_user alice
    assert_success
    assert_output "{\"accounting_sink\": false, \"disabled\": false, \"group\": \"operator\", \"hash\": \"${HASH_A}\", \"name\": \"alice\", \"password_changed\": \"2026-09-30\", \"scopes\": [\"lab\"]}"
}

@test "store_user_set: create without hash starts disabled; group is required" {
    use_store_fixture store.minimal.yaml
    run store_user_set alice scopes=lab
    assert_failure
    assert_output --partial "group is required when creating a user"
    store_user_set alice group=readonly
    run model_user alice disabled
    assert_output "true"
    run model_user alice hash
    assert_output ""
}

@test "store_user_set: update touches only the named fields" {
    use_store_fixture store.multiscope.yaml
    store_user_set alice disabled=true
    run model_user alice disabled
    assert_output "true"
    run model_user alice group
    assert_output "superuser"
    run model_user alice scopes
    assert_output "prod
lab"
    store_user_set alice scopes=dmz,lab,dmz password_changed=today
    run model_user alice scopes
    assert_output "dmz
lab"
    run model_user alice password_changed
    assert_output "$(date +%Y-%m-%d)"
    store_user_set alice scopes= password_changed=null
    run model_user alice scopes
    assert_output ""
    run model_user alice password_changed
    assert_output ""
}

@test "store_user_set: rejects a bad hash, the marker, and unknown fields without echoing the hash" {
    use_store_fixture store.multiscope.yaml
    run store_user_set alice hash=definitely-not-bcrypt
    assert_failure
    assert_output --partial "hash is not a bcrypt hash"
    refute_output --partial "definitely-not-bcrypt"
    run store_user_set alice "hash=${DISABLED_MARKER_HEX}"
    assert_failure
    assert_output --partial "use disabled=true"
    run store_user_set alice shoe_size=9
    assert_failure
    assert_output --partial "unknown field 'shoe_size'"
}

@test "store_user_set: root is created as the accounting sink and takes no password" {
    use_store_fixture store.minimal.yaml
    store_user_set root group=readonly scopes=lab
    run model_user root accounting_sink
    assert_output "true"
    run model_user root disabled
    assert_output "true"
    run store_user_set root "hash=${HASH_A}"
    assert_failure
    assert_output --partial "accounting sink"
    run store_user_set root disabled=false
    assert_failure
    assert_output --partial "the accounting sink must stay disabled"
}

@test "store_user_set: reserved and malformed names are rejected" {
    use_store_fixture store.minimal.yaml
    run store_user_set tacquito group=readonly
    assert_failure
    assert_output --partial "reserved name"
    run store_user_set 'bad name' group=readonly
    assert_failure
    assert_output --partial "invalid name"
}

@test "store_user_del / store_user_rename" {
    use_store_fixture store.multiscope.yaml
    store_user_rename bob robert
    run model_user bob
    assert_failure
    run model_user robert group
    assert_output "operator"
    run store_user_rename robert alice
    assert_failure
    assert_output --partial "user 'alice' already exists"
    store_user_del robert
    run model_users
    assert_output "alice
carol"
    run store_user_del robert
    assert_failure
    assert_output --partial "user 'robert' does not exist"
}

# --- groups -----------------------------------------------------------------

@test "store_group_set: create, edit, and validation" {
    use_store_fixture store.minimal.yaml
    run store_group_set helpdesk priv_lvl=5
    assert_failure
    assert_output --partial "juniper_class required when creating a group"
    store_group_set helpdesk priv_lvl=5 juniper_class=HELPDESK-CLASS
    run model_group helpdesk
    assert_output '{"builtin": false, "juniper_class": "HELPDESK-CLASS", "name": "helpdesk", "priv_lvl": 5}'
    store_group_set helpdesk priv_lvl=6
    run model_group helpdesk priv_lvl
    assert_output "6"
    run store_group_set helpdesk priv_lvl=16
    assert_failure
    run store_group_set helpdesk juniper_class='BAD CLASS'
    assert_failure
    run store_group_set Helpdesk priv_lvl=5 juniper_class=X
    assert_failure
    assert_output --partial "invalid name"
}

@test "store_group_set: built-ins are editable and keep their flag" {
    use_store_fixture store.minimal.yaml
    store_group_set operator priv_lvl=8
    run model_group operator
    assert_output '{"builtin": true, "juniper_class": "OP-CLASS", "name": "operator", "priv_lvl": 8}'
}

@test "store_group_del: refuses built-ins, groups in use, and unknown groups" {
    use_store_fixture store.multiscope.yaml
    run store_group_del superuser
    assert_failure
    assert_output --partial "cannot remove built-in group 'superuser'"
    store_group_set helpdesk priv_lvl=5 juniper_class=HELPDESK-CLASS
    store_user_set bob group=helpdesk
    run store_group_del helpdesk
    assert_failure
    assert_output --partial "1 user(s) are assigned to it"
    store_user_set bob group=operator
    store_group_del helpdesk
    run model_group helpdesk
    assert_failure
    run store_group_del helpdesk
    assert_failure
    assert_output --partial "does not exist"
}

# --- scopes -----------------------------------------------------------------

@test "store_scope_set: create canonicalises, dedupes and sorts prefixes" {
    use_store_fixture store.minimal.yaml
    run store_scope_set prod prefixes=10.0.0.0/8
    assert_failure
    assert_output --partial "secret required when creating a scope"
    store_scope_set prod "prefixes=2001:DB8::/32, 10.0.0.0/8,10.10.99.7/24,10.0.0.0/8" secret=prod-secret-0123456789
    run model_scope prod prefixes
    assert_output "10.10.99.0/24
10.0.0.0/8
2001:db8::/32"
    run model_scope prod protocols
    assert_output ""
}

@test "store_scope_set: a prefix may belong to one scope only" {
    use_store_fixture store.multiscope.yaml
    run store_scope_set dmz prefixes=203.0.113.0/24,10.10.99.0/24
    assert_failure
    assert_output --partial "prefix 10.10.99.0/24 is claimed by scopes"
    run store_scope_set dmz prefixes=not-a-cidr
    assert_failure
    assert_output --partial "invalid CIDR"
    run store_scope_set dmz prefixes=
    assert_failure
    assert_output --partial "must list at least one CIDR"
}

@test "store_scope_set: protocols set and clear" {
    use_store_fixture store.minimal.yaml
    store_scope_set lab protocols=radius
    run model_scope lab protocols
    assert_output "radius"
    run grep -c 'protocols: \[radius\]' "$STORE_FILE"
    assert_output "1"
    run store_scope_set lab protocols=ldap
    assert_failure
    store_scope_set lab protocols=null
    run model_scope lab protocols
    assert_output ""
    run grep -c protocols "$STORE_FILE"
    assert_output "0"
}

@test "store_scope_del: refuses a referenced scope unless --strip-users" {
    use_store_fixture store.multiscope.yaml
    run store_scope_del lab
    assert_failure
    assert_output --partial "3 user(s) still reference it"
    store_scope_del lab --strip-users
    run model_scope lab
    assert_failure
    run model_user alice scopes
    assert_output "prod"
    run model_user bob scopes
    assert_output ""
    store_scope_del prod-inner
    run model_scopes
    assert_output "dmz
prod"
}

@test "store_scope_rename: updates every user's scope list in place" {
    use_store_fixture store.multiscope.yaml
    store_scope_rename lab bench
    run model_scopes
    assert_output "bench
dmz
prod
prod-inner"
    run model_user alice scopes
    assert_output "prod
bench"
    run store_scope_rename bench prod
    assert_failure
    assert_output --partial "scope 'prod' already exists"
}

# --- filters ----------------------------------------------------------------

@test "store_filters_set: set, canonicalise, clear" {
    use_store_fixture store.minimal.yaml
    store_filters_set allow "192.168.0.0/16,10.5.5.5/8"
    run model_filters allow
    assert_output "10.0.0.0/8
192.168.0.0/16"
    run model_filters
    assert_output '{"allow": ["10.0.0.0/8", "192.168.0.0/16"], "deny": []}'
    store_filters_set allow ""
    run model_filters allow
    assert_output ""
    run store_filters_set maybe 10.0.0.0/8
    assert_failure
    run store_filters_set deny nonsense
    assert_failure
    assert_output --partial "invalid CIDR"
}
