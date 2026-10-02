#!/usr/bin/env bats
# Unit tests for lib/model.sh: mode detection, the two loaders, the accessors
# and the per-invocation cache.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

# Legacy-loader tests place tacquito.* fixtures with place_fixture (copy only):
# load_fixture would seed a store, and the store would win.

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

use_store_fixture() {
    cp "${TACCTL_SRC}/tests/fixtures/$1" "$STORE_FILE"
}

dump_model_to() {
    model_dump | python3 -m json.tool --sort-keys > "$1"
}

# --- mode -------------------------------------------------------------------

@test "model_mode: legacy without a store, store with one" {
    run model_mode
    assert_output "legacy"
    use_store_fixture store.minimal.yaml
    run model_mode
    assert_output "store"
}

@test "model_dump: fails cleanly when neither store nor config exists" {
    run model_dump
    assert_failure
    assert_output --partial "No store at"
}

# --- store loader -----------------------------------------------------------

@test "store loader: each store fixture yields the golden model of its tacquito twin" {
    local name
    for name in minimal multiscope; do
        use_store_fixture "store.${name}.yaml"
        _model_invalidate
        dump_model_to "${BATS_TEST_TMPDIR}/${name}.json"
        golden_diff "${BATS_TEST_TMPDIR}/${name}.json" "../model/${name}.json"
    done
}

@test "store loader: the store wins over tacquito.yaml once it exists" {
    place_fixture tacquito.multiscope.yaml
    use_store_fixture store.minimal.yaml
    run model_users
    assert_output ""
    run model_scopes
    assert_output "lab"
}

@test "store loader: optional fields are filled in with defaults" {
    cat > "$STORE_FILE" <<'YAML'
version: 1
groups:
  readonly: {priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}
  helpdesk: {priv_lvl: 5, juniper_class: HD-CLASS}
users:
  alice: {group: helpdesk, scopes: [lab], hash: null, disabled: true}
scopes:
  lab: {prefixes: ["10.0.0.0/8"], secret: "s3cret-s3cret-s3cret"}
YAML
    run model_group helpdesk builtin
    assert_output "false"
    run model_user alice accounting_sink
    assert_output "false"
    run model_user alice password_changed
    assert_output ""
    run model_scope lab protocols
    assert_output ""
    run model_filters
    assert_output '{"allow": [], "deny": []}'
}

@test "store loader: unparseable store fails the read and names the file, not its content" {
    printf 'version: 1\nscopes: {lab: {secret: "leaky-secret-0123456789"\n' > "$STORE_FILE"
    run model_dump
    assert_failure
    assert_output --partial "store.yaml"
    refute_output --partial "leaky-secret"
}

# --- legacy loader ----------------------------------------------------------

@test "legacy loader: reads tacquito.yaml when no store exists" {
    place_fixture tacquito.multiscope.yaml
    dump_model_to "${BATS_TEST_TMPDIR}/multiscope.json"
    golden_diff "${BATS_TEST_TMPDIR}/multiscope.json" ../model/multiscope.json
}

@test "legacy loader: agrees with today's readers on the multiscope fixture" {
    place_fixture tacquito.multiscope.yaml
    # Scope names: list_scopes is first-appearance order, the model is sorted.
    [[ "$(model_scopes)" == "$(list_scopes | sort)" ]]
    local s
    for s in $(list_scopes); do
        [[ "$(model_scope "$s" secret)" == "$(read_scope_secret "$s")" ]]
        [[ "$(model_scope "$s" prefixes | sort)" == "$(read_scope_prefixes "$s" | sort)" ]]
    done
    local u
    for u in alice bob carol; do
        [[ "$(model_user "$u" scopes)" == "$(read_user_scopes "$u")" ]]
    done
    [[ "$(model_groups)" == "$(list_all_groups | sort)" ]]
    local g
    for g in $(list_all_groups); do
        [[ "$(model_group "$g" priv_lvl)" == "$(get_group_privlvl "$g")" ]]
    done
}

@test "legacy loader: agrees with today's readers on users added by cmd_add's layout" {
    load_fixture legacy.import-edge.yaml
    [[ "$(model_user alice group)" == "$(get_user_group alice)" ]]
    [[ "$(model_user alice hash)" == "$(get_user_hash alice)" ]]
    [[ "$(model_user dave group)" == "$(get_user_group dave)" ]]
    [[ "$(model_filters allow)" == "$(read_prefix_list prefix_allow)" ]]
    [[ "$(model_filters deny)" == "$(read_prefix_list prefix_deny)" ]]
    [[ "$(model_group helpdesk priv_lvl)" == "$(get_group_privlvl helpdesk)" ]]
}

# --- accessors --------------------------------------------------------------

@test "accessors: list forms print sorted names" {
    use_store_fixture store.multiscope.yaml
    run model_users
    assert_output "alice
bob
carol"
    run model_groups
    assert_output "operator
readonly
superuser"
    run model_scopes
    assert_output "dmz
lab
prod
prod-inner"
}

@test "accessors: entry form prints JSON with the name; field form prints text" {
    use_store_fixture store.multiscope.yaml
    run model_scope lab
    assert_output '{"name": "lab", "prefixes": ["172.16.0.0/12", "192.168.0.0/16"], "protocols": null, "secret": "lab-secret-0123456789abcdef"}'
    run model_scope lab prefixes
    assert_output "172.16.0.0/12
192.168.0.0/16"
    run model_user carol group
    assert_output "readonly"
    run model_user carol disabled
    assert_output "false"
    run model_group superuser
    assert_output '{"builtin": true, "juniper_class": "RW-CLASS", "name": "superuser", "priv_lvl": 15}'
}

@test "accessors: a missing entry returns 1 and prints nothing" {
    use_store_fixture store.multiscope.yaml
    run model_user nobody
    assert_failure 1
    assert_output ""
    run model_user nobody group
    assert_failure 1
    run model_group nogroup
    assert_failure 1
    run model_scope noscope
    assert_failure 1
}

@test "accessors: an unknown field is an error, not empty output" {
    use_store_fixture store.multiscope.yaml
    run model_user alice shoe_size
    assert_failure
    assert_output --partial "unknown field 'shoe_size'"
    run model_filters maybe
    assert_failure
}

# --- cache ------------------------------------------------------------------

@test "cache: model_load primes it; a store write invalidates it" {
    use_store_fixture store.multiscope.yaml
    [[ -z "$_TACCTL_MODEL_CACHE" ]]
    model_load
    [[ -n "$_TACCTL_MODEL_CACHE" ]]
    # A change behind the cache's back is not seen...
    sed -i 's/RW-CLASS/XX-CLASS/' "$STORE_FILE"
    [[ "$(model_group superuser juniper_class)" == "RW-CLASS" ]]
    # ...a write through the store API is.
    store_group_set superuser juniper_class=YY-CLASS
    [[ -z "$_TACCTL_MODEL_CACHE" ]]
    [[ "$(model_group superuser juniper_class)" == "YY-CLASS" ]]
}
