#!/usr/bin/env bats
# 'tacctl store show|import' through the real entrypoint (subprocess).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

bats_require_minimum_version 1.5.0   # run --separate-stderr

# 'tacctl store' tests start from an empty state dir: tacquito.* fixtures go in
# with place_fixture (copy only), not load_fixture (which would seed the store).

setup() {
    tacctl_tmpenv_init
    STORE="${TACCTL_STATE_DIR}/store.yaml"
}

@test "store: no subcommand prints usage" {
    run "$TACCTL_BIN_SCRIPT" store
    assert_success
    assert_output --partial "tacctl store"
    assert_output --partial "import [--check|--force]"
}

@test "store: unknown subcommand fails" {
    run "$TACCTL_BIN_SCRIPT" store frobnicate
    assert_failure
    assert_output --partial "Unknown store subcommand 'frobnicate'"
}

@test "store show: legacy mode prints the model derived from tacquito.yaml as YAML" {
    place_fixture tacquito.multiscope.yaml
    run --separate-stderr "$TACCTL_BIN_SCRIPT" store show
    assert_success
    [[ "$stderr" == *"legacy read-only mode"* ]]
    printf '%s\n' "$output" > "${BATS_TEST_TMPDIR}/shown.yaml"
    run python3 - "${BATS_TEST_TMPDIR}/shown.yaml" <<'PY'
import sys, yaml
m = yaml.safe_load(open(sys.argv[1]))
assert m['version'] == 1
assert sorted(m['users']) == ['alice', 'bob', 'carol'], m['users']
assert m['users']['alice']['scopes'] == ['prod', 'lab']
assert m['scopes']['lab']['prefixes'] == ['172.16.0.0/12', '192.168.0.0/16']
assert m['groups']['superuser'] == {'priv_lvl': 15, 'juniper_class': 'RW-CLASS', 'builtin': True}
print('ok')
PY
    assert_output "ok"
    [[ ! -e "$STORE" ]]
}

@test "store show: store mode prints the same model, with no legacy warning" {
    place_fixture tacquito.multiscope.yaml
    run --separate-stderr "$TACCTL_BIN_SCRIPT" store show
    local legacy_view="$output"
    run "$TACCTL_BIN_SCRIPT" store import
    assert_success
    run --separate-stderr "$TACCTL_BIN_SCRIPT" store show
    assert_success
    [[ "$stderr" != *"legacy"* ]]
    [[ "$output" == "$legacy_view" ]]
}

@test "store show --json: prints the model as JSON" {
    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    run "$TACCTL_BIN_SCRIPT" store show --json
    assert_success
    printf '%s\n' "$output" > "${BATS_TEST_TMPDIR}/shown.json"
    golden_diff "${BATS_TEST_TMPDIR}/shown.json" ../model/multiscope.json
}

@test "store show: fails when there is neither a store nor a config" {
    run "$TACCTL_BIN_SCRIPT" store show
    assert_failure
    assert_output --partial "No store at"
}

@test "store import: writes a 0600 store and leaves tacquito.yaml untouched" {
    place_fixture tacquito.multiscope.yaml
    cp "$TACCTL_CONFIG" "${BATS_TEST_TMPDIR}/before.yaml"
    run "$TACCTL_BIN_SCRIPT" store import
    assert_success
    assert_output --partial "Users:    3 (0 disabled)"
    assert_output --partial "Store written to ${STORE}."
    [[ "$(stat -c %a "$STORE")" == "600" ]]
    diff -u "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    cmp "$TACCTL_CONFIG" "${BATS_TEST_TMPDIR}/before.yaml"
}

@test "store import: strict failure exits 1 and writes nothing; --force succeeds" {
    load_fixture legacy.unrepresentable.yaml
    run "$TACCTL_BIN_SCRIPT" store import
    assert_failure 1
    assert_output --partial "group 'netops': service 'ppp'"
    assert_output --partial "Nothing was written"
    [[ ! -e "$STORE" ]]
    run "$TACCTL_BIN_SCRIPT" store import --force
    assert_success
    assert_output --partial "Dropped (--force)"
    [[ -f "$STORE" ]]
}

@test "store import --check: a file the render would change exits 1 and writes nothing" {
    # The raw fixture has no command rules; the render adds tacctl.yaml's.
    place_fixture tacquito.multiscope.yaml
    local before
    before=$(find "$TACCTL_STATE_DIR" "$TACCTL_ETC" | sort)
    run "$TACCTL_BIN_SCRIPT" store import --check
    assert_failure 1
    assert_output --partial "import + validate:   OK"
    assert_output --partial "render:              OK"
    assert_output --partial "NOT EQUIVALENT"
    [[ ! -e "$STORE" ]]
    [[ "$(find "$TACCTL_STATE_DIR" "$TACCTL_ETC" | sort)" == "$before" ]]
    cmp "$TACCTL_CONFIG" "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
}

@test "store import --check: a file tacctl rendered exits 0 and writes nothing" {
    load_fixture golden/tacquito.multiscope.rendered.yaml
    local before
    before=$(find "$TACCTL_STATE_DIR" "$TACCTL_ETC" | sort)
    run "$TACCTL_BIN_SCRIPT" store import --check
    assert_success
    assert_output --partial "    EQUIVALENT"
    assert_output --partial "daemon load-smoke:   SKIPPED"
    assert_output --partial "Check passed. Nothing was written."
    [[ ! -e "$STORE" ]]
    [[ "$(find "$TACCTL_STATE_DIR" "$TACCTL_ETC" | sort)" == "$before" ]]
}

@test "store import <file>: imports a named file, e.g. a legacy backup" {
    place_fixture tacquito.minimal.yaml
    run "$TACCTL_BIN_SCRIPT" store import "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
    assert_success
    diff -u "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
}

@test "store import: works with no tacquito.yaml in place when a file is named" {
    run "$TACCTL_BIN_SCRIPT" store import "${TACCTL_SRC}/tests/fixtures/tacquito.minimal.yaml"
    assert_success
    diff -u "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml" "$STORE"
}

@test "store: commands read tacquito.yaml until a store exists, and the store from then on" {
    place_fixture tacquito.multiscope.yaml
    local users_before scopes_before
    users_before=$("$TACCTL_BIN_SCRIPT" user list)
    scopes_before=$("$TACCTL_BIN_SCRIPT" scope list)
    [[ "$users_before" == *"alice"* ]]
    [[ "$scopes_before" == *"prod-inner"* ]]
    run "$TACCTL_BIN_SCRIPT" store import
    assert_success
    # The import changes nothing a reader sees.
    [[ "$("$TACCTL_BIN_SCRIPT" user list)" == "$users_before" ]]
    [[ "$("$TACCTL_BIN_SCRIPT" scope list)" == "$scopes_before" ]]
    # Swap in a different store: the readers follow it, not tacquito.yaml,
    # which still holds the multiscope data.
    cp "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml" "$STORE"
    run "$TACCTL_BIN_SCRIPT" user list
    refute_output --partial "alice"
    run "$TACCTL_BIN_SCRIPT" scope list
    assert_output --partial "lab"
    refute_output --partial "prod-inner"
    grep -q 'prod-inner' "$TACCTL_CONFIG"
}

@test "store: tier gate keeps store commands superuser-only" {
    tacctl_source_lib
    run tier_permits readonly store show
    assert_failure
    run tier_permits operator store show
    assert_failure
    run tier_permits operator store import
    assert_failure
    run tier_permits superuser store show
    assert_success
}
