#!/usr/bin/env bats
# The fixture helpers themselves: load_fixture seeding, load_store_fixture,
# place_fixture. See tests/README.md "Fixtures and the store".

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

bats_require_minimum_version 1.5.0   # run --separate-stderr

setup() {
    tacctl_tmpenv_init
    STORE="${TACCTL_STATE_DIR}/store.yaml"
}

@test "load_fixture: tacquito.X.yaml is placed and seeds the store the importer would write" {
    load_fixture tacquito.multiscope.yaml
    cmp "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml" "$TACCTL_CONFIG"
    cmp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    [[ "$(stat -c %a "$STORE")" == 600 ]]
}

@test "load_fixture: seeding leaves nothing but store.yaml in the state dir" {
    before=$(find "$TACCTL_STATE_DIR" | sort)
    load_fixture tacquito.minimal.yaml
    after=$(find "$TACCTL_STATE_DIR" | sort)
    [[ "$after" == "$before"$'\n'"$STORE" ]]
}

@test "load_fixture: a second load replaces both the file and the store" {
    load_fixture tacquito.multiscope.yaml
    load_fixture tacquito.minimal.yaml
    cmp "${TACCTL_SRC}/tests/fixtures/tacquito.minimal.yaml" "$TACCTL_CONFIG"
    cmp "${TACCTL_SRC}/tests/fixtures/store.minimal.yaml" "$STORE"
}

@test "load_fixture: sidecars planted before loading are imported (direct import, not the cache)" {
    load_fixture tacquito.multiscope.yaml    # fills the cache without sidecars
    echo "2026-08-15" > "${TACCTL_STATE_DIR}/backups/password-dates/alice.date"
    load_fixture tacquito.multiscope.yaml
    run grep -c '2026-08-15' "$STORE"
    assert_output 1
    [[ ! -e "${TACCTL_STATE_DIR}/.store.lock" ]]
}

@test "load_fixture: a tacquito.* fixture the importer rejects fails the test and shows why" {
    local fake="${BATS_TEST_TMPDIR}/src"
    mkdir -p "${fake}/tests/fixtures"
    cp "${TACCTL_SRC}/tests/fixtures/legacy.unrepresentable.yaml" "${fake}/tests/fixtures/tacquito.bad.yaml"
    TACCTL_SRC="$fake" run --separate-stderr load_fixture tacquito.bad.yaml
    assert_failure
    [[ "$stderr" == *"rejected tests/fixtures/tacquito.bad.yaml"* ]]
    [[ "$stderr" == *"Import failed"* ]]
    [[ ! -e "$STORE" ]]
}

@test "load_fixture: legacy.*.yaml is placed but not seeded" {
    load_fixture legacy.unrepresentable.yaml
    [[ -f "$TACCTL_CONFIG" ]]
    [[ ! -e "$STORE" ]]
}

@test "place_fixture: copies only, no store" {
    place_fixture tacquito.minimal.yaml
    [[ -f "$TACCTL_CONFIG" ]]
    [[ ! -e "$STORE" ]]
}

@test "load_fixture: an unknown fixture fails" {
    run load_fixture tacquito.nope.yaml
    assert_failure
}

@test "load_store_fixture: places the store 0600 and leaves tacquito.yaml alone" {
    load_store_fixture store.multiscope.yaml
    cmp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    [[ "$(stat -c %a "$STORE")" == 600 ]]
    [[ ! -e "$TACCTL_CONFIG" ]]
}

@test "load_store_fixture: an unknown fixture fails" {
    run load_store_fixture store.nope.yaml
    assert_failure
}

@test "load_store_fixture: the library reads the placed store, even after an earlier read" {
    tacctl_source_lib
    load_store_fixture store.multiscope.yaml
    run model_scopes
    assert_line "dmz"
    load_store_fixture store.minimal.yaml
    run model_scopes
    assert_output "lab"
}
