#!/usr/bin/env bats
# Integration tests for `tacctl scope`: add, remove, rename, lookup.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger

    load_fixture tacquito.minimal.yaml
}

# --- scopes add --------------------------------------------------------------

@test "scopes add: creates a new scope with prefixes + explicit secret" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-1234567890abcdef"
    assert_success

    # secrets[] entry appears in the YAML.
    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "1"
    # Prefix and secret key both land in the entry.
    run grep -F '10.0.0.0/8' "$TACCTL_CONFIG"
    assert_success
    run grep -F 'prod-secret-1234567890abcdef' "$TACCTL_CONFIG"
    assert_success
}

@test "scopes add: rejects short secret (< SECRET_MIN_LENGTH)" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "short"
    assert_failure
    assert_output --partial "minimum is"
}

@test "scopes add: rejects invalid scope name" {
    run "$TACCTL_BIN_SCRIPT" scope add "1bad" \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-1234567890abcdef"
    assert_failure
}

@test "scopes add: rejects duplicate scope name" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 172.16.0.0/12 --secret "another-prod-1234567890abc"
    assert_failure
    assert_output --partial "already exists"
}

@test "scopes add: rejects exact-prefix collision across scopes" {
    # The collision check enforces one-scope-per-exact-prefix, not containment.
    # Tacquito resolves overlaps by first-match walk; overlapping-but-distinct
    # prefixes are legal and useful (see tacquito.multiscope.yaml fixture).
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope add prod-copy \
        --prefixes 10.0.0.0/8 --secret "another-secret-1234567890ab"
    assert_failure
    assert_output --partial "already claimed"
}

@test "scopes add: rejects invalid CIDR" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes not-a-cidr --secret "prod-secret-1234567890abcdef"
    assert_failure
}

@test "scopes add: --default sets the new scope as default" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-1234567890abcdef" \
        --default
    assert_success
    [[ "$(conf_get scope.default)" == "prod" ]]
}

# --- scopes list / show / lookup --------------------------------------------

@test "scopes list: shows all scopes with prefix rows" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope list
    assert_success
    assert_output --partial "lab"
    assert_output --partial "prod"
    assert_output --partial "10.0.0.0/8"
}

@test "scopes show: prints a scope's prefixes, secret, and user count" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope show prod
    assert_success
    assert_output --partial "10.0.0.0/8"
    assert_output --partial "prod-secret-1234567890abcdef"
}

@test "scopes lookup: returns owning scope for a covered IP" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope lookup 10.1.2.3
    assert_success
    assert_output --partial "prod"
}

# --- scopes remove -----------------------------------------------------------

@test "scopes remove: deletes an unused scope after 'y' confirmation" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_success
    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "scopes remove: refuses to delete a scope in use without --force" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes prod

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_failure
    assert_output --partial "still reference"
}

@test "scopes remove: --force strips scope from users and deletes" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab,prod

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod --force'
    assert_success

    # Scope is gone.
    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "0"

    # Alice's scope list no longer includes prod (she still has lab).
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab"]'
    refute_output --partial '"prod"'
}

@test "scopes remove: refuses to delete the default scope" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef" --default

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_failure
    assert_output --partial "default scope"
}

# --- scopes rename -----------------------------------------------------------

@test "scopes rename: renames scope and rewrites user references" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes prod

    run "$TACCTL_BIN_SCRIPT" scope rename prod production
    assert_success

    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^  - name: production$' "$TACCTL_CONFIG"
    assert_output "1"

    # Alice's scope reference is rewritten.
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["production"]'
}
