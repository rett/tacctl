#!/usr/bin/env bats
# Integration tests for the user-lifecycle subcommands:
#   passwd, disable, enable, rename, move, scopes {list|add|remove|set|clear}.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

# Two distinct hex-encoded bcrypt hashes (cost 10, canned). Used to assert
# that passwd actually swaps the stored value.
HASH_A="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
HASH_B="24326224313024626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml

    # Seed a prod scope + alice so every test starts from a clean known state.
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef" > /dev/null
    "$TACCTL_BIN_SCRIPT" user add alice superuser \
        --hash "$HASH_A" --scopes lab > /dev/null
}

# Dump alice's hash from the config. The authenticator block cmd_add writes:
#   bcrypt_alice: &bcrypt_alice
#     type: *authenticator_type_bcrypt
#     options:
#       hash: <hex>
# so the hash line is the 4th line of the block.
_alice_hash() {
    grep -A5 '^bcrypt_alice:' "$TACCTL_CONFIG" | awk '/^[[:space:]]*hash:/ {print $2; exit}'
}

# --- user passwd --------------------------------------------------------------

@test "user passwd --hash: swaps the stored bcrypt hash" {
    local before; before=$(_alice_hash)
    [[ "$before" == "$HASH_A" ]]

    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "$HASH_B"
    assert_success

    local after; after=$(_alice_hash)
    [[ "$after" == "$HASH_B" ]]
}

@test "user passwd: records a password-date sidecar" {
    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "$HASH_B"
    assert_success
    [[ -f "$TACCTL_ETC/backups/password-dates/alice.date" ]]
}

@test "user passwd: rejects unknown user" {
    run "$TACCTL_BIN_SCRIPT" user passwd ghost --hash "$HASH_B"
    assert_failure
    assert_output --partial "does not exist"
}

@test "user passwd: rejects invalid hash" {
    run "$TACCTL_BIN_SCRIPT" user passwd alice --hash "not-a-hash"
    assert_failure
    assert_output --partial "Invalid bcrypt hash"
}

# --- user disable / enable ---------------------------------------------------

@test "user disable: replaces hash with DISABLED_MARKER_HEX + sidecar saves original" {
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success

    # Hash was swapped for the marker; original is parked in disabled/ sidecar.
    local current; current=$(_alice_hash)
    [[ "$current" != "$HASH_A" ]]
    [[ -f "$TACCTL_ETC/backups/disabled/alice.hash" ]]
    [[ "$(cat "$TACCTL_ETC/backups/disabled/alice.hash")" == "$HASH_A" ]]
}

@test "user disable: idempotent on an already-disabled user" {
    "$TACCTL_BIN_SCRIPT" user disable alice
    run "$TACCTL_BIN_SCRIPT" user disable alice
    assert_success
    assert_output --partial "already disabled"
}

@test "user enable: restores the original hash and deletes the sidecar" {
    "$TACCTL_BIN_SCRIPT" user disable alice
    [[ -f "$TACCTL_ETC/backups/disabled/alice.hash" ]]

    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_success
    [[ "$(_alice_hash)" == "$HASH_A" ]]
    [[ ! -f "$TACCTL_ETC/backups/disabled/alice.hash" ]]
}

@test "user enable: refuses when there's no sidecar to restore from" {
    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_success
    assert_output --partial "not disabled"
}

@test "user enable: errors when sidecar was hand-deleted" {
    "$TACCTL_BIN_SCRIPT" user disable alice
    rm -f "$TACCTL_ETC/backups/disabled/alice.hash"
    run "$TACCTL_BIN_SCRIPT" user enable alice
    assert_failure
    assert_output --partial "No saved hash"
}

# --- user rename -------------------------------------------------------------

@test "user rename: updates both anchor name and user entry in one pass" {
    run "$TACCTL_BIN_SCRIPT" user rename alice aliceA
    assert_success

    run grep -c '^bcrypt_alice: &bcrypt_alice$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^bcrypt_aliceA: &bcrypt_aliceA$' "$TACCTL_CONFIG"
    assert_output "1"
    run grep -c '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^  - name: aliceA$' "$TACCTL_CONFIG"
    assert_output "1"
    run grep -F '*bcrypt_aliceA' "$TACCTL_CONFIG"
    assert_success
}

@test "user rename: migrates the password-date sidecar too" {
    date -u +%Y-%m-%d > "$TACCTL_ETC/backups/password-dates/alice.date"
    run "$TACCTL_BIN_SCRIPT" user rename alice aliceA
    assert_success
    [[ ! -f "$TACCTL_ETC/backups/password-dates/alice.date" ]]
    [[ -f "$TACCTL_ETC/backups/password-dates/aliceA.date" ]]
}

@test "user rename: rejects when new name is already taken" {
    "$TACCTL_BIN_SCRIPT" user add bob operator --hash "$HASH_A" --scopes lab > /dev/null
    run "$TACCTL_BIN_SCRIPT" user rename alice bob
    assert_failure
    assert_output --partial "already exists"
}

@test "user rename: rejects unknown old-name" {
    run "$TACCTL_BIN_SCRIPT" user rename ghost aliceA
    assert_failure
    assert_output --partial "does not exist"
}

@test "user rename: rejects invalid new-name" {
    run "$TACCTL_BIN_SCRIPT" user rename alice 'alice evil'
    assert_failure
}

# --- user move ---------------------------------------------------------------

@test "user move: rewrites groups: reference to the new group" {
    run "$TACCTL_BIN_SCRIPT" user move alice operator
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'groups: [*operator]'
    refute_output --partial 'groups: [*superuser]'
}

@test "user move: no-op when already in target group" {
    run "$TACCTL_BIN_SCRIPT" user move alice superuser
    assert_success
    assert_output --partial "already in"
}

@test "user move: rejects unknown group" {
    run "$TACCTL_BIN_SCRIPT" user move alice nosuchgroup
    assert_failure
    assert_output --partial "does not exist"
}

# --- user scopes -------------------------------------------------------------

@test "user scopes list: prints current scope memberships" {
    run "$TACCTL_BIN_SCRIPT" user scope alice list
    assert_success
    assert_output --partial "lab"
    refute_output --partial "prod"
}

@test "user scopes add: appends a new scope to the list" {
    run "$TACCTL_BIN_SCRIPT" user scope alice add prod
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    # Order is "prior list then appended" — lab first, then prod.
    assert_output --partial 'scopes: ["lab", "prod"]'
}

@test "user scopes add: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" user scope alice add nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "user scopes remove: drops a scope from the list" {
    "$TACCTL_BIN_SCRIPT" user scope alice add prod > /dev/null
    run "$TACCTL_BIN_SCRIPT" user scope alice remove lab
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["prod"]'
    refute_output --partial '"lab"'
}

@test "user scopes set: replaces the list wholesale" {
    run "$TACCTL_BIN_SCRIPT" user scope alice set prod
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["prod"]'
    refute_output --partial '"lab"'
}

@test "user scopes clear: wipes all scopes after 'y' confirmation" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" user scope alice clear'
    assert_success

    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: []'
}

@test "user scopes: rejects unknown user" {
    run "$TACCTL_BIN_SCRIPT" user scope ghost list
    assert_failure
    assert_output --partial "does not exist"
}
