#!/usr/bin/env bats
# Unit tests for YAML-reading helpers (read-only: fixtures unchanged).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
    load_fixture tacquito.multiscope.yaml
}

# --- list_scopes -------------------------------------------------------------

@test "list_scopes: enumerates all secrets[] entries by name" {
    run list_scopes
    assert_success
    # Order may vary; membership is what matters.
    assert_line "prod"
    assert_line "prod-inner"
    assert_line "lab"
    assert_line "dmz"
}

# --- scope_exists ------------------------------------------------------------

@test "scope_exists: returns 0 for known scope" {
    run scope_exists "prod"
    assert_success
    run scope_exists "lab"
    assert_success
}

@test "scope_exists: returns non-zero for unknown and empty" {
    run scope_exists "nonexistent"
    assert_failure
    run scope_exists ""
    assert_failure
}

# --- read_scope_prefixes -----------------------------------------------------

@test "read_scope_prefixes: emits canonical prefixes, sorted" {
    run read_scope_prefixes "prod"
    assert_success
    assert_output "10.0.0.0/8"

    run read_scope_prefixes "lab"
    assert_success
    # Sorted specificity-first (length DESC, then address ASC), so
    # /16 comes before /12. Matches tacquito's most-specific-wins
    # routing and what `scope routing` / `scope list` display.
    local expected="192.168.0.0/16
172.16.0.0/12"
    [[ "$output" == "$expected" ]]
}

@test "read_scope_prefixes: unknown scope → empty output" {
    run read_scope_prefixes "nonexistent"
    assert_success
    assert_output ""
}

# --- read_scope_secret -------------------------------------------------------

@test "read_scope_secret: returns raw key for named scope" {
    run read_scope_secret "prod"
    assert_success
    assert_output "prod-secret-0123456789abcdef"
    run read_scope_secret "lab"
    assert_success
    assert_output "lab-secret-0123456789abcdef"
}

@test "read_scope_secret: unknown scope → empty" {
    run read_scope_secret "nonexistent"
    assert_success
    assert_output ""
}

# --- scope_owning_prefix: FIRST-MATCH LOOKUP --------------------------------

@test "scope_owning_prefix: exact match on 10.0.0.0/8 → prod" {
    run scope_owning_prefix "10.0.0.0/8"
    assert_success
    assert_output "prod"
}

@test "scope_owning_prefix: exact match on 10.10.99.0/24 → prod-inner" {
    run scope_owning_prefix "10.10.99.0/24"
    assert_success
    assert_output "prod-inner"
}

@test "scope_owning_prefix: canonicalizes input before comparing" {
    # 10.10.99.5/24 canonicalizes to 10.10.99.0/24 → prod-inner.
    run scope_owning_prefix "10.10.99.5/24"
    assert_success
    assert_output "prod-inner"
}

@test "scope_owning_prefix: no match → empty output" {
    run scope_owning_prefix "8.8.8.0/24"
    assert_success
    assert_output ""
}

@test "scope_owning_prefix: empty input → empty" {
    run scope_owning_prefix ""
    assert_success
    assert_output ""
}

# --- read_user_scopes --------------------------------------------------------

@test "read_user_scopes: lists scopes for known user in YAML order" {
    run read_user_scopes "alice"
    assert_success
    local expected="prod
lab"
    [[ "$output" == "$expected" ]]

    run read_user_scopes "carol"
    assert_success
    expected="lab
dmz"
    [[ "$output" == "$expected" ]]
}

@test "read_user_scopes: unknown user → empty" {
    run read_user_scopes "nobody"
    assert_success
    assert_output ""
}

# --- count_users_in_scope / list_users_in_scope ------------------------------

@test "count_users_in_scope: counts scope membership across users" {
    run count_users_in_scope "lab"
    assert_success
    assert_output "3"          # alice + bob + carol

    run count_users_in_scope "prod"
    assert_success
    assert_output "1"          # alice

    run count_users_in_scope "dmz"
    assert_success
    assert_output "1"          # carol

    run count_users_in_scope "prod-inner"
    assert_success
    assert_output "0"
}

@test "list_users_in_scope: returns member usernames" {
    run list_users_in_scope "lab"
    assert_success
    assert_line "alice"
    assert_line "bob"
    assert_line "carol"

    run list_users_in_scope "prod"
    assert_success
    assert_output "alice"
}

# --- list_all_groups ---------------------------------------------------------

@test "list_all_groups: returns group anchors defined in fixture" {
    run list_all_groups
    assert_success
    assert_line "readonly"
    assert_line "operator"
    assert_line "superuser"
}

# --- get_group_privlvl -------------------------------------------------------

@test "get_group_privlvl: returns Cisco priv-lvl for built-in groups" {
    run get_group_privlvl "readonly"
    assert_success
    assert_output "1"
    run get_group_privlvl "operator"
    assert_success
    assert_output "7"
    run get_group_privlvl "superuser"
    assert_success
    assert_output "15"
}

@test "get_group_privlvl: unknown group → empty" {
    run get_group_privlvl "nonexistent"
    assert_success
    assert_output ""
}
