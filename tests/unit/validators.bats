#!/usr/bin/env bats
# Unit tests for validate_* / is_* pure-logic helpers.

load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

# --- validate_username -------------------------------------------------------

@test "validate_username: accepts alphanumeric + underscore + hyphen" {
    run validate_username "jsmith"
    assert_success
    run validate_username "j_smith-2"
    assert_success
    run validate_username "A1"
    assert_success
}

@test "validate_username: rejects whitespace" {
    run validate_username "j smith"
    assert_failure
    assert_output --partial "letters, numbers"
}

@test "validate_username: rejects empty" {
    run validate_username ""
    assert_failure
}

@test "validate_username: rejects shell metacharacters" {
    run validate_username 'foo;rm'
    assert_failure
    run validate_username 'foo$bar'
    assert_failure
    run validate_username 'foo/bar'
    assert_failure
    run validate_username 'foo.bar'
    assert_failure
}

# --- validate_class_name -----------------------------------------------------

@test "validate_class_name: same rules as username" {
    run validate_class_name "readonly"
    assert_success
    run validate_class_name "my-group_1"
    assert_success
    run validate_class_name "bad group"
    assert_failure
    run validate_class_name ""
    assert_failure
}

# --- validate_regex ----------------------------------------------------------

@test "validate_regex: accepts valid python regex" {
    run validate_regex '^show .*$'
    assert_success
    run validate_regex 'config(ure)?'
    assert_success
}

@test "validate_regex: rejects invalid regex" {
    run validate_regex '('
    assert_failure
    assert_output --partial "Invalid regex"
}

# --- validate_priv_command_string --------------------------------------------

@test "validate_priv_command_string: accepts cisco commands with spaces" {
    run validate_priv_command_string "show running-config"
    assert_success
    run validate_priv_command_string "terminal monitor"
    assert_success
}

@test "validate_priv_command_string: rejects empty" {
    run validate_priv_command_string ""
    assert_failure
    assert_output --partial "must not be empty"
}

@test "validate_priv_command_string: rejects leading/trailing whitespace" {
    run validate_priv_command_string " show"
    assert_failure
    run validate_priv_command_string "show "
    assert_failure
}

@test "validate_priv_command_string: rejects shell metacharacters" {
    run validate_priv_command_string 'show; rm'
    assert_failure
    run validate_priv_command_string 'show$(pwd)'
    assert_failure
}

@test "validate_priv_command_string: rejects >64 chars" {
    run validate_priv_command_string "$(printf 'a%.0s' {1..65})"
    assert_failure
    assert_output --partial "too long"
}

# --- validate_command_name ---------------------------------------------------

@test "validate_command_name: accepts single wildcard" {
    run validate_command_name "*"
    assert_success
}

@test "validate_command_name: accepts typical verbs" {
    run validate_command_name "show"
    assert_success
    run validate_command_name "configure"
    assert_success
    run validate_command_name "ping"
    assert_success
}

@test "validate_command_name: rejects digits-first, spaces, wildcard-mixed" {
    run validate_command_name "1show"
    assert_failure
    run validate_command_name "show all"
    assert_failure
    run validate_command_name "show*"
    assert_failure
}

# --- validate_acl_name -------------------------------------------------------

@test "validate_acl_name: accepts letter-start, letters/digits/_/-" {
    run validate_acl_name "VTY-ACL"
    assert_success
    run validate_acl_name "mgmt_ssh_v2"
    assert_success
}

@test "validate_acl_name: rejects empty, digit-start, too-long" {
    run validate_acl_name ""
    assert_failure
    run validate_acl_name "1-ACL"
    assert_failure
    run validate_acl_name "$(printf 'A%.0s' {1..64})"
    assert_failure
    assert_output --partial "too long"
}

# --- is_disabled_hash --------------------------------------------------------

@test "is_disabled_hash: recognizes the hex marker" {
    run is_disabled_hash "$DISABLED_MARKER_HEX"
    assert_success
}

@test "is_disabled_hash: rejects real-looking hashes and empty" {
    run is_disabled_hash ""
    assert_failure
    run is_disabled_hash '$2b$12$somehashvalue'
    assert_failure
    # The plain "DISABLED" literal was a legacy marker; no longer recognized.
    run is_disabled_hash "DISABLED"
    assert_failure
}
