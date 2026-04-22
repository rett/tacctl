#!/usr/bin/env bats
# Unit tests for the conf_* helpers that back the unified tacctl config.

load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

# --- conf_get ---------------------------------------------------------------

@test "conf_get: returns default from conf_emit_defaults when no override" {
    run conf_get bcrypt.cost
    assert_success
    assert_output "12"
}

@test "conf_get: empty when path missing and no fallback" {
    run conf_get nonexistent.key
    assert_success
    assert_output ""
}

@test "conf_get: returns fallback when path missing" {
    run conf_get nonexistent.key "my-fallback"
    assert_success
    assert_output "my-fallback"
}

@test "conf_get: overrides win over defaults" {
    conf_set bcrypt.cost 14
    run conf_get bcrypt.cost
    assert_output "14"
}

@test "conf_get: deep merge keeps sibling defaults when overriding one key" {
    conf_set password.max_age_days 180

    run conf_get password.max_age_days
    assert_output "180"
    # password.min_length wasn't overridden — still the default.
    run conf_get password.min_length
    assert_output "12"
}

@test "conf_get: canonical defaults come from conf_emit_defaults()" {
    # No override file → the in-script defaults answer.
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
    run conf_get bcrypt.cost
    assert_output "12"
    run conf_get mgmt_acl.names.cisco
    assert_output "VTY-ACL"
    # Fallback arg only kicks in for paths that aren't covered by defaults.
    run conf_get nonexistent.key 99
    assert_output "99"
}

# --- conf_set ---------------------------------------------------------------

@test "conf_set: creates tacctl.yaml with 0640 perms" {
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
    conf_set bcrypt.cost 14
    [[ -f "$TACCTL_OVERRIDES_FILE" ]]
    [[ "$(stat -c %a "$TACCTL_OVERRIDES_FILE")" == "640" ]]
}

@test "conf_set: revert-to-default deletes the key (overrides file pruned)" {
    conf_set bcrypt.cost 14
    [[ -f "$TACCTL_OVERRIDES_FILE" ]]
    conf_set bcrypt.cost 12    # 12 is the default
    # With only that one key reverted, overrides dict is empty → file removed.
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
}

@test "conf_set: coerces integers and booleans" {
    conf_set bcrypt.cost 14        # int
    conf_set scope.default "prod"  # string

    run grep 'cost: 14' "$TACCTL_OVERRIDES_FILE"
    assert_success
    run grep 'default: prod' "$TACCTL_OVERRIDES_FILE"
    assert_success
}

# --- conf_unset -------------------------------------------------------------

@test "conf_unset: drops the key + prunes empty parent maps" {
    conf_set mgmt_acl.names.cisco CUSTOM
    run grep 'cisco: CUSTOM' "$TACCTL_OVERRIDES_FILE"
    assert_success

    conf_unset mgmt_acl.names.cisco
    # The nested names block was sole-key; pruning should remove it entirely.
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
}

@test "conf_unset: missing key is a no-op" {
    conf_set bcrypt.cost 14
    conf_unset nonexistent.key
    run conf_get bcrypt.cost
    assert_output "14"
}

# --- list helpers -----------------------------------------------------------

@test "conf_set_list + conf_get_list round-trip" {
    printf '%s\n' 10.0.0.0/8 192.168.1.0/24 | conf_set_list mgmt_acl.permits
    run conf_get_list mgmt_acl.permits
    assert_line "10.0.0.0/8"
    assert_line "192.168.1.0/24"
}

@test "conf_set_list: lists replace wholesale on override (no concatenation)" {
    # Shadow conf_emit_defaults to pretend the default list is non-empty.
    # conf_get/conf_set both call the function; overriding it here exercises
    # the merge path without touching the canonical defaults in the script.
    conf_emit_defaults() {
        printf '%s\n' \
            'bcrypt:' '  cost: 12' \
            'privileges:' '  operator:' '    - show running-config'
    }
    _conf_invalidate

    run conf_get_list privileges.operator
    assert_output "show running-config"

    # Override with a single different command — default list is NOT merged in.
    printf 'show version\n' | conf_set_list privileges.operator
    run conf_get_list privileges.operator
    assert_output "show version"
}

@test "conf_set_list: empty input unsets (revert to default)" {
    printf '%s\n' 10.0.0.0/8 | conf_set_list mgmt_acl.permits
    run conf_get_list mgmt_acl.permits
    assert_output "10.0.0.0/8"

    printf '' | conf_set_list mgmt_acl.permits
    # Default is [], so empty-list == default → key unset → file pruned.
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
}

# --- conf_get_keys ----------------------------------------------------------

@test "conf_get_keys: enumerates the keys of a map" {
    conf_set mgmt_acl.names.cisco A
    conf_set mgmt_acl.names.juniper B

    run conf_get_keys mgmt_acl.names
    assert_line "cisco"
    assert_line "juniper"
}

@test "conf_get_keys: empty when path is a scalar / absent" {
    run conf_get_keys bcrypt.cost     # scalar, not a map
    assert_output ""
    run conf_get_keys nonexistent
    assert_output ""
}

# --- Schema validation (C) --------------------------------------------------

@test "conf_set: rejects out-of-range int with clear diagnostic" {
    run conf_set bcrypt.cost 99
    assert_failure
    assert_output --partial "bcrypt.cost: must be <= 14; got 99"
    # Nothing written.
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
}

@test "conf_set: rejects non-numeric where int required" {
    run conf_set bcrypt.cost abc
    assert_failure
    assert_output --partial "must be an integer"
}

@test "conf_set: rejects unknown key as typo" {
    run conf_set bcrypt.cst 14    # typo: cst instead of cost
    assert_failure
    assert_output --partial "unknown config key"
}

@test "conf_set: rejects ACL name not matching pattern" {
    run conf_set mgmt_acl.names.cisco "1bad-start"
    assert_failure
    assert_output --partial "must start with a letter"
}

@test "conf_set_list: rejects malformed CIDRs" {
    run conf_set_list mgmt_acl.permits <<< "10.0.0.0/8
garbage"
    assert_failure
    assert_output --partial "element 1: 'garbage' is not a valid CIDR"
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
}

@test "conf_set_list: rejects malformed cisco priv-exec strings" {
    run conf_set_list privileges.operator <<< "show version
show; rm"
    assert_failure
    assert_output --partial "element 1:"
    assert_output --partial "invalid characters"
}

@test "conf_set_list: rejects scalar mis-call on list path" {
    run conf_set mgmt_acl.permits "10.0.0.0/8"
    assert_failure
    assert_output --partial "requires list input"
}

@test "conf_set: rejects list mis-call on scalar path" {
    run conf_set_list bcrypt.cost <<< "12"
    assert_failure
    assert_output --partial "does not accept list input"
}

# --- Overrides-file schema scan (tacctl config validate) -------------------

@test "_conf_validate_overrides_file: no output on a clean file" {
    conf_set bcrypt.cost 14
    run _conf_validate_overrides_file
    assert_output ""
}

@test "_conf_validate_overrides_file: catches hand-edited out-of-range" {
    printf 'bcrypt:\n  cost: 99\n' > "$TACCTL_OVERRIDES_FILE"
    run _conf_validate_overrides_file
    assert_output --partial "bcrypt.cost: must be <= 14"
}

@test "_conf_validate_overrides_file: catches hand-edited unknown key" {
    printf 'bcrypt:\n  cst: 14\n' > "$TACCTL_OVERRIDES_FILE"
    run _conf_validate_overrides_file
    assert_output --partial "bcrypt.cst: unknown config key"
}

@test "_conf_validate_overrides_file: catches malformed list elements" {
    printf 'mgmt_acl:\n  permits:\n    - 10.0.0.0/8\n    - garbage\n' > "$TACCTL_OVERRIDES_FILE"
    run _conf_validate_overrides_file
    assert_output --partial "mgmt_acl.permits:"
    assert_output --partial "not a valid CIDR"
}
