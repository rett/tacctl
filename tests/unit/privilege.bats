#!/usr/bin/env bats
# Unit tests for Cisco privilege-exec command map helpers.

load ../helpers/setup
load ../helpers/tmpenv

setup() {
    tacctl_tmpenv_init
    tacctl_source_lib
}

# --- default_privileges_for_group -------------------------------------------

@test "default_privileges_for_group: readonly → empty (priv 1 floor)" {
    run default_privileges_for_group "readonly"
    assert_success
    # Trim trailing blank line from `echo ""`
    [[ -z "$output" ]]
}

@test "default_privileges_for_group: operator → show-config family" {
    run default_privileges_for_group "operator"
    assert_success
    local expected="show running-config
show startup-config"
    [[ "$output" == "$expected" ]]
}

@test "default_privileges_for_group: superuser → empty (priv 15 ceiling)" {
    run default_privileges_for_group "superuser"
    assert_success
    [[ -z "$output" ]]
}

@test "default_privileges_for_group: unknown group → empty" {
    run default_privileges_for_group "custom-group"
    assert_success
    [[ -z "$output" ]]
}

# --- read_all_privileges / read_group_privileges -----------------------------
#
# Privilege mappings now live under privileges.<group>: in tacctl.yaml.
# Tests assert against the read_* / write_* helpers' public contract — they
# emit `group|cmd` tuples on read and accept newline-separated command lists
# on write, regardless of the on-disk YAML shape.

@test "read_all_privileges: no overrides → only shipped defaults" {
    # No override file → read_all_privileges emits only the shipped
    # defaults from conf_emit_defaults (operator's show-config family).
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
    run read_all_privileges
    assert_success
    assert_line "operator|show running-config"
    assert_line "operator|show startup-config"
    # Exactly the two default lines, nothing else.
    [[ "$(printf '%s\n' "$output" | awk 'NF' | wc -l)" == "2" ]]
}

@test "read_all_privileges: emits one group|cmd line per mapping" {
    write_group_privileges "operator" "$(printf '%s\n' 'show running-config' 'show startup-config')"
    write_group_privileges "readonly" "show version"

    run read_all_privileges
    assert_success
    assert_line "operator|show running-config"
    assert_line "operator|show startup-config"
    assert_line "readonly|show version"
    # No spurious blank lines.
    [[ "$(printf '%s\n' "$output" | awk 'NF' | wc -l)" == "3" ]]
}

@test "read_group_privileges: filters to one group's commands" {
    write_group_privileges "operator" "$(printf '%s\n' 'show running-config' 'show startup-config')"
    write_group_privileges "readonly" "show version"

    run read_group_privileges "operator"
    assert_success
    local expected="show running-config
show startup-config"
    [[ "$output" == "$expected" ]]

    run read_group_privileges "readonly"
    assert_success
    assert_output "show version"

    run read_group_privileges "superuser"
    assert_success
    assert_output ""
}

# --- write_group_privileges --------------------------------------------------

@test "write_group_privileges: creates overrides file when absent" {
    [[ ! -f "$TACCTL_OVERRIDES_FILE" ]]
    write_group_privileges "operator" "show running-config"
    [[ -f "$TACCTL_OVERRIDES_FILE" ]]

    # Round-trip reads back the single mapping.
    run read_group_privileges "operator"
    assert_output "show running-config"
}

@test "write_group_privileges: replaces only the target group's list" {
    write_group_privileges "operator" "$(printf '%s\n' 'show running-config' 'show startup-config')"
    write_group_privileges "readonly" "show version"

    write_group_privileges "operator" "show ip interface brief"

    run read_group_privileges "operator"
    assert_output "show ip interface brief"
    run read_group_privileges "readonly"
    assert_output "show version"
}

@test "write_group_privileges: empty new_list wipes the target group" {
    write_group_privileges "operator" "show running-config"
    write_group_privileges "readonly" "show version"

    write_group_privileges "operator" ""

    run read_group_privileges "operator"
    assert_output ""
    run read_group_privileges "readonly"
    assert_output "show version"
}

@test "write_group_privileges: newline-separated list preserves each item" {
    local cmds="show running-config
show startup-config
show version"
    write_group_privileges "operator" "$cmds"

    run read_group_privileges "operator"
    [[ "$output" == "$cmds" ]]
}

@test "write_group_privileges: round-trips through read_group_privileges" {
    local cmds="show running-config
show startup-config"
    write_group_privileges "operator" "$cmds"

    run read_group_privileges "operator"
    assert_success
    [[ "$output" == "$cmds" ]]
}
