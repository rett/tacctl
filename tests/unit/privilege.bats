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

@test "read_all_privileges: missing file → empty" {
    [[ ! -f "$PRIVILEGE_FILE" ]]
    run read_all_privileges
    assert_success
    assert_output ""
}

@test "read_all_privileges: strips comments and blank lines, preserves mappings" {
    cat > "$PRIVILEGE_FILE" <<EOF
# header comment
# another comment

operator|show running-config
operator|show startup-config
readonly|show version

# trailing comment
EOF
    run read_all_privileges
    assert_success
    local expected="operator|show running-config
operator|show startup-config
readonly|show version"
    [[ "$output" == "$expected" ]]
}

@test "read_group_privileges: filters to one group's commands" {
    cat > "$PRIVILEGE_FILE" <<EOF
operator|show running-config
operator|show startup-config
readonly|show version
EOF
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

@test "write_group_privileges: creates file with header when absent" {
    [[ ! -f "$PRIVILEGE_FILE" ]]
    write_group_privileges "operator" "show running-config"
    [[ -f "$PRIVILEGE_FILE" ]]

    # Header + single mapping line.
    run grep -c '^operator|' "$PRIVILEGE_FILE"
    assert_output "1"
    run grep -q '^# tacctl-managed' "$PRIVILEGE_FILE"
    assert_success
}

@test "write_group_privileges: replaces only the target group's lines" {
    cat > "$PRIVILEGE_FILE" <<EOF
# tacctl-managed Cisco priv-exec command mappings.
operator|show running-config
operator|show startup-config
readonly|show version
EOF
    write_group_privileges "operator" "show ip interface brief"
    # operator lines replaced; readonly untouched.
    run grep '^operator|' "$PRIVILEGE_FILE"
    assert_output "operator|show ip interface brief"
    run grep '^readonly|' "$PRIVILEGE_FILE"
    assert_output "readonly|show version"
}

@test "write_group_privileges: empty new_list wipes target group's lines" {
    cat > "$PRIVILEGE_FILE" <<EOF
operator|show running-config
readonly|show version
EOF
    write_group_privileges "operator" ""
    run grep -c '^operator|' "$PRIVILEGE_FILE"
    assert_output "0"
    run grep '^readonly|' "$PRIVILEGE_FILE"
    assert_output "readonly|show version"
}

@test "write_group_privileges: newline-separated list writes each line" {
    local cmds="show running-config
show startup-config
show version"
    write_group_privileges "operator" "$cmds"
    run grep -c '^operator|' "$PRIVILEGE_FILE"
    assert_output "3"
}

@test "write_group_privileges: round-trips through read_group_privileges" {
    local cmds="show running-config
show startup-config"
    write_group_privileges "operator" "$cmds"
    run read_group_privileges "operator"
    assert_success
    [[ "$output" == "$cmds" ]]
}
