#!/usr/bin/env bats
# Integration tests for `tacctl group` add/remove/list + privilege mappings.

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

# --- group list --------------------------------------------------------------

@test "group list: shows built-in groups from fixture" {
    run "$TACCTL_BIN_SCRIPT" group list
    assert_success
    assert_output --partial "readonly"
    assert_output --partial "operator"
    assert_output --partial "superuser"
}

# --- group add ---------------------------------------------------------------

@test "group add: creates a new group with Cisco priv-lvl + Juniper class" {
    run "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HELPDESK-CLASS
    assert_success
    assert_output --partial "added"

    # Group anchor + service anchors are in the YAML.
    run grep -c '^helpdesk: &helpdesk$' "$TACCTL_CONFIG"
    assert_output "1"
    run grep -c '^exec_helpdesk: &exec_helpdesk$' "$TACCTL_CONFIG"
    assert_output "1"
    run grep -c '^junos_exec_helpdesk: &junos_exec_helpdesk$' "$TACCTL_CONFIG"
    assert_output "1"

    # Priv-lvl lands in the exec block.
    run grep -A5 '^exec_helpdesk:' "$TACCTL_CONFIG"
    assert_output --partial "values: [5]"

    # Juniper class lands in the junos block.
    run grep -A5 '^junos_exec_helpdesk:' "$TACCTL_CONFIG"
    assert_output --partial 'HELPDESK-CLASS'
}

@test "group add: rejects missing arguments" {
    run "$TACCTL_BIN_SCRIPT" group add
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group add name
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group add name 5
    assert_failure
}

@test "group add: rejects uppercase / non-letter-starting names" {
    run "$TACCTL_BIN_SCRIPT" group add HelpDesk 5 HELPDESK
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group add 1bad 5 HELPDESK
    assert_failure
}

@test "group add: rejects duplicate group name" {
    run "$TACCTL_BIN_SCRIPT" group add superuser 14 RW-CLASS
    assert_failure
    assert_output --partial "already exists"
}

@test "group add: rejects priv-lvl outside 0..15" {
    run "$TACCTL_BIN_SCRIPT" group add netops 16 NETOPS
    assert_failure
    assert_output --partial "0-15"
    run "$TACCTL_BIN_SCRIPT" group add netops -1 NETOPS
    assert_failure
}

@test "group add: rejects invalid juniper class name" {
    run "$TACCTL_BIN_SCRIPT" group add netops 7 "bad class"
    assert_failure
}

# --- group remove ------------------------------------------------------------

@test "group remove: requires a group name" {
    run "$TACCTL_BIN_SCRIPT" group remove
    assert_failure
}

@test "group remove: refuses to delete built-in groups" {
    for g in readonly operator superuser; do
        run "$TACCTL_BIN_SCRIPT" group remove "$g"
        assert_failure
        assert_output --partial "built-in"
    done
}

@test "group remove: rejects unknown group" {
    run "$TACCTL_BIN_SCRIPT" group remove nosuchgroup
    assert_failure
    assert_output --partial "does not exist"
}

@test "group remove: deletes custom group + its service anchors" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HELPDESK

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" group remove helpdesk'
    assert_success

    run grep -c '^helpdesk: &helpdesk$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^exec_helpdesk: &exec_helpdesk$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^junos_exec_helpdesk:' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "group remove: refuses when users still reference the group" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HELPDESK
    "$TACCTL_BIN_SCRIPT" user add alice helpdesk --hash "$TEST_HASH" --scopes lab

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" group remove helpdesk'
    assert_failure
    assert_output --partial "user(s) are assigned"
}

# --- group privilege list / add / remove -------------------------------------

@test "group privilege list: shows default mappings when none explicit" {
    run "$TACCTL_BIN_SCRIPT" group privilege list operator
    assert_success
    assert_output --partial "default"
    assert_output --partial "show running-config"
}

@test "group privilege list: flips to 'explicit' once mappings are written" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator "show version"
    run "$TACCTL_BIN_SCRIPT" group privilege list operator
    assert_success
    assert_output --partial "explicit"
    assert_output --partial "show version"
}

@test "group privilege add: stores mapping under privileges.<group>" {
    run "$TACCTL_BIN_SCRIPT" group privilege add operator "show version"
    assert_success
    run conf_get_list privileges.operator
    assert_line "show version"
}

@test "group privilege add: accepts comma-separated list" {
    # First 'add' on a group with empty explicit mappings seeds from defaults
    # first (so the user's addition doesn't silently drop the conservative
    # built-ins). Operator's defaults are the two show-config lines — adding
    # two more commands yields 4 total.
    run "$TACCTL_BIN_SCRIPT" group privilege add operator "show version,show ip interface brief"
    assert_success
    run conf_get_list privileges.operator
    [[ "$(printf '%s\n' "$output" | wc -l)" == "4" ]]
    assert_line "show running-config"
    assert_line "show startup-config"
    assert_line "show version"
    assert_line "show ip interface brief"
}

@test "group privilege add: rejects invalid command strings" {
    run "$TACCTL_BIN_SCRIPT" group privilege add operator 'show; rm -rf /'
    assert_failure
}

@test "group privilege add: errors on unknown group" {
    run "$TACCTL_BIN_SCRIPT" group privilege add nosuchgroup "show version"
    assert_failure
    assert_output --partial "does not exist"
}

@test "group privilege remove: drops one command from the list" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator "show version,show users"

    run "$TACCTL_BIN_SCRIPT" group privilege remove operator "show users"
    assert_success
    run conf_get_list privileges.operator
    refute_line "show users"
    assert_line "show version"
}

@test "group privilege clear: wipes all mappings for a group" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator "show version,show users"

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" group privilege clear operator'
    assert_success
    run conf_get_list privileges.operator
    assert_output ""
}

@test "group privilege list: priv-lvl 1 (readonly) has no mappings to emit" {
    run "$TACCTL_BIN_SCRIPT" group privilege list readonly
    assert_success
    # 'readonly' is priv-lvl 1 (the floor) — its default is intentionally empty.
    refute_output --partial "show running-config"
}
