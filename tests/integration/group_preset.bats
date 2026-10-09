#!/usr/bin/env bats
# Integration tests for `tacctl group preset roles` (0.2.2, D11).

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
}

@test "group preset roles --dry-run: lists every setting and writes nothing" {
    cp "$TACCTL_CONFIG" "$BATS_TEST_TMPDIR/before"
    run "$TACCTL_BIN_SCRIPT" group preset roles --dry-run
    assert_success
    assert_output --partial "readonly (viewer)"
    assert_output --partial "Junos deny-commands (112/241 bytes)"
    assert_output --partial "Junos deny-commands (226/241 bytes)"
    assert_output --partial "Junos deny-commands (192/241 bytes)"
    assert_output --partial "create (priv-lvl 15, class EN-CLASS)"
    assert_output --partial "tacctl tier engineer"
    assert_output --partial "Cisco command rules (34, default permit)"
    refute_output --partial "deny-configuration"
    refute_output --partial "management filter"
    assert_output --partial "Dry run: 12 setting(s) would change; nothing was written."
    run cmp "$TACCTL_CONFIG" "$BATS_TEST_TMPDIR/before"
    assert_success
    run "$TACCTL_BIN_SCRIPT" group show engineer
    assert_failure
}

@test "group preset roles: applies on y, renders the roles, and is idempotent" {
    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group preset roles"
    assert_success
    assert_output --partial "Role preset applied: 12 setting(s) changed."
    assert_output --partial "tacctl user move <user> engineer"
    assert_output --partial "Engineers are not restricted in configuration mode"

    run grep -A3 '^wti_exec_engineer:' "$TACCTL_CONFIG"
    assert_output --partial 'name: wti'
    # The rules reach the daemon whole: every match is ^(?:...)$, the
    # engineer's configuration mode is not restricted, its lifecycle is not.
    run grep -c 'match: \["^(?:' "$TACCTL_CONFIG"
    assert_success
    run grep -A2 'name: "reload"' "$TACCTL_CONFIG"
    assert_output --partial 'action: *action_deny'
    run grep -c 'name: "username"' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -A1 'name: "show"' "$TACCTL_CONFIG"
    assert_output --partial '^(?:^(running-config view full|tech-support|startup-config|derived-config|key chain|snmp (community|user)|crypto|archive log)( .*)?$)$'

    run "$TACCTL_BIN_SCRIPT" group preset roles --dry-run
    assert_success
    assert_output --partial "Nothing to change."
    refute_output --partial "  set"
}

@test "group preset roles: a different value is kept unless --force; an existing engineer keeps its priv-lvl" {
    "$TACCTL_BIN_SCRIPT" group add engineer 14 RW-CLASS
    "$TACCTL_BIN_SCRIPT" group edit operator wti-level superuser
    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group preset roles"
    assert_success
    assert_output --regexp "Juniper class EN-CLASS +kept \(pass --force\)"
    assert_output --regexp "WTI level user +kept \(pass --force\)"
    run "$TACCTL_BIN_SCRIPT" group show operator
    assert_output --partial "WTI level:         SuperUser (set"

    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group preset roles --force"
    assert_success
    assert_output --regexp "WTI level user +replaced"
    run "$TACCTL_BIN_SCRIPT" group show engineer
    assert_output --partial "Cisco priv-lvl:    14"
    assert_output --partial "Juniper class:     EN-CLASS"
}

@test "group preset roles: the 0.2.2 engineer deny-configuration is kept unless --force clears it" {
    "$TACCTL_BIN_SCRIPT" group add engineer 15 EN-CLASS
    "$TACCTL_BIN_SCRIPT" group junos engineer deny-configuration add '^(snmp|system login)'
    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group preset roles"
    assert_success
    assert_output --regexp "Junos deny-configuration \(0/236 bytes\) +kept \(pass --force\)"
    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group preset roles --force"
    assert_success
    assert_output --regexp "Junos deny-configuration \(0/236 bytes\) +replaced"
    run "$TACCTL_BIN_SCRIPT" group show engineer
    refute_output --partial "deny-configuration"
}

@test "group preset roles: answering no changes nothing; --mgmt-filter is gone" {
    run bash -c "echo n | '$TACCTL_BIN_SCRIPT' group preset roles"
    assert_output --partial "Aborted."
    run "$TACCTL_BIN_SCRIPT" group show engineer
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group preset roles --mgmt-filter MGMT-FILTER
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group preset
    assert_failure
    assert_output --partial "Usage: tacctl group preset roles"
}
