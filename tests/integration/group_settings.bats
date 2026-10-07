#!/usr/bin/env bats
# Integration tests for the per-group device settings of 0.2.2:
# `tacctl group junos`, `group edit <g> wti-level|tier`, `group add
# --tier/--wti-level` and `group show`.

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

@test "group junos: add renders deny-commands into junos-exec; list shows it with its size" {
    run "$TACCTL_BIN_SCRIPT" group junos operator deny-commands add '^(request|start shell)( .*)?$'
    assert_success
    assert_output --partial "Added to deny-commands of group 'operator' (now 1 pattern, 31 of 241 bytes)."

    run grep -A8 '^junos_exec_operator:' "$TACCTL_CONFIG"
    assert_output --partial '- name: deny-commands'
    assert_output --partial 'values: ["(^(request|start shell)( .*)?$)"]'

    run "$TACCTL_BIN_SCRIPT" group junos operator list
    assert_success
    assert_output --partial "Junos rules for group 'operator' (class OP-CLASS)"
    assert_output --partial "deny-commands        1 pattern    31 of 241 bytes"
    assert_output --partial "deny-configuration   none"
}

@test "group junos: a duplicate is no change; an unknown remove warns; remove drops it" {
    "$TACCTL_BIN_SCRIPT" group junos operator deny-configuration add '^snmp'
    run "$TACCTL_BIN_SCRIPT" group junos operator deny-configuration add '^snmp'
    assert_success
    assert_output --partial "already present"
    run "$TACCTL_BIN_SCRIPT" group junos operator deny-configuration remove '^nothing'
    assert_success
    assert_output --partial "Pattern not in deny-configuration of group 'operator'."
    run "$TACCTL_BIN_SCRIPT" group junos operator deny-configuration remove '^snmp'
    assert_success
    run grep -c 'deny-configuration' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "group junos: a set over the limit is refused and nothing is written" {
    run "$TACCTL_BIN_SCRIPT" group junos operator deny-commands add "^$(printf 'x%.0s' {1..240})"
    assert_failure
    assert_output --partial "Group 'operator': deny-commands would be 243 bytes; the limit is 241"
    assert_output --partial "tacctl group junos operator deny-commands list"
    run grep -c 'deny-commands' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "group junos: a pattern that is not POSIX ERE is refused" {
    run "$TACCTL_BIN_SCRIPT" group junos operator deny-commands add '(?i)^show'
    assert_failure
    assert_output --partial "not POSIX ERE"
}

@test "group junos clear: confirms, then drops both sets" {
    "$TACCTL_BIN_SCRIPT" group junos operator deny-commands add '^request'
    "$TACCTL_BIN_SCRIPT" group junos operator deny-configuration add '^snmp'
    run bash -c "echo n | '$TACCTL_BIN_SCRIPT' group junos operator clear"
    assert_output --partial "Aborted."
    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group junos operator clear"
    assert_success
    assert_output --partial "Cleared deny-commands and deny-configuration of group 'operator'."
    run grep -c 'deny-' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "group edit wti-level: adds a wti service; auto removes it" {
    run "$TACCTL_BIN_SCRIPT" group edit superuser wti-level superuser
    assert_success
    assert_output --partial "WTI level set to superuser (TACACS+: service wti priv-lvl 10; RADIUS: WTI-Super 2)."
    assert_output --partial "Service Name 'wti'"
    run grep -A5 '^wti_exec_superuser:' "$TACCTL_CONFIG"
    assert_output --partial 'name: wti'
    assert_output --partial 'values: [10]'
    run grep -c -- '- \*wti_exec_superuser' "$TACCTL_CONFIG"
    assert_output "1"

    run "$TACCTL_BIN_SCRIPT" group edit superuser wti-level auto
    assert_success
    assert_output --partial "automatic again (priv-lvl 15 → Administrator)"
    run grep -c 'wti_exec_' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "group edit wti-level / tier: unknown values are refused" {
    run "$TACCTL_BIN_SCRIPT" group edit operator wti-level root
    assert_failure
    assert_output --partial "Unknown WTI level 'root'"
    run "$TACCTL_BIN_SCRIPT" group edit operator tier root
    assert_failure
    assert_output --partial "Unknown tier 'root'"
}

@test "group add --tier --wti-level, show, then remove forgets the settings" {
    run "$TACCTL_BIN_SCRIPT" group add engineer 15 ENG-CLASS --tier engineer --wti-level superuser
    assert_success
    assert_output --partial "tacctl tier: engineer."
    "$TACCTL_BIN_SCRIPT" group junos engineer deny-configuration add '^snmp'

    run "$TACCTL_BIN_SCRIPT" group show engineer
    assert_success
    assert_output --partial "Cisco priv-lvl:    15"
    assert_output --partial "Juniper class:     ENG-CLASS"
    assert_output --partial "tacctl tier:       engineer (set; auto would be superuser)"
    assert_output --partial "WTI level:         SuperUser (set; auto would be Administrator)"
    assert_output --partial "deny-configuration 7/236 bytes"

    run "$TACCTL_BIN_SCRIPT" group show operator
    assert_output --partial "tacctl tier:       operator (auto, from priv-lvl)"
    assert_output --partial "WTI level:         User (auto, from priv-lvl)"

    run bash -c "echo y | '$TACCTL_BIN_SCRIPT' group remove engineer"
    assert_success
    run grep -E '^(junos|wti_level|tier):|engineer' "$TACCTL_STATE_DIR/tacctl.yaml"
    assert_failure
}
