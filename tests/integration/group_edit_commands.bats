#!/usr/bin/env bats
# Integration tests for `tacctl group edit` + `tacctl group commands`.

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

# =============================================================================
#  group edit
# =============================================================================

@test "group edit priv-lvl: rewrites the exec service values" {
    run "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 10
    assert_success
    assert_output --partial "changed to 10"

    run grep -A5 '^exec_operator:' "$TACCTL_CONFIG"
    assert_output --partial "values: [10]"
    refute_output --partial "values: [7]"
}

@test "group edit juniper-class: rewrites the junos-exec values and its comment" {
    run "$TACCTL_BIN_SCRIPT" group edit operator juniper-class NEW-OP-CLASS
    assert_success
    assert_output --partial "changed to NEW-OP-CLASS"

    run grep -A5 '^junos_exec_operator:' "$TACCTL_CONFIG"
    assert_output --partial 'NEW-OP-CLASS'
    refute_output --partial '"OP-CLASS"'
}

@test "group edit: rejects missing args" {
    run "$TACCTL_BIN_SCRIPT" group edit
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group edit operator
    assert_failure
    run "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl
    assert_failure
}

@test "group edit: rejects unknown group" {
    run "$TACCTL_BIN_SCRIPT" group edit nosuchgroup priv-lvl 5
    assert_failure
    assert_output --partial "does not exist"
}

@test "group edit priv-lvl: rejects out-of-range values" {
    run "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 99
    assert_failure
    assert_output --partial "0-15"
}

@test "group edit juniper-class: rejects invalid class names" {
    run "$TACCTL_BIN_SCRIPT" group edit operator juniper-class "bad class"
    assert_failure
}

@test "group edit: rejects unknown field" {
    run "$TACCTL_BIN_SCRIPT" group edit operator foo bar
    assert_failure
    assert_output --partial "Unknown field"
}

# =============================================================================
#  group commands
# =============================================================================

@test "group commands list: operator ships with default rules + deny catch-all" {
    # Under the unified-config model, tacctl.yaml (merged with conf_emit_defaults)
    # is the source of truth. Operator's shipped defaults: 4 explicit permits
    # (show/ping/traceroute/terminal) + deny catch-all.
    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_success
    assert_output --partial "Default action"
    assert_output --partial "deny"
    assert_output --partial "show"
    assert_output --partial "ping"
}

@test "group commands list: superuser ships with a permit catch-all only" {
    run "$TACCTL_BIN_SCRIPT" group commands list superuser
    assert_success
    assert_output --partial "permit"
}

@test "group commands list: custom group without rules reports 'no commands'" {
    "$TACCTL_BIN_SCRIPT" group add netops 10 NET-CLASS
    run "$TACCTL_BIN_SCRIPT" group commands list netops
    assert_success
    assert_output --partial "no commands"
}

@test "group commands default: seeds block and sets catchall to deny" {
    run "$TACCTL_BIN_SCRIPT" group commands default operator deny
    assert_success
    assert_output --partial "default action set to deny"

    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial "deny"
}

@test "group commands default: rejects non-{permit,deny} values" {
    run "$TACCTL_BIN_SCRIPT" group commands default operator maybe
    assert_failure
}

@test "group commands add: inserts a named rule with a regex match" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^show .*$' --action permit
    assert_success

    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial "show"
    assert_output --partial "permit"
    assert_output --partial '^show .*$'
}

@test "group commands add: rejects '*' (must use default)" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator '*' --action permit
    assert_failure
    assert_output --partial "catchall"
}

@test "group commands add: rejects invalid name" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator '1bad' --action permit
    assert_failure
}

@test "group commands add: rejects invalid regex in --match" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '(' --action permit
    assert_failure
}

@test "group commands add: rejects invalid --action" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^show' --action maybe
    assert_failure
}

@test "group commands add: rejects unknown flag" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --bogus "foo"
    assert_failure
    assert_output --partial "Unknown flag"
}

@test "group commands add: idempotent for the same (name, match) pair" {
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^show' --action permit
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^show' --action permit
    assert_success
    assert_output --partial "already present"
}

@test "group commands remove: drops a named rule" {
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^show' --action permit
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show
    assert_success
    assert_output --partial "Removed rule"

    run "$TACCTL_BIN_SCRIPT" group commands list operator
    # 'show' shouldn't appear as a rule name anymore, but 'permit' still will
    # (the catchall). Check that the regex is gone.
    refute_output --partial '^show'
}

@test "group commands remove: refuses to drop the catchall" {
    run "$TACCTL_BIN_SCRIPT" group commands remove operator '*'
    assert_failure
    assert_output --partial "Cannot remove the '*' catchall"
}

@test "group commands remove: warns when rule is absent (exits 0)" {
    run "$TACCTL_BIN_SCRIPT" group commands remove operator missing
    assert_success
    assert_output --partial "No rule named"
}

@test "group commands clear: reverts overridden group back to shipped defaults" {
    # Set a non-default override, then clear, then re-inspect — the merged
    # view should show the shipped default rules again (not the override).
    "$TACCTL_BIN_SCRIPT" group commands default operator permit > /dev/null
    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial "permit"
    # Now clear the override.
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" group commands clear operator'
    assert_success
    assert_output --partial "Cleared command rules"

    # Back to shipped defaults: catch-all is deny, show rule present.
    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial "deny"
    assert_output --partial "show"
}

@test "group commands clear: no-op on a group without rules" {
    # Custom group never had rules → clear reports nothing to do.
    "$TACCTL_BIN_SCRIPT" group add netops 10 NET-CLASS
    run "$TACCTL_BIN_SCRIPT" group commands clear netops
    assert_success
    assert_output --partial "nothing to clear"
}

@test "group commands: errors on unknown group" {
    run "$TACCTL_BIN_SCRIPT" group commands list nosuchgroup
    assert_failure
    assert_output --partial "does not exist"
}

@test "group commands: rejects unknown subcommand" {
    run "$TACCTL_BIN_SCRIPT" group commands bogus operator
    assert_failure
    assert_output --partial "Unknown subcommand"
}
