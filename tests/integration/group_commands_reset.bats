#!/usr/bin/env bats
# Integration tests for `tacctl group commands reset` (0.2.3, D51, WP10.5h):
# the command rules of one group back to the shipped defaults, with the diff
# and a confirmation of `group reset`.

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
    YAML="${TACCTL_STATE_DIR}/tacctl.yaml"
    STORE="${TACCTL_STATE_DIR}/store.yaml"
}

# prun <command...>: run, with the colours taken out of $output.
prun() {
    run "$@"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

# on_tty <stdin text> <args...>: tacctl on a pseudo-terminal fed the text.
on_tty() {
    local input="$1" cmd
    shift
    printf -v cmd '%q ' "$TACCTL_BIN_SCRIPT" "$@"
    prun bash -c "printf '%b' '$input' | script -qec '$cmd' /dev/null"
    output=${output//$'\r'/}
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

modify_operator() {
    "$TACCTL_BIN_SCRIPT" group commands add operator configure --action permit > /dev/null
    "$TACCTL_BIN_SCRIPT" group commands default operator permit > /dev/null
}

@test "group commands reset: a group in its canonical state says so and asks nothing" {
    for g in readonly operator superuser; do
        prun "$TACCTL_BIN_SCRIPT" group commands reset "$g"
        assert_success
        assert_output --partial "Group '$g' is already canonical (commands); nothing to change."
    done
}

@test "group commands reset --dry-run: prints the rules diff and writes nothing" {
    modify_operator
    cp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    cp "$TACCTL_CONFIG" "$BATS_TEST_TMPDIR/tacquito.before"
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --dry-run
    assert_success
    assert_output --partial "Reset of the command rules of group 'operator' to the shipped default"
    assert_output --partial "    - configure    permit"
    assert_output --partial "    - *            permit"
    assert_output --partial "    + *            deny"
    assert_output --partial "    default action: permit -> deny"
    assert_output --partial "Dry run: nothing was written."
    run cmp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    assert_success
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
    run cmp "$TACCTL_CONFIG" "$BATS_TEST_TMPDIR/tacquito.before"
    assert_success
    if stub_called '^logger .*group commands reset'; then echo 'audit line written'; return 1; fi
}

@test "group commands reset: without a terminal and without --yes it refuses and changes nothing" {
    modify_operator
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    prun bash -c "echo y | '$TACCTL_BIN_SCRIPT' group commands reset operator"
    assert_failure 1
    assert_output --partial "    - configure    permit"
    assert_output --partial "No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes."
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
}

@test "group commands reset --yes: applies, re-renders, logs, and a second run changes nothing" {
    modify_operator
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --yes
    assert_success
    assert_output --partial "Group 'operator': the command rules are back to the shipped default."
    stub_called '^logger -t tacctl -p auth.info group commands reset name=operator by='
    prun "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial "Default action: deny"
    assert_output --partial "show"
    refute_output --partial "configure"
    run grep -c 'name: "configure"' "$TACCTL_CONFIG"
    assert_output "0"
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --yes
    assert_success
    assert_output --partial "already canonical (commands); nothing to change."
    if stub_called '^logger .*group commands reset'; then echo 'audit line written'; return 1; fi
}

@test "group commands reset: the prompt answered n changes nothing, answered y applies" {
    modify_operator
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    on_tty 'n\n' group commands reset operator
    assert_success
    assert_output --partial "Apply these changes to the command rules of group 'operator'? [y/N]:"
    assert_output --partial "Aborted."
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
    on_tty '\n' group commands reset operator
    assert_output --partial "Aborted."
    on_tty 'y\n' group commands reset operator
    assert_success
    assert_output --partial "the command rules are back to the shipped default."
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator
    assert_output --partial "already canonical"
}

@test "group commands reset: a custom group has no shipped rules, so its override is removed" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HD-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group commands add helpdesk show > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group commands reset helpdesk --dry-run
    assert_success
    assert_output --partial "warning: group 'helpdesk' has no command rules at priv-lvl 5"
    prun "$TACCTL_BIN_SCRIPT" group commands reset helpdesk --yes
    assert_success
    assert_output --partial "the override of its command rules is removed; none are shipped for it, so it has none."
    run grep -F 'helpdesk' "$YAML"
    assert_failure
    prun "$TACCTL_BIN_SCRIPT" group commands list helpdesk
    assert_output --partial "no commands"
}

@test "group commands reset: the lockout guard gives a sibling without rules a permit catchall, as group reset does" {
    "$TACCTL_BIN_SCRIPT" group commands add operator configure --action permit > /dev/null
    "$TACCTL_BIN_SCRIPT" group add helpdesk 7 HD-CLASS > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --dry-run
    assert_output --partial "Groups at priv-lvl 7 without command rules get a permit-* catchall, so that Cisco does not deny them every command: helpdesk"
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --yes
    assert_success
    assert_output --partial "Auto-seeded permit-* catchall on sibling groups at priv-lvl 7: helpdesk"
    prun "$TACCTL_BIN_SCRIPT" group commands list helpdesk
    assert_output --partial "Default action: permit"
}

@test "group commands reset equals group reset --only commands for a built-in group" {
    modify_operator
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --dry-run
    local a=$output
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only commands --dry-run
    local b=$output
    [[ "$(grep -E '^    ' <<< "$a")" == "$(grep -E '^    ' <<< "$b")" ]]
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --yes
    assert_success
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only commands
    assert_output --partial "already canonical (commands)"
}

@test "group commands reset: refusals, and clear is gone" {
    prun "$TACCTL_BIN_SCRIPT" group commands reset ghost --yes
    assert_failure 1
    assert_output --partial "Group 'ghost' does not exist."
    prun "$TACCTL_BIN_SCRIPT" group commands reset
    assert_failure 1
    assert_output --partial "Usage: tacctl group commands reset <group> [--dry-run] [--yes]"
    prun "$TACCTL_BIN_SCRIPT" group commands reset operator --preset
    assert_failure 1
    assert_output --partial "Usage: tacctl group commands reset <group> [--dry-run] [--yes]"
    prun "$TACCTL_BIN_SCRIPT" group commands clear operator
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'clear'"
    refute_output --partial "clear <group>"
}
