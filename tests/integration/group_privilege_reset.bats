#!/usr/bin/env bats
# Integration tests for `tacctl group privilege reset` (0.2.3, D51, WP10.5h):
# the privileges of one group back to the shipped default, with the diff and a
# confirmation of `group reset`.

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

@test "group privilege reset: a group in its canonical state says so and asks nothing" {
    for g in readonly operator superuser; do
        prun "$TACCTL_BIN_SCRIPT" group privilege reset "$g"
        assert_success
        assert_output --partial "Group '$g' is already canonical (privileges); nothing to change."
    done
}

@test "group privilege reset --dry-run: prints the diff and the device lines, writes nothing" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version,configure: router bgp' > /dev/null
    "$TACCTL_BIN_SCRIPT" group privilege remove operator 'clear counters' > /dev/null
    cp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator --dry-run
    assert_success
    assert_output --partial "Reset of the privileges of group 'operator' to the shipped default"
    assert_output --partial "    - show version"
    assert_output --partial "    - configure: router bgp"
    assert_output --partial "    + clear counters"
    assert_output --partial "warning: devices keep the old 'privilege exec level 7 ...' lines until you re-paste tacctl config cisco and remove them (no privilege exec level 7 ...):"
    assert_output --partial "      no privilege exec level 7 show version"
    assert_output --partial "      no privilege configure level 7 router bgp"
    assert_output --partial "Dry run: nothing was written."
    run cmp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    assert_success
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
    if stub_called '^logger .*group privilege reset'; then echo 'audit line written'; return 1; fi
}

@test "group privilege reset: without a terminal and without --yes it refuses and changes nothing" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version' > /dev/null
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    # A piped 'y' is not a confirmation.
    prun bash -c "echo y | '$TACCTL_BIN_SCRIPT' group privilege reset operator"
    assert_failure 1
    assert_output --partial "    - show version"
    assert_output --partial "No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes."
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
}

@test "group privilege reset --yes: applies, logs, and a second run changes nothing" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version' > /dev/null
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator --yes
    assert_success
    assert_output --partial "Group 'operator': the privileges are back to the shipped default."
    stub_called '^logger -t tacctl -p auth.info group privilege reset name=operator by='
    prun "$TACCTL_BIN_SCRIPT" group privilege list operator
    assert_output --partial "Source: default"
    refute_output --partial "show version"
    if [[ -e "$YAML" ]] && grep -q 'privileges' "$YAML"; then cat "$YAML"; return 1; fi
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator --yes
    assert_success
    assert_output --partial "already canonical (privileges); nothing to change."
    if stub_called '^logger .*group privilege reset'; then echo 'audit line written'; return 1; fi
}

@test "group privilege reset: the prompt answered n changes nothing, answered y applies" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version' > /dev/null
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    on_tty 'n\n' group privilege reset operator
    assert_success
    assert_output --partial "Apply these changes to the privileges of group 'operator'? [y/N]:"
    assert_output --partial "Aborted."
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
    on_tty '\n' group privilege reset operator
    assert_output --partial "Aborted."
    on_tty 'y\n' group privilege reset operator
    assert_success
    assert_output --partial "Apply these changes to the privileges of group 'operator'? [y/N]:"
    assert_output --partial "the privileges are back to the shipped default."
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator
    assert_output --partial "already canonical"
}

@test "group privilege reset: the empty list an old clear stored is a change to the shipped default" {
    "$TACCTL_BIN_SCRIPT" group privilege remove readonly 'show running-config' > /dev/null
    run grep -F 'readonly: []' "$YAML"
    assert_success
    prun "$TACCTL_BIN_SCRIPT" group privilege reset readonly --dry-run
    assert_success
    assert_output --partial "    + show running-config"
    prun "$TACCTL_BIN_SCRIPT" group privilege reset readonly --yes
    assert_success
    prun "$TACCTL_BIN_SCRIPT" group privilege list readonly
    assert_output --partial "Source: default"
}

@test "group privilege reset: a custom group has no shipped list, so its override is removed" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HD-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group privilege add helpdesk 'show clock' > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group privilege reset helpdesk --yes
    assert_success
    assert_output --partial "the override of its privileges is removed; none are shipped for it, so it has none."
    run grep -F 'show clock' "$YAML"
    assert_failure
    run grep -F '[]' "$YAML"
    assert_failure
    prun "$TACCTL_BIN_SCRIPT" group privilege list helpdesk
    assert_output --partial "no mappings"
}

@test "group privilege reset equals group reset --only privileges for a built-in group" {
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version' > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator --dry-run
    local a=$output
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only privileges --dry-run
    local b=$output
    [[ "$(grep -E '^    [-+~] ' <<< "$a")" == "$(grep -E '^    [-+~] ' <<< "$b")" ]]
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator --yes
    assert_success
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only privileges
    assert_output --partial "already canonical (privileges)"
}

@test "group privilege reset: refusals, and clear is gone" {
    prun "$TACCTL_BIN_SCRIPT" group privilege reset ghost --yes
    assert_failure 1
    assert_output --partial "Group 'ghost' does not exist."
    prun "$TACCTL_BIN_SCRIPT" group privilege reset
    assert_failure 1
    assert_output --partial "Usage: tacctl group privilege reset <group> [--dry-run] [--yes]"
    prun "$TACCTL_BIN_SCRIPT" group privilege reset operator --preset
    assert_failure 1
    assert_output --partial "Usage: tacctl group privilege reset <group> [--dry-run] [--yes]"
    prun "$TACCTL_BIN_SCRIPT" group privilege clear operator
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'clear'"
    refute_output --partial "clear <group>"
}
