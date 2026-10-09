#!/usr/bin/env bats
# Integration tests for `tacctl group reset` (0.2.3, D51).

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

# Moves the operator away from its canonical state in every section.
modify_operator() {
    "$TACCTL_BIN_SCRIPT" group commands add operator configure --action permit > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 10 > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator juniper-class NEW-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator wti-level administrator > /dev/null
    "$TACCTL_BIN_SCRIPT" group junos operator deny-commands add '^foo' > /dev/null
    "$TACCTL_BIN_SCRIPT" group privilege add operator 'show version' > /dev/null
}

@test "group reset: a group in its canonical state says so and asks nothing" {
    for g in readonly operator superuser; do
        run "$TACCTL_BIN_SCRIPT" group reset "$g"
        assert_success
        assert_output --partial "Group '$g' is already canonical; nothing to change."
    done
    prun "$TACCTL_BIN_SCRIPT" group reset operator --preset --yes
    assert_success
    assert_output --partial "Reset of group 'operator' to the role preset's values"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --preset
    assert_success
    assert_output --partial "already canonical"
}

@test "group reset --dry-run: prints the diff of each section and writes nothing" {
    modify_operator
    cp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    cp "$TACCTL_CONFIG" "$BATS_TEST_TMPDIR/tacquito.before"
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --dry-run
    assert_success
    assert_output --partial "Reset of group 'operator' to its canonical defaults"
    assert_output --partial "Cisco priv-lvl:  10 -> 7"
    assert_output --partial "Juniper class:   NEW-CLASS -> OP-CLASS"
    assert_output --partial "WTI level:       Administrator (set) -> User (auto, from priv-lvl)"
    assert_output --partial "warning: Cisco logins and the per-level authorization lines change; re-paste tacctl config cisco"
    assert_output --partial "warning: the Junos template user of the class changes; re-paste tacctl config juniper Step 1"
    assert_output --partial "    - configure    permit"
    assert_output --partial "    - show version"
    assert_output --partial "deny-commands: 6/241 bytes -> none"
    assert_output --partial "Dry run: nothing was written."
    run cmp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    assert_success
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
    run cmp "$TACCTL_CONFIG" "$BATS_TEST_TMPDIR/tacquito.before"
    assert_success
    if stub_called '^logger .*group reset'; then echo 'audit line written'; return 1; fi
}

@test "group reset: without a terminal and without --yes it refuses and changes nothing" {
    modify_operator
    cp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    # A piped 'y' is not a confirmation.
    prun bash -c "echo y | '$TACCTL_BIN_SCRIPT' group reset operator"
    assert_failure 1
    assert_output --partial "Cisco priv-lvl:  10 -> 7"
    assert_output --partial "No terminal to confirm on; nothing was changed. Review with --dry-run, then run again with --yes."
    run cmp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    assert_success
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
}

@test "group reset --yes: applies, renders, logs, and a second run changes nothing" {
    modify_operator
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --yes
    assert_success
    assert_output --partial "Group 'operator' reset (settings, commands, privileges, junos)."
    stub_called '^logger -t tacctl -p auth.info group reset name=operator sections=settings,commands,privileges,junos by='
    prun "$TACCTL_BIN_SCRIPT" group show operator
    assert_output --partial "Cisco priv-lvl:    7"
    assert_output --partial "Juniper class:     OP-CLASS"
    assert_output --partial "WTI level:         User (auto, from priv-lvl)"
    refute_output --partial "deny-commands"
    # Nothing of the operator is left in tacctl.yaml (which may be gone).
    if [[ -e "$YAML" ]] && grep -q operator "$YAML"; then cat "$YAML"; return 1; fi
    # The rendered tacquito.yaml has the shipped operator rules again.
    run grep -c 'name: "configure"' "$TACCTL_CONFIG"
    assert_output "0"
    : > "$CALLS_LOG"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --yes
    assert_success
    assert_output --partial "Group 'operator' is already canonical; nothing to change."
    if stub_called '^logger .*group reset'; then echo 'audit line written'; return 1; fi
}

@test "group reset: the prompt answered n changes nothing, answered y applies" {
    modify_operator
    cp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    cp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    on_tty 'n\n' group reset operator
    assert_success
    assert_output --partial "Apply these changes to group 'operator'? [y/N]:"
    assert_output --partial "Aborted."
    run cmp "$STORE" "$BATS_TEST_TMPDIR/store.before"
    assert_success
    run cmp "$YAML" "$BATS_TEST_TMPDIR/yaml.before"
    assert_success
    on_tty '\n' group reset operator
    assert_output --partial "Aborted."
    on_tty 'y\n' group reset operator
    assert_success
    assert_output --partial "Apply these changes to group 'operator'? [y/N]:"
    assert_output --partial "Group 'operator' reset ("
    prun "$TACCTL_BIN_SCRIPT" group reset operator
    assert_output --partial "already canonical"
}

@test "group reset: a custom group has no canonical defaults; other refusals" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HD-CLASS > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group reset helpdesk --yes
    assert_failure 1
    assert_output --partial "Group 'helpdesk' is not a built-in or role group, so it has no canonical defaults; group commands reset helpdesk drops its command overrides."
    prun "$TACCTL_BIN_SCRIPT" group reset ghost --yes
    assert_failure 1
    assert_output --partial "Group 'ghost' does not exist."
    prun "$TACCTL_BIN_SCRIPT" group reset
    assert_failure 1
    assert_output --partial "Usage: tacctl group reset <group> [--preset] [--only settings,commands,privileges,junos] [--dry-run] [--yes]"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only settings,rules
    assert_failure 1
    assert_output --partial "Unknown section 'rules' for --only. Use: settings, commands, privileges, junos"
}

@test "group reset --only limits the reset to the sections named" {
    modify_operator
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only commands,privileges --yes
    assert_success
    assert_output --partial "Group 'operator' reset (commands, privileges)."
    stub_called '^logger -t tacctl -p auth.info group reset name=operator sections=commands,privileges by='
    prun "$TACCTL_BIN_SCRIPT" group show operator
    assert_output --partial "Cisco priv-lvl:    10"
    assert_output --partial "Juniper class:     NEW-CLASS"
    assert_output --partial "deny-commands"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --only commands,privileges
    assert_output --partial "is already canonical (commands, privileges); nothing to change."
    prun "$TACCTL_BIN_SCRIPT" group reset operator --dry-run
    assert_output --partial "  commands
    unchanged"
    assert_output --partial "  settings
    Cisco priv-lvl:  10 -> 7"
}

@test "group reset engineer is the preset's engineer: it creates the group, and equals preset --force" {
    prun "$TACCTL_BIN_SCRIPT" group reset engineer --dry-run
    assert_success
    assert_output --partial "group:           does not exist: it is created with Cisco priv-lvl 15 and Juniper class EN-CLASS"
    assert_output --partial "tacctl tier:     none -> engineer (set)"
    assert_output --partial "deny-commands: none -> 192/241 bytes"
    prun "$TACCTL_BIN_SCRIPT" group reset engineer --yes
    assert_success
    prun "$TACCTL_BIN_SCRIPT" group show engineer
    assert_output --partial "Cisco priv-lvl:    15"
    assert_output --partial "Juniper class:     EN-CLASS"
    assert_output --partial "tacctl tier:       engineer (set"
    local shown
    shown=$output
    # The same group through the preset, from the 0.2.2 text of a deny set.
    "$TACCTL_BIN_SCRIPT" group edit engineer priv-lvl 14 > /dev/null
    "$TACCTL_BIN_SCRIPT" group junos engineer deny-configuration add '^snmp' > /dev/null
    "$TACCTL_BIN_SCRIPT" group commands add engineer extra --action deny > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group reset engineer --yes
    assert_success
    prun "$TACCTL_BIN_SCRIPT" group show engineer
    assert_output "$shown"
    prun "$TACCTL_BIN_SCRIPT" group reset engineer
    assert_output --partial "already canonical"
}

@test "group reset: the lockout guard gives a sibling without rules a permit catchall" {
    "$TACCTL_BIN_SCRIPT" group add helpdesk 7 HD-CLASS > /dev/null
    "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 10 > /dev/null
    prun "$TACCTL_BIN_SCRIPT" group reset operator --dry-run
    assert_output --partial "Groups at priv-lvl 7 without command rules get a permit-* catchall, so that Cisco does not deny them every command: helpdesk"
    prun "$TACCTL_BIN_SCRIPT" group reset operator --yes
    assert_success
    assert_output --partial "Auto-seeded permit-* catchall on sibling groups at priv-lvl 7: helpdesk"
    prun "$TACCTL_BIN_SCRIPT" group commands list helpdesk
    assert_output --partial "Default action: permit"
}
