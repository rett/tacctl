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

# list_rules <group>: 'group commands list' as run sets it, without the
# colours, so the table's columns can be matched.
list_rules() {
    run "$TACCTL_BIN_SCRIPT" group commands list "$1"
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
}

# =============================================================================
#  group edit
# =============================================================================

@test "group edit priv-lvl: rewrites the exec service values" {
    run "$TACCTL_BIN_SCRIPT" group edit operator priv-lvl 10
    assert_success
    assert_output --partial "changed to 10"
    # Regression: backticks in the embedded python comment sat inside a
    # double-quoted bash string, so bash ran `name: shell` as a command.
    refute_output --partial "command not found"

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

@test "group commands add: inserts a named rule with an argument regex match" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'running-config.*' --action permit
    assert_success

    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial "show"
    assert_output --partial "permit"
    assert_output --partial 'running-config.*'
}

@test "group commands add: rejects a --match that repeats the command word (can never fire)" {
    # tacquito tests match regexes against the arguments only, so a regex
    # anchored on the command word itself never matches anything.
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^show .*$' --action permit
    assert_failure
    assert_output --partial "can never match"
    assert_output --partial "ARGUMENTS only"

    run "$TACCTL_BIN_SCRIPT" group commands add operator ping --match '^ping( .*)?$' --action permit
    assert_failure

    # The override must not have been written.
    run "$TACCTL_BIN_SCRIPT" group commands list operator
    refute_output --partial '^show .*$'
}

@test "group commands: shipped defaults render into tacquito.yaml, show name-only and every match whole" {
    # Any mutation regenerates the tacquito.yaml commands: blocks from the
    # merged tacctl view. `show` must be a name-only rule so
    # `show running-config` (tested by tacquito as 'running-config') is
    # authorized rather than falling through to the deny catch-all; the two
    # rules with a match carry it as ^(?:...)$, so tacquito adds no anchors.
    # The shipped deny of `show running-config view full` stands before it.
    "$TACCTL_BIN_SCRIPT" group commands default operator deny > /dev/null
    run awk '/^operator: &operator/,/^  accounter:/' "$TACCTL_CONFIG"
    assert_output --partial $'name: "show"\n      action: *action_permit'
    assert_output --partial 'name: "*"'
    assert_output --partial 'match: ["^(?:^(capture)( .*)?$)$"]'
    assert_output --partial 'match: ["^(?:^(running-config view full)( .*)?$)$"]'
    refute_output --partial '"^show'
    run grep -c 'match: \["' <(awk '/^operator: &operator/,/^  accounter:/' "$TACCTL_CONFIG")
    assert_output "3"
}

@test "group commands add: refuses a comma in --match (the rule line form would split it); \\x2c works" {
    local before
    before=$("$TACCTL_BIN_SCRIPT" group commands list operator)
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'a{1,3}' --action permit
    assert_failure 1
    assert_output --partial 'A comma cannot be used in --match (the rule line form splits on it); use \x2c'
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'ok' --match 'x,y'
    assert_failure 1
    assert_output --partial "A comma cannot be used in --match"
    [[ "$("$TACCTL_BIN_SCRIPT" group commands list operator)" == "$before" ]]

    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'a\x2cb' --action permit
    assert_success
    run "$TACCTL_BIN_SCRIPT" group commands list operator
    assert_output --partial 'a\x2cb'
}

@test "group commands add: refuses an empty or invalid --match; warns about a prefix form and an unreachable rule" {
    local before
    before=$("$TACCTL_BIN_SCRIPT" group commands list operator)
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '' --action deny
    assert_failure
    assert_output --partial "--match needs a regex; an empty one is skipped by tacquito"
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^(a' --action deny
    assert_failure
    assert_output --partial "Invalid regex: '^(a'"
    [[ "$("$TACCTL_BIN_SCRIPT" group commands list operator)" == "$before" ]]

    # A prefix form without '( .*)?$' matches the exact arguments only.
    run "$TACCTL_BIN_SCRIPT" group commands add operator clear --match '^ip route' --action deny --first
    assert_success
    assert_output --partial "matches only the exact arguments 'ip route'"
    assert_output --partial "write '^ip route( .*)?\$'"
    run "$TACCTL_BIN_SCRIPT" group commands add operator clear --match '^ip route( .*)?$' --action deny --first
    assert_success
    refute_output --partial "matches only"

    # The shipped 'show' permit (rule #4 after the two 'clear' rules and the
    # view full deny) has no
    # match, so a later 'show' rule is dead.
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^crypto( .*)?$' --action deny
    assert_success
    assert_output --partial "never reached: rule #4 'show' has no match and decides every 'show' command first"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_output --partial "Command rules:"
    assert_output --partial "never reached"
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
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'run.*' --action maybe
    assert_failure
}

@test "group commands add: rejects unknown flag" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --bogus "foo"
    assert_failure
    assert_output --partial "Unknown flag"
}

@test "group commands add: idempotent for the same (name, match) pair" {
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'run.*' --action permit
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'run.*' --action permit
    assert_success
    assert_output --partial "already present"
}

@test "group commands remove: drops a named rule" {
    run "$TACCTL_BIN_SCRIPT" group commands remove operator ping
    assert_success
    assert_output --partial "Removed rule #4 'ping' (permit, match=[]) from group 'operator'."

    run "$TACCTL_BIN_SCRIPT" group commands list operator
    refute_output --partial 'ping'
}

@test "group commands remove: refuses several rules of a name without a selector" {
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'run.*' --action permit
    before=$("$TACCTL_BIN_SCRIPT" group commands list operator)
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show
    assert_failure
    assert_output --partial "Group 'operator' has 3 rules named 'show'; select one with --match/--action (see 'tacctl group commands list operator'), or pass --all."
    [[ "$("$TACCTL_BIN_SCRIPT" group commands list operator)" == "$before" ]]
}

@test "group commands remove: --match and --action pick one rule of several" {
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^crypto( .*)?' --action deny --before show
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'run.*' --match 'start.*' --action permit
    # The match list is compared whole and in order: no rule has this one.
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show --match 'start.*' --match 'run.*'
    assert_success
    assert_output --partial "No rule named 'show' in group 'operator' has that --match/--action."

    run "$TACCTL_BIN_SCRIPT" group commands remove operator show --match 'run.*' --match 'start.*'
    assert_success
    assert_output --partial "Removed rule #15 'show' (permit, match=[run.*,start.*]) from group 'operator'."
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show --action deny --match '^crypto( .*)?'
    assert_success
    assert_output --partial "Removed rule #1 'show' (deny, match=[^crypto( .*)?]) from group 'operator'."

    list_rules operator
    refute_output --partial 'crypto'
    refute_output --partial 'run.*'
    assert_output --regexp '1 +show +deny +\^\(running-config view full\)'
    assert_output --regexp '2 +show +permit'
}

@test "group commands remove: --all drops every rule of the name (and only those)" {
    "$TACCTL_BIN_SCRIPT" group commands add operator show --match 'run.*' --action permit
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show --all
    assert_success
    assert_output --partial "Removed rule #1 'show' (deny, match=[^(running-config view full)( .*)?$]) from group 'operator'."
    assert_output --partial "Removed rule #2 'show' (permit, match=[]) from group 'operator'."
    assert_output --partial "Removed rule #14 'show' (permit, match=[run.*]) from group 'operator'."

    list_rules operator
    refute_output --regexp ' show '
    assert_output --regexp '1 +dir +permit'
    assert_output --regexp '12 +\* \(catchall\) +deny'
}

@test "group commands remove: rejects an unknown flag and a bad --action" {
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show --bogus
    assert_failure
    assert_output --partial "Unknown flag: '--bogus'"
    run "$TACCTL_BIN_SCRIPT" group commands remove operator show --action maybe
    assert_failure
    assert_output --partial "--action must be 'permit' or 'deny'."
}

@test "group commands list: the # column numbers the rules in order" {
    list_rules operator
    assert_success
    assert_output --regexp '# +NAME +ACTION +MATCH'
    assert_output --regexp '1 +show +deny +\^\(running-config view full\)'
    assert_output --regexp '2 +show +permit'
    assert_output --regexp '6 +terminal +permit'
    assert_output --regexp '14 +\* \(catchall\) +deny'
}

@test "group commands add: --before puts the rule before the first rule of that name" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator show --match '^crypto( .*)?' --action deny --before show
    assert_success
    list_rules operator
    assert_output --regexp '1 +show +deny +\^crypto\( \.\*\)\?'
    assert_output --regexp '3 +show +permit'
    assert_output --regexp '15 +\* \(catchall\) +deny'

    # '--before *' is the default place, before the catchall.
    run "$TACCTL_BIN_SCRIPT" group commands add operator reload --action deny --before '*'
    assert_success
    list_rules operator
    assert_output --regexp '15 +reload +deny'
    assert_output --regexp '16 +\* \(catchall\) +deny'

    # The rendered tacquito.yaml keeps the order: the deny is operator's
    # first rule.
    run awk '/^  name: operator$/ { g = 1 } g && /^  commands:/ { getline a; getline b; print a; print b; exit }' "$TACCTL_CONFIG"
    assert_line --index 0 '    - name: "show"'
    assert_line --index 1 --partial 'crypto'
}

@test "group commands add: --first puts the rule at position 1" {
    run "$TACCTL_BIN_SCRIPT" group commands add operator configure --action deny --first
    assert_success
    list_rules operator
    assert_output --regexp '1 +configure +deny'
    assert_output --regexp '3 +show +permit'
}

@test "group commands add: --before a missing rule, or with --first, changes nothing" {
    before=$("$TACCTL_BIN_SCRIPT" group commands list operator)
    run "$TACCTL_BIN_SCRIPT" group commands add operator configure --before missing
    assert_failure
    assert_output --partial "No rule named 'missing' in group 'operator'."
    run "$TACCTL_BIN_SCRIPT" group commands add operator configure --before show --first
    assert_failure
    assert_output --partial "--before and --first cannot be used together."
    [[ "$("$TACCTL_BIN_SCRIPT" group commands list operator)" == "$before" ]]
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
