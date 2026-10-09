#!/usr/bin/env bats
# Integration tests for `tacctl scope breakglass <scope> list|add|remove`
# (D55): the per-scope break-glass local users. Only names and roles are
# recorded, in tacctl.yaml; the walkthroughs render the account lines with a
# placeholder where the credential goes.

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
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'
    load_fixture tacquito.multiscope.yaml
    OVERRIDES="${TACCTL_STATE_DIR}/tacctl.yaml"
}

# tacctl's output without colours.
plain() {
    local rc=0
    "$TACCTL_BIN_SCRIPT" "$@" > "${BATS_TEST_TMPDIR}/plain.out" 2>&1 || rc=$?
    sed -E 's/\x1b\[[0-9;]*m//g' "${BATS_TEST_TMPDIR}/plain.out"
    return "$rc"
}

# The walkthrough of a vendor and scope.
walk() {
    plain config "$@"
}

@test "scope breakglass: a scope starts with none, and list says what that risks" {
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab
    assert_success
    assert_output --partial "Scope 'lab' has no break-glass local user."
    assert_output --partial "stores no password or hash"
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab list
    assert_success
    assert_output --partial "Scope 'lab' has no break-glass local user."
    [[ ! -e "$OVERRIDES" ]]
}

@test "scope breakglass add: the default role is admin; names and roles only land in tacctl.yaml" {
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin
    assert_success
    assert_output --partial "Break-glass user 'lab-admin' (admin) recorded for scope 'lab'."
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-ops --role operator
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab add --role readonly lab-ro
    assert_success
    run cat "$OVERRIDES"
    assert_output --partial $'breakglass_scope:\n  lab:\n    users:\n    - lab-admin:admin\n    - lab-ops:operator\n    - lab-ro:readonly'
    refute_output --partial "HASH"
    refute_output --partial "secret"
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab list
    assert_output --partial "lab-admin  (admin)"
    assert_output --partial "lab-ops  (operator)"
    assert_output --partial "lab-ro  (readonly)"
    stub_called "logger -t tacctl -p auth.info scope breakglass add scope=lab name=lab-ops role=operator by=root"
}

@test "scope breakglass: the record is per scope" {
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass prod add prod-ro --role readonly > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab list
    assert_output --partial "lab-admin"
    refute_output --partial "prod-ro"
    run "$TACCTL_BIN_SCRIPT" scope breakglass prod list
    assert_output --partial "prod-ro  (readonly)"
    refute_output --partial "lab-admin"
    run "$TACCTL_BIN_SCRIPT" scope breakglass dmz list
    assert_output --partial "Scope 'dmz' has no break-glass local user."
}

@test "scope breakglass add: refuses names that are not device-safe, reserved, users of the scope or class names" {
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    local before
    before=$(cat "$OVERRIDES")
    local case
    for case in '9lives|not a device-safe user name' 'has space|not a device-safe user name' 'a;b|not a device-safe user name' \
        'root|is reserved' 'tacquito|is reserved' 'remote|is a Junos system account' 'Remote|is a Junos system account' \
        'BOB|is a tacctl user of scope' 'Lab-Admin|already has break-glass user' \
        'bob|is a tacctl user of scope' 'alice|is a tacctl user of scope' \
        'RW-CLASS|template-user or class name' 'op-class|template-user or class name' 'super-user|template-user or class name' \
        'lab-admin|already has break-glass user'; do
        run "$TACCTL_BIN_SCRIPT" scope breakglass lab add "${case%%|*}"
        assert_failure
        assert_output --partial "${case#*|}"
    done
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab add x --role boss
    assert_failure
    assert_output --partial "Unknown role 'boss'. Roles: admin, operator, readonly"
    run "$TACCTL_BIN_SCRIPT" scope breakglass nosuch add x
    assert_failure
    assert_output --partial "Scope 'nosuch' does not exist."
    [[ "$(cat "$OVERRIDES")" == "$before" ]]
}

@test "scope breakglass remove: drops one; the last one takes the key out of tacctl.yaml" {
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 30 > /dev/null
    local before
    before=$(cat "$OVERRIDES")
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-ro --role readonly > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab remove lab-ro
    assert_success
    assert_output --partial "Break-glass user 'lab-ro' removed from scope 'lab'."
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab remove lab-ro
    assert_failure
    assert_output --partial "Scope 'lab' has no break-glass user 'lab-ro'."
    run "$TACCTL_BIN_SCRIPT" scope breakglass lab remove lab-admin
    assert_success
    assert_output --partial "nobody can log in"
    # A tacctl.yaml written without the key is byte-identical to one that had it set and cleared.
    [[ "$(cat "$OVERRIDES")" == "$before" ]]
}

@test "scope breakglass: the record follows scope rename and goes with scope remove" {
    "$TACCTL_BIN_SCRIPT" scope breakglass dmz add edge-admin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope rename dmz edge
    assert_success
    run cat "$OVERRIDES"
    assert_output --partial $'  edge:\n    users:\n    - edge-admin:admin'
    refute_output --partial "dmz"
    run "$TACCTL_BIN_SCRIPT" scope breakglass edge list
    assert_output --partial "edge-admin  (admin)"
    run "$TACCTL_BIN_SCRIPT" scope remove edge --force <<<"y"
    assert_success
    run cat "$OVERRIDES"
    refute_output --partial "edge"
    assert_output --partial "lab-admin:admin"
}

@test "scope show: names the break-glass users, or says the scope has none" {
    run plain scope show lab
    assert_success
    assert_output --partial "none — a lockout risk with the server unreachable (tacctl scope breakglass lab add <name>)"
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    run plain scope show lab
    assert_output --partial "Break-glass:    lab-admin (admin)"
    run plain scope show prod
    assert_output --partial "Break-glass:    "
    assert_output --partial "none — a lockout risk"
}

@test "config validate: a scope without a break-glass user is a warning, never an error" {
    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null
    run plain config validate
    assert_success
    # One line, naming the scopes.
    assert_output --partial "scopes 'dmz', 'lab', 'prod', 'prod-inner' without a break-glass local user — a lockout risk"
    [[ "$(grep -c 'Break-glass:' <<< "$output")" == 1 ]]
    assert_output --partial "Configuration is valid."
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    run plain config validate
    assert_success
    refute_output --partial "'lab'"
    assert_output --partial "scopes 'dmz', 'prod', 'prod-inner' without a break-glass"
    # A hand edit the setter would refuse is an error with its path.
    printf 'breakglass_scope:\n  lab:\n    users: [lab-admin:boss]\n' > "$OVERRIDES"
    run plain config validate
    assert_failure
    assert_output --partial "breakglass_scope.lab.users: element 0: the role of 'lab-admin' must be one of"
}

@test "config cisco|juniper|wti: the scope's accounts with a placeholder, and the Unfilled line" {
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-admin > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-ops --role operator > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add lab-ro --role readonly > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass prod add prod-admin > /dev/null

    run walk cisco --scope lab
    assert_success
    assert_output --partial $'\n! username lab-admin privilege 15 secret 9 <TYPE9-HASH>\n'
    assert_output --partial $'\n! username lab-ops privilege 7 secret 9 <TYPE9-HASH>\n'
    assert_output --partial $'\n! username lab-ro privilege 1 secret 9 <TYPE9-HASH>\n'
    # 'algorithm-type scrypt secret' takes a plaintext password: never rendered.
    refute_output --partial "algorithm-type"
    assert_output --partial "Unfilled break-glass credentials (tacctl stores none; put in your own): lab-admin (admin), lab-ops (operator), lab-ro (readonly)"
    refute_output --partial "prod-admin"
    refute_line --regexp '^username '

    run walk cisco --scope lab --legacy
    assert_output --partial $'\n! username lab-admin privilege 15 secret 5 <HASH>\n'

    run walk juniper --scope lab
    assert_output --partial $'\n# set system login user lab-admin class RW-CLASS authentication encrypted-password \'<HASH>\'\n'
    assert_output --partial $'\n# set system login user lab-ops class OP-CLASS authentication encrypted-password \'<HASH>\'\n'
    assert_output --partial $'\n# set system login user lab-ro class RO-CLASS authentication encrypted-password \'<HASH>\'\n'
    refute_line --regexp '^set system login user lab-'

    run walk wti --scope lab
    assert_output --partial "lab-admin  Access Level: Administrator  Password: <PASSWORD>"
    assert_output --partial "lab-ops  Access Level: User  Password: <PASSWORD>"
    assert_output --partial "lab-ro  Access Level: ViewOnly  Password: <PASSWORD>"

    run walk wti --scope prod
    assert_output --partial "prod-admin  Access Level: Administrator  Password: <PASSWORD>"
    refute_output --partial "lab-admin"
}

@test "config cisco|juniper|wti: a scope without break-glass users gets a notice and no Unfilled line" {
    for v in cisco juniper wti; do
        run walk "$v" --scope dmz
        assert_success
        assert_output --partial "No break-glass local user is recorded for scope 'dmz'"
        assert_output --partial "tacctl scope breakglass dmz add <name>"
        refute_output --partial "Unfilled break-glass"
    done
}

@test "user add, user scope add|replace and user rename: refuse a name that is a break-glass account of the scope" {
    "$TACCTL_BIN_SCRIPT" scope breakglass lab add ghost > /dev/null
    "$TACCTL_BIN_SCRIPT" scope breakglass dmz add bob > /dev/null
    local hash=24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161

    run plain user add ghost readonly --hash "$hash" --scopes lab
    assert_failure
    assert_output --partial "'ghost' is a break-glass local user of scope 'lab' (admin)"
    assert_output --partial "tacctl scope breakglass lab remove ghost"
    run plain user add GHOST readonly --hash "$hash" --scopes prod,lab
    assert_failure
    # Another scope: no collision.
    run plain user add ghost readonly --hash "$hash" --scopes prod
    assert_success

    # bob is a user of lab only; the account 'bob' is recorded for dmz.
    run plain user scope bob add dmz
    assert_failure
    assert_output --partial "'bob' is a break-glass local user of scope 'dmz' (admin)"
    run plain user scope bob replace dmz
    assert_failure
    run plain user scope bob add prod
    assert_success

    "$TACCTL_BIN_SCRIPT" scope breakglass lab add newname > /dev/null
    run plain user rename bob newname
    assert_failure
    assert_output --partial "'newname' is a break-glass local user of scope 'lab' (admin)"
    run plain user rename bob Newname
    assert_failure

    # The way out the message names.
    "$TACCTL_BIN_SCRIPT" scope breakglass lab remove newname > /dev/null
    run plain user rename bob newname
    assert_success
}
