#!/usr/bin/env bats
# Golden-file tests for device config template rendering.
# Set UPDATE_GOLDEN=1 to regenerate tests/fixtures/golden/*.conf after
# intentional changes.

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
    # Freeze server-IP discovery so rendered output is deterministic.
    stub_cmd ip 'if [[ "$*" == *"route get 1.0.0.0"* ]]; then echo "1.0.0.0 via 10.0.0.1 dev eth0 src 10.0.0.42 uid 0"; fi'

    load_fixture tacquito.multiscope.yaml
}

# Strip ANSI color codes and the dynamic hostname line that can vary across
# machines / test runs, so the golden file is reproducible.
_normalize() {
    sed -E 's/\x1b\[[0-9;]*m//g' \
        | sed -E 's/^hostname .*/hostname TACQUITO-HOSTNAME/'
}

@test "config cisco: renders deterministic IOS config from fixture + lab scope" {
    local out="$BATS_TEST_TMPDIR/cisco.conf"
    "$TACCTL_BIN_SCRIPT" config cisco --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "cisco-lab.conf"
}

@test "config cisco: renders deterministic IOS config for prod scope" {
    local out="$BATS_TEST_TMPDIR/cisco-prod.conf"
    "$TACCTL_BIN_SCRIPT" config cisco --scope prod | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "cisco-prod.conf"
}

@test "config juniper: renders deterministic Junos config from fixture + lab scope" {
    local out="$BATS_TEST_TMPDIR/juniper.conf"
    "$TACCTL_BIN_SCRIPT" config juniper --scope lab | _normalize > "$out"
    [[ -s "$out" ]]
    golden_diff "$out" "juniper-lab.conf"
}

@test "config cisco: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" config cisco --scope nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "config juniper: errors on unknown scope" {
    run "$TACCTL_BIN_SCRIPT" config juniper --scope nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "config validate: succeeds on a valid config" {
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
}

# --- per-scope aaa-order: render flip ----------------------------------------
# Goldens above cover the tacacs-first default. These assert the
# local-first shape when a specific scope overrides via
# `tacctl scope aaa-order <scope> local-first`, and verify that
# overrides stay scoped (other scopes keep the default).

@test "config cisco: scope aaa-order local-first puts local ahead of the TACACS group" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "aaa authentication login default local group TACACS-GROUP"
    assert_output --partial "aaa authorization exec default local group TACACS-GROUP if-authenticated"
    assert_output --partial "aaa authorization commands 1 default local group TACACS-GROUP"
    assert_output --partial "aaa authorization commands 15 default local group TACACS-GROUP"
    refute_output --partial "aaa authentication login default group TACACS-GROUP local"
}

@test "config juniper: scope aaa-order local-first flips authentication-order" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "set system authentication-order [ password tacplus ]"
    refute_output --partial "set system authentication-order [ tacplus password ]"
}

@test "config cisco: scope aaa-order override is per-scope (prod unaffected)" {
    # Flip lab to local-first; prod (no override) should still render
    # the default tacacs-first shape.
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod
    assert_success
    assert_output --partial "aaa authentication login default group TACACS-GROUP local"
    refute_output --partial "aaa authentication login default local group TACACS-GROUP"
}

@test "config cisco: scope exec-timeout applies to line con + line vty" {
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    # Both line con 0 and line vty 0 15 carry the override.
    run bash -c '"'"$TACCTL_BIN_SCRIPT"'" config cisco --scope lab | grep -c "^  exec-timeout 15 0$"'
    [[ "$output" == "2" ]]
}

@test "config juniper: scope exec-timeout emits idle-timeout line" {
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "set system login idle-timeout 15"
}

@test "config cisco: scope tacacs-group overrides the aaa-group-server label" {
    "$TACCTL_BIN_SCRIPT" scope tacacs-group lab TACACS_PROD > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "aaa group server tacacs+ TACACS_PROD"
    assert_output --partial "aaa authentication login default group TACACS_PROD local"
    assert_output --partial "aaa accounting exec default start-stop group TACACS_PROD"
    refute_output --partial "TACACS-GROUP"
}

@test "config cisco: per-scope mgmt-acl wins over global" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name GLOBAL-VTY > /dev/null
    "$TACCTL_BIN_SCRIPT" scope  mgmt-acl lab cisco-name LAB-VTY-ACL > /dev/null
    # Populate at least one permit so the ACL block actually renders.
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "ip access-list standard LAB-VTY-ACL"
    assert_output --partial "access-class LAB-VTY-ACL in"
    refute_output --partial "GLOBAL-VTY"
}

@test "config juniper: per-scope mgmt-acl wins over global" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl juniper-name GLOBAL-MGMT > /dev/null
    "$TACCTL_BIN_SCRIPT" scope  mgmt-acl lab juniper-name LAB-MGMT-FILTER > /dev/null
    "$TACCTL_BIN_SCRIPT" config mgmt-acl add 10.0.0.0/8 > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "filter LAB-MGMT-FILTER"
    refute_output --partial "GLOBAL-MGMT"
}
