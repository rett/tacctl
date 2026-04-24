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
# Goldens above cover the local-first default. These assert the
# tacacs-first shape when a specific scope overrides via
# `tacctl scope aaa-order <scope> tacacs-first`, and verify that
# overrides stay scoped (other scopes keep the default).

@test "config cisco: scope aaa-order tacacs-first puts TACACS group ahead of local" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab tacacs-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope lab
    assert_success
    assert_output --partial "aaa authentication login default group TACACS-GROUP local"
    assert_output --partial "aaa authorization exec default group TACACS-GROUP local if-authenticated"
    assert_output --partial "aaa authorization commands 1 default group TACACS-GROUP local"
    assert_output --partial "aaa authorization commands 15 default group TACACS-GROUP local"
    refute_output --partial "aaa authentication login default local group TACACS-GROUP"
}

@test "config juniper: scope aaa-order tacacs-first flips authentication-order" {
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab tacacs-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config juniper --scope lab
    assert_success
    assert_output --partial "set system authentication-order [ tacplus password ]"
    refute_output --partial "set system authentication-order [ password tacplus ]"
}

@test "config cisco: scope aaa-order override is per-scope (prod unaffected)" {
    # Flip lab to tacacs-first; prod (no override) should still render
    # the default local-first shape.
    "$TACCTL_BIN_SCRIPT" scope aaa-order lab tacacs-first > /dev/null
    run "$TACCTL_BIN_SCRIPT" config cisco --scope prod
    assert_success
    assert_output --partial "aaa authentication login default local group TACACS-GROUP"
    refute_output --partial "aaa authentication login default group TACACS-GROUP local"
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
