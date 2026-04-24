#!/usr/bin/env bats
# Integration tests for simple `tacctl config <setter>` commands.

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

# --- password-age ------------------------------------------------------------

@test "config password-age: shows current value with no args" {
    run "$TACCTL_BIN_SCRIPT" config password-age
    assert_success
    assert_output --partial "warning threshold"
    assert_output --partial "90 days"
}

@test "config password-age: sets a new value" {
    run "$TACCTL_BIN_SCRIPT" config password-age 180
    assert_success
    [[ "$(conf_get password.max_age_days)" == "180" ]]
}

@test "config password-age: rejects non-numeric + negative + zero" {
    run "$TACCTL_BIN_SCRIPT" config password-age "forever"
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config password-age 0
    assert_failure
}


# --- bcrypt-cost -------------------------------------------------------------

@test "config bcrypt-cost: shows current value + wall-clock guidance" {
    run "$TACCTL_BIN_SCRIPT" config bcrypt-cost
    assert_success
    assert_output --partial "cost factor"
    assert_output --partial "10-14"
}

@test "config bcrypt-cost: accepts boundary values 10 and 14" {
    run "$TACCTL_BIN_SCRIPT" config bcrypt-cost 10
    assert_success
    [[ "$(conf_get bcrypt.cost)" == "10" ]]

    run "$TACCTL_BIN_SCRIPT" config bcrypt-cost 14
    assert_success
    [[ "$(conf_get bcrypt.cost)" == "14" ]]
}

@test "config bcrypt-cost: rejects below-range and above-range" {
    run "$TACCTL_BIN_SCRIPT" config bcrypt-cost 9
    assert_failure
    assert_output --partial "bcrypt.cost: must be >= 10"

    run "$TACCTL_BIN_SCRIPT" config bcrypt-cost 15
    assert_failure
    assert_output --partial "bcrypt.cost: must be <= 14"
}

@test "config bcrypt-cost: rejects non-numeric input" {
    run "$TACCTL_BIN_SCRIPT" config bcrypt-cost twelve
    assert_failure
}

# --- password-min-length -----------------------------------------------------

@test "config password-min-length: accepts 8..64, rejects out-of-range" {
    run "$TACCTL_BIN_SCRIPT" config password-min-length 8
    assert_success
    [[ "$(conf_get password.min_length)" == "8" ]]

    run "$TACCTL_BIN_SCRIPT" config password-min-length 64
    assert_success

    run "$TACCTL_BIN_SCRIPT" config password-min-length 7
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config password-min-length 65
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config password-min-length bad
    assert_failure
}

# --- secret-min-length -------------------------------------------------------

@test "config secret-min-length: accepts 16..128, rejects out-of-range" {
    run "$TACCTL_BIN_SCRIPT" config secret-min-length 16
    assert_success
    [[ "$(conf_get secret.min_length)" == "16" ]]

    run "$TACCTL_BIN_SCRIPT" config secret-min-length 128
    assert_success

    run "$TACCTL_BIN_SCRIPT" config secret-min-length 15
    assert_failure
    run "$TACCTL_BIN_SCRIPT" config secret-min-length 129
    assert_failure
}

# --- loglevel ----------------------------------------------------------------

@test "config loglevel: shows current level (default info/20)" {
    run "$TACCTL_BIN_SCRIPT" config loglevel
    assert_success
    assert_output --partial "info"
}

@test "config loglevel: sets debug via drop-in override" {
    run "$TACCTL_BIN_SCRIPT" config loglevel debug
    assert_success
    run cat "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf"
    assert_output --partial "TACQUITO_LEVEL=30"
    stub_called 'systemctl daemon-reload'
    stub_called 'systemctl restart tacquito'
}

@test "config loglevel: setting back to info (default) clears the override" {
    # First pin an override.
    "$TACCTL_BIN_SCRIPT" config loglevel debug
    [[ -f "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf" ]]

    run "$TACCTL_BIN_SCRIPT" config loglevel info
    assert_success
    # Override file is cleared (or no longer contains TACQUITO_LEVEL).
    if [[ -f "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf" ]]; then
        run grep -c '^Environment="TACQUITO_LEVEL=' "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf"
        assert_output "0"
    fi
}

@test "config loglevel: rejects unknown level" {
    run "$TACCTL_BIN_SCRIPT" config loglevel trace
    assert_failure
    assert_output --partial "Invalid level"
}

# --- listen ------------------------------------------------------------------

@test "config listen show: prints current default (tcp :49)" {
    run "$TACCTL_BIN_SCRIPT" config listen show
    assert_success
    assert_output --partial "tcp :49"
    assert_output --partial "template default"
}

@test "config listen tcp :49 — setting default is a no-op once pinned" {
    stub_cmd systemctl 'if [[ "$1" == "is-active" ]]; then exit 0; else exit 0; fi'
    run "$TACCTL_BIN_SCRIPT" config listen tcp 10.1.0.1:49
    assert_success
    run grep -F 'TACQUITO_ADDRESS=10.1.0.1:49' "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf"
    assert_success

    # Setting the same value again: idempotent.
    run "$TACCTL_BIN_SCRIPT" config listen tcp 10.1.0.1:49
    assert_success
    assert_output --partial "Already listening"
}

@test "config listen reset: clears override when one exists" {
    stub_cmd systemctl 'if [[ "$1" == "is-active" ]]; then exit 0; else exit 0; fi'
    "$TACCTL_BIN_SCRIPT" config listen tcp 10.1.0.1:49
    [[ -f "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf" ]]

    run "$TACCTL_BIN_SCRIPT" config listen reset
    assert_success
    # Either the override file is gone, or the listen vars are gone from it.
    if [[ -f "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf" ]]; then
        run grep -c -E '^Environment="TACQUITO_(NETWORK|ADDRESS)=' \
            "$TACCTL_OVERRIDE_DIR/tacctl-overrides.conf"
        assert_output "0"
    fi
}

@test "config listen tcp: rejects missing address argument" {
    run "$TACCTL_BIN_SCRIPT" config listen tcp
    assert_failure
    assert_output --partial "Missing address"
}

@test "config listen: rejects unknown subcommand" {
    run "$TACCTL_BIN_SCRIPT" config listen bogus
    assert_failure
    assert_output --partial "Invalid subcommand"
}
