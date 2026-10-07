#!/usr/bin/env bats
# Integration tests for `tacctl config metrics` + `tacctl config sudoers`.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    export TACCTL_SETTLE_SECONDS=0
    stub_cmd chown
    # systemctl stub: is-active returns 0 (active), others succeed.
    stub_cmd systemctl 'if [[ "$1" == "is-active" ]]; then exit 0; fi; exit 0'
    stub_cmd logger
    load_fixture tacquito.minimal.yaml
}

# --- metrics: show (default state) -------------------------------------------

@test "config metrics: default show reports loopback-only default" {
    run "$TACCTL_BIN_SCRIPT" config metrics
    assert_success
    assert_output --partial "enabled (loopback-only)"
    assert_output --partial "127.0.0.1:8080"
    assert_output --partial "default"
}

@test "config metrics show: prints scrape URL for enabled state" {
    run "$TACCTL_BIN_SCRIPT" config metrics show
    assert_success
    assert_output --partial "http://127.0.0.1:8080/metrics"
}

# --- metrics: enable (no-op when already default) ----------------------------

@test "config metrics enable: no-op on fresh install (already on default)" {
    run "$TACCTL_BIN_SCRIPT" config metrics enable
    assert_success
    assert_output --partial "Already enabled"
}

# --- metrics: address --------------------------------------------------------

@test "config metrics address: pins a custom host:port in tacctl.yaml and the rendered drop-in" {
    run "$TACCTL_BIN_SCRIPT" config metrics address 10.1.0.1:9090
    assert_success
    run grep -F 'metrics_address: 10.1.0.1:9090' "$TACCTL_STATE_DIR/tacctl.yaml"
    assert_success
    run grep -F 'TACQUITO_METRICS_ADDRESS=10.1.0.1:9090' "$TACCTL_OVERRIDE_DIR/tacctl.conf"
    assert_success
    stub_called 'systemctl daemon-reload'
    stub_called 'systemctl restart tacquito'
}

@test "config metrics address: externally reachable address emits a warning" {
    run "$TACCTL_BIN_SCRIPT" config metrics address :9090
    assert_success
    assert_output --partial "externally reachable"
}

@test "config metrics address: setting default clears the override" {
    # Pin first, then set to default value.
    "$TACCTL_BIN_SCRIPT" config metrics address 10.1.0.1:9090
    grep -q 'metrics_address' "$TACCTL_STATE_DIR/tacctl.yaml"

    run "$TACCTL_BIN_SCRIPT" config metrics address 127.0.0.1:8080
    assert_success
    # tacctl.yaml (if it still exists) no longer names the metrics address,
    # and the drop-in is rendered with the default.
    if [[ -f "$TACCTL_STATE_DIR/tacctl.yaml" ]]; then
        run grep -c 'metrics_address' "$TACCTL_STATE_DIR/tacctl.yaml"
        assert_output "0"
    fi
    grep -qxF 'Environment="TACQUITO_METRICS_ADDRESS=127.0.0.1:8080"' "$TACCTL_OVERRIDE_DIR/tacctl.conf"
    run "$TACCTL_BIN_SCRIPT" config metrics
    assert_output --partial "127.0.0.1:8080  (default)"
}

@test "config metrics address: rejects missing argument" {
    run "$TACCTL_BIN_SCRIPT" config metrics address
    assert_failure
    assert_output --partial "Examples:"
}

@test "config metrics address: rejects address with no port" {
    run "$TACCTL_BIN_SCRIPT" config metrics address 127.0.0.1
    assert_failure
    assert_output --partial "must include a port"
}

# --- metrics: disable --------------------------------------------------------

@test "config metrics disable: sinks exporter to 127.0.0.1:0" {
    run "$TACCTL_BIN_SCRIPT" config metrics disable
    assert_success

    run grep -F 'TACQUITO_METRICS_ADDRESS=127.0.0.1:0' "$TACCTL_OVERRIDE_DIR/tacctl.conf"
    assert_success

    run "$TACCTL_BIN_SCRIPT" config metrics
    assert_output --partial "disabled"
}

@test "config metrics disable: no-op when already disabled" {
    "$TACCTL_BIN_SCRIPT" config metrics disable
    run "$TACCTL_BIN_SCRIPT" config metrics disable
    assert_success
    assert_output --partial "Already disabled"
}

# --- metrics: reset ----------------------------------------------------------

@test "config metrics reset: clears the override" {
    "$TACCTL_BIN_SCRIPT" config metrics address 10.1.0.1:9090
    grep -q 'metrics_address' "$TACCTL_STATE_DIR/tacctl.yaml"

    run "$TACCTL_BIN_SCRIPT" config metrics reset
    assert_success
    assert_output --partial "Metrics override cleared. Using unit default (127.0.0.1:8080)."
    if [[ -f "$TACCTL_STATE_DIR/tacctl.yaml" ]]; then
        run grep -c 'metrics_address' "$TACCTL_STATE_DIR/tacctl.yaml"
        assert_output "0"
    fi
    grep -qxF 'Environment="TACQUITO_METRICS_ADDRESS=127.0.0.1:8080"' "$TACCTL_OVERRIDE_DIR/tacctl.conf"
}

@test "config metrics: rejects unknown subcommand" {
    run "$TACCTL_BIN_SCRIPT" config metrics bogus
    assert_failure
    assert_output --partial "Unknown subcommand"
}

# =============================================================================
#  config sudoers
# =============================================================================

# `install` (coreutils) + `visudo` need stubbing so the test can exercise the
# install path as a non-root user without touching /etc.

@test "config sudoers show: reports 'not installed' on fresh env" {
    run "$TACCTL_BIN_SCRIPT" config sudoers show
    assert_success
    assert_output --partial "not installed"
}

@test "config sudoers (no args): equivalent to show, prints usage" {
    run "$TACCTL_BIN_SCRIPT" config sudoers
    assert_success
    assert_output --partial "not installed"
    assert_output --partial "Usage:"
}

@test "config sudoers install: writes a drop-in with the target group" {
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install wheel'
    assert_success

    [[ -f "$TACCTL_SUDOERS_FILE" ]]
    run cat "$TACCTL_SUDOERS_FILE"
    assert_output --partial "%wheel ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl"
    assert_output --partial 'Defaults!/usr/local/bin/tacctl env_keep += "SSH_AUTH_SOCK TACCTL_CONSOLE DISPLAY"'
    refute_output --partial "SETENV"
    assert_output --partial "Managed by tacctl"
}

@test "config sudoers install: the drop-in passes a real visudo (env_keep, no SETENV)" {
    local visudo_bin
    visudo_bin=$(PATH="$PATH:/usr/sbin:/sbin" command -v visudo) || skip "visudo not installed"
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install wheel'
    assert_success
    run "$visudo_bin" -cf "$TACCTL_SUDOERS_FILE"
    assert_success
}

@test "config sudoers install: strips leading '%' from group name" {
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install %wheel'
    assert_success

    # The bare group name lands in the emitted line (no double '%').
    run cat "$TACCTL_SUDOERS_FILE"
    assert_output --partial "%wheel ALL="
    refute_output --partial "%%wheel"
}

@test "config sudoers install: defaults to group 'adm' when no group given" {
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install'
    assert_success
    run cat "$TACCTL_SUDOERS_FILE"
    assert_output --partial "%adm ALL="
}

@test "config sudoers install: rejects invalid group name" {
    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install "bad group"'
    assert_failure
    assert_output --partial "Invalid group name"
}

@test "config sudoers install: 'n' confirmation aborts before writing" {
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    stub_cmd visudo
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'

    run bash -c 'echo n | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install wheel'
    assert_success
    assert_output --partial "Aborted"
    [[ ! -f "$TACCTL_SUDOERS_FILE" ]]
}

@test "config sudoers install: aborts when visudo validation fails" {
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    stub_cmd visudo 'exit 1'
    stub_cmd install 'cp "${@: -2:1}" "${@: -1}"'

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" config sudoers install wheel'
    assert_failure
    assert_output --partial "visudo validation failed"
    [[ ! -f "$TACCTL_SUDOERS_FILE" ]]
}

@test "config sudoers remove: no-op when nothing is installed" {
    run "$TACCTL_BIN_SCRIPT" config sudoers remove
    assert_success
    assert_output --partial "Nothing to remove"
}

@test "config sudoers remove: deletes the drop-in file" {
    mkdir -p "$(dirname "$TACCTL_SUDOERS_FILE")"
    echo "%wheel ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl" > "$TACCTL_SUDOERS_FILE"
    [[ -f "$TACCTL_SUDOERS_FILE" ]]

    run "$TACCTL_BIN_SCRIPT" config sudoers remove
    assert_success
    [[ ! -f "$TACCTL_SUDOERS_FILE" ]]
}

@test "config sudoers: rejects unknown subcommand" {
    run "$TACCTL_BIN_SCRIPT" config sudoers bogus
    assert_failure
    assert_output --partial "Invalid subcommand"
}
