#!/usr/bin/env bats
# Integration tests for `tacctl config devices`: device.config.max_concurrency,
# .transport and .timeout, which `device config pull` reads.

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
    load_fixture tacquito.multiscope.yaml
}

plain() {
    output=$(sed 's/\x1b\[[0-9;]*m//g' <<< "$output")
    mapfile -t lines <<< "$output"
}

@test "config devices: shows the three defaults" {
    run "$TACCTL_BIN_SCRIPT" config devices
    assert_success
    plain
    assert_line --regexp '^  max-concurrency: 8 +\(default; 1-64'
    assert_line --regexp '^  transport: +auto +\(default; auto, netconf or ssh'
    assert_line --regexp '^  timeout: +90 s +\(default; 10-600'
    # The defaults are the schema's, not a line of tacctl.yaml.
    run "$TACCTL_BIN_SCRIPT" config get device.config.max_concurrency 8
    assert_output "8"
    [[ ! -e "${TACCTL_STATE_DIR}/tacctl.yaml" ]]
}

@test "config devices: each setter writes tacctl.yaml, shows, and validates" {
    run "$TACCTL_BIN_SCRIPT" config devices max-concurrency 16
    assert_success
    assert_output --partial "The most devices read at once set to 16."
    run "$TACCTL_BIN_SCRIPT" config devices transport ssh
    assert_success
    run "$TACCTL_BIN_SCRIPT" config devices timeout 120
    assert_success
    run "$TACCTL_BIN_SCRIPT" config get device.config.max_concurrency
    assert_output "16"
    run "$TACCTL_BIN_SCRIPT" config get device.config.transport
    assert_output "ssh"
    run "$TACCTL_BIN_SCRIPT" config get device.config.timeout
    assert_output "120"
    run "$TACCTL_BIN_SCRIPT" config devices
    plain
    assert_line --regexp '^  max-concurrency: 16 +\(set;'
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    for bad in "max-concurrency 0" "max-concurrency 65" "max-concurrency many" "transport pigeon" "timeout 9" "timeout 601"; do
        run "$TACCTL_BIN_SCRIPT" config devices $bad
        assert_failure 1
        assert_output --partial "device.config."
    done
    run "$TACCTL_BIN_SCRIPT" config devices max-concurrency
    assert_success
    assert_output --partial "Devices read at once: 16"
}

@test "config devices: usage and the unknown word" {
    run "$TACCTL_BIN_SCRIPT" config devices --help
    assert_success
    assert_output --partial "Usage: tacctl config devices [show|max-concurrency|transport|timeout] [value]"
    run "$TACCTL_BIN_SCRIPT" config devices frobnicate
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frobnicate'"
}
