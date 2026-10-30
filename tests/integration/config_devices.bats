#!/usr/bin/env bats
# Integration tests for `tacctl config devices`: device.config.max_concurrency,
# .transport and .timeout, which `device config pull` reads, and
# .confirm_timeout, the N of the confirmed commit of `device config plan`,
# and device.apply.confirm_timeout and .pause, which `device config apply`
# reads.

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

@test "config devices: shows the six defaults" {
    run "$TACCTL_BIN_SCRIPT" config devices
    assert_success
    plain
    assert_line --regexp '^  max-concurrency: 8 +\(default; 1-64'
    assert_line --regexp '^  transport: +auto +\(default; auto, netconf or ssh'
    assert_line --regexp '^  timeout: +90 s +\(default; 10-600'
    assert_line --regexp '^  confirm-timeout: 5 min +\(default; 1-60'
    assert_line --regexp '^  apply-confirm-timeout: 10 min +\(default; 3-60'
    assert_line --regexp '^  apply-pause: +60 s +\(default; 0-3600'
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
    run "$TACCTL_BIN_SCRIPT" config devices confirm-timeout 10
    assert_success
    assert_output --partial "The confirm timeout of a Junos plan set to 10 minutes."
    run "$TACCTL_BIN_SCRIPT" config devices apply-confirm-timeout 15
    assert_success
    assert_output --partial "The confirm timeout of an apply set to 15 minutes."
    run "$TACCTL_BIN_SCRIPT" config devices apply-pause 0
    assert_success
    assert_output --partial "The pause between the devices of an apply set to 0 s."
    run "$TACCTL_BIN_SCRIPT" config get device.config.max_concurrency
    assert_output "16"
    run "$TACCTL_BIN_SCRIPT" config get device.config.transport
    assert_output "ssh"
    run "$TACCTL_BIN_SCRIPT" config get device.config.timeout
    assert_output "120"
    run "$TACCTL_BIN_SCRIPT" config get device.config.confirm_timeout
    assert_output "10"
    run "$TACCTL_BIN_SCRIPT" config get device.apply.confirm_timeout
    assert_output "15"
    run "$TACCTL_BIN_SCRIPT" config get device.apply.pause
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" config devices
    plain
    assert_line --regexp '^  max-concurrency: 16 +\(set;'
    assert_line --regexp '^  apply-confirm-timeout: 15 min +\(set;'
    assert_line --regexp '^  apply-pause: +0 s +\(set;'
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    for bad in "max-concurrency 0" "max-concurrency 65" "max-concurrency many" "transport pigeon" "timeout 9" "timeout 601" "confirm-timeout 0" "confirm-timeout 61" "confirm-timeout soon"; do
        run "$TACCTL_BIN_SCRIPT" config devices $bad
        assert_failure 1
        assert_output --partial "device.config."
    done
    for bad in "apply-confirm-timeout 2" "apply-confirm-timeout 61" "apply-confirm-timeout soon" "apply-pause -1" "apply-pause 3601" "apply-pause soon"; do
        run "$TACCTL_BIN_SCRIPT" config devices $bad
        assert_failure 1
        assert_output --partial "device.apply."
    done
    # A refused value left the file as it was.
    run "$TACCTL_BIN_SCRIPT" config get device.apply.pause
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" config devices max-concurrency
    assert_success
    assert_output --partial "Devices read at once: 16"
}

@test "config devices: usage and the unknown word" {
    run "$TACCTL_BIN_SCRIPT" config devices help
    assert_success
    assert_output --partial "Usage: tacctl config devices [show|max-concurrency|transport|timeout|confirm-timeout|apply-confirm-timeout|apply-pause|apply-transport|timeout-scale] [<value>]"
    # --help is the list of '?': each word with its description.
    run "$TACCTL_BIN_SCRIPT" config devices --help
    assert_success
    assert_line --index 0 "Possible completions:"
    local w
    for w in apply-confirm-timeout apply-pause apply-transport confirm-timeout max-concurrency show timeout timeout-scale transport; do
        assert_line --regexp "^  ${w} +[A-Z]"
    done
    [ "${#lines[@]}" -eq 10 ]
    run "$TACCTL_BIN_SCRIPT" config devices frobnicate
    assert_failure 1
    assert_output --partial "Unknown subcommand: 'frobnicate'"
}

@test "config devices: the apply keys are written only when set, shown by config devices, and refused by validate when out of range" {
    run "$TACCTL_BIN_SCRIPT" config devices apply-pause 30
    assert_success
    run grep -c "confirm_timeout" "${TACCTL_STATE_DIR}/tacctl.yaml"
    assert_output "0"
    run "$TACCTL_BIN_SCRIPT" config devices show
    assert_success
    assert_output --partial "apply-pause:           30 s   (set;"
    assert_output --partial "apply-confirm-timeout: 10 min   (default;"
    run "$TACCTL_BIN_SCRIPT" config get device.apply.confirm_timeout 10
    assert_output "10"
    printf 'device:\n  apply:\n    confirm_timeout: 2\n' > "${TACCTL_STATE_DIR}/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_failure
    assert_output --partial "device.apply.confirm_timeout"
}
